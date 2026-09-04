//! Agent Fabric — edge channel-pairing authorization (ADR-0020, #72 AF2b).
//!
//! The edge is the rendezvous gate for agent-to-agent channels: two agents that
//! want a direct channel each present a [`SignedChannelGrant`] for the same
//! [`ChannelId`], and the edge decides whether to broker them together. This module
//! is the **pure authorization + pairing core** (no sockets): it verifies both
//! grants against the channel operator's key, checks they are for the same channel
//! with compatible directions, and returns which side initiates and which accepts.
//! The socket-level QUIC brokering (generalising `rendezvous.rs` to relay between
//! two agents) and where the operator key comes from are later sub-packets.

use ct_common::sync::MutexExt;
use ct_common::channel::{
    encode_channel_refusal, verify_holder_possession, verify_stateless, ChannelId,
    ChannelJoinRequest, Direction, GrantError, SignedChannelGrant, UnixSeconds,
};
use quinn::Endpoint;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The decided pairing for a channel: who dials (initiator) and who accepts, bound
/// to each side's holder identity (the pubkey its grant is bound to).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPairing {
    pub channel: ChannelId,
    pub initiator_holder: [u8; 32],
    pub acceptor_holder: [u8; 32],
}

/// Why two presented grants could not be brokered into a channel pairing.
#[derive(Debug, PartialEq, Eq)]
pub enum BrokerError {
    /// One side's grant failed verification (bad signature / expired / bad key).
    GrantInvalid(GrantError),
    /// The two grants are for different channels.
    ChannelMismatch,
    /// Neither side can initiate while the other accepts (e.g. both initiate-only).
    IncompatibleDirections,
    /// Both grants bind the same holder — an agent cannot channel to itself.
    SameHolder,
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::GrantInvalid(e) => write!(f, "channel grant invalid: {e}"),
            BrokerError::ChannelMismatch => write!(f, "grants are for different channels"),
            BrokerError::IncompatibleDirections => {
                write!(f, "no initiator/acceptor pairing between the two grants")
            }
            BrokerError::SameHolder => write!(f, "both grants bind the same holder"),
        }
    }
}

impl std::error::Error for BrokerError {}

/// Decide whether two presented grants may be brokered into a direct channel, and
/// which side initiates. Both grants must verify against the channel operator's
/// public key at `now`, be for the same channel, bind distinct holders, and offer a
/// compatible direction split (one may Initiate, the other may Accept). When both
/// sides permit either direction, `a` is chosen as the initiator (a stable, caller-
/// independent convention).
///
/// #415: `verify_stateless` (not `verify_fresh`) is deliberate — every caller in this
/// crate pairs both `a` and `b` here with a grant that already passed the join
/// endpoint's own [`verify_holder_possession`] challenge/response before reaching
/// this pairing step, an independent defense stronger than a seen-nonce cache.
pub fn authorize_channel_pair(
    operator_pubkey: &[u8; 32],
    a: &SignedChannelGrant,
    b: &SignedChannelGrant,
    now: UnixSeconds,
) -> Result<ChannelPairing, BrokerError> {
    verify_stateless(operator_pubkey, a, now).map_err(BrokerError::GrantInvalid)?;
    verify_stateless(operator_pubkey, b, now).map_err(BrokerError::GrantInvalid)?;

    if a.grant.channel != b.grant.channel {
        return Err(BrokerError::ChannelMismatch);
    }
    if a.grant.holder == b.grant.holder {
        return Err(BrokerError::SameHolder);
    }

    let channel = a.grant.channel;
    // Prefer a-initiates when a may initiate and b may accept; else b-initiates.
    if a.grant.direction.permits(Direction::Initiate)
        && b.grant.direction.permits(Direction::Accept)
    {
        Ok(ChannelPairing {
            channel,
            initiator_holder: a.grant.holder,
            acceptor_holder: b.grant.holder,
        })
    } else if b.grant.direction.permits(Direction::Initiate)
        && a.grant.direction.permits(Direction::Accept)
    {
        Ok(ChannelPairing {
            channel,
            initiator_holder: b.grant.holder,
            acceptor_holder: a.grant.holder,
        })
    } else {
        Err(BrokerError::IncompatibleDirections)
    }
}

/// A member parked in the [`ChannelPairer`] waiting to be matched with the other
/// holder of its channel. `payload` is opaque to the pairer — the live broker carries
/// the accepted connection + its send stream + the verified [`ChannelJoinRequest`] +
/// operator key there; the pairer itself only correlates by `channel`/`holder` and
/// enforces `deadline`, so it stays pure and socket-free (unit-testable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingMember<T> {
    pub channel: ChannelId,
    pub holder: [u8; 32],
    /// #508: the member's observed remote IP, when the admission path knows it --
    /// used ONLY by the sibling-channel mismatch diagnostic in `drain_expired`
    /// (a lone park expiring while a SAME-peer park waits on a DIFFERENT channel
    /// is the mismatched-provisioning signature that cost 19h to diagnose by hand).
    pub observed: Option<std::net::IpAddr>,
    /// Absolute time by which this lone waiter must be paired or evicted (#109 #3).
    pub deadline: UnixSeconds,
    /// #499 slice B: live corpse signal for this park. The `:443` park pump sets it the
    /// moment the CLIENT side of the parked connection dies (EOF/error on the read half
    /// while parked); `offer`/`drain_expired` then drop the member instead of ever handing
    /// a corpse to an arriving partner (the FIFO-pairs-the-corpse-first failure that cost
    /// real first-contact latency, measured live: 20.6s + a transport fault on the re-park
    /// boundary). `default()` (unmonitored, e.g. QUIC members -- QUIC has connection-level
    /// death detection of its own) never reads as dead.
    pub liveness: ParkLiveness,
    /// #495 slice 2a: the park's protocol phase -- see [`ParkPhase`].
    pub phase: ParkPhase,
    pub payload: T,
}

/// #499 slice B: a shared park-death flag (see [`WaitingMember::liveness`]). Deliberately
/// equality-neutral -- two members are the same member regardless of monitor identity --
/// so `WaitingMember`'s derived `PartialEq/Eq` (used by pairer unit tests) keep working.
#[derive(Debug, Clone, Default)]
pub struct ParkLiveness(Option<std::sync::Arc<std::sync::atomic::AtomicBool>>);

impl ParkLiveness {
    /// A monitored flag: the pump holds the returned handle and sets it on client death.
    ///
    /// **The guarantee is conditional, and the condition is the negotiated ALPN.** In
    /// [`spawn_park_keepalive_pump`]:
    ///
    /// - A **hard** error (RST-class) sets this on any client version.
    /// - A clean `EOF` sets it **only on a keepalive-negotiated leg**, where the contract says
    ///   a parked leg stays fully open, so EOF can only mean death. On a plain leg the same
    ///   EOF is deliberately tolerated as a legacy half-close (`read_open = false`) and this
    ///   flag stays clear — the two are wire-ambiguous, and guessing wrong would tear down a
    ///   healthy old client.
    ///
    /// So a plain-ALPN park whose client exits cleanly is NOT flagged; it lives until its
    /// TTL, and can win a pairing in that window. That is a deliberate trade, not an
    /// oversight, but anything reasoning about corpse detection has to know it holds for one
    /// population and not the other. `ct_edge_channel_park_legs_total{keepalive=…}` (#558)
    /// reports how large each population currently is; ct-agent#22's accept-vs-relay design
    /// turns on exactly this distinction.
    pub fn monitored() -> (Self, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        (Self(Some(flag.clone())), flag)
    }
    pub fn is_dead(&self) -> bool {
        self.0.as_ref().is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl PartialEq for ParkLiveness {
    fn eq(&self, _other: &Self) -> bool {
        true // identity-neutral by design; see the type's doc comment
    }
}
impl Eq for ParkLiveness {}

/// #495 slice 2a: which protocol PHASE a park belongs to. Phase 1 (`Rendezvous`) is the
/// admission park -- its client reads the ack and CLOSES; phase 2 (`Relay`) is the relay
/// leg -- its client expects the spliced session on the SAME stream after the ack. A
/// phase-mixed pairing puts a splice against an ack-and-close peer (instant early eof,
/// the residual boundary-transportFault class measured after #499b). The QUIC brokers
/// have always separated the phases by PORT (4435/4436); the `:443`/WS legs cannot tell
/// them apart on today's wire, so they park as [`ParkPhase::Unmarked`] -- which pairs
/// with ANYTHING, i.e. exactly today's mixed behavior, until the v0.4.14 client marks
/// its relay legs. Same-phase-only pairing is therefore strictly additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// #495 2a: which join PHASE a parked member declared — and, per transport, where that
/// declaration comes from (#511, the one place this is written down):
///
/// | transport                       | phase origin                                       |
/// |---------------------------------|----------------------------------------------------|
/// | QUIC broker `:4435` (rendezvous)| constant at the accept-loop spawn site (`serve.rs`)|
/// | QUIC broker `:4436` (relay)     | constant at the accept-loop spawn site (`serve.rs`)|
/// | `:443` front door (TLS-TCP)     | the client's `[0xFF, phase]` preamble (peeked in `admit_and_pair_on_boxed_stream`; absent → `Unmarked`) |
/// | WS upgrade path                 | always `Unmarked` (no peek on this path)           |
///
/// The QUIC brokers can use constants because each port IS one phase; only `:443`
/// multiplexes both phases over one listener and needs the client to say which.
/// The phase→completion decision is [`completion_for`].
pub enum ParkPhase {
    Rendezvous,
    Relay,
    Unmarked,
}

impl ParkPhase {
    /// Whether two parks may pair: equal phases, or either side legacy-unmarked.
    pub fn compatible(self, other: ParkPhase) -> bool {
        self == other || self == ParkPhase::Unmarked || other == ParkPhase::Unmarked
    }
}

/// #495 slice 2a (v0.4.14 client marker): first byte of the OPTIONAL phase preamble a
/// KA-generation client may send before its length-framed join. Unambiguous against the
/// length prefix by construction: 0xFF as the length's high byte would mean a >=65280-byte
/// join, which the admission's own `len > 1024` bound has always rejected ("len-oob").
/// Only ever interpreted on connections whose TLS negotiation selected a #500 KA id --
/// an old client can never send it (it never negotiates KA), and a NON-KA connection's
/// stray 0xFF falls into the existing len-oob refusal, not into phase parsing.
pub(crate) const PHASE_PREAMBLE_MAGIC: u8 = 0xFF;

/// #495 U2 (b'): read the OPTIONAL phase preamble off a join stream, whatever transport it
/// arrived on, and hand back a stream that reads identically either way.
///
/// Both branches return the same type: on a marker, `pos = 2` (nothing to replay); with no
/// marker, `pos = 0` (both bytes replay as the length prefix they were). That is what makes
/// this usable where the caller cannot branch on a type -- notably the QUIC admission path,
/// which has no preamble handling at all today.
///
/// **The safety argument here is NOT the one the `:443` peek relies on.** That one is gated
/// on a #500 keepalive ALPN, so an old client's bytes are never even inspected. QUIC
/// negotiates no ALPN at all (measured: `pki.rs`'s `quic_channel_endpoint_and_an_alpn_...`),
/// so on that path every client's first two bytes pass through here. What carries the
/// safety instead is the length bound alone: a legitimate join is under 1024 bytes, so its
/// length's high byte is never 0xFF, and a stray 0xFF still lands in the existing len-oob
/// refusal rather than in phase parsing. Stated explicitly because a reader who assumes the
/// KA gate protects this path too would draw a stronger conclusion than the code supports.
async fn peek_optional_phase_marker<R: AsyncRead + Unpin>(
    mut recv: R,
) -> Result<(PrependBytes<R>, ParkPhase), BoxError> {
    let mut first = [0u8; 2];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| -> BoxError { format!("channel join: preamble/length read failed: {e}").into() })?;
    if first[0] != PHASE_PREAMBLE_MAGIC {
        return Ok((PrependBytes { pre: first, pos: 0, inner: recv }, ParkPhase::Unmarked));
    }
    let phase = match first[1] {
        0x01 => ParkPhase::Rendezvous,
        0x02 => ParkPhase::Relay,
        // Same reasoning as the `:443` peek: a wrong byte AFTER the magic is a defect in the
        // client's marker writer, never transient, so the per-IP penalty must see it as
        // definitive (#509).
        other => {
            return Err(DefinitiveJoinRefusal::boxed(
                format!("channel join: unknown phase marker 0x{other:02x} after the preamble magic")
                    .into(),
            ))
        }
    };
    Ok((PrependBytes { pre: first, pos: 2, inner: recv }, phase))
}

/// Put two already-read bytes back in front of a stream -- the no-preamble path of the
/// phase peek (the two bytes were the join's length prefix after all). Write half passes
/// through untouched.
struct PrependBytes<S> {
    pre: [u8; 2],
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependBytes<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.pre[start..start + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependBytes<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// First 8 bytes of an id as lowercase hex — enough to correlate with other log
/// lines (the reaper prints the same prefix length) without dumping full ids.
fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The outcome of offering a member to the [`ChannelPairer`].
#[derive(Debug, PartialEq, Eq)]
pub enum PairOutcome<T> {
    /// First holder of this channel — now parked, waiting for its partner.
    Parked,
    /// A different holder of the *same* channel arrived: broker exactly these two.
    Paired(WaitingMember<T>, WaitingMember<T>),
    /// The same holder re-presented (a retry) before its partner arrived: the newer
    /// offer supersedes and stays parked; the returned stale waiter must be closed
    /// (pairing a holder with itself would only earn a `SameHolder` refusal).
    Superseded(WaitingMember<T>),
}

/// Channel-keyed pairing correlator (#109 robustness): the substrate that replaces the
/// broker's channel-blind "pair the next two arrivals" accept model. Each accepted +
/// admitted member is `offer`ed here; the pairer parks the first holder of a channel
/// and only pairs it with a *different holder of the same channel* — so two channels'
/// members racing to connect can never cross-pair (the #109 mis-pairing failure), and
/// a lone first-comer is bounded by its `deadline` instead of wedging the round.
///
/// #495 slice 1: how many parks ONE member (channel+holder) may hold queued at once before its
/// oldest is superseded. Why a queue at all: the old single-slot supersede-on-reoffer semantics
/// meant every consumed park left a no-park window until the client's re-admit round trip
/// (~200-400ms over WAN) landed -- measured live as a structural 15-22% per-round fault rate for
/// call-per-round consumers (ct-agent#18). A client that re-parks BEFORE its previous park is
/// consumed now simply deepens the queue instead of killing its own live park. Why a CAP: each
/// queued park holds a real connection and (#451) a cap permit; a crash-looping client must not
/// accumulate them unboundedly. 4 = deep enough that a serve loop keeping 1-2 parks in flight
/// never trips it, small enough that the worst case per member stays trivial. Entries expire at
/// the park TTL (30s) well inside the client-side 45s admission bound (#140), so queued parks
/// are live in practice, not corpses.
const PARKS_PER_MEMBER: usize = 4;

#[derive(Debug, Default)]
pub struct ChannelPairer<T> {
    /// #495 slice 1: a small FIFO of waiters per channel (was: exactly one). Since the 2a
    /// phases, one channel's queue may legitimately hold BOTH holders' parks at once (e.g.
    /// A's rendezvous park alongside B's relay park — phase-incompatible, so `offer` skips
    /// rather than pairs them); the bounding invariant is PER-HOLDER, kept by `offer`:
    /// at most [`PARKS_PER_MEMBER`] parks per holder per channel, oldest superseded first.
    /// (#511: this doc used to state the pre-2a one-holder-per-queue invariant, which 2a
    /// deliberately abolished.)
    waiting: std::collections::HashMap<ChannelId, std::collections::VecDeque<WaitingMember<T>>>,
    /// #499 slice B: corpses dropped so far (parks whose client died while queued, detected
    /// via [`ParkLiveness`] and discarded at offer/drain time instead of being paired or
    /// EX-notified). Monotonic; [`Self::take_dead_dropped`] reads-and-resets for the reaper's
    /// per-sweep visibility line.
    dead_dropped: u64,
    /// #508 persistence memory: how long each (expired-channel, waiting-channel, ip)
    /// sibling triple has been recurring. Field-tuned 2026-08-14 evening: the naive
    /// per-sighting log fired every minute for the 12-minute post-redeploy settle of a
    /// legitimate MULTI-CHANNEL host (an idle channel's parks expire partnerless every
    /// park cycle while a busy sibling waits — normal), while the true positive it was
    /// built for (mismatched provisioning) recurs for HOURS. A triple must persist
    /// [`SIBLING_PERSISTENCE_SECS`] across [`SIBLING_MIN_SIGHTINGS`] sweeps before it
    /// is spoken; entries unseen for [`SIBLING_PRUNE_SECS`] reset.
    sibling_sightings: std::collections::HashMap<(ChannelId, ChannelId, std::net::IpAddr), SiblingSighting>,
}

/// One #508 triple's recurrence record (see `ChannelPairer::sibling_sightings`).
#[derive(Debug, Clone, Copy)]
struct SiblingSighting {
    first: UnixSeconds,
    last: UnixSeconds,
    count: u32,
}

/// #508: how long a sibling-channel triple must keep recurring before it is logged.
/// 15 min: the flappy-class true positive (19 h) trips early and keeps alarming; a
/// post-redeploy settle (measured ≤12 min) never speaks.
const SIBLING_PERSISTENCE_SECS: u64 = 900;
/// #508: minimum recurrences within the persistence window (guards against sparse
/// coincidental overlaps counting as persistence).
const SIBLING_MIN_SIGHTINGS: u32 = 10;
/// #508: a triple unseen this long is forgotten (the condition resolved).
const SIBLING_PRUNE_SECS: u64 = 600;

impl<T> ChannelPairer<T> {
    pub fn new() -> Self {
        Self {
            waiting: std::collections::HashMap::new(),
            dead_dropped: 0,
            sibling_sightings: std::collections::HashMap::new(),
        }
    }

    /// #499 slice B: corpses dropped since the last call (read-and-reset -- the reaper logs
    /// a per-sweep summary so silent discards stay operator-visible).
    pub fn take_dead_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dead_dropped)
    }

    /// Offer an admitted member. Pairs it with the OLDEST queued **live** waiter of a
    /// different holder on the same channel (FIFO fairness; #499 slice B: corpses -- parks
    /// whose client already died -- are discarded, never handed to a partner), parks it
    /// otherwise, or -- only when this member already has [`PARKS_PER_MEMBER`] parks queued
    /// -- supersedes its own oldest park. See [`PairOutcome`].
    pub fn offer(&mut self, member: WaitingMember<T>) -> PairOutcome<T> {
        let queue = self.waiting.entry(member.channel).or_default();
        // #495 slice 2a: pair with the OLDEST live, DIFFERENT-holder, PHASE-COMPATIBLE park
        // (FIFO fairness within the compatible set). Corpses encountered during the search
        // are dropped (#499 slice B); phase-INCOMPATIBLE members are skipped but KEPT in
        // order -- with phases, one channel's queue may legitimately hold BOTH holders'
        // parks (e.g. A's rendezvous park alongside B's relay park), so the old
        // one-holder-per-queue invariant becomes the PER-HOLDER accounting below.
        let mut idx = 0;
        while idx < queue.len() {
            if queue[idx].liveness.is_dead() {
                queue.remove(idx);
                self.dead_dropped += 1;
                continue; // same idx now holds the next member
            }
            if queue[idx].holder != member.holder && queue[idx].phase.compatible(member.phase) {
                let candidate = queue.remove(idx).expect("idx < len just checked");
                if queue.is_empty() {
                    self.waiting.remove(&member.channel);
                }
                return PairOutcome::Paired(candidate, member);
            }
            idx += 1;
        }
        // No live compatible partner: purge this member's OWN corpses (they must neither
        // block the cap nor age out ahead of live parks -- #499 slice B; other holders'
        // members are untouched here, their corpses fall to the search above / the sweep),
        // then join the queue; beyond the PER-HOLDER cap, the member's own OLDEST park is
        // superseded -- not the newest, so a member's parks age out in arrival order.
        let before = queue.len();
        queue.retain(|w| w.holder != member.holder || !w.liveness.is_dead());
        self.dead_dropped += (before - queue.len()) as u64;
        let holder = member.holder;
        queue.push_back(member);
        let own_count = queue.iter().filter(|w| w.holder == holder).count();
        if own_count > PARKS_PER_MEMBER {
            let stale_idx = queue
                .iter()
                .position(|w| w.holder == holder)
                .expect("at least the just-pushed park has this holder");
            let stale = queue.remove(stale_idx).expect("position just found");
            return PairOutcome::Superseded(stale);
        }
        PairOutcome::Parked
    }

    /// Evict and return every waiter whose `deadline` is at or before `now` (#3): a park with
    /// no partner is bounded instead of wedging the round forever. Sweeps INSIDE each queue
    /// (an expired older park behind a fresher one is still evicted) and drops emptied queues.
    /// #499 slice B: corpses are dropped and counted here too -- NOT returned as expired,
    /// because the reaper's EX notification exists for live clients and a corpse has nobody
    /// left to notify.
    pub fn drain_expired(&mut self, now: UnixSeconds) -> Vec<WaitingMember<T>> {
        let mut drained = Vec::new();
        let mut dead = 0u64;
        self.waiting.retain(|_, queue| {
            let mut kept = std::collections::VecDeque::with_capacity(queue.len());
            for m in queue.drain(..) {
                if m.liveness.is_dead() {
                    dead += 1;
                } else if m.deadline <= now {
                    drained.push(m);
                } else {
                    kept.push_back(m);
                }
            }
            *queue = kept;
            !queue.is_empty()
        });
        self.dead_dropped += dead;
        // #508: the mismatched-provisioning diagnostic. A lone park expiring while a
        // SAME-peer park still waits on a DIFFERENT channel is the signature of a
        // half-updated deployment (one side's grants regenerated, the other's env
        // stale) -- the pairer correctly never matches them, but its silence cost 19h
        // of by-hand diagnosis in the field (2026-08-14, flappy crew bridge). A triple
        // must PERSIST (see `sibling_sightings`) before it is spoken -- a legitimate
        // multi-channel host recreates this signature transiently after every
        // redeploy -- and confirmed triples stay rate-limited to one line per minute.
        // (The scan runs on every non-empty drain to feed the persistence memory; the
        // #511 gate-first micro-optimization gave way to that -- `drained` is a
        // handful of members and the scan is bounded by the queue count.)
        if !drained.is_empty() {
            let triples = self.sibling_channel_mismatches(&drained);
            for (expired_channel, waiting_channel, ip) in self.note_sibling_sightings(triples, now) {
                static LAST_508_LOG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let last = LAST_508_LOG.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= 60 && LAST_508_LOG
                    .compare_exchange(last, now, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed)
                    .is_ok()
                {
                    eprintln!(
                        "ct-edge: lone park expired (channel={}…) while a park from the SAME peer ({ip}) \
                         has waited on a DIFFERENT channel ({}…) persistently for 15+ minutes — \
                         mismatched provisioning between the two sides? (#508)",
                        hex_prefix(&expired_channel.0),
                        hex_prefix(&waiting_channel.0),
                    );
                }
            }
        }
        drained
    }

    /// #508 persistence core (pure, unit-tested): record `triples` as sighted at `now`,
    /// prune entries unseen for [`SIBLING_PRUNE_SECS`], and return only the triples
    /// whose recurrence has now crossed BOTH thresholds ([`SIBLING_PERSISTENCE_SECS`]
    /// since first sighting and [`SIBLING_MIN_SIGHTINGS`] sightings) -- the ones worth
    /// an operator's attention.
    fn note_sibling_sightings(
        &mut self,
        triples: Vec<(ChannelId, ChannelId, std::net::IpAddr)>,
        now: UnixSeconds,
    ) -> Vec<(ChannelId, ChannelId, std::net::IpAddr)> {
        self.sibling_sightings.retain(|_, s| now.saturating_sub(s.last) <= SIBLING_PRUNE_SECS);
        let mut confirmed = Vec::new();
        for t in triples {
            let s = self
                .sibling_sightings
                .entry(t)
                .or_insert(SiblingSighting { first: now, last: now, count: 0 });
            s.last = now;
            s.count = s.count.saturating_add(1);
            if s.count >= SIBLING_MIN_SIGHTINGS && now.saturating_sub(s.first) >= SIBLING_PERSISTENCE_SECS {
                confirmed.push(t);
            }
        }
        confirmed
    }

    /// #508, pure core: for each drained (expired, partnerless) member with a known
    /// observed IP, find a STILL-WAITING member from the same IP parked on a
    /// different channel. Returns (expired member's channel, waiting sibling's
    /// channel, shared IP) triples — the caller logs them rate-limited.
    pub(crate) fn sibling_channel_mismatches(
        &self,
        drained: &[WaitingMember<T>],
    ) -> Vec<(ChannelId, ChannelId, std::net::IpAddr)> {
        let mut out = Vec::new();
        for e in drained {
            let Some(ip) = e.observed else { continue };
            for (chan, queue) in &self.waiting {
                if *chan == e.channel {
                    continue;
                }
                if queue.iter().any(|w| w.observed == Some(ip)) {
                    out.push((e.channel, *chan, ip));
                    break; // one sibling per expired member is signal enough
                }
            }
        }
        out
    }

    /// Total members currently parked (across all channels and queue depths).
    pub fn len(&self) -> usize {
        self.waiting.values().map(std::collections::VecDeque::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }
}

/// Endpoint policy (#81 gap 3, tightened for #94): a peer agent will *dial* this
/// advertised address, so it must be a real, **publicly-routable** socket address and
/// not an SSRF / internal-pivot target. A malicious holder must not be able to make the
/// peer dial into the operator's LAN (`10.0.0.5:22`, a metadata service, an internal
/// admin API). Reject anything that isn't a parseable `SocketAddr`, and reject
/// loopback / unspecified / multicast **plus** every private / internal range: RFC1918,
/// link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`) and IPv6 unique-local
/// (`fc00::/7`). Only global unicast passes. Returns the parsed address when acceptable.
fn safe_endpoint(ep: &str) -> Option<std::net::SocketAddr> {
    // Behaviour-preserving (#121 Phase B1): the private/internal-range test is factored into
    // the shared `ct_common::channel::is_global_unicast`, so the edge's SSRF filter and the
    // reflexive-reachability classifier agree by construction on what counts as reachable.
    ep.parse::<std::net::SocketAddr>()
        .ok()
        .filter(|addr| ct_common::channel::is_global_unicast(*addr))
}

/// Admission predicate for a join's advertised endpoint (#121): admit the explicit
/// `relay-only` sentinel (`CHANNEL_ENDPOINT_RELAY_ONLY`; a NAT-only member that participates via the
/// relay only) **or** a safe, globally-routable address ([`safe_endpoint`]). A private /
/// loopback / internal address is STILL refused exactly as #94 requires — the sentinel is a
/// reserved non-address, so a member cannot smuggle a LAN SSRF target through it, and
/// [`safe_endpoint`] itself is left untouched. So a member either advertises a global-unicast
/// address it can be dialed at, or the sentinel (not an address at all): there is no third
/// case a hostile holder can exploit.
fn admissible_endpoint(req: &ChannelJoinRequest) -> bool {
    req.is_relay_only() || safe_endpoint(&req.endpoint).is_some()
}

/// Accept one QUIC connection and read + verify a presented [`ChannelJoinRequest`],
/// but do NOT ack yet — the caller owns the reply, because a single admission acks
/// `OK` immediately while the two-party broker must defer until it knows the pairing.
///
/// `authorize(channel, holder)` returns the channel's operator public key **iff the
/// holder is a current member** of the channel — a single lookup that folds the
/// #81 gap-2 membership/revocation check into the operator-key source (removing a
/// member from the registry now denies admission at the gate, no key rotation or
/// expiry-shortening needed). Rejects (with a `NO`) a malformed request, an
/// #81 gap-3 unsafe advertised endpoint, an unknown-channel/non-member holder, a
/// bad/expired grant, and (#81 gap 1) a presenter that cannot prove it holds the
/// grant's `holder` private key. Returns the request and the resolved operator key.
///
/// Wire framing: the presenter sends a `u16`-BE length prefix + the encoded request,
/// then keeps its stream open. The edge replies with a fresh 32-byte challenge; the
/// presenter must answer with a 64-byte ed25519 signature over it under `holder`
/// before the edge acks. (A plain `read_to_end` would force the presenter to finish
/// its send stream, leaving no room for the possession round-trip.)
pub async fn read_join_on_connection<F, Fut>(
    conn: &quinn::Connection,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<
    (
        quinn::SendStream,
        ChannelJoinRequest,
        [u8; 32],
        Option<[u8; 32]>,
        Option<[u8; 64]>,
        std::net::SocketAddr,
    ),
    BoxError,
>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1: the reflexive (post-NAT) address the QUIC transport observed as this
    // authenticated connection's source — the AutoNAT primitive, the same `remote_address()`
    // the classic tunnel uses (see `serve.rs`). Captured here where the whole connection
    // exists and passed into the stream-generic admission so it can travel back in the ack.
    let observed = conn.remote_address();
    // #105: bound `accept_bi` itself — a connection that completes the QUIC handshake
    // but never opens a stream can't wedge the broker's serial round loop. The framed
    // request + possession round-trip is then bounded a second time inside
    // `read_channel_join_on_stream`, so each phase has its own guard.
    //
    // #231 root-cause (2026-08-01): this used to share the FULL `join_timeout` with the
    // read phase below, stacking to up to 2x join_timeout (30s at the real 15s constant)
    // of total server-side tolerance for one admission -- while the CLIENT's own total
    // budget (ADMISSION_EXCHANGE_TIMEOUT, ct-agent's channel.rs) is a single 15s window
    // covering the whole round trip. A perfectly healthy admission whose CP `authorize`
    // call takes several seconds (well within ITS OWN 10s bound, and well within the read
    // phase's own 15s bound) could already have exceeded what the client was still
    // waiting for -- the server hadn't "failed", the client had just already given up,
    // live-reproduced as the intermittent "channel join admission exchange stalled
    // (#140)" pattern this issue tracks. `accept_bi` itself should be near-instant for a
    // well-behaved peer (its own bi-stream open, right after completing the QUIC
    // handshake) -- it is NOT a network round-trip to an external control-plane like the
    // read phase is, so it doesn't need anywhere near the same budget. Capped at 5s (or
    // `join_timeout` itself when a caller configures something shorter, e.g. this file's
    // own fast unit tests) rather than a separate hardcoded constant, so the #105
    // slow/hostile-client protection this timeout exists for is unchanged in spirit, just
    // no longer wastefully large for this specific phase.
    let accept_bi_timeout = join_timeout.min(std::time::Duration::from_secs(5));
    let (send, recv) = match tokio::time::timeout(accept_bi_timeout, conn.accept_bi()).await {
        // #128: tag the bi-stream-open phase — a peer that completes the QUIC handshake but
        // closes before opening its stream surfaces here, not at handshake.
        Ok(streams) => streams.map_err(|e| format!("[quic-bistream] {e}"))?,
        Err(_) => {
            // A peer that completes the QUIC handshake but never opens a bi-stream within the
            // timeout (#105 stalled connection): log the problem, don't wedge the loop.
            eprintln!("ct-edge: channel-join NO [bi-timeout] peer={observed}: no bi-stream within {accept_bi_timeout:?}");
            return Err(
                "channel join not submitted within the timeout — dropping stalled connection (#105)"
                    .into(),
            )
        }
    };
    // The quinn broker pairs over the `quinn::Connection` (rendezvous endpoint swap /
    // relay bi-stream), not over this join stream, so the returned read half is dropped.
    // #495 U2 (b'): TOLERATE an optional phase preamble here. Purely additive -- the value
    // is read and discarded, so every current client (none of which sends one) behaves
    // exactly as before, and a future marker-sending client is no longer refused before it
    // can be understood. Landing the toleration FIRST is not a preference: the measurements
    // in #495 show the QUIC join has no forward-compatibility slack at all, so a client that
    // ships before this would have every join rejected.
    let (recv, _phase) = peek_optional_phase_marker(recv).await?;
    let (send, _recv, req, operator, member_noise, member_attest, observed) =
        read_channel_join_on_stream(send, recv, observed, now, join_timeout, authorize).await?;
    Ok((send, req, operator, member_noise, member_attest, observed))
}

/// Admit a channel join over an already-established bidirectional byte stream —
/// transport-agnostic (#106 edge-dispatch). The QUIC broker reaches this via
/// [`read_join_on_connection`] (a `quinn` bi-stream), but the same admission —
/// length-framed [`ChannelJoinRequest`], membership + grant verification, and the
/// single-use holder-possession challenge — runs unchanged over *any* duplex, so a
/// TLS-over-TCP `:443` front-door stream (for members whose network blocks the
/// channel UDP/TCP ports) is admitted identically. `send`/`recv` are the write/read
/// halves of the stream; on success **both** are returned (the write half first, then
/// the read half) so the caller can reunite them into the full duplex and drive the
/// pairing (rendezvous endpoint exchange or relay splice) on the same stream — the
/// read half is not consumed by admission (#106 complete-wire443).
///
/// `observed` is the member's **reflexive** (post-NAT) source address as seen on this
/// already-authenticated connection (#121 Phase B1 — the AutoNAT primitive): the
/// transport-aware caller supplies it (`conn.remote_address()` for QUIC, the accepted
/// `TcpStream`'s `peer_addr()` for the `:443` front door), keeping this stream-generic
/// core transport-agnostic, and it is echoed back as the last returned element so the
/// caller can report it to the member and classify reachability
/// ([`ct_common::channel::reachability_class`]).
pub async fn read_channel_join_on_stream<W, R, F, Fut>(
    mut send: W,
    mut recv: R,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<
    (W, R, ChannelJoinRequest, [u8; 32], Option<[u8; 32]>, Option<[u8; 64]>, std::net::SocketAddr),
    BoxError,
>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #124 observability: refuse an admission by logging the per-checkpoint reason
    // server-side with a stable, greppable tag (`ct-edge: channel-join NO [<tag>]`), then
    // sending the refusal on the wire. #524 (superseding #124's bare-`NO`-only wire): the
    // ack now carries the CATEGORY too — `NO` + one length-framed token from the closed
    // vocabulary (`ct_common::channel::CHANNEL_REFUSAL_CATEGORIES`, exactly these `tag`s)
    // — so a legitimate member can self-diagnose "wrong holder key" vs. "not a member"
    // vs. "expired grant" without an operator reading edge logs (the 2026-08-15 live
    // incident: a `[possession]` refusal cost a CP-DB + edge-log escalation to diagnose).
    // Deliberately still NEVER the free-text reason: the category names the checkpoint
    // class only, while the detailed reason — with grant fields, expiry values, signature
    // errors — stays in the operator's server-side log. `context` (empty for the framing
    // checks) carries the public grant fields (channel/holder hex, advertised endpoint)
    // that let a live operator pin a refusal — never a private key or the possession
    // challenge/signature bytes.
    async fn refuse<W: AsyncWrite + Unpin>(
        send: &mut W,
        tag: &str,
        context: &str,
        reason: BoxError,
        peer: std::net::SocketAddr,
    ) -> BoxError {
        // #248-follow: `observed` (the real remote address, QUIC or TCP) was already in
        // scope everywhere this is called from -- just never included in the log line, so
        // an operator watching a repeated refusal (e.g. a stale/leaked client retrying a
        // channel-join for a since-deleted channel/holder forever) had no way to tell WHO
        // was doing it, only that it was happening. Every other tagged refusal below now
        // passes its own `observed` through.
        if context.is_empty() {
            eprintln!("ct-edge: channel-join NO [{tag}] peer={peer}: {reason}");
        } else {
            eprintln!("ct-edge: channel-join NO [{tag}] peer={peer} {context}: {reason}");
        }
        let _ = send.write_all(&encode_channel_refusal(tag)).await;
        let _ = send.shutdown().await;
        reason
    }

    // #105: bound the framed request + possession round-trip so a peer that opens the
    // stream but never submits a valid join can't wedge the broker's serial round loop.
    let read = async {
    // Length-framed request so the presenter's send stream stays open for the
    // possession challenge-response below.
    let mut len_buf = [0u8; 2];
    // #125: log the bare-I/O failure paths too (no `NO` ack — the stream is already
    // broken), tagged `io-*` so `grep 'channel-join NO'` surfaces an I/O drop (early
    // half-close, reset, an ALPN-acceptor stream hiccup) alongside validation refusals.
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| { eprintln!("ct-edge: channel-join NO [io-len]: {e}"); e })?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1024 {
        return Err(refuse(&mut send, "len-oob", "", "channel join request length out of range".into(), observed).await);
    }
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|e| { eprintln!("ct-edge: channel-join NO [io-body]: {e}"); e })?;

    let req = match ChannelJoinRequest::decode(&bytes) {
        Ok(r) => r,
        Err(_) => {
            return Err(refuse(&mut send, "malformed", "", "malformed channel join request".into(), observed).await);
        }
    };
    // The public grant fields that identify a live refusal to the operator: the channel
    // id + holder key hex (both public grant bytes — never a secret). Reused verbatim in
    // every post-decode refusal log below so a `[not-member]`/`[grant-verify]`/`[possession]`
    // line can be pinned to a specific channel + holder.
    let grant_ctx = format!(
        "channel={} holder={}",
        hex_of(&req.grant.grant.channel.0),
        hex_of(&req.grant.grant.holder),
    );
    // #81 gap 3 / #121: the advertised endpoint must be a safe, dialable socket address —
    // OR the explicit relay-only sentinel for a NAT-only member that joins via relay only.
    // A private/loopback address is still refused (the sentinel is not an address, so it
    // can't smuggle a LAN SSRF target; `safe_endpoint` is untouched).
    if !admissible_endpoint(&req) {
        return Err(refuse(
            &mut send,
            "endpoint",
            &format!("endpoint={}", req.endpoint),
            "unsafe advertised endpoint".into(),
            observed,
        )
        .await);
    }
    // #546: the check above rules out INTERNAL targets; this one rules out third parties.
    // Same refusal category on the wire ("endpoint" already means "advertised endpoint
    // unsafe/undialable"), so no new token and no risk to the <32-byte refusal frame (#524).
    // Off by default -- see `require_attested_endpoint`.
    if require_attested_endpoint()
        && !req.is_relay_only()
        && !endpoint_is_attested(&req.endpoint, observed.ip())
    {
        return Err(refuse(
            &mut send,
            "endpoint",
            &format!("endpoint={} observed={}", req.endpoint, observed.ip()),
            "advertised endpoint not corroborated by the observed source address".into(),
            observed,
        )
        .await);
    }
    // #81 gap 2: the holder must be a current member; `authorize` yields the
    // operator key only then, so a revoked member is refused here.
    let (operator, member_noise, member_attest) =
        match authorize(req.grant.grant.channel, req.grant.grant.holder).await {
            Some(t) => t,
            None => {
                return Err(DefinitiveJoinRefusal::boxed(
                    refuse(&mut send, "not-member", &grant_ctx, "unknown channel or holder not a member".into(), observed).await,
                ));
            }
        };
    // #415: `verify_stateless` here is deliberate, not an oversight -- the fresh
    // challenge + `verify_holder_possession` immediately below independently
    // defeats replay, stronger than a seen-nonce cache.
    if let Err(e) = verify_stateless(&operator, &req.grant, now) {
        return Err(refuse(&mut send, "grant-verify", &grant_ctx, format!("channel grant rejected: {e}").into(), observed).await);
    }
    // #81 gap 1: a signed grant is bearer bytes until the presenter proves it holds
    // the `holder` private key. The edge picks a fresh single-use challenge; the
    // presenter must return an ed25519 signature over it under `holder`. A stolen
    // grant (exfiltrated wire bytes) cannot answer, and a captured old signature
    // can't be replayed against a new challenge.
    // ct-agent#36: this challenge is the holder key's entire signing contract with an
    // edge it does not otherwise trust -- `holder.sign(&challenge)` on the client side
    // signs it with NO domain-separation prefix. Safe only because every generator of
    // this challenge (this one, and `relay_gate.rs`'s TLS-`:443` sibling) draws it fresh
    // from the OS CSPRNG on every call, never a value the caller can steer or replay.
    // Weakening either property (predictable bytes, reuse across calls) at ANY generator
    // would turn the holder key into a raw signing oracle for that path.
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    send.write_all(&challenge)
        .await
        .map_err(|e| { eprintln!("ct-edge: channel-join NO [io-challenge]: {e}"); e })?;
    let mut sig = [0u8; 64];
    if recv.read_exact(&mut sig).await.is_err()
        || !verify_holder_possession(&req.grant.grant.holder, &challenge, &sig)
    {
        return Err(DefinitiveJoinRefusal::boxed(
            refuse(&mut send, "possession", &grant_ctx, "holder possession proof failed".into(), observed).await,
        ));
    }
    Ok((send, recv, req, operator, member_noise, member_attest, observed))
    };
    match tokio::time::timeout(join_timeout, read).await {
        Ok(r) => r,
        Err(_) => {
            // #124: the timeout drops the stalled connection without a wire ack (as before);
            // log it under the same greppable scheme so an operator sees the stall too.
            eprintln!("ct-edge: channel-join NO [timeout]: join not submitted within {join_timeout:?} — dropping stalled connection (#105)");
            Err("channel join not submitted within the timeout — dropping stalled connection (#105)".into())
        }
    }
}

/// Admit a channel join over an already-TLS-accepted `:443` front-door stream —
/// the broker's **TLS-TCP accept leg** (#106 dispatch-transport). The broker speaks
/// QUIC, but `:443` is TLS-over-TCP; a member whose restrictive network blocks the
/// channel UDP/TCP ports reaches the same admission through the front door, which
/// terminates TLS over TCP. `stream` is the already-TLS-accepted duplex (a
/// `tokio_rustls` server stream — any `AsyncRead + AsyncWrite + Unpin`); this splits
/// it into read/write halves with [`tokio::io::split`] and runs the identical
/// [`read_channel_join_on_stream`] admission (length-framed [`ChannelJoinRequest`],
/// membership + grant verification, single-use holder-possession challenge) over
/// them — so a real TLS-over-TCP stream is admitted exactly as a QUIC bi-stream is.
/// On success the **reunited full-duplex stream** is returned (the read half is not
/// consumed by admission), alongside the admitted request/keys, so the caller can hand
/// it straight to [`finish_relay_pair_over_streams`] to relay-splice two `:443` members
/// end-to-end (#106 complete-wire443).
pub async fn admit_channel_join_on_duplex<S, F, Fut>(
    stream: S,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
) -> Result<
    (S, ChannelJoinRequest, [u8; 32], Option<[u8; 32]>, Option<[u8; 64]>, std::net::SocketAddr),
    BoxError,
>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1: the `:443` front door terminates TLS over TCP, so its accept loop knows
    // the member's reflexive source from the accepted `TcpStream`'s `peer_addr()` and passes
    // it as `observed` — this stream-generic core never calls `remote_address()` itself.
    let (recv, send) = tokio::io::split(stream);
    let (send, recv, req, operator, member_noise, member_attest, observed) =
        read_channel_join_on_stream(send, recv, observed, now, join_timeout, authorize).await?;
    // Reunite the split halves back into the original stream (`ReadHalf::unsplit`), so
    // the post-admission data path is the whole duplex — the read half is no longer
    // trapped inside admission and the caller can relay-splice it.
    Ok((recv.unsplit(send), req, operator, member_noise, member_attest, observed))
}

/// The bound on a single connection's join read (#105). A legitimate join completes
/// in one CP `authorize` HTTP round-trip plus a local possession exchange; anything
/// slower is a slow/broken/hostile client whose stalled connection would otherwise
/// wedge the broker's serial round loop, so it is dropped and the loop moves on.
const JOIN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// #452: bound completing the QUIC handshake itself on an already-accepted incoming
/// connection (`admit_incoming_member`'s `incoming.await`) -- the channel-broker analog of
/// [`crate::serve::FRONT_DOOR_TLS_ACCEPT_TIMEOUT`]/`TCP_FALLBACK_ADMISSION_TIMEOUT`. Without
/// this a peer that starts but never completes the handshake held its #450 cap permit (now
/// carried on the spawned admission task's [`AdmittedMember`]) forever, one of the "QUIC
/// channel endpoints have neither a cap nor a timeout" gaps #452 identified (the cap landed in
/// #450; this is the matching timeout). Same 10s value as the other public listeners' handshake
/// bounds for consistency -- a real QUIC handshake is a handful of round trips, not a long-lived
/// exchange.
const QUIC_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept one QUIC connection from `endpoint` and read its channel-join via
/// [`read_join_on_connection`]. The standalone entrypoint used by the broker's own
/// tests and by any dedicated channel-rendezvous endpoint; the live edge instead calls
/// `read_join_on_connection` directly on a connection dispatched by its accept loop.
async fn accept_and_read_join<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: &F,
) -> Result<
    (
        quinn::Connection,
        quinn::SendStream,
        ChannelJoinRequest,
        [u8; 32],
        Option<[u8; 32]>,
        Option<[u8; 64]>,
        std::net::SocketAddr,
    ),
    BoxError,
>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    // #128: tag the QUIC connection-handshake phase so a peer that closes here (vs. at the
    // bi-stream open below) is distinguishable in the accept_member catch-all log — the
    // QUIC analog of #127's `:443` TLS-accept tag.
    let conn = incoming
        .await
        .map_err(|e| format!("[quic-handshake] {e}"))?;
    match read_join_on_connection(&conn, now, JOIN_READ_TIMEOUT, authorize).await {
        Ok((send, req, operator, noise, attest, observed)) => {
            Ok((conn, send, req, operator, noise, attest, observed))
        }
        Err(e) => {
            // #129-follow: a refusal wrote `NO` to the stream; keep the connection alive
            // briefly so the peer reads the NO before teardown, instead of it racing to an
            // empty read the client can't classify (broken-vs-refused). Detached + bounded, so
            // it does NOT block the concurrent accept loop; a dropped conn's `closed()` returns
            // at once. This makes the client's #129 empty-vs-NO distinction reliable over QUIC.
            let held = conn.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), held.closed()).await;
            });
            Err(e)
        }
    }
}

/// The post-accept admission of ONE already-accepted incoming connection: finish the QUIC handshake,
/// read + authorize the channel-join, and return the [`AdmittedMember`]. Split out from
/// [`accept_and_read_join`] so [`run_channel_broker_loop`] can `spawn` it per connection — the slow
/// part (grant verification + possession-proof challenge-response) then runs OFF the accept loop, so
/// one in-flight admission can't serialize every other channel's admission on this edge (#203).
///
/// `permit` (#451) is the [`crate::state::ConnectionCap`] permit `run_channel_broker_loop` already
/// acquired at accept time — it is moved onto the returned [`AdmittedMember`] (not just held as a
/// task-local binding) so it travels with the connection through however long it actually lives:
/// parked in the [`ChannelPairer`] awaiting a partner, handed to the pair completer, or dropped here
/// on an admission failure. `None` on an error path (this function's own early returns) is correct —
/// the connection is being torn down either way, so releasing its permit immediately is right.
async fn admit_incoming_member<F, Fut>(
    incoming: quinn::Incoming,
    now: UnixSeconds,
    authorize: &F,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<AdmittedMember, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #452 parity: bound the QUIC handshake itself, same as the front door's/TCP-fallback's TLS
    // accept -- previously unbounded here (a peer that opens the TCP 5-tuple / initial UDP
    // datagram but never completes the handshake held its accept-loop task, and its #450 cap
    // permit, forever).
    let conn = tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| -> BoxError { "[quic-handshake] handshake not completed within the timeout".into() })?
        .map_err(|e| format!("[quic-handshake] {e}"))?;
    match read_join_on_connection(&conn, now, JOIN_READ_TIMEOUT, authorize).await {
        Ok((send, req, operator, noise, attest, observed)) => {
            // #546: measure before deciding. Refusing an uncorroborated endpoint would be a
            // wire-behaviour change that could lock out legitimate members (dual-stack, or
            // shapes nobody has enumerated yet), so this counts first and refuses nothing.
            note_endpoint_attestation_with(
                classify_endpoint(&req.endpoint, observed.ip()),
                &req.endpoint,
                observed.ip(),
            );
            Ok(AdmittedMember { conn, send, req, operator, noise, attest, observed, _permit: permit })
        }
        Err(e) => {
            // #129-follow: keep the connection alive briefly so the peer reads the `NO` refusal
            // before teardown (same as accept_and_read_join). Detached + bounded.
            let held = conn.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), held.closed()).await;
            });
            Err(e)
        }
    }
}

/// Accept one channel-join over QUIC (AF2d-transport-a): read the presented
/// [`ChannelJoinRequest`], authorize the holder + verify its grant (via `authorize`,
/// wired to the control-plane channel registry — see [`accept_and_read_join`]),
/// reply `OK`/`NO`, and return the request on success. This is the edge admission
/// gate for a *single* participant; [`broker_channel_rendezvous`] pairs two.
pub async fn resolve_channel_join<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelJoinRequest, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    let (conn, mut send, req, _op, _noise, _attest, _observed) =
        accept_and_read_join(endpoint, now, &authorize).await?;
    send.write_all(b"OK").await?;
    send.finish()?;
    conn.closed().await; // hold the connection so the peer reads the ack
    Ok(req)
}

/// Marker wrapper for a **definitive** channel-join refusal -- one the presenting
/// client can never turn into a success by retrying (`[not-member]`: the channel or
/// holder no longer exists; `[possession]`: it cannot prove it holds the holder key).
/// Everything else (timeouts, malformed frames, I/O drops, grant-verify, which clock
/// skew can trip transiently) stays a plain error.
///
/// This is the typed seam the per-IP penalty (`crate::state::JoinRefusalPenalty`)
/// keys on: the accept loops downcast the admission error to decide whether to count
/// it, instead of string-matching log text. Calibrated against the 2026-08-13 storm,
/// #517 V1: process-wide tally of CHANNEL relay bytes (both directions) and
/// completed splices -- the channel plane's counterpart to the state-held
/// per-plane relay counters. Statics rather than state plumbing because the
/// completers deliberately have no EdgeState handle (they are transport-generic
/// and test-driven standalone); same precedent as the #508 rate-limit gate.
static CHANNEL_SPLICE_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CHANNEL_SPLICES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// #517 V1 (Nachtrag): completed RENDEZVOUS pairings -- the ones where the edge handed
/// each side the other's endpoint and left the data path. The counterpart the splice
/// counter needs to be readable at all: on its own, `splices == 0` means both "every
/// session went direct" and "no session happened", and the offload question turns on
/// exactly that difference.
static CHANNEL_RENDEZVOUS_PAIRS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// #517 V1: `(channel_relay_bytes_total, channel_splices_total)` for `/metrics`.
pub fn channel_relay_totals() -> (u64, u64) {
    (
        CHANNEL_SPLICE_BYTES.load(std::sync::atomic::Ordering::Relaxed),
        CHANNEL_SPLICES.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// #546 enforcement: may `advertised` be dialed, given the source address the edge observed?
///
/// The rule, refined by the first field measurement (which refuted the naive form): compare
/// **only when the observed source is itself global-unicast**. A member the edge sees on a
/// private address is behind a NAT or co-located with the edge, and its observed address then
/// carries no information about its public identity -- demanding equality there would refuse
/// perfectly ordinary members. The first reading was 4 mismatches, 0 matches, every one of
/// them `advertised <public> / observed 172.18.0.1` (an agent behind the Docker bridge).
///
/// Where the observed address IS global, an advertised address of the same family must equal
/// it. That removes the primitive rather than filtering it: with the IP fixed to what the
/// edge saw, a member can only ever point its partner at a port on the machine that just
/// proved it holds the channel key -- never at a third party. A different family is allowed
/// (dual-stack: reach the edge over v4, advertise the v6 listener) and counted separately.
///
/// Not an address at all (the relay-only sentinel) is not this check's business --
/// `admissible_endpoint` already ruled on it.
pub fn endpoint_is_attested(advertised: &str, observed: std::net::IpAddr) -> bool {
    // One classifier, one rule: `Mismatch` is by construction the only outcome where the
    // observed address was global AND the advertised one differed in the same family.
    // Deriving the decision from the classification (rather than re-testing the same
    // conditions here) is what keeps metric and enforcement from drifting apart.
    classify_endpoint(advertised, observed) != EndpointAttestation::Mismatch
}

/// #546: is enforcement switched on? Default **off** -- the measurement runs first, and
/// flipping this is an operator decision with the counters in hand. Only the literal `1`
/// enables it, matching the control plane's background-loop flags rather than the flood
/// limits' `off/false/none` vocabulary (the two differ; see the runbook).
fn require_attested_endpoint() -> bool {
    std::env::var("CT_EDGE_REQUIRE_ATTESTED_ENDPOINT").ok().as_deref() == Some("1")
}

/// #552: the startup line for [`require_attested_endpoint`], stated in both directions.
///
/// A control that logs a line when armed and nothing when off cannot be checked by reading
/// the log: silence means "off" and "this build predates the line" and "the log scrolled",
/// which is precisely the failure this exists to catch -- an operator arms it in `.env`,
/// a later redeploy drops the line, and the door reopens with no trace. So the OFF case is
/// the one that must speak.
///
/// It also reports the value that was actually parsed, not the raw string: only the literal
/// `1` arms this, so an operator who wrote `true` or `yes` has enforcement OFF while their
/// config file reads as though it were on. That mistake is invisible everywhere else.
pub fn attested_endpoint_startup_line() -> String {
    attested_endpoint_startup_line_for(std::env::var("CT_EDGE_REQUIRE_ATTESTED_ENDPOINT").ok().as_deref())
}

/// Pure core of [`attested_endpoint_startup_line`], so the wording is testable without
/// mutating process-global environment state from a test (same split as
/// `admin_gate_startup_line`).
fn attested_endpoint_startup_line_for(raw: Option<&str>) -> String {
    match raw.map(|s| s.to_string()) {
        Some(v) if v == "1" => {
            "ct-edge: endpoint attestation ENFORCED -- a channel join observed on a global \
             address that advertises a different one of the same family is refused \
             (CT_EDGE_REQUIRE_ATTESTED_ENDPOINT=1, #546)"
                .to_string()
        }
        Some(v) => format!(
            "ct-edge: endpoint attestation OFF -- CT_EDGE_REQUIRE_ATTESTED_ENDPOINT is set to \
             {v:?}, and ONLY the literal \"1\" arms it. Mismatches are counted, not refused \
             (#546)"
        ),
        None => "ct-edge: endpoint attestation OFF -- mismatches are counted, not refused. Set \
                 CT_EDGE_REQUIRE_ATTESTED_ENDPOINT=1 to enforce (#546)"
            .to_string(),
    }
}

/// #546: how a member's ADVERTISED endpoint relates to the address the edge actually
/// observed it connect from. Counting only -- nothing is refused on this basis yet.
///
/// Why it matters: `is_global_unicast` (#94/#121/#267) keeps a member from pointing its
/// partner at anything INTERNAL -- loopback, RFC1918, CGNAT, link-local, cloud metadata,
/// including the IPv4-in-IPv6 forms. It does not keep it from pointing at an arbitrary
/// PUBLIC host: an admitted-but-compromised member can name any global address and have
/// its counterpart dial it once per pairing. The address the edge observed is attested by
/// an independent party (the connection itself); the advertised one is a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointAttestation {
    /// Advertised IP equals the observed source IP -- the claim is corroborated.
    Matches,
    /// Different address families (member connected over v4 and advertises v6, or vice
    /// versa). A dual-stack host legitimately does this, so it must NOT be treated as a
    /// mismatch -- it is counted separately precisely so the two never get conflated.
    CrossFamily,
    /// Same family, different address, and the edge observed the member on a **global**
    /// address -- so equality was meaningful and did not hold. This is the case the whole
    /// measurement exists for, and the only one enforcement refuses.
    Mismatch,
    /// Same family, different address, but the edge observed the member on a **private**
    /// address (co-located, or behind a NAT). Equality is structurally impossible there, so
    /// this is not evidence of anything. Split from `Mismatch` because merging them makes
    /// the counter unable to answer the question it was collected for: with one bucket, an
    /// operator reading `mismatch=29` cannot tell whether enforcing would refuse 29 members
    /// or none.
    Unobservable,
    /// The relay-only sentinel or an unparseable endpoint -- not an address at all.
    NoAddress,
}

/// Pure classifier for [`EndpointAttestation`] -- caller supplies both values, so this is
/// testable without a live connection.
pub fn classify_endpoint(advertised: &str, observed: std::net::IpAddr) -> EndpointAttestation {
    let Ok(addr) = advertised.parse::<std::net::SocketAddr>() else {
        return EndpointAttestation::NoAddress;
    };
    let adv = addr.ip();
    if adv == observed {
        EndpointAttestation::Matches
    } else if adv.is_ipv4() != observed.is_ipv4() {
        EndpointAttestation::CrossFamily
    } else if ct_common::channel::is_global_unicast(std::net::SocketAddr::new(observed, 0)) {
        EndpointAttestation::Mismatch
    } else {
        EndpointAttestation::Unobservable
    }
}

static ENDPOINT_MATCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ENDPOINT_CROSS_FAMILY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ENDPOINT_MISMATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ENDPOINT_NO_ADDRESS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ENDPOINT_UNOBSERVABLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// #546: `(matches, cross_family, mismatch, no_address, unobservable)` for `/metrics`.
pub fn endpoint_attestation_totals() -> (u64, u64, u64, u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        ENDPOINT_MATCHES.load(Relaxed),
        ENDPOINT_CROSS_FAMILY.load(Relaxed),
        ENDPOINT_MISMATCH.load(Relaxed),
        ENDPOINT_NO_ADDRESS.load(Relaxed),
        ENDPOINT_UNOBSERVABLE.load(Relaxed),
    )
}

fn note_endpoint_attestation_with(a: EndpointAttestation, advertised: &str, observed: std::net::IpAddr) {
    use std::sync::atomic::Ordering::Relaxed;
    let c = match a {
        EndpointAttestation::Matches => &ENDPOINT_MATCHES,
        EndpointAttestation::CrossFamily => &ENDPOINT_CROSS_FAMILY,
        EndpointAttestation::Mismatch => &ENDPOINT_MISMATCH,
        EndpointAttestation::NoAddress => &ENDPOINT_NO_ADDRESS,
        EndpointAttestation::Unobservable => &ENDPOINT_UNOBSERVABLE,
    };
    let n = c.fetch_add(1, Relaxed) + 1;
    // Only the uncorroborated case is worth a line, and only occasionally: a member that
    // re-parks every park-TTL would otherwise repeat it forever (the #530 lesson).
    // The two shapes get DIFFERENT log policies. `Unobservable` is steady-state noise from
    // co-located agents and is throttled hard; `Mismatch` is the actionable one and every
    // occurrence is logged until it becomes frequent. Sharing one throttle meant a rare
    // actionable case could fall between the powers of two and never be printed at all.
    let should_log = match a {
        EndpointAttestation::Mismatch => n <= 20 || n % 100 == 0,
        EndpointAttestation::Unobservable => n.is_power_of_two() || n % 1000 == 0,
        _ => false,
    };
    if should_log {
        // Both addresses named: a bare count cannot be acted on. The two shapes behind
        // this bucket need opposite responses -- a member behind a NAT the edge sees as
        // private simply CANNOT match (equality is meaningless there), while a member the
        // edge sees on a global address that advertises a different global address is the
        // case the whole measurement is about. Without the addresses the operator cannot
        // tell which one they have, and the number is unusable for the enforcement
        // decision it exists to inform.
        eprintln!(
            "ct-edge: #546 advertised {advertised} but observed source {observed} \
             (observed_global={}, {n} so far) -- counting only, nothing refused",
            ct_common::channel::is_global_unicast(std::net::SocketAddr::new(observed, 0))
        );
    }
}

/// #517 V1 (Nachtrag): completed rendezvous pairings for `/metrics`.
pub fn channel_rendezvous_pairs_total() -> u64 {
    CHANNEL_RENDEZVOUS_PAIRS.load(std::sync::atomic::Ordering::Relaxed)
}

fn note_channel_rendezvous_pair() {
    CHANNEL_RENDEZVOUS_PAIRS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// #555: process-wide registry of channel splices that are **currently carrying bytes**.
///
/// Membership is checked once, at admission. After that `finish_quic_pair_inner` /
/// `finish_stream_pair_inner` copy bytes and consult nothing, so removing a member from a
/// channel had no effect on their live connection — measured: the removed member kept
/// receiving and answering indefinitely. `channel_remove_member` is a real routed endpoint,
/// so that is a control an operator can exercise and watch do nothing.
///
/// Process-wide rather than threaded through the completers on purpose. The resolver lives
/// far from the splice — passing it down would touch every completer, wrapper and caller,
/// and a signature sweep that wide is exactly where a path gets missed. The same reasoning
/// (and the same `static`) as the splice/park counters above.
static LIVE_SPLICES: std::sync::Mutex<Option<LiveSplices>> = std::sync::Mutex::new(None);

/// #555: what a cut splice reports. One shared constant so both completer families say the
/// same thing — a member reading their logs should not have to know which transport they
/// were on to recognise the same event.
pub(crate) const SPLICE_CUT_BY_REMOVAL: &str =
    "channel splice cut: this member is no longer authorized on the channel (#555)";

/// #555: how often a live splice's membership is re-checked.
///
/// One `CACHE_TTL` (30s, `channel_authorize.rs`). Deliberately equal rather than a multiple:
/// that module's own promise is that a revoked member rides a stale entry for seconds, not
/// minutes, and a re-check slower than the cache it reads through would quietly break that
/// promise for live sessions while appearing to honour it for new joins. The cost is one
/// control-plane round trip per distinct `(channel, holder)` with a live splice per interval
/// -- proportional to concurrent calls, not to traffic.
const MEMBERSHIP_RECHECK_SECS: u64 = 30;

type SpliceKey = ([u8; 32], [u8; 32]);

#[derive(Default)]
struct LiveSplices {
    next_id: u64,
    entries: std::collections::HashMap<SpliceKey, Vec<(u64, tokio::sync::watch::Sender<bool>)>>,
}

/// Registration handle for one member's leg of a live splice. Deregisters on drop, so a
/// splice that ends normally leaves nothing behind for the poller to ask about.
pub(crate) struct SpliceGuard {
    key: SpliceKey,
    id: u64,
    rx: tokio::sync::watch::Receiver<bool>,
}

impl SpliceGuard {
    /// Resolves when this leg has been cut because its membership went away.
    pub(crate) async fn cut(&self) {
        let mut rx = self.rx.clone();
        loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Drop for SpliceGuard {
    fn drop(&mut self) {
        let mut g = LIVE_SPLICES.lock_safe();
        if let Some(live) = g.as_mut() {
            if let Some(v) = live.entries.get_mut(&self.key) {
                v.retain(|(id, _)| *id != self.id);
                if v.is_empty() {
                    live.entries.remove(&self.key);
                }
            }
        }
    }
}

/// #555: register one member of a splice that is about to start carrying bytes.
pub(crate) fn register_live_splice(channel: &ChannelId, holder: &[u8; 32]) -> SpliceGuard {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let key = (channel.0, *holder);
    let mut g = LIVE_SPLICES.lock_safe();
    let live = g.get_or_insert_with(LiveSplices::default);
    live.next_id += 1;
    let id = live.next_id;
    live.entries.entry(key).or_default().push((id, tx));
    SpliceGuard { key, id, rx }
}

/// #555: every `(channel, holder)` with at least one live splice leg — what the membership
/// poller has to ask the control plane about.
pub(crate) fn live_splice_members() -> Vec<SpliceKey> {
    let g = LIVE_SPLICES.lock_safe();
    g.as_ref().map(|l| l.entries.keys().copied().collect()).unwrap_or_default()
}

/// #555: cut every live splice leg held by `holder` on `channel`. Returns how many legs
/// were signalled, so the caller can log a real number instead of "probably did something".
pub(crate) fn cut_live_splices(channel: &[u8; 32], holder: &[u8; 32]) -> usize {
    let g = LIVE_SPLICES.lock_safe();
    match g.as_ref().and_then(|l| l.entries.get(&(*channel, *holder))) {
        Some(v) => {
            for (_, tx) in v {
                let _ = tx.send(true);
            }
            v.len()
        }
        None => 0,
    }
}

/// #555: first four bytes as hex -- the channel/holder fields are public identifiers, the
/// same shortening the pairer reapers already log.
fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// #555: one sweep — ask the resolver about every `(channel, holder)` that currently has a
/// live splice, and cut the ones it no longer authorizes. Returns the number of legs cut.
///
/// Split out from the spawning loop so the decision is testable without a timer: the whole
/// risk here is the OVER-firing direction (cutting a healthy call), and that must be provable
/// rather than observed to not have happened yet.
pub(crate) async fn sweep_live_splice_memberships(
    resolver: &std::sync::Arc<dyn crate::serve::ChannelMemberResolver>,
) -> usize {
    let mut cut = 0;
    for (channel, holder) in live_splice_members() {
        // A transport failure must NOT cut. `resolve` already fails closed for ADMISSION,
        // where refusing an unproven claim is right; here the membership was proven once
        // and a CP blip is not evidence against it. Only a definitive "not a member"
        // ends a call in progress -- anything else and one control-plane restart would
        // drop every conversation on the edge.
        if resolver.membership_revoked(ChannelId(channel), holder).await {
                let n = cut_live_splices(&channel, &holder);
                if n > 0 {
                    eprintln!(
                        "ct-edge: cutting {n} live splice leg(s) for holder {} on channel {} -- \
                         membership was removed (#555)",
                        short_hex(&holder),
                        short_hex(&channel)
                    );
                }
            cut += n;
        }
    }
    cut
}

/// #555: run [`sweep_live_splice_memberships`] forever. Spawned once where the resolver
/// lives; does nothing at all until some splice registers, so an edge with no channel
/// traffic never talks to the control plane on this account.
pub async fn run_membership_recheck_loop(
    resolver: std::sync::Arc<dyn crate::serve::ChannelMemberResolver>,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(MEMBERSHIP_RECHECK_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if live_splice_members().is_empty() {
            continue;
        }
        sweep_live_splice_memberships(&resolver).await;
    }
}

fn note_channel_splice(bytes: (u64, u64)) {
    CHANNEL_SPLICE_BYTES.fetch_add(bytes.0.saturating_add(bytes.1), std::sync::atomic::Ordering::Relaxed);
    CHANNEL_SPLICES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// #530: process-wide tally of channel-pairer parks reaped past their TTL with no
/// partner (every reaper: the `:443` front-door/shared reaper in `serve.rs` and the
/// ws-channel standalone reaper). The channel plane's counterpart to
/// `ct_edge_tcp_fallback_reaped_total` (#522): its RATE is the lone-park churn rate,
/// and a sustained CHANGE in that rate is the regression signal the log line alone
/// could never provide (it drowned in its own steady-state repetition). Static rather
/// than state plumbing for the same reason as `CHANNEL_SPLICE_BYTES` above: the
/// reapers deliberately have no `EdgeState` handle.
static CHANNEL_PARK_REAPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// #530: `ct_edge_channel_park_reaped_total` for `/metrics`.
pub fn channel_park_reaped_total() -> u64 {
    CHANNEL_PARK_REAPED.load(std::sync::atomic::Ordering::Relaxed)
}

/// #558: `:443` channel legs that reached the pairer, split by whether the client negotiated
/// the park-keepalive ALPN (`ct-edge-channel-ka`) or the plain one.
///
/// Both #500's NUL ticks and #506's longer park TTL apply **only** to a keepalive-negotiated
/// leg. Without this split there is no way to tell, from outside a running edge, whether any
/// leg is negotiated at all -- and an operator who raises `CT_EDGE_KA_PARK_TTL_SECS` and sees
/// no change cannot distinguish "the setting was ignored" from "the setting had nothing to
/// apply to", which are opposite problems with opposite fixes.
static CHANNEL_PARK_LEGS_KA: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CHANNEL_PARK_LEGS_PLAIN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// #558: `(keepalive_negotiated, plain)`.
pub fn channel_park_leg_totals() -> (u64, u64) {
    (
        CHANNEL_PARK_LEGS_KA.load(std::sync::atomic::Ordering::Relaxed),
        CHANNEL_PARK_LEGS_PLAIN.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// #558: count one admitted `:443` leg. Taken from the SAME `keepalive` value that drives the
/// pump and the TTL choice, rather than re-derived — a counter that decided for itself what
/// "negotiated" means could disagree with the behaviour it is supposed to describe.
fn note_channel_park_leg(keepalive: bool) {
    let c = if keepalive { &CHANNEL_PARK_LEGS_KA } else { &CHANNEL_PARK_LEGS_PLAIN };
    c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// #530: count one reaped lone park. Called for EVERY reap, including reaps whose
/// per-member log line the [`ReapLogThrottle`] suppresses — the metric is the
/// complete record, the log is the bounded diagnostic sample.
pub(crate) fn note_channel_park_reaped() {
    CHANNEL_PARK_REAPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Parks torn down because the SAME holder re-joined past the [`PARKS_PER_MEMBER`] queue
/// cap — [`PairOutcome::Superseded`].
///
/// Deliberately separate from [`CHANNEL_PARK_REAPED`], because the two are indistinguishable
/// everywhere else and mean opposite things. On the wire they are identical **by design**:
/// a superseded leg gets the same `EX` token / `park-expired:` close reason a TTL reap
/// sends, so a live client re-parks on the same rung instead of misreading the close as a
/// refusal. Toward the operator that sameness was **not** a decision, it was an omission —
/// a supersede incremented nothing and logged nothing at all, while a TTL reap has a
/// counter, a throttled per-member line and a window summary.
///
/// The two questions they answer are different:
///
/// * a rising reap rate means *nobody is coming* — idle parks aging out (tune the TTL, #506);
/// * a rising supersede rate means *the same holder keeps re-joining* before its partner
///   arrives, i.e. a client retry storm — the failure #231/#250 exist for.
///
/// Without this split both look like park churn, and the second one looked like nothing:
/// legs vanished without incrementing the reap counter, so parks-minus-reaps drifted upward
/// and read as "lots of healthy live parks".
static CHANNEL_PARK_SUPERSEDED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `ct_edge_channel_park_superseded_total` for `/metrics`.
pub fn channel_park_superseded_total() -> u64 {
    CHANNEL_PARK_SUPERSEDED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Count one park torn down by a same-holder re-join. Counted, not logged per occurrence:
/// a supersede storm is by definition a flood, and one line each would reproduce the flood
/// in the log — the same argument the reap line's throttle already makes.
fn note_channel_park_superseded() {
    CHANNEL_PARK_SUPERSEDED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// #530: how long one reap-log summary window lasts. Within a window, each
/// (channel,holder) pair gets ONE full per-member log line (its first reap); further
/// reaps of the same pair only feed the window's aggregate, spoken as a single
/// summary line when the window rolls over.
pub(crate) const REAP_LOG_SUMMARY_WINDOW_SECS: u64 = 600;

/// #530: hard cap on the (channel,holder) pairs a [`ReapLogThrottle`] tracks per
/// window. Pairs arriving beyond the cap are counted WITHOUT identity (`untracked`
/// in the summary) and get no full line — this bounds both the map's memory and the
/// log volume against an attacker cycling many distinct channels. Far above the
/// steady-state reality (4 pairs measured live, 2026-08-15) so a legitimate
/// deployment never hits it.
pub(crate) const REAP_LOG_MAX_TRACKED_PAIRS: usize = 64;

/// #530: how many of the busiest pairs a window summary names explicitly.
pub(crate) const REAP_LOG_TOP_PAIRS: usize = 3;

/// #530: the reap sites' instantiation of the shared, memory-bounded log throttle
/// ([`crate::log_throttle::WindowLogThrottle`]), keyed on the `(channel_hex,
/// holder_hex)` pair.
///
/// Live-measured finding (2026-08-15): demo serve-loops park BY DESIGN forever, are
/// reaped every park-TTL cycle (~35 s) and immediately re-park (ct-agent#21 —
/// correct, untouched), so the per-member reap line repeated identically ~70x/10 min
/// (~10k/day) from the same 4 pairs and drowned real signals (e.g. the #508 line).
/// The throttle keeps the first reap of each pair fully logged, aggregates repeats,
/// and hands the reaper one [`crate::log_throttle::WindowSummary`] per window.
///
/// #533 generalized the decision core out of here (verbatim) so the `:443`
/// front-door's benign client-abort line could share ONE tested implementation
/// instead of carrying a second copy — the two sites differ only in the key they
/// aggregate on.
pub(crate) type ReapLogThrottle = crate::log_throttle::WindowLogThrottle<(String, String)>;

/// #530: what the reaper should do with one reap's per-member log line — the reap
/// sites' spelling of the shared [`crate::log_throttle::LogDecision`].
pub(crate) use crate::log_throttle::LogDecision as ReapLogDecision;

impl ReapLogThrottle {
    /// Note one reap of `(channel_hex, holder_hex)` at `now` and decide its log fate —
    /// the reap sites' spelling of [`crate::log_throttle::WindowLogThrottle::note`],
    /// which builds the owned pair key for them.
    pub(crate) fn note_reap(&mut self, now: UnixSeconds, channel_hex: &str, holder_hex: &str) -> ReapLogDecision {
        self.note(now, (channel_hex.to_owned(), holder_hex.to_owned()))
    }
}

/// where one stale client retried two `[not-member]` channels at 25-75ms cadence for
/// ~10 hours through a NAT shared with innocent tenants.
#[derive(Debug)]
pub struct DefinitiveJoinRefusal(BoxError);

impl DefinitiveJoinRefusal {
    /// Wrap `reason` for returning from admission -- kept as a helper so the refusal
    /// sites stay one-liners.
    fn boxed(reason: BoxError) -> BoxError {
        Box::new(DefinitiveJoinRefusal(reason))
    }
}

impl std::fmt::Display for DefinitiveJoinRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for DefinitiveJoinRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Whether `e` is a [`DefinitiveJoinRefusal`] -- the predicate the accept-path
/// penalty call sites share (QUIC broker loop, `:443` front-door arm).
pub fn is_definitive_join_refusal(e: &BoxError) -> bool {
    e.downcast_ref::<DefinitiveJoinRefusal>().is_some()
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The ` <noise> <holder> <attest>` suffix appended to `OK <endpoint>` carrying the
/// peer's attested Noise key, the peer's holder, and its holder-signed attestation
/// (#72 AF4 / #100 / #101) — so the paired agent can VERIFY the key is genuinely the
/// holder's before pinning it. Emitted only when both the Noise key and its attestation
/// are present (all-or-nothing — an initiator can't verify a key without its
/// attestation). `holder` is the peer's **grant-authenticated** holder (from the
/// verified grant, not the mutable registry), so a DB-tampered attestation over a
/// different key won't verify against it.
fn member_ack_suffix(noise: Option<[u8; 32]>, holder: &[u8; 32], attest: Option<[u8; 64]>) -> String {
    match (noise, attest) {
        (Some(n), Some(a)) => format!(" {} {} {}", hex_of(&n), hex_of(holder), hex_of(&a)),
        _ => String::new(),
    }
}

/// #276 piece 1: whether a paired pair's two edge-observed reflexive addresses share the
/// same public IP (same NAT/network) — the edge-attested fact a client needs before it may
/// safely try a private-range dial candidate against its peer (#137's SSRF guard still
/// applies to any candidate that ISN'T independently corroborated this way). Compares only
/// the IP, not the port: two members behind the same NAT get the same public IP but distinct
/// NAT-assigned ports.
fn same_public_ip(a: std::net::SocketAddr, b: std::net::SocketAddr) -> bool {
    a.ip() == b.ip()
}

/// A channel member that has cleared admission (`accept_and_read_join` /
/// [`read_join_on_connection`]): its live QUIC connection and reply stream, the
/// verified [`ChannelJoinRequest`] it presented, the operator key its grant was
/// verified under, and the peer key material to relay to its partner. This is the
/// unit the *admit* stage produces and the `finish_*_pair` *completers* consume —
/// the seam that lets a `ChannelPairer`-driven concurrent accept loop park a lone
/// arrival and hand off exactly two members once paired (#109-concurrent).
pub(crate) struct AdmittedMember {
    conn: quinn::Connection,
    send: quinn::SendStream,
    req: ChannelJoinRequest,
    operator: [u8; 32],
    noise: Option<[u8; 32]>,
    attest: Option<[u8; 64]>,
    /// #121 Phase B1: this member's **reflexive** (post-NAT) source as the edge observed it
    /// on the admitted connection — echoed back to the member as the `r=<addr>` ack token so
    /// it learns its punch address during live rendezvous pairing (the B1-follow slice).
    observed: std::net::SocketAddr,
    /// #451: the [`crate::state::ConnectionCap`] permit admitting this connection, carried on
    /// the value that OWNS the live socket rather than a task-local binding that drops when
    /// whichever function happens to return — so it stays held for as long as the connection
    /// genuinely does: through a park in the [`ChannelPairer`], through `complete(..).await`
    /// once paired, or released here immediately when there is no cap (`None`) or a test
    /// constructs a member directly (`accept_member`, used only by this module's own legacy
    /// serial-broker tests, always passes `None`). Never read, only held for its `Drop` --
    /// leading underscore so `-D dead_code` doesn't flag that as unused.
    _permit: Option<OwnedSemaphorePermit>,
}

/// The QUIC-native analog of [`SharedChannelPairer`] (which is stream-generic, for the
/// `:443`/ws-channel front doors): one `Arc` per QUIC channel-broker endpoint (relay,
/// rendezvous -- each gets its OWN, they are never shared with each other), constructed
/// by [`crate::serve::run_edge`] and passed into [`run_channel_broker_loop`] rather than
/// built internally, so `run_edge` can keep its own clone alive independently of the
/// loop's own lifetime (#400 -- see `run_channel_broker_loop`'s doc comment for why that
/// matters: an internally-constructed pairer would be dropped, force-closing every
/// parked member, the instant the loop returns on shutdown).
pub(crate) type SharedQuicChannelPairer =
    std::sync::Arc<std::sync::Mutex<ChannelPairer<AdmittedMember>>>;

/// Accept one QUIC connection and admit its channel-join, returning it as an
/// [`AdmittedMember`] ready to pair. Thin wrapper over `accept_and_read_join` that
/// packs the admitted tuple into the pairing unit both `broker_channel_*` functions
/// (and, later, the concurrent accept loop) consume.
async fn accept_member<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: &F,
) -> Result<AdmittedMember, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1-follow: the observed reflexive address is captured at admission and now
    // carried on `AdmittedMember` so `finish_rendezvous_pair` can echo it back as the
    // `r=<addr>` ack token — the member learns its punch address during live rendezvous
    // pairing (not only at the isolated admission seam).
    let (conn, send, req, operator, noise, attest, observed) =
        accept_and_read_join(endpoint, now, authorize).await?;
    Ok(AdmittedMember { conn, send, req, operator, noise, attest, observed, _permit: None })
}

/// Complete a **rendezvous** pairing for two already-admitted members: authorize the
/// pair under member A's operator key (`authorize_channel_pair` rejects a
/// cross-channel / incompatible / same-holder pair), then hand each side the OTHER's
/// advertised endpoint plus (when registered) the peer's attested Noise key +
/// attestation to VERIFY and pin — so an A2A session forms with no operator-conveyed
/// key. An unpairable pair gets `NO` on both sides. This is the behaviour-preserving
/// pair-completion tail of [`broker_channel_rendezvous`], split from admission so a
/// concurrent loop can `spawn` it per `ChannelPairer::offer` -> `Paired(a, b)`.
pub(crate) async fn finish_rendezvous_pair(
    a: AdmittedMember,
    b: AdmittedMember,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError> {
    finish_quic_pair_inner(a, b, now, QuicPairCompletion::EndpointSwap).await
}

/// How a completed **QUIC-native** pairing ends after both acks — the QUIC twin of
/// [`StreamPairCompletion`] (#511: the two families used to be ~40 duplicated lines
/// whose ack construction had already diverged once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicPairCompletion {
    /// Rendezvous: each side got the other's endpoint/keys; wait out both connections
    /// (the members dial each other directly / walk their own relay fallback).
    EndpointSwap,
    /// Relay: splice each side's next bi-stream through the edge.
    Splice,
}

/// The shared completion tail of [`finish_rendezvous_pair`] / [`finish_relay_pair`]:
/// authorize the pair, ack both sides, then run `completion`.
///
/// The ack line is the SAME on both completers — `OK <peer-endpoint><suffix> r=<own
/// observed> sp=<0|1>`:
/// - `r=<addr>` (#121 B1-follow, #104-follow): each side's OWN edge-observed reflexive,
///   the punch address / the input to the in-band relay→direct upgrade. Members reach
///   these completers over the direct QUIC broker port, so the reflexive is genuinely
///   meaningful (unlike `finish_relay_pair_over_streams`'s deliberately deferred case).
/// - `<suffix>` (#122/#101, #134-follow): the peer's attested Noise key + holder +
///   attestation. The relay completer historically omitted it, which made the #136
///   NAT-to-NAT DCUtR upgrade structurally impossible against a real edge — the
///   shared construction here is what prevents that class of divergence.
/// - `sp=<0|1>` (#276 piece 1): edge-attested same-public-IP fact gating LAN-local
///   dial candidates; always present, unlike the suffix's all-or-nothing convention.
///
/// Acks go through [`quic_ack_member`] (#148/#154/#155) so a mid-handoff drop names
/// the dead side (a transient race) instead of reading like a refusal.
async fn finish_quic_pair_inner(
    mut a: AdmittedMember,
    mut b: AdmittedMember,
    now: UnixSeconds,
    completion: QuicPairCompletion,
) -> Result<ChannelPairing, BoxError> {
    let refusal_label = match completion {
        QuicPairCompletion::EndpointSwap => "channel pair refused",
        QuicPairCompletion::Splice => "channel relay pair refused",
    };
    match authorize_channel_pair(&a.operator, &a.req.grant, &b.req.grant, now) {
        Ok(pairing) => {
            let sp = same_public_ip(a.observed, b.observed);
            let a_ack = format!(
                "OK {}{} r={} sp={}",
                b.req.endpoint,
                member_ack_suffix(b.noise, &b.req.grant.grant.holder, b.attest),
                a.observed,
                sp as u8
            );
            let b_ack = format!(
                "OK {}{} r={} sp={}",
                a.req.endpoint,
                member_ack_suffix(a.noise, &a.req.grant.grant.holder, a.attest),
                b.observed,
                sp as u8
            );
            quic_ack_member(&mut a.send, a_ack.as_bytes(), PairSide::A).await?;
            quic_ack_member(&mut b.send, b_ack.as_bytes(), PairSide::B).await?;
            match completion {
                QuicPairCompletion::EndpointSwap => {
                    // #517 V1 (Nachtrag): counted HERE, right after both acks land -- this
                    // is the moment the edge hands each side the other's endpoint and steps
                    // out of the data path. Without it the splice counter alone is
                    // ambiguous: zero splices reads as "everything went direct" and as
                    // "nothing happened at all", which are opposite conclusions from the
                    // same number. Paired with the splice counter it is the offload figure.
                    note_channel_rendezvous_pair();
                    a.conn.closed().await;
                    b.conn.closed().await;
                }
                QuicPairCompletion::Splice => {
                    let (init_conn, acc_conn) = if pairing.initiator_holder == a.req.grant.grant.holder {
                        (&a.conn, &b.conn)
                    } else {
                        (&b.conn, &a.conn)
                    };
                    // #555: both legs are registered for the lifetime of the copy, and the
                    // copy loses to either one being cut. Registered per MEMBER, not per
                    // pair: removing one participant must end that participant's session,
                    // and since a splice has exactly two ends, ending either ends both --
                    // which is correct, the remaining side is no longer talking to anyone.
                    let _ga = register_live_splice(&a.req.grant.grant.channel, &a.req.grant.grant.holder);
                    let _gb = register_live_splice(&b.req.grant.grant.channel, &b.req.grant.grant.holder);
                    // Both sides acked cleanly; a failure now is the splice itself, not a
                    // one-sided ack race.
                    let bytes = tokio::select! {
                        r = crate::relay::relay_initiator_to_acceptor(init_conn, acc_conn, "channel-relay") => {
                            r.map_err(|e| -> BoxError {
                                format!("channel relay splice ended after both sides acked: {e}").into()
                            })?
                        }
                        _ = _ga.cut() => return Err(SPLICE_CUT_BY_REMOVAL.into()),
                        _ = _gb.cut() => return Err(SPLICE_CUT_BY_REMOVAL.into()),
                    };
                    note_channel_splice(bytes); // #517 V1
                }
            }
            Ok(pairing)
        }
        Err(e) => {
            // #524: `pairing` — post-admission pair authorization refused. A distinct
            // category from the admission checkpoints: the member's grant/possession were
            // fine, the PAIR was not, which needs a different self-diagnosis (partner
            // mismatch) than "fix your grant".
            let refusal = encode_channel_refusal("pairing");
            let _ = a.send.write_all(&refusal).await;
            let _ = b.send.write_all(&refusal).await;
            let _ = a.send.finish();
            let _ = b.send.finish();
            // #753: do NOT return -- and thereby drop both `AdmittedMember`s -- yet. Dropping
            // the last handle of a `quinn::Connection` closes it implicitly, and a close sends
            // NO further data: the refusal `write_all`ed above is still sitting in quinn's send
            // buffer at this point (a stream write only enqueues; the endpoint driver transmits
            // asynchronously), so returning here discarded it. Both members then saw their
            // connection close with zero ack bytes and, per the ack contract (#23/#148),
            // classified a DEFINITIVE pairing refusal as a retryable dropped leg -- #524's
            // `pairing` category never reached a QUIC member (found by the shared-client
            // contract test `shared_client_surfaces_the_edges_framed_pairing_refusal_after_
            // possession_p2`, deterministic). Same remedy as the admission-refusal path's
            // #129-follow hold (`accept_and_read_join`): keep both connections alive until the
            // peer has read the refusal and closed, bounded so a peer that never closes cannot
            // pin this completer. Waited concurrently, so the bound is 2 s total, not 4 s.
            let hold = std::time::Duration::from_secs(2);
            let _ = tokio::join!(
                tokio::time::timeout(hold, a.conn.closed()),
                tokio::time::timeout(hold, b.conn.closed()),
            );
            Err(format!("{refusal_label}: {e}").into())
        }
    }
}

/// Complete a **relay** pairing for two already-admitted members: authorize the pair,
/// ack both `OK`, then splice each side's next bi-stream through the edge via
/// [`crate::relay::relay_initiator_to_acceptor`] — preserving the direct-path stream
/// roles (initiator opens, acceptor accepts the edge-opened stream) so the agents'
/// `run_channel_session` runs unchanged. The tunnel flows through the edge as
/// ciphertext. This is the behaviour-preserving pair-completion tail of
/// [`broker_channel_relay`], split from admission so a concurrent loop can `spawn` it
/// per pair — the mechanical prerequisite for taking the splice off the accept loop's
/// single global slot (#109-concurrent).
pub(crate) async fn finish_relay_pair(
    a: AdmittedMember,
    b: AdmittedMember,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError> {
    finish_quic_pair_inner(a, b, now, QuicPairCompletion::Splice).await
}

/// Write one **QUIC-native** member's `ack` bytes + FIN, tagging any I/O failure with `side` so a
/// mid-handoff drop is a [`RelayHandoffError`] naming the dead side — not a bare error indistinguishable
/// from an admission refusal (#148/#154/#155). The QUIC-native analog of [`write_member_ack`], shared
/// by all three QUIC completers: [`finish_relay_pair`] passes `OK r=<observed>` (#104-follow — no
/// peer endpoint/keys to relay-splice, just each side's own reflexive), while
/// [`finish_rendezvous_pair`] passes its rich `OK <peer…> r=<observed>` line — the helper is content-
/// agnostic, so every completer distinguishes a handoff race from a refusal consistently.
async fn quic_ack_member(
    send: &mut quinn::SendStream,
    ack: &[u8],
    side: PairSide,
) -> Result<(), RelayHandoffError> {
    send.write_all(ack)
        .await
        .map_err(|e| RelayHandoffError { failed_side: side, source: e.into() })?;
    send.finish()
        .map_err(|e| RelayHandoffError { failed_side: side, source: e.into() })?;
    Ok(())
}

/// A type-erased channel duplex: box any transport's concrete stream (the `:443`
/// front door's TLS-over-TCP stream, a browser's WebSocket byte stream, ...) into
/// this so members that arrive over DIFFERENT transports but hold the same channel
/// can still be offered to and correlated by ONE shared [`ChannelPairer`]
/// (cross-transport pairing: a native `:443`/QUIC member and a browser member of the
/// same channel now pair with EACH OTHER, not only with another member of their own
/// transport). [`finish_relay_pair_over_streams`] is already generic over two
/// independent stream types, so relay-splicing a boxed browser stream with a boxed
/// front-door stream needs no change there at all — only the shared admission/pairing
/// state needed one common type, which is exactly what this is.
pub trait AsyncDuplex: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncDuplex for T {}
pub type BoxedChannelStream = std::pin::Pin<Box<dyn AsyncDuplex>>;

/// #495-U2 slice 1: adapts a QUIC **bidirectional stream** (a `quinn` `SendStream` +
/// `RecvStream`, plus the owning `Connection` held only for liveness) into a single
/// [`AsyncDuplex`], so a QUIC-relay member's session stream can be `Box::pin`-ed into a
/// [`BoxedChannelStream`] and parked in the SAME shared pairer as the `:443`/WebSocket
/// stream members — exactly how [`crate::ws_channel`] boxes its `WsByteStream`. Read
/// delegates to the `RecvStream`, write/flush/shutdown to the `SendStream`. The
/// `Connection` is held (never used directly) so the pair of streams outlives any *other*
/// clone of the connection being dropped elsewhere — the "conn-liveness, not a pump task"
/// the U2 plan calls for. quinn's `SendStream`/`RecvStream` already implement
/// tokio's `AsyncWrite`/`AsyncRead` (runtime-tokio), so this is a thin, allocation-free
/// combiner. Not yet wired: the `:4436` relay offer path (a later U2 slice) constructs one
/// and hands it to the shared pairer behind `CT_EDGE_UNIFIED_PAIRER`.
pub struct QuicBi {
    _conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBi {
    /// Wrap a QUIC bi-stream (its `send`/`recv` halves) plus the owning `conn` (kept alive
    /// for this duplex's whole life) as an [`AsyncDuplex`].
    pub fn new(conn: quinn::Connection, send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { _conn: conn, send, recv }
    }
}

// NB: quinn's `SendStream`/`RecvStream` carry INHERENT `poll_write`/`poll_read` (returning
// quinn's `WriteError`/`ReadError`) that shadow the tokio-trait methods via method-resolution
// precedence, so each impl calls the trait method explicitly (UFCS) to get the `io::Error`
// contract `AsyncDuplex` requires.
impl tokio::io::AsyncRead for QuicBi {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicBi {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// The shared cross-transport channel pairer type every transport opts into (the
/// `:443` front door, the browser WebSocket listener, ...): one `Arc` constructed
/// once at edge startup ([`crate::serve::run_edge`]) and cloned into each transport's
/// context, so members that arrive over different transports but hold the same
/// channel still correlate through the same map.
pub type SharedChannelPairer =
    std::sync::Arc<std::sync::Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>>>;

/// A fresh, empty [`SharedChannelPairer`] — callers still own spawning their own
/// reaper against it (the interval/`now_fn` choice is caller-specific; see
/// `serve.rs`'s `spawn_front_door_pairer_reaper`), this just gives every call site
/// the same one-line way to construct the shared type instead of spelling out the
/// nested `Arc<Mutex<ChannelPairer<...>>>` each time.
pub fn new_shared_channel_pairer() -> SharedChannelPairer {
    std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new()))
}

/// The wire token an expiring park sends before closing (ct-agent#21): a reaped member's
/// client used to read a SILENT close, indistinguishable from a refusal -- it then advanced
/// its dial ladder and backed off, burning 40s windows on what was a perfectly healthy rung
/// (measured: 271 "rung failures" that were just idle park expiries). `EX` names the event so
/// a current client re-parks on the SAME rung immediately; an older client sees it as the
/// same EOF-ish close it always did (no behavior change).
/// #557: re-exported from [`ct_common::channel::PARK_EXPIRED_TOKEN`], which is now the single
/// definition. ct-agent compared against its own bare `"EX"` literal and each side pinned its
/// own copy with its own test -- two self-consistent tests cannot see the copies drift apart.
/// Kept as a re-export rather than replaced at ~30 call sites: the name is what this module
/// reads as, and the aliasing makes a divergence impossible rather than merely tested.
pub use ct_common::channel::PARK_EXPIRED_TOKEN;

/// The QUIC-leg park-expiry close-reason PREFIX -- the `quinn::Connection::close` analog of
/// the stream-leg [`PARK_EXPIRED_TOKEN`] (`EX`). When the edge reaps an idle QUIC park it closes
/// the connection with an ApplicationClose reason beginning with this prefix; ct-agent's
/// `error_names_park_expiry` matches exactly this substring in the quinn-surfaced close reason to
/// classify the event as "re-park", NOT a refusal (no ladder advance, no refusal backoff). It
/// previously lived as two independent inline literals (a TTL reap and a supersede) with no shared
/// source of truth -- unlike its stream-leg sibling, which is this named const. Centralized here
/// so a reword can't silently decouple that cross-repo client classification; both reasons are
/// built via [`quic_park_expired_reason`], and `quic_park_expiry_reasons_carry_the_wire_prefix`
/// pins the contract so a breaking edit fails the edge's own gate.
/// #557: likewise re-exported from [`ct_common::channel::PARK_EXPIRED_REASON_PREFIX`].
pub use ct_common::channel::PARK_EXPIRED_REASON_PREFIX as QUIC_PARK_EXPIRED_REASON_PREFIX;

/// Build a QUIC park-expiry close reason: the [`QUIC_PARK_EXPIRED_REASON_PREFIX`] the client
/// classifies on, plus an honest human-readable `why` suffix (logged, never parsed).
pub fn quic_park_expired_reason(why: &str) -> String {
    format!("{QUIC_PARK_EXPIRED_REASON_PREFIX} {why}")
}

/// A channel member admitted over a **generic byte stream** (not a `quinn::Connection`)
/// — e.g. a `:443` TLS-over-TCP front-door member whose network blocks the channel
/// UDP/TCP ports (#106). Unlike [`AdmittedMember`] it carries no `quinn::Connection`:
/// its data path is the **same** duplex the join was admitted over (there is no separate
/// bi-stream to open), so the relay splice reads/writes the Noise ciphertext directly on
/// `stream`. Only the relay path needs this (a member that can't be dialed can't use
/// rendezvous), so it carries just what the relay completer uses — `stream` + the
/// verified request + the operator key its grant verified under. `pub` like the rest of
/// the transport-generic seam ([`admit_channel_join_on_duplex`]); the `:443` front-door
/// wiring (#106-complete-wire443) constructs it from an admitted stream + its keys.
///
/// `noise`/`attest` are the member's registered Noise key + its holder-signed attestation
/// (#101), captured at admission so the relay finisher can relay each side the PEER's
/// attested key in the ack (#122) — exactly as the rendezvous path does. Without them a
/// `:443`-only pair (both members forced onto the relay) could never learn each other's
/// Noise key and the join failed at the pin step; carrying them here closes that gap.
/// #495-U1: where a member's **session** lives once its admission ack is written —
/// the one semantic that genuinely differs per transport and therefore the pivot of
/// the unified pairer:
///
/// - [`SessionSource::SameStream`] (`:443` TLS-TCP, WS): the Noise session continues
///   on the very stream the join was admitted over — a paired member is spliced.
/// - [`SessionSource::EndpointSwap`] (QUIC rendezvous, U2): the admission stream ends
///   after the ack (the client `finish()`ed its half at the possession signature and
///   expects ack-then-`finish()` back); the members then dial each other / their
///   relay fallback using the endpoints exchanged in the acks. A pair with ANY
///   EndpointSwap side must therefore complete ack-then-close even where the phases
///   alone would splice — splicing an EOF'd admission stream would resurrect the
///   phase-mixed early-eof class (#495 2a) for cross-transport pairs.
///
/// U3 adds the third variant (QUIC relay: session on the connection's NEXT bi-stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
    /// The session continues on the admission stream (splice on pairing).
    SameStream,
    /// The admission stream ends after the ack; the session forms out-of-band via
    /// the exchanged endpoints (ack-then-close on pairing).
    EndpointSwap,
}

pub struct AdmittedStreamMember<S> {
    stream: S,
    req: ChannelJoinRequest,
    operator: [u8; 32],
    noise: Option<[u8; 32]>,
    attest: Option<[u8; 64]>,
    /// #495-U1: this member's edge-observed reflexive (post-NAT) source, captured at
    /// admission — echoed back as the ack's self-addressed `r=<addr>` token and the
    /// input to the pair's `sp=` same-public-IP fact, exactly as the QUIC completers
    /// have carried since #121/#276. Bringing it to the stream family is what erases
    /// the historical ack-format asymmetry the unified pairer would otherwise trip
    /// over (a QUIC member pairing via the shared pairer must not lose its punch
    /// address).
    observed: std::net::SocketAddr,
    /// #495-U1: where this member's SESSION lives after the ack — the transport
    /// difference the unified pairer must respect at completion time (see
    /// [`SessionSource`]).
    session: SessionSource,
    /// #451: the [`crate::state::ConnectionCap`] permit admitting this connection, carried on
    /// the value that owns the live stream (same rationale as [`AdmittedMember::_permit`]) —
    /// `admit_and_pair_on_stream`'s caller (the `:443` front door's `ChannelBroker` arm,
    /// `ws_channel.rs`'s upgrade handler) acquires it before/at accept and passes it in, so it
    /// stays held through a park in the `ChannelPairer`, through the relay splice once paired,
    /// and drops on whichever exit path actually closes the connection. `None` for every
    /// unbounded caller (`cap: None`) and every direct test construction in this module. Never
    /// read, only held for its `Drop` -- leading underscore so `-D dead_code` doesn't flag it.
    _permit: Option<OwnedSemaphorePermit>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AdmittedStreamMember<S> {
    /// ct-agent#21: notify this parked member that its park EXPIRED (no partner within the
    /// TTL) before its stream is dropped -- best-effort (`EX` + shutdown, every error
    /// ignored: the member may already be gone, which is fine, the write existed to help a
    /// live one). Consumes the member; dropping the stream afterwards closes the connection
    /// and releases the #451 permit, exactly as the silent drop did.
    pub async fn notify_park_expired(mut self) {
        let _ = self.stream.write_all(PARK_EXPIRED_TOKEN).await;
        // Graceful close (found here first, 2026-08-14: v0.4.11 clients half-close their
        // leg right after the possession signature, so by reap time this socket holds
        // their unread close_notify — the EX was then RST-discarded on every remote
        // measurement while the local E2E repro passed). The rule now lives in
        // [`graceful_close`], shared with the 2b rendezvous completion (#511).
        graceful_close(&mut self.stream).await;
    }
}

/// Which member of a relay pair a **mid-handoff** failure struck (#148). A completer ack-writes each
/// side sequentially after authorization already succeeded; if one side's stream is dying (e.g. a
/// long-running member caught mid-re-park), its write fails while the other side is perfectly healthy.
/// Naming the side lets a log / caller tell the transient race apart from an actual admission refusal
/// (and, by elimination, identify the healthy survivor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairSide {
    A,
    B,
}

impl std::fmt::Display for PairSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PairSide::A => "A",
            PairSide::B => "B",
        })
    }
}

/// A relay pair that failed **after authorization succeeded** — while acking one side, NOT because a
/// grant/membership was refused (#148). This distinction is the whole point: a mid-handoff write
/// failure against one member (typically its stream torn down in a re-park race) is transient and says
/// **nothing** about the other member, whose grant was already verified — so it must not surface as an
/// ambiguous "connection lost" / "refused" that reads like an authorization problem. `failed_side`
/// names the member whose I/O failed; the opposite side was healthy up to that point (a bare retry by
/// the survivor should re-pair).
#[derive(Debug)]
pub struct RelayHandoffError {
    /// The member whose ack write/flush failed. Its peer was healthy.
    pub failed_side: PairSide,
    source: BoxError,
}

impl std::fmt::Display for RelayHandoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "relay handoff failed acking side {} (authorization already succeeded; the peer side was \
             healthy — this is a transient handoff race, not an admission refusal): {}",
            self.failed_side, self.source
        )
    }
}

impl std::error::Error for RelayHandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Write one member the rich `OK <peer…>\n` ack (+flush), tagging any I/O failure with `side` so the
/// completer can report *which* member died mid-handoff (#148) rather than collapsing it into an
/// indistinguishable error.
async fn write_member_ack<S: AsyncWrite + Unpin>(
    stream: &mut S,
    peer_endpoint: &str,
    peer_noise: Option<[u8; 32]>,
    peer_holder: &[u8; 32],
    peer_attest: Option<[u8; 64]>,
    own_observed: std::net::SocketAddr,
    sp: bool,
    side: PairSide,
) -> Result<(), RelayHandoffError> {
    // #495-U1: `r=` (the member's OWN reflexive, #121) and `sp=` (edge-attested
    // same-public-IP, #276) now ride the stream ack exactly as on the QUIC
    // completers — backward-additive (clients parse `r=` order-independently since
    // v0.4.13; unknown tokens fall out of the positional fields harmlessly), and
    // the precondition for pairing QUIC members through the shared pairer without
    // losing their punch address.
    let line = format!(
        "OK {}{} r={} sp={}\n",
        peer_endpoint,
        member_ack_suffix(peer_noise, peer_holder, peer_attest),
        own_observed,
        sp as u8
    );
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| RelayHandoffError { failed_side: side, source: e.into() })?;
    stream
        .flush()
        .await
        .map_err(|e| RelayHandoffError { failed_side: side, source: e.into() })?;
    Ok(())
}

/// Complete a **relay** pairing for two members admitted over generic byte streams
/// (#106 relay-splice-generic) — the transport-agnostic sibling of [`finish_relay_pair`].
/// Authorize the pair under member A's operator key, ack each side the RICH
/// `OK <peer_endpoint> <peer_noise> <peer_holder> <peer_attest>\n` line (#122 — mirroring
/// the rendezvous path via [`member_ack_suffix`]), then splice the two duplexes through the
/// edge via [`crate::relay::relay_streams`] so the Noise_IK tunnel flows end-to-end as
/// ciphertext (the edge sees only opaque bytes). Conveying the peer's **attested** Noise key
/// in the ack is what lets a fresh `:443`-only pair — both members forced onto the relay,
/// neither dialable, with no pre-shared peer key — verify (#101) and pin each other's key and
/// actually form the tunnel; before this the bare `OK` conveyed nothing and every such join
/// failed at the pin step. The peer's `holder` is taken from its **grant** (`peer.req.grant`),
/// not the mutable registry, so a DB-tampered attestation won't verify. The trailing `\n`
/// delimits the ack from the Noise session that follows on the **same** spliced stream, so
/// the relay client ([`ct_agent::channel::present_channel_relay_join_on_stream`]) can read the
/// rich ack without over-reading into the session's first frame. Because each member's data
/// path is the **same** stream it joined on (no separate bi-stream to open/accept, unlike the
/// quinn path), the splice is a plain symmetric bidirectional pump — no initiator/acceptor
/// stream-role dance. Returns the decided pairing when either side closes; an unpairable pair
/// gets `NO`.
pub async fn finish_relay_pair_over_streams<A, B>(
    a: AdmittedStreamMember<A>,
    b: AdmittedStreamMember<B>,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    finish_stream_pair_inner(a, b, now, StreamPairCompletion::Splice).await
}

/// #495 slice 2b: complete a **rendezvous-phase** `:443` pairing — ack each side the
/// peer's identity exactly like the relay finisher, then **close both streams**
/// instead of splicing. The rendezvous contract is "read the ack, then the stream
/// ends" (QUIC `finish()`es; pre-v0.4.16 stream clients literally `read_to_end`),
/// so ack-then-close is what a marked rendezvous member expects — and it heals
/// v0.4.14/v0.4.15 clients (marked, but still on the EOF-waiting ack reader)
/// server-side: their read completes at this close instead of deadlocking against
/// a splice that never ends (CADS-Tunnel#494). Only reachable when BOTH members
/// carried the 0x01 rendezvous preamble; legacy/mixed pairs keep the splice.
pub async fn finish_rendezvous_pair_over_streams<A, B>(
    a: AdmittedStreamMember<A>,
    b: AdmittedStreamMember<B>,
    now: UnixSeconds,
) -> Result<ChannelPairing, BoxError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    finish_stream_pair_inner(a, b, now, StreamPairCompletion::RendezvousClose).await
}

/// How a completed `:443` stream pairing ends after both acks (#495 slice 2b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPairCompletion {
    /// Historical behavior: the acked streams become the session (relay splice).
    Splice,
    /// Rendezvous contract: ack, flush, close — each member then opens its relay leg.
    RendezvousClose,
}

/// #495 2b / #511: THE phase→completion decision for stream pairings, in one place —
/// every stream call site (the `:443` front-door arm; the WS upgrade path, whose
/// members are always [`ParkPhase::Unmarked`]) routes through this rule. Ack-then-
/// close ONLY when BOTH members marked the rendezvous phase; every other combination
/// (relay-marked, legacy unmarked, mixed) keeps the historical splice — which is why
/// `Unmarked` members can never reach `RendezvousClose`, by rule rather than by
/// coincidence.
pub fn completion_for(a: ParkPhase, b: ParkPhase) -> StreamPairCompletion {
    if a == ParkPhase::Rendezvous && b == ParkPhase::Rendezvous {
        StreamPairCompletion::RendezvousClose
    } else {
        StreamPairCompletion::Splice
    }
}

async fn finish_stream_pair_inner<A, B>(
    mut a: AdmittedStreamMember<A>,
    mut b: AdmittedStreamMember<B>,
    now: UnixSeconds,
    completion: StreamPairCompletion,
) -> Result<ChannelPairing, BoxError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    // #495-U1: a pair with ANY EndpointSwap side completes ack-then-close regardless
    // of what the phases alone decided -- there is no stream to splice on that side,
    // and splicing its EOF'd admission stream against a live partner would hand the
    // partner an instant early-eof (the resurrected 2a mixed-phase class).
    let completion = if a.session == SessionSource::SameStream && b.session == SessionSource::SameStream {
        completion
    } else {
        StreamPairCompletion::RendezvousClose
    };
    match authorize_channel_pair(&a.operator, &a.req.grant, &b.req.grant, now) {
        Ok(pairing) => {
            // Each side learns the OTHER's advertised endpoint + attested Noise key + holder +
            // attestation, exactly as `finish_rendezvous_pair` does — but with a trailing `\n`
            // because the Noise session follows on this same stream (the rendezvous path
            // `finish()`es the quinn stream instead, so it needs no delimiter). A relay-only
            // member's `endpoint` is the relay-only sentinel: the peer won't dial it (it's
            // relayed), it's just echoed through.
            //
            // #148: ack each side through `write_member_ack`, which tags an I/O failure with the
            // side. If one member's stream is dying (a re-park race), this returns a
            // `RelayHandoffError` naming the dead side — so the caller can log "handoff race, side X"
            // instead of a bare "connection lost" that reads like the healthy peer was refused.
            let sp = same_public_ip(a.observed, b.observed);
            write_member_ack(
                &mut a.stream,
                &b.req.endpoint,
                b.noise,
                &b.req.grant.grant.holder,
                b.attest,
                a.observed,
                sp,
                PairSide::A,
            )
            .await?;
            write_member_ack(
                &mut b.stream,
                &a.req.endpoint,
                a.noise,
                &a.req.grant.grant.holder,
                a.attest,
                b.observed,
                sp,
                PairSide::B,
            )
            .await?;
            match completion {
                StreamPairCompletion::Splice => {
                    // #555: same registration as the QUIC completer. Both families are wired
                    // because a membership removal that ends the session on one transport and
                    // not the other is worse than one that ends it nowhere -- an operator
                    // cannot tell which transport a given participant arrived on.
                    let _ga = register_live_splice(&a.req.grant.grant.channel, &a.req.grant.grant.holder);
                    let _gb = register_live_splice(&b.req.grant.grant.channel, &b.req.grant.grant.holder);
                    // Both sides acked cleanly; a failure now is the splice itself, not a
                    // one-sided ack race.
                    let bytes = tokio::select! {
                        r = crate::relay::relay_streams(a.stream, b.stream, "channel-relay-443") => {
                            r.map_err(|e| -> BoxError {
                                format!("channel relay splice ended after both sides acked: {e}").into()
                            })?
                        }
                        _ = _ga.cut() => return Err(SPLICE_CUT_BY_REMOVAL.into()),
                        _ = _gb.cut() => return Err(SPLICE_CUT_BY_REMOVAL.into()),
                    };
                    note_channel_splice(bytes); // #517 V1
                }
                StreamPairCompletion::RendezvousClose => {
                    // #517 V1 (Nachtrag): the SAME count as the QUIC family's EndpointSwap,
                    // and the one that matters most in this deployment -- the `:443` front
                    // door is the pairer real channel traffic uses (agents are forced to
                    // FRONT_DOOR_ONLY until #495 unifies the pairers), so counting only the
                    // QUIC family would have measured a path that carries almost nothing.
                    note_channel_rendezvous_pair();
                    // #495 2b: the rendezvous contract ends the stream after the ack —
                    // gracefully (#511): for this completer the ack IS the in-flight
                    // final record the RST race would discard, see [`graceful_close`].
                    tokio::join!(graceful_close(&mut a.stream), graceful_close(&mut b.stream));
                }
            }
            Ok(pairing)
        }
        Err(e) => {
            // #524: same `pairing` category as the QUIC pair-refusal above — the old
            // client's line reader stops at the first 0x0A/EOF and still classifies on
            // the `NO` prefix, so the framed token is back-compatible here too.
            let refusal = encode_channel_refusal("pairing");
            let _ = a.stream.write_all(&refusal).await;
            let _ = b.stream.write_all(&refusal).await;
            let _ = a.stream.shutdown().await;
            let _ = b.stream.shutdown().await;
            let refusal_label = match completion {
                StreamPairCompletion::Splice => "channel relay pair refused",
                // #511: a rendezvous pairing used to report itself as a "relay pair" here.
                StreamPairCompletion::RendezvousClose => "channel rendezvous pair refused",
            };
            Err(format!("{refusal_label}: {e}").into())
        }
    }
}

/// Close a stream gracefully: flush, shutdown (FIN), then DRAIN to EOF (bounded 2s).
/// Packet-capture-proven rule (ct-agent#21 measurement failure, 2026-08-14): dropping
/// a socket that still holds the peer's unread close_notify makes the kernel send an
/// RST right after our FIN, and at real-world RTT that RST overtakes the last record
/// still in flight (the `EX` token there; the 2b rendezvous ack equally) and discards
/// it from the peer's receive buffer. Draining keeps the close FIN-only so the final
/// record survives delivery. Best-effort: every error ignored. Takes `&mut` so the
/// caller's owner (and its #451 permit) stays alive through the close (#511).
async fn graceful_close<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    let mut sink = [0u8; 256];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while let Ok(n) = stream.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    })
    .await;
}

/// Admit one channel member arriving over a `:443` front-door stream and offer it to a
/// shared [`ChannelPairer`] (#106 dispatch-frontdoor). Because a `:443` member cannot
/// be dialed, front-door connections arrive **independently** (the two holders of a
/// channel connect separately), so the front door can't pair "the next two arrivals" —
/// it must correlate by `ChannelId`. This admits the stream
/// ([`admit_channel_join_on_duplex`]), parks it in `pairer` keyed by channel, and:
/// - returns `Ok(None)` when it is the first holder of its channel (now parked), or
/// - returns `Ok(Some((a, b)))` when its partner was already waiting — the caller then
///   relay-splices exactly those two with [`finish_relay_pair_over_streams`] (typically
///   on its own task, so the accept loop stays free).
///
/// A same-holder retry supersedes the stale wait (its stream is closed) and the fresh
/// offer stays parked (`Ok(None)`). The lock is held only for the synchronous `offer`,
/// never across `.await`. This is the transport-generic core the front-door accept loop
/// drives; wiring it into `serve_front_door` is the follow slice.
///
/// `permit` (#451) is the caller's already-acquired [`crate::state::ConnectionCap`] permit for
/// this connection (`None` when uncapped); on success it is moved onto the constructed
/// [`AdmittedStreamMember`] so it travels with the stream through however long it actually
/// lives — parked in `pairer` until matched or TTL-swept, or straight into the relay splice
/// once paired — instead of dropping the instant this function returns (which, for the
/// `Parked`/immediately-`Ok(None)` case, used to happen while the live socket was still very
/// much open inside `pairer`). Dropped here on an admission failure, which is correct: the
/// connection is being torn down either way.
pub async fn admit_and_pair_on_stream<S, F, Fut>(
    stream: S,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
    deadline: UnixSeconds,
    pairer: &std::sync::Mutex<ChannelPairer<AdmittedStreamMember<S>>>,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<Option<(AdmittedStreamMember<S>, AdmittedStreamMember<S>)>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #121 Phase B1: `observed` is this member's reflexive source (the front door fills it from
    // the accepted `TcpStream`'s `peer_addr()`). It is captured through admission; carrying it
    // into the relay-pair ack for a `:443` member is the deferred B1 follow slice (a `:443`-only
    // member is behind symmetric/CGNAT NAT — `RelayOnly` — so it needs no reflexive to punch).
    // #122: keep the member's attested Noise key + attestation (admission already read them);
    // the relay finisher relays each side the PEER's, so a `:443`-only pair can pin each other.
    let (stream, req, operator, noise, attest, _observed) =
        admit_channel_join_on_duplex(stream, observed, now, join_timeout, authorize).await?;
    let member = AdmittedStreamMember { stream, req, operator, noise, attest, observed, session: SessionSource::SameStream, _permit: permit };
    // Unmarked: this generic path (WS + tests) has no phase peek -- historical behavior.
    Ok(offer_admitted_stream_member(pairer, deadline, member, ParkLiveness::default(), ParkPhase::Unmarked, Some(observed.ip()))
        .await?
        .map(|((a, _), (b, _))| (a, b)))
}

/// A completed pairing with each member's park phase (#495 slice 2b): the caller
/// picks the completion — `Rendezvous + Rendezvous` pairs get ack-then-close
/// (the rendezvous contract), everything else the historical relay splice.
pub type PairedWithPhases<S> =
    Option<((AdmittedStreamMember<S>, ParkPhase), (AdmittedStreamMember<S>, ParkPhase))>;

/// The post-admission tail shared by [`admit_and_pair_on_stream`] and
/// [`admit_and_pair_on_boxed_stream`]: offer the admitted member to the pairer and
/// translate the outcome (park / pair / supersede-with-EX). `liveness` is the #499 slice B
/// corpse flag (monitored for pumped `:443` members, `default()` elsewhere).
async fn offer_admitted_stream_member<S>(
    pairer: &std::sync::Mutex<ChannelPairer<AdmittedStreamMember<S>>>,
    deadline: UnixSeconds,
    member: AdmittedStreamMember<S>,
    liveness: ParkLiveness,
    phase: ParkPhase,
    observed: Option<std::net::IpAddr>,
) -> Result<PairedWithPhases<S>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let channel = member.req.grant.grant.channel;
    let holder = member.req.grant.grant.holder;
    // #497: lock_safe -- a panic in some other critical section must not permanently wedge
    // every later offer (the 2026-08-13 broker-outage class).
    let outcome = pairer
        .lock_safe()
        .offer(WaitingMember {
            channel,
            holder,
            observed,
            deadline,
            liveness,
            // #495 slice 2a: today's `:443`/WS wire cannot distinguish the phases, so
            // stream members park Unmarked (pairs with anything = exactly the historical
            // behavior). The v0.4.14 client's relay-leg marker upgrades this to `Relay`.
            phase,
            payload: member,
        });
    match outcome {
        PairOutcome::Parked => Ok(None),
        PairOutcome::Paired(a, b) => {
            // #495 slice 2a observability: name the ONE interesting case -- a pairing whose
            // phases differ (only possible with a legacy Unmarked member involved).
            // Same-phase pairings stay silent, so this is what answers "was THAT pairing
            // phase-mixed?" during field falsification without per-pair log spam.
            if a.phase != b.phase {
                eprintln!(
                    "ct-edge: phase-mixed channel pairing ({:?}+{:?}, legacy member involved) (#495)",
                    a.phase, b.phase
                );
            }
            Ok(Some(((a.payload, a.phase), (b.payload, b.phase))))
        }
        PairOutcome::Superseded(stale) => {
            // A retry from the same holder arrived before its partner (beyond the #495 queue
            // cap); the fresh offer is now parked, so tear down the stale stream and report
            // "parked" (nothing to pair). #499 slice A: the teardown used to be a silent
            // shutdown -- a LIVE client on the stale leg saw exactly the pre-ct-agent#21
            // ambiguous EOF (classified as a refusal, advancing its ladder). It now gets the
            // same best-effort `EX` token a TTL reap sends: the park is gone through no
            // fault of its grant, and re-park-same-rung is the correct client reaction in
            // both cases. In the common case the stale leg is a corpse (an abandoned retry)
            // and the write vanishes harmlessly, like the reaper's. Spawned (#511): the
            // notify's graceful close drains up to 2s, and this is the NEW member's
            // admission path — the fresh park must not wait out the stale leg's teardown.
            note_channel_park_superseded();
            tokio::spawn(stale.payload.notify_park_expired());
            Ok(None)
        }
    }
}

/// #500 K2: how often a parked, keepalive-negotiated `:443` leg gets one NUL byte of real
/// application payload. Tester-proven necessity: parked legs are otherwise completely
/// traffic-free, and payload-required middleboxes reap them at ~40s -- BEFORE the 30s park
/// TTL can fire and send `EX` -- while the TCP-level keepalive the front door has applied
/// since #452 flows beneath such a middlebox's payload counter unnoticed. 10s stays far
/// inside every plausible idle timer and costs ~one TLS record per tick.
pub(crate) const PARK_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// #500 K2: wrap an ADMITTED (post-challenge) keepalive-negotiated stream in a pump task
/// that owns the real connection and injects one NUL byte of application payload every
/// [`PARK_KEEPALIVE_INTERVAL`] while the leg is parked. The pairer parks the returned
/// duplex end instead; acks/`EX`/the relay splice flow through the pump transparently.
///
/// The parked phase ends at the FIRST edge->client chunk after this wrap (the ack or the
/// `EX` token -- admission's challenge was written before the wrap): keepalive stops
/// permanently then, so no NUL can ever interleave into the spliced session. A NUL racing
/// the ack's first chunk lands BEFORE it (the select! serializes whole chunks), i.e. as
/// one more leading NUL of exactly the kind a keepalive-negotiated client strips. Client
/// EOF/error tears the pump down (the parked side then fails fast on its next write --
/// the corpse surfaces at pairing instead of poisoning it silently); the arm side
/// dropping/shutting down closes the real connection.
fn spawn_park_keepalive_pump(
    stream: BoxedChannelStream,
    keepalive: bool,
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> tokio::io::DuplexStream {
    let (near, far) = tokio::io::duplex(16 * 1024);
    tokio::spawn(async move {
        let (mut real_r, mut real_w) = tokio::io::split(stream);
        let (mut far_r, mut far_w) = tokio::io::split(far);
        // interval() fires immediately on its first tick; the first keepalive belongs one
        // full interval AFTER parking, so anchor the start explicitly.
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + PARK_KEEPALIVE_INTERVAL,
            PARK_KEEPALIVE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut parked = true;
        // #499 slice B, corrected after a live false-positive regression (2026-08-14): a clean
        // read EOF while parked is NOT a death signal on its own -- v0.4.11-and-older clients
        // legitimately HALF-CLOSE right after the possession signature, and flagging their EOF
        // as a corpse killed every old client's live park (4-5 false drops per sweep, plane-
        // wide). The discriminator is the negotiated contract: a KA-negotiated client
        // (#500 ALPNs) promises a fully-open parked leg, so its EOF is unambiguous death; for
        // everyone else only a HARD read error (RST) is -- a clean EOF just closes the read
        // half and the pump keeps forwarding outbound (the ack/EX must still reach a
        // half-closed old client, which can still receive).
        let mut read_open = true;
        let mut from_client = vec![0u8; 16 * 1024];
        let mut to_client = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                r = real_r.read(&mut from_client), if read_open => match r {
                    Err(_) => {
                        // Hard error (RST-class): unambiguous death on every client version.
                        if parked {
                            dead.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        break;
                    }
                    Ok(0) => {
                        if keepalive {
                            // KA contract: the parked leg stays fully open, so EOF = death.
                            if parked {
                                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            break;
                        }
                        // Legacy half-close (or a v0.4.12 process death -- wire-ambiguous
                        // by design until the client speaks the KA ALPN): tolerate, keep
                        // the outbound direction alive.
                        read_open = false;
                    }
                    Ok(n) => {
                        if far_w.write_all(&from_client[..n]).await.is_err() {
                            break;
                        }
                        let _ = far_w.flush().await;
                    }
                },
                r = far_r.read(&mut to_client) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        parked = false; // ack/EX started -- keepalive off for good
                        if real_w.write_all(&to_client[..n]).await.is_err() {
                            break;
                        }
                        let _ = real_w.flush().await;
                    }
                },
                _ = ticker.tick(), if parked && keepalive => {
                    if real_w.write_all(&[0u8]).await.is_err() {
                        // The write path died while parked: same corpse semantics as a
                        // read-side death (#499 slice B).
                        dead.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    let _ = real_w.flush().await;
                }
            }
        }
        let _ = real_w.shutdown().await;
    });
    near
}

/// [`admit_and_pair_on_stream`] for the shared boxed stream type, with the #500 K2 park
/// keepalive: when `keepalive` (the client negotiated a KA-capable ALPN -- see
/// `pki::build_channel_front_door_acceptor`'s list), the admitted stream is wrapped in
/// [`spawn_park_keepalive_pump`] BEFORE it is offered/parked, so a parked leg carries one
/// NUL of application payload every [`PARK_KEEPALIVE_INTERVAL`]. `keepalive: false` is
/// byte-for-byte [`admit_and_pair_on_stream`].
#[allow(clippy::too_many_arguments)] // mirrors admit_and_pair_on_stream's signature + the flag
pub async fn admit_and_pair_on_boxed_stream<F, Fut>(
    stream: BoxedChannelStream,
    observed: std::net::SocketAddr,
    now: UnixSeconds,
    join_timeout: std::time::Duration,
    authorize: &F,
    deadline: UnixSeconds,
    pairer: &std::sync::Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>>,
    permit: Option<OwnedSemaphorePermit>,
    keepalive: bool,
) -> Result<PairedWithPhases<BoxedChannelStream>, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // #495 slice 2a (v0.4.14 marker, edge half): a KA-generation client MAY prefix its
    // join with `[0xFF, phase]`. Peek the first two bytes only on KA-negotiated
    // connections; without the magic they ARE the length prefix and are put back
    // verbatim (PrependBytes), so a v0.4.13 KA client without the preamble stays
    // byte-identical. Non-KA connections are never peeked (legacy path untouched); a
    // stray 0xFF there falls into the admission's existing len-oob refusal.
    // #509: the peek is part of the admission read, so it runs under the SAME
    // `join_timeout` bound the admission proper applies internally
    // (`read_channel_join_on_stream`, #105/#452). The `:443` listener deliberately
    // passes no listener-level handshake timeout and relies on every arm bounding
    // its own read phase -- an unguarded peek let a KA peer that completed TLS and
    // then went silent hold its conn-cap and #451 permits forever.
    let (stream, phase): (BoxedChannelStream, ParkPhase) = if keepalive {
        let peek = async {
            let mut stream = stream;
            let mut first = [0u8; 2];
            stream
                .read_exact(&mut first)
                .await
                .map_err(|e| -> BoxError { format!("channel join: preamble/length read failed: {e}").into() })?;
            if first[0] == PHASE_PREAMBLE_MAGIC {
                let phase = match first[1] {
                    0x01 => ParkPhase::Rendezvous,
                    0x02 => ParkPhase::Relay,
                    // A wrong byte AFTER the magic is a defect in the client's marker
                    // writer, never transient -- no retry can succeed, so the per-IP
                    // penalty must see it as definitive (#509).
                    other => {
                        return Err(DefinitiveJoinRefusal::boxed(
                            format!(
                                "channel join: unknown phase marker 0x{other:02x} after the preamble magic"
                            )
                            .into(),
                        ))
                    }
                };
                Ok((stream, phase))
            } else {
                Ok((
                    Box::pin(PrependBytes { pre: first, pos: 0, inner: stream }) as BoxedChannelStream,
                    ParkPhase::Unmarked,
                ))
            }
        };
        match tokio::time::timeout(join_timeout, peek).await {
            Ok(r) => r?,
            Err(_) => {
                eprintln!("ct-edge: channel-join NO [timeout]: phase preamble not submitted within {join_timeout:?} — dropping stalled connection (#509)");
                return Err(
                    "channel join preamble not submitted within the timeout — dropping stalled connection (#509)"
                        .into(),
                );
            }
        }
    } else {
        (stream, ParkPhase::Unmarked)
    };
    let (stream, req, operator, noise, attest, _observed) =
        admit_channel_join_on_duplex(stream, observed, now, join_timeout, authorize).await?;
    // #499 slice B: EVERY admitted `:443` member is pumped now (not only KA-negotiated
    // ones) -- the pump is also the park's death monitor, and a corpse must be flagged
    // regardless of whether its client spoke the keepalive ALPN. `keepalive` only gates
    // the NUL ticks.
    let (liveness, dead) = ParkLiveness::monitored();
    // #558: counted here, from the same flag the pump and the TTL read.
    note_channel_park_leg(keepalive);
    let stream: BoxedChannelStream = Box::pin(spawn_park_keepalive_pump(stream, keepalive, dead));
    let member = AdmittedStreamMember { stream, req, operator, noise, attest, observed, session: SessionSource::SameStream, _permit: permit };
    offer_admitted_stream_member(pairer, deadline, member, liveness, phase, Some(observed.ip())).await
}


/// Broker a direct channel between two agents (AF2d-transport-b): accept two
/// channel-joins for the same channel, pair them via [`authorize_channel_pair`],
/// and reply to each side with the *peer's* advertised endpoint (`OK <endpoint>`)
/// so the two can connect directly — the edge is only the rendezvous broker and
/// never sees their payload. An unpairable pair (channel mismatch / incompatible
/// directions / same holder) gets `NO` on both sides. Returns the decided pairing.
pub async fn broker_channel_rendezvous<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelPairing, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // Admit two members, then complete the pairing. Splitting admission from
    // completion is the seam a `ChannelPairer`-driven concurrent loop will drive
    // (park lone arrivals, spawn the finisher once two same-channel holders meet).
    let a = accept_member(endpoint, now, &authorize).await?;
    let b = accept_member(endpoint, now, &authorize).await?;
    finish_rendezvous_pair(a, b, now).await
}

/// Relay-mode admission for two channel members that can't reach each other on the
/// **direct** path (#72 AF4-session-resilience). Like [`broker_channel_rendezvous`] it
/// accepts + authorizes two joins for the same channel, but instead of swapping
/// endpoints for a direct dial it acks `OK` and then splices each side's *next*
/// bi-stream through the edge via [`crate::relay::relay_two_connections`] — so the
/// tunnel flows through the edge as ciphertext (the Noise_IK session the agents run
/// over the relayed stream stays end-to-end; the edge sees only opaque bytes). This is
/// the edge endpoint two agents fall back to when the direct dial is `Unreachable`.
/// Returns the pairing when the relay ends (either side closing tears it down).
pub async fn broker_channel_relay<F, Fut>(
    endpoint: &Endpoint,
    now: UnixSeconds,
    authorize: F,
) -> Result<ChannelPairing, BoxError>
where
    F: Fn(ChannelId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>>,
{
    // Admit two members, then complete the relay. The splice lives in
    // `finish_relay_pair` so a concurrent loop can take it off the accept loop's
    // single global slot (the #109 failure mode #1) in the follow sub-packet.
    let a = accept_member(endpoint, now, &authorize).await?;
    let b = accept_member(endpoint, now, &authorize).await?;
    finish_relay_pair(a, b, now).await
}

/// Drive a QUIC channel endpoint (RELAY *or* RENDEZVOUS) as a concurrent, channel-keyed
/// broker (#109-concurrent-b, #120) — the QUIC analog of the front-door
/// [`admit_and_pair_on_stream`] loop, generic over the pairing **completer**. This replaces
/// the serial `loop { broker_channel_relay(..).await }` / `loop { broker_channel_rendezvous
/// (..).await }` the edge used to run, which admitted exactly two connections and then ran
/// the pair-completion **inline**: a single member that held its connection open (a #103
/// persistent relay sink, or — #120 — a rendezvous member that never closes) held that one
/// global slot forever, so every other member of every channel was blocked (#109/#120
/// failure #1), and two channels racing were paired blind by arrival order (#109 failure #2).
///
/// Each accepted + admitted member is `offer`ed to a channel-keyed [`ChannelPairer`]: the
/// first holder of a channel parks; when a *different holder of the same channel* arrives
/// the two are paired and `complete(a, b, now)` (e.g. [`finish_relay_pair`] for the relay,
/// [`finish_rendezvous_pair`] for rendezvous) is `spawn`ed on its own task, so the accept
/// loop immediately returns to admit the next member — a held-open member can no longer wedge
/// the endpoint (#1), and channel-keying means two channels can never cross-pair (#2). A
/// same-holder retry supersedes the stale wait (its connection is closed). On each accept the
/// pairer is swept for lone waiters past their `park_ttl` deadline, which are closed instead
/// of parked forever (#109 failure #3). `now_fn` is sampled per accept (a real clock in the
/// daemon, a fixed stub in tests). The `Mutex` is held only for the synchronous
/// `offer`/`drain_expired`, never across an `.await`; the spawned `complete` future must be
/// `Send + 'static` ([`AdmittedMember`] is).
///
/// `shutdown` (#400): raced against `endpoint.accept()` via `tokio::select!` each
/// iteration, so a pending accept doesn't stop this loop from noticing shutdown
/// promptly. Once triggered, this returns (stops admitting new channel members)
/// instead of accepting further connections. The park-TTL sweep also stops running at
/// that point -- a member already parked, waiting for a partner that may never arrive,
/// is no longer proactively closed by this loop.
///
/// `pairer` (#400): passed in by the CALLER rather than constructed internally --
/// deliberately, not cosmetically. This function's own local variables (including a
/// self-constructed pairer) are dropped the instant it returns, which happens
/// immediately on shutdown; a parked member's `AdmittedMember` (and the connection +
/// cap permit it carries) lives inside the pairer's map, so if this function's return
/// dropped the LAST `Arc` reference to it, every parked member would be force-closed
/// the moment shutdown fires -- defeating the whole point of the bounded grace period
/// (a real bug caught by this crate's own `run_channel_broker_loop_stops_accepting_
/// promptly_once_shutdown_is_triggered_400` test). By taking the pairer as a parameter,
/// the caller (`run_edge`) can keep its OWN clone alive in its own stack frame for the
/// whole bounded drain window ([`crate::shutdown::wait_for_drain`]) -- this function's
/// return no longer drops the last reference, so a parked member survives exactly as
/// long as every other still-open connection does, and is force-closed together with
/// them only when `run_edge` itself finally returns.
///
/// Otherwise never returns: it *is* the endpoint's accept loop, spawned by `run_edge`.
pub(crate) async fn run_channel_broker_loop<F, Fut, N, C, CFut>(
    endpoint: &Endpoint,
    now_fn: N,
    authorize: F,
    park_ttl: UnixSeconds,
    // #495 slice 2a: which protocol phase this endpoint serves (relay :4436 -> Relay,
    // rendezvous :4435 -> Rendezvous) -- stamped on every park it offers.
    phase: ParkPhase,
    complete: C,
    cap: Option<crate::state::ConnectionCap>,
    shutdown: crate::shutdown::ShutdownSignal,
    pairer: SharedQuicChannelPairer,
    penalty: std::sync::Arc<crate::state::JoinRefusalPenalty>,
    heartbeat: std::sync::Arc<crate::state::BrokerHeartbeat>,
    // #603 step 2: `None` from every call site until step 6 wires the real store +
    // compose/env plumbing -- see `audit_log.rs`'s module doc. Optional so a broker
    // that never gets a store (tests, and every caller until step 6) pays nothing.
    audit_log: Option<std::sync::Arc<crate::audit_log::SqliteAuditLog>>,
) where
    N: Fn() -> UnixSeconds + Send + Sync + 'static,
    F: Fn(ChannelId, [u8; 32]) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send,
    C: Fn(AdmittedMember, AdmittedMember, UnixSeconds) -> CFut + Send + Sync + 'static,
    CFut: std::future::Future<Output = Result<ChannelPairing, BoxError>> + Send + 'static,
{
    // #203: the closures are shared into each per-connection admission task, so admission
    // (the slow grant-verify + possession-proof handshake) runs concurrently across channels instead
    // of serialized in the accept loop — the admission analog of #120/#1's already-spawned pair
    // COMPLETION. Arc so each spawned task can hold them. (The pairer itself is now a parameter --
    // see this function's own doc comment, #400.)
    let now_fn = std::sync::Arc::new(now_fn);
    let authorize = std::sync::Arc::new(authorize);
    let complete = std::sync::Arc::new(complete);
    // #497 slice 2: a fixed idle tick serves two jobs at once. (1) LIVENESS: the loop beats
    // the shared heartbeat on every iteration -- including idle ones -- so `/metrics` can
    // distinguish "idle broker" from "wedged broker" (the 2026-08-13 outage was invisible
    // for 22 minutes precisely because it couldn't). (2) IDLE-TIME SWEEPING: the TTL sweep
    // below used to run only when a NEW connection arrived, so on a quiet endpoint an
    // expired lone park (and its #451 cap permit!) lingered indefinitely -- now the tick
    // sweeps too. 10s: three ticks per park TTL, and a staleness alert at ~30s is
    // unambiguous.
    const BROKER_IDLE_TICK: std::time::Duration = std::time::Duration::from_secs(10);
    let mut idle_tick = tokio::time::interval(BROKER_IDLE_TICK);
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let now = now_fn();
        heartbeat.beat(now);

        // Sweep lone waiters past their park deadline (#3) before accepting the next connection,
        // so a first-comer with no partner is bounded instead of wedging the endpoint.
        let expired = pairer.lock_safe().drain_expired(now); // #497: poison-resilient
        for m in expired {
            // ct-agent#21: a NAMED close reason -- the QUIC analog of the stream path's EX
            // token; a current client reads the ApplicationClose reason and re-parks on the
            // same rung instead of misreading the close as a rung failure.
            m.payload
                .conn
                .close(0u32.into(), quic_park_expired_reason("no partner within the park TTL").as_bytes());
        }

        // Accept the next incoming CONNECTION only — fast (the QUIC accept, not the handshake). The
        // slow admission (handshake + join read + grant verify + possession-proof) then runs on a
        // SPAWNED task, so ONE in-flight admission can't serialize every other channel's admission on
        // this edge (#203: the loop awaited accept_member — the whole handshake — inline; `structure`
        // / `review`, dialed last in a multi-stage pipeline, lost most to that contention).
        let incoming = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                eprintln!("ct-edge: channel broker stopping new accepts (shutdown)");
                return;
            }
            _ = idle_tick.tick() => {
                // Idle tick: loop back around to beat + sweep, then wait again (#497).
                continue;
            }
            accepted = endpoint.accept() => match accepted {
                Some(i) => i,
                None => {
                    eprintln!("ct-edge: channel broker endpoint closed with no incoming");
                    return;
                }
            },
        };
        // Per-IP definitive-refusal penalty (2026-08-13 storm): an IP that exhausted its
        // definitive-refusal budget this window gets its join connections dropped HERE --
        // before the QUIC handshake, before a cap permit, before a spawned task -- because
        // the storm's actual damage was ~29 handshakes/s of doomed admissions congesting
        // the shared accept path, not broker CPU. `ignore()` (no response datagram at all)
        // rather than `refuse()`: a penalized storm client's retry loop gets nothing to
        // react to, and the edge spends nothing answering it. Deliberately silent per shed
        // (logged on power-of-two totals below), or the log flood would just move here.
        let peer_ip = incoming.remote_address().ip();
        if penalty.penalized(peer_ip, now_fn()) {
            incoming.ignore();
            let total = penalty.note_shed();
            if total.is_power_of_two() || total % 1000 == 0 {
                eprintln!(
                    "ct-edge: channel-join penalty shedding {peer_ip} pre-handshake — {total} connection(s) shed since start"
                );
            }
            continue;
        }
        // #450: every other public listener acquires a connection-cap permit before
        // spawning its per-connection task; this loop spawned unbounded until now.
        // Shed BEFORE spawning (cheaper than admitting then dropping mid-handshake),
        // same posture as every other listener's cap. #451: the permit is moved onto
        // the [`AdmittedMember`] itself (inside `admit_incoming_member`), not just held
        // as a task-local binding here — so it now stays held for exactly as long as
        // the connection actually lives: through a park in the pairer (released only
        // when TTL-swept below or superseded), through `complete(..).await` once
        // paired, or dropped immediately on an admission failure.
        let permit = match &cap {
            Some(c) => match c.try_admit() {
                Some(p) => Some(p),
                None => {
                    let total = c.note_shed();
                    if total.is_power_of_two() || total % 1000 == 0 {
                        eprintln!(
                            "ct-edge: channel-broker shedding — connection cap full, {total} connection(s) shed since start"
                        );
                    }
                    continue;
                }
            },
            None => None,
        };
        let pairer = pairer.clone();
        let now_fn = now_fn.clone();
        let authorize = authorize.clone();
        let complete = complete.clone();
        let penalty = penalty.clone();
        let audit_log = audit_log.clone();
        tokio::spawn(async move {
            let now = now_fn();
            // Admit this one member (its join read is bounded by #105); on error, log and drop it —
            // a single bad connection must not affect any other channel. The permit travels with
            // `incoming` into `admit_incoming_member` and is set on the returned `AdmittedMember`
            // (or simply dropped here, correctly, on an admission failure).
            let member = match admit_incoming_member(incoming, now, &*authorize, permit).await {
                Ok(m) => m,
                Err(e) => {
                    // Feed the per-IP penalty on DEFINITIVE refusals only (typed via
                    // [`DefinitiveJoinRefusal`], never string-matched) -- timeouts and I/O
                    // drops from flaky-but-honest networks must not count toward a shed.
                    if is_definitive_join_refusal(&e)
                        && penalty.note_definitive_refusal(peer_ip, now_fn())
                    {
                        eprintln!(
                            "ct-edge: channel-join penalty engaged for {peer_ip} — definitive-refusal budget exhausted; shedding its joins pre-handshake for the rest of the window"
                        );
                    }
                    eprintln!("ct-edge: channel admit failed: {e}");
                    return;
                }
            };
            // #103: sample `now` at ADMISSION time for the parked member's deadline (the deadline is
            // TTL from the member's ACTUAL admission time, not from before the handshake wait).
            let now = now_fn();
            let channel = member.req.grant.grant.channel;
            let holder = member.req.grant.grant.holder;

            // #603: durable evidentiary record of this admitted member's source IP,
            // independent of whether it ends up Parked or Paired below -- admission
            // (grant + possession-proof verified) is the meaningful "a real client
            // reached this channel" event, not the later pairing outcome.
            if let Some(log) = &audit_log {
                let ip = member.conn.remote_address().ip();
                if let Err(e) = log.record(
                    crate::audit_log::ConnTransport::QuicChannel,
                    ip,
                    now as i64,
                    None,
                    Some(&crate::serve::hex_of_bytes(&channel.0)),
                    Some(&crate::serve::hex_of_bytes(&holder)),
                ) {
                    eprintln!("ct-edge: audit-log record failed: {e} (#603)");
                }
            }

            // Offer to the channel-keyed pairer; the lock is held only for the sync `offer`.
            let outcome = pairer.lock_safe().offer(WaitingMember { // #497: poison-resilient
                channel,
                holder,
                observed: Some(member.conn.remote_address().ip()),
                deadline: now.saturating_add(park_ttl),
                // #499 slice B: unmonitored -- a QUIC park's death is visible at the
                // connection layer (the sweep's close/read paths), unlike a raw stream's.
                liveness: ParkLiveness::default(),
                // #495 slice 2a: the QUIC brokers' phase IS their port -- the loop is
                // told which one it serves.
                phase,
                payload: member,
            });
            match outcome {
                // First holder of this channel — parked, waiting for its partner.
                PairOutcome::Parked => {}
                // Its partner met it: complete the pair (this task is already off the accept loop).
                PairOutcome::Paired(a, b) => {
                    if let Err(e) = complete(a.payload, b.payload, now).await {
                        eprintln!("ct-edge: channel pair ended: {e}");
                    }
                }
                // Same holder re-presented before its partner arrived (beyond the #495 queue
                // cap): the fresh offer stays parked; close the stale connection. #499 slice A:
                // the reason carries the `park-expired:` wire prefix so a LIVE client on the
                // stale leg classifies it as ParkExpired (re-park, no ladder advance, no
                // refusal backoff) instead of an anonymous transport error -- the park is gone
                // through no fault of its grant, exactly like a TTL reap. The suffix stays
                // honest about WHY.
                PairOutcome::Superseded(stale) => {
                    note_channel_park_superseded();
                    stale.payload.conn.close(
                        0u32.into(),
                        quic_park_expired_reason("superseded by a newer join from the same holder").as_bytes(),
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ct_common::channel::{ChannelGrant, Rights};
    use ed25519_dalek::{Signer, SigningKey};

    const OP_SEED: [u8; 32] = [5u8; 32];

    fn operator_pubkey() -> [u8; 32] {
        SigningKey::from_bytes(&OP_SEED).verifying_key().to_bytes()
    }

    /// #530: first reap of a pair logs in full; repeats of the SAME pair are suppressed
    /// (they only feed the window aggregate). Pure — injected times, no clock.
    #[test]
    fn reap_throttle_first_reap_logs_full_and_repeats_are_suppressed_530() {
        let mut t = ReapLogThrottle::new(600, 64, REAP_LOG_TOP_PAIRS);
        assert_eq!(t.note_reap(100, "aa", "01"), ReapLogDecision::LogFull, "first reap of a pair");
        assert_eq!(t.note_reap(135, "aa", "01"), ReapLogDecision::Suppress, "repeat of the same pair");
        assert_eq!(t.note_reap(170, "aa", "01"), ReapLogDecision::Suppress);
        // A DIFFERENT pair (same channel, other holder) is its own first sighting.
        assert_eq!(t.note_reap(170, "aa", "02"), ReapLogDecision::LogFull);
        // Mid-window there is no summary yet.
        assert_eq!(t.window_summary(100 + 599), None, "window still open -> no summary");
    }

    #[test]
    fn reap_throttle_window_summary_carries_correct_counts_and_top_pairs_530() {
        // #530: the steady-state shape measured live — a few pairs reaped every TTL
        // cycle. After the window elapses, ONE summary carries the totals and the
        // busiest pairs, ordered by count.
        let mut t = ReapLogThrottle::new(600, 64, REAP_LOG_TOP_PAIRS);
        for i in 0..5 {
            t.note_reap(100 + i * 35, "aa", "01"); // 5 reaps
        }
        for i in 0..3 {
            t.note_reap(100 + i * 35, "bb", "02"); // 3 reaps
        }
        t.note_reap(200, "cc", "03"); // 1 reap
        t.note_reap(210, "dd", "04"); // 1 reap
        let s = t.window_summary(100 + 600).expect("window elapsed with repeats -> summary");
        assert_eq!(s.total, 10);
        assert_eq!(s.distinct_keys, 4);
        assert_eq!(s.untracked, 0);
        assert_eq!(s.top.len(), REAP_LOG_TOP_PAIRS, "top list is capped");
        assert_eq!(s.top[0], (("aa".into(), "01".into()), 5), "busiest pair first");
        assert_eq!(s.top[1], (("bb".into(), "02".into()), 3));
        assert_eq!(s.top[2].1, 1, "third slot holds one of the single-reap pairs");
    }

    #[test]
    fn reap_throttle_resets_after_each_window_so_pairs_log_full_again_530() {
        // The window reset IS the eviction strategy: the next window starts clean, so a
        // persistent pair gets exactly one full line + (at most) one summary mention per
        // window — bounded log volume forever — and the map never outlives a window.
        let mut t = ReapLogThrottle::new(600, 64, REAP_LOG_TOP_PAIRS);
        t.note_reap(100, "aa", "01");
        t.note_reap(135, "aa", "01");
        assert!(t.window_summary(700).is_some(), "repeats happened -> summary");
        assert_eq!(
            t.note_reap(710, "aa", "01"),
            ReapLogDecision::LogFull,
            "after the reset the pair's next reap logs in full again"
        );
        // A window in which every pair reaped exactly once was already fully logged
        // line by line — no summary, but the state still resets.
        assert_eq!(t.window_summary(710 + 600), None, "no repeats -> no summary line");
        assert_eq!(t.note_reap(1400, "aa", "01"), ReapLogDecision::LogFull, "state was still reset");
    }

    #[test]
    fn reap_throttle_caps_tracked_pairs_and_counts_the_overflow_530() {
        // #530 security aspect: an attacker cycling many distinct channels must neither
        // grow the map beyond the cap nor mint unbounded full log lines — beyond the
        // cap, reaps are counted WITHOUT identity and suppressed.
        let mut t = ReapLogThrottle::new(600, 2, REAP_LOG_TOP_PAIRS);
        assert_eq!(t.note_reap(100, "aa", "01"), ReapLogDecision::LogFull);
        assert_eq!(t.note_reap(101, "bb", "02"), ReapLogDecision::LogFull);
        assert_eq!(t.note_reap(102, "cc", "03"), ReapLogDecision::Suppress, "beyond the cap -> no full line");
        assert_eq!(t.note_reap(103, "dd", "04"), ReapLogDecision::Suppress);
        assert_eq!(t.tracked_len(), 2, "the map never exceeds the cap");
        // A pair that IS tracked still aggregates normally alongside the overflow.
        assert_eq!(t.note_reap(104, "aa", "01"), ReapLogDecision::Suppress);
        let s = t.window_summary(100 + 600).expect("summary");
        assert_eq!(s.total, 5, "every reap counted, tracked or not");
        assert_eq!(s.distinct_keys, 2);
        assert_eq!(s.untracked, 2, "overflow reaps are counted without identity");
        assert_eq!(s.top.len(), 2);
    }

    #[test]
    fn channel_park_reaped_counter_is_monotonic_530() {
        // The global counter (rendered as ct_edge_channel_park_reaped_total) counts
        // every reap. Other tests may increment it concurrently, so assert a DELTA
        // lower bound, not an absolute value.
        let before = channel_park_reaped_total();
        note_channel_park_reaped();
        note_channel_park_reaped();
        note_channel_park_reaped();
        assert!(
            channel_park_reaped_total() >= before + 3,
            "3 notes must raise the total by at least 3"
        );
    }

    /// Cross-repo wire contract: ct-agent's `error_names_park_expiry` classifies a QUIC
    /// park-expiry (vs a refusal) by matching the substring `park-expired` in the quinn-surfaced
    /// close reason. Both edge close reasons are built from
    /// [`QUIC_PARK_EXPIRED_REASON_PREFIX`]; this pins that the prefix still carries the substring
    /// the client matches, so a reword that would silently make ct-agent misread a park-expiry as
    /// a refusal fails the edge's own gate instead.
    #[test]
    fn quic_park_expiry_reasons_carry_the_wire_prefix() {
        assert!(
            QUIC_PARK_EXPIRED_REASON_PREFIX.contains("park-expired"),
            "ct-agent matches the substring \"park-expired\"; the prefix must contain it"
        );
        for why in [
            "no partner within the park TTL",
            "superseded by a newer join from the same holder",
        ] {
            let reason = quic_park_expired_reason(why);
            assert!(reason.starts_with(QUIC_PARK_EXPIRED_REASON_PREFIX));
            assert!(
                reason.contains("park-expired"),
                "a current ct-agent must classify {reason:?} as park-expiry, not a refusal"
            );
            assert!(reason.ends_with(why), "the honest human-readable why-suffix is preserved");
        }
    }

    /// #495-U2 slice 1: a `QuicBi` wraps a real quinn bi-stream as an `AsyncDuplex`, boxes
    /// into a `BoxedChannelStream` exactly like a shared-pairer offer would, and round-trips
    /// bytes both ways with a clean finish surfacing as EOF through its read half.
    #[tokio::test]
    async fn quic_bi_adapts_a_quinn_bistream_as_a_boxed_channel_stream_495_u2() {
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        let (server, cert) = build_server_endpoint_with_cert().expect("server endpoint");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.await.expect("server accepts");
            let (send, recv) = conn.accept_bi().await.expect("accept bi");
            // Box exactly as a real :4436 offer into the shared pairer will (cf. ws_channel).
            let mut duplex: BoxedChannelStream = Box::pin(QuicBi::new(conn, send, recv));
            let mut got = [0u8; 5];
            duplex.read_exact(&mut got).await.expect("read via QuicBi");
            assert_eq!(&got, b"hello");
            duplex.write_all(b"world").await.expect("write via QuicBi");
            duplex.flush().await.expect("flush via QuicBi");
            // The peer finishes its send → our read half sees EOF (no extra bytes).
            let mut tail = Vec::new();
            duplex.read_to_end(&mut tail).await.expect("read to EOF via QuicBi");
            assert!(tail.is_empty(), "a clean peer finish is EOF, not stray bytes");
        });
        let client = build_client_endpoint(cert).expect("client endpoint");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("connects");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"hello").await.expect("client writes");
        let mut reply = [0u8; 5];
        recv.read_exact(&mut reply).await.expect("client reads reply");
        assert_eq!(&reply, b"world");
        send.finish().expect("client finishes → server read half sees EOF");
        srv.await.expect("server task completes");
        drop(conn);
    }

    #[test]
    fn same_public_ip_matches_by_ip_ignoring_port_276() {
        let a: std::net::SocketAddr = "203.0.113.9:40001".parse().unwrap();
        let b: std::net::SocketAddr = "203.0.113.9:51234".parse().unwrap();
        assert!(same_public_ip(a, b), "same IP, different NAT-assigned ports must still match");
    }

    #[test]
    fn same_public_ip_rejects_different_ips_even_with_the_same_port_276() {
        let a: std::net::SocketAddr = "203.0.113.9:40001".parse().unwrap();
        let b: std::net::SocketAddr = "203.0.113.10:40001".parse().unwrap();
        assert!(!same_public_ip(a, b), "different IPs must never match regardless of port");
    }

    #[test]
    fn same_public_ip_treats_ipv4_and_ipv6_forms_of_the_same_address_as_distinct_276() {
        // Deliberately conservative: an IPv4-mapped-IPv6 vs plain-IPv4 representation of "the
        // same" address does NOT compare equal here (std::net::IpAddr::eq is exact-form, no
        // normalization) -- correct for this use, since a client that got fed a spuriously
        // "same" signal across address families could be misled into dialing an IPv6-only
        // local candidate a genuinely-IPv4-only peer can never reach.
        let a: std::net::SocketAddr = "203.0.113.9:1".parse().unwrap();
        let b: std::net::SocketAddr = "[::ffff:203.0.113.9]:1".parse().unwrap();
        assert!(!same_public_ip(a, b), "no cross-family normalization -- exact IpAddr equality only");
    }

    /// A grant for `channel`, bound to `holder`, signed by the channel operator.
    fn grant(
        channel: [u8; 32],
        holder: u8,
        direction: Direction,
        expires_at: UnixSeconds,
    ) -> SignedChannelGrant {
        let sk = SigningKey::from_bytes(&OP_SEED);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: [holder; 32],
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = sk.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    #[test]
    fn pairs_initiator_and_acceptor() {
        let pk = operator_pubkey();
        let a = grant([1u8; 32], 0xa1, Direction::Initiate, 1_000);
        let b = grant([1u8; 32], 0xb2, Direction::Accept, 1_000);
        let pairing = authorize_channel_pair(&pk, &a, &b, 500).expect("pairs");
        assert_eq!(pairing.channel, ChannelId([1u8; 32]));
        assert_eq!(pairing.initiator_holder, [0xa1; 32]);
        assert_eq!(pairing.acceptor_holder, [0xb2; 32]);
    }

    #[test]
    fn both_directions_makes_a_the_initiator() {
        let pk = operator_pubkey();
        let a = grant([2u8; 32], 0x11, Direction::Both, 1_000);
        let b = grant([2u8; 32], 0x22, Direction::Both, 1_000);
        let pairing = authorize_channel_pair(&pk, &a, &b, 500).expect("pairs");
        assert_eq!(pairing.initiator_holder, [0x11; 32], "a leads when both are flexible");
        assert_eq!(pairing.acceptor_holder, [0x22; 32]);
    }

    #[test]
    fn reverses_roles_when_only_b_can_initiate() {
        let pk = operator_pubkey();
        let a = grant([3u8; 32], 0xaa, Direction::Accept, 1_000);
        let b = grant([3u8; 32], 0xbb, Direction::Initiate, 1_000);
        let pairing = authorize_channel_pair(&pk, &a, &b, 500).expect("pairs");
        assert_eq!(pairing.initiator_holder, [0xbb; 32]);
        assert_eq!(pairing.acceptor_holder, [0xaa; 32]);
    }

    #[test]
    fn rejects_two_initiators_and_two_acceptors() {
        let pk = operator_pubkey();
        let ii_a = grant([4u8; 32], 0x01, Direction::Initiate, 1_000);
        let ii_b = grant([4u8; 32], 0x02, Direction::Initiate, 1_000);
        assert_eq!(
            authorize_channel_pair(&pk, &ii_a, &ii_b, 500),
            Err(BrokerError::IncompatibleDirections)
        );
        let aa_a = grant([4u8; 32], 0x01, Direction::Accept, 1_000);
        let aa_b = grant([4u8; 32], 0x02, Direction::Accept, 1_000);
        assert_eq!(
            authorize_channel_pair(&pk, &aa_a, &aa_b, 500),
            Err(BrokerError::IncompatibleDirections)
        );
    }

    #[test]
    fn rejects_different_channels() {
        let pk = operator_pubkey();
        let a = grant([5u8; 32], 0x01, Direction::Initiate, 1_000);
        let b = grant([6u8; 32], 0x02, Direction::Accept, 1_000);
        assert_eq!(
            authorize_channel_pair(&pk, &a, &b, 500),
            Err(BrokerError::ChannelMismatch)
        );
    }

    #[test]
    fn rejects_same_holder() {
        let pk = operator_pubkey();
        let a = grant([7u8; 32], 0x09, Direction::Both, 1_000);
        let b = grant([7u8; 32], 0x09, Direction::Both, 1_000);
        assert_eq!(authorize_channel_pair(&pk, &a, &b, 500), Err(BrokerError::SameHolder));
    }

    #[test]
    fn rejects_expired_and_wrong_operator_key() {
        let pk = operator_pubkey();
        let a = grant([8u8; 32], 0x01, Direction::Initiate, 1_000);
        let b = grant([8u8; 32], 0x02, Direction::Accept, 1_000);
        // Expired at now == expires_at.
        assert_eq!(
            authorize_channel_pair(&pk, &a, &b, 1_000),
            Err(BrokerError::GrantInvalid(GrantError::Expired))
        );
        // A different operator key must not validate these grants.
        let other = SigningKey::from_bytes(&[6u8; 32]).verifying_key().to_bytes();
        assert_eq!(
            authorize_channel_pair(&other, &a, &b, 500),
            Err(BrokerError::GrantInvalid(GrantError::BadSignature))
        );
    }

    #[test]
    fn channel_pairer_correlates_by_channel_and_never_cross_pairs() {
        // #109-pairer (frozen): the channel-keyed correlator that replaces the broker's
        // channel-blind "pair the next two arrivals". Two channels racing to connect
        // must park independently and pair only same-channel holders — never cross.
        let m = |chan: u8, holder: u8, deadline: UnixSeconds, tag: &'static str| WaitingMember {
            channel: ChannelId([chan; 32]),
            holder: [holder; 32],
            observed: None,
            deadline,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: tag,
        };
        let mut pairer: ChannelPairer<&'static str> = ChannelPairer::new();

        // First holder of channel X parks.
        assert_eq!(pairer.offer(m(0x11, 0xAA, 100, "X-init")), PairOutcome::Parked);
        assert_eq!(pairer.len(), 1);

        // A different channel Y parks independently — it does NOT cross-pair with the
        // waiting X member (this is the #109 mis-pairing failure the pairer closes).
        assert_eq!(pairer.offer(m(0x22, 0xCC, 100, "Y-init")), PairOutcome::Parked);
        assert_eq!(pairer.len(), 2);

        // The second holder of channel X pairs with exactly the first X member; Y stays.
        match pairer.offer(m(0x11, 0xBB, 100, "X-acc")) {
            PairOutcome::Paired(first, second) => {
                assert_eq!(first.payload, "X-init");
                assert_eq!(second.payload, "X-acc");
                assert_eq!(first.channel, ChannelId([0x11; 32]));
            }
            other => panic!("expected Paired(X-init, X-acc), got {other:?}"),
        }
        assert_eq!(pairer.len(), 1, "X consumed by the pairing; Y still parked");

        // A same-holder re-offer (a retry) supersedes the stale wait rather than
        // pairing the holder with itself.
        // #495 slice 1 CONTRACT CHANGE: a same-holder re-offer QUEUES (up to PARKS_PER_MEMBER)
        // instead of superseding at depth 1 -- the whole point of the queue is that a fresh
        // park no longer kills the live older one (the re-park gap, ct-agent#18).
        assert_eq!(pairer.offer(m(0x33, 0xDD, 100, "Z-v1")), PairOutcome::Parked);
        assert_eq!(pairer.offer(m(0x33, 0xDD, 200, "Z-v2")), PairOutcome::Parked, "same holder queues now");
        assert_eq!(pairer.len(), 3, "both Z parks queued, plus Y");

        // Expired waiters are drained from INSIDE queues (#3/#495): Y (deadline 100) and the
        // older Z-v1 (deadline 100) are evicted at now=150; the fresh Z-v2 (deadline 200)
        // survives behind its evicted elder.
        let mut drained: Vec<&str> = pairer.drain_expired(150).into_iter().map(|m| m.payload).collect();
        drained.sort_unstable();
        assert_eq!(drained, vec!["Y-init", "Z-v1"]);
        assert_eq!(pairer.len(), 1, "Z-v2 (deadline 200) is not yet expired at 150");
    }

    #[test]
    fn park_queue_closes_the_repark_gap_and_caps_per_member_495() {
        // #495 slice 1, the three queue properties in one place:
        // (1) same-holder re-parks DEEPEN the queue (no gap: consuming one park leaves the
        //     next already standing); (2) a different holder pairs with the OLDEST park (FIFO);
        //     (3) beyond PARKS_PER_MEMBER the member's own oldest park is superseded (bounded).
        let m = |chan: u8, holder: u8, deadline: u64, tag: &'static str| WaitingMember {
            channel: ChannelId([chan; 32]),
            holder: [holder; 32],
            observed: None,
            deadline,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: tag,
        };
        let mut pairer: ChannelPairer<&'static str> = ChannelPairer::new();

        // (1) depth builds without supersede up to the cap.
        for (i, tag) in ["a1", "a2", "a3", "a4"].iter().enumerate() {
            assert_eq!(
                pairer.offer(m(0x55, 0xAA, 100 + i as u64, tag)),
                PairOutcome::Parked,
                "park {tag} queues"
            );
        }
        assert_eq!(pairer.len(), 4);

        // (3) the 5th park supersedes the OLDEST (a1), not the newest.
        match pairer.offer(m(0x55, 0xAA, 105, "a5")) {
            PairOutcome::Superseded(stale) => assert_eq!(stale.payload, "a1", "oldest ages out first"),
            other => panic!("expected Superseded(a1), got {other:?}"),
        }
        assert_eq!(pairer.len(), 4, "still at the cap");

        // (2) a different holder pairs with the oldest REMAINING park (a2)...
        match pairer.offer(m(0x55, 0xBB, 300, "b1")) {
            PairOutcome::Paired(oldest, fresh) => {
                assert_eq!(oldest.payload, "a2", "FIFO: the longest-waiting park is consumed first");
                assert_eq!(fresh.payload, "b1");
            }
            other => panic!("expected Paired, got {other:?}"),
        }
        // ...and the NEXT partner pairs instantly with a3 -- the re-park gap is structurally
        // gone: no window where the member has zero parks between consumption and re-admit.
        match pairer.offer(m(0x55, 0xBB, 300, "b2")) {
            PairOutcome::Paired(oldest, _) => assert_eq!(oldest.payload, "a3"),
            other => panic!("expected Paired with a3, got {other:?}"),
        }
        assert_eq!(pairer.len(), 2, "a4 + a5 still parked, ready for further partners");
    }

    #[test]
    fn admission_accepts_the_relay_only_sentinel_but_still_refuses_private_addresses() {
        // #121 (frozen): a NAT-only member advertises the relay-only sentinel and is admitted
        // WITHOUT weakening `safe_endpoint` — a private / loopback / internal address is still
        // refused exactly as #94 requires. The sentinel is a reserved non-address, so a hostile
        // holder can't smuggle a LAN SSRF target through it: it's the sentinel or a real
        // global-unicast address, nothing in between.
        use ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY;
        let mk = |ep: &str| ChannelJoinRequest {
            grant: grant([1u8; 32], 0xaa, Direction::Initiate, 1_000),
            endpoint: ep.to_string(),
        };
        // The explicit sentinel is admitted...
        assert!(admissible_endpoint(&mk(CHANNEL_ENDPOINT_RELAY_ONLY)), "the relay-only sentinel is admitted");
        // ...and is not itself a parseable address, so it can't collide with a real endpoint
        // and `safe_endpoint` (unchanged) never treats it as one.
        assert!(safe_endpoint(CHANNEL_ENDPOINT_RELAY_ONLY).is_none(), "the sentinel is not a safe_endpoint address");
        // Every private / loopback / internal address is STILL refused (safe_endpoint intact).
        for bad in ["10.0.0.5:22", "127.0.0.1:22", "192.168.1.1:22", "169.254.169.254:80", "[fc00::1]:22"] {
            assert!(!admissible_endpoint(&mk(bad)), "{bad} is still refused — the sentinel didn't weaken #94");
        }
        // A real global-unicast address still passes on its own merits.
        assert!(admissible_endpoint(&mk("203.0.113.10:7001")), "a public address is still admitted");
    }

    /// Wire-Probe (#495 U2): traegt das `endpoint`-Feld einen Faehigkeits-Marker?
    ///
    /// Der letzte verbliebene Kandidat, nachdem das Praeambel-Byte (definitive Abweisung
    /// samt #509-Strafe) und ALPN (Stichtag, gemessen in `pki.rs`) ausgeschieden sind. Der
    /// Rumpf der Anfrage ist `grant(fest) | endpoint(Rest)` und hat keine Feldstruktur --
    /// ein Marker koennte nur an die Endpunkt-Zeichenkette angehaengt werden.
    ///
    /// Gemessen statt geschlossen: `safe_endpoint` parst die GANZE Zeichenkette strikt,
    /// und das relay-only-Sentinel wird exakt verglichen. Damit ist auch dieser Weg zu.
    /// #495 U2 (b'): der QUIC-Pfad TOLERIERT jetzt eine optionale Phasen-Praeambel.
    ///
    /// Drei Faelle, und der erste ist der wichtigste: **ein Bestandsclient**, der gar keine
    /// Praeambel sendet, muss byte-genau wie zuvor gelesen werden. Genau das leistet der
    /// Peek, indem er die beiden Bytes zurueckstellt -- ohne diese Zusage waere die
    /// Toleranz-Scheibe ein Ausfall aller heutigen QUIC-Joins statt einer Vorbereitung.
    #[tokio::test]
    async fn the_quic_join_tolerates_an_optional_phase_preamble_495_u2() {
        use tokio::io::AsyncWriteExt;

        // 1. Bestandsclient: keine Praeambel. Die zwei Bytes sind die Laenge und muessen
        //    unveraendert wieder herauskommen.
        let (mut c, srv) = tokio::io::duplex(64);
        tokio::spawn(async move { c.write_all(&[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']).await.unwrap(); });
        let Ok((mut recv, phase)) = peek_optional_phase_marker(srv).await else { panic!("kein Marker ist zulaessig") };
        assert_eq!(phase, ParkPhase::Unmarked);
        let mut got = [0u8; 7];
        recv.read_exact(&mut got).await.expect("Bytes zurueckgestellt");
        assert_eq!(&got, &[0x00, 0x05, b'h', b'e', b'l', b'l', b'o'], "byte-genau wie ohne Peek");

        // 2. Markierter Client: der Marker wird verbraucht, der Rest bleibt unberuehrt.
        let (mut c2, srv2) = tokio::io::duplex(64);
        tokio::spawn(async move {
            c2.write_all(&[PHASE_PREAMBLE_MAGIC, 0x02, 0x00, 0x02, b'h', b'i']).await.unwrap();
        });
        let Ok((mut recv2, phase2)) = peek_optional_phase_marker(srv2).await else { panic!("Marker zulaessig") };
        assert_eq!(phase2, ParkPhase::Relay);
        let mut got2 = [0u8; 4];
        recv2.read_exact(&mut got2).await.expect("Rest unberuehrt");
        assert_eq!(&got2, &[0x00, 0x02, b'h', b'i'], "der Marker ist verbraucht, sonst nichts");

        // 3. Unbekanntes Byte nach der Magie: bleibt DEFINITIV abgewiesen -- die Toleranz
        //    ist eng, nicht generell. Ein Client-Fehler darf weiterhin nicht als transient
        //    durchgehen (#509).
        let (mut c3, srv3) = tokio::io::duplex(64);
        tokio::spawn(async move { let _ = c3.write_all(&[PHASE_PREAMBLE_MAGIC, 0x7F]).await; });
        let Err(e) = peek_optional_phase_marker(srv3).await else { panic!("unbekannter Marker muss abgewiesen werden") };
        assert!(
            e.downcast_ref::<DefinitiveJoinRefusal>().is_some(),
            "und zwar DEFINITIV, damit die Pro-IP-Strafe greift: {e}"
        );
    }

    #[test]
    fn an_endpoint_with_an_appended_capability_marker_is_refused_495_u2() {
        use ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY;
        assert!(safe_endpoint("203.0.113.9:9001").is_some(), "die nackte Adresse ist zulaessig");
        assert!(
            safe_endpoint("203.0.113.9:9001;ss").is_none(),
            "ein angehaengter Marker macht die Adresse unparsbar -- der Bestands-Edge weist ab"
        );
        let relay_only_with_marker = format!("{CHANNEL_ENDPOINT_RELAY_ONLY};ss");
        assert_ne!(
            relay_only_with_marker, CHANNEL_ENDPOINT_RELAY_ONLY,
            "und am relay-only-Sentinel ebenso: es wird exakt verglichen"
        );
    }

    #[test]
    fn safe_endpoint_rejects_private_and_internal_ranges() {
        // #94: a peer dials the advertised endpoint, so only publicly-routable
        // addresses may pass — a holder must not be able to make the peer dial the
        // operator's LAN, the cloud metadata service, or a link-local host.
        for bad in [
            "127.0.0.1:22",        // loopback
            "0.0.0.0:80",          // unspecified
            "224.0.0.1:80",        // multicast
            "10.0.0.5:22",         // RFC1918
            "172.16.0.1:22",       // RFC1918
            "192.168.1.1:22",      // RFC1918
            "169.254.169.254:80",  // link-local (cloud metadata!)
            "100.64.0.1:22",       // CGNAT 100.64/10
            "[::1]:22",            // v6 loopback
            "[fe80::1]:22",        // v6 link-local
            "[fc00::1]:22",        // v6 unique-local
            "[fd12:3456::1]:22",   // v6 unique-local
            "not-an-address",
        ] {
            assert!(safe_endpoint(bad).is_none(), "{bad} must be rejected");
        }
        for ok in [
            "203.0.113.10:7001",             // public unicast (TEST-NET stand-in)
            "8.8.8.8:443",                   // public unicast
            "[2001:4860:4860::8888]:443",    // public v6 unicast
        ] {
            assert!(safe_endpoint(ok).is_some(), "{ok} must be allowed");
        }
    }

    // --- AF2d-transport: the QUIC channel-join admission gate ---

    /// A holder keypair with a real ed25519 public key (unlike the `[byte; 32]`
    /// fake pubkeys used in the pure-authz tests) so the possession round-trip works.
    fn holder_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A grant bound to a real holder pubkey, signed by the channel operator.
    fn grant_h(
        channel: [u8; 32],
        holder: &SigningKey,
        direction: Direction,
        expires_at: UnixSeconds,
    ) -> SignedChannelGrant {
        let sk = SigningKey::from_bytes(&OP_SEED);
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = sk.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// Drive the client side of the admission handshake: send the length-framed
    /// request, then (if the edge challenges) sign it under `holder` to prove
    /// possession. Returns the edge's final ack (empty if refused pre-possession).
    async fn present_join(
        conn: &quinn::Connection,
        req_bytes: &[u8],
        holder: &SigningKey,
    ) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        send.write_all(req_bytes).await.expect("write request");
        // Answer the edge's possession challenge; if the join was refused before
        // that point the stream finishes early and read_exact fails — return the ack.
        let mut challenge = [0u8; 32];
        if recv.read_exact(&mut challenge).await.is_ok() {
            let sig = holder.sign(&challenge).to_bytes();
            let _ = send.write_all(&sig).await;
        }
        let _ = send.finish();
        // 512, matching the real client's cap (`present_channel_join_on_stream`'s
        // `recv.take(512)`) -- a rich relay ack (endpoint + noise + holder + attestation,
        // #134-follow) can exceed the old 128-byte cap, which silently truncated to empty
        // via `unwrap_or_default()` rather than failing loudly.
        recv.read_to_end(512).await.unwrap_or_default()
    }

    /// Like [`present_join`], but returns as soon as the possession signature is sent —
    /// does NOT wait for an ack. A successfully-admitted-but-PARKED member gets no ack at
    /// all until it's matched or TTL-swept (silence, not a reply — see e.g.
    /// `ws_channel.rs`'s "a lone member with no partner parks" test), so `present_join`'s
    /// trailing `recv.read_to_end` would block for however long that takes. Used by tests
    /// that need to observe the parked state itself (e.g. permit accounting, #451) rather
    /// than wait through to a pairing/eviction outcome.
    async fn present_join_no_ack(conn: &quinn::Connection, req_bytes: &[u8], holder: &SigningKey) {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        send.write_all(req_bytes).await.expect("write request");
        let mut challenge = [0u8; 32];
        recv.read_exact(&mut challenge).await.expect("challenge");
        let sig = holder.sign(&challenge).to_bytes();
        send.write_all(&sig).await.expect("write signature");
    }

    fn join_request(channel: [u8; 32], holder: u8, endpoint: &str) -> ChannelJoinRequest {
        ChannelJoinRequest {
            grant: grant(channel, holder, Direction::Initiate, 1_000),
            endpoint: endpoint.to_string(),
        }
    }

    #[tokio::test]
    async fn relay_handoff_ack_failure_names_the_dead_side_not_an_auth_refusal() {
        // #148 (frozen): when one member's stream dies mid-handoff (a re-park race), the completer
        // must report WHICH side failed — distinct from an authorization refusal — so the healthy
        // survivor's drop doesn't read as "your grant was refused". Here authorization succeeds for
        // both, A's ack lands, then B's already-dead stream fails: the error is a RelayHandoffError
        // naming side B (not a "refused"), and A did receive its OK (proving it was healthy).
        use tokio::io::{duplex, AsyncReadExt};

        let ch = [7u8; 32];
        let a_key = SigningKey::from_bytes(&[0x21u8; 32]);
        let b_key = SigningKey::from_bytes(&[0x22u8; 32]);
        let op = operator_pubkey();
        let now = 100;

        let (a_stream, mut a_peer) = duplex(1024);
        let (b_stream, b_peer) = duplex(1024);
        drop(b_peer); // B's stream is "dying" — writes to it now fail (BrokenPipe).

        let a = AdmittedStreamMember {
            stream: a_stream,
            req: ChannelJoinRequest {
                grant: grant_h(ch, &a_key, Direction::Both, 9_000),
                endpoint: "relay-only".to_string(),
            },
            operator: op,
            noise: None,
            attest: None,
            observed: "203.0.113.9:9999".parse().unwrap(),
            session: SessionSource::SameStream,
            _permit: None,
        };
        let b = AdmittedStreamMember {
            stream: b_stream,
            req: ChannelJoinRequest {
                grant: grant_h(ch, &b_key, Direction::Both, 9_000),
                endpoint: "relay-only".to_string(),
            },
            operator: op,
            noise: None,
            attest: None,
            observed: "203.0.113.9:9999".parse().unwrap(),
            session: SessionSource::SameStream,
            _permit: None,
        };

        let err = finish_relay_pair_over_streams(a, b, now)
            .await
            .expect_err("B's dead stream must fail the handoff");

        // The failure is typed and names side B — NOT an authorization refusal.
        let handoff = err
            .downcast_ref::<RelayHandoffError>()
            .expect("a mid-handoff ack failure is a RelayHandoffError, not a generic drop");
        assert_eq!(handoff.failed_side, PairSide::B, "the dead side (B) is identified");
        let msg = format!("{err}");
        assert!(!msg.contains("refused"), "must not read as an authorization refusal: {msg}");

        // The survivor A DID receive its OK ack before B failed — proof it was healthy and this is a
        // handoff race, not an admission problem on A.
        let mut buf = [0u8; 3];
        a_peer.read_exact(&mut buf).await.expect("A got its ack before B failed");
        assert_eq!(&buf, b"OK ", "the surviving side A was acked OK (its grant was fine all along)");
    }

    #[tokio::test]
    async fn quic_ack_member_tags_the_side_on_a_mid_handoff_write_failure() {
        // #154 (frozen): the QUIC-native completer's per-side ack (finish_relay_pair) tags an I/O
        // failure with its PairSide, so a mid-handoff drop on the NAT-to-NAT relay path is a typed
        // RelayHandoffError (naming the dead side, explicitly "not an admission refusal") — not the bare
        // "connection lost" that #148 eliminated on the stream sibling but missed here.
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let conn = incoming.await.expect("server accepts the connection");
                // Keep the connection alive briefly so the client handshake + open_bi complete.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                drop(conn);
            }
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("client connects");
        let (mut send, _recv) = conn.open_bi().await.expect("open the admission bi-stream");
        // Close the connection locally → any ack write on its stream now fails (a dying member's
        // mid-handoff drop, deterministically reproduced).
        conn.close(0u32.into(), b"member gone mid-handoff");

        // Pass a rich `OK ...` ack line (the shape finish_rendezvous_pair uses) to confirm the shared
        // helper is content-agnostic across all three completers.
        let err = quic_ack_member(&mut send, b"OK 203.0.113.9:1 r=203.0.113.9:2", PairSide::B)
            .await
            .expect_err("acking over a closed connection must fail");
        assert_eq!(err.failed_side, PairSide::B, "the dead side (B) is identified, not a bare error");
        assert!(
            format!("{err}").contains("not an admission refusal"),
            "the QUIC-native completer now disambiguates a handoff race from a refusal too"
        );
        srv.abort();
    }

    /// Read the relay's `OK <..>\n` ack line off a spliced stream, stopping at the newline
    /// delimiter (#122) so the session/app bytes that follow on the SAME stream stay unread —
    /// mirroring the client's `present_channel_relay_join_on_stream`. Returns the line without
    /// the trailing newline (a bare `NO` refusal, which has no newline, comes back on EOF).
    async fn read_relay_ack_line<R: AsyncRead + Unpin>(recv: &mut R) -> Vec<u8> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while recv.read_exact(&mut byte).await.is_ok() {
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        line
    }

    #[tokio::test]
    async fn edge_admits_a_valid_channel_join() {
        let pk = operator_pubkey();
        let channel = [0xC1u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6001".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|r| r.endpoint)
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert_eq!(ack, b"OK");
        conn.close(0u32.into(), b"done");

        let endpoint = server_task.await.expect("join").expect("admitted");
        assert_eq!(endpoint, "203.0.113.9:6001", "handler returns the advertised endpoint");
    }

    #[tokio::test]
    async fn read_join_on_connection_admits_a_valid_join() {
        // #81 SEC81c-c c-iii-2: the connection-level entry point — what the live edge's
        // accept loop dispatches to once it has accepted the QUIC connection itself.
        let pk = operator_pubkey();
        let channel = [0xD7u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6011".to_string(),
        };
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            // Accept the connection first (as the live edge loop does), then read the join.
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut send, req, _op, _noise, _attest, _observed) = read_join_on_connection(&conn, 500, std::time::Duration::from_secs(5), &move |c, _h| async move {
                (c.0 == channel).then_some((pk, None, None))
            })
            .await
            .expect("admitted");
            send.write_all(b"OK").await.expect("ack");
            send.finish().expect("finish");
            conn.closed().await;
            req.endpoint
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert_eq!(ack, b"OK", "connection-level gate admits a valid join");
        conn.close(0u32.into(), b"done");
        assert_eq!(server_task.await.expect("join"), "203.0.113.9:6011");
    }

    #[tokio::test]
    async fn read_channel_join_on_stream_admits_over_a_plain_duplex() {
        // #106 edge-dispatch (frozen): the admission is transport-agnostic. The SAME
        // framed request + membership/grant check + single-use possession challenge the
        // QUIC broker runs over a quinn bi-stream must admit an identical join presented
        // over a plain in-memory duplex — the stand-in for a TLS-over-TCP `:443`
        // front-door stream. This is what lets a member whose restrictive network blocks
        // the channel UDP/TCP ports reach the broker through the `:443` front door.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let pk = operator_pubkey();
        let channel = [0xE2u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6021".to_string(),
        };

        let (client_end, server_end) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = split(server_end);
        let server_task = tokio::spawn(async move {
            // Note: read/write halves are passed as distinct AsyncRead/AsyncWrite, not a
            // quinn connection — no QUIC anywhere in this path.
            let observed: std::net::SocketAddr = "203.0.113.50:40001".parse().unwrap();
            let (mut send, _recv, req, _op, _noise, _attest, _observed) = read_channel_join_on_stream(
                srv_w,
                srv_r,
                observed,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a plain duplex");
            send.write_all(b"OK").await.expect("ack");
            send.shutdown().await.expect("shutdown");
            req.endpoint
        });

        // Drive the client side of the admission handshake over the same duplex.
        let (mut cli_r, mut cli_w) = split(client_end);
        let req_bytes = req.encode();
        cli_w
            .write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        cli_w.write_all(&req_bytes).await.expect("write request");
        let mut challenge = [0u8; 32];
        cli_r.read_exact(&mut challenge).await.expect("read challenge");
        let sig = holder.sign(&challenge).to_bytes();
        cli_w.write_all(&sig).await.expect("write possession sig");
        let mut ack = [0u8; 2];
        cli_r.read_exact(&mut ack).await.expect("read ack");
        assert_eq!(&ack, b"OK", "plain-duplex admission returns the same OK ack as QUIC");

        assert_eq!(
            server_task.await.expect("join"),
            "203.0.113.9:6021",
            "the handler receives the advertised endpoint over a non-QUIC transport",
        );
    }

    #[tokio::test]
    async fn channel_join_refusal_wire_carries_the_category_token() {
        // #524: a refusal is no longer the bare `NO` — it is `NO` + one length-framed
        // category token from the closed vocabulary, so the client can self-diagnose the
        // CLASS of failure (the free-text reason still never leaves the edge log). Drive
        // the two client-visible flagship checkpoints end to end and pin the exact wire
        // bytes; every frame must also stay strictly under 32 bytes (ct-agent v0.4.14
        // reads the pre-challenge response with `take(32)` and would mistake an exactly-
        // 32-byte refusal for the possession challenge).
        use ct_common::channel::decode_channel_refusal_category;
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let pk = operator_pubkey();
        let channel = [0xE3u8; 32];
        let holder = holder_sk(0x0b);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6022".to_string(),
        };

        // (1) possession: challenge answered under the WRONG key -> `NO` + `possession`.
        let (client_end, server_end) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = split(server_end);
        let server_task = tokio::spawn(async move {
            let observed: std::net::SocketAddr = "203.0.113.50:40002".parse().unwrap();
            read_channel_join_on_stream(
                srv_w,
                srv_r,
                observed,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .map(|_| ())
        });
        let (mut cli_r, mut cli_w) = split(client_end);
        let req_bytes = req.encode();
        cli_w.write_all(&(req_bytes.len() as u16).to_be_bytes()).await.expect("write length");
        cli_w.write_all(&req_bytes).await.expect("write request");
        let mut challenge = [0u8; 32];
        cli_r.read_exact(&mut challenge).await.expect("read challenge");
        let thief = holder_sk(0x77);
        let sig = thief.sign(&challenge).to_bytes();
        cli_w.write_all(&sig).await.expect("write bad possession sig");
        let mut refusal = Vec::new();
        cli_r.read_to_end(&mut refusal).await.expect("read refusal to EOF");
        assert_eq!(refusal, encode_channel_refusal("possession"), "NO + framed `possession`");
        assert_eq!(decode_channel_refusal_category(&refusal[2..]), Some("possession"));
        assert!(refusal.len() < 32, "v0.4.14 take(32) challenge-ambiguity guard");
        assert!(server_task.await.expect("task").is_err(), "the join itself was refused");

        // (2) not-member: authorize says no -> pre-challenge `NO` + `not-member`.
        let (client_end, server_end) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = split(server_end);
        let server_task = tokio::spawn(async move {
            let observed: std::net::SocketAddr = "203.0.113.50:40003".parse().unwrap();
            read_channel_join_on_stream(
                srv_w,
                srv_r,
                observed,
                500,
                std::time::Duration::from_secs(5),
                &move |_c, _h| async move { None },
            )
            .await
            .map(|_| ())
        });
        let (mut cli_r, mut cli_w) = split(client_end);
        cli_w.write_all(&(req_bytes.len() as u16).to_be_bytes()).await.expect("write length");
        cli_w.write_all(&req_bytes).await.expect("write request");
        let mut refusal = Vec::new();
        cli_r.read_to_end(&mut refusal).await.expect("read refusal to EOF");
        assert_eq!(refusal, encode_channel_refusal("not-member"), "NO + framed `not-member`");
        assert!(refusal.len() < 32, "v0.4.14 take(32) challenge-ambiguity guard");
        assert!(server_task.await.expect("task").is_err(), "the join itself was refused");
    }

    #[test]
    fn no_channel_plane_refusal_site_writes_a_bare_no_literal() {
        // #524 regression guard: every channel-plane refusal must go through
        // `ct_common::channel::encode_channel_refusal` (sentinel + framed category), so a
        // future checkpoint can't quietly reintroduce the diagnosis-free bare `NO`. The
        // pattern is assembled at runtime so this test doesn't match itself.
        //
        // The file set is DERIVED, not listed. It used to be two `include_str!`s naming
        // channel_broker.rs and relay_gate.rs — correct on the day it was written, and a
        // snapshot ever after: `ws_channel.rs` already admits channel joins, and the day a
        // refusal is written there (or in any new channel-plane file) the guard would have
        // kept passing without ever looking. That is the #566 shape — a guard whose coverage
        // is a hand-kept list rather than a consequence of what it protects.
        //
        // A file belongs to the channel plane iff it uses the channel-refusal machinery.
        // Bare `NO` writes elsewhere in this crate are correct: the rendezvous, credential
        // and agent-registration planes have their own wire contracts and are not #524's
        // subject. Reading the directory at test time is what makes "every channel-plane
        // file" true rather than "the two we thought of".
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let bare_write = format!("write_all(b\"{}\")", "NO");
        let mut scanned = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("edge src dir is readable") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("source file is readable");
            let in_channel_plane =
                src.contains("encode_channel_refusal") || src.contains("CHANNEL_REFUSAL_SENTINEL");
            if !in_channel_plane {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            scanned.push(name.clone());
            assert_eq!(
                src.matches(&bare_write).count(),
                0,
                "{name} writes a bare NO literal — route it through encode_channel_refusal (#524)",
            );
        }
        // A scan that silently covered nothing would pass exactly like a clean one.
        assert!(
            scanned.len() >= 2,
            "expected to find at least the two known channel-plane files, scanned: {scanned:?}"
        );
    }

    #[tokio::test]
    async fn channel_join_refusal_reason_is_distinct_per_checkpoint() {
        // #124 observability contract (frozen): `read_channel_join_on_stream` refuses at
        // six admission checkpoints, and each must return a DISTINCT,
        // checkpoint-identifying `Err` so the operator's server-side `[<tag>]` log can pin
        // a live refusal (e.g. the #103 :443 sink↔source stall) to the exact check that
        // fired. Drive each checkpoint by mutating one thing off the happy path and assert
        // the returned reason names it. (#524 updated the wire half of #124: the ack now
        // carries the checkpoint CATEGORY as a framed closed-vocabulary token after `NO` —
        // see `channel_join_refusal_wire_carries_the_category_token` — while the free-text
        // reason still lives only in the Err/log, never on the wire.)
        use std::future::Future;
        use std::time::Duration;
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt, DuplexStream};

        // Run one crafted admission attempt to completion and return the refusal reason.
        // `authorize` supplies the membership verdict; `client` drives the presenter side
        // (writing the crafted request, answering the possession challenge, etc.).
        async fn refusal<F, Fut, C, CFut>(now: UnixSeconds, authorize: F, client: C) -> String
        where
            F: Fn(ChannelId, [u8; 32]) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send,
            C: FnOnce(DuplexStream) -> CFut,
            CFut: Future<Output = ()>,
        {
            let (client_end, server_end) = tokio::io::duplex(4096);
            let (srv_r, srv_w) = split(server_end);
            let observed: std::net::SocketAddr = "203.0.113.50:40001".parse().unwrap();
            let server = tokio::spawn(async move {
                read_channel_join_on_stream(
                    srv_w,
                    srv_r,
                    observed,
                    now,
                    Duration::from_secs(5),
                    &authorize,
                )
                .await
            });
            client(client_end).await;
            server
                .await
                .expect("server task")
                .expect_err("admission must be refused")
                .to_string()
        }

        // Present a length-framed request, then answer the possession challenge with the
        // supplied 64-byte signature (`None` = never reach/answer possession).
        async fn present(mut c: DuplexStream, req_bytes: Vec<u8>, sig: Option<[u8; 64]>) {
            c.write_all(&(req_bytes.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&req_bytes).await.unwrap();
            if let Some(sig) = sig {
                let mut challenge = [0u8; 32];
                if c.read_exact(&mut challenge).await.is_ok() {
                    c.write_all(&sig).await.unwrap();
                }
            }
        }

        let channel = [0x7Au8; 32];
        let holder = holder_sk(0x0a);
        let pk = operator_pubkey();
        // A well-formed, member, public-endpoint, unexpired request — the single fixture we
        // mutate one field of per case to hit each checkpoint.
        let good = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6021".to_string(),
        };
        // authorize verdicts: a member (yields the real operator key) vs. a non-member.
        let member = move |c: ChannelId, _h: [u8; 32]| async move {
            (c.0 == channel).then_some((pk, None, None))
        };
        let non_member = move |_c: ChannelId, _h: [u8; 32]| async move { None };

        // 1) len-oob: a length prefix of 0 (before any request bytes).
        let r1 = refusal(500, member, |mut c| async move {
            c.write_all(&0u16.to_be_bytes()).await.unwrap();
        })
        .await;
        assert_eq!(r1, "channel join request length out of range", "len-oob");

        // 2) malformed: a valid length prefix over undecodable bytes.
        let r2 = refusal(500, member, |mut c| async move {
            let junk = [0xFFu8; 4];
            c.write_all(&(junk.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&junk).await.unwrap();
        })
        .await;
        assert_eq!(r2, "malformed channel join request", "malformed");

        // 3) endpoint: a well-formed request advertising a private (SSRF) address.
        let mut bad_ep = good.clone();
        bad_ep.endpoint = "10.0.0.5:22".to_string();
        let bytes3 = bad_ep.encode();
        let r3 = refusal(500, member, move |c| present(c, bytes3, None)).await;
        assert_eq!(r3, "unsafe advertised endpoint", "endpoint");

        // 4) not-member: a fully valid request, but authorize yields no membership.
        let bytes4 = good.encode();
        let r4 = refusal(500, non_member, move |c| present(c, bytes4, None)).await;
        assert_eq!(r4, "unknown channel or holder not a member", "not-member");

        // 5) grant-verify: a member, but the grant is expired (now >= expires_at).
        let bytes5 = good.encode();
        let r5 = refusal(2_000, member, move |c| present(c, bytes5, None)).await;
        assert!(
            r5.starts_with("channel grant rejected"),
            "grant-verify reason must name the grant check, got: {r5}",
        );

        // 6) possession: valid up to the challenge, then a wrong 64-byte signature.
        let bytes6 = good.encode();
        let r6 = refusal(500, member, move |c| present(c, bytes6, Some([0u8; 64]))).await;
        assert_eq!(r6, "holder possession proof failed", "possession");

        // The six reasons must all be distinct so each maps to exactly one checkpoint.
        let reasons = [r1, r2, r3, r4, r5, r6];
        for i in 0..reasons.len() {
            for j in (i + 1)..reasons.len() {
                assert_ne!(reasons[i], reasons[j], "checkpoint reasons must be distinct");
            }
        }
    }

    #[tokio::test]
    async fn idle_broker_loop_beats_the_heartbeat_and_sweeps_expired_parks_497() {
        // #497 slice 2, both halves of the idle tick's job, against a REAL loopback QUIC
        // endpoint: (1) liveness -- the heartbeat advances while the loop sits idle, so
        // /metrics can tell "idle" from "wedged" (the 2026-08-13 invisible-outage class);
        // (2) idle-time sweeping -- an expired lone park is reaped WITHOUT any new connection
        // arriving. Previously the sweep ran only per-accept, so a quiet endpoint held an
        // expired park (and its #451 cap permit) indefinitely; this test parks ONE real member,
        // expires it via the fake clock, and proves the tick alone evicts it.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let pk = operator_pubkey();
        let chan = [0x77u8; 32];
        let clock = Arc::new(AtomicU64::new(100));
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let pairer: SharedQuicChannelPairer =
            std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new()));
        let heartbeat = std::sync::Arc::new(crate::state::BrokerHeartbeat::new());

        let clock_loop = clock.clone();
        let pairer_loop = pairer.clone();
        let hb_loop = heartbeat.clone();
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                move || clock_loop.load(Ordering::Relaxed),
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == chan).then_some((pk, None, None)) },
                5, // park TTL in fake-clock seconds
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_rendezvous_pair,
                None,
                crate::shutdown::ShutdownSignal::never(),
                pairer_loop,
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                hb_loop,
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        // ONE real member joins and parks (its partner never comes).
        let lone = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan, holder_sk(0xc3), Direction::Initiate, "203.0.113.9:7009", None, None,
        ));
        // Wait until it is genuinely parked.
        for _ in 0..100 {
            if !pairer.lock_safe().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(pairer.lock_safe().len(), 1, "the lone member parked");
        let beat_at_park = heartbeat.last_seen();
        assert_eq!(beat_at_park, 100, "iterations so far beat with the fake clock's time");

        // Expire it and let ONE idle tick (10s real time) pass -- NO further connection.
        clock.store(200, Ordering::Relaxed);
        let mut swept = false;
        for _ in 0..140 {
            if pairer.lock_safe().is_empty() {
                swept = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(swept, "the expired park was swept by the idle tick alone (no new connection)");
        assert_eq!(heartbeat.last_seen(), 200, "the idle tick beat the heartbeat with fresh time");
        // The reaped member's connection was closed -- its join attempt ends (err or timeout).
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), lone).await;
        driver.abort();
    }

    #[tokio::test]
    async fn a_reaped_park_notifies_the_client_with_the_ex_token_21() {
        // ct-agent#21: a reaped member's client must be able to DISTINGUISH "your park
        // expired, re-park" from a refusal/failure -- the wire signal is the bare EX token
        // followed by stream shutdown. An old client that doesn't know EX sees the same
        // close-with-junk-or-nothing it always did; a current one re-parks the same rung.
        use tokio::io::AsyncReadExt;
        let (mut client_end, server_end) = tokio::io::duplex(64);
        let member = AdmittedStreamMember {
            stream: server_end,
            req: ChannelJoinRequest {
                grant: grant_h([0x21u8; 32], &holder_sk(0x21), Direction::Accept, 1_000),
                endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            },
            operator: operator_pubkey(),
            noise: None,
            attest: None,
            observed: "203.0.113.9:9999".parse().unwrap(),
            session: SessionSource::SameStream,
            _permit: None,
        };
        member.notify_park_expired().await;
        let mut buf = Vec::new();
        client_end.read_to_end(&mut buf).await.expect("read to EOF");
        assert_eq!(buf, PARK_EXPIRED_TOKEN, "exactly the EX token, then clean EOF");
    }

    #[tokio::test(start_paused = true)]
    async fn park_keepalive_pump_ticks_nuls_while_parked_and_stops_at_the_first_ack_chunk_500() {
        // #500 K2 core behavior: one NUL of application payload per PARK_KEEPALIVE_INTERVAL
        // toward the client while parked; the FIRST edge->client chunk (the ack/EX) stops
        // the keepalive for good; payload still relays in both directions afterwards.
        use tokio::io::AsyncReadExt;
        let (client_end, real) = tokio::io::duplex(4096);
        let boxed: BoxedChannelStream = Box::pin(real);
        let (lv, _dead) = ParkLiveness::monitored();
        let _ = lv;
        let mut parked_end = spawn_park_keepalive_pump(boxed, true, _dead);
        let (mut client_r, mut client_w) = tokio::io::split(client_end);

        // Three intervals of parked silence -> exactly three NULs, on schedule.
        let mut nul = [0u8; 1];
        for i in 0..3u32 {
            tokio::time::advance(PARK_KEEPALIVE_INTERVAL).await;
            client_r.read_exact(&mut nul).await.expect("keepalive byte");
            assert_eq!(nul[0], 0, "keepalive tick {i} is a NUL");
        }

        // The completer writes the ack through the parked end -> client sees it verbatim...
        parked_end.write_all(b"OK 203.0.113.5:9999").await.expect("ack");
        parked_end.flush().await.expect("flush");
        let mut ack = [0u8; 19];
        client_r.read_exact(&mut ack).await.expect("ack relayed");
        assert_eq!(&ack[..], b"OK 203.0.113.5:9999");

        // ...and the keepalive is off for good: two more intervals, not one further byte.
        let quiet = tokio::time::timeout(PARK_KEEPALIVE_INTERVAL * 2 + std::time::Duration::from_secs(1), async {
            let mut b = [0u8; 1];
            client_r.read_exact(&mut b).await.map(|_| b[0])
        })
        .await;
        assert!(quiet.is_err(), "no byte after the ack -- keepalive stopped, got {quiet:?}");

        // Client->edge payload still relays through the pump (the session phase).
        client_w.write_all(b"m1").await.expect("client payload");
        client_w.flush().await.expect("flush");
        let mut m1 = [0u8; 2];
        parked_end.read_exact(&mut m1).await.expect("relayed to the parked side");
        assert_eq!(&m1[..], b"m1");
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_park_delivers_nuls_then_ex_through_the_real_admission_path_500() {
        // #500 K2 end-to-end (minus TLS): a keepalive-negotiated member drives the REAL
        // admission over admit_and_pair_on_boxed_stream, parks, receives NUL keepalives,
        // and when the reaper drains it past TTL the EX token arrives THROUGH the pump --
        // the client-visible byte stream is NUL* then EX then EOF, exactly what a
        // KA-negotiated v0.4.12 client strips-then-classifies.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x50u8; 32];
        let holder = holder_sk(0xd4);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Accept, 1_000),
            endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        };
        let (c, s) = tokio::io::duplex(4096);
        let sk = holder_sk(0xd4);
        let client = tokio::spawn(async move {
            let mut c = c;
            let rb = req.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf).await;
            buf
        });
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.7:7050".parse().unwrap();
        let r = admit_and_pair_on_boxed_stream(
            Box::pin(s),
            obs,
            500,
            std::time::Duration::from_secs(5),
            &authorize,
            530, // deadline: 30s TTL from admission at now=500
            &pairer,
            None,
            true,
        )
        .await
        .expect("admit");
        assert!(r.is_none(), "lone member parks");

        // Let the freshly spawned pump task take its first poll NOW (virtual t0), so its
        // interval anchors at t0 + INTERVAL -- without this, the task's first poll happens
        // after the first advance and one tick is lost to the late anchor.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        // Three parked intervals pass (virtual time). Advance one interval at a time and
        // yield in between: a single big advance would leave all three ticks AND the later
        // EX write racing in one select round, which no real clock ever produces -- the
        // pump must get to write each tick's NUL while it is the only ready branch.
        for _ in 0..3 {
            tokio::time::advance(PARK_KEEPALIVE_INTERVAL).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        let expired = pairer.lock().unwrap().drain_expired(531);
        assert_eq!(expired.len(), 1, "the park expired at its deadline");
        for m in expired {
            m.payload.notify_park_expired().await;
        }

        let bytes = client.await.expect("client task");
        let (nuls, tail): (Vec<u8>, Vec<u8>) = {
            let split = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
            (bytes[..split].to_vec(), bytes[split..].to_vec())
        };
        assert!(
            nuls.len() >= 3,
            "at least the three parked intervals' keepalives arrived, got {} NULs",
            nuls.len()
        );
        assert_eq!(tail, PARK_EXPIRED_TOKEN, "after stripping NULs the tail is exactly EX");
    }

    /// #508: the mismatched-provisioning diagnostic — an expired lone park whose
    /// SAME-peer sibling waits on a DIFFERENT channel is detected; different peers
    /// or unknown IPs stay silent (no false alarm on normal multi-tenant traffic).
    #[test]
    fn sibling_channel_mismatch_detects_same_peer_on_different_channels_508() {
        use std::net::IpAddr;
        let ip_a: IpAddr = "203.0.113.50".parse().unwrap();
        let ip_other: IpAddr = "203.0.113.99".parse().unwrap();
        let m = |chan: u8, holder: u8, observed: Option<IpAddr>| WaitingMember {
            channel: ChannelId([chan; 32]),
            holder: [holder; 32],
            observed,
            deadline: 100,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: (),
        };
        let mut pairer: ChannelPairer<()> = ChannelPairer::new();
        // Still waiting: same peer on channel B, a different peer on channel C.
        assert!(matches!(pairer.offer(m(0xB, 1, Some(ip_a))), PairOutcome::Parked));
        assert!(matches!(pairer.offer(m(0xC, 2, Some(ip_other))), PairOutcome::Parked));

        // Expired: same peer, channel A -> exactly one (expired A, waiting B, ip_a) hit.
        let hits = pairer.sibling_channel_mismatches(&[m(0xA, 3, Some(ip_a))]);
        assert_eq!(hits, vec![(ChannelId([0xA; 32]), ChannelId([0xB; 32]), ip_a)]);

        // A different peer expiring, or an unknown IP: silent.
        assert!(pairer.sibling_channel_mismatches(&[m(0xA, 4, Some("198.51.100.7".parse().unwrap()))]).is_empty());
        assert!(pairer.sibling_channel_mismatches(&[m(0xA, 5, None)]).is_empty());

        // Same peer expiring on the SAME channel it waits on: not a mismatch.
        assert!(pairer.sibling_channel_mismatches(&[m(0xB, 6, Some(ip_a))]).is_empty());
    }

    /// #495 slice 2b: two RENDEZVOUS-marked members (0x01 preamble) complete with
    /// ack-then-CLOSE — and that heals even the pre-v0.4.16 EOF-waiting ack reader
    /// (simulated here with `take(512).read_to_end`, the exact #494 deadlock shape):
    /// both clients get their ack promptly because the stream genuinely ends.
    #[tokio::test]
    async fn rendezvous_marked_pair_acks_then_closes_healing_eof_readers_495_2b() {
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x5Au8; 32];
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.11:1111".parse().unwrap();

        let member = |holder_byte: u8, direction: Direction| {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder_sk(holder_byte), direction, 1_000),
                endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            };
            let sk = holder_sk(holder_byte);
            let (c, s) = tokio::io::duplex(4096);
            let client = tokio::spawn(async move {
                let mut c = c;
                c.write_all(&[PHASE_PREAMBLE_MAGIC, 0x01]).await.expect("preamble");
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                c.read_exact(&mut ch).await.expect("challenge");
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                // The pre-v0.4.16 ack reader: completes ONLY at EOF (or 512 bytes) --
                // under the relay splice this deadlocked (#494); under 2b's
                // ack-then-close it must complete promptly.
                let mut ack = Vec::new();
                use tokio::io::AsyncReadExt as _;
                (&mut c).take(512).read_to_end(&mut ack).await.expect("read to close");
                let first = ack.iter().position(|b| *b != 0).unwrap_or(ack.len());
                assert!(
                    ack[first..].starts_with(b"OK"),
                    "rendezvous ack delivered before the close: {:?}",
                    String::from_utf8_lossy(&ack[first..])
                );
            });
            (client, s)
        };

        let (client_a, s_a) = member(0x5a, Direction::Accept);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_a), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit A");
        assert!(r.is_none(), "A parks rendezvous-marked");
        let (client_b, s_b) = member(0x5b, Direction::Initiate);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_b), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit B");
        let ((a, pa), (b, pb)) = r.expect("B pairs with parked A");
        assert_eq!((pa, pb), (ParkPhase::Rendezvous, ParkPhase::Rendezvous));
        // #517 V1 (Nachtrag): this is the completer the `:443` front door uses, i.e. the
        // one carrying real channel traffic in this deployment -- counting only the QUIC
        // family would have measured a near-empty path. Delta, not absolute: the counter is
        // process-wide and the suite runs concurrently.
        let pairs_before = channel_rendezvous_pairs_total();
        tokio::spawn(async move {
            let _ = finish_rendezvous_pair_over_streams(a, b, 500).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            client_a.await.expect("a");
            client_b.await.expect("b");
        })
        .await
        .expect("ack-then-close must complete EOF-waiting readers promptly (#495 2b)");
        assert!(
            channel_rendezvous_pairs_total() > pairs_before,
            "a front-door rendezvous pairing must be counted too -- otherwise the offload \
             figure ignores the pairer that actually carries the traffic (#517 V1)"
        );
    }

    /// #495-U1: a pair with an EndpointSwap side (a QUIC-rendezvous member, whose
    /// admission stream carries no session) completes ack-then-close even where the
    /// PHASES alone would splice — driven here through the RELAY completer exactly
    /// as serve.rs would for an Unmarked pairing. Both sides must receive the rich
    /// ack (incl. `r=`/`sp=`) and then EOF; a splice would instead hand the
    /// same-stream member the EndpointSwap side's EOF as an instant early-eof (the
    /// resurrected 2a mixed-phase class).
    #[tokio::test]
    async fn an_endpoint_swap_member_forces_ack_then_close_over_splice_495_u1() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let pk = operator_pubkey();
        let channel = [0x71u8; 32];
        let swap_sk = holder_sk(0x11);
        let same_sk = holder_sk(0x12);
        let (mut swap_client, swap_edge) = tokio::io::duplex(4096);
        let (mut same_client, same_edge) = tokio::io::duplex(4096);
        let a = AdmittedStreamMember {
            stream: swap_edge,
            req: ChannelJoinRequest {
                grant: grant_h(channel, &swap_sk, Direction::Accept, 1_000),
                endpoint: "203.0.113.4:4004".to_string(),
            },
            operator: pk,
            noise: None,
            attest: None,
            observed: "203.0.113.4:4004".parse().unwrap(),
            session: SessionSource::EndpointSwap,
            _permit: None,
        };
        let b = AdmittedStreamMember {
            stream: same_edge,
            req: ChannelJoinRequest {
                grant: grant_h(channel, &same_sk, Direction::Initiate, 1_000),
                endpoint: "203.0.113.5:5005".to_string(),
            },
            operator: pk,
            noise: None,
            attest: None,
            observed: "203.0.113.5:5005".parse().unwrap(),
            session: SessionSource::SameStream,
            _permit: None,
        };
        let done = tokio::spawn(finish_relay_pair_over_streams(a, b, 500));

        for (c, who) in [(&mut swap_client, "endpoint-swap"), (&mut same_client, "same-stream")] {
            let mut buf = Vec::new();
            tokio::time::timeout(std::time::Duration::from_secs(5), c.read_to_end(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("{who}: ack-then-CLOSE must EOF the stream"))
                .expect("read");
            let text = String::from_utf8_lossy(&buf);
            assert!(text.starts_with("OK "), "{who}: rich ack first, got {text:?}");
            assert!(
                text.contains(" r=") && text.contains(" sp="),
                "{who}: the unified ack carries r=/sp= (#121/#276), got {text:?}"
            );
            let _ = c.shutdown().await; // let the edge-side graceful drain finish promptly
        }
        done.await.expect("completer task").expect("pairing completes");
    }

    /// #508 persistence tuning (field-falsified 2026-08-14 evening: the per-sighting
    /// log fired every minute through a legitimate multi-channel host's 12-minute
    /// post-redeploy settle): a sibling triple is only confirmed after 15+ minutes
    /// AND 10+ sightings; a gap over 10 minutes resets the record.
    #[test]
    fn sibling_sightings_confirm_only_persistent_triples_508() {
        let mut pairer: ChannelPairer<()> = ChannelPairer::new();
        let ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();
        let triple = (ChannelId([0xA; 32]), ChannelId([0xB; 32]), ip);

        // A post-redeploy settle: sightings every 60s for 12 minutes -- never confirmed.
        for min in 0..12 {
            assert!(
                pairer.note_sibling_sightings(vec![triple], 1_000 + min * 60).is_empty(),
                "minute {min}: not yet persistent"
            );
        }
        // The condition clears for >10 minutes: the record is pruned, a fresh start.
        assert!(pairer.note_sibling_sightings(vec![triple], 1_000 + 12 * 60 + 601).is_empty());
        // The flappy class: recurring every 60s -- confirmed once BOTH thresholds hold
        // (>=10 sightings and >=900s since the post-prune first sighting).
        let base = 1_000 + 12 * 60 + 601;
        let mut confirmed_at = None;
        for min in 1..=20 {
            if !pairer.note_sibling_sightings(vec![triple], base + min * 60).is_empty() {
                confirmed_at = Some(min);
                break;
            }
        }
        assert_eq!(confirmed_at, Some(15), "confirmed at the 15-minute persistence bound");
    }

    /// #511: THE phase→completion rule, pinned as a matrix — ack-then-close ONLY for
    /// a both-rendezvous pair; every other combination (mixed, relay, legacy
    /// unmarked) splices. `Unmarked` never reaching `RendezvousClose` is what makes
    /// the WS path's direct relay-completer call an instance of this rule.
    #[test]
    fn completion_for_closes_only_a_both_rendezvous_pair_511() {
        use ParkPhase::*;
        assert_eq!(completion_for(Rendezvous, Rendezvous), StreamPairCompletion::RendezvousClose);
        for (a, b) in [
            (Rendezvous, Relay),
            (Rendezvous, Unmarked),
            (Relay, Relay),
            (Relay, Unmarked),
            (Unmarked, Unmarked),
            (Unmarked, Rendezvous),
            (Relay, Rendezvous),
        ] {
            assert_eq!(completion_for(a, b), StreamPairCompletion::Splice, "{a:?}+{b:?} must splice");
        }
    }

    /// #509: the #495-2a preamble peek is an admission read and must sit under the
    /// same `join_timeout` bound as the admission proper -- the `:443` listener
    /// passes no listener-level handshake timeout and relies on every arm bounding
    /// its own read phase. A KA peer that completes TLS and then goes silent must
    /// be dropped within `join_timeout`, not held (with its permits) forever.
    #[tokio::test]
    async fn silent_ka_peer_is_dropped_within_the_join_timeout_509() {
        use std::sync::Mutex;
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize = |_c: ChannelId, _h: [u8; 32]| async move { None };
        let obs: std::net::SocketAddr = "203.0.113.31:3131".parse().unwrap();
        // `_c` held open and never written to: TLS done, then silence.
        let (_c, s) = tokio::io::duplex(4096);
        let join_timeout = std::time::Duration::from_millis(200);
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            admit_and_pair_on_boxed_stream(Box::pin(s), obs, 500, join_timeout, &authorize, 10_000, &pairer, None, true),
        )
        .await
        .expect("the peek must not hang past join_timeout (#509)");
        let e = match r {
            Err(e) => e,
            Ok(_) => panic!("a silent peer is an admission error, not a park"),
        };
        assert!(
            !is_definitive_join_refusal(&e),
            "a stall is transient (a retry may succeed), not a definitive refusal: {e}"
        );
    }

    /// #509 (typed-errors half): a wrong byte AFTER the preamble magic is a defect
    /// in the client's marker writer -- no retry can succeed -- so it must be a
    /// [`DefinitiveJoinRefusal`] for the per-IP penalty to catch a client looping
    /// on it, and it must fail promptly (it is part of the guarded admission read).
    #[tokio::test]
    async fn unknown_phase_marker_is_a_definitive_refusal_509() {
        use std::sync::Mutex;
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize = |_c: ChannelId, _h: [u8; 32]| async move { None };
        let obs: std::net::SocketAddr = "203.0.113.32:3232".parse().unwrap();
        let (c, s) = tokio::io::duplex(4096);
        let mut c = c;
        c.write_all(&[PHASE_PREAMBLE_MAGIC, 0x7F]).await.expect("bad marker");
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            admit_and_pair_on_boxed_stream(Box::pin(s), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true),
        )
        .await
        .expect("an unknown marker must fail promptly, not hang");
        let e = match r {
            Err(e) => e,
            Ok(_) => panic!("an unknown marker is refused"),
        };
        assert!(
            is_definitive_join_refusal(&e),
            "unknown phase marker must be typed as a definitive refusal (#509): {e}"
        );
    }

    /// #494 field repro (2026-08-14): two v0.4.13-shaped KA members (keepalive
    /// negotiated, NO phase preamble) of one channel, driven through the exact
    /// field path -- preamble peek + PrependBytes + park-keepalive pump + offer +
    /// `finish_relay_pair_over_streams` -- must BOTH receive their acks and splice
    /// within seconds. In the field both clients hung ~45s with the park consumed
    /// and no ack ever arriving; this pins the completion end-to-end.
    #[tokio::test]
    async fn two_ka_members_without_preamble_pair_ack_and_splice_promptly_494() {
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x4Fu8; 32];
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.9:9099".parse().unwrap();

        let member = |holder_byte: u8, direction: Direction, payload: u8| {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder_sk(holder_byte), direction, 1_000),
                endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            };
            let sk = holder_sk(holder_byte);
            let (c, s) = tokio::io::duplex(4096);
            let client = tokio::spawn(async move {
                let mut c = c;
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                c.read_exact(&mut ch).await.expect("challenge");
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                // Ack line ("OK ...\n"), tolerating leading keepalive NULs (#500).
                let mut line = Vec::new();
                loop {
                    let mut b = [0u8; 1];
                    c.read_exact(&mut b).await.expect("ack byte");
                    if b[0] == 0 && line.is_empty() {
                        continue;
                    }
                    if b[0] == b'\n' {
                        break;
                    }
                    line.push(b[0]);
                }
                assert!(line.starts_with(b"OK"), "ack: {:?}", String::from_utf8_lossy(&line));
                // Spliced session: exchange one byte with the peer.
                c.write_all(&[payload]).await.expect("send");
                let mut got = [0u8; 1];
                c.read_exact(&mut got).await.expect("recv");
                got[0]
            });
            (client, s)
        };

        let (client_a, s_a) = member(0x4a, Direction::Accept, 0xAA);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_a), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit A");
        assert!(r.is_none(), "A parks");
        let (client_b, s_b) = member(0x4b, Direction::Initiate, 0xBB);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_b), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit B");
        let ((a, _), (b, _)) = r.expect("B pairs with parked A");
        tokio::spawn(async move {
            let _ = finish_relay_pair_over_streams(a, b, 500).await;
        });

        // The field hang was ~45s of silence; 5s is generous for an in-memory pair.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            (client_a.await.expect("a"), client_b.await.expect("b"))
        })
        .await
        .expect("both members must be acked and spliced promptly -- a hang here is the #494 field defect");
        assert_eq!(joined, (0xBB, 0xAA), "bytes crossed the spliced session");
    }

    #[tokio::test]
    async fn ka_clients_phase_preamble_stamps_the_park_and_gates_pairing_495a_marker() {
        // v0.4.14 edge half: a KA-negotiated member may prefix [0xFF, phase] before its
        // join. Prove through the REAL boxed admission path: (1) a Relay-marked park does
        // NOT pair with a Rendezvous-marked arrival (both queue); (2) a Relay-marked
        // arrival pairs with the Relay park; (3) a KA member WITHOUT preamble parks
        // Unmarked (pairs with anything -- v0.4.13 compatibility, PrependBytes puts the
        // peeked length bytes back); (4) an unknown phase byte is rejected.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x7Eu8; 32];
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.3:3099".parse().unwrap();

        let admit = |holder_byte: u8, direction: Direction, preamble: Option<[u8; 2]>| {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder_sk(holder_byte), direction, 1_000),
                endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            };
            let sk = holder_sk(holder_byte);
            let (c, s) = tokio::io::duplex(4096);
            let client = tokio::spawn(async move {
                let mut c = c;
                if let Some(p) = preamble {
                    c.write_all(&p).await.expect("preamble");
                }
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                if c.read_exact(&mut ch).await.is_err() {
                    return c; // rejected before the challenge (invalid-marker case)
                }
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                c
            });
            (client, s)
        };

        // (1) A parks Relay-marked; B arrives Rendezvous-marked -> both queue.
        let (_ca, s_a) = admit(0xe1, Direction::Accept, Some([PHASE_PREAMBLE_MAGIC, 0x02]));
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_a), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit A (relay-marked)");
        assert!(r.is_none(), "A parks");
        let (_cb, s_b) = admit(0xe2, Direction::Initiate, Some([PHASE_PREAMBLE_MAGIC, 0x01]));
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_b), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit B (rendezvous-marked)");
        assert!(r.is_none(), "phase mismatch: B queues instead of pairing with A");
        assert_eq!(pairer.lock().unwrap().len(), 2);

        // (2) A second Relay-marked arrival (different holder) pairs with A's Relay park.
        let (_cc, s_c) = admit(0xe2, Direction::Initiate, Some([PHASE_PREAMBLE_MAGIC, 0x02]));
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_c), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit C (relay-marked)");
        assert!(r.is_some(), "relay pairs with relay");

        // (3) No preamble on a KA connection -> Unmarked -> pairs with B's marked park.
        let (_cd, s_d) = admit(0xe1, Direction::Accept, None);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_d), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit D (v0.4.13-style, no preamble)");
        assert!(r.is_some(), "Unmarked pairs with the remaining marked park");
        assert!(pairer.lock().unwrap().is_empty());

        // (4) Unknown phase byte -> admission error, nothing parked.
        let (_ce, s_e) = admit(0xe3, Direction::Accept, Some([PHASE_PREAMBLE_MAGIC, 0x7F]));
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_e), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true).await;
        assert!(r.is_err(), "unknown phase marker is rejected");
        assert!(pairer.lock().unwrap().is_empty());
    }

    #[test]
    fn pairing_is_phase_compatible_and_the_cap_is_per_holder_495a() {
        // #495 slice 2a: (1) same-phase pairs; (2) mismatched phases coexist in ONE
        // channel queue across holders (the old one-holder invariant is now per-holder
        // accounting); (3) Unmarked (legacy :443) pairs with anything; (4) the supersede
        // cap counts only the member's OWN parks.
        let m = |holder: u8, phase: ParkPhase, tag: &'static str| WaitingMember {
            channel: ChannelId([0x2Au8; 32]),
            holder: [holder; 32],
            observed: None,
            deadline: 1_000,
            liveness: ParkLiveness::default(),
            phase,
            payload: tag,
        };
        let mut p = ChannelPairer::new();

        // A parks Rendezvous; B arrives with Relay -> INCOMPATIBLE -> B parks alongside.
        assert_eq!(p.offer(m(1, ParkPhase::Rendezvous, "a-rdv")), PairOutcome::Parked);
        assert_eq!(p.offer(m(2, ParkPhase::Relay, "b-relay")), PairOutcome::Parked);
        assert_eq!(p.len(), 2, "both holders' parks coexist, phase-separated");

        // B's Rendezvous join pairs with A's Rendezvous park (skipping B's own Relay park
        // and A's... none) -- FIFO within the compatible set.
        match p.offer(m(2, ParkPhase::Rendezvous, "b-rdv")) {
            PairOutcome::Paired(x, y) => {
                assert_eq!(x.payload, "a-rdv");
                assert_eq!(y.payload, "b-rdv");
            }
            other => panic!("rendezvous must pair with rendezvous, got {other:?}"),
        }
        // A's Relay join pairs with B's waiting Relay park.
        match p.offer(m(1, ParkPhase::Relay, "a-relay")) {
            PairOutcome::Paired(x, y) => {
                assert_eq!(x.payload, "b-relay");
                assert_eq!(y.payload, "a-relay");
            }
            other => panic!("relay must pair with relay, got {other:?}"),
        }
        assert!(p.is_empty());

        // Unmarked pairs with a marked phase (legacy compatibility).
        assert_eq!(p.offer(m(1, ParkPhase::Relay, "a-relay2")), PairOutcome::Parked);
        assert!(matches!(p.offer(m(2, ParkPhase::Unmarked, "b-legacy")), PairOutcome::Paired(..)));

        // Per-holder cap: A queues PARKS_PER_MEMBER Rendezvous parks; B's incompatible
        // Relay park sits in the same queue; A's (cap+1)th supersedes A's OWN oldest --
        // B's park is untouched.
        for i in 0..PARKS_PER_MEMBER {
            assert_eq!(p.offer(m(1, ParkPhase::Rendezvous, "a-park")), PairOutcome::Parked, "park {i}");
        }
        assert_eq!(p.offer(m(2, ParkPhase::Relay, "b-waiting")), PairOutcome::Parked);
        match p.offer(m(1, ParkPhase::Rendezvous, "a-overflow")) {
            PairOutcome::Superseded(stale) => assert_eq!(stale.holder, [1u8; 32], "A's own oldest, never B's"),
            other => panic!("beyond the per-holder cap the own oldest is superseded, got {other:?}"),
        }
        assert_eq!(
            p.len(),
            PARKS_PER_MEMBER + 1,
            "A back at cap, B's incompatible park still queued"
        );
    }

    #[test]
    fn pairer_never_hands_out_a_corpse_and_counts_the_drop_499b() {
        // #499 slice B, pairer level: a queued park flagged dead must be skipped by FIFO
        // pairing (the arriving partner gets the oldest LIVE park), purged by the sweep
        // without being returned as expired (no EX for corpses), and counted.
        let m = |holder: u8, liveness: ParkLiveness, tag: &'static str| WaitingMember {
            channel: ChannelId([0x4Bu8; 32]),
            holder: [holder; 32],
            observed: None,
            deadline: 1_000,
            liveness,
            phase: ParkPhase::Unmarked,
            payload: tag,
        };
        let (dead_liveness, dead_flag) = ParkLiveness::monitored();
        let mut pairer = ChannelPairer::new();
        assert_eq!(pairer.offer(m(1, dead_liveness, "corpse")), PairOutcome::Parked);
        assert_eq!(pairer.offer(m(1, ParkLiveness::default(), "live")), PairOutcome::Parked);
        dead_flag.store(true, std::sync::atomic::Ordering::Relaxed);

        // A different holder arrives: FIFO would pick "corpse" first -- slice B must skip
        // it and pair with "live".
        match pairer.offer(m(2, ParkLiveness::default(), "partner")) {
            PairOutcome::Paired(a, b) => {
                assert_eq!(a.payload, "live", "the corpse is never handed to a partner");
                assert_eq!(b.payload, "partner");
            }
            other => panic!("expected a pairing with the live park, got {other:?}"),
        }
        assert_eq!(pairer.take_dead_dropped(), 1, "the skipped corpse is counted");
        assert!(pairer.is_empty(), "corpse dropped, pair consumed -- nothing queued");

        // Sweep path: a corpse expires silently (not returned -- nobody to EX-notify).
        let (dl2, df2) = ParkLiveness::monitored();
        assert_eq!(pairer.offer(m(3, dl2, "corpse2")), PairOutcome::Parked);
        df2.store(true, std::sync::atomic::Ordering::Relaxed);
        let expired = pairer.drain_expired(2_000);
        assert!(expired.is_empty(), "a corpse is not 'expired' -- it is dropped: {expired:?}");
        assert_eq!(pairer.take_dead_dropped(), 1);
    }

    #[tokio::test]
    async fn a_dead_parked_client_is_flagged_by_the_pump_and_never_paired_499b() {
        // #499 slice B end to end (minus TLS): member A parks via the REAL boxed admission
        // path, its client dies (the tester's early-eof producer), A re-parks fresh; an
        // arriving partner B must pair with the LIVE park -- the corpse is dropped, not
        // spliced (the N x 10s first-contact staircase this slice removes).
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x5Bu8; 32];
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.4:4099".parse().unwrap();

        let admit = |holder_byte: u8, direction: Direction| {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder_sk(holder_byte), direction, 1_000),
                endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            };
            let sk = holder_sk(holder_byte);
            let (c, s) = tokio::io::duplex(4096);
            let client = tokio::spawn(async move {
                let mut c = c;
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                c.read_exact(&mut ch).await.expect("challenge");
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                c // keep the connection alive; the caller decides its fate
            });
            (client, s)
        };

        // A parks AS A KEEPALIVE-NEGOTIATED MEMBER (the contract that makes a clean EOF an
        // unambiguous death signal -- see the pump's half-close discriminator); its client
        // then DIES.
        let (client_a, s_a) = admit(0xa1, Direction::Accept);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_a), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, true)
            .await
            .expect("admit A");
        assert!(r.is_none(), "A parks");
        let conn_a = client_a.await.expect("client A");
        drop(conn_a); // the client-side death the pump must notice
        // Give the pump a few polls to observe the EOF and flag the corpse.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // A re-parks fresh (the tester's serve loop does exactly this).
        let (client_a2, s_a2) = admit(0xa1, Direction::Accept);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_a2), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, false)
            .await
            .expect("admit A2");
        assert!(r.is_none(), "A's fresh park queues");

        // B arrives: must pair with the FRESH park, never the corpse.
        let (client_b, s_b) = admit(0xb2, Direction::Initiate);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_b), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, false)
            .await
            .expect("admit B");
        let ((a, _), (b, _)) = r.expect("B pairs with the live park");
        assert_eq!(pairer.lock().unwrap().take_dead_dropped(), 1, "the corpse was dropped, counted");
        // Prove the paired A-side leg is the LIVE second connection: splice and pass a byte.
        let mut live_a = client_a2.await.expect("client A2");
        let mut live_b = client_b.await.expect("client B");
        tokio::spawn(async move {
            let _ = finish_relay_pair_over_streams(a, b, 500).await;
        });
        let ack = read_relay_ack_line(&mut live_a).await;
        assert!(ack.starts_with(b"OK"), "live A2 got the relay ack: {:?}", String::from_utf8_lossy(&ack));
        let ack = read_relay_ack_line(&mut live_b).await;
        assert!(ack.starts_with(b"OK"), "B got the relay ack");
        live_a.write_all(&[0x77]).await.expect("A2 sends");
        live_a.flush().await.expect("flush");
        let mut got = [0u8; 1];
        live_b.read_exact(&mut got).await.expect("B receives through the splice");
        assert_eq!(got[0], 0x77, "the spliced pair is the LIVE leg, not the corpse");
    }

    #[tokio::test]
    async fn a_legacy_half_close_is_not_a_corpse_and_the_park_stays_pairable_499b_fix() {
        // Live regression fix (2026-08-14): v0.4.11-and-older clients half-close right after
        // the possession signature. That clean EOF must NOT flag the park dead (only a
        // KA-negotiated member's EOF or a hard error may) -- the first slice B cut flagged
        // every legacy park as a corpse within ~100ms, breaking pairing for every deployed
        // old client. Prove: a non-KA member half-closes, stays pairable, and still RECEIVES
        // the relay ack through the pump's outbound direction.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x6Cu8; 32];
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<BoxedChannelStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.6:6099".parse().unwrap();

        let admit = |holder_byte: u8, direction: Direction| {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder_sk(holder_byte), direction, 1_000),
                endpoint: ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            };
            let sk = holder_sk(holder_byte);
            let (c, s) = tokio::io::duplex(4096);
            let client = tokio::spawn(async move {
                let mut c = c;
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                c.read_exact(&mut ch).await.expect("challenge");
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                // The v0.4.11 behavior under test: half-close the write direction, keep reading.
                c.shutdown().await.expect("legacy half-close");
                c
            });
            (client, s)
        };

        // A parks as a NON-KA member and half-closes (the legacy pattern).
        let (client_a, s_a) = admit(0xa7, Direction::Accept);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_a), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, false)
            .await
            .expect("admit A");
        assert!(r.is_none(), "A parks");
        let mut half_closed_a = client_a.await.expect("client A");
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // B arrives: A's half-closed park must STILL pair (no corpse flag), and A must
        // still receive the relay ack through the pump.
        let (client_b, s_b) = admit(0xb8, Direction::Initiate);
        let r = admit_and_pair_on_boxed_stream(Box::pin(s_b), obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None, false)
            .await
            .expect("admit B");
        let ((a, _), (b, _)) = r.expect("the half-closed legacy park pairs");
        assert_eq!(pairer.lock().unwrap().take_dead_dropped(), 0, "no false corpse drop");
        tokio::spawn(async move {
            let _ = finish_relay_pair_over_streams(a, b, 500).await;
        });
        let ack = read_relay_ack_line(&mut half_closed_a).await;
        assert!(
            ack.starts_with(b"OK"),
            "the half-closed legacy client still receives its ack: {:?}",
            String::from_utf8_lossy(&ack)
        );
        let mut live_b = client_b.await.expect("client B");
        let ack = read_relay_ack_line(&mut live_b).await;
        assert!(ack.starts_with(b"OK"), "B acked too");
    }

    #[tokio::test]
    async fn a_superseded_park_gets_the_ex_token_not_a_silent_close_499() {
        // #499 slice A: when the same holder's (PARKS_PER_MEMBER+1)th park supersedes its
        // oldest, the stale leg's teardown must carry the same EX token a TTL reap sends --
        // a LIVE client there would otherwise see the pre-ct-agent#21 ambiguous EOF and
        // misread its lost park as a refusal. Drive the REAL admit_and_pair_on_stream path
        // for every offer; assert the FIRST (oldest) client reads exactly EX + EOF while
        // the queue still holds the newest PARKS_PER_MEMBER parks.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x99u8; 32];
        let holder = holder_sk(0xc3);
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<tokio::io::DuplexStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.9:9009".parse().unwrap();

        let mut clients = Vec::new();
        for i in 0..=PARKS_PER_MEMBER {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder, Direction::Accept, 1_000),
                endpoint: format!("203.0.113.9:9{i:03}"),
            };
            let sk = holder_sk(0xc3);
            let (c, s) = tokio::io::duplex(4096);
            clients.push(tokio::spawn(async move {
                let mut c = c;
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                c.read_exact(&mut ch).await.expect("challenge");
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                // Parked: read whatever teardown (or nothing) arrives.
                let mut buf = Vec::new();
                let _ = c.read_to_end(&mut buf).await;
                buf
            }));
            let r = admit_and_pair_on_stream(s, obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
                .await
                .expect("admit");
            assert!(r.is_none(), "same-holder offers park (or supersede-park), never pair");
        }

        // The oldest park was superseded by the (cap+1)th offer -- its client must read the
        // EX token, not a bare EOF.
        let oldest = clients.remove(0).await.expect("oldest client");
        assert_eq!(oldest, PARK_EXPIRED_TOKEN, "the superseded leg carries EX (#499 slice A)");
        assert_eq!(
            pairer.lock().unwrap().len(),
            PARKS_PER_MEMBER,
            "the newest {PARKS_PER_MEMBER} parks remain queued"
        );
        for c in clients {
            c.abort(); // still parked -- nothing to read; the test only asserts the superseded one
        }
    }

    /// A supersede must be countable, and countable as ITSELF -- not as a reap.
    ///
    /// The two are identical on the wire on purpose (the test above pins that: a superseded
    /// leg gets the same `EX` a TTL reap sends, so a live client re-parks instead of reading
    /// a refusal). Toward the operator that sameness was an omission: a supersede
    /// incremented nothing, so a holder retry storm -- the failure #231/#250 exist for --
    /// left the reap counter flat and the park counter climbing, which reads as healthy
    /// live parks.
    ///
    /// Driven through the REAL `admit_and_pair_on_stream` path, not by calling the counter:
    /// a test that calls `note_channel_park_superseded` directly would pass even if no
    /// production site ever did.
    #[tokio::test]
    async fn a_supersede_is_counted_as_a_supersede_and_not_as_a_reap() {
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x9Au8; 32];
        let holder = holder_sk(0xc4);
        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<tokio::io::DuplexStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs: std::net::SocketAddr = "203.0.113.10:9010".parse().unwrap();

        let before = channel_park_superseded_total();
        let mut clients = Vec::new();
        for i in 0..=PARKS_PER_MEMBER {
            let req = ChannelJoinRequest {
                grant: grant_h(channel, &holder, Direction::Accept, 1_000),
                endpoint: format!("203.0.113.10:9{i:03}"),
            };
            let sk = holder_sk(0xc4);
            let (c, s) = tokio::io::duplex(4096);
            clients.push(tokio::spawn(async move {
                let mut c = c;
                let rb = req.encode();
                c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
                c.write_all(&rb).await.expect("req");
                let mut ch = [0u8; 32];
                c.read_exact(&mut ch).await.expect("challenge");
                c.write_all(&sk.sign(&ch).to_bytes()).await.expect("sig");
                let mut buf = Vec::new();
                let _ = c.read_to_end(&mut buf).await;
            }));
            admit_and_pair_on_stream(s, obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
                .await
                .expect("admit");
        }

        // `>=`, not `==`: this counter is process-wide and the #499 test above drives the
        // same path concurrently. The claim that matters is that the path increments it AT
        // ALL, which it did not before.
        assert!(
            channel_park_superseded_total() >= before + 1,
            "the (cap+1)th same-holder offer must be counted as a supersede: {} did not exceed {before}",
            channel_park_superseded_total()
        );
        // Deliberately NOT asserted: that the reap counter stayed put. It is process-wide
        // too, so "did not move" is a statement about every other test running right now,
        // not about this code path -- it would be a flake, not a check. What actually
        // separates the two here is that the `Superseded` arm calls only the supersede
        // counter; the reap counter is incremented solely by the TTL drain loops in
        // `serve.rs` and `ws_channel.rs`, which this test never runs.
        for c in clients {
            c.abort();
        }
    }

    #[test]
    fn pairer_survives_a_poisoned_mutex_497() {
        // #497 (the 2026-08-13 broker-wedge class): a panic while holding the pairer mutex used
        // to poison it permanently -- every later `.lock().unwrap()` then panicked too, killing
        // the accept loop / reapers while the process stayed "healthy". All production locks now
        // go through ct_common's poison-recovering `lock_safe`; this proves offer + drain still
        // work through a mutex that a panicking thread genuinely poisoned.
        let pairer: std::sync::Arc<std::sync::Mutex<ChannelPairer<()>>> =
            std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new()));

        // Genuinely poison it: panic in another thread while holding the lock.
        let poisoner = pairer.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("deliberate poison (#497 test)");
        })
        .join();
        assert!(pairer.lock().is_err(), "the mutex is really poisoned -- the precondition holds");

        // The production paths' idiom still works: offer parks, the sweep drains.
        let outcome = pairer.lock_safe().offer(WaitingMember {
            channel: ChannelId([0x97u8; 32]),
            holder: [0x11u8; 32],
            observed: None,
            deadline: 100,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: (),
        });
        assert!(matches!(outcome, PairOutcome::Parked), "offer works through the poisoned lock");
        let expired = pairer.lock_safe().drain_expired(500);
        assert_eq!(expired.len(), 1, "the TTL sweep works through the poisoned lock too");
    }

    #[tokio::test]
    async fn only_not_member_and_possession_refusals_classify_as_definitive() {
        // The per-IP penalty's typed contract (2026-08-13 storm): exactly the two
        // refusals a client can never retry into a success -- `[not-member]` and
        // `[possession]` -- are wrapped as [`DefinitiveJoinRefusal`]; every other
        // checkpoint (framing, endpoint, grant-verify, which clock skew can trip
        // transiently) must NOT be, or a flaky-but-honest client could be shed.
        use std::future::Future;
        use std::time::Duration;
        use tokio::io::{split, AsyncWriteExt, DuplexStream};

        // Same harness as `channel_join_refusal_reason_is_distinct_per_checkpoint`,
        // returning the RAW error so the classification (not the message) is asserted.
        async fn refusal_err<F, Fut, C, CFut>(now: UnixSeconds, authorize: F, client: C) -> BoxError
        where
            F: Fn(ChannelId, [u8; 32]) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send,
            C: FnOnce(DuplexStream) -> CFut,
            CFut: Future<Output = ()>,
        {
            let (client_end, server_end) = tokio::io::duplex(4096);
            let (srv_r, srv_w) = split(server_end);
            let observed: std::net::SocketAddr = "203.0.113.50:40001".parse().unwrap();
            let server = tokio::spawn(async move {
                read_channel_join_on_stream(srv_w, srv_r, observed, now, Duration::from_secs(5), &authorize)
                    .await
            });
            client(client_end).await;
            server
                .await
                .expect("server task")
                .err()
                .expect("admission must be refused")
        }

        async fn present(mut c: DuplexStream, req_bytes: Vec<u8>, sig: Option<[u8; 64]>) {
            use tokio::io::AsyncReadExt;
            c.write_all(&(req_bytes.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&req_bytes).await.unwrap();
            if let Some(sig) = sig {
                let mut challenge = [0u8; 32];
                if c.read_exact(&mut challenge).await.is_ok() {
                    c.write_all(&sig).await.unwrap();
                }
            }
        }

        let channel = [0x7Bu8; 32];
        let holder = holder_sk(0x0b);
        let pk = operator_pubkey();
        let good = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6021".to_string(),
        };
        let member = move |c: ChannelId, _h: [u8; 32]| async move {
            (c.0 == channel).then_some((pk, None, None))
        };
        let non_member = move |_c: ChannelId, _h: [u8; 32]| async move { None };

        // DEFINITIVE: not-member.
        let bytes = good.encode();
        let e = refusal_err(500, non_member, move |c| present(c, bytes, None)).await;
        assert!(is_definitive_join_refusal(&e), "[not-member] must be definitive, got: {e}");

        // DEFINITIVE: possession (wrong signature over the challenge).
        let bytes = good.encode();
        let e = refusal_err(500, member, move |c| present(c, bytes, Some([0u8; 64]))).await;
        assert!(is_definitive_join_refusal(&e), "[possession] must be definitive, got: {e}");

        // NOT definitive: malformed framing.
        let e = refusal_err(500, member, |mut c: DuplexStream| async move {
            let junk = [0xFFu8; 4];
            c.write_all(&(junk.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&junk).await.unwrap();
        })
        .await;
        assert!(!is_definitive_join_refusal(&e), "[malformed] must NOT be definitive, got: {e}");

        // NOT definitive: grant-verify (expired grant -- clock-skew-sensitive).
        let bytes = good.encode();
        let e = refusal_err(2_000, member, move |c| present(c, bytes, None)).await;
        assert!(!is_definitive_join_refusal(&e), "[grant-verify] must NOT be definitive, got: {e}");

        // NOT definitive: unsafe advertised endpoint.
        let mut bad_ep = good.clone();
        bad_ep.endpoint = "10.0.0.5:22".to_string();
        let bytes = bad_ep.encode();
        let e = refusal_err(500, member, move |c| present(c, bytes, None)).await;
        assert!(!is_definitive_join_refusal(&e), "[endpoint] must NOT be definitive, got: {e}");
    }

    #[tokio::test]
    async fn channel_join_io_drop_at_read_returns_err_not_a_silent_hang() {
        // #125 (frozen): the bare I/O points (length read, body read, challenge write) must
        // return an Err PROMPTLY on an early half-close/reset — logged server-side as
        // `[io-len]`/`[io-body]`/`[io-challenge]` — not hang and not silently succeed. This
        // is the suspected cause of #103's "refused, no log" reports (a mid-handshake drop).
        use std::time::Duration;
        use tokio::io::{split, AsyncWriteExt};
        let observed: std::net::SocketAddr = "203.0.113.50:40002".parse().unwrap();
        let authorize = |_c: ChannelId, _h: [u8; 32]| async move {
            Option::<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>::None
        };

        // io-len: half-close before writing the 2-byte length prefix.
        let (client_end, server_end) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = split(server_end);
        let s1 = tokio::spawn(async move {
            read_channel_join_on_stream(srv_w, srv_r, observed, 500, Duration::from_secs(5), &authorize).await
        });
        drop(client_end);
        assert!(s1.await.unwrap().is_err(), "io-len: an early close must error, not hang/succeed");

        // io-body: send a length prefix, then half-close before the body.
        let (mut client_end, server_end) = tokio::io::duplex(4096);
        let (srv_r, srv_w) = split(server_end);
        let s2 = tokio::spawn(async move {
            read_channel_join_on_stream(srv_w, srv_r, observed, 500, Duration::from_secs(5), &authorize).await
        });
        client_end.write_all(&10u16.to_be_bytes()).await.unwrap();
        drop(client_end);
        assert!(s2.await.unwrap().is_err(), "io-body: a truncated body must error, not hang/succeed");
    }

    #[tokio::test]
    async fn admit_channel_join_over_tls_tcp_matches_the_quic_path() {
        // #106 dispatch-transport (accept leg, frozen): the `:443` front-door channel
        // admission runs over a REAL TLS-over-TCP stream, not just an in-memory duplex.
        // Stand up a genuine rustls TLS-over-TCP server+client over loopback (the
        // `transport.rs` fallback helpers the classic edge uses for its `:443` leg) and
        // drive the full admission handshake — length-framed request → possession
        // challenge → OK — through `admit_channel_join_on_duplex`. The admitted member
        // must match the QUIC path exactly (same OK ack, same advertised endpoint), so a
        // member whose network blocks the channel ports is admitted identically via `:443`.
        use crate::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};

        let pk = operator_pubkey();
        let channel = [0xF4u8; 32];
        let holder = holder_sk(0x0a);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6041".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let addr: SocketAddr = listener.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("tcp accept");
            // A real TLS handshake terminates here — `tls` is a tokio_rustls server
            // stream, the exact transport the `:443` front door yields.
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a real TLS-TCP stream");
            // #106 complete-wire443: `admit_channel_join_on_duplex` returns the REUNITED
            // full duplex, not just the write half. Prove it: ack on the write side, then
            // read a post-admission app byte off the SAME stream — the read half survived
            // admission, so this stream is ready to hand to `finish_relay_pair_over_streams`.
            stream.write_all(b"OK").await.expect("ack");
            let mut app = [0u8; 1];
            stream.read_exact(&mut app).await.expect("read app byte over the reunited stream");
            stream.shutdown().await.expect("shutdown");
            (req.endpoint, app[0])
        });

        // Client: connect over TLS-TCP and drive the same handshake `present_join` drives
        // over QUIC (framed request, then answer the edge's possession challenge).
        let mut client = tcp_tls_connect(addr, cert).await.expect("tls-tcp connect");
        let req_bytes = req.encode();
        client
            .write_all(&(req_bytes.len() as u16).to_be_bytes())
            .await
            .expect("write length");
        client.write_all(&req_bytes).await.expect("write request");
        let mut challenge = [0u8; 32];
        client.read_exact(&mut challenge).await.expect("read challenge");
        let sig = holder.sign(&challenge).to_bytes();
        client.write_all(&sig).await.expect("write possession sig");
        let mut ack = [0u8; 2];
        client.read_exact(&mut ack).await.expect("read ack");
        assert_eq!(&ack, b"OK", "TLS-TCP admission returns the same OK ack as QUIC");
        // Post-admission app byte on the same TLS-TCP stream — the server reads it off
        // the reunited duplex, proving the full stream survives admission (wire443).
        client.write_all(&[0x5a]).await.expect("write app byte after OK");

        let (endpoint, app) = server_task.await.expect("join");
        assert_eq!(
            endpoint, "203.0.113.9:6041",
            "the admitted member's advertised endpoint matches the QUIC path",
        );
        assert_eq!(
            app, 0x5a,
            "the reunited TLS-TCP stream carries post-admission app data (read half survived)",
        );
    }

    #[tokio::test]
    async fn relay_pairs_two_admitted_tls_tcp_members_end_to_end() {
        // #106 complete-wire443-e2e (frozen): the capstone `:443` relay path. Admit TWO
        // real TLS-over-TCP members (a source + a `:443`-only sink, neither dialable) via
        // `admit_channel_join_on_duplex`, then `finish_relay_pair_over_streams` them —
        // proving a full source<->sink A2A relay forms end-to-end over `:443`, edge-
        // brokered, with no quinn anywhere. The Noise_IK session would run over this
        // spliced path; here each side pushes one app byte to prove the edge splices the
        // two admitted duplexes together (and that roles come from the grants).
        use crate::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};

        let pk = operator_pubkey();
        let channel = [0x7Eu8; 32];
        let src = holder_sk(0xa1); // Initiate grant → initiator
        let snk = holder_sk(0xb2); // Accept grant → acceptor
        let src_pk = src.verifying_key().to_bytes();
        let snk_pk = snk.verifying_key().to_bytes();
        let req_src = ChannelJoinRequest {
            grant: grant_h(channel, &src, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(channel, &snk, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let addr: SocketAddr = listener.local_addr().expect("addr");

        // Edge: accept two TLS-TCP connections, admit both over the front-door transport,
        // then relay-splice the two admitted `:443` duplexes.
        let server = tokio::spawn(async move {
            let authorize =
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
            let (t1, peer1) = listener.accept().await.expect("accept 1");
            let tls1 = acceptor.accept(t1).await.expect("tls 1");
            let (s1, r1, op1, _n1, _a1, _o1) =
                admit_channel_join_on_duplex(tls1, peer1, 500, std::time::Duration::from_secs(5), &authorize)
                    .await
                    .expect("admit 1");
            let (t2, peer2) = listener.accept().await.expect("accept 2");
            let tls2 = acceptor.accept(t2).await.expect("tls 2");
            let (s2, r2, op2, _n2, _a2, _o2) =
                admit_channel_join_on_duplex(tls2, peer2, 500, std::time::Duration::from_secs(5), &authorize)
                    .await
                    .expect("admit 2");
            finish_relay_pair_over_streams(
                AdmittedStreamMember { stream: s1, req: r1, operator: op1, noise: None, attest: None, observed: "203.0.113.1:1111".parse().unwrap(), session: SessionSource::SameStream, _permit: None },
                AdmittedStreamMember { stream: s2, req: r2, operator: op2, noise: None, attest: None, observed: "203.0.113.2:2222".parse().unwrap(), session: SessionSource::SameStream, _permit: None },
                500,
            )
            .await
            .map(|p| (p.initiator_holder, p.acceptor_holder))
            .map_err(|e| e.to_string())
        });

        // Each member: connect over TLS-TCP, run the admission handshake, wait for the
        // relay's OK (written once both are paired), then push one app byte and read the
        // peer's — the bytes cross only if the edge spliced the two duplexes.
        let cert2 = cert.clone();
        let src_task = tokio::spawn(async move {
            let mut c = tcp_tls_connect(addr, cert).await.expect("connect src");
            let rb = req_src.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&src.sign(&ch).to_bytes()).await.expect("sig");
            let ack = read_relay_ack_line(&mut c).await;
            assert!(ack.starts_with(b"OK"), "relay acks OK once both :443 members are paired, got {:?}", String::from_utf8_lossy(&ack));
            c.write_all(&[0x11]).await.expect("app send");
            let mut got = [0u8; 1];
            c.read_exact(&mut got).await.expect("app recv");
            // Close gracefully (TLS close_notify) so the relay sees a clean EOF, not an
            // abrupt drop — a real client shuts down; the test must too.
            let _ = c.shutdown().await;
            got[0]
        });
        let snk_task = tokio::spawn(async move {
            let mut c = tcp_tls_connect(addr, cert2).await.expect("connect snk");
            let rb = req_snk.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&snk.sign(&ch).to_bytes()).await.expect("sig");
            let ack = read_relay_ack_line(&mut c).await;
            assert!(ack.starts_with(b"OK"), "relay acks OK once both :443 members are paired, got {:?}", String::from_utf8_lossy(&ack));
            c.write_all(&[0x22]).await.expect("app send");
            let mut got = [0u8; 1];
            c.read_exact(&mut got).await.expect("app recv");
            let _ = c.shutdown().await;
            got[0]
        });

        let got_src = src_task.await.expect("src task");
        let got_snk = snk_task.await.expect("snk task");
        let (init_h, acc_h) = server.await.expect("server task").expect("relay paired");

        assert_eq!(got_src, 0x22, "source received the sink's byte through the :443 relay");
        assert_eq!(got_snk, 0x11, "sink received the source's byte through the :443 relay");
        assert_eq!(init_h, src_pk, "the Initiate-grant holder is the initiator");
        assert_eq!(acc_h, snk_pk, "the Accept-grant holder is the acceptor");
    }

    #[tokio::test]
    async fn admit_and_pair_on_stream_parks_then_pairs_by_channel() {
        // #106 dispatch-frontdoor (handler, frozen): the front door's `:443` members arrive
        // independently, so admission must correlate by `ChannelId` via a shared
        // `ChannelPairer`. The FIRST holder of a channel parks (Ok(None)); the SECOND
        // returns Ok(Some((a, b))) — exactly the two same-channel members — which the
        // caller relay-splices. Prove it end-to-end over two in-memory duplexes: park,
        // pair, splice, bytes cross, pairer drained.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x9Au8; 32];
        let src = holder_sk(0xa1); // Initiate
        let snk = holder_sk(0xb2); // Accept
        let req_src = ChannelJoinRequest {
            grant: grant_h(channel, &src, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:8001".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(channel, &snk, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:8002".to_string(),
        };

        let (c1, s1) = tokio::io::duplex(4096);
        let (c2, s2) = tokio::io::duplex(4096);

        // Two members drive the admission handshake independently, then exchange a byte
        // once the relay's OK arrives.
        let src_task = tokio::spawn(async move {
            let mut c = c1;
            let rb = req_src.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&src.sign(&ch).to_bytes()).await.expect("sig");
            let ack = read_relay_ack_line(&mut c).await;
            assert!(ack.starts_with(b"OK"), "got {:?}", String::from_utf8_lossy(&ack));
            c.write_all(&[0x11]).await.expect("send");
            let mut g = [0u8; 1];
            c.read_exact(&mut g).await.expect("recv");
            let _ = c.shutdown().await;
            g[0]
        });
        let snk_task = tokio::spawn(async move {
            let mut c = c2;
            let rb = req_snk.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&snk.sign(&ch).to_bytes()).await.expect("sig");
            let ack = read_relay_ack_line(&mut c).await;
            assert!(ack.starts_with(b"OK"), "got {:?}", String::from_utf8_lossy(&ack));
            c.write_all(&[0x22]).await.expect("send");
            let mut g = [0u8; 1];
            c.read_exact(&mut g).await.expect("recv");
            let _ = c.shutdown().await;
            g[0]
        });

        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<tokio::io::DuplexStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };

        // In-memory duplexes have no socket peer; a dummy reflexive addr stands in (the observed
        // address isn't asserted here — the front-door wiring test covers real `peer_addr()`).
        let obs1: std::net::SocketAddr = "203.0.113.1:8001".parse().unwrap();
        let obs2: std::net::SocketAddr = "203.0.113.2:8002".parse().unwrap();

        // First holder → parked (no partner yet).
        let r1 = admit_and_pair_on_stream(s1, obs1, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
            .await
            .expect("admit 1");
        assert!(r1.is_none(), "first holder of the channel parks in the pairer");
        assert_eq!(pairer.lock().unwrap().len(), 1, "one member waiting");

        // Second holder → paired with exactly the parked first.
        let r2 = admit_and_pair_on_stream(s2, obs2, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
            .await
            .expect("admit 2");
        let (a, b) = r2.expect("second holder pairs with the parked first");
        assert!(pairer.lock().unwrap().is_empty(), "the pair was removed from the pairer");

        // The caller relay-splices exactly those two.
        finish_relay_pair_over_streams(a, b, 500).await.expect("relay spliced the paired members");

        assert_eq!(src_task.await.expect("src"), 0x22, "source got the sink's byte via the paired relay");
        assert_eq!(snk_task.await.expect("snk"), 0x11, "sink got the source's byte via the paired relay");
    }

    /// A trivial newtype around `tokio::io::DuplexStream` -- a distinct Rust TYPE (not
    /// just a different value) standing in for "a different transport's concrete
    /// stream" in the cross-transport pairing test below, so boxing genuinely erases
    /// two DIFFERENT types into [`BoxedChannelStream`], not just two instances of one.
    struct OtherTransportStream(tokio::io::DuplexStream);

    impl AsyncRead for OtherTransportStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for OtherTransportStream {
        fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn boxed_channel_stream_pairs_two_different_concrete_stream_types_cross_transport() {
        // Cross-transport pairing (video-conferencing feature follow-up): the whole
        // point of BoxedChannelStream/SharedChannelPairer is that a `:443` front-door
        // member's TLS stream and a browser's WsByteStream -- two genuinely DIFFERENT
        // concrete types -- can be admitted onto the SAME shared pairer and pair with
        // EACH OTHER. Proves the type-erasure mechanism itself with two different
        // concrete stream types (a plain DuplexStream and a distinct newtype wrapping
        // one), independent of either transport's own admission wiring (those stay
        // covered by ws_channel.rs's and serve.rs's own tests).
        let pk = operator_pubkey();
        let channel = [0x9Bu8; 32];
        let src = holder_sk(0xc1);
        let snk = holder_sk(0xd2);
        let req_src = ChannelJoinRequest {
            grant: grant_h(channel, &src, Direction::Initiate, 1_000),
            endpoint: "relay-only".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(channel, &snk, Direction::Accept, 1_000),
            endpoint: "relay-only".to_string(),
        };

        let (c1, s1) = tokio::io::duplex(4096);
        let (c2, s2) = tokio::io::duplex(4096);
        let s2 = OtherTransportStream(s2); // a genuinely different concrete type than s1

        let src_task = tokio::spawn(async move {
            let mut c = c1;
            let rb = req_src.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&src.sign(&ch).to_bytes()).await.expect("sig");
            let ack = read_relay_ack_line(&mut c).await;
            assert!(ack.starts_with(b"OK"), "got {:?}", String::from_utf8_lossy(&ack));
            c.write_all(&[0x33]).await.expect("send");
            let mut g = [0u8; 1];
            c.read_exact(&mut g).await.expect("recv");
            let _ = c.shutdown().await;
            g[0]
        });
        let snk_task = tokio::spawn(async move {
            let mut c = c2;
            let rb = req_snk.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&snk.sign(&ch).to_bytes()).await.expect("sig");
            let ack = read_relay_ack_line(&mut c).await;
            assert!(ack.starts_with(b"OK"), "got {:?}", String::from_utf8_lossy(&ack));
            c.write_all(&[0x44]).await.expect("send");
            let mut g = [0u8; 1];
            c.read_exact(&mut g).await.expect("recv");
            let _ = c.shutdown().await;
            g[0]
        });

        let pairer: SharedChannelPairer = new_shared_channel_pairer();
        let authorize = move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs1: std::net::SocketAddr = "203.0.113.1:8001".parse().unwrap();
        let obs2: std::net::SocketAddr = "203.0.113.2:8002".parse().unwrap();

        let boxed1: BoxedChannelStream = Box::pin(s1);
        let r1 = admit_and_pair_on_stream(boxed1, obs1, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
            .await
            .expect("admit 1 (transport A: a plain DuplexStream)");
        assert!(r1.is_none(), "first holder parks");
        assert_eq!(pairer.lock().unwrap().len(), 1);

        let boxed2: BoxedChannelStream = Box::pin(s2);
        let r2 = admit_and_pair_on_stream(boxed2, obs2, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
            .await
            .expect("admit 2 (transport B: a DIFFERENT concrete stream type)");
        let (a, b) = r2.expect("second holder pairs with the parked first, across the type boundary");
        assert!(pairer.lock().unwrap().is_empty());

        finish_relay_pair_over_streams(a, b, 500).await.expect("relay spliced two different stream types");

        assert_eq!(src_task.await.expect("src"), 0x44, "the transport-A member got transport-B's byte");
        assert_eq!(snk_task.await.expect("snk"), 0x33, "the transport-B member got transport-A's byte");
    }

    /// One member's full admission handshake over an in-memory duplex, ending with
    /// one application byte exchanged post-pairing -- the shared body every member
    /// task in the room test below runs, parameterized by its own stream/request/
    /// key/send-byte so that test stays readable as "which participant, which pair,
    /// which byte" instead of repeating the handshake six times inline.
    async fn room_member_roundtrip(
        mut stream: tokio::io::DuplexStream,
        req: ChannelJoinRequest,
        holder_sk: SigningKey,
        send_byte: u8,
    ) -> u8 {
        let rb = req.encode();
        stream.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
        stream.write_all(&rb).await.expect("req");
        let mut ch = [0u8; 32];
        stream.read_exact(&mut ch).await.expect("challenge");
        stream.write_all(&holder_sk.sign(&ch).to_bytes()).await.expect("sig");
        let ack = read_relay_ack_line(&mut stream).await;
        assert!(ack.starts_with(b"OK"), "got {:?}", String::from_utf8_lossy(&ack));
        stream.write_all(&[send_byte]).await.expect("send");
        let mut g = [0u8; 1];
        stream.read_exact(&mut g).await.expect("recv");
        let _ = stream.shutdown().await;
        g[0]
    }

    #[tokio::test]
    async fn a_three_person_room_pairs_its_three_pairwise_channels_concurrently_without_cross_talk() {
        // ADR-0023 (video-conferencing multicast/room fan-out): a room is full mesh --
        // C(N,2) independent PAIRWISE channels through ONE shared pairer, never a
        // server-side fan-out. For 3 participants (Alice, Bob, Carol) that's 3
        // pairwise channels (A-B, B-C, A-C). This proves the concrete claim ADR-0023
        // rests on: all 3 channels' admissions INTERLEAVED (not grouped by channel --
        // A-B's first member, then B-C's first, then A-C's first, THEN each channel's
        // second member, closing them in a different order again) still correlate
        // and pair EXACTLY the right two holders per channel, with each pair's relay
        // traffic staying isolated from the other two pairs -- through the exact
        // SharedChannelPairer type both ws_channel.rs (browser) and the `:443` front
        // door (native) already use in production, so this is a direct proof a real
        // room, mixing transports, would behave correctly.
        let pk = operator_pubkey();
        let chan_ab = [0xABu8; 32];
        let chan_bc = [0xBCu8; 32];
        let chan_ac = [0xACu8; 32];
        let alice = holder_sk(0xA1);
        let bob = holder_sk(0xB2);
        let carol = holder_sk(0xC3);

        let req = |channel: [u8; 32], holder: &SigningKey| ChannelJoinRequest {
            grant: grant_h(channel, holder, Direction::Both, 1_000),
            endpoint: "relay-only".to_string(),
        };

        let (c_ab_a, s_ab_a) = tokio::io::duplex(4096); // Alice's leg of A-B
        let (c_ab_b, s_ab_b) = tokio::io::duplex(4096); // Bob's leg of A-B
        let (c_bc_b, s_bc_b) = tokio::io::duplex(4096); // Bob's leg of B-C
        let (c_bc_c, s_bc_c) = tokio::io::duplex(4096); // Carol's leg of B-C
        let (c_ac_a, s_ac_a) = tokio::io::duplex(4096); // Alice's leg of A-C
        let (c_ac_c, s_ac_c) = tokio::io::duplex(4096); // Carol's leg of A-C

        let t_ab_a = tokio::spawn(room_member_roundtrip(c_ab_a, req(chan_ab, &alice), alice.clone(), 0xA0));
        let t_ab_b = tokio::spawn(room_member_roundtrip(c_ab_b, req(chan_ab, &bob), bob.clone(), 0xB0));
        let t_bc_b = tokio::spawn(room_member_roundtrip(c_bc_b, req(chan_bc, &bob), bob.clone(), 0xB1));
        let t_bc_c = tokio::spawn(room_member_roundtrip(c_bc_c, req(chan_bc, &carol), carol.clone(), 0xC1));
        let t_ac_a = tokio::spawn(room_member_roundtrip(c_ac_a, req(chan_ac, &alice), alice.clone(), 0xA2));
        let t_ac_c = tokio::spawn(room_member_roundtrip(c_ac_c, req(chan_ac, &carol), carol.clone(), 0xC2));

        let pairer: SharedChannelPairer = new_shared_channel_pairer();
        let authorize = move |c: ChannelId, _h: [u8; 32]| async move {
            (c.0 == chan_ab || c.0 == chan_bc || c.0 == chan_ac).then_some((pk, None, None))
        };
        let obs: std::net::SocketAddr = "203.0.113.9:9001".parse().unwrap();

        // Admit all 6 members CONCURRENTLY, deliberately interleaved across the three
        // channels (not grouped) -- each admit_and_pair_on_stream call is its own
        // task, so the real ordering is whatever the executor happens to schedule,
        // exactly like 3 browser tabs' WebSocket connections racing in on a real edge.
        async fn admit(
            stream: tokio::io::DuplexStream,
            obs: std::net::SocketAddr,
            authorize: impl Fn(ChannelId, [u8; 32]) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send>>
                + Send
                + Sync
                + 'static,
            pairer: SharedChannelPairer,
        ) -> Option<(AdmittedStreamMember<BoxedChannelStream>, AdmittedStreamMember<BoxedChannelStream>)> {
            let boxed: BoxedChannelStream = Box::pin(stream);
            admit_and_pair_on_stream(boxed, obs, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, None)
                .await
                .expect("admission")
        }
        // A boxed, cloneable authorize closure so each spawned admit task can own one.
        let authorize_dyn = move |c: ChannelId, h: [u8; 32]| -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send>> {
            Box::pin(authorize(c, h))
        };
        let a_ab_a = { let p = pairer.clone(); let f = authorize_dyn.clone(); tokio::spawn(async move { admit(s_ab_a, obs, f, p).await }) };
        let a_bc_b = { let p = pairer.clone(); let f = authorize_dyn.clone(); tokio::spawn(async move { admit(s_bc_b, obs, f, p).await }) };
        let a_ac_a = { let p = pairer.clone(); let f = authorize_dyn.clone(); tokio::spawn(async move { admit(s_ac_a, obs, f, p).await }) };
        // Give the three first-arrivals above a moment to park before the seconds
        // arrive, so this genuinely exercises "3 different lone waiters parked at
        // once" (not just a race that happens to resolve either way).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(pairer.lock().unwrap().len(), 3, "all three channels' first arrivals are parked simultaneously");

        let a_ab_b = { let p = pairer.clone(); let f = authorize_dyn.clone(); tokio::spawn(async move { admit(s_ab_b, obs, f, p).await }) };
        let a_ac_c = { let p = pairer.clone(); let f = authorize_dyn.clone(); tokio::spawn(async move { admit(s_ac_c, obs, f, p).await }) };
        let a_bc_c = { let p = pairer.clone(); let f = authorize_dyn.clone(); tokio::spawn(async move { admit(s_bc_c, obs, f, p).await }) };

        let (r_ab_a, r_bc_b, r_ac_a, r_ab_b, r_ac_c, r_bc_c) =
            tokio::join!(a_ab_a, a_bc_b, a_ac_a, a_ab_b, a_ac_c, a_bc_c);
        assert!(pairer.lock().unwrap().is_empty(), "every parked member found its own pair, none left waiting");

        // Exactly one of each pair's two admit calls carries the real Some((a, b));
        // the other necessarily returned None (it was the one that parked).
        let pair_ab = r_ab_a.unwrap().or(r_ab_b.unwrap()).expect("A-B paired");
        let pair_bc = r_bc_b.unwrap().or(r_bc_c.unwrap()).expect("B-C paired");
        let pair_ac = r_ac_a.unwrap().or(r_ac_c.unwrap()).expect("A-C paired");

        tokio::join!(
            async { finish_relay_pair_over_streams(pair_ab.0, pair_ab.1, 500).await.expect("A-B relay") },
            async { finish_relay_pair_over_streams(pair_bc.0, pair_bc.1, 500).await.expect("B-C relay") },
            async { finish_relay_pair_over_streams(pair_ac.0, pair_ac.1, 500).await.expect("A-C relay") },
        );

        // Each side got EXACTLY its own pairwise partner's byte -- never a byte from
        // either of the other two pairs (the concrete proof there is no cross-talk).
        assert_eq!(t_ab_a.await.unwrap(), 0xB0, "Alice's A-B leg got Bob's A-B byte");
        assert_eq!(t_ab_b.await.unwrap(), 0xA0, "Bob's A-B leg got Alice's A-B byte");
        assert_eq!(t_bc_b.await.unwrap(), 0xC1, "Bob's B-C leg got Carol's B-C byte");
        assert_eq!(t_bc_c.await.unwrap(), 0xB1, "Carol's B-C leg got Bob's B-C byte");
        assert_eq!(t_ac_a.await.unwrap(), 0xC2, "Alice's A-C leg got Carol's A-C byte");
        assert_eq!(t_ac_c.await.unwrap(), 0xA2, "Carol's A-C leg got Alice's A-C byte");
    }

    #[tokio::test]
    async fn read_join_on_connection_times_out_a_stalled_connection() {
        // #105: a client that completes the QUIC handshake but never opens a bi-stream
        // (never submits a join) must NOT wedge the broker — read_join_on_connection
        // abandons it within the timeout instead of blocking the serial round forever.
        use std::time::{Duration, Instant};
        let pk = operator_pubkey();
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let start = Instant::now();
            let r = read_join_on_connection(&conn, 500, Duration::from_millis(400), &move |c, _h| async move {
                (c.0 == [0u8; 32]).then_some((pk, None, None))
            })
            .await;
            (r.is_err(), start.elapsed())
        });
        let client = build_client_endpoint(cert).expect("client");
        // Connect but NEVER open a bi-stream — the stalled/silent case. Hold the
        // connection so accept_bi genuinely waits (and hits the timeout).
        let _conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (errored, elapsed) = server_task.await.expect("task");
        assert!(errored, "a stalled connection is abandoned with an error, not hung");
        assert!(elapsed < Duration::from_secs(2), "it timed out fast ({elapsed:?}), not forever");
    }

    #[tokio::test]
    async fn edge_refuses_unknown_channel_and_expired_grant() {
        // Unknown channel: the operator lookup returns None -> NO.
        let unknown = join_request([0xC2u8; 32], 0x0b, "203.0.113.9:6002");
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task =
            tokio::spawn(
                async move {
                    resolve_channel_join(&server, 500, |_c, _h| async move { None::<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)> })
                        .await
                        .map(|_| ())
                },
            );
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &unknown.encode(), &holder_sk(0x0b)).await;
        assert_ne!(ack, b"OK", "an unknown channel must be refused");
        let _ = server_task.await;

        // Known channel but the grant is expired at `now` -> NO.
        let pk = operator_pubkey();
        let channel = [0xC3u8; 32];
        let expired = join_request(channel, 0x0c, "203.0.113.9:6003"); // expires_at = 1_000
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let server2_task = tokio::spawn(async move {
            resolve_channel_join(&server2, 2_000, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let ack2 = present_join(&conn2, &expired.encode(), &holder_sk(0x0c)).await;
        assert_ne!(ack2, b"OK", "an expired grant must be refused");
        let _ = server2_task.await;
    }

    /// #555: the registry cuts exactly the removed member's legs and nothing else.
    #[tokio::test]
    async fn cutting_a_members_splice_leaves_every_other_leg_alone_555() {
        let chan_a = ChannelId([0x11; 32]);
        let chan_b = ChannelId([0x22; 32]);
        let alice = [0xaa; 32];
        let bob = [0xbb; 32];

        let g_alice = register_live_splice(&chan_a, &alice);
        let g_bob = register_live_splice(&chan_a, &bob);
        let g_alice_other_channel = register_live_splice(&chan_b, &alice);

        // The registry is process-wide and tests run concurrently, so assert about OUR
        // keys rather than the total -- a global count here would fail for reasons that
        // have nothing to do with what is being tested.
        let members = live_splice_members();
        for k in [(chan_a.0, alice), (chan_a.0, bob), (chan_b.0, alice)] {
            assert!(members.contains(&k), "our three legs must be registered: {members:?}");
        }

        assert_eq!(cut_live_splices(&chan_a.0, &alice), 1, "exactly Alice's leg on channel A");

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), g_alice.cut()).await.is_ok(),
            "the removed member's leg must be cut"
        );
        // The same holder on a DIFFERENT channel is a different membership: removing her
        // from one conversation must not end the other.
        for (g, who) in [(&g_bob, "Bob on the same channel"), (&g_alice_other_channel, "Alice on another channel")] {
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(200), g.cut()).await.is_err(),
                "{who} must be untouched"
            );
        }

        drop(g_alice);
        drop(g_bob);
        drop(g_alice_other_channel);
        let after = live_splice_members();
        for k in [(chan_a.0, alice), (chan_a.0, bob), (chan_b.0, alice)] {
            assert!(!after.contains(&k), "guards deregister on drop: {after:?}");
        }
    }

    /// #555, the direction that matters more: a control plane that cannot answer must NOT
    /// end calls. `resolve_member` flattens "not a member" and "could not ask" into `None`
    /// because admission fails closed; reusing that here would drop every conversation on
    /// the edge the moment the CP restarted.
    #[tokio::test]
    async fn an_unreachable_control_plane_never_cuts_a_live_splice_555() {
        struct Silent;
        impl crate::serve::ChannelMemberResolver for Silent {
            fn resolve_member<'a>(
                &'a self,
                _c: ChannelId,
                _h: [u8; 32],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send + 'a>> {
                // What an unreachable CP looks like to admission: refuse, fail closed.
                Box::pin(async { None })
            }
            // `membership_revoked` deliberately NOT overridden -- this resolver cannot tell
            // the two cases apart, so it must never cause a cut. That is the default.
        }

        let chan = ChannelId([0x33; 32]);
        let holder = [0xcc; 32];
        let guard = register_live_splice(&chan, &holder);

        let resolver: std::sync::Arc<dyn crate::serve::ChannelMemberResolver> = std::sync::Arc::new(Silent);
        let cut = sweep_live_splice_memberships(&resolver).await;

        assert_eq!(
            cut, 0,
            "a resolver that answers None for BOTH 'removed' and 'unreachable' must cut \
             nothing -- otherwise one CP restart ends every call on this edge"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), guard.cut()).await.is_err(),
            "the live splice must still be running"
        );
    }

    /// #555: and a resolver that CAN tell, and says the membership is gone, does cut.
    ///
    /// The resolver answers for ONE channel and says "still a member" for every other. That
    /// is not test decoration -- a blanket "everyone is revoked" resolver is not a thing a
    /// real control plane can be, and because the splice registry is process-wide, such a
    /// resolver reaches the legs of every other test running at that moment. The first
    /// version of this test did exactly that and made all three #555 tests flaky.
    #[tokio::test]
    async fn a_definitive_removal_cuts_the_splice_555() {
        struct Authoritative(ChannelId);
        impl crate::serve::ChannelMemberResolver for Authoritative {
            fn resolve_member<'a>(
                &'a self,
                _c: ChannelId,
                _h: [u8; 32],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> + Send + 'a>> {
                Box::pin(async { None })
            }
            fn membership_revoked<'a>(
                &'a self,
                c: ChannelId,
                _h: [u8; 32],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
                let mine = self.0.0 == c.0;
                Box::pin(async move { mine })
            }
        }

        let chan = ChannelId([0x44; 32]);
        let holder = [0xdd; 32];
        let guard = register_live_splice(&chan, &holder);

        let resolver: std::sync::Arc<dyn crate::serve::ChannelMemberResolver> =
            std::sync::Arc::new(Authoritative(chan.clone()));
        // Assert about OUR leg, not the sweep's total: the registry is process-wide, so a
        // count is a statement about whatever else happens to be running.
        assert!(sweep_live_splice_memberships(&resolver).await >= 1, "our leg was cut");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), guard.cut()).await.is_ok(),
            "and the splice actually learns about it"
        );
    }

    #[tokio::test]
    async fn broker_channel_relay_splices_two_members_tunnels() {
        // #72 AF4-relay-fallback (edge side): the connection-difficulty path. Two
        // members that can't go direct both join the RELAY endpoint; the edge auths +
        // pairs them and splices their data streams, so the tunnel flows THROUGH the
        // edge (ciphertext). Prove bytes cross both ways over the relay.
        let pk = operator_pubkey();
        let channel = [0xE0u8; 32];
        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&server, 500, move |c, _h| async move {
                (c.0 == channel).then_some((pk, None, None))
            })
            .await
            .map(|_| ())
        });

        // Roles preserved through the relay (as the real Noise session needs): the
        // INITIATOR opens its data stream; the ACCEPTOR accepts one the edge opens.
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack_a = present_join(&conn, &req_a.encode(), &holder_a).await;
            assert!(ack_a.starts_with(b"OK 203.0.113.2:7002 r="), "A admitted to relay with B's endpoint + its own observed reflexive, got {:?}", String::from_utf8_lossy(&ack_a));
            // #276 piece 1: both test clients dial from loopback, so the edge observes the SAME
            // reflexive IP for both -- proving the `sp=1` token is genuinely wired end to end
            // through `finish_relay_pair`, not just correct in the pure `same_public_ip` unit tests.
            let text_a = String::from_utf8_lossy(&ack_a);
            assert!(text_a.ends_with(" sp=1"), "same-loopback-IP pair must be tagged sp=1, got {text_a:?}");
            let (mut s, mut r) = conn.open_bi().await.expect("a data bi"); // initiator opens
            s.write_all(b"tunnel A->B via edge").await.expect("a write");
            let mut got = vec![0u8; 20];
            r.read_exact(&mut got).await.expect("a read");
            conn.close(0u32.into(), b"done");
            got
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack_b = present_join(&conn, &req_b.encode(), &holder_b).await;
            assert!(ack_b.starts_with(b"OK 203.0.113.1:7001 r="), "B admitted to relay with A's endpoint + its own observed reflexive, got {:?}", String::from_utf8_lossy(&ack_b));
            let (mut s, mut r) = conn.accept_bi().await.expect("b data bi"); // acceptor accepts the edge-opened stream
            let mut got = vec![0u8; 20];
            r.read_exact(&mut got).await.expect("b read");
            s.write_all(b"tunnel B->A via edge").await.expect("b write");
            let _ = s.finish();
            conn.closed().await;
            got
        });

        let got_a = a.await.expect("a");
        let got_b = b.await.expect("b");
        let _ = relay_task.await;
        assert_eq!(&got_a, b"tunnel B->A via edge", "A receives B's bytes through the edge relay");
        assert_eq!(&got_b, b"tunnel A->B via edge", "B receives A's bytes through the edge relay");
    }

    #[tokio::test]
    async fn broker_channel_relay_echoes_each_members_own_observed_reflexive() {
        // #104-follow: `finish_relay_pair` (the QUIC-native completer -- what a real
        // CT_CHANNEL_RELAY_ONLY member uses) previously acked a bare `OK`, so a relay-only
        // member's own ct-agent never learned its edge-observed reflexive address and #104's
        // in-band direct-upgrade was structurally unreachable for it (live-reproduced via
        // #248's cross-NAT test). This proves each side's ack now carries `r=<its own reflexive>`
        // -- specifically ITS OWN, not the peer's -- exactly as `finish_rendezvous_pair` already
        // does (#121 B1-follow).
        let pk = operator_pubkey();
        let channel = [0xE1u8; 32];
        let holder_a = holder_sk(0xa3);
        let holder_b = holder_sk(0xb4);
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.3:7003".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.4:7004".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&server, 500, move |c, _h| async move {
                (c.0 == channel).then_some((pk, None, None))
            })
            .await
            .map(|_| ())
        });

        // No data-stream exchange needed here — `finish_relay_pair` writes both acks as soon as
        // authorization succeeds, before the relay splice starts, so closing right after reading
        // the ack is enough to observe it (the splice itself is already covered by the sibling
        // test above). Quinn streams open lazily on first write, so opening a bi-stream and never
        // writing to it would just idle out — avoided entirely by not opening one.
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_a.encode(), &holder_a).await;
            conn.close(0u32.into(), b"done");
            ack
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_b.encode(), &holder_b).await;
            conn.close(0u32.into(), b"done");
            ack
        });

        let ack_a = a.await.expect("a");
        let ack_b = b.await.expect("b");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task).await;

        let text_a = String::from_utf8_lossy(&ack_a);
        let text_b = String::from_utf8_lossy(&ack_b);
        let r_a = text_a.strip_prefix("OK 203.0.113.4:7004 r=").expect("A's ack carries B's endpoint + its own r= token");
        let r_b = text_b.strip_prefix("OK 203.0.113.3:7003 r=").expect("B's ack carries A's endpoint + its own r= token");
        // #276 piece 1 added a trailing ` sp=<0|1>` token after `r=<addr>` -- split it off before
        // parsing the address.
        let (r_a, sp_a) = r_a.split_once(" sp=").expect("A's ack carries the sp= token after r=");
        let (r_b, sp_b) = r_b.split_once(" sp=").expect("B's ack carries the sp= token after r=");
        assert_eq!(sp_a, "1", "same-loopback-IP pair must be tagged sp=1");
        assert_eq!(sp_b, "1", "same-loopback-IP pair must be tagged sp=1");

        // Both connected from loopback, so each reflexive is 127.0.0.1:<ephemeral port>; the
        // real assertion is that the two are DIFFERENT (each got its own address, not a shared
        // or swapped one) and both parse as real socket addresses.
        let addr_a: std::net::SocketAddr = r_a.parse().expect("A's r= is a real socket address");
        let addr_b: std::net::SocketAddr = r_b.parse().expect("B's r= is a real socket address");
        assert_eq!(addr_a.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(addr_b.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_ne!(addr_a.port(), addr_b.port(), "each member's own reflexive port, not swapped or shared");
    }

    #[tokio::test]
    async fn broker_channel_relay_relays_each_members_peer_attested_noise_key() {
        // #134-follow (found live while E2E-verifying the real gated relay-gate hole-punch):
        // `finish_relay_pair` (the QUIC-native completer -- the ONLY completer
        // `join_via_relay_dcutr`/`join_via_relay_gate_dcutr` reach) acked a bare `OK r=<observed>`,
        // never relaying the peer's attested Noise key/holder/attestation -- unlike
        // `finish_rendezvous_pair` and `finish_relay_pair_over_streams`, both of which already
        // carry it via `member_ack_suffix`/`write_member_ack`. Every real `CT_CHANNEL_RELAY_ONLY`
        // DCUtR join therefore failed against a real deployed edge with "needs the peer's relayed
        // Noise key (#101)" -- the #136 NAT-to-NAT upgrade had never actually completed outside an
        // in-process test that bypasses this completer entirely. Proves each side's ack now carries
        // the OTHER side's endpoint + noise + holder + attestation, hex-encoded, positioned exactly
        // where `parse_channel_ack` (ct-agent) expects them.
        let pk = operator_pubkey();
        let channel = [0xE2u8; 32];
        let holder_a = holder_sk(0xa5);
        let holder_b = holder_sk(0xb6);
        let noise_a = [0x11u8; 32];
        let noise_b = [0x22u8; 32];
        let attest_a = [0x33u8; 64];
        let attest_b = [0x44u8; 64];
        let holder_a_pub = holder_a.verifying_key().to_bytes();
        let holder_b_pub = holder_b.verifying_key().to_bytes();
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.5:7005".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.6:7006".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            broker_channel_relay(&server, 500, move |c, h| {
                let ret = if h == holder_a_pub { (pk, Some(noise_a), Some(attest_a)) } else { (pk, Some(noise_b), Some(attest_b)) };
                async move { (c.0 == channel).then_some(ret) }
            })
            .await
            .map(|_| ())
        });

        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_a.encode(), &holder_a).await;
            conn.close(0u32.into(), b"done");
            ack
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_b.encode(), &holder_b).await;
            conn.close(0u32.into(), b"done");
            ack
        });

        let ack_a = a.await.expect("a");
        let ack_b = b.await.expect("b");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task).await;

        let text_a = String::from_utf8_lossy(&ack_a);
        let text_b = String::from_utf8_lossy(&ack_b);
        assert_eq!(
            text_a.split(" r=").next().unwrap(),
            format!("OK 203.0.113.6:7006 {} {} {}", hex_of(&noise_b), hex_of(&holder_b_pub), hex_of(&attest_b)),
            "A's ack carries B's endpoint + attested Noise key + holder + attestation, got {text_a:?}"
        );
        assert_eq!(
            text_b.split(" r=").next().unwrap(),
            format!("OK 203.0.113.5:7005 {} {} {}", hex_of(&noise_a), hex_of(&holder_a_pub), hex_of(&attest_a)),
            "B's ack carries A's endpoint + attested Noise key + holder + attestation, got {text_b:?}"
        );
    }

    /// One relay member for the concurrency test: connect over QUIC, run the admission
    /// handshake, await the relay's `OK` (written only once the member is PAIRED), then run
    /// the data-stream dance for its role and exchange one byte through the edge. The
    /// Initiate side opens its data stream; the Accept side accepts the edge-opened one
    /// (roles come from the grant direction), exactly as the live Noise session does. After
    /// the byte crosses, it signals `on_ready` (proving it paired + is relaying) and, when
    /// `hold` is set, keeps its connection open until notified — so one channel's relay can
    /// be held LIVE while another channel races to pair. Returns the peer's byte.
    async fn run_relay_member(
        cert: rustls::pki_types::CertificateDer<'static>,
        addr: std::net::SocketAddr,
        channel: [u8; 32],
        holder: SigningKey,
        direction: Direction,
        send_byte: u8,
        on_ready: Option<tokio::sync::mpsc::Sender<()>>,
        hold: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> u8 {
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, direction, 1_000),
            endpoint: "203.0.113.9:7000".to_string(),
        };
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert!(ack.starts_with(b"OK 203.0.113.9:7000 r="), "member admitted + paired with its own observed reflexive, got {:?}", String::from_utf8_lossy(&ack));
        let mut got = [0u8; 1];
        if direction == Direction::Initiate {
            let (mut s, mut r) = conn.open_bi().await.expect("init data bi"); // initiator opens
            s.write_all(&[send_byte]).await.expect("init write");
            r.read_exact(&mut got).await.expect("init read");
        } else {
            let (mut s, mut r) = conn.accept_bi().await.expect("acc data bi"); // acceptor accepts edge-opened
            r.read_exact(&mut got).await.expect("acc read");
            s.write_all(&[send_byte]).await.expect("acc write");
            let _ = s.finish(); // finish (not abort) so the relay forwards the byte + EOF
        }
        if let Some(tx) = on_ready {
            let _ = tx.send(()).await; // paired + a byte has crossed → relay is live
        }
        if let Some(rx) = hold {
            let _ = rx.await; // keep the relay (and connection) open until released
        }
        // Teardown order matches the passing `broker_channel_relay_splices` test: the
        // initiator closes the connection (tearing the relay down), and the acceptor
        // WAITS for that teardown so its finished byte is fully forwarded first — an
        // abrupt `conn.close()` on the writer races the relay and drops the last byte.
        if direction == Direction::Initiate {
            conn.close(0u32.into(), b"done");
        } else {
            conn.closed().await;
        }
        got[0]
    }

    #[tokio::test]
    async fn relay_broker_loop_pairs_two_channels_concurrently_without_wedging() {
        // #109-concurrent-b (frozen): the anti-wedge + correct-correlation property over real
        // QUIC, driving the RELAY endpoint with `run_relay_broker_loop`. Channel X and channel
        // Y each present an Initiate+Accept member (4 connections). We deterministically pair X
        // FIRST and HOLD its relay open, then race Y in: with the pairer-driven loop that spawns
        // each splice on its own task, Y still pairs and its bytes cross (anti-wedge, #1) while
        // being channel-keyed so X and Y never cross-pair (#2). Under the old serial
        // `loop { broker_channel_relay }`, X's held-open inline splice would block the accept
        // loop forever and Y would never be admitted — this test would hang.
        let pk = operator_pubkey();
        let chan_x = [0x11u8; 32];
        let chan_y = [0x22u8; 32];

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Drive the relay endpoint with the concurrent, channel-keyed broker loop. Fixed clock
        // + generous park TTL so no lone waiter is evicted mid-test.
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move {
                    (c.0 == chan_x || c.0 == chan_y).then_some((pk, None, None))
                },
                10_000,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_relay_pair,
            None,
            crate::shutdown::ShutdownSignal::never(),
            std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new())),
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        // Phase 1: pair channel X and hold its relay OPEN. A per-member oneshot keeps X's two
        // members (hence X's spawned splice task) alive until we release them after Y is done
        // — a oneshot is race-free (the release is delivered even if sent before the member
        // awaits it, unlike `Notify::notify_waiters`).
        let (x1_tx, x1_rx) = tokio::sync::oneshot::channel::<()>();
        let (x2_tx, x2_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(2);
        let x_init = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_x, holder_sk(0xa1), Direction::Initiate, 0x01,
            Some(ready_tx.clone()), Some(x1_rx),
        ));
        let x_acc = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_x, holder_sk(0xb2), Direction::Accept, 0x02,
            Some(ready_tx.clone()), Some(x2_rx),
        ));
        drop(ready_tx);
        // Both X members report a byte has crossed: X is paired and its relay is actively
        // splicing (and held open) BEFORE any Y connection exists.
        ready_rx.recv().await.expect("x member 1 relaying");
        ready_rx.recv().await.expect("x member 2 relaying");

        // Phase 2: now race channel Y in. If the accept loop were wedged by X's held-open relay,
        // these would hang; with the pairer-driven loop they pair on a fresh spawned splice.
        let y_init = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_y, holder_sk(0xc3), Direction::Initiate, 0x91,
            None, None,
        ));
        let y_acc = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan_y, holder_sk(0xd4), Direction::Accept, 0x92,
            None, None,
        ));
        let got_y_init = y_init.await.expect("y init task");
        let got_y_acc = y_acc.await.expect("y acc task");
        assert_eq!(got_y_init, 0x92, "Y initiator received Y acceptor's byte (Y paired while X held)");
        assert_eq!(got_y_acc, 0x91, "Y acceptor received Y initiator's byte (no cross-channel mis-pair)");

        // Release X and verify its own bytes crossed correctly (X paired with X, not Y).
        let _ = x1_tx.send(());
        let _ = x2_tx.send(());
        let got_x_init = x_init.await.expect("x init task");
        let got_x_acc = x_acc.await.expect("x acc task");
        assert_eq!(got_x_init, 0x02, "X initiator received X acceptor's byte");
        assert_eq!(got_x_acc, 0x01, "X acceptor received X initiator's byte");

        driver.abort();
    }

    /// One rendezvous member for the concurrency test: connect over QUIC, run the admission
    /// handshake, and receive the rendezvous `OK <peer_endpoint>` ack (written only once the
    /// member is PAIRED and its finisher runs). Rendezvous is an endpoint swap, not a data
    /// splice — the member only READS its ack (no stream exchange, so no writer-finish race).
    /// It reports readiness via `on_ready` (proving it paired) and, when `hold` is set, keeps
    /// its connection OPEN until notified — so one channel's rendezvous finisher (blocked in
    /// `conn.closed()`) stays live while another channel races to pair. Returns the ack text.
    async fn run_rendezvous_member(
        cert: rustls::pki_types::CertificateDer<'static>,
        addr: std::net::SocketAddr,
        channel: [u8; 32],
        holder: SigningKey,
        direction: Direction,
        advertised: &'static str,
        on_ready: Option<tokio::sync::mpsc::Sender<()>>,
        hold: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> String {
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, direction, 1_000),
            endpoint: advertised.to_string(),
        };
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = String::from_utf8(present_join(&conn, &req.encode(), &holder).await)
            .unwrap_or_default();
        if let Some(tx) = on_ready {
            let _ = tx.send(()).await; // paired: the OK ack arrived
        }
        if let Some(rx) = hold {
            let _ = rx.await; // keep the rendezvous connection OPEN until released
        }
        // Release: close the connection so the spawned finisher's `conn.closed()` returns.
        conn.close(0u32.into(), b"done");
        ack
    }

    #[tokio::test]
    async fn rendezvous_broker_loop_pairs_two_channels_concurrently_without_wedging() {
        // #120 (frozen): the anti-wedge + correct-correlation property over real QUIC, driving
        // the RENDEZVOUS endpoint with `run_channel_broker_loop` + `finish_rendezvous_pair`.
        // Channel X and channel Y each present an Initiate+Accept member (4 connections). We
        // deterministically pair X FIRST and HOLD its rendezvous connections open — so X's
        // spawned `finish_rendezvous_pair` blocks forever in `conn.closed()` — then race Y in:
        // with the pairer-driven loop that spawns each finisher on its own task, Y still pairs
        // and both Y members get their `OK <peer_endpoint>` ack (anti-wedge, #1) while channel-
        // keying means X and Y never cross-pair (#2). Under the old serial
        // `loop { broker_channel_rendezvous }`, X's held-open `conn.closed()` await would block
        // the accept loop forever and Y would never be admitted — this test would hang. (This is
        // the exact single-slot wedge #109 fixed for the relay, left serial for rendezvous.)
        let pk = operator_pubkey();
        let chan_x = [0x11u8; 32];
        let chan_y = [0x22u8; 32];

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        // Drive the rendezvous endpoint with the concurrent, channel-keyed broker loop, passing
        // the rendezvous completer. Fixed clock + generous park TTL so no waiter is evicted.
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move {
                    (c.0 == chan_x || c.0 == chan_y).then_some((pk, None, None))
                },
                10_000,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_rendezvous_pair,
            None,
            crate::shutdown::ShutdownSignal::never(),
            std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new())),
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        // Phase 1: pair channel X and HOLD its two rendezvous connections open. A per-member
        // oneshot keeps X's members (and hence X's spawned finisher, blocked in `conn.closed()`)
        // alive until released after Y is done.
        let (x1_tx, x1_rx) = tokio::sync::oneshot::channel::<()>();
        let (x2_tx, x2_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(2);
        let x_init = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_x, holder_sk(0xa1), Direction::Initiate, "203.0.113.1:7001",
            Some(ready_tx.clone()), Some(x1_rx),
        ));
        let x_acc = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_x, holder_sk(0xb2), Direction::Accept, "203.0.113.2:7002",
            Some(ready_tx.clone()), Some(x2_rx),
        ));
        drop(ready_tx);
        // Both X members received their OK ack: X is paired and its finisher is now blocked in
        // `conn.closed()` (held open) BEFORE any Y connection exists.
        ready_rx.recv().await.expect("x member 1 paired");
        ready_rx.recv().await.expect("x member 2 paired");

        // Phase 2: now race channel Y in. If the accept loop were wedged by X's held-open
        // finisher, these would hang; with the pairer-driven loop they pair on a fresh finisher.
        let y_init = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_y, holder_sk(0xc3), Direction::Initiate, "203.0.113.3:7003",
            None, None,
        ));
        let y_acc = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_y, holder_sk(0xd4), Direction::Accept, "203.0.113.4:7004",
            None, None,
        ));
        let ack_y_init = y_init.await.expect("y init task");
        let ack_y_acc = y_acc.await.expect("y acc task");
        // Each Y member is admitted+paired and learns the OTHER Y member's endpoint (paired
        // while X was held) — and NEVER an X endpoint (channel-keyed: no cross-pair).
        assert!(ack_y_init.starts_with("OK "), "Y initiator was admitted+paired, got {ack_y_init:?}");
        assert!(ack_y_acc.starts_with("OK "), "Y acceptor was admitted+paired, got {ack_y_acc:?}");
        assert!(ack_y_init.contains("203.0.113.4:7004"), "Y initiator learns Y acceptor's endpoint, got {ack_y_init:?}");
        assert!(ack_y_acc.contains("203.0.113.3:7003"), "Y acceptor learns Y initiator's endpoint, got {ack_y_acc:?}");
        // No X<->Y cross-pair: match X's FULL advertised host:port strings, not bare ":7001"/
        // ":7002" ports. Each ack also carries the member's own `r=<reflexive>` token (an ephemeral
        // `127.0.0.1:<port>` source the edge observed); that ephemeral port can substring-match a
        // bare "7001"/"7002" and spuriously trip this check even with zero cross-pairing. An X
        // endpoint can only appear in a Y ack via an actual cross-pair.
        for x_ep in ["203.0.113.1:7001", "203.0.113.2:7002"] {
            assert!(!ack_y_init.contains(x_ep), "channel-keyed: Y initiator never learns X endpoint {x_ep}, got {ack_y_init:?}");
            assert!(!ack_y_acc.contains(x_ep), "channel-keyed: Y acceptor never learns X endpoint {x_ep}, got {ack_y_acc:?}");
        }

        // Release X and verify its own acks swapped the X endpoints (X paired with X, not Y).
        let _ = x1_tx.send(());
        let _ = x2_tx.send(());
        let ack_x_init = x_init.await.expect("x init task");
        let ack_x_acc = x_acc.await.expect("x acc task");
        assert!(ack_x_init.contains("203.0.113.2:7002"), "X initiator learns X acceptor's endpoint, got {ack_x_init:?}");
        assert!(ack_x_acc.contains("203.0.113.1:7001"), "X acceptor learns X initiator's endpoint, got {ack_x_acc:?}");

        driver.abort();
    }

    #[tokio::test]
    async fn admission_is_concurrent_a_stalled_join_does_not_block_other_channels() {
        // #203 (frozen): ADMISSION must be spawned, not awaited inline. A member that connects but
        // never sends its join stalls its admission (read_join blocks up to JOIN_READ_TIMEOUT = 15s).
        // Under the OLD serial loop that stalled admission wedged the single accept slot, so ANOTHER
        // channel could not be admitted until the staller timed out ~15s later (exactly why
        // `structure`/`review`, dialed last, lost to contention behind an in-flight admission). Here
        // channel Y admits + pairs PROMPTLY (well under 15s) despite the staller.
        let pk = operator_pubkey();
        let chan_y = [0x22u8; 32];
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == chan_y).then_some((pk, None, None)) },
                10_000,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_rendezvous_pair,
            None,
            crate::shutdown::ShutdownSignal::never(),
            std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new())),
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        // A staller: connect over QUIC and hold it open, NEVER sending a join → its admission blocks
        // in read_join for the full JOIN_READ_TIMEOUT. Held in scope so it stays connected + stalling.
        let staller_client = build_client_endpoint(cert.clone()).expect("staller client");
        let _staller = staller_client.connect(addr, "localhost").expect("cfg").await.expect("staller conn");
        // Let the staller be an accepted, in-flight admission before channel Y arrives.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Channel Y's two members must admit + pair PROMPTLY (< the 15s stall) — the proof that
        // admission is concurrent. Under the old serial loop these would not resolve until ~15s.
        let y_init = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_y, holder_sk(0xc3), Direction::Initiate, "203.0.113.3:7003", None, None,
        ));
        let y_acc = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan_y, holder_sk(0xd4), Direction::Accept, "203.0.113.4:7004", None, None,
        ));
        let ack_i = tokio::time::timeout(std::time::Duration::from_secs(8), y_init)
            .await
            .expect("Y initiator must pair promptly despite the stalled admission (#203 admission concurrency)")
            .expect("y init task");
        let ack_a = tokio::time::timeout(std::time::Duration::from_secs(8), y_acc)
            .await
            .expect("Y acceptor must pair promptly (#203)")
            .expect("y acc task");
        assert!(ack_i.starts_with("OK ") && ack_i.contains("203.0.113.4:7004"), "Y initiator admitted+paired: {ack_i:?}");
        assert!(ack_a.starts_with("OK ") && ack_a.contains("203.0.113.3:7003"), "Y acceptor admitted+paired: {ack_a:?}");

        driver.abort();
    }

    #[tokio::test]
    async fn a_member_parked_after_idle_is_not_evicted_before_its_partner_pairs() {
        // #103 regression (root cause, central-confirmed): the parked member's deadline must be
        // TTL from its ADMISSION time, not from the loop-iteration top sampled BEFORE the idle
        // accept wait. Model the idle with a controllable clock: the loop starts + goes idle
        // (top-of-iter `now` = 100), THEN the clock jumps far past `park_ttl` before either
        // member connects (admission `now` = 900). A correct impl dates member 1's deadline at
        // 900+ttl so the next iteration's drain (now=900) keeps it and the pair forms; the old
        // stale-`now` dated it at 100+ttl=105 << 900 -> drained ~instantly -> member 2 parks
        // alone -> no pairing (this test would hang without the fix). Grant expiry is 1_000, so
        // both admission `now`s (100, 900) stay under it and the grants still verify.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let pk = operator_pubkey();
        let chan = [0x11u8; 32];
        let clock = Arc::new(AtomicU64::new(100));
        let park_ttl = 5u64;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let clock_loop = clock.clone();
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                move || clock_loop.load(Ordering::Relaxed),
                move |c: ChannelId, _h: [u8; 32]| async move {
                    (c.0 == chan).then_some((pk, None, None))
                },
                park_ttl,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_rendezvous_pair,
            None,
            crate::shutdown::ShutdownSignal::never(),
            std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new())),
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        // Let the loop reach its idle `accept_member().await` (top-of-iter now sampled = 100),
        // THEN jump the clock far past park_ttl — simulating the idle period before the first
        // connection that made the old code's parked deadline already-expired.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        clock.store(900, Ordering::Relaxed);

        let m1 = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan, holder_sk(0xa1), Direction::Initiate, "203.0.113.1:7001", None, None,
        ));
        let m2 = tokio::spawn(run_rendezvous_member(
            cert.clone(), addr, chan, holder_sk(0xb2), Direction::Accept, "203.0.113.2:7002", None, None,
        ));

        // Both must get their `OK <peer_endpoint>` ack — i.e. they PAIRED. Without the fix,
        // member 1 is drain-evicted before member 2 offers, so neither pairs and this times out.
        let ack1 = tokio::time::timeout(std::time::Duration::from_secs(10), m1)
            .await
            .expect("member 1 pairs — not evicted by a stale-now drain (#103)")
            .expect("m1 join");
        let ack2 = tokio::time::timeout(std::time::Duration::from_secs(10), m2)
            .await
            .expect("member 2 pairs (#103)")
            .expect("m2 join");
        assert!(ack1.starts_with("OK"), "member 1 got a pairing ack, got {ack1:?}");
        assert!(ack2.starts_with("OK"), "member 2 got a pairing ack, got {ack2:?}");
        // And each learned its partner's advertised endpoint (a real rendezvous pairing).
        assert!(ack1.contains("203.0.113.2:7002"), "m1 learns m2's endpoint: {ack1:?}");
        assert!(ack2.contains("203.0.113.1:7001"), "m2 learns m1's endpoint: {ack2:?}");

        driver.abort();
    }

    #[tokio::test]
    async fn broker_pairs_two_agents_and_swaps_endpoints() {
        // The end-to-end AF2d milestone: two agents present valid joins for the
        // SAME channel (one Initiate, one Accept); the edge pairs them and hands
        // each the OTHER's advertised endpoint so they can connect directly.
        let pk = operator_pubkey();
        let channel = [0xD1u8; 32];
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|p| (p.initiator_holder[0], p.acceptor_holder[0]))
                .map_err(|e| e.to_string())
        });

        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        // First pubkey byte identifies each holder in the returned pairing.
        let ia = holder_a.verifying_key().to_bytes()[0];
        let ib = holder_b.verifying_key().to_bytes()[0];
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7002".to_string(),
        };
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_a.encode(), &holder_a).await;
            conn.close(0u32.into(), b"done");
            String::from_utf8(ack).unwrap_or_default()
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_b.encode(), &holder_b).await;
            conn.close(0u32.into(), b"done");
            String::from_utf8(ack).unwrap_or_default()
        });

        let ack_a = a.await.expect("a");
        let ack_b = b.await.expect("b");
        let paired = server_task.await.expect("join").expect("paired");

        // Each agent learned the PEER's endpoint (independent of edge accept order).
        assert!(ack_a.contains("203.0.113.2:7002"), "agent A learns B's endpoint, got {ack_a:?}");
        assert!(ack_b.contains("203.0.113.1:7001"), "agent B learns A's endpoint, got {ack_b:?}");
        // The initiator is the Initiate-holder, the acceptor the Accept-holder.
        assert_eq!(paired, (ia, ib), "roles follow the grants' directions");
    }

    #[tokio::test]
    async fn finish_rendezvous_pair_completes_two_separately_admitted_members() {
        // #109-concurrent finish-pair (frozen): admission is now separable from
        // pair-completion. Admit two members with `accept_member`, THEN hand them to
        // `finish_rendezvous_pair` directly — the exact seam a `ChannelPairer`-driven
        // loop uses (`offer` -> `Paired(a, b)` -> spawn the finisher). The completion
        // must match the monolithic broker: each side learns the OTHER's endpoint and
        // roles follow the grants — proving the extraction is behaviour-preserving.
        // #517 V1 (Nachtrag): the offload figure is read as a PAIR of counters, so this
        // test also proves the rendezvous side is counted -- a successful pairing that the
        // edge steps out of must show up somewhere, or "0 splices" stays unreadable.
        // Measured as a delta, not an absolute: the counters are process-wide and other
        // tests in this binary run concurrently. That makes the bound one-sided on purpose
        // (>= 1), which is still discriminating -- without the increment it would be 0.
        let pairs_before = channel_rendezvous_pairs_total();
        let pk = operator_pubkey();
        let channel = [0xD5u8; 32];
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let authorize =
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
            let a = accept_member(&server, 500, &authorize).await.expect("admit a");
            let b = accept_member(&server, 500, &authorize).await.expect("admit b");
            finish_rendezvous_pair(a, b, 500)
                .await
                .map(|p| (p.initiator_holder[0], p.acceptor_holder[0]))
                .map_err(|e| e.to_string())
        });

        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        let ia = holder_a.verifying_key().to_bytes()[0];
        let ib = holder_b.verifying_key().to_bytes()[0];
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7051".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7052".to_string(),
        };
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_a.encode(), &holder_a).await;
            conn.close(0u32.into(), b"done");
            String::from_utf8(ack).unwrap_or_default()
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let ack = present_join(&conn, &req_b.encode(), &holder_b).await;
            conn.close(0u32.into(), b"done");
            String::from_utf8(ack).unwrap_or_default()
        });

        let ack_a = a.await.expect("a");
        let ack_b = b.await.expect("b");
        let paired = server_task.await.expect("join").expect("paired");

        assert!(ack_a.contains("203.0.113.2:7052"), "A learns B's endpoint via the finisher, got {ack_a:?}");
        assert!(ack_b.contains("203.0.113.1:7051"), "B learns A's endpoint via the finisher, got {ack_b:?}");
        assert_eq!(paired, (ia, ib), "the finisher decides roles from the grants, same as the monolithic broker");
        assert!(
            channel_rendezvous_pairs_total() > pairs_before,
            "a completed rendezvous pairing must be counted -- otherwise a fully offloaded \
             channel plane is indistinguishable from one that never ran (#517 V1)"
        );
    }

    #[tokio::test]
    async fn finish_rendezvous_pair_tags_the_side_on_a_mid_handoff_write_failure() {
        // #155 (frozen): the QUIC rendezvous completer — the one EVERY member (incl. relay-only NAT'd
        // ones) admits through before any relay fallback, i.e. source-2/sink's actual critical path —
        // now tags an ack I/O failure with its PairSide (RelayHandoffError) instead of the bare
        // "connection lost" that #148/#154 eliminated on the other two completers. Authorization
        // succeeds for both; B's connection is dropped before its ack, so the ack fails mid-handoff.
        let pk = operator_pubkey();
        let channel = [0xD6u8; 32];
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let cert_b = cert.clone();
        let holder_a = holder_sk(0xa3);
        let holder_b = holder_sk(0xb4);
        let req_a = ChannelJoinRequest {
            grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:7061".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
            endpoint: "203.0.113.2:7062".to_string(),
        };
        // Both clients connect + present their joins so admission succeeds; keep them alive so the
        // failure is purely the server-side connection drop below, not a client race.
        let a_cli = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let _ = present_join(&conn, &req_a.encode(), &holder_a).await;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            conn.close(0u32.into(), b"done");
        });
        let b_cli = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let _ = present_join(&conn, &req_b.encode(), &holder_b).await;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            conn.close(0u32.into(), b"done");
        });

        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let a = accept_member(&server, 500, &authorize).await.expect("admit a");
        let b = accept_member(&server, 500, &authorize).await.expect("admit b");
        // Deterministically break B's ack: close B's connection server-side before the finisher acks.
        b.conn.close(0u32.into(), b"member gone before ack");

        let err = finish_rendezvous_pair(a, b, 500)
            .await
            .expect_err("B's closed connection must fail its ack mid-handoff");
        let handoff = err
            .downcast_ref::<RelayHandoffError>()
            .expect("a typed RelayHandoffError, not a bare I/O error");
        assert_eq!(handoff.failed_side, PairSide::B, "the dead side (B) is identified");
        assert!(
            format!("{err}").contains("not an admission refusal"),
            "the rendezvous completer now disambiguates a handoff race from a refusal too"
        );
        let _ = a_cli.await;
        let _ = b_cli.await;
    }

    #[tokio::test]
    async fn finish_relay_pair_over_streams_splices_two_non_quinn_members() {
        // #106 relay-splice-generic (frozen): a `:443`/TLS-TCP member can't be dialed, so
        // rendezvous (direct endpoint exchange) is useless to it — it needs the RELAY.
        // Prove the transport-generic relay finisher works over NON-quinn streams: two
        // members admitted over plain in-memory duplexes are acked `OK` and their data
        // streams spliced end-to-end (the Noise_IK ciphertext would flow exactly this
        // way), with roles decided from the grants — the same completion the quinn
        // `finish_relay_pair` gives, but with no `quinn::Connection` anywhere.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pk = operator_pubkey();
        let channel = [0x77u8; 32];
        let holder_a = holder_sk(0xa1);
        let holder_b = holder_sk(0xb2);
        let ia = holder_a.verifying_key().to_bytes()[0];
        let ib = holder_b.verifying_key().to_bytes()[0];

        let (mut member_a, broker_a) = tokio::io::duplex(1024);
        let (mut member_b, broker_b) = tokio::io::duplex(1024);
        let a = AdmittedStreamMember {
            stream: broker_a,
            req: ChannelJoinRequest {
                grant: grant_h(channel, &holder_a, Direction::Initiate, 1_000),
                endpoint: "203.0.113.1:7051".to_string(),
            },
            operator: pk,
            noise: None,
            attest: None,
            observed: "203.0.113.9:9999".parse().unwrap(),
            session: SessionSource::SameStream,
            _permit: None,
        };
        let b = AdmittedStreamMember {
            stream: broker_b,
            req: ChannelJoinRequest {
                grant: grant_h(channel, &holder_b, Direction::Accept, 1_000),
                endpoint: "203.0.113.2:7052".to_string(),
            },
            operator: pk,
            noise: None,
            attest: None,
            observed: "203.0.113.9:9999".parse().unwrap(),
            session: SessionSource::SameStream,
            _permit: None,
        };

        let splice = tokio::spawn(async move {
            finish_relay_pair_over_streams(a, b, 500)
                .await
                .map(|p| (p.initiator_holder[0], p.acceptor_holder[0]))
                .map_err(|e| e.to_string())
        });

        // Each member reads its `OK <..>\n` ack line, then the relay carries bytes both ways.
        let ack_a = read_relay_ack_line(&mut member_a).await;
        assert!(ack_a.starts_with(b"OK"), "member A is acked OK over its plain stream, got {:?}", String::from_utf8_lossy(&ack_a));
        let ack_b = read_relay_ack_line(&mut member_b).await;
        assert!(ack_b.starts_with(b"OK"), "member B is acked OK over its plain stream, got {:?}", String::from_utf8_lossy(&ack_b));

        // A -> B through the edge splice (A keeps its stream open, like a Noise msg1).
        member_a.write_all(b"noise-msg1-from-a").await.expect("a writes");
        let mut on_b = [0u8; 17];
        member_b.read_exact(&mut on_b).await.expect("b reads a");
        assert_eq!(&on_b, b"noise-msg1-from-a", "A's ciphertext reaches B via the generic relay");

        // B -> A with the forward leg still open — the reply must not be starved.
        member_b.write_all(b"noise-msg2-from-b").await.expect("b writes");
        let mut on_a = [0u8; 17];
        member_a.read_exact(&mut on_a).await.expect("a reads b");
        assert_eq!(&on_a, b"noise-msg2-from-b", "B's reply reaches A via the generic relay");

        // Both close -> the splice tears down and returns the decided pairing (no hang).
        member_a.shutdown().await.expect("a shutdown");
        member_b.shutdown().await.expect("b shutdown");
        let paired = splice.await.expect("join").expect("paired");
        assert_eq!(paired, (ia, ib), "roles follow the grants, same as the quinn relay finisher");
    }

    #[tokio::test]
    async fn edge_refuses_a_non_member_holder() {
        // #81 gap 2: a holder that is NOT a current member is refused even with a
        // valid, signed, unexpired grant — this is what makes revocation work
        // (removing a member from the registry denies admission at the gate).
        let pk = operator_pubkey();
        let channel = [0xE1u8; 32];
        let member = [0x0au8; 32];
        let req = join_request(channel, 0x0b, "203.0.113.9:6100"); // holder 0x0b, not a member
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, h| async move {
                (c.0 == channel && h == member).then_some((pk, None, None))
            })
            .await
            .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder_sk(0x0b)).await;
        assert_ne!(ack, b"OK", "a non-member holder must be refused");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn edge_refuses_an_unsafe_endpoint() {
        // #81 gap 3: a loopback advertised endpoint (a dial-to-self SSRF target) is
        // refused before pairing, even for an authorized member with a valid grant.
        let pk = operator_pubkey();
        let channel = [0xE2u8; 32];
        let req = join_request(channel, 0x0c, "127.0.0.1:22"); // loopback -> unsafe
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder_sk(0x0c)).await;
        assert_ne!(ack, b"OK", "a loopback advertised endpoint must be refused");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn edge_requires_holder_possession_of_the_grant() {
        // #81 gap 1: a valid, signed, unexpired grant for a current member is still
        // bearer bytes until the presenter proves it holds the holder private key.
        // The genuine holder signs the edge challenge and is admitted; a thief who
        // replays the SAME ~139-byte grant but signs with a different key is refused.
        let pk = operator_pubkey();
        let channel = [0xF1u8; 32];
        let holder = holder_sk(0x33);
        let req = ChannelJoinRequest {
            grant: grant_h(channel, &holder, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6200".to_string(),
        };

        // (1) genuine holder proves possession -> admitted.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &holder).await;
        assert_eq!(ack, b"OK", "the genuine holder proves possession and is admitted");
        conn.close(0u32.into(), b"done");
        task.await.expect("join").expect("admitted");

        // (2) a thief replays the identical grant bytes but signs with another key.
        let thief = holder_sk(0x99);
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let task2 = tokio::spawn(async move {
            resolve_channel_join(&server2, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let ack2 = present_join(&conn2, &req.encode(), &thief).await;
        assert_eq!(
            ack2,
            encode_channel_refusal("possession"),
            "a stolen grant without holder possession is refused — and over the real QUIC \
             path the refusal carries the framed `possession` category (#524)",
        );
        let _ = task2.await;
    }

    #[tokio::test]
    async fn channel_authorizer_as_the_gate_closure_admits_a_member() {
        // #81 SEC81c-c c-iii-3a: the live wiring — the c-ii resolver (ChannelAuthorizer)
        // plugged in as the broker's async authorize closure, sourcing membership from a
        // (mock) control plane. A member is admitted; a non-member is refused. Proves the
        // c-ii resolver + c-iii-1 async gate compose before c-iii-3 mounts them in run_edge.
        use crate::channel_authorize::ChannelAuthorizer;
        use axum::routing::post;
        use axum::{Json, Router};
        use serde_json::Value;

        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let op = operator_pubkey();
        let channel = [0xE7u8; 32];
        let member = holder_sk(0x0a);
        let member_hex = hx(&member.verifying_key().to_bytes());
        let op_hex = hx(&op);
        let admin_hex = hx(&[0x7au8; 32]);

        // Mock CP c-i endpoint: operator key iff the right admin token + the known member.
        let app = Router::new().route(
            "/internal/channel/authorize",
            post(move |headers: axum::http::HeaderMap, Json(b): Json<Value>| {
                let (op_hex, member_hex, admin_hex) =
                    (op_hex.clone(), member_hex.clone(), admin_hex.clone());
                async move {
                    if headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok())
                        != Some(admin_hex.as_str())
                    {
                        return Err(axum::http::StatusCode::UNAUTHORIZED);
                    }
                    if b.get("holder").and_then(|v| v.as_str()) == Some(member_hex.as_str()) {
                        Ok(Json(serde_json::json!({ "operator_pubkey": op_hex })))
                    } else {
                        Err(axum::http::StatusCode::NOT_FOUND)
                    }
                }
            }),
        );
        let cp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cp_addr = cp.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(cp, app).await.unwrap() });
        let authorizer = ChannelAuthorizer::new(&format!("http://{cp_addr}"), &[0x7au8; 32]);

        // Broker on a QUIC endpoint, authorize sourced from the CP via the resolver.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let az = authorizer.clone();
        let server_task = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, h| {
                let a = az.clone();
                async move { a.resolve(&c, &h).await.map(|m| (m.operator_pubkey, m.noise_pubkey, m.noise_attestation)) }
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
        });

        let req = ChannelJoinRequest {
            grant: grant_h(channel, &member, Direction::Initiate, 1_000),
            endpoint: "203.0.113.9:6100".to_string(),
        };
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let ack = present_join(&conn, &req.encode(), &member).await;
        assert_eq!(ack, b"OK", "a member (per the mock CP) is admitted via ChannelAuthorizer");
        conn.close(0u32.into(), b"done");
        server_task.await.expect("join").expect("admitted");
    }

    // ---- #451: connection-cap permit accounting ----------------------------------------

    #[test]
    fn a_parked_members_permit_is_held_by_the_pairer_not_released_on_offer_451() {
        // The core structural claim #451's fix rests on: `WaitingMember<T>`'s payload T now
        // carries the cap permit (on `AdmittedMember`/`AdmittedStreamMember`), so parking a
        // member (`PairOutcome::Parked`) must NOT release its permit — the permit is only
        // dropped when the `WaitingMember` itself is dropped (matched, superseded, or swept).
        // Proven here against the pure, socket-free `ChannelPairer`/`WaitingMember` machinery
        // with a lightweight fake payload standing in for the real member types, independent
        // of QUIC/TLS — the fastest, most direct proof of the pattern the real fix relies on.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let p1 = std::sync::Arc::clone(&sem).try_acquire_owned().unwrap();
        struct FakeMember {
            _permit: OwnedSemaphorePermit,
        }
        let mut pairer = ChannelPairer::<FakeMember>::new();

        let outcome = pairer.offer(WaitingMember {
            channel: ChannelId([1u8; 32]),
            holder: [1u8; 32],
            observed: None,
            deadline: 100,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: FakeMember { _permit: p1 },
        });
        assert!(matches!(outcome, PairOutcome::Parked), "first offer parks");
        assert_eq!(
            sem.available_permits(),
            1,
            "the parked member's permit must still be held — `offer` returning must not release it"
        );

        // Swept past its deadline: the permit releases only once the returned WaitingMember
        // (and its payload) is actually dropped by the caller (mirroring `run_channel_broker_loop`
        // closing the connection then letting the value drop).
        let expired = pairer.drain_expired(101);
        assert_eq!(expired.len(), 1, "one lone waiter past its deadline");
        assert_eq!(sem.available_permits(), 1, "still held — drain_expired returns it, doesn't drop it");
        drop(expired);
        assert_eq!(sem.available_permits(), 2, "released once the swept member is actually torn down");
    }

    #[test]
    fn a_matched_members_permit_travels_into_paired_not_dropped_on_offer_451() {
        // The other structural claim: when a SECOND holder arrives and `offer` returns
        // `Paired(a, b)`, BOTH members' permits travel out inside the returned pair (not just
        // the second, freshly-offered one) — so a caller that hands `Paired(a, b)` to a
        // completer (e.g. `finish_relay_pair_over_streams`) is holding 2 permits for the 2
        // live sockets about to be relay-spliced, matching #451's "N pairs, 2N sockets, 2N
        // permits" requirement instead of the pre-fix "0 permits" for N pairs.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let p1 = std::sync::Arc::clone(&sem).try_acquire_owned().unwrap();
        let p2 = std::sync::Arc::clone(&sem).try_acquire_owned().unwrap();
        #[derive(Debug)]
        struct FakeMember {
            _permit: OwnedSemaphorePermit,
        }
        let mut pairer = ChannelPairer::<FakeMember>::new();
        let _ = pairer.offer(WaitingMember {
            channel: ChannelId([2u8; 32]),
            holder: [1u8; 32],
            observed: None,
            deadline: 100,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: FakeMember { _permit: p1 },
        });
        assert_eq!(sem.available_permits(), 0, "both permits are outstanding: 1 parked, 1 about to offer");

        let outcome = pairer.offer(WaitingMember {
            channel: ChannelId([2u8; 32]),
            holder: [2u8; 32],
            observed: None,
            deadline: 100,
            liveness: ParkLiveness::default(),
            phase: ParkPhase::Unmarked,
            payload: FakeMember { _permit: p2 },
        });
        let (a, b) = match outcome {
            PairOutcome::Paired(a, b) => (a, b),
            other => panic!("expected Paired, got {other:?}"),
        };
        assert_eq!(sem.available_permits(), 0, "both permits still held, now inside the Paired pair");
        drop(a);
        drop(b);
        assert_eq!(sem.available_permits(), 2, "both release once the pair (e.g. after its relay ends) is dropped");
    }

    #[tokio::test]
    async fn run_channel_broker_loop_holds_a_parked_members_permit_until_ttl_sweep_451() {
        // The real, end-to-end version of the two unit tests above: drive
        // `run_channel_broker_loop` over a real QUIC endpoint with a real `ConnectionCap`, park
        // ONE lone member (no partner ever arrives), and prove the cap's available-permit count
        // stays down by 1 the whole time it's parked — not just for the brief admission window —
        // then that it's returned once the periodic TTL sweep evicts it. Before the #451 fix the
        // permit released the instant the spawned admission task returned from `offer` (i.e.
        // almost immediately after connecting), so `cap.available()` would have already read 2
        // long before this test ever advances the clock.
        use std::sync::atomic::{AtomicU64, Ordering};

        let pk = operator_pubkey();
        let chan = [0x51u8; 32];
        let chan2 = [0x52u8; 32];
        let clock = std::sync::Arc::new(AtomicU64::new(100));
        let park_ttl = 5u64;
        let cap = crate::state::ConnectionCap::new(2);

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let clock_loop = clock.clone();
        let cap_loop = cap.clone();
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                move || clock_loop.load(Ordering::Relaxed),
                move |c: ChannelId, _h: [u8; 32]| async move {
                    (c.0 == chan || c.0 == chan2).then_some((pk, None, None))
                },
                park_ttl,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_rendezvous_pair,
                Some(cap_loop),
                crate::shutdown::ShutdownSignal::never(),
                std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new())),
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        assert_eq!(cap.available(), 2, "nothing admitted yet");

        // One lone member connects and parks — no partner ever shows up. Held open in scope
        // (not closed) so its socket genuinely stays live while parked, exactly the #451
        // scenario ("the member's TLS/WebSocket stream lives on inside the pairer... uncounted
        // against the cap").
        let client = build_client_endpoint(cert.clone()).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let req = ChannelJoinRequest {
            grant: grant_h(chan, &holder_sk(0xa1), Direction::Initiate, 1_000),
            endpoint: "203.0.113.1:9101".to_string(),
        };
        // Drive admission up through the possession signature only -- NOT `present_join`,
        // which then blocks on `read_to_end` waiting for the stream to finish/EOF. A parked
        // member is never ack'd (silence, same as `ws_channel.rs`'s "a lone member... parks"
        // test) until it's matched or TTL-swept, so `read_to_end` would block for however
        // long THAT takes, which is exactly the state transition this test drives from the
        // outside -- awaiting it here would deadlock the test against itself.
        present_join_no_ack(&conn, &req.encode(), &holder_sk(0xa1)).await;

        // Give the spawned admission task a moment to finish admitting + park in the pairer.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            cap.available(),
            1,
            "the parked member's permit must still be held while its connection is live and \
             uncounted-for in the pairer — the #451 gap"
        );

        // Jump the clock well past the park TTL, then wake the accept loop (which samples
        // `now` and sweeps `drain_expired` at the TOP of every iteration) with a throwaway
        // second connection on an unrelated channel.
        clock.store(1_000, Ordering::Relaxed);
        let client2 = build_client_endpoint(cert).expect("client 2");
        let conn2 = client2.connect(addr, "localhost").expect("cfg").await.expect("conn2");
        // A different channel so it parks too, rather than pairing with the first (which would
        // otherwise also release its permit via the Paired path, muddying the TTL assertion).
        let req2 = ChannelJoinRequest {
            grant: grant_h([0x52u8; 32], &holder_sk(0xb2), Direction::Initiate, 10_000),
            endpoint: "203.0.113.2:9102".to_string(),
        };
        present_join_no_ack(&conn2, &req2.encode(), &holder_sk(0xb2)).await;
        // Let this second admission complete AND the loop's next iteration (which samples the
        // now-jumped clock and sweeps) run.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        assert_eq!(
            cap.available(),
            1,
            "the first (TTL-swept) member's permit was released; the second (still-parked, not \
             yet expired under its OWN fresh deadline) member's permit is still held"
        );

        drop(conn);
        drop(conn2);
        driver.abort();
    }

    #[tokio::test]
    async fn run_channel_broker_loop_stops_accepting_promptly_once_shutdown_is_triggered_400() {
        // #400 property (a), for the QUIC channel-broker accept loop specifically (it does
        // NOT go through `crate::transport::serve_listener` -- `endpoint.accept()` has a
        // different shape than `TcpListener::accept()`, per #452's own doc comment -- so its
        // shutdown wiring is separately proven here rather than inherited from
        // `transport.rs`'s test). Once triggered, the loop must stop calling
        // `endpoint.accept()` and return promptly -- proven by the driving task joining
        // within a bounded time -- without touching a member ALREADY admitted and parked
        // (that member's permit stays held; force-closing it is `run_edge`'s
        // `wait_for_drain` job, not this loop's, exactly as its own doc comment says).
        let pk = operator_pubkey();
        let chan = [0x53u8; 32];
        let cap = crate::state::ConnectionCap::new(2);

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let (ctl, shutdown) = crate::shutdown::ShutdownController::new();
        let cap_loop = cap.clone();
        // #400: the pairer is constructed HERE, outside the spawned driver task, and this
        // test keeps its own clone (`pairer`) alive in its own scope for the whole test --
        // exactly mirroring the real fix in `run_edge` (which keeps its own clone alive for
        // the whole bounded drain window). Without this, `run_channel_broker_loop` itself
        // would own the only reference and drop it (force-closing the parked member) the
        // instant it returns on shutdown, which is the real bug this test exists to catch.
        let pairer = std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new()));
        let pairer_loop = pairer.clone();
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == chan).then_some((pk, None, None)) },
                10_000,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_rendezvous_pair,
                Some(cap_loop),
                shutdown,
                pairer_loop,
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        // A member connects and parks BEFORE shutdown -- admitted normally.
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let req = ChannelJoinRequest {
            grant: grant_h(chan, &holder_sk(0xc1), Direction::Initiate, 1_000),
            endpoint: "203.0.113.3:9103".to_string(),
        };
        present_join_no_ack(&conn, &req.encode(), &holder_sk(0xc1)).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(cap.available(), 1, "the member admitted before shutdown holds its permit");

        ctl.trigger();
        tokio::time::timeout(std::time::Duration::from_millis(500), driver)
            .await
            .expect("run_channel_broker_loop returns promptly once shutdown is triggered")
            .expect("task joined without panicking");

        // The already-parked member from before shutdown is untouched by the loop's own
        // return -- its permit is still held (force-closing it is `wait_for_drain`'s job,
        // exercised separately in `shutdown.rs`'s tests).
        assert_eq!(cap.available(), 1, "shutdown does not itself force-close an already-parked member");
        drop(conn);
    }

    #[tokio::test]
    async fn run_channel_broker_loop_holds_two_permits_for_a_matched_relay_pair_451() {
        // The relay-side companion to the park test: two members of the SAME channel connect,
        // pair, and their relay is spliced on a freshly spawned `complete(..)` task. Before the
        // #451 fix that spawned task held NO permit (both callers' own permits had already
        // dropped when their `offer`-calling tasks returned) — "N concurrent relayed pairs hold
        // 2N live sockets against 0 counted permits". Prove the fixed behaviour: while the pair
        // is actively relaying (held open by both ends), the cap shows exactly 2 permits in use.
        let pk = operator_pubkey();
        let chan = [0x61u8; 32];
        let cap = crate::state::ConnectionCap::new(2);

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let cap_loop = cap.clone();
        let driver = tokio::spawn(async move {
            run_channel_broker_loop(
                &server,
                || 500u64,
                move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == chan).then_some((pk, None, None)) },
                10_000,
                ParkPhase::Unmarked, // 2a: neutral in tests
                finish_relay_pair,
                Some(cap_loop),
                crate::shutdown::ShutdownSignal::never(),
                std::sync::Arc::new(std::sync::Mutex::new(ChannelPairer::new())),
                std::sync::Arc::new(crate::state::JoinRefusalPenalty::new()),
                std::sync::Arc::new(crate::state::BrokerHeartbeat::new()),
                None, // #603: step 6 wires the real store
            )
            .await;
        });

        assert_eq!(cap.available(), 2);

        // Both members connect and hold their relay open (never send their post-pairing byte)
        // until released, so the splice stays live while we sample the cap.
        let (rel1_tx, rel1_rx) = tokio::sync::oneshot::channel::<()>();
        let (rel2_tx, rel2_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(2);
        let m1 = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan, holder_sk(0xc1), Direction::Initiate, 0x01,
            Some(ready_tx.clone()), Some(rel1_rx),
        ));
        let m2 = tokio::spawn(run_relay_member(
            cert.clone(), addr, chan, holder_sk(0xd2), Direction::Accept, 0x02,
            Some(ready_tx.clone()), Some(rel2_rx),
        ));
        drop(ready_tx);
        ready_rx.recv().await.expect("member 1 relaying");
        ready_rx.recv().await.expect("member 2 relaying");

        assert_eq!(
            cap.available(),
            0,
            "both live sockets of the matched, actively-relaying pair are counted against the \
             cap — not 0, per #451"
        );

        let _ = rel1_tx.send(());
        let _ = rel2_tx.send(());
        let _ = m1.await;
        let _ = m2.await;

        // Give the completer's task a moment to actually return (releasing both permits) after
        // the relay ends.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(cap.available(), 2, "both permits release once the relay (and the pair) end");

        driver.abort();
    }

    #[tokio::test]
    async fn admit_and_pair_on_stream_holds_the_permit_while_parked_and_moves_both_into_a_pair_451() {
        // The stream-generic (front-door / ws-channel) sibling of the QUIC-native tests above:
        // `admit_and_pair_on_stream` is the shared core both `serve.rs`'s `:443` ChannelBroker
        // arm and `ws_channel.rs` drive. Proves the same two properties directly against it: a
        // parked member's permit is NOT released when the function returns `Ok(None)`, and a
        // matched pair's `Ok(Some((a, b)))` carries BOTH permits.
        use std::sync::Mutex;
        let pk = operator_pubkey();
        let channel = [0x71u8; 32];
        let src = holder_sk(0xe1);
        let snk = holder_sk(0xf2);
        let req_src = ChannelJoinRequest {
            grant: grant_h(channel, &src, Direction::Initiate, 1_000),
            endpoint: "relay-only".to_string(),
        };
        let req_snk = ChannelJoinRequest {
            grant: grant_h(channel, &snk, Direction::Accept, 1_000),
            endpoint: "relay-only".to_string(),
        };

        let (c1, s1) = tokio::io::duplex(4096);
        let (c2, s2) = tokio::io::duplex(4096);

        let src_task = tokio::spawn(async move {
            let mut c = c1;
            let rb = req_src.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&src.sign(&ch).to_bytes()).await.expect("sig");
            let _ = read_relay_ack_line(&mut c).await;
        });
        let snk_task = tokio::spawn(async move {
            let mut c = c2;
            let rb = req_snk.encode();
            c.write_all(&(rb.len() as u16).to_be_bytes()).await.expect("len");
            c.write_all(&rb).await.expect("req");
            let mut ch = [0u8; 32];
            c.read_exact(&mut ch).await.expect("challenge");
            c.write_all(&snk.sign(&ch).to_bytes()).await.expect("sig");
            let _ = read_relay_ack_line(&mut c).await;
        });

        let pairer: Mutex<ChannelPairer<AdmittedStreamMember<tokio::io::DuplexStream>>> =
            Mutex::new(ChannelPairer::new());
        let authorize = move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
        let obs1: std::net::SocketAddr = "203.0.113.1:8001".parse().unwrap();
        let obs2: std::net::SocketAddr = "203.0.113.2:8002".parse().unwrap();

        let cap = crate::state::ConnectionCap::new(2);
        let permit1 = cap.try_admit().expect("permit 1");
        let r1 = admit_and_pair_on_stream(
            s1, obs1, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, Some(permit1),
        )
        .await
        .expect("admit 1");
        assert!(r1.is_none(), "first holder parks");
        assert_eq!(cap.available(), 1, "the parked member's permit must still be held, not dropped on return");

        let permit2 = cap.try_admit().expect("permit 2");
        let r2 = admit_and_pair_on_stream(
            s2, obs2, 500, std::time::Duration::from_secs(5), &authorize, 10_000, &pairer, Some(permit2),
        )
        .await
        .expect("admit 2");
        assert_eq!(cap.available(), 0, "both permits outstanding: one just acquired, one still parked");
        let (a, b) = r2.expect("second holder pairs with the parked first");

        // Both permits travelled into the pair (not dropped by either `offer` call).
        drop(a);
        drop(b);
        assert_eq!(cap.available(), 2, "both permits release once the paired members are dropped");

        drop(src_task);
        drop(snk_task);
    }
    #[test]
    fn classify_endpoint_separates_corroborated_dual_stack_and_uncorroborated_546() {
        use std::net::IpAddr;
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::7".parse().unwrap();

        // Corroborated: the advertised IP is the one the edge saw. The port may differ --
        // a member advertises its listener, not the ephemeral source port of this join.
        assert_eq!(classify_endpoint("203.0.113.7:9000", v4), EndpointAttestation::Matches);

        // Dual-stack is NOT a mismatch. A member reaching the edge over v4 while offering
        // its v6 listener is ordinary; conflating it with the uncorroborated case would
        // make the interesting counter useless the moment IPv6 is in play.
        assert_eq!(classify_endpoint("[2001:db8::7]:9000", v4), EndpointAttestation::CrossFamily);
        assert_eq!(classify_endpoint("203.0.113.7:9000", v6), EndpointAttestation::CrossFamily);

        // Same family, different address: nothing corroborates this. THIS is the case that
        // lets an admitted member point its partner at an arbitrary public host --
        // is_global_unicast only rules out internal targets.
        assert_eq!(classify_endpoint("198.51.100.9:443", v4), EndpointAttestation::Mismatch);
        assert_eq!(classify_endpoint("[2001:db8::99]:443", v6), EndpointAttestation::Mismatch);
        // The same advertised address observed from behind a NAT is a DIFFERENT outcome --
        // this is the split that lets `mismatch` be read as "enforcement would refuse this".
        assert_eq!(
            classify_endpoint("198.51.100.9:443", "10.0.0.5".parse::<IpAddr>().unwrap()),
            EndpointAttestation::Unobservable
        );

        // The relay-only sentinel is not an address and must not land in any of the three
        // address buckets -- otherwise every NAT'd member would be counted as something.
        assert_eq!(
            classify_endpoint(ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY, v4),
            EndpointAttestation::NoAddress
        );
        assert_eq!(classify_endpoint("not-an-address", v4), EndpointAttestation::NoAddress);
    }

    #[test]
    fn endpoint_is_attested_only_judges_when_the_observed_address_says_something_546() {
        use std::net::IpAddr;
        let global: IpAddr = "203.0.113.7".parse().unwrap();
        let behind_nat: IpAddr = "172.18.0.1".parse().unwrap();

        // Observed on a private address -- co-located or behind a NAT. The observed value
        // carries no information about the member's public identity, so there is nothing to
        // corroborate against and NOTHING may be refused on this basis. This is not a
        // concession: the first field reading was 4 mismatches / 0 matches, every one of
        // them exactly this shape, and the naive rule would have refused all of them.
        assert!(endpoint_is_attested("57.131.133.91:5333", behind_nat));
        assert!(endpoint_is_attested("198.51.100.9:443", behind_nat));
        // ...and it lands in its OWN bucket, not in the one enforcement reads.
        assert_eq!(
            classify_endpoint("198.51.100.9:443", behind_nat),
            EndpointAttestation::Unobservable,
            "a privately-observed member must never inflate the actionable counter"
        );

        // Observed on a global address: an advertised address of the same family must be it.
        assert!(endpoint_is_attested("203.0.113.7:9000", global), "same address, other port");
        assert!(
            !endpoint_is_attested("198.51.100.9:443", global),
            "a third party's address is exactly what this closes"
        );

        // Dual-stack stays allowed -- reaching the edge over v4 while advertising the v6
        // listener is ordinary, and refusing it would break real members for no gain.
        assert!(endpoint_is_attested("[2001:db8::7]:9000", global));
        let global_v6: IpAddr = "2001:db8::7".parse().unwrap();
        assert!(endpoint_is_attested("203.0.113.7:9000", global_v6));
        assert!(!endpoint_is_attested("[2001:db8::99]:443", global_v6), "same family, other host");
    }

    #[test]
    fn attested_endpoint_enforcement_is_off_unless_explicitly_enabled_546() {
        // The flag is read from the process environment, so this asserts the DEFAULT that
        // ships: absent means off. A guard that silently switched itself on would be a wire
        // behaviour change nobody chose -- the same count-then-enforce discipline as #540.
        assert!(
            !require_attested_endpoint(),
            "enforcement must stay off until an operator sets CT_EDGE_REQUIRE_ATTESTED_ENDPOINT=1"
        );
    }

    /// #552: the startup line must state the setting in BOTH directions, and must report
    /// what was actually PARSED rather than echo what was written.
    #[test]
    fn attested_endpoint_startup_line_speaks_when_off_too_551() {
        let armed = attested_endpoint_startup_line_for(Some("1"));
        assert!(armed.contains("ENFORCED"), "armed must say so: {armed}");

        // The case this exists for: a redeploy loses the `.env` line. Silence here would be
        // indistinguishable from an armed edge, so "off" has to be an affirmative statement.
        let unset = attested_endpoint_startup_line_for(None);
        assert!(
            unset.contains("OFF") && unset.contains("counted, not refused"),
            "unset must state plainly that nothing is being refused: {unset}"
        );

        // And the trap: only the literal "1" arms it. An operator who wrote a word that
        // reads as true has enforcement OFF while their config file looks armed -- so the
        // line must name the offending value instead of just saying "off".
        for near_miss in ["true", "yes", "on", "TRUE", " 1", "1 "] {
            let line = attested_endpoint_startup_line_for(Some(near_miss));
            assert!(
                line.contains("OFF"),
                "{near_miss:?} does not arm enforcement, so the line must say OFF: {line}"
            );
            assert!(
                line.contains(&format!("{near_miss:?}")),
                "the line must quote back the value that failed to arm it: {line}"
            );
        }
    }


    /// Phase-2 PR3 (CADS-Tunnel/ct-agent consolidation): **real edge vs SHARED client**
    /// contract tests. ct-agent's own `channel.rs` tests drove its client half against a
    /// pinned `ct_edge` dev-dependency (`present_channel_join_completes_the_possession_
    /// handshake`, `two_agent_clients_learn_each_others_endpoint`, `rendezvous_relays_each_
    /// peers_attested_noise_key`, `member_learns_its_edge_observed_reflexive_over_quic`,
    /// ct-agent `native/src/channel.rs:1603-1917` @ v0.7.23) — a cross-repo, tag-lagged
    /// gate. Now that the client half lives in `ct_common::channel_wire` / `channel_quic`
    /// (PR2, verbatim port), the same intents run HERE, in the dependency direction that
    /// already exists (`ct-edge → ct-common`), against this module's own admission and
    /// pairing entry points: every edge-side change to the ack line, the refusal frame, the
    /// possession exchange or the QUIC close reasons is checked against the real shared
    /// client in this workspace's CI, before any tag reaches ct-agent. Hermetic (loopback
    /// and in-memory duplexes only); every await is bounded by [`BOUND`].
    mod wire_contract_p2 {
        use super::*;
        use ct_common::channel::{member_noise_attest_bytes, verify_member_noise_attestation};
        use ct_common::channel_quic::{open_channel_streams, present_channel_join_quic};
        use ct_common::channel_wire::io::{
            present_channel_join_on_stream, present_channel_relay_join_on_stream, ADMISSION_EXCHANGE_TIMEOUT,
        };
        use ct_common::channel_wire::test_support::{operator, signed_grant};
        use ct_common::channel_wire::{ChannelJoinOutcome, PHASE_MARKER_RELAY, PHASE_MARKER_RENDEZVOUS};
        use rustls::pki_types::CertificateDer;
        use std::net::SocketAddr;

        /// Every await in these tests is bounded by this — a hung contract fails, never wedges CI.
        const BOUND: std::time::Duration = std::time::Duration::from_secs(5);

        async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
            tokio::time::timeout(BOUND, f)
                .await
                .unwrap_or_else(|_| panic!("{what}: exceeded the {BOUND:?} test bound"))
        }

        /// The fixture operator's public key: ct-common's `test_support::signed_grant` signs
        /// under it, so the edge-side `authorize` resolves to exactly this key.
        fn op_pub() -> [u8; 32] {
            operator().verifying_key().to_bytes()
        }

        fn request(channel: [u8; 32], holder: &SigningKey, dir: Direction, endpoint: &str) -> ChannelJoinRequest {
            ChannelJoinRequest { grant: signed_grant(channel, holder, dir), endpoint: endpoint.to_string() }
        }

        /// Dial the edge over QUIC from a fresh loopback client endpoint and run the SHARED
        /// QUIC join (`channel_quic::present_channel_join_quic`) on it. Returns the outcome,
        /// the client's own bound source address (what the edge must report as `r=`), and
        /// the still-open connection for tests that continue on it.
        async fn join_quic(
            cert: CertificateDer<'static>,
            addr: SocketAddr,
            req: &ChannelJoinRequest,
            holder: &SigningKey,
            marker: Option<u8>,
        ) -> (ChannelJoinOutcome, SocketAddr, quinn::Connection) {
            let client = build_client_endpoint(cert).expect("client endpoint");
            let source = client.local_addr().expect("client local addr");
            let conn = within("connect", client.connect(addr, "localhost").expect("cfg")).await.expect("conn");
            let outcome = within("join", present_channel_join_quic(&conn, req, holder, marker))
                .await
                .expect("the shared QUIC join drives to an outcome");
            (outcome, source, conn)
        }

        #[tokio::test]
        async fn shared_client_proves_possession_to_the_real_edge_admission_over_a_duplex_p2() {
            // ct-agent#72 AF4 + CADS-Tunnel#524 (from ct-agent's `present_channel_join_completes_
            // the_possession_handshake`): the shared client's framed request, possession
            // signature and ack reader against `admit_channel_join_on_duplex`, the `:443`
            // front door's admission core. A genuine holder is admitted (the edge decodes the
            // very request the client framed); a holder signing with the wrong key is refused
            // with the edge's OWN framed `possession` category — the real-edge proof that the
            // token the client parses is the one this module writes (ct-agent#129: an explicit
            // refusal is `Refused`, never an error).
            let channel = [0xA0u8; 32];
            let holder = holder_sk(0x11);
            let req = request(channel, &holder, Direction::Initiate, "203.0.113.7:9000");
            let pk = op_pub();
            let authorize = move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
            let observed: SocketAddr = "198.51.100.7:4477".parse().unwrap();

            // (1) Genuine holder → Admitted; a lone admission acks a bare `OK` and closes
            // (the `resolve_channel_join` shape).
            let (client_end, edge_end) = tokio::io::duplex(4096);
            let edge = tokio::spawn(async move {
                let (mut stream, seen_req, op, noise, attest, seen) =
                    admit_channel_join_on_duplex(edge_end, observed, 500, BOUND, &authorize)
                        .await
                        .expect("the real edge admits the shared client's join");
                stream.write_all(b"OK").await.expect("ack");
                stream.shutdown().await.expect("close");
                (seen_req, op, noise, attest, seen)
            });
            let (cr, cw) = tokio::io::split(client_end);
            let outcome = within(
                "join",
                present_channel_join_on_stream(cw, cr, &req, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false),
            )
            .await
            .expect("join drives");
            let (seen_req, op, noise, attest, seen) = within("edge", edge).await.expect("edge task");
            assert_eq!(
                outcome,
                ChannelJoinOutcome::Admitted {
                    peer_endpoint: String::new(),
                    peer_noise_pubkey: None,
                    peer_holder: None,
                    peer_attestation: None,
                    observed_reflexive: None,
                },
                "the genuine holder proves possession and is admitted"
            );
            assert_eq!(seen_req, req, "the edge decoded exactly the request the shared client framed");
            assert_eq!((op, noise, attest, seen), (pk, None, None, observed));

            // (2) Wrong possession key → the edge's framed `possession` refusal, classified
            // as definitive on the edge and as `Refused { Some("possession") }` by the client.
            let thief = holder_sk(0x99);
            let (client_end, edge_end) = tokio::io::duplex(4096);
            let edge = tokio::spawn(async move {
                admit_channel_join_on_duplex(edge_end, observed, 500, BOUND, &authorize).await.map(|_| ())
            });
            let (cr, cw) = tokio::io::split(client_end);
            let outcome = within(
                "refused join",
                present_channel_join_on_stream(cw, cr, &req, &thief, ADMISSION_EXCHANGE_TIMEOUT, false, None, false),
            )
            .await
            .expect("an explicit refusal is a clean outcome, not an error (#129)");
            let err = within("edge", edge).await.expect("edge task").expect_err("the edge refuses the thief");
            assert!(is_definitive_join_refusal(&err), "a failed possession proof is definitive on the edge: {err}");
            assert_eq!(
                outcome,
                ChannelJoinOutcome::Refused { category: Some("possession".to_string()) },
                "the client surfaces the edge's own category token (#524)"
            );
        }

        #[tokio::test]
        async fn shared_client_learns_peer_endpoint_and_own_reflexive_from_the_edge_rendezvous_p2() {
            // ct-agent#72 AF4 + #121 B1 + CADS-Tunnel#495 U2 (from ct-agent's `two_agent_clients_
            // learn_each_others_endpoint` / `member_learns_its_edge_observed_reflexive_over_quic`):
            // two shared QUIC clients join the same channel; `broker_channel_rendezvous` pairs
            // them and each parses the PEER's advertised endpoint and its OWN edge-observed
            // reflexive (`r=`, exactly the loopback source it dialed from) out of the ack. B
            // sends the `[0xFF, 0x01]` rendezvous preamble and A none: the edge's marker
            // toleration (#495 U2 b') and the unmarked legacy wire are both proven against
            // the real admission.
            let channel = [0xB0u8; 32];
            let holder_a = holder_sk(0x21);
            let holder_b = holder_sk(0x22);
            let req_a = request(channel, &holder_a, Direction::Initiate, "203.0.113.1:7001");
            let req_b = request(channel, &holder_b, Direction::Accept, "203.0.113.2:7002");
            let pk = op_pub();

            let (server, cert) = build_server_endpoint_with_cert().expect("server");
            let addr = server.local_addr().expect("addr");
            let srv = tokio::spawn(async move {
                broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                    .await
                    .map(|_| ())
            });
            let cert_b = cert.clone();
            let a = tokio::spawn(async move {
                let (out, source, conn) = join_quic(cert, addr, &req_a, &holder_a, None).await;
                conn.close(0u32.into(), b"done");
                (out, source)
            });
            let b = tokio::spawn(async move {
                let (out, source, conn) = join_quic(cert_b, addr, &req_b, &holder_b, Some(PHASE_MARKER_RENDEZVOUS)).await;
                conn.close(0u32.into(), b"done");
                (out, source)
            });
            let (out_a, src_a) = within("a", a).await.expect("a");
            let (out_b, src_b) = within("b", b).await.expect("b");
            within("broker", srv).await.expect("broker task").expect("the edge paired the two members");

            for (out, src, peer_ep, who) in [(out_a, src_a, "203.0.113.2:7002", "A"), (out_b, src_b, "203.0.113.1:7001", "B")] {
                match out {
                    ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive } => {
                        assert_eq!(peer_endpoint, peer_ep, "{who} learns the peer's advertised endpoint");
                        assert_eq!((peer_noise_pubkey, peer_holder, peer_attestation), (None, None, None), "no registry keys -> no triple, not a parse artifact");
                        assert_eq!(observed_reflexive, Some(src), "{who} learns exactly the reflexive the edge observed (#121 B1)");
                    }
                    other => panic!("{who}: expected Admitted, got {other:?}"),
                }
            }
        }

        #[tokio::test]
        async fn shared_client_receives_and_verifies_the_peers_attested_noise_key_from_the_edge_p2() {
            // ct-agent#101/#100 + CADS-Tunnel#122 + ct-agent#28 (from ct-agent's `rendezvous_relays_
            // each_peers_attested_noise_key`): when the registry holds each member's Noise key +
            // holder-signed attestation, the edge's ack carries the PEER's `<noise> <holder>
            // <attest>` triple followed by the `r=`/`sp=` tags. The shared client's grammar-true
            // parser (#28) recovers the triple intact next to the tags, and the attestation
            // verifies under the peer's grant-authenticated holder — the exact pre-pin check a
            // ct-agent initiator performs before trusting the key.
            let channel = [0xC0u8; 32];
            let holder_a = holder_sk(0x31);
            let holder_b = holder_sk(0x32);
            let hkey_a = holder_a.verifying_key().to_bytes();
            let hkey_b = holder_b.verifying_key().to_bytes();
            let noise_a = [0xAAu8; 32];
            let noise_b = [0xBBu8; 32];
            let attest_a = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &hkey_a, &noise_a)).to_bytes();
            let attest_b = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hkey_b, &noise_b)).to_bytes();
            let req_a = request(channel, &holder_a, Direction::Initiate, "203.0.113.1:7001");
            let req_b = request(channel, &holder_b, Direction::Accept, "203.0.113.2:7002");
            let pk = op_pub();

            let (server, cert) = build_server_endpoint_with_cert().expect("server");
            let addr = server.local_addr().expect("addr");
            let srv = tokio::spawn(async move {
                broker_channel_rendezvous(&server, 500, move |c, h| async move {
                    let (noise, attest) = if h == hkey_a { (noise_a, attest_a) } else { (noise_b, attest_b) };
                    (c.0 == channel).then_some((pk, Some(noise), Some(attest)))
                })
                .await
                .map(|_| ())
            });
            let cert_b = cert.clone();
            let a = tokio::spawn(async move {
                let (out, _, conn) = join_quic(cert, addr, &req_a, &holder_a, None).await;
                conn.close(0u32.into(), b"done");
                out
            });
            let b = tokio::spawn(async move {
                let (out, _, conn) = join_quic(cert_b, addr, &req_b, &holder_b, None).await;
                conn.close(0u32.into(), b"done");
                out
            });
            let out_a = within("a", a).await.expect("a");
            let out_b = within("b", b).await.expect("b");
            within("broker", srv).await.expect("broker task").expect("paired");

            for (out, peer_ep, pn, ph, pa, who) in [
                (out_a, "203.0.113.2:7002", noise_b, hkey_b, attest_b, "A"),
                (out_b, "203.0.113.1:7001", noise_a, hkey_a, attest_a, "B"),
            ] {
                match out {
                    ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive } => {
                        assert_eq!(peer_endpoint, peer_ep, "{who}: positional endpoint unaffected by the tags (#28)");
                        assert_eq!((peer_noise_pubkey, peer_holder, peer_attestation), (Some(pn), Some(ph), Some(pa)), "{who} learns the peer's attested triple (#101/#122)");
                        assert!(
                            verify_member_noise_attestation(&ChannelId(channel), &ph, &pn, &pa),
                            "{who}: the relayed attestation verifies under the peer's grant holder (#101)"
                        );
                        assert!(observed_reflexive.is_some_and(|r| r.ip().is_loopback()), "{who}: `r=` still parsed next to the triple");
                    }
                    other => panic!("{who}: expected Admitted, got {other:?}"),
                }
            }
        }

        #[tokio::test]
        async fn shared_client_joins_the_edge_relay_and_carries_bytes_over_open_channel_streams_p2() {
            // ct-agent#72 AF4-relay + ct-agent#139 + CADS-Tunnel#495 U2 (a') (the shared-client
            // form of this module's `broker_channel_relay_splices_two_members_tunnels`): both
            // members join the RELAY endpoint with the relay phase preamble via the shared QUIC
            // join, each learns the other's endpoint from the ack, then the shared bounded
            // stream setup (`open_channel_streams`: initiator opens, acceptor accepts the
            // edge-opened stream) carries bytes both ways THROUGH the edge splice.
            let channel = [0xE0u8; 32];
            let holder_a = holder_sk(0xa1);
            let holder_b = holder_sk(0xb2);
            let req_a = request(channel, &holder_a, Direction::Initiate, "203.0.113.1:7001");
            let req_b = request(channel, &holder_b, Direction::Accept, "203.0.113.2:7002");
            let pk = op_pub();

            let (server, cert) = build_server_endpoint_with_cert().expect("server");
            let addr = server.local_addr().expect("addr");
            let relay = tokio::spawn(async move {
                broker_channel_relay(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                    .await
                    .map(|_| ())
            });
            let cert_b = cert.clone();
            let a = tokio::spawn(async move {
                let (out, _, conn) = join_quic(cert, addr, &req_a, &holder_a, Some(PHASE_MARKER_RELAY)).await;
                assert!(matches!(&out, ChannelJoinOutcome::Admitted { peer_endpoint, .. } if peer_endpoint == "203.0.113.2:7002"), "A admitted with B's endpoint, got {out:?}");
                let (mut s, mut r) = within("a streams", open_channel_streams(&conn, true, BOUND)).await.expect("initiator opens");
                s.write_all(b"tunnel A->B via edge").await.expect("a write");
                let mut got = vec![0u8; 20];
                within("a read", r.read_exact(&mut got)).await.expect("a read");
                conn.close(0u32.into(), b"done");
                got
            });
            let b = tokio::spawn(async move {
                let (out, _, conn) = join_quic(cert_b, addr, &req_b, &holder_b, Some(PHASE_MARKER_RELAY)).await;
                assert!(matches!(&out, ChannelJoinOutcome::Admitted { peer_endpoint, .. } if peer_endpoint == "203.0.113.1:7001"), "B admitted with A's endpoint, got {out:?}");
                let (mut s, mut r) = within("b streams", open_channel_streams(&conn, false, BOUND)).await.expect("acceptor accepts");
                let mut got = vec![0u8; 20];
                within("b read", r.read_exact(&mut got)).await.expect("b read");
                s.write_all(b"tunnel B->A via edge").await.expect("b write");
                let _ = s.finish();
                within("b closed", conn.closed()).await;
                got
            });
            let got_a = within("a", a).await.expect("a");
            let got_b = within("b", b).await.expect("b");
            let _ = within("relay", relay).await;
            assert_eq!(&got_a, b"tunnel B->A via edge", "A receives B's bytes through the edge relay");
            assert_eq!(&got_b, b"tunnel A->B via edge", "B receives A's bytes through the edge relay");
        }

        #[tokio::test]
        async fn shared_relay_leg_client_reads_the_rich_ack_then_the_session_on_the_same_stream_p2() {
            // CADS-Tunnel#106/#122 + ct-agent#148 + #495-U1: the `:443` SAME-stream contract.
            // Two members are admitted over duplexes by `admit_channel_join_on_duplex` and
            // relay-spliced by `finish_relay_pair_over_streams`, which acks each the RICH
            // `OK <peer> <noise> <holder> <attest> r=<own> sp=<0|1>\n` line and then splices.
            // The shared relay-leg client (`present_channel_relay_join_on_stream`) must read
            // the ack up to its `\n` and not one byte further: the very next bytes on the same
            // stream are the peer's session, and both directions must arrive intact.
            let channel = [0xD0u8; 32];
            let holder_a = holder_sk(0x41);
            let holder_b = holder_sk(0x42);
            let hkey_a = holder_a.verifying_key().to_bytes();
            let hkey_b = holder_b.verifying_key().to_bytes();
            let noise_a = [0xA1u8; 32];
            let noise_b = [0xB1u8; 32];
            let attest_a = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &hkey_a, &noise_a)).to_bytes();
            let attest_b = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hkey_b, &noise_b)).to_bytes();
            let req_a = request(channel, &holder_a, Direction::Initiate, "203.0.113.1:7001");
            let req_b = request(channel, &holder_b, Direction::Accept, "203.0.113.2:7002");
            let pk = op_pub();
            let authorize = move |c: ChannelId, h: [u8; 32]| async move {
                let (noise, attest) = if h == hkey_a { (noise_a, attest_a) } else { (noise_b, attest_b) };
                (c.0 == channel).then_some((pk, Some(noise), Some(attest)))
            };
            // Distinct observed IPs: `sp=0`, and each side must get ITS OWN back as `r=`.
            let obs_a: SocketAddr = "198.51.100.1:8001".parse().unwrap();
            let obs_b: SocketAddr = "198.51.100.2:8002".parse().unwrap();

            let (client_a, edge_a) = tokio::io::duplex(4096);
            let (client_b, edge_b) = tokio::io::duplex(4096);
            let edge = tokio::spawn(async move {
                let mut members = Vec::new();
                for (stream, observed) in [(edge_a, obs_a), (edge_b, obs_b)] {
                    let (stream, req, operator, noise, attest, observed) =
                        admit_channel_join_on_duplex(stream, observed, 500, BOUND, &authorize)
                            .await
                            .expect("the real edge admits the shared relay-leg client");
                    members.push(AdmittedStreamMember { stream, req, operator, noise, attest, observed, session: SessionSource::SameStream, _permit: None });
                }
                let b = members.pop().unwrap();
                let a = members.pop().unwrap();
                finish_relay_pair_over_streams(a, b, 500).await.map(|_| ())
            });

            let client = |stream: tokio::io::DuplexStream, req: ChannelJoinRequest, holder: SigningKey, send: &'static [u8], want: &'static [u8]| async move {
                let (mut cr, mut cw) = tokio::io::split(stream);
                let out = within("relay join", present_channel_relay_join_on_stream(&mut cw, &mut cr, &req, &holder, None))
                    .await
                    .expect("relay-leg join drives");
                // The session follows on the SAME halves the join used.
                cw.write_all(send).await.expect("session write");
                cw.flush().await.expect("flush");
                let mut got = vec![0u8; want.len()];
                within("session read", cr.read_exact(&mut got)).await.expect("session read");
                assert_eq!(got, want, "the peer's first session bytes arrive intact right after the ack");
                out
            };
            let a = tokio::spawn(client(client_a, req_a, holder_a, b"session A->B", b"session B->A"));
            let b = tokio::spawn(client(client_b, req_b, holder_b, b"session B->A", b"session A->B"));
            let out_a = within("a", a).await.expect("a");
            let out_b = within("b", b).await.expect("b");
            let _ = within("edge", edge).await.expect("edge task"); // the splice ends when the clients drop

            for (out, peer_ep, pn, ph, pa, own, who) in [
                (out_a, "203.0.113.2:7002", noise_b, hkey_b, attest_b, obs_a, "A"),
                (out_b, "203.0.113.1:7001", noise_a, hkey_a, attest_a, obs_b, "B"),
            ] {
                assert_eq!(
                    out,
                    ChannelJoinOutcome::Admitted {
                        peer_endpoint: peer_ep.to_string(),
                        peer_noise_pubkey: Some(pn),
                        peer_holder: Some(ph),
                        peer_attestation: Some(pa),
                        observed_reflexive: Some(own),
                    },
                    "{who}: the rich relay ack parses whole — peer triple (#122) and its OWN reflexive (#495-U1)"
                );
            }
        }

        /// CADS-Tunnel#753 REGRESSION GUARD. This test found the defect it now guards (PR3,
        /// 2026-09-03, deterministic): `finish_quic_pair_inner`'s refusal arm buffered the
        /// framed `pairing` refusal on both members' streams and then returned `Err`, which
        /// dropped both `quinn::Connection`s -- and a quinn close sends no further data, so
        /// the refusal never left the edge. Both members saw an empty-ack close and (correctly,
        /// per #23/#148) reported the retryable `DroppedLegBeforeAck` for a DEFINITIVE
        /// refusal; #524's post-admission `pairing` category was unreachable on QUIC. The arm
        /// now holds both connections until the peer has read and closed (2 s bound, the
        /// #129-follow pattern). Red without that hold, green with it.
        #[tokio::test]
        async fn shared_client_surfaces_the_edges_framed_pairing_refusal_after_possession_p2() {
            // CADS-Tunnel#524 (post-admission category) + ct-agent#23 + CADS-Tunnel#753: two
            // INITIATORS of the same channel each pass admission (grant + possession) but cannot
            // be paired; the edge writes the framed `pairing` refusal after the possession
            // exchange and must keep the connections alive until it is delivered. The shared
            // client classifies it at the byte level as `Refused { Some("pairing") }` — not a
            // dropped leg, not an error, and not the generic category-less refusal.
            let channel = [0xF0u8; 32];
            let holder_a = holder_sk(0x51);
            let holder_b = holder_sk(0x52);
            let req_a = request(channel, &holder_a, Direction::Initiate, "203.0.113.1:7001");
            let req_b = request(channel, &holder_b, Direction::Initiate, "203.0.113.2:7002");
            let pk = op_pub();

            let (server, cert) = build_server_endpoint_with_cert().expect("server");
            let addr = server.local_addr().expect("addr");
            let srv = tokio::spawn(async move {
                let r = broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                    .await
                    .map(|_| ());
                // The live edge's endpoint outlives one refused pairing; only the members'
                // connections are dropped by the completer. Mirror that here.
                within("drain", server.wait_idle()).await;
                r
            });
            let cert_b = cert.clone();
            let a = tokio::spawn(async move { join_quic(cert, addr, &req_a, &holder_a, None).await.0 });
            let b = tokio::spawn(async move { join_quic(cert_b, addr, &req_b, &holder_b, None).await.0 });
            let out_a = within("a", a).await.expect("a");
            let out_b = within("b", b).await.expect("b");
            within("broker", srv).await.expect("broker task").expect_err("two initiators are not pairable");
            for (out, who) in [(out_a, "A"), (out_b, "B")] {
                assert_eq!(out, ChannelJoinOutcome::Refused { category: Some("pairing".to_string()) }, "{who}");
            }
        }

        /// CADS-Tunnel#754 CONTRACT (the `:443` twin of the #753 guard above). Two
        /// INITIATORS of the same channel arrive over REAL TLS-over-TCP front-door streams
        /// (the exact `tokio_rustls` transport the live `:443` leg yields), pass admission,
        /// and are handed to `finish_relay_pair_over_streams`, whose refusal arm writes the
        /// framed `pairing` refusal, `shutdown()`s (close_notify + FIN) and returns. #754
        /// asked whether that arm needs the Ok path's #511 `graceful_close` drain against
        /// the close_notify RST race. It does not, and this test pins the delivered contract
        /// so a change to that arm is judged against the real transport: at the moment the
        /// edge shuts down, the member has sent nothing after its possession signature -- it
        /// is blocked reading the ack -- so no unread close_notify sits in the edge's receive
        /// buffer and the drop is FIN-only; the refusal record is on the wire ahead of the
        /// FIN and the shared relay-leg client classifies it as the definitive
        /// `Refused { Some("pairing") }`, never a retryable dropped leg.
        #[tokio::test]
        async fn shared_relay_leg_client_surfaces_the_frontdoor_pairing_refusal_over_real_tls_754() {
            use crate::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
            use std::net::Ipv4Addr;

            let channel = [0xF7u8; 32];
            let holder_a = holder_sk(0x61);
            let holder_b = holder_sk(0x62);
            let req_a = request(channel, &holder_a, Direction::Initiate, "203.0.113.1:7001");
            let req_b = request(channel, &holder_b, Direction::Initiate, "203.0.113.2:7002");
            let pk = op_pub();

            let (listener, acceptor, cert) = within("listen", build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()))
                .await
                .expect("tls-tcp listener");
            let addr: SocketAddr = listener.local_addr().expect("addr");

            let edge = tokio::spawn(async move {
                let authorize =
                    move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((pk, None, None)) };
                let mut members = Vec::new();
                for _ in 0..2 {
                    let (tcp, peer) = within("tcp accept", listener.accept()).await.expect("tcp accept");
                    let tls = within("tls accept", acceptor.accept(tcp)).await.expect("tls accept");
                    let (stream, req, operator, noise, attest, observed) =
                        admit_channel_join_on_duplex(tls, peer, 500, BOUND, &authorize)
                            .await
                            .expect("the real edge admits the shared relay-leg client over TLS-TCP");
                    members.push(AdmittedStreamMember { stream, req, operator, noise, attest, observed, session: SessionSource::SameStream, _permit: None });
                }
                let b = members.pop().unwrap();
                let a = members.pop().unwrap();
                finish_relay_pair_over_streams(a, b, 500).await.map(|_| ()).map_err(|e| e.to_string())
            });

            let client = |req: ChannelJoinRequest, holder: SigningKey, cert: CertificateDer<'static>| async move {
                let stream = within("tls connect", tcp_tls_connect(addr, cert)).await.expect("tls-tcp connect");
                let (mut cr, mut cw) = tokio::io::split(stream);
                within("relay join", present_channel_relay_join_on_stream(&mut cw, &mut cr, &req, &holder, None))
                    .await
                    .expect("an explicit refusal is a clean outcome, not an error (ct-agent#129)")
                // Dropping the halves here closes the member's connection the way ct-agent does
                // once it has its outcome -- AFTER the edge's shutdown, never before.
            };
            let cert_b = cert.clone();
            let a = tokio::spawn(client(req_a, holder_a, cert));
            let b = tokio::spawn(client(req_b, holder_b, cert_b));
            let out_a = within("a", a).await.expect("a");
            let out_b = within("b", b).await.expect("b");
            let err = within("edge", edge).await.expect("edge task").expect_err("two initiators are not pairable");
            assert!(err.contains("channel relay pair refused"), "the edge reports the `:443` pair refusal: {err}");
            for (out, who) in [(out_a, "A"), (out_b, "B")] {
                assert_eq!(
                    out,
                    ChannelJoinOutcome::Refused { category: Some("pairing".to_string()) },
                    "{who}: the framed refusal reaches the member over real TLS-TCP and is definitive"
                );
            }
        }

        #[tokio::test]
        async fn shared_client_classifies_the_edges_quic_park_expiry_close_as_park_expired_p2() {
            // ct-agent#21 (QUIC half) + CADS-Tunnel#557: a reaped QUIC park writes no ack at all —
            // the edge closes the CONNECTION with the named `park-expired: …` reason
            // (`quic_park_expired_reason`, built from the shared `PARK_EXPIRED_REASON_PREFIX`).
            // The shared client must read that wire-carried reason out of quinn's error chain
            // and return `ParkExpired` — neither `Refused` (the #21 phantom rung failures) nor
            // a transport error. Both sides now derive the token from ct_common, and this is
            // where a reword on either side fails.
            let channel = [0x21u8; 32];
            let holder = holder_sk(0x61);
            let req = request(channel, &holder, Direction::Accept, "203.0.113.8:7008");
            let pk = op_pub();

            let (server, cert) = build_server_endpoint_with_cert().expect("server");
            let addr = server.local_addr().expect("addr");
            let edge = tokio::spawn(async move {
                let conn = within("accept", server.accept()).await.expect("incoming");
                let conn = within("handshake", std::future::IntoFuture::into_future(conn)).await.expect("conn");
                let (_send, _req, _op, _noise, _attest, _observed) =
                    read_join_on_connection(&conn, 500, BOUND, &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) })
                        .await
                        .expect("admitted, then parked with no partner");
                // The park TTL reap: close the whole connection, naming why.
                conn.close(0u32.into(), quic_park_expired_reason("no partner within the park TTL").as_bytes());
                within("drain", server.wait_idle()).await;
            });
            let (outcome, _, conn) = join_quic(cert, addr, &req, &holder, None).await;
            conn.close(0u32.into(), b"done");
            within("edge", edge).await.expect("edge task");
            assert_eq!(outcome, ChannelJoinOutcome::ParkExpired, "the named close reason classifies as ParkExpired (#21), not a refusal");
        }
    }
}
