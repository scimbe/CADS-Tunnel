//! Edge routing state (M5.1b).
//!
//! Maps a Routing Token to the Agent tunnel handle that serves it, so the Edge
//! can route a resolved Client rendezvous to the right Agent connection. Generic
//! over the handle type (`quinn::Connection` in the daemon) to stay
//! unit-testable. `is_known` feeds [`Self::is_resolvable`], which gates the
//! rate limiter ahead of the inline PoW-gated `'C'` admission in `serve.rs`
//! (the original `resolve_rendezvous_gated` this fed had zero production
//! callers and was removed as dead code, #580).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use ct_common::metrics::Counter;
use ct_common::ratelimit::{KeyedRateLimiter, RateLimiter};
use ct_common::RoutingToken;
use ct_common::sync::{MutexExt, RwLockExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use std::sync::Arc;
use std::time::Duration;

/// A concurrency cap for the edge accept loop (#86 SEC86b, ADR-0018's connection-
/// flood half): at most `max` connections are handled at once. [`try_admit`] hands
/// out an owned permit that the caller holds for the connection's lifetime; when the
/// cap is reached it returns `None` and the caller sheds the connection (quinn
/// `Incoming::ignore`), so a flood can't exhaust memory / file descriptors before the
/// PoW gate even runs. Load-shedding (not queueing) keeps a rejected connection cheap.
///
/// [`try_admit`]: ConnectionCap::try_admit
#[derive(Clone)]
pub struct ConnectionCap {
    sem: Arc<Semaphore>,
    shed: Arc<AtomicU64>,
    max: usize,
}

impl ConnectionCap {
    /// A cap admitting at most `max` concurrent connections.
    pub fn new(max: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max)),
            shed: Arc::new(AtomicU64::new(0)),
            max,
        }
    }

    /// The configured capacity this cap was built with (for metrics -- `available()`
    /// alone can't tell a caller how many of that budget are currently in use).
    pub fn max(&self) -> usize {
        self.max
    }

    /// Connections currently in use (`max` minus free slots).
    pub fn in_use(&self) -> usize {
        self.max.saturating_sub(self.available())
    }

    /// Total sheds recorded so far (read-only -- unlike [`Self::note_shed`], which
    /// also increments the counter).
    pub fn shed_total(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }

    /// Try to admit one connection: `Some(permit)` when below the cap (hold it for
    /// the connection's lifetime), `None` when full (shed the connection). Never
    /// blocks.
    pub fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.sem).try_acquire_owned().ok()
    }

    /// Currently free slots (for tests / metrics).
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }

    /// Record one shed connection (the cap was full when a caller tried to admit)
    /// and return the running total. A cap-exhaustion shed previously left NO trace
    /// anywhere in the edge's own logs — from the caller's own TCP accept loop it's
    /// indistinguishable from any other closed socket, so an operator chasing a
    /// client-reported "TLS handshake EOF right after connect" symptom had no way to
    /// confirm or rule out "the cap is full" from the edge side at all. Callers log
    /// this occasionally (not every shed — that would defeat the whole point of
    /// shedding cheaply under a real flood); this just makes the running total
    /// available to do so.
    pub fn note_shed(&self) -> u64 {
        self.shed.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// A boxed bidirectional byte stream — the concrete handoff type for a
/// TCP-fallback agent rendezvous (issue #3 / P1.2c-3), where a single stream
/// cannot be cloned/multiplexed like a QUIC connection.
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}
/// #517 V1: WHICH relay plane a byte tally belongs to -- the per-plane split that
/// makes the traffic-offload work measurable (where do the central host's relayed
/// bytes actually come from?).
///
/// #534 made the partition rule explicit, because the two axes it mixes (plane
/// vs. transport) are what let the counters drift apart: **`TcpFallback` wins
/// whenever EITHER leg of the relay ran over the TLS-TCP fallback** -- the
/// agent leg (an agent whose UDP is blocked, parked via `park_tcp_agent` and
/// served by `serve_tcp_connection`'s 'A'/'K'/'B'/'L'/'F' arms) or the client
/// leg (a ct-client or a peer edge dialing the :4433 listener's 'C'/'M' roles).
/// `Browser` and `DataPlane` therefore describe QUIC-to-QUIC-or-:443 traffic
/// only. That is what makes the counter answer the operator's actual question
/// ("how much of my traffic is on the DPI/NAT fallback?") with a single label,
/// and it keeps the three kinds a genuine partition of `relay_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayKind {
    /// Browser-Plane: SNI passthrough / Gelb-terminated browser traffic to a
    /// QUIC-registered agent (a browser served by a PARKED fallback agent is
    /// `TcpFallback`, booked in the park arm that actually relays it -- #534).
    Browser,
    /// QUIC data plane: a ct-client relaying to an agent (route_and_relay / the 'C' arm),
    /// both legs QUIC.
    DataPlane,
    /// The TLS-TCP fallback (:4433, or the :443 front door's EdgeRelay dispatch):
    /// either the parked-agent hop or the fallback client/peer-edge hop. See the
    /// enum doc for the "either leg wins" rule.
    TcpFallback,
}

/// #502-follow (#513): WHY a hostname bind was refused. The 'H' arm's operator log
/// used to collapse "already bound to a different token" and "token revoked" into
/// one line, leaving exactly the revoke case -- the one an operator can act on
/// (re-provision the agent) -- indistinguishable from a takeover refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostBindRefusal {
    /// Rejected by hostname normalization (#23 BP4b-d).
    MalformedHostname,
    /// The token is revoked (#411) -- re-provision the agent.
    Revoked,
    /// The hostname is bound to a DIFFERENT token (takeover refusal, #23 BP4a).
    BoundToDifferentToken,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> DuplexStream for T {}
pub type BoxedStream = Box<dyn DuplexStream>;

/// Budget of **definitive** channel-join refusals per source IP per window before new
/// join connections from that IP are shed pre-handshake (see `join_refusal_limiter`).
/// Calibration from the 2026-08-13 incident: the storm produced 1,500-2,500 definitive
/// refusals/min from one IP (trips this in ~1s of each window); a well-behaved client
/// with a genuinely dead grant retries with exponential backoff (ct-agent #231) and
/// produces single-digit refusals/min. The two are three orders of magnitude apart, so
/// 30 leaves enormous headroom for NAT-shared IPs with several legitimate clients.
const JOIN_REFUSALS_PER_MINUTE: u32 = 30;
/// Window length for [`JOIN_REFUSALS_PER_MINUTE`], in seconds. A penalty therefore
/// self-clears within at most one minute of the offender stopping -- deliberate: the
/// goal is absorbing storms cheaply, not durably banning an IP that other, innocent
/// tenants may share.
const JOIN_REFUSAL_WINDOW_SECS: u64 = 60;
/// Capacity bound on distinct IPs tracked at once (#414-style FIFO eviction). 4096 IPs
/// x ~24 bytes is trivially small, yet far above any plausible number of *distinct*
/// definitively-refused sources per minute.
const JOIN_REFUSAL_MAX_TRACKED_IPS: usize = 4096;

/// #497 slice 2: liveness heartbeat for a broker accept loop. The 2026-08-13 broker wedge
/// (accept loop dead inside a live, healthcheck-green process, 22 minutes of fleet-wide
/// channel outage) was invisible precisely because nothing observable distinguished "idle
/// broker" from "dead broker". Each loop iteration -- INCLUDING idle ticks, see
/// `run_channel_broker_loop`'s select! -- stores the current unix time here; `/metrics`
/// exposes it as `ct_edge_channel_broker_loop_last_seen_seconds{loop=...}`, so a scraper (or
/// a hardened container healthcheck) can alert on staleness: with the loop's own 10s idle
/// tick, anything older than ~30s means the loop is genuinely wedged, not idle.
pub struct BrokerHeartbeat {
    last_seen: std::sync::atomic::AtomicU64,
    /// #539: when the edge DECIDED to run this loop (unix seconds); 0 = it never intended to.
    /// Without this, `last_seen == 0` conflates two opposite situations -- a loop the edge
    /// deliberately does not run (the #103 address-collision guard) and a loop that was
    /// supposed to run and failed to come up (a bind error, which only reaches an `eprintln!`).
    /// Health cannot tell them apart from the beat alone, so the intent has to be recorded
    /// where it is known: at the spawn site.
    expected_since: std::sync::atomic::AtomicU64,
}

impl BrokerHeartbeat {
    pub fn new() -> Self {
        Self {
            last_seen: std::sync::atomic::AtomicU64::new(0),
            expected_since: std::sync::atomic::AtomicU64::new(0),
        }
    }
    /// Record one loop iteration at `now` (unix seconds).
    pub fn beat(&self, now: u64) {
        self.last_seen.store(now, std::sync::atomic::Ordering::Relaxed);
    }
    /// The last recorded iteration time (unix seconds); 0 = this loop never beat.
    pub fn last_seen(&self) -> u64 {
        self.last_seen.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// #539: declare that this loop is supposed to run, as of `now`. Call it immediately
    /// before spawning -- after any deliberate decision NOT to run the loop, and before the
    /// listener is bound, so that a failure to bind still counts as "expected but absent".
    /// First call wins: a re-declaration must not reset the clock a health check measures against.
    pub fn expect_start(&self, now: u64) {
        let _ = self.expected_since.compare_exchange(
            0,
            now,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    /// When this loop was declared expected (unix seconds); 0 = the edge never intended to run it.
    pub fn expected_since(&self) -> u64 {
        self.expected_since.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for BrokerHeartbeat {
    fn default() -> Self {
        Self::new()
    }
}

/// The per-source-IP definitive-refusal tracker behind [`EdgeState::join_penalized`] --
/// a standalone, `Arc`-shareable type (rather than a private `EdgeState` field only)
/// because TWO accept paths must consult the SAME budget: the `:443` front door's
/// `ChannelBroker` arm (which has `&EdgeState` in scope) and the QUIC channel broker's
/// accept loop (`run_channel_broker_loop`, a generic free function that deliberately
/// does not know about `EdgeState`). See the field doc on `EdgeState::join_refusal`
/// for the incident rationale.
pub struct JoinRefusalPenalty {
    limiter: Mutex<KeyedRateLimiter<std::net::IpAddr>>,
    /// Running total of connections shed by the penalty, mirroring
    /// [`ConnectionCap`]'s shed counter: callers log occasionally (powers of two),
    /// never per shed -- under a real storm, per-shed logging would reintroduce the
    /// very log flood the penalty exists to end.
    sheds: std::sync::atomic::AtomicU64,
}

impl JoinRefusalPenalty {
    pub fn new() -> Self {
        Self {
            limiter: Mutex::new(KeyedRateLimiter::with_max_tracked_keys(
                JOIN_REFUSALS_PER_MINUTE,
                JOIN_REFUSAL_MAX_TRACKED_IPS,
            )),
            sheds: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record one **definitive** channel-join refusal (not-member / possession-proof
    /// failure) from `ip` at `now_secs` (Unix seconds). Returns `true` exactly when
    /// this refusal is the one that pushes the IP over its per-window budget -- so the
    /// caller logs the escalation once per (ip, window) instead of once per storm
    /// packet.
    ///
    /// Transient failures (timeouts, malformed frames, TLS errors, I/O drops) must NOT
    /// be recorded here: they can hit well-behaved clients on bad networks, and
    /// shedding on them would turn a flaky link into a lockout.
    pub fn note_definitive_refusal(&self, ip: std::net::IpAddr, now_secs: u64) -> bool {
        let window = now_secs / JOIN_REFUSAL_WINDOW_SECS;
        let mut limiter = self.limiter.lock_safe();
        // The escalation is the over-limit TRANSITION (this refusal makes the count
        // reach the budget), detected as a before/after `over_limit` edge -- not
        // `!allow`, which first reports false one refusal LATER than `over_limit`
        // starts shedding ("strictly under" vs ">= budget"), so keying the log on it
        // would report the escalation a beat after enforcement already began.
        let was_over = limiter.over_limit(&ip, window);
        let _ = limiter.allow(&ip, window);
        limiter.over_limit(&ip, window) && !was_over
    }

    /// Whether new channel-join connections from `ip` should be shed *before* the
    /// TLS/QUIC handshake, because the IP exhausted its definitive-refusal budget in
    /// the current window. Read-only: checking never consumes budget, so the
    /// enforcement path can't penalize an IP by itself.
    pub fn penalized(&self, ip: std::net::IpAddr, now_secs: u64) -> bool {
        let window = now_secs / JOIN_REFUSAL_WINDOW_SECS;
        self.limiter.lock_safe().over_limit(&ip, window)
    }

    /// Count one pre-handshake shed; returns the new running total. Callers log only
    /// when the total is a power of two (or a round thousand), same posture as
    /// [`ConnectionCap::note_shed`].
    pub fn note_shed(&self) -> u64 {
        self.sheds.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    /// #551: read the running shed total, the half of [`ConnectionCap`]'s pattern this
    /// type was missing. The counter above was incremented from the start but had no
    /// reader, so it could never reach `/metrics` -- the penalty absorbed storms with
    /// nothing to show for it, and "never fired" was indistinguishable from "not wired
    /// up". Occasional power-of-two log lines are not a substitute: they are lost to log
    /// rotation and cannot be graphed or alerted on.
    pub fn shed_total(&self) -> u64 {
        self.sheds.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// #551: how many distinct source IPs are currently tracked, bounded by
    /// [`JOIN_REFUSAL_MAX_TRACKED_IPS`].
    ///
    /// This is the number that says whether the penalty can still *work*. The table
    /// evicts FIFO at the bound, so an attacker spreading definitive refusals across more
    /// than that many sources within one window pushes each entry out before it reaches
    /// the per-IP budget -- the penalty then never engages. That is the defence failing
    /// under precisely the conditions it exists for, and without this it fails silently:
    /// a saturated table and an idle one both report nothing at all.
    pub fn tracked_ips(&self) -> usize {
        self.limiter.lock_safe().tracked_keys()
    }

    /// #551: the capacity the gauge above is read against. Exported rather than left as a
    /// private constant so a scraper can alert on the RATIO instead of a hard-coded 4096
    /// that silently becomes wrong if the bound is ever retuned.
    pub fn max_tracked_ips(&self) -> usize {
        JOIN_REFUSAL_MAX_TRACKED_IPS
    }
}

impl Default for JoinRefusalPenalty {
    fn default() -> Self {
        Self::new()
    }
}

/// Capacity bound on distinct JA4 fingerprint strings tracked by
/// [`Ja4Observations`] at once (FIFO eviction at the bound, same pattern
/// [`JoinRefusalPenalty`] uses via [`KeyedRateLimiter::with_max_tracked_keys`]).
/// An unauthenticated peer can present an arbitrary JA4 string simply by
/// varying its ClientHello's own cipher/extension offer, so this map -- purely
/// informational, no admission decision ever reads it -- still needs the same
/// "can't grow forever under attacker control" bound every other per-key table
/// in this file has. Kept deliberately smaller than
/// [`JOIN_REFUSAL_MAX_TRACKED_IPS`] (4096): that table backs a real security
/// control that needs headroom against a spread-out storm, while this one only
/// ever gets rendered wholesale into `/metrics` on every scrape -- the
/// "keine Folgekosten" (no follow-on cost) constraint this feature shipped
/// under argues for keeping that render small (256 rows is at most a few tens
/// of KB) rather than matching the security-table's budget just because the
/// eviction mechanism is the same.
const JA4_MAX_TRACKED_FINGERPRINTS: usize = 256;

/// Passive JA4 TLS-ClientHello fingerprint counter (`crate::ja4::compute_ja4`),
/// Prometheus-exposed by `observe.rs`. Bounded per
/// [`JA4_MAX_TRACKED_FINGERPRINTS`]'s doc: `counts` holds at most that many
/// distinct fingerprint strings, `order` is the FIFO eviction queue for the
/// oldest one once the bound is hit -- structurally the same two-piece shape
/// [`JoinRefusalPenalty`] uses (a bounded map plus its own eviction order),
/// specialized here to a plain cumulative counter instead of a rate-limited
/// window, since this is a counter, not a rate limiter: nothing is ever denied
/// on account of a JA4 value.
struct Ja4Table {
    counts: HashMap<String, u64>,
    order: std::collections::VecDeque<String>,
}

pub struct Ja4Observations {
    table: Mutex<Ja4Table>,
    /// Total ClientHellos observed since start, INCLUDING ones whose
    /// fingerprint didn't get a tracked slot (evicted or never inserted) --
    /// the denominator that makes `tracked_fingerprints`'s bound legible: if
    /// this keeps climbing while `tracked_fingerprints` sits at the cap, the
    /// per-fingerprint breakdown below is churning, not complete.
    total: Counter,
    /// Distinct fingerprints evicted to make room for a new one since start.
    /// Zero for the whole life of a quiet edge; a rising rate is the signal
    /// that real distinct-fingerprint traffic exceeds
    /// [`JA4_MAX_TRACKED_FINGERPRINTS`] and the per-fingerprint counts below
    /// are no longer a complete picture (mirrors
    /// [`JoinRefusalPenalty::tracked_ips`]'s own "the table can still fail"
    /// reasoning).
    evictions: Counter,
}

impl Ja4Table {
    fn new() -> Self {
        Self { counts: HashMap::new(), order: std::collections::VecDeque::new() }
    }
}

impl Ja4Observations {
    pub fn new() -> Self {
        Self { table: Mutex::new(Ja4Table::new()), total: Counter::default(), evictions: Counter::default() }
    }

    /// Record one observed ClientHello's fingerprint. Purely additive
    /// bookkeeping -- never returns anything a caller could branch admission
    /// on, by construction (there is nothing to return).
    pub fn note(&self, fingerprint: &str) {
        self.total.inc();
        let mut t = self.table.lock_safe();
        if let Some(c) = t.counts.get_mut(fingerprint) {
            *c += 1;
            return;
        }
        if t.counts.len() >= JA4_MAX_TRACKED_FINGERPRINTS {
            while let Some(oldest) = t.order.pop_front() {
                if t.counts.remove(&oldest).is_some() {
                    self.evictions.inc();
                    break;
                }
                // Already gone -- keep popping (mirrors JoinRefusalPenalty's
                // own eviction loop, `state.rs`'s `JoinRefusalPenalty` note).
            }
        }
        t.order.push_back(fingerprint.to_string());
        t.counts.insert(fingerprint.to_string(), 1);
    }

    /// A snapshot of every currently-tracked `(fingerprint, count)` pair, for
    /// `/metrics` rendering. Allocates (a `Vec` copy of the live table) --
    /// acceptable at a `/metrics`-scrape cadence and a `JA4_MAX_TRACKED_
    /// FINGERPRINTS`-bounded size, unlike the per-connection hot path this
    /// counter is fed from.
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        self.table.lock_safe().counts.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Total ClientHellos observed since start (see the field doc).
    pub fn total(&self) -> u64 {
        self.total.get()
    }

    /// Distinct fingerprints currently tracked, bounded by
    /// [`Self::max_tracked_fingerprints`].
    pub fn tracked_fingerprints(&self) -> usize {
        self.table.lock_safe().counts.len()
    }

    /// The capacity [`Self::tracked_fingerprints`] is bounded by.
    pub fn max_tracked_fingerprints(&self) -> usize {
        JA4_MAX_TRACKED_FINGERPRINTS
    }

    /// Distinct fingerprints evicted since start (see the field doc).
    pub fn evictions(&self) -> u64 {
        self.evictions.get()
    }
}

impl Default for Ja4Observations {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe registry of live Agent tunnels keyed by Routing Token, plus each
/// Agent's Edge-observed peer candidate (its reflexive address) for P2P
/// rendezvous (M11.1).
pub struct EdgeState<H> {
    /// Live Agent tunnels per token. **Multiple** Agents may register the same
    /// token for redundancy/failover (#8); each is tagged with a monotonic
    /// registration id so exactly one can be evicted when its connection drops.
    /// #362: `RwLock`, not `Mutex` -- read far more often (every `route`/
    /// `routes`/`is_known`/`registration_count` call, the rendezvous hot
    /// path) than written (only `register_locked`/`remove_registration`/
    /// `remove`, connection-setup-time operations, not per-relay-byte).
    agents: RwLock<HashMap<RoutingToken, Vec<(u64, H)>>>,
    /// Source of monotonic registration ids.
    next_reg: AtomicU64,
    /// #362: `RwLock` -- read on every `candidate()` lookup (P2P rendezvous),
    /// written only at register/teardown.
    candidates: RwLock<HashMap<RoutingToken, SocketAddr>>,
    /// Agent-advertised direct-path listener: (address, cert DER) a Client can
    /// connect to directly, bypassing the Edge relay (M11.4b).
    /// #362: `RwLock` -- read on every `direct_endpoint()` lookup, written
    /// only at advertise/teardown.
    direct: RwLock<HashMap<RoutingToken, (SocketAddr, Vec<u8>)>>,
    /// Parked TCP-fallback agents (issue #3 / P1.2c-3, pooled since #229): a
    /// `token` maps to a FIFO queue of senders, one per concurrently-parked
    /// registration -- the Agent-side pool (`run_agent_tcp_fallback`) holds
    /// several of these open at once so more than one simultaneous Client can
    /// be served (a real browser page load opens several parallel
    /// connections per origin; a single parked slot could only ever satisfy
    /// one, dropping every other simultaneous request). Each entry is still
    /// single-use (one Client per registration) -- `deliver_to_tcp_agent`
    /// pops the oldest.
    tcp_agents: Mutex<HashMap<RoutingToken, std::collections::VecDeque<oneshot::Sender<BoxedStream>>>>,
    /// Woken every time [`park_tcp_agent`](Self::park_tcp_agent) adds a fresh
    /// registration, for any token. Lets [`wait_for_tcp_agent`](Self::wait_for_tcp_agent)
    /// block briefly instead of polling when a Client arrives between two of the
    /// Agent-side pool's registration cycles (#229 follow-up: a real browser's
    /// burst of parallel connections can momentarily exceed the pool size even
    /// though a slot frees up milliseconds later).
    tcp_agent_parked: Notify,
    /// Browser Plane (#23): public hostname -> routing token, so an SNI-routed
    /// TLS connection can be mapped to a tunnel without the Client protocol.
    /// Hostnames are stored lowercased. The payload stays blind (TLS ciphertext
    /// is passed through); only the SNI hostname is visible to the Edge.
    /// #362: `RwLock` -- read on every `route_host()` SNI lookup (the
    /// rendezvous hot path), written only at bind/teardown.
    hosts: RwLock<HashMap<String, RoutingToken>>,
    /// #360: reverse index of [`hosts`](Self::hosts) -- routing token ->
    /// every hostname currently bound to it. Kept in lockstep at `hosts`'s
    /// own two real mutation sites, [`register_host`](Self::register_host)
    /// (insert) and [`clear_hosts_for`](Self::clear_hosts_for) (bulk
    /// removal) -- confirmed via a full `grep` these are the only two.
    /// `clear_hosts_for` used to `retain()`-scan the *entire* `hosts` map on
    /// every last-agent teardown to find the handful belonging to one token;
    /// this turns that into an O(hosts for this token) removal instead of
    /// O(all hosts on the Edge).
    hosts_by_token: Mutex<HashMap<RoutingToken, HashSet<String>>>,
    /// Revoked routing tokens (#27 RB3): a token here is torn down and refuses
    /// re-registration, so a customer's "revoke" actually stops the tunnel even
    /// though the agent keeps reconnecting.
    ///
    /// #280: this set has no eviction, and deliberately so. A `RoutingToken` is
    /// an opaque 32 bytes with no embedded expiry (`ct_common::RoutingToken`) --
    /// the CP hands out a token once and it's expected to keep working until the
    /// customer explicitly revokes it, so nothing else independently invalidates
    /// a revoked token. A TTL or size-capped eviction here would therefore be a
    /// **security regression**, not just a robustness trade-off: aging out a
    /// revocation record would let that same token become valid again on a
    /// later reconnect attempt, silently undoing the customer's revoke. Growth
    /// is bounded only by process lifetime (one 32-byte entry per ever-revoked
    /// token).
    ///
    /// A restart IS a full reclamation of this set (and, today, the ONLY one) --
    /// but that is a pre-existing, separate gap from what #280 covers, not a
    /// mitigation of it: `POST /admin/revoke/:token` (`admin.rs`) is a one-time
    /// push at the moment of revocation, and nothing replays the CP's
    /// currently-revoked tokens to the Edge at boot (checked: no such call
    /// anywhere in this crate). So a restarted Edge starts with an *empty*
    /// revoked set, and a still-reconnecting Agent for an already-revoked
    /// tunnel would successfully re-register until the customer revokes again
    /// -- which they have no reason to, believing it's already done. Filed
    /// separately (deserves its own fix: a boot-time sync endpoint or
    /// replay-on-connect from the CP), since building that is a real feature
    /// addition, not the same bounded scope as this unbounded-growth finding.
    /// #362: `RwLock` -- read on every `is_revoked()` check (the rendezvous
    /// hot path), written only at revoke/boot-seed time.
    revoked: RwLock<HashSet<RoutingToken>>,
    /// Shared admin secret authenticating the control plane's `'R'` revoke op
    /// (#27 RB3). `None` = revocation disabled (no `CT_EDGE_ADMIN_TOKEN`).
    admin_token: Mutex<Option<[u8; 32]>>,
    /// #603: durable connection-source audit log. `None` = disabled (no
    /// `CT_EDGE_AUDIT_LOG_PATH`), the default until step 6 wires the compose/env
    /// plumbing -- see `audit_log.rs`'s module doc for scope/rationale.
    audit_log: Mutex<Option<std::sync::Arc<crate::audit_log::SqliteAuditLog>>>,
    /// Hostname-ownership authorization (#23 BP4b). `None` = not required (legacy
    /// binds allowed, subject to BP4a takeover-safety). `Some(map)` = required:
    /// a hostname may only be bound by the token the control plane authorized for
    /// it — so an anonymous `'H'` bind on a public `:443` can't claim a name.
    /// #362: `RwLock` -- read on every `host_bind_allowed()` check (the
    /// rendezvous hot path) and `dump_host_auth()`, written only when the
    /// control plane pushes an authorization change.
    host_auth: RwLock<Option<HashMap<String, RoutingToken>>>,
    /// Rot/Gelb/Grün certificate tier (#233): hostnames currently in the
    /// **Gelb** tier — live via the shared front-door wildcard certificate,
    /// not yet on their own agent-held one. Absence here (the default for
    /// every hostname on a fresh boot) means ordinary SNI-passthrough
    /// (`serve_sni_passthrough`), exactly today's behavior — a host only
    /// ever gets TLS-terminated at the edge with the wildcard cert when the
    /// control plane has explicitly pushed it here via
    /// `POST /admin/authorize-host/:token/:host?channel_tier=gelb`.
    /// #362: `RwLock` -- read on every `is_gelb()` check (the TLS-terminate
    /// decision on the connection-accept hot path), written only when the
    /// control plane pushes a tier change.
    gelb_hosts: RwLock<HashSet<String>>,
    /// Per-token fixed-window rendezvous rate limit (#86, ADR-0018). `None` = off
    /// (no cap). `Some(limiter)` caps how many rendezvous a single routing token may
    /// drive per window — the second half of the layered rendezvous-flood defense
    /// (PoW raises per-attempt cost; this caps per-token volume even for a solver).
    rendezvous_limiter: Mutex<Option<RateLimiter>>,
    /// Per-source-IP counter of **definitive** channel-join refusals (not-member /
    /// possession-proof failures) -- the offenses a client can never turn into a success
    /// by retrying, only an operator can. Live incident, 2026-08-13 (#494): one stale
    /// client behind a NAT retried two dead channels at 25-75ms cadence for ~10 hours
    /// (~1,500-2,500 refusals/min). The edge itself absorbed it (2.5% CPU, zero sheds),
    /// but ~29 TLS/QUIC handshakes per second on the shared front door degraded
    /// connection ESTABLISHMENT for every other tenant of this IP -- measured externally
    /// as time-clustered setup failures, and every co-hosted service healed within two
    /// minutes of the storm's source going away.
    ///
    /// Keyed by IP, counting refusals in fixed 60s windows via the same bounded
    /// [`KeyedRateLimiter`] the rendezvous limit uses. Once an IP exceeds the per-window
    /// budget, new CHANNEL-JOIN connections from it are shed before the TLS/QUIC
    /// handshake for the remainder of the window -- cheap for the edge, invisible to
    /// every other protocol (tunnels, web, ws) from the same possibly-NAT-shared IP,
    /// and self-clearing on the next window. A well-behaved client with a genuinely
    /// refused grant retries with exponential backoff (ct-agent's #231 fix, a handful
    /// per minute at worst) and never comes near the budget.
    ///
    /// `Arc`-shared (see [`JoinRefusalPenalty`]) because the QUIC broker loop enforces
    /// the SAME budget without holding an `EdgeState`.
    join_refusal: std::sync::Arc<JoinRefusalPenalty>,
    /// JA4 TLS-ClientHello fingerprint counter (see [`Ja4Observations`]) --
    /// `Arc`-shared for the same reason `join_refusal` is, even though today only
    /// `serve_front_door` (which already holds an `&EdgeState`) feeds it.
    ja4: std::sync::Arc<Ja4Observations>,
    /// #497 slice 2: liveness heartbeats for the two QUIC broker accept loops (relay,
    /// rendezvous) -- `Arc`-shared into the loops the same way `join_refusal` is, read by
    /// `/metrics`. See [`BrokerHeartbeat`].
    relay_broker_heartbeat: std::sync::Arc<BrokerHeartbeat>,
    rendezvous_broker_heartbeat: std::sync::Arc<BrokerHeartbeat>,
    /// #553: liveness for the TCP accept loops (`transport::serve_listener`). The two
    /// heartbeats above cover the QUIC channel brokers only, so a dead `:443` accept task
    /// left `/healthz` answering 200 with every public hostname dark -- the #497 outage
    /// class on the listener with the widest blast radius. Keyed by the loop's own label
    /// so `/healthz` can name which one is gone.
    listener_heartbeats: RwLock<HashMap<&'static str, std::sync::Arc<BrokerHeartbeat>>>,
    /// Listeners that are watched but must NOT decide `/healthz`.
    ///
    /// Registering a listener used to mean two things at once: it becomes visible in
    /// `/metrics`, and its death turns `/healthz` into a 503 — which restarts the container.
    /// For a loop that carries the data plane that is right. For the `:80` redirect it is
    /// not: losing it costs a convenience redirect, and tearing down every live tunnel to
    /// recover it does far more damage than the fault (#553 argued exactly this).
    ///
    /// With only those two settings available, #553 had to pick "invisible", and the
    /// consequence was the failure mode this whole family of checks exists against: a dead
    /// `:80` listener and a healthy one produce the same output — nothing. This set is the
    /// missing third setting: watched, reported, never fatal.
    advisory_listeners: RwLock<std::collections::HashSet<&'static str>>,
    /// #554: bumped by [`Self::revoke_token`] to wake live relays.
    ///
    /// Deliberately ONE global counter rather than a per-token registry of cancel handles.
    /// A woken relay re-checks `is_revoked` for its own token, so the wake-up carries no
    /// identity and needs no bookkeeping that could leak an entry per token ever revoked.
    /// It is also race-free in the direction that matters: `watch` retains its latest
    /// value, so a relay that subscribes *after* a revocation still sees a changed value
    /// and re-checks — and the pre-relay `is_revoked` check covers the rest.
    revocation_tick: tokio::sync::watch::Sender<u64>,
    /// Cumulative data-plane counters for observability (#10 O2).
    registrations: Counter,
    relays: Counter,
    relay_bytes: Counter,
    failovers: Counter,
    /// TLS-TCP **fallback** observability. The counters above only ever see the
    /// QUIC path: `register_locked` increments `registrations`/the gauges below,
    /// but [`park_tcp_agent`](Self::park_tcp_agent) writes to a completely
    /// separate `tcp_agents` map and historically touched no metric at all. An
    /// Agent reachable only over `:4433` — the normal case when a network blocks
    /// the QUIC ports — was therefore **invisible in every single edge metric**:
    /// `active_tunnels`, `active_agents` and `registrations_total` all stayed
    /// flat no matter how often it connected, reconnected, or served traffic.
    ///
    /// That cost real debugging time in a live incident (2026-08-13,
    /// sort.bunsenbrenner.org): flat counters were read as "the agent never even
    /// tries to connect" while the agent was in fact reconnecting continuously
    /// over the fallback (~737 cycles in 17.5h, measured agent-side) and serving
    /// a fraction of requests. Two independent observers reached opposite,
    /// equally-wrong conclusions from the same metrics.
    ///
    /// `tcp_parks` counts every park (each is one reconnect/pool slot, so its
    /// rate IS the churn rate); `tcp_deliveries` counts slots actually consumed
    /// by a Client; `tcp_parked_gauge` is how many are waiting right now.
    tcp_parks: Counter,
    tcp_deliveries: Counter,
    /// #522: TCP-fallback parks reaped as dead by the periodic sweep since start.
    /// Its RATE is the orphan rate -- a spike means agents are abandoning parks
    /// (crash loop, respawn storm) faster than usual; a return to a high sustained
    /// rate after the #522 fix is the regression signal to watch on `/metrics`.
    tcp_reaped: Counter,
    tcp_parked_gauge: AtomicU64,
    /// #517 V1: per-plane relay byte tallies (browser / QUIC data plane / TCP
    /// fallback) -- their sum equals `relay_bytes`, keeping the historical total
    /// untouched while making the offload split visible. The sum invariant holds
    /// by construction: `note_relay` is the ONLY writer of both, and it always
    /// writes exactly one kind. #534: it is also the only writer, full stop --
    /// a relay that forgets to call it is missing from the total AND from every
    /// kind, which is how the fallback's bytes went unreported for so long.
    relay_bytes_browser: AtomicU64,
    relay_bytes_dataplane: AtomicU64,
    relay_bytes_tcp_fallback: AtomicU64,
    /// #359: live gauges maintained incrementally at every real mutation of
    /// `agents` (`register_locked`/`remove_registration`/`remove`, the only
    /// three call sites that ever insert into or remove from that map -- all
    /// three already run under `registration_lock`, so a plain `Relaxed`
    /// store here is fully consistent with no extra synchronization cost).
    /// [`active_tunnels`](Self::active_tunnels)/[`total_registrations`](Self::total_registrations)
    /// used to be O(n) scans over the whole map on every read -- real cost on
    /// a frequently-scraped `/metrics` endpoint, and one that grows with
    /// tunnel count while blocking the same lock the routing hot path needs.
    /// Reading a gauge is now O(1) and lock-free.
    active_tunnels_gauge: AtomicU64,
    total_registrations_gauge: AtomicU64,
    /// Per-token cumulative relay byte counters -- `(bytes client->agent,
    /// bytes agent->client)` -- monitoring-feature v1 follow-up (operator
    /// decision, 2026-08-01): the "bytes sent/received" half of the original
    /// request, alongside [`tunnel_status`](Self::tunnel_status)'s
    /// "connected or not". Deliberately per-token (unlike [`relay_bytes`],
    /// the pre-existing fleet-wide-only counter #10 O2 added) since a
    /// tunnel's own owner needs their own number, not the fleet aggregate --
    /// still ADR-0016-bounded: liveness/volume only, never payload content.
    /// Grows by one entry per distinct token ever seen and, deliberately
    /// UNLIKE `agents`/`hosts` (which genuinely shrink back to zero on
    /// deregistration/revoke), a token's entry here is never removed even
    /// after revoke -- this is meant as a cumulative-forever tunnel-owner
    /// total, the same intent as `relay_bytes`'s own fleet-wide aggregate
    /// (a structurally different `Counter`, not a per-token map, but the
    /// same "never reset except by restart" semantics). A revoked/deleted
    /// tunnel's historical byte total stays visible rather than vanishing.
    /// Restarting the Edge is the only reset, same as every other
    /// in-memory counter here. Bounded in practice by how many distinct
    /// routing tokens the operator ever provisions, not by attacker input
    /// (an entry is only created by `note_relay`, reachable only after a
    /// real relay actually happened on an already-registered token).
    tunnel_bytes: Mutex<HashMap<RoutingToken, (u64, u64)>>,
    /// ADR-0025 Decision 6: wall-clock (Unix seconds) the token's CURRENT
    /// unbroken registration streak started -- set the moment the first Agent
    /// registers (mirrors [`active_tunnels_gauge`](Self::active_tunnels_gauge)'s
    /// own "was the entry empty before this push" condition), removed the
    /// moment the LAST live registration for the token drops. The admin
    /// console's tunnel-overview dashboard's "uptime" is `now - this`, and is
    /// therefore only ever reported while the token is actually connected --
    /// a token that reconnects starts a fresh streak, it does not resume the
    /// old one.
    connected_since: Mutex<HashMap<RoutingToken, u64>>,
    /// ADR-0025 Decision 6: wall-clock (Unix seconds) of the most recent
    /// registration OR relay activity for a token. Unlike `connected_since`,
    /// this is **never removed** on disconnect -- the whole point of
    /// "last-seen" is that a currently-offline tunnel still reports when it
    /// was last seen, which `connected_since` alone cannot answer once cleared.
    last_seen: Mutex<HashMap<RoutingToken, u64>>,
    /// #282 follow-up: `agents`/`candidates`/`direct`/`hosts` are four
    /// independent mutexes with no shared critical section of their own, which
    /// left a narrow but real TOCTOU window between [`remove_registration`]'s
    /// teardown and a concurrent [`register_with_candidate`]/[`register_host`]
    /// for the same token (#282's original fix only narrowed this window with
    /// a re-check; the closing comment on #282 flagged a combined lock as the
    /// honest follow-up if the residual window ever proved to matter -- CI
    /// started reproducing it reliably under real thread contention, so it
    /// did). Every mutation entry point that touches more than one of those
    /// four maps for the *same* registration lifecycle now holds this lock for
    /// its entire critical section, so a teardown and a concurrent
    /// (re-)registration can never interleave -- coarser than per-token, but
    /// registration/teardown/host-bind are connection-setup-time operations,
    /// not the data-relay hot path, so global serialization here is cheap.
    registration_lock: Mutex<()>,
}

impl<H: Clone> EdgeState<H> {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            next_reg: AtomicU64::new(1),
            candidates: RwLock::new(HashMap::new()),
            direct: RwLock::new(HashMap::new()),
            tcp_agents: Mutex::new(HashMap::new()),
            tcp_agent_parked: Notify::new(),
            hosts: RwLock::new(HashMap::new()),
            hosts_by_token: Mutex::new(HashMap::new()),
            revoked: RwLock::new(HashSet::new()),
            admin_token: Mutex::new(None),
            audit_log: Mutex::new(None),
            host_auth: RwLock::new(None),
            gelb_hosts: RwLock::new(HashSet::new()),
            rendezvous_limiter: Mutex::new(None),
            join_refusal: std::sync::Arc::new(JoinRefusalPenalty::new()),
            ja4: std::sync::Arc::new(Ja4Observations::new()),
            relay_broker_heartbeat: std::sync::Arc::new(BrokerHeartbeat::new()),
            rendezvous_broker_heartbeat: std::sync::Arc::new(BrokerHeartbeat::new()),
            listener_heartbeats: RwLock::new(HashMap::new()),
            advisory_listeners: RwLock::new(std::collections::HashSet::new()),
            revocation_tick: tokio::sync::watch::channel(0).0,
            registrations: Counter::default(),
            relays: Counter::default(),
            tcp_parks: Counter::default(),
            tcp_deliveries: Counter::default(),
            tcp_reaped: Counter::default(),
            tcp_parked_gauge: AtomicU64::new(0),
            relay_bytes_browser: AtomicU64::new(0),
            relay_bytes_dataplane: AtomicU64::new(0),
            relay_bytes_tcp_fallback: AtomicU64::new(0),
            relay_bytes: Counter::default(),
            failovers: Counter::default(),
            tunnel_bytes: Mutex::new(HashMap::new()),
            connected_since: Mutex::new(HashMap::new()),
            last_seen: Mutex::new(HashMap::new()),
            registration_lock: Mutex::new(()),
            active_tunnels_gauge: AtomicU64::new(0),
            total_registrations_gauge: AtomicU64::new(0),
        }
    }



    /// Bind a public hostname to a routing token (Browser Plane, #23), **unless**
    /// the hostname is already bound to a *different* token — a takeover-safe bind
    /// (#23 BP4a). Rebinding the same token (an agent reconnecting) is idempotent
    /// and succeeds. Returns `true` when the binding is in place, `false` when a
    /// conflicting bind was refused (the existing route is left untouched). The
    /// hostname is lowercased so SNI lookups are case-insensitive.
    pub fn register_host(&self, host: &str, token: RoutingToken) -> Result<(), HostBindRefusal> {
        let Some(key) = ct_common::normalize_hostname(host) else {
            return Err(HostBindRefusal::MalformedHostname);
        };
        // #282: held across the whole bind so a concurrent remove_registration
        // teardown for this token can't observe "not yet bound" and wipe this
        // bind out from under it a moment later -- see registration_lock's doc.
        let _guard = self.registration_lock.lock_safe();
        // #411: checked inside the same lock hold, not by each caller separately
        // -- neither the QUIC 'H' bind arm nor the TCP-fallback 'B' arm checked
        // revocation before calling this, so a revoked token could still claim a
        // public hostname. Fixed once, here, so no caller can forget it.
        if self.is_revoked(&token) {
            return Err(HostBindRefusal::Revoked);
        }
        let mut hosts = self.hosts.write_safe();
        match hosts.get(&key) {
            Some(existing) if *existing != token => Err(HostBindRefusal::BoundToDifferentToken),
            _ => {
                // #360: keep the reverse index in lockstep. A HashSet insert
                // is naturally idempotent, so the "same token reconnects,
                // rebinding the same hostname" case (this same match arm)
                // never double-counts -- unlike a plain counter, no separate
                // "was it already there" check is needed here.
                self.hosts_by_token.lock_safe().entry(token.clone()).or_default().insert(key.clone());
                hosts.insert(key, token);
                Ok(())
            }
        }
    }

    /// Remove every hostname bound to `token` — called when its last agent drops
    /// or it is revoked, so no stale host->token route lingers (#23 BP4a).
    /// Callers already hold `registration_lock` (see [`remove_registration`]/
    /// [`remove`]) -- this does not re-acquire it.
    ///
    /// #360: used to `retain()`-scan the *entire* `hosts` map to find the
    /// handful bound to this one token -- real cost on an Edge with many
    /// bound hostnames, on every last-agent teardown. The reverse index
    /// gives the exact set to remove directly, so this is now
    /// O(hosts for this token), not O(every host on the Edge).
    fn clear_hosts_for(&self, token: &RoutingToken) {
        let Some(owned) = self.hosts_by_token.lock_safe().remove(token) else {
            return;
        };
        let mut hosts = self.hosts.write_safe();
        // #426: `gelb_hosts` is keyed purely by hostname (Gelb/Grün is a property
        // of the hostname's own cert tier, not of any one token), so it was never
        // cleared here -- a hostname re-bound to a different tenant after revoke
        // silently inherited whatever tier flag the PREVIOUS tenant's token left
        // behind, independent of the new tenant's own actual cert state.
        let mut gelb_hosts = self.gelb_hosts.write_safe();
        for host in owned {
            hosts.remove(&host);
            gelb_hosts.remove(&host);
        }
    }

    /// Every currently-authorized (hostname, token) pair, or `None` if
    /// authorization was never required on this edge (host_auth still `None`).
    /// Read-only — the operator-facing admin dump this deployment's own current
    /// state can be backfilled from before touching a control-plane registry
    /// that has no other way to learn what this edge already knows (#153: a
    /// live edge holds authorizations the control plane never persisted itself
    /// for hostnames bound via the loopback admin API directly).
    pub fn dump_host_auth(&self) -> Option<Vec<(String, RoutingToken)>> {
        self.host_auth
            .read_safe()
            .as_ref()
            .map(|m| m.iter().map(|(h, t)| (h.clone(), t.clone())).collect())
    }

    /// Require hostname-ownership authorization (#23 BP4b): once enabled, an
    /// `'H'` bind is refused unless the control plane has authorized that
    /// (hostname, token) pair. Enabled at startup for a reachable `:443`.
    pub fn require_host_auth(&self) {
        let mut ha = self.host_auth.write_safe();
        if ha.is_none() {
            *ha = Some(HashMap::new());
        }
    }

    /// Authorize `host` to be bound by `token` (#23 BP4b) — the control plane
    /// pushes this when a customer sets a hostname on a tunnel they own. Also
    /// enables authorization if it was not already required.
    pub fn authorize_host(&self, host: &str, token: RoutingToken) {
        if let Some(key) = ct_common::normalize_hostname(host) {
            self.host_auth
                .write_safe()
                .get_or_insert_with(HashMap::new)
                .insert(key, token);
        }
    }

    /// De-authorize `host` (#281) — the counterpart `authorize_host` never had.
    /// A no-op (not an error) if authorization was never required or `host`
    /// wasn't authorized. Callers: [`revoke_token`](Self::revoke_token) (a
    /// fully revoked token must not keep authorizing any of its hosts) and,
    /// once the control plane grows a per-hostname (as opposed to per-tunnel)
    /// revoke, that call path too.
    pub fn unauthorize_host(&self, host: &str) {
        if let Some(key) = ct_common::normalize_hostname(host) {
            if let Some(map) = self.host_auth.write_safe().as_mut() {
                map.remove(&key);
            }
        }
    }

    /// Remove every `host_auth` entry currently authorizing `token` (#281):
    /// unlike [`clear_hosts_for`](Self::clear_hosts_for) (the active routing
    /// table, cleared on both a transient agent-drop and a real revoke),
    /// this is deliberately called ONLY from [`revoke_token`](Self::revoke_token)
    /// -- an ordinary disconnect-then-reconnect must keep its CP-granted
    /// authorization, but a token the control plane has actually revoked must
    /// never keep re-authorizing a hostname bind on a later reconnect attempt,
    /// and the entry must not linger in memory for the rest of the process's
    /// life either.
    fn clear_host_auth_for(&self, token: &RoutingToken) {
        if let Some(map) = self.host_auth.write_safe().as_mut() {
            map.retain(|_, t| t != token);
        }
    }

    /// Whether binding `host` to `token` is permitted (#23 BP4b): always true
    /// when authorization is not required; otherwise only for the authorized
    /// (hostname, token) pair.
    pub fn host_bind_allowed(&self, host: &str, token: &RoutingToken) -> bool {
        let Some(key) = ct_common::normalize_hostname(host) else {
            return false; // a malformed hostname is never bindable (#23 BP4b-d)
        };
        match self.host_auth.read_safe().as_ref() {
            None => true,
            Some(map) => map.get(&key) == Some(token),
        }
    }

    /// Enable the per-token rendezvous rate limit (#86, ADR-0018): at most
    /// `max_per_window` rendezvous per routing token per window. Off until called.
    pub fn set_rendezvous_limit(&self, max_per_window: u32) {
        *self.rendezvous_limiter.lock_safe() = Some(RateLimiter::new(max_per_window));
    }

    /// Number of distinct routing tokens currently occupying a slot in the
    /// rendezvous rate limiter's per-window counter map (0 if the limit is
    /// off). Exposed for tests (#472): proves an unresolvable token was
    /// rejected before ever reaching [`Self::rendezvous_allowed`], i.e. it
    /// never occupies a limiter slot.
    pub fn rendezvous_tracked_keys(&self) -> usize {
        match self.rendezvous_limiter.lock_safe().as_ref() {
            None => 0,
            Some(rl) => rl.tracked_keys(),
        }
    }

    /// Whether `token` may drive another rendezvous in `window` (#86): always true
    /// when the limit is off; otherwise consults the fixed-window counter. `window`
    /// is a caller-supplied window index (e.g. `unix_secs / window_secs`), so this
    /// stays deterministic and unit-testable.
    pub fn rendezvous_allowed(&self, token: &RoutingToken, window: u64) -> bool {
        match self.rendezvous_limiter.lock_safe().as_mut() {
            None => true,
            Some(rl) => rl.allow(token, window),
        }
    }

    /// The shared per-IP definitive-refusal penalty (see [`JoinRefusalPenalty`] and the
    /// `join_refusal` field doc): the `:443` front-door arm records/enforces through
    /// [`Self::note_definitive_join_refusal`]/[`Self::join_penalized`]; `run_edge` hands
    /// a clone of this `Arc` to the QUIC broker loop so BOTH accept paths share one
    /// budget per IP -- a storm that alternates transports can't double its allowance.
    pub fn join_refusal_penalty(&self) -> std::sync::Arc<JoinRefusalPenalty> {
        self.join_refusal.clone()
    }

    /// The shared JA4 fingerprint counter (see [`Ja4Observations`]): the `:443`
    /// front door records through [`Self::note_ja4`]; `/metrics` reads it via
    /// this accessor. Purely observational -- nothing else in this codebase
    /// reads a JA4 value to make an admission/routing decision.
    pub fn ja4_observations(&self) -> std::sync::Arc<Ja4Observations> {
        self.ja4.clone()
    }

    /// Record one observed ClientHello's JA4 fingerprint (see
    /// [`Ja4Observations::note`]). A thin pass-through so call sites don't need
    /// to reach through [`Self::ja4_observations`] just to record one value.
    pub fn note_ja4(&self, fingerprint: &str) {
        self.ja4.note(fingerprint);
    }

    /// #497 slice 2: the relay broker loop's liveness heartbeat (see [`BrokerHeartbeat`]).
    pub fn relay_broker_heartbeat(&self) -> std::sync::Arc<BrokerHeartbeat> {
        self.relay_broker_heartbeat.clone()
    }

    /// #497 slice 2: the rendezvous broker loop's liveness heartbeat.
    /// #553: register a TCP accept loop as **expected**, returning the heartbeat it must
    /// stamp. Call this where the listener is CONFIGURED, not where it first accepts —
    /// `expect_start()` (#539) is what lets `/healthz` tell "this edge runs no front door"
    /// apart from "the front door was supposed to start and never did". Registering at
    /// first-accept would make a listener that never binds look like one that was never
    /// wanted, which is the failure being closed here.
    /// #554: resolves once `token` has been revoked — for a live relay to race against its
    /// own byte copying. Returns immediately if it is revoked already.
    ///
    /// Re-checks on every tick rather than trusting the wake-up, because the tick is
    /// shared: a revocation of some *other* token wakes this relay too, and it must go
    /// back to waiting rather than cut a tunnel nobody revoked.
    pub async fn revoked_signal(&self, token: &RoutingToken) {
        let mut rx = self.revocation_tick.subscribe();
        loop {
            if self.is_revoked(token) {
                return;
            }
            if rx.changed().await.is_err() {
                // The sender lives in `EdgeState`, which outlives any relay it routed, so
                // this is unreachable in practice. Park forever rather than return: a
                // spurious "revoked" verdict would tear down a healthy tunnel.
                std::future::pending::<()>().await;
            }
        }
    }

    pub fn expect_listener(&self, label: &'static str, now: u64) -> std::sync::Arc<BrokerHeartbeat> {
        let mut map = self.listener_heartbeats.write_safe();
        let hb = map
            .entry(label)
            .or_insert_with(|| std::sync::Arc::new(BrokerHeartbeat::new()))
            .clone();
        hb.expect_start(now);
        hb
    }

    /// Register a listener that is reported but never fails `/healthz`.
    ///
    /// Same bookkeeping as [`Self::expect_listener`] — call it before the bind, so a
    /// listener that never starts is distinguishable from one that was never wanted — but
    /// excluded from the health verdict. See [`Self::advisory_listeners`].
    pub fn expect_listener_advisory(
        &self,
        label: &'static str,
        now: u64,
    ) -> std::sync::Arc<BrokerHeartbeat> {
        self.advisory_listeners.write_safe().insert(label);
        self.expect_listener(label, now)
    }

    /// #553: every registered accept loop, for `/metrics`. Includes the advisory ones —
    /// being reported is the whole point of them.
    pub fn listener_heartbeats(&self) -> Vec<(&'static str, std::sync::Arc<BrokerHeartbeat>)> {
        self.listener_heartbeats
            .read_safe()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Is this listener allowed to turn `/healthz` into a 503?
    pub fn listener_is_health_gating(&self, label: &str) -> bool {
        !self.advisory_listeners.read_safe().contains(label)
    }

    /// The subset of [`Self::listener_heartbeats`] that decides `/healthz`.
    pub fn gating_listener_heartbeats(
        &self,
    ) -> Vec<(&'static str, std::sync::Arc<BrokerHeartbeat>)> {
        let advisory = self.advisory_listeners.read_safe();
        self.listener_heartbeats
            .read_safe()
            .iter()
            .filter(|(k, _)| !advisory.contains(*k))
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    pub fn rendezvous_broker_heartbeat(&self) -> std::sync::Arc<BrokerHeartbeat> {
        self.rendezvous_broker_heartbeat.clone()
    }

    /// [`JoinRefusalPenalty::note_definitive_refusal`] on the shared penalty.
    pub fn note_definitive_join_refusal(&self, ip: std::net::IpAddr, now_secs: u64) -> bool {
        self.join_refusal.note_definitive_refusal(ip, now_secs)
    }

    /// [`JoinRefusalPenalty::penalized`] on the shared penalty.
    pub fn join_penalized(&self, ip: std::net::IpAddr, now_secs: u64) -> bool {
        self.join_refusal.penalized(ip, now_secs)
    }

    /// Resolve a public hostname (from the TLS SNI) to its routing token.
    pub fn route_host(&self, host: &str) -> Option<RoutingToken> {
        let key = ct_common::normalize_hostname(host)?;
        self.hosts.read_safe().get(&key).cloned()
    }

    /// Set whether `host` is currently in the **Gelb** certificate tier
    /// (#233) — the control plane calls this (via the admin API) every time
    /// a hostname's tier changes, in both directions: `true` when it enters
    /// Gelb (live via the shared wildcard cert), `false` once it reaches
    /// Grün (its own cert exists; revert to ordinary passthrough so the
    /// browser sees the origin's own certificate again). A malformed
    /// hostname is silently a no-op, same as [`Self::register_host`].
    pub fn set_cert_tier(&self, host: &str, gelb: bool) {
        let Some(key) = ct_common::normalize_hostname(host) else {
            return;
        };
        let mut gelb_hosts = self.gelb_hosts.write_safe();
        if gelb {
            gelb_hosts.insert(key);
        } else {
            gelb_hosts.remove(&key);
        }
    }

    /// Whether `host` is currently in the Gelb tier — `false` for any
    /// hostname never explicitly marked so (a fresh boot, or one the control
    /// plane has never pushed a tier for), which is exactly what preserves
    /// today's ordinary SNI-passthrough behavior for every hostname this
    /// feature doesn't touch.
    pub fn is_gelb(&self, host: &str) -> bool {
        match ct_common::normalize_hostname(host) {
            Some(key) => self.gelb_hosts.read_safe().contains(&key),
            None => false,
        }
    }

    /// Note a completed relay for `token`: `client_to_agent`/`agent_to_client`
    /// are the two directions' byte counts (#10 O2's fleet-wide total, plus
    /// the per-token split added for the monitoring feature's byte counters,
    /// 2026-08-01).
    pub fn note_relay(&self, token: &RoutingToken, client_to_agent: u64, agent_to_client: u64, kind: RelayKind) {
        let total = client_to_agent.saturating_add(agent_to_client);
        match kind {
            RelayKind::Browser => self.relay_bytes_browser.fetch_add(total, Ordering::Relaxed),
            RelayKind::DataPlane => self.relay_bytes_dataplane.fetch_add(total, Ordering::Relaxed),
            RelayKind::TcpFallback => self.relay_bytes_tcp_fallback.fetch_add(total, Ordering::Relaxed),
        };
        self.relays.inc();
        self.relay_bytes.add(client_to_agent + agent_to_client);
        let mut bytes = self.tunnel_bytes.lock_safe();
        let entry = bytes.entry(token.clone()).or_insert((0, 0));
        entry.0 += client_to_agent;
        entry.1 += agent_to_client;
        drop(bytes);
        // ADR-0025 Decision 6: relay activity is "seen" too, not just a fresh
        // registration -- a long-lived, already-registered tunnel that never
        // re-registers must still show recent activity, not a stale timestamp.
        self.last_seen.lock_safe().insert(token.clone(), Self::wall_now());
    }

    /// Cumulative `(bytes received from the client, bytes sent to the
    /// client)` relayed for `token` since this Edge process started --
    /// `(0, 0)` for a token that has never relayed anything. The per-tunnel
    /// counterpart to [`relay_bytes_total`](Self::relay_bytes_total)'s
    /// fleet-wide aggregate.
    /// #517 V1: the per-plane relay byte split `(browser, dataplane, tcp_fallback)`.
    pub fn relay_bytes_by_kind(&self) -> (u64, u64, u64) {
        (
            self.relay_bytes_browser.load(Ordering::Relaxed),
            self.relay_bytes_dataplane.load(Ordering::Relaxed),
            self.relay_bytes_tcp_fallback.load(Ordering::Relaxed),
        )
    }

    pub fn tunnel_bytes(&self, token: &RoutingToken) -> (u64, u64) {
        self.tunnel_bytes.lock_safe().get(token).copied().unwrap_or((0, 0))
    }

    /// ADR-0025 Decision 6: `(connected_since, last_seen)`, both Unix seconds --
    /// the admin console's tunnel-overview dashboard's raw timing inputs. See
    /// the two fields' own doc comments for exactly when each is set/cleared;
    /// this is a plain read of both, deliberately NOT computing "uptime" itself
    /// (that subtraction happens where "now" is meaningfully callable/testable,
    /// the HTTP handler, not here).
    pub fn connection_timing(&self, token: &RoutingToken) -> (Option<u64>, Option<u64>) {
        (
            self.connected_since.lock_safe().get(token).copied(),
            self.last_seen.lock_safe().get(token).copied(),
        )
    }

    pub fn note_failover(&self) {
        self.failovers.inc();
    }
    /// Cumulative counter snapshots for the metrics endpoint (#10 O2).
    pub fn registrations_total(&self) -> u64 {
        self.registrations.get()
    }
    pub fn relays_total(&self) -> u64 {
        self.relays.get()
    }
    pub fn relay_bytes_total(&self) -> u64 {
        self.relay_bytes.get()
    }
    pub fn failovers_total(&self) -> u64 {
        self.failovers.get()
    }
    /// TLS-TCP fallback parks since start. Its **rate is the fallback pool's churn
    /// rate**: each park is one Agent-side connection joining the pool, so a
    /// steadily climbing counter on an otherwise-idle tunnel means the Agent's
    /// parked connections keep dying and being re-established — the signal that
    /// was completely unavailable before, and whose absence made a fallback-only
    /// Agent indistinguishable from one that never connects at all.
    /// #522: cumulative dead TCP-fallback parks reaped since start (see `tcp_reaped`).
    pub fn tcp_reaped_total(&self) -> u64 {
        self.tcp_reaped.get()
    }

    pub fn tcp_parks_total(&self) -> u64 {
        self.tcp_parks.get()
    }
    /// TLS-TCP fallback parks actually consumed by a Client.
    pub fn tcp_deliveries_total(&self) -> u64 {
        self.tcp_deliveries.get()
    }
    /// TLS-TCP fallback registrations parked right now, across all tokens — the
    /// fallback counterpart to [`active_tunnels`](Self::active_tunnels). Zero here
    /// while requests fail means the pool is momentarily empty (churn), which is a
    /// different failure from "no registration exists".
    pub fn tcp_parked(&self) -> u64 {
        self.tcp_parked_gauge.load(Ordering::Relaxed)
    }

    /// #544: TLS-TCP fallback registrations parked right now **for one token**. The
    /// per-token counterpart to [`registration_count`](Self::registration_count), which
    /// only ever counted QUIC registrations -- so a tunnel served entirely over the
    /// fallback reported zero everywhere and was indistinguishable from a dead one, even
    /// while it was relaying bytes. Cheap: one map lookup, same lock the park/deliver
    /// paths already take at connection setup, never per relayed byte.
    pub fn tcp_parked_for(&self, token: &RoutingToken) -> usize {
        self.tcp_agents.lock_safe().get(token).map_or(0, |q| q.len())
    }

    /// Park a TCP-fallback agent for `token`: returns a receiver that resolves to
    /// a Client's stream once one rendezvouses for this token. Additive -- an
    /// existing parked registration for the same token is NOT evicted (#229:
    /// the Agent-side pool holds several of these open concurrently on
    /// purpose, so more than one simultaneous Client can be served).
    pub fn park_tcp_agent(&self, token: RoutingToken) -> oneshot::Receiver<BoxedStream> {
        let (tx, rx) = oneshot::channel();
        self.tcp_agents.lock_safe().entry(token.clone()).or_default().push_back(tx);
        // ADR-0025 Decision 6: a fallback-only tunnel (never QUIC-registered) must
        // still show up as connected/uptime-tracked -- see `note_connected`'s doc.
        self.note_connected(&token, Self::wall_now());
        // Instrumented so a fallback-only Agent is visible at all (see `tcp_parks`).
        self.tcp_parks.inc();
        self.tcp_parked_gauge.fetch_add(1, Ordering::Relaxed);
        // `notify_one` (not `notify_waiters`): it stores a permit when nobody is
        // currently waiting, so a park() that races ahead of a concurrent
        // `wait_for_tcp_agent`'s has_tcp_agent-then-notified() check is never
        // lost. One permit per available slot is exactly the right amount of
        // wakeup for a FIFO queue where each park() adds one deliverable slot.
        self.tcp_agent_parked.notify_one();
        rx
    }

    /// Hand a Client's `stream` to the oldest parked TCP-fallback agent for
    /// `token`. Returns the stream back as `Err` if none is waiting (so the
    /// caller can fall through to the QUIC route), consuming that one
    /// registration (FIFO) on success -- the rest of the pool, if any, stays
    /// parked for the next concurrent Client.
    ///
    /// PRIVATE on purpose (#528 review findings 8/9): a single delivery
    /// attempt stops at the FIRST parked slot -- if that slot is dead (a
    /// dropped receiver), the attempt fails with the stream handed back even
    /// when a live park sits right behind the corpse. Callers then either
    /// discarded the stream (the 'K'/'L' verify-at-delivery failover's
    /// `let _ =`, losing the request) or spuriously fell through to the QUIC
    /// route (the QUIC 'C' cross-transport handoff, the TCP 'C'/'M' arms).
    /// Every production path must go through
    /// [`deliver_to_tcp_agent_draining`](Self::deliver_to_tcp_agent_draining),
    /// which consumes dead slots until a live one answers -- private
    /// visibility now enforces what used to be a code-review rule (#505/#510
    /// called draining "THE delivery entry point" and review still found six
    /// non-draining production call sites).
    fn deliver_to_tcp_agent(
        &self,
        token: &RoutingToken,
        stream: BoxedStream,
    ) -> Result<(), BoxedStream> {
        let mut agents = self.tcp_agents.lock_safe();
        let Some(queue) = agents.get_mut(token) else {
            return Err(stream);
        };
        let Some(tx) = queue.pop_front() else {
            return Err(stream);
        };
        if queue.is_empty() {
            agents.remove(token);
        }
        drop(agents);
        // One parked slot consumed, whether or not the Agent is still there to
        // receive it (a dropped receiver means that slot is gone either way).
        // Saturating (#510): a gauge can never owe parks, and a miscounted
        // increment elsewhere must show as 0, not wrap to u64::MAX in /metrics.
        let _ = self
            .tcp_parked_gauge
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |g| Some(g.saturating_sub(1)));
        let sent = tx.send(stream);
        if sent.is_ok() {
            self.tcp_deliveries.inc();
        }
        sent
    }

    /// [`deliver_to_tcp_agent`](Self::deliver_to_tcp_agent) in a drain loop
    /// (#505/#510): dead parked slots (dropped receivers) are consumed one by
    /// one; succeeds on the first live one and hands the stream back once no
    /// parked slot is left, so the caller can fall through to the QUIC
    /// registration. This is THE delivery entry point -- every serve path
    /// (primary and recovery) must drain, or a stale dead park blocks a
    /// hostname that has a healthy registration right behind it.
    pub fn deliver_to_tcp_agent_draining(
        &self,
        token: &RoutingToken,
        mut stream: BoxedStream,
    ) -> Result<(), BoxedStream> {
        while self.has_tcp_agent(token) {
            match self.deliver_to_tcp_agent(token, stream) {
                Ok(()) => return Ok(()),
                Err(back) => stream = back, // dead slot consumed; try the next
            }
        }
        Err(stream)
    }

    /// Whether at least one TCP-fallback agent is currently parked for `token`.
    pub fn has_tcp_agent(&self, token: &RoutingToken) -> bool {
        self.tcp_agents.lock_safe().get(token).is_some_and(|q| !q.is_empty())
    }

    /// #522: proactively drop every DEAD TCP-fallback park (its Agent-side
    /// receiver was dropped -- the process exited, the connection ladder leaked
    /// it, a watchdog respawn abandoned it) and return how many were reaped.
    /// Until this existed, dead parks were only ever cleared lazily on a Browser
    /// delivery (#505/#510) -- so a burst that leaves many dead parks (a crash
    /// loop, a duplicate-process flood) accumulated them indefinitely between
    /// deliveries, and once EVERY park for a token was a corpse, a browser
    /// draining them all found nothing live and 000'd on the UDP-blocked path
    /// with no QUIC fallback. `oneshot::Sender::is_closed()` detects a dropped
    /// receiver without consuming the slot, so this is a pure sweep: no live
    /// park is ever touched. The gauge is decremented per reaped slot (saturating,
    /// like delivery) so `/metrics` reflects the live pool, not the corpse pile.
    pub fn reap_dead_tcp_parks(&self) -> u64 {
        let mut agents = self.tcp_agents.lock_safe();
        let mut reaped = 0u64;
        agents.retain(|_token, queue| {
            let before = queue.len();
            queue.retain(|tx| !tx.is_closed());
            reaped += (before - queue.len()) as u64;
            !queue.is_empty()
        });
        for _ in 0..reaped {
            self.tcp_reaped.inc();
        }
        drop(agents);
        for _ in 0..reaped {
            let _ = self
                .tcp_parked_gauge
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |g| Some(g.saturating_sub(1)));
        }
        reaped
    }

    /// Wait up to `timeout` for a TCP-fallback registration to appear for
    /// `token`, returning `true` as soon as one does (or immediately, if one
    /// is already parked) and `false` if `timeout` elapses first. For a
    /// Client whose rendezvous found the Agent-side pool momentarily
    /// exhausted (a real browser's burst of parallel connections can exceed
    /// the pool size for a few milliseconds even though a worker is about to
    /// cycle free) -- a short, bounded wait here turns what would otherwise
    /// be a hard connection failure into a brief, invisible delay.
    ///
    /// Race-free: `park_tcp_agent` uses `Notify::notify_one`, which stores a
    /// permit when called with nobody currently waiting, so a park() that
    /// lands between this method's `has_tcp_agent` check and its `notified()`
    /// call is never missed (see `park_tcp_agent`'s doc comment).
    pub async fn wait_for_tcp_agent(&self, token: &RoutingToken, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.has_tcp_agent(token) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            // A wakeup here may be for a different token (Notify is shared,
            // not per-token) -- loop back to the has_tcp_agent recheck above,
            // which is correct if occasionally wasteful.
            let _ = tokio::time::timeout(remaining, self.tcp_agent_parked.notified()).await;
        }
    }

    /// Record the Agent's advertised direct-path listener for `token` (M11.4b):
    /// the address and cert DER a Client uses to connect directly. Returns
    /// `false` (and records nothing) for a revoked token (#665) -- unlike
    /// every other arm ('A'/'K'/'H'), this one had no revocation check at
    /// all, so a revoked Agent's own reconnect loop could deterministically
    /// (no race needed) keep re-advertising a direct endpoint forever, which
    /// [`Self::direct_endpoint`] would then hand to any token-bearing client,
    /// bypassing `until_revoked()` (which only guards edge-mediated splices)
    /// entirely -- a client dialing that endpoint reaches the origin P2P
    /// directly. Checked under `registration_lock` for the same reason as
    /// [`register_host`](Self::register_host)'s own #411 revocation check:
    /// one lock hold, not a separate check every caller has to remember.
    pub fn advertise_direct(&self, token: RoutingToken, addr: SocketAddr, cert: Vec<u8>) -> bool {
        let _guard = self.registration_lock.lock_safe();
        if self.is_revoked(&token) {
            return false;
        }
        self.direct.write_safe().insert(token, (addr, cert));
        true
    }

    /// The Agent's advertised direct-path `(addr, cert)` for `token`, if any --
    /// `None` (the same "nothing advertised" sentinel) for a revoked token
    /// (#665), even if a stale entry somehow still exists in `self.direct`.
    /// Belt-and-suspenders alongside [`Self::advertise_direct`]'s own refusal:
    /// `revoke_token`/`remove_locked` already sweep `self.direct` on revoke,
    /// so in the steady state this never has anything to filter -- this
    /// closes the same class of gap for any future direct-map write path that
    /// forgets the revocation check the way this one originally did.
    pub fn direct_endpoint(&self, token: &RoutingToken) -> Option<(SocketAddr, Vec<u8>)> {
        if self.is_revoked(token) {
            return None;
        }
        self.direct.read_safe().get(token).cloned()
    }

    /// Register an Agent tunnel serving `token`, returning a **registration id**.
    /// Multiple Agents may register the same token for redundancy/failover (#8);
    /// the id lets exactly this registration be evicted (via
    /// [`remove_registration`](Self::remove_registration)) when its connection
    /// drops, without disturbing the other Agents serving the token.
    pub fn register(&self, token: RoutingToken, handle: H) -> u64 {
        let _guard = self.registration_lock.lock_safe();
        self.register_locked(token, handle)
    }

    /// Shared by [`register`](Self::register) and
    /// [`register_with_candidate`](Self::register_with_candidate) -- assumes
    /// `registration_lock` is already held by the caller (it is NOT reentrant,
    /// so this must never call back into `register`).
    fn register_locked(&self, token: RoutingToken, handle: H) -> u64 {
        let id = self.next_reg.fetch_add(1, Ordering::Relaxed);
        let now = Self::wall_now();
        {
            let mut agents = self.agents.write_safe();
            let entry = agents.entry(token.clone()).or_default();
            if entry.is_empty() {
                self.active_tunnels_gauge.fetch_add(1, Ordering::Relaxed);
            }
            entry.push((id, handle));
        }
        self.note_connected(&token, now);
        self.total_registrations_gauge.fetch_add(1, Ordering::Relaxed);
        self.registrations.inc();
        id
    }

    /// ADR-0025 Decision 6: record `token` as connected/active as of `now` --
    /// `last_seen` unconditionally moves forward, while `connected_since` is
    /// only ever set the FIRST time this fires after a disconnect (`or_insert`,
    /// not `insert`), so a token already known to be connected keeps its real
    /// streak start rather than having it pushed forward by every subsequent
    /// registration or relay. Shared by [`register_locked`](Self::register_locked)
    /// (QUIC) and [`park_tcp_agent`](Self::park_tcp_agent) (TCP fallback) --
    /// either transport counts as "connected" (mirrors `tunnel_status`'s own
    /// `registrations > 0 || fallback_parked > 0` #544 contract), and
    /// [`note_relay`] separately keeps `last_seen` moving for an
    /// already-registered tunnel between registration events.
    fn note_connected(&self, token: &RoutingToken, now: u64) {
        self.connected_since.lock_safe().entry(token.clone()).or_insert(now);
        self.last_seen.lock_safe().insert(token.clone(), now);
    }

    /// Current wall-clock time in Unix seconds, `0` on a clock error (matches
    /// this codebase's existing `SystemTime::now()` convention, e.g.
    /// `audit_log.rs::now_secs`) -- used only for the ADR-0025 admin-console
    /// timing fields below, never for anything security-relevant.
    fn wall_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Register the Agent tunnel and record its Edge-observed peer candidate —
    /// the reflexive address a Client will hole-punch toward (M11.1). Returns the
    /// registration id (see [`register`](Self::register)).
    ///
    /// #282: the whole function now holds `registration_lock` (see its doc),
    /// which fully closes the original race this comment used to only narrow --
    /// a concurrent `remove_registration` for the same token cannot interleave
    /// with this at all anymore, so the `agents`-before-`candidates` insert
    /// order documented here is now belt-and-suspenders, not the only guard.
    pub fn register_with_candidate(
        &self,
        token: RoutingToken,
        handle: H,
        candidate: SocketAddr,
    ) -> u64 {
        let _guard = self.registration_lock.lock_safe();
        let id = self.register_locked(token.clone(), handle);
        self.candidates.write_safe().insert(token, candidate);
        id
    }

    /// The Agent's Edge-observed peer candidate for `token`, if recorded.
    pub fn candidate(&self, token: &RoutingToken) -> Option<SocketAddr> {
        self.candidates.read_safe().get(token).copied()
    }

    /// Route `token` to a live Agent tunnel handle, if any. Returns the **most
    /// recently registered** Agent, so a reconnecting Agent is preferred over its
    /// own dying registration and, with redundant Agents (#8), the newest serves
    /// (the next takes over on its drop).
    pub fn route(&self, token: &RoutingToken) -> Option<H> {
        self.agents
            .read_safe()
            .get(token)
            .and_then(|v| v.last().map(|(_, h)| h.clone()))
    }

    /// All live Agent handles for `token`, **most-recently-registered first** —
    /// the failover order for the relay: try the newest, fall back to older ones
    /// if its `open_bi()` fails (#8 R2, covers the dead-but-not-yet-evicted race).
    pub fn routes(&self, token: &RoutingToken) -> Vec<H> {
        self.agents.read_safe().get(token).map_or_else(Vec::new, |v| {
            v.iter().rev().map(|(_, h)| h.clone()).collect()
        })
    }

    /// Number of redundant Agent registrations currently serving `token` (#8).
    pub fn registration_count(&self, token: &RoutingToken) -> usize {
        self.agents.read_safe().get(token).map_or(0, Vec::len)
    }

    /// Is `token` currently connected (at least one live Agent registration)?
    /// The per-tunnel counterpart to [`active_tunnels`](Self::active_tunnels)'s
    /// fleet-wide gauge -- monitoring-feature v1 (operator decision, 2026-08-01):
    /// "connected or not" is the first piece of per-tunnel status surfaced to a
    /// tunnel's own owner (and, via the admin API, to the operator for any
    /// tunnel) -- see `crates/edge/src/admin.rs`'s `tunnel_status` route. Pure
    /// read of already-tracked state, no new bookkeeping.
    pub fn tunnel_status(&self, token: &RoutingToken) -> bool {
        self.registration_count(token) > 0
    }

    /// Distinct routing tokens with at least one live Agent — the number of
    /// tunnels the Edge is currently serving (observability gauge, #10).
    ///
    /// #359: was an O(n) scan over `agents` on every call (real cost on a
    /// frequently-scraped `/metrics` endpoint, competing with the routing hot
    /// path for the same lock). Now a lock-free O(1) read of a gauge
    /// maintained incrementally by every real mutation of `agents` --
    /// [`register_locked`](Self::register_locked)/[`remove_registration`]/[`remove`].
    pub fn active_tunnels(&self) -> usize {
        self.active_tunnels_gauge.load(Ordering::Relaxed) as usize
    }

    /// Total live Agent registrations across all tokens — redundant Agents (#8)
    /// counted separately (observability gauge, #10).
    ///
    /// #359: same lock-free O(1) gauge read as [`active_tunnels`](Self::active_tunnels),
    /// same reason.
    pub fn total_registrations(&self) -> usize {
        self.total_registrations_gauge.load(Ordering::Relaxed) as usize
    }

    /// Evict exactly the registration `id` for `token` — an Agent whose
    /// connection dropped — leaving any other redundant Agents in place (#8).
    /// The token's candidate/direct entries are cleared only when the **last**
    /// Agent for the token is gone.
    ///
    /// #282 follow-up: this now holds `registration_lock` for its entire body
    /// (see that field's doc), so a concurrent `register_with_candidate`/
    /// `register_host` for this token cannot interleave with the check-then-wipe
    /// below at all -- not narrowed, closed. The original per-map re-check this
    /// comment used to describe is gone: with the coarse lock held throughout,
    /// `agents` cannot change between the emptiness check and the wipe, so
    /// re-reading it added nothing once the lock spans both.
    pub fn remove_registration(&self, token: &RoutingToken, id: u64) {
        let _guard = self.registration_lock.lock_safe();
        let mut agents = self.agents.write_safe();
        let Some(v) = agents.get_mut(token) else { return };
        let before = v.len();
        v.retain(|(rid, _)| *rid != id);
        let removed = before - v.len();
        // #359: keep the incremental gauges in lockstep with the real removal
        // below, not just the map -- `removed` is 0 if `id` wasn't actually
        // present (a no-op retain), which must not decrement anything.
        self.total_registrations_gauge.fetch_sub(removed as u64, Ordering::Relaxed);
        if !v.is_empty() {
            return;
        }
        if removed > 0 {
            self.active_tunnels_gauge.fetch_sub(1, Ordering::Relaxed);
        }
        agents.remove(token);
        drop(agents);
        self.candidates.write_safe().remove(token);
        self.direct.write_safe().remove(token);
        // The QUIC side is gone — drop its hostname routes too (#23 BP4a), UNLESS
        // a live TCP-fallback registration for this same token still exists (#661,
        // found live via a real field trial: a token's hostname binding can be
        // served by either transport, and this function only ever looks at the
        // QUIC 'agents' map going empty. Clearing routes unconditionally here
        // wiped a perfectly healthy TCP-fallback-only tunnel's real, working
        // routing the moment an UNRELATED QUIC registration for the same token
        // (e.g. a stale reprobe connection finally detected as dead) reached
        // zero -- with nothing to automatically re-populate it until some other
        // event happened to trigger a fresh register_host call, stranding real
        // traffic for anywhere from tens of seconds to minutes with no error
        // logged that pointed at the actual cause.
        if !self.has_tcp_agent(token) {
            self.clear_hosts_for(token);
            // ADR-0025 Decision 6: same #661 reasoning as the hostname-route clear
            // just above -- the QUIC side alone going empty is not "disconnected"
            // while a TCP-fallback registration for the same token is still live,
            // so `connected_since` (which "uptime" is computed from) must not be
            // cleared out from under a tunnel that is still actually serving.
            self.connected_since.lock_safe().remove(token);
        }
    }

    /// Remove **all** Agent tunnels (and candidate + direct + tcp) for `token` —
    /// a full teardown, regardless of how many redundant Agents serve it.
    /// Holds `registration_lock` for the same #282 reason as
    /// [`remove_registration`](Self::remove_registration).
    pub fn remove(&self, token: &RoutingToken) {
        let _guard = self.registration_lock.lock_safe();
        self.remove_locked(token);
    }

    /// Shared by [`remove`](Self::remove) and [`revoke_token`](Self::revoke_token)
    /// -- assumes `registration_lock` is already held by the caller (it is NOT
    /// reentrant, so this must never call back into `remove`).
    fn remove_locked(&self, token: &RoutingToken) {
        // #359: unlike remove_registration's single-id retain, this always
        // drops the token's *entire* entry -- gauges move by however many
        // registrations it actually held, not by a flat 1, and only if it
        // was ever inserted (registration_count() > 0 -> a real, non-empty
        // entry, matching register_locked's own invariant that an entry is
        // never left empty in the map).
        if let Some(v) = self.agents.write_safe().remove(token) {
            if !v.is_empty() {
                self.active_tunnels_gauge.fetch_sub(1, Ordering::Relaxed);
                self.total_registrations_gauge.fetch_sub(v.len() as u64, Ordering::Relaxed);
            }
        }
        self.candidates.write_safe().remove(token);
        self.direct.write_safe().remove(token);
        self.tcp_agents.lock_safe().remove(token);
        self.clear_hosts_for(token);
        // ADR-0025 Decision 6: unlike `remove_registration`, this always tears
        // down BOTH transports (the `tcp_agents.remove` above), so unlike that
        // function this needs no #661 has_tcp_agent guard -- it is unconditionally
        // a full disconnect.
        self.connected_since.lock_safe().remove(token);
    }

    /// Revoke `token` (#27 RB3): tear down its live registrations and any hostname
    /// mappings, and mark it so a reconnecting Agent cannot re-register it. This
    /// is what makes a customer's "revoke" actually stop the tunnel — without the
    /// revoked set, the Agent's reconnect loop would simply register again.
    pub fn revoke_token(&self, token: &RoutingToken) {
        // #421: hold registration_lock across BOTH the revoked-insert and the
        // teardown -- otherwise a concurrent register call could read
        // `is_revoked() == false` before the insert below, then complete its
        // own (separately locked) registration AFTER this function's teardown
        // has already run, leaving the token both revoked and registered,
        // permanently (nothing else ever sweeps it again). See
        // `register_with_candidate_unless_revoked`'s own doc for the
        // registration-side half of this fix.
        let _guard = self.registration_lock.lock_safe();
        self.revoked.write_safe().insert(token.clone());
        self.remove_locked(token); // also clears the token's hostname routes (#23 BP4a)
        // #554: wake every live relay so it can re-check its own token and cut itself.
        // Dropping the registration above only stops NEW connections; an already-spliced
        // `copy_bidirectional` consults nothing and would keep carrying traffic for a
        // tunnel the customer just revoked -- measured, not assumed.
        self.revocation_tick.send_modify(|n| *n += 1);
        // #281: also drop any host_auth grant(s) for this token, so a revoked
        // token can never re-authorize a hostname bind on a later reconnect --
        // clear_hosts_for (inside remove_locked()) only wipes the *active*
        // routing table, not the separate, otherwise-permanent authorization
        // grant.
        self.clear_host_auth_for(token);
    }

    /// Whether `token` has been revoked (#27 RB3).
    pub fn is_revoked(&self, token: &RoutingToken) -> bool {
        self.revoked.read_safe().contains(token)
    }

    /// Seed the revoked set from the control plane's durable record (#327
    /// boot-time replay) — unlike [`revoke_token`](Self::revoke_token), this
    /// never calls [`remove`](Self::remove): at boot nothing is registered
    /// yet, so there's nothing to tear down, only the future re-registration
    /// to refuse.
    pub fn seed_revoked_tokens(&self, tokens: impl IntoIterator<Item = RoutingToken>) {
        let mut set = self.revoked.write_safe();
        set.extend(tokens);
    }

    /// Configure the shared admin secret that authenticates the `'R'` revoke op
    /// (#27 RB3). Set from `CT_EDGE_ADMIN_TOKEN` at startup.
    pub fn set_admin_token(&self, token: [u8; 32]) {
        *self.admin_token.lock_safe() = Some(token);
    }

    /// Configure the durable connection-source audit log (#603). `None` (the
    /// default) leaves every accept path's audit-log call a no-op -- set from
    /// `CT_EDGE_AUDIT_LOG_PATH` at startup once step 6 wires it.
    pub fn set_audit_log(&self, log: std::sync::Arc<crate::audit_log::SqliteAuditLog>) {
        *self.audit_log.lock_safe() = Some(log);
    }

    /// The configured audit log, if any (#603).
    pub fn audit_log(&self) -> Option<std::sync::Arc<crate::audit_log::SqliteAuditLog>> {
        self.audit_log.lock_safe().clone()
    }

    /// Constant-time check that `auth` matches the configured admin secret.
    /// Always `false` when no admin token is configured (revocation disabled).
    pub fn admin_revoke_ok(&self, auth: &[u8; 32]) -> bool {
        match self.admin_token.lock_safe().as_ref() {
            Some(expected) => {
                auth.iter().zip(expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
            }
            None => false,
        }
    }

    /// Register an Agent tunnel unless its token has been revoked (#27 RB3).
    /// Returns the registration id, or `None` if the token is revoked — the
    /// registration path the serve loop uses so a revoked token stays down even
    /// as its Agent keeps reconnecting.
    ///
    /// #421: checked and registered under ONE `registration_lock` hold, not a
    /// separate `is_revoked` read followed by a separately-locked `register`
    /// call — see [`register_with_candidate_unless_revoked`]'s doc for the
    /// exact TOCTOU that split shape allowed.
    pub fn register_unless_revoked(&self, token: RoutingToken, handle: H) -> Option<u64> {
        let _guard = self.registration_lock.lock_safe();
        if self.is_revoked(&token) {
            return None;
        }
        Some(self.register_locked(token, handle))
    }

    /// [`register_with_candidate`], but atomically refuses a revoked token
    /// (#411, #421): holds `registration_lock` across the revocation check AND
    /// the register itself, so a concurrent [`revoke_token`](Self::revoke_token)
    /// can't complete inside the gap between a separate check and a separate
    /// register call. Before this, `is_revoked` and the register were two
    /// independent lock acquisitions — a revoke that ran entirely between them
    /// left the token both revoked and registered, permanently (nothing else
    /// ever sweeps it again, since `revoke_token`'s own teardown had already
    /// run). Proved with a real multi-threaded stress test
    /// (`revoke_and_register_race_never_leaves_a_revoked_token_registered_421`),
    /// not just that the functions look right in isolation.
    pub fn register_with_candidate_unless_revoked(
        &self,
        token: RoutingToken,
        handle: H,
        candidate: SocketAddr,
    ) -> Option<u64> {
        let _guard = self.registration_lock.lock_safe();
        if self.is_revoked(&token) {
            return None;
        }
        let id = self.register_locked(token.clone(), handle);
        self.candidates.write_safe().insert(token, candidate);
        Some(id)
    }

    /// [`park_tcp_agent`], but atomically refuses a revoked token (#411): the
    /// TCP-fallback registration path previously had no revocation check at
    /// all, so a revoked token could still be queued as a waiting agent
    /// forever. Holds `registration_lock` across the check for the same reason
    /// as [`register_with_candidate_unless_revoked`].
    pub fn park_tcp_agent_unless_revoked(
        &self,
        token: RoutingToken,
    ) -> Option<oneshot::Receiver<BoxedStream>> {
        let _guard = self.registration_lock.lock_safe();
        if self.is_revoked(&token) {
            return None;
        }
        // #510: delegate to `park_tcp_agent` so this (the production 'A'/'K'
        // path) counts `tcp_parks`/`tcp_parked_gauge` exactly like the plain
        // path -- it used to skip both while `deliver_to_tcp_agent` always
        // decremented, wrapping the gauge to u64::MAX on first delivery.
        Some(self.park_tcp_agent(token))
    }

    /// Whether `token` currently has at least one live Agent tunnel.
    pub fn is_known(&self, token: &RoutingToken) -> bool {
        self.agents
            .read_safe()
            .get(token)
            .is_some_and(|v| !v.is_empty())
    }

    /// Whether `token` resolves to *any* registered Agent -- QUIC
    /// ([`Self::is_known`]) or TCP-fallback ([`Self::has_tcp_agent`]) (#472).
    /// This is the admission gate the rendezvous ('C') paths must run
    /// **before** [`Self::rendezvous_allowed`]: the rate limiter is keyed on
    /// the routing token the Client itself supplies, so a flooder rotating
    /// random tokens got a fresh limiter budget and a fresh map entry on
    /// every attempt when the limiter was checked first -- the per-token cap
    /// never actually engaged against that attack shape. Gating on this
    /// first means only tokens that resolve to a real tunnel ever occupy a
    /// limiter slot; an unresolvable token is rejected outright.
    pub fn is_resolvable(&self, token: &RoutingToken) -> bool {
        self.is_known(token) || self.has_tcp_agent(token)
    }
}

impl<H: Clone> Default for EdgeState<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn connection_cap_admits_up_to_max_then_sheds_and_recovers_on_release() {
        // #95/#119: the load-shedding cap admits at most `max` concurrent connections
        // (each admitted connection holds its permit for its lifetime). Over the cap
        // `try_admit` returns `None` so the accept loop sheds cheaply, and dropping a
        // permit (a connection closed) frees a slot for the next admission. This is the
        // mechanism every edge accept loop — QUIC, the TCP fallback, and the `:443` front
        // door (#119) — relies on to bound a pre-auth connection flood.
        let cap = ConnectionCap::new(2);
        assert_eq!(cap.available(), 2);
        let p1 = cap.try_admit().expect("1st admitted");
        let _p2 = cap.try_admit().expect("2nd admitted");
        assert_eq!(cap.available(), 0, "at the cap");
        assert!(cap.try_admit().is_none(), "over the cap -> shed");
        drop(p1); // a connection closed, releasing its slot
        assert_eq!(cap.available(), 1);
        let _p3 = cap.try_admit().expect("a freed slot admits the next");
        assert!(cap.try_admit().is_none(), "full again after re-admitting");
    }

    #[test]
    fn register_then_route() {
        let state = EdgeState::new();
        state.register(token(1), 42u32);
        assert_eq!(state.route(&token(1)), Some(42));
        assert!(state.is_known(&token(1)));
    }

    #[test]
    fn tunnel_status_reflects_registration_count() {
        // Monitoring feature v1 (2026-08-01): never registered -> false; one live
        // registration -> true; a second redundant one (#8) -> still true.
        let state = EdgeState::new();
        assert!(!state.tunnel_status(&token(1)), "never registered -> not connected");
        let id_a = state.register(token(1), 1u32);
        assert!(state.tunnel_status(&token(1)));
        let id_b = state.register(token(1), 2u32);
        assert!(state.tunnel_status(&token(1)), "still connected with two redundant agents");
        // Evicting one of two still leaves it connected; evicting the last does not.
        state.remove_registration(&token(1), id_a);
        assert!(state.tunnel_status(&token(1)), "one of two evicted -> still connected");
        state.remove_registration(&token(1), id_b);
        assert!(!state.tunnel_status(&token(1)), "last one evicted -> not connected");
        // A different, never-registered token is unaffected.
        assert!(!state.tunnel_status(&token(2)));
    }

    #[test]
    fn tunnel_bytes_accumulate_per_token_and_split_by_direction() {
        // Monitoring feature byte counters (2026-08-01): per-token
        // client->agent / agent->client totals, additive across multiple
        // relays, isolated per token, unaffected by registration state
        // (note_relay never touches `agents`).
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.tunnel_bytes(&token(1)), (0, 0), "never relayed -> (0, 0)");
        state.note_relay(&token(1), 100, 40, RelayKind::DataPlane);
        assert_eq!(state.tunnel_bytes(&token(1)), (100, 40));
        state.note_relay(&token(1), 25, 5, RelayKind::DataPlane);
        assert_eq!(state.tunnel_bytes(&token(1)), (125, 45), "accumulates across relays");
        // A different token has its own independent counters.
        assert_eq!(state.tunnel_bytes(&token(2)), (0, 0));
        state.note_relay(&token(2), 7, 3, RelayKind::DataPlane);
        assert_eq!(state.tunnel_bytes(&token(2)), (7, 3));
        assert_eq!(state.tunnel_bytes(&token(1)), (125, 45), "token 1 unaffected by token 2's relay");
        // The fleet-wide total (#10 O2) still reflects both directions of both tokens.
        assert_eq!(state.relay_bytes_total(), 125 + 45 + 7 + 3);
    }

    fn wall_now_for_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn connected_since_is_set_on_first_registration_and_cleared_on_full_disconnect() {
        // ADR-0025 Decision 6: the admin console's "uptime" input.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(60);
        assert_eq!(state.connection_timing(&t), (None, None), "never registered -> no timing at all");

        let before = wall_now_for_test();
        let id_a = state.register(t.clone(), 1);
        let after = wall_now_for_test();
        let (since, seen) = state.connection_timing(&t);
        let since = since.expect("connected_since set on first registration");
        let seen = seen.expect("last_seen set on first registration");
        assert!(since >= before && since <= after, "connected_since is real wall-clock, not a placeholder");
        assert_eq!(since, seen, "first-ever activity: both timestamps coincide");

        // A second, redundant registration (#8) must NOT push connected_since
        // forward -- the streak already started with the first agent.
        let id_b = state.register(t.clone(), 2);
        assert_eq!(state.connection_timing(&t).0, Some(since), "redundant registration does not reset the streak start");

        // Evicting one of two redundant agents leaves the tunnel connected.
        state.remove_registration(&t, id_a);
        assert_eq!(state.connection_timing(&t).0, Some(since), "still connected -> streak start unchanged");

        // Evicting the LAST agent -> fully disconnected -> connected_since is
        // cleared, but last_seen is NOT (the whole point of "last seen").
        state.remove_registration(&t, id_b);
        let (since3, seen3) = state.connection_timing(&t);
        assert_eq!(since3, None, "fully disconnected -> no live streak to report");
        assert!(seen3.is_some(), "last-seen must survive disconnect -- that's what it's for");
    }

    #[test]
    fn park_tcp_agent_also_sets_connected_since_and_last_seen_for_a_fallback_only_tunnel() {
        // #544's own "either transport counts as connected" contract, extended to
        // the ADR-0025 timing fields -- a fallback-only Agent must not be invisible
        // to the admin console's uptime column just because it never used QUIC.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(61);
        assert_eq!(state.connection_timing(&t), (None, None));
        let _rx = state.park_tcp_agent(t.clone());
        let (since, seen) = state.connection_timing(&t);
        assert!(since.is_some() && seen.is_some());
    }

    #[test]
    fn connected_since_survives_a_quic_teardown_while_a_tcp_fallback_registration_is_still_live_661() {
        // Same #661 scenario `remove_registration`'s own hosts-clearing guard
        // already covers -- connected_since must not be wiped out from under a
        // tunnel that is still actually serving over the OTHER transport.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(62);
        let id = state.register(t.clone(), 1);
        let since_before = state.connection_timing(&t).0.expect("connected via QUIC");
        let _rx = state.park_tcp_agent(t.clone()); // also live over TCP fallback now
        state.remove_registration(&t, id); // QUIC side drops...
        assert_eq!(
            state.connection_timing(&t).0,
            Some(since_before),
            "TCP fallback still live -> streak must not reset (#661)"
        );
    }

    #[test]
    fn note_relay_advances_activity_without_fabricating_or_resetting_a_connection() {
        let state: EdgeState<u32> = EdgeState::new();
        // A relay against an ALREADY-registered token is activity, not a new
        // connection -- connected_since must not move.
        let registered = token(63);
        state.register(registered.clone(), 1);
        let since = state.connection_timing(&registered).0.unwrap();
        state.note_relay(&registered, 10, 5, RelayKind::DataPlane);
        assert_eq!(state.connection_timing(&registered).0, Some(since));

        // A relay against a token that was NEVER registered (note_relay never
        // touches `agents`, per its own doc comment) must set last_seen but must
        // NOT fabricate a connected_since -- relaying alone proves activity, not
        // a live registration.
        let never_registered = token(64);
        state.note_relay(&never_registered, 1, 1, RelayKind::DataPlane);
        let (since, seen) = state.connection_timing(&never_registered);
        assert_eq!(since, None, "relaying alone is not a registration");
        assert!(seen.is_some());
    }

    #[test]
    fn remove_clears_connected_since_unconditionally_but_keeps_last_seen() {
        // Unlike `remove_registration` (single-id, #661-guarded), `remove` tears
        // down BOTH transports at once -- always a real full disconnect.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(65);
        state.register(t.clone(), 1);
        let _rx = state.park_tcp_agent(t.clone());
        state.remove(&t);
        let (since, seen) = state.connection_timing(&t);
        assert_eq!(since, None, "remove() is a full disconnect regardless of transport");
        assert!(seen.is_some(), "last-seen still survives");
    }

    #[test]
    fn rendezvous_rate_limit_off_by_default_then_caps_per_token_per_window() {
        let state: EdgeState<u32> = EdgeState::new();
        // Off by default: any number of rendezvous is allowed.
        for _ in 0..100 {
            assert!(state.rendezvous_allowed(&token(1), 0), "no cap until enabled (#86)");
        }
        // Enable a cap of 2 per window.
        state.set_rendezvous_limit(2);
        assert!(state.rendezvous_allowed(&token(1), 0), "1st allowed");
        assert!(state.rendezvous_allowed(&token(1), 0), "2nd allowed");
        assert!(!state.rendezvous_allowed(&token(1), 0), "3rd in the window rejected");
        // A different token has its own budget.
        assert!(state.rendezvous_allowed(&token(2), 0), "per-token budget is independent");
        // A new window resets the budget.
        assert!(state.rendezvous_allowed(&token(1), 1), "next window resets the cap");
    }

    #[test]
    fn host_bind_authorization_gates_binds_when_required() {
        // #23 BP4b: with authorization required, only the CP-authorized (host,
        // token) pair may bind; unauthorized host or wrong token is refused.
        let state = EdgeState::<u32>::new();
        // Legacy (not required): any bind allowed.
        assert!(state.host_bind_allowed("x.test", &token(1)));

        state.require_host_auth();
        assert!(!state.host_bind_allowed("x.test", &token(1)), "nothing allowed until authorized");

        state.authorize_host("X.Test", token(1)); // case-insensitive
        assert!(state.host_bind_allowed("x.test", &token(1)), "authorized pair allowed");
        assert!(!state.host_bind_allowed("x.test", &token(2)), "wrong token refused");
        assert!(!state.host_bind_allowed("y.test", &token(1)), "unauthorized host refused");
    }

    #[test]
    fn dump_host_auth_reflects_current_authorizations_or_none_if_never_required() {
        let state = EdgeState::<u32>::new();
        assert_eq!(state.dump_host_auth(), None, "authorization never required -> None, not empty");

        state.require_host_auth();
        assert_eq!(state.dump_host_auth(), Some(vec![]), "required but nothing authorized yet -> empty");

        state.authorize_host("a.test", token(1));
        state.authorize_host("b.test", token(2));
        let mut dump = state.dump_host_auth().unwrap();
        dump.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(dump, vec![("a.test".to_string(), token(1)), ("b.test".to_string(), token(2))]);
    }

    #[test]
    fn unauthorize_host_drops_exactly_that_entry_281() {
        let state = EdgeState::<u32>::new();
        state.require_host_auth();
        state.authorize_host("a.test", token(1));
        state.authorize_host("b.test", token(2));

        state.unauthorize_host("a.test");
        assert!(!state.host_bind_allowed("a.test", &token(1)), "de-authorized host no longer binds");
        assert!(state.host_bind_allowed("b.test", &token(2)), "the other authorization is untouched");

        // A no-op on an unknown host, or when authorization was never required.
        state.unauthorize_host("never-authorized.test");
        let fresh = EdgeState::<u32>::new();
        fresh.unauthorize_host("x.test"); // must not panic
    }

    #[test]
    fn revoke_token_drops_its_host_auth_grants_so_a_later_reconnect_cant_rebind_281() {
        // #281: authorize_host's grant otherwise persisted forever -- a customer
        // revoking their tunnel at the control plane must also stop a
        // still-reconnecting Agent from re-binding a hostname it was
        // previously (but no longer) authorized for.
        let state = EdgeState::<u32>::new();
        state.require_host_auth();
        state.authorize_host("app.example.com", token(1));
        state.authorize_host("other.example.com", token(2));
        assert!(state.host_bind_allowed("app.example.com", &token(1)));

        state.revoke_token(&token(1));

        assert!(
            !state.host_bind_allowed("app.example.com", &token(1)),
            "the revoked token's host authorization is gone, not just its live registration"
        );
        assert!(
            state.host_bind_allowed("other.example.com", &token(2)),
            "an unrelated token's authorization survives"
        );
    }

    #[test]
    fn host_normalization_collapses_trailing_dot_and_rejects_junk() {
        // #23 BP4b-d: bind/lookup normalize identically; malformed hosts refused.
        let state = EdgeState::<u32>::new();
        assert!(state.register_host("App.Example.", token(7)).is_ok());
        assert_eq!(state.route_host("app.example"), Some(token(7)));
        assert_eq!(state.route_host("app.example."), Some(token(7)), "trailing dot collapses");
        assert_eq!(
            state.register_host("bad host", token(8)),
            Err(HostBindRefusal::MalformedHostname),
            "malformed hostname refused at bind"
        );
        assert_eq!(state.route_host("bad host"), None);
    }

    #[test]
    fn cert_tier_defaults_to_not_gelb_and_is_toggleable_both_ways() {
        // #233: a fresh boot (or any hostname the control plane never pushed a
        // tier for) must default to false -- that's what keeps every existing,
        // already-gruen hostname on ordinary passthrough with zero config.
        let state = EdgeState::<u32>::new();
        assert!(!state.is_gelb("app.example"), "never marked -> not gelb, the safe default");

        state.set_cert_tier("App.Example.", true);
        assert!(state.is_gelb("app.example"), "normalized the same way register_host/route_host do");

        // Gelb -> Grün: the control plane reverts the tier once the hostname's
        // own real cert exists, and passthrough must resume.
        state.set_cert_tier("app.example", false);
        assert!(!state.is_gelb("app.example"));

        // A malformed hostname is a silent no-op, same as register_host.
        state.set_cert_tier("bad host", true);
        assert!(!state.is_gelb("bad host"));
    }

    #[test]
    fn host_binding_is_takeover_safe_and_cleared_on_agent_drop() {
        // #23 BP4a: first bind wins; a conflicting bind can't steal the route;
        // the binding is cleared when the tunnel's last agent drops.
        let state = EdgeState::new();
        let (t1, t2) = (token(1), token(2));
        let id = state.register(t1.clone(), 5u32);

        // First bind wins; rebinding the SAME token (reconnect) is idempotent-OK.
        assert!(state.register_host("app.example", t1.clone()).is_ok());
        assert!(state.register_host("app.example", t1.clone()).is_ok(), "same-token rebind ok");
        assert_eq!(state.route_host("app.example"), Some(t1.clone()));

        // #360: bind a SECOND, different hostname to the same token. This is
        // the case the hosts_by_token reverse index has to get right -- one
        // token owning multiple hostnames, all of which must be found and
        // cleared on teardown, not just the first one ever bound.
        assert!(state.register_host("app-2.example", t1.clone()).is_ok());
        assert_eq!(state.route_host("app-2.example"), Some(t1.clone()));

        // A conflicting bind to a DIFFERENT token is refused; route untouched.
        assert_eq!(
            state.register_host("app.example", t2.clone()),
            Err(HostBindRefusal::BoundToDifferentToken),
            "takeover refused"
        );
        assert_eq!(state.route_host("app.example"), Some(t1.clone()), "original route intact");

        // When the tunnel's last agent drops, BOTH stale host routes are
        // cleared -- proving the reverse index tracked the full set owned by
        // this token, not just the most recently bound one.
        state.remove_registration(&t1, id);
        assert_eq!(state.route_host("app.example"), None, "host route cleared on drop");
        assert_eq!(state.route_host("app-2.example"), None, "second host route also cleared on drop");

        // ...so the hostnames are now free for a different tunnel to claim.
        assert!(state.register_host("app.example", t2.clone()).is_ok());
        assert_eq!(state.route_host("app.example"), Some(t2));
    }

    #[test]
    fn admin_revoke_ok_requires_the_configured_secret() {
        // #27 RB3: the 'R' revoke op authenticates against CT_EDGE_ADMIN_TOKEN.
        let state = EdgeState::<u32>::new();
        let secret = [0x11u8; 32];
        // Unconfigured -> revocation disabled, every auth rejected.
        assert!(!state.admin_revoke_ok(&secret));
        state.set_admin_token(secret);
        assert!(state.admin_revoke_ok(&secret), "correct secret accepted");
        let mut wrong = secret;
        wrong[31] ^= 1;
        assert!(!state.admin_revoke_ok(&wrong), "wrong secret rejected");
    }

    #[test]
    fn revoke_token_drops_registration_and_blocks_reregistration() {
        // #27 RB3: revoke tears down the live tunnel and refuses re-registration,
        // so a reconnecting agent can't defeat a customer's "revoke".
        let state = EdgeState::new();
        let t = token(9);
        let _ = state.register_host("app.example", t.clone());
        state.register(t.clone(), 1u32);
        state.register(t.clone(), 4u32); // a second, redundant registration (#8)
        assert_eq!(state.active_tunnels(), 1);
        assert_eq!(state.total_registrations(), 2, "both redundant registrations counted");

        state.revoke_token(&t);
        // #359: remove() tears down the whole token's entry in one shot --
        // both gauges must reflect the real count that was actually there,
        // not just decrement by one regardless of how many registrations
        // the token held.
        assert_eq!(state.active_tunnels(), 0, "revoke drops the live registration");
        assert_eq!(state.total_registrations(), 0, "revoke drops every redundant registration too");
        assert!(state.is_revoked(&t));
        assert_eq!(state.route_host("app.example"), None, "hostname mapping cleared");

        // A reconnecting agent cannot re-register the revoked token.
        assert!(state.register_unless_revoked(t.clone(), 2u32).is_none());
        assert_eq!(state.active_tunnels(), 0, "still no tunnel after a blocked re-register");

        // A different (unrevoked) token registers normally.
        assert!(state.register_unless_revoked(token(10), 3u32).is_some());
        assert_eq!(state.active_tunnels(), 1);
    }

    #[test]
    fn revoke_clears_the_gelb_tier_so_a_re_bound_hostname_starts_neutral_426() {
        // #426: `gelb_hosts` is keyed purely by hostname (Gelb/Grün is a
        // property of the hostname's cert tier, not of any one token) --
        // `revoke_token`'s teardown never touched it, so a re-bound hostname
        // silently inherited whatever tier flag the PREVIOUS tenant's token
        // left behind, independent of the new tenant's own actual cert state.
        let state = EdgeState::<u32>::new();
        let old_owner = token(11);
        let _ = state.register_host("shared.example", old_owner.clone());
        state.set_cert_tier("shared.example", true); // old tenant is Gelb
        assert!(state.is_gelb("shared.example"));

        state.revoke_token(&old_owner);
        assert!(
            !state.is_gelb("shared.example"),
            "revoke must clear the hostname's tier flag, not just its routing/auth"
        );

        // A different tenant/token now binds the SAME hostname (e.g. after
        // re-provisioning) -- it must start neutral (not-Gelb), not inherit
        // the old tenant's tier.
        let new_owner = token(12);
        assert!(state.register_host("shared.example", new_owner).is_ok());
        assert!(
            !state.is_gelb("shared.example"),
            "a freshly re-bound hostname must never inherit a previous tenant's Gelb/Grün tier"
        );
    }

    #[test]
    fn register_with_candidate_unless_revoked_refuses_a_revoked_token_411_421() {
        // #421: the atomic QUIC-role-'A' registration path -- direct functional
        // check that a revoked token is refused, distinct from the concurrency
        // stress test below which proves it can't be raced around.
        let state = EdgeState::new();
        let t = token(1);
        state.revoke_token(&t);
        assert!(
            state
                .register_with_candidate_unless_revoked(t.clone(), 1u32, "127.0.0.1:1".parse().unwrap())
                .is_none(),
            "a revoked token must never acquire a live registration"
        );
        assert!(!state.is_known(&t));

        let live = token(2);
        assert!(
            state
                .register_with_candidate_unless_revoked(live.clone(), 2u32, "127.0.0.1:2".parse().unwrap())
                .is_some(),
            "an unrevoked token registers normally"
        );
        assert!(state.is_known(&live));
    }

    #[test]
    fn park_tcp_agent_unless_revoked_refuses_a_revoked_token_411() {
        // #411: the TCP-fallback registration path previously had NO revocation
        // check at all -- `park_tcp_agent` would happily queue a revoked token
        // forever. Direct functional check that the new atomic entry point
        // refuses it instead.
        let state = EdgeState::<u32>::new();
        let t = token(3);
        state.revoke_token(&t);
        assert!(
            state.park_tcp_agent_unless_revoked(t).is_none(),
            "a revoked token must never be parked as a waiting TCP-fallback agent"
        );

        let live = token(4);
        assert!(
            state.park_tcp_agent_unless_revoked(live).is_some(),
            "an unrevoked token parks normally"
        );
    }

    #[test]
    fn register_host_refuses_a_revoked_token_411() {
        // #411: neither the QUIC 'H' arm nor the TCP-fallback 'B' arm checked
        // revocation before calling `register_host` -- fixed inside
        // `register_host` itself so no caller can forget it.
        let state = EdgeState::<u32>::new();
        let t = token(5);
        state.revoke_token(&t);
        assert_eq!(
            state.register_host("revoked.example", t),
            Err(HostBindRefusal::Revoked),
            "a revoked token must never be able to bind a public hostname"
        );
        assert_eq!(state.route_host("revoked.example"), None);
    }

    #[test]
    fn revoke_and_register_race_never_leaves_a_revoked_token_registered_421() {
        // #421: real, multi-threaded proof that the TOCTOU this issue described
        // is actually closed, not just that the individual functions look right
        // in isolation. Before the fix, `register_with_candidate_unless_revoked`'s
        // predecessor did a bare `is_revoked` read, then a SEPARATE
        // `register_with_candidate` call with no lock spanning both -- a
        // concurrent `revoke_token` that ran entirely inside that gap left the
        // token both revoked AND registered, permanently (nothing ever swept it
        // again). Hammering register/revoke concurrently from real OS threads
        // and asserting the invariant after every round is the same "prove the
        // actual property, not just that code changed" style used elsewhere
        // this session for concurrency claims.
        use std::sync::Arc;

        let state = Arc::new(EdgeState::new());

        // A FRESH token every round (revocation is permanent in the real API,
        // so reusing one token would only genuinely race on round 0 -- every
        // later round would see `is_revoked` already true before its threads
        // even start, which can't exercise the timing-sensitive window this
        // test exists to stress).
        for round in 0u32..300 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&round.to_be_bytes());
            let t = RoutingToken(bytes);

            let mut handles = Vec::new();
            for i in 0..4u16 {
                let state = Arc::clone(&state);
                let t = t.clone();
                handles.push(std::thread::spawn(move || {
                    let addr = format!("127.0.0.1:{}", 10_000 + i).parse().unwrap();
                    let _ = state.register_with_candidate_unless_revoked(t, u32::from(i), addr);
                }));
            }
            {
                let state = Arc::clone(&state);
                let t = t.clone();
                handles.push(std::thread::spawn(move || {
                    state.revoke_token(&t);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }

            // The invariant this issue exists to guarantee: once revoked (and
            // every round DOES revoke it), the token can never be found with a
            // live registration, no matter how the register/revoke threads in
            // this round happened to interleave.
            assert!(state.is_revoked(&t), "sanity: revoke always runs each round");
            assert!(
                !state.is_known(&t),
                "round {round}: a revoked token ended up with a live registration -- the race is not closed"
            );
        }
    }

    #[test]
    fn revoke_and_browser_plane_admit_race_never_leaves_a_revoked_token_parked_665() {
        // #665: `admit_tcp_agent_b` (serve.rs's shared 'B'/'L'/'F' admission body)
        // calls `register_host` then, separately, parks -- two independent
        // `registration_lock` acquisitions, not one held across both. Before this
        // fix the second step was a plain `park_tcp_agent`, which never checks
        // revocation at all, so a `revoke_token` landing in the gap between the
        // two acquisitions left a revoked token parked as a live waiting Agent
        // anyway. Same "prove the actual property with real threads" style as
        // #421's `revoke_and_register_race_never_leaves_a_revoked_token_registered_421`
        // -- this races the exact two-call composition `admit_tcp_agent_b` now
        // performs (`register_host` then `park_tcp_agent_unless_revoked`), not
        // just one of the two primitives in isolation.
        use std::sync::Arc;

        let state: Arc<EdgeState<u32>> = Arc::new(EdgeState::new());

        for round in 0u32..300 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&round.to_be_bytes());
            let t = RoutingToken(bytes);
            let host = format!("round-{round}.example");
            state.authorize_host(&host, t.clone());

            let mut handles = Vec::new();
            {
                let state = Arc::clone(&state);
                let t = t.clone();
                let host = host.clone();
                handles.push(std::thread::spawn(move || {
                    // Mirrors admit_tcp_agent_b's own two-step body exactly.
                    if state.register_host(&host, t.clone()).is_ok() {
                        let _ = state.park_tcp_agent_unless_revoked(t);
                    }
                }));
            }
            {
                let state = Arc::clone(&state);
                let t = t.clone();
                handles.push(std::thread::spawn(move || {
                    state.revoke_token(&t);
                }));
            }
            for h in handles {
                h.join().unwrap();
            }

            assert!(state.is_revoked(&t), "sanity: revoke always runs each round");
            assert!(
                !state.has_tcp_agent(&t),
                "round {round}: a revoked token ended up parked as a live waiting TCP-fallback agent -- the race is not closed"
            );
        }
    }

    #[test]
    fn seed_revoked_tokens_blocks_registration_without_touching_a_live_one_327() {
        // #327: boot-time replay from the control plane's durable record must
        // block re-registration of a previously-revoked token, exactly like a
        // live `revoke_token` call would -- but must never tear down anything,
        // since at boot there's nothing registered yet to tear down.
        let state = EdgeState::new();
        let seeded = token(20);
        let live = token(21);
        assert_eq!(state.active_tunnels(), 0, "sanity: nothing registered before seeding");

        state.seed_revoked_tokens(vec![seeded.clone()]);
        assert!(state.is_revoked(&seeded));
        assert_eq!(state.active_tunnels(), 0, "seeding never registers or removes anything");

        // The seeded token can't be registered (mirrors a live revoke's effect).
        assert!(state.register_unless_revoked(seeded, 1u32).is_none());
        // An unrelated, unrevoked token still registers normally.
        assert!(state.register_unless_revoked(live.clone(), 2u32).is_some());
        assert!(!state.is_revoked(&live));
        assert_eq!(state.active_tunnels(), 1);
    }

    #[test]
    fn route_unknown_is_none() {
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.route(&token(9)), None);
        assert!(!state.is_known(&token(9)));
    }

    #[test]
    fn redundant_agents_fail_over_on_registration_drop() {
        // #8 R1: two Agents register the same token; routing prefers the most
        // recent, and evicting one registration fails over to the other without
        // disturbing it — the whole point of Agent redundancy.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(1);
        let a = state.register(t.clone(), 10); // Agent A
        let b = state.register(t.clone(), 20); // Agent B (more recent)
        assert_eq!(state.registration_count(&t), 2, "both agents registered");
        assert_eq!(state.route(&t), Some(20), "most-recent agent serves");
        // #359: one token, two redundant registrations -- active_tunnels counts
        // the token once, total_registrations counts each real registration.
        assert_eq!(state.active_tunnels(), 1, "one distinct token, however many redundant agents");
        assert_eq!(state.total_registrations(), 2);

        // Agent B's connection drops → evict just B → fail over to A.
        state.remove_registration(&t, b);
        assert_eq!(state.route(&t), Some(10), "failover to the surviving agent");
        assert_eq!(state.registration_count(&t), 1);
        assert!(state.is_known(&t), "tunnel still up on one agent");
        assert_eq!(state.active_tunnels(), 1, "the token is still live on the surviving agent");
        assert_eq!(state.total_registrations(), 1);

        // Evicting an already-gone id is a no-op (idempotent) -- must not
        // double-decrement the gauges for a registration that was never real.
        state.remove_registration(&t, b);
        assert_eq!(state.route(&t), Some(10));
        assert_eq!(state.active_tunnels(), 1, "a no-op eviction must not touch the gauge");
        assert_eq!(state.total_registrations(), 1, "a no-op eviction must not touch the gauge");

        // Last agent drops → tunnel is gone and its metadata is cleaned up.
        state.remove_registration(&t, a);
        assert_eq!(state.route(&t), None, "no agents left");
        assert!(!state.is_known(&t));
        assert_eq!(state.registration_count(&t), 0);
        assert_eq!(state.active_tunnels(), 0, "the last real registration is gone");
        assert_eq!(state.total_registrations(), 0);
    }

    #[test]
    fn remove_drops_route() {
        let state = EdgeState::new();
        state.register(token(1), 42u32);
        state.remove(&token(1));
        assert_eq!(state.route(&token(1)), None);
        assert!(!state.is_known(&token(1)));
    }

    #[test]
    fn register_with_candidate_records_and_routes() {
        let state = EdgeState::new();
        let cand: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
        state.register_with_candidate(token(2), 7u32, cand);
        assert_eq!(state.route(&token(2)), Some(7), "handle routable");
        assert_eq!(state.candidate(&token(2)), Some(cand), "candidate recorded");
    }

    #[test]
    fn remove_registration_never_leaves_a_live_agent_without_its_candidate_282() {
        // #282: a concurrent register_with_candidate that races a remove_registration
        // teardown for the same token must never end up "live in agents but missing
        // its candidate/hosts" -- exercised as a stress test (genuine thread
        // concurrency, not a hand-crafted single interleaving) because the four maps
        // involved are independent mutexes with no combined lock; this can't assert
        // zero residual race window (documented on remove_registration itself), only
        // that the invariant holds under real contention across many iterations.
        use std::sync::Arc;
        let state = Arc::new(EdgeState::<u32>::new());
        let t = token(42);
        let cand: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();

        std::thread::scope(|scope| {
            for _ in 0..4 {
                let state = Arc::clone(&state);
                let t = t.clone();
                scope.spawn(move || {
                    for i in 0..200u64 {
                        let id = state.register_with_candidate(t.clone(), i as u32, cand);
                        // The invariant this bug violated: while this registration is
                        // live, its candidate must be present.
                        if state.registration_count(&t) > 0 {
                            assert!(
                                state.candidate(&t).is_some(),
                                "a live registration with no candidate (#282 regression)"
                            );
                        }
                        state.remove_registration(&t, id);
                    }
                });
            }
        });
    }

    #[test]
    fn remove_registration_leaves_hostname_routing_intact_when_a_tcp_fallback_agent_is_still_live_661() {
        // #661: found live via a real field trial -- a token's hostname binding
        // can be served by EITHER transport (QUIC 'agents' or the TCP-fallback
        // pool), but remove_registration used to decide whether to wipe the
        // hostname route by looking ONLY at whether the QUIC 'agents' map for
        // this token had gone empty. A perfectly healthy, still-parked
        // TCP-fallback registration for the SAME token got its real, working
        // hostname routing wiped the moment an unrelated QUIC registration
        // (e.g. a stale reprobe connection finally detected as dead) reached
        // zero -- stranding real traffic with nothing to automatically
        // re-populate the route.
        let state = EdgeState::<u32>::new();
        let t = token(61);
        let cand: std::net::SocketAddr = "203.0.113.9:4433".parse().unwrap();

        // A live TCP-fallback registration for this token -- keep the receiver
        // alive so `has_tcp_agent` sees it as live, same as a real parked pool
        // worker awaiting a Client.
        let _parked = state.park_tcp_agent(t.clone());
        assert!(state.has_tcp_agent(&t), "the park above must register as live");

        // The token's ONLY hostname binding was actually established via the
        // TCP-fallback ('B'/'L') path in the real bug -- register_host is the
        // same call either transport uses.
        state.register_host("kali.test", t.clone()).expect("hostname binds cleanly");
        assert_eq!(state.route_host("kali.test"), Some(t.clone()), "sanity: routed before teardown");

        // A SEPARATE, unrelated QUIC registration for the same token (e.g. a
        // stale reprobe) now gets torn down.
        let id = state.register_with_candidate(t.clone(), 1u32, cand);
        state.remove_registration(&t, id);

        assert_eq!(
            state.route_host("kali.test"),
            Some(t.clone()),
            "a live TCP-fallback registration must keep the hostname routed even after \
             an unrelated QUIC registration for the same token is torn down (#661 regression)"
        );
    }

    #[test]
    fn candidate_unknown_is_none() {
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.candidate(&token(9)), None);
    }

    #[test]
    fn remove_drops_candidate() {
        let state = EdgeState::new();
        let cand: std::net::SocketAddr = "198.51.100.4:4433".parse().unwrap();
        state.register_with_candidate(token(3), 1u32, cand);
        state.remove(&token(3));
        assert_eq!(state.candidate(&token(3)), None);
    }

    #[test]
    fn advertise_and_look_up_direct_endpoint() {
        let state: EdgeState<u32> = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        state.advertise_direct(token(4), addr, vec![1, 2, 3, 4]);
        assert_eq!(state.direct_endpoint(&token(4)), Some((addr, vec![1, 2, 3, 4])));
        assert_eq!(state.direct_endpoint(&token(5)), None, "unknown → None");
    }

    #[test]
    fn remove_drops_direct_endpoint() {
        let state = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        state.advertise_direct(token(6), addr, vec![9, 9]);
        state.register(token(6), 1u32);
        state.remove(&token(6));
        assert_eq!(state.direct_endpoint(&token(6)), None);
    }

    /// #665: unlike every other registration arm ('A'/'K'/'H'), `advertise_direct`
    /// had no revocation check at all -- a revoked Agent's own reconnect loop
    /// could deterministically (no race needed) keep re-advertising a direct
    /// endpoint forever, which a client could then dial to reach the origin P2P
    /// directly, bypassing `until_revoked()` entirely.
    #[test]
    fn advertise_direct_refuses_a_revoked_token_665() {
        let state: EdgeState<u32> = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let revoked = token(7);
        state.revoke_token(&revoked);
        assert!(
            !state.advertise_direct(revoked.clone(), addr, vec![1, 2, 3]),
            "a revoked token must never acquire a live direct-path advertisement"
        );
        assert_eq!(state.direct_endpoint(&revoked), None, "the refused advertisement must not be recorded");

        let live = token(8);
        assert!(state.advertise_direct(live.clone(), addr, vec![4, 5, 6]), "an unrevoked token advertises normally");
        assert_eq!(state.direct_endpoint(&live), Some((addr, vec![4, 5, 6])));
    }

    /// #665: belt-and-suspenders alongside `advertise_direct`'s own refusal --
    /// even if a stale entry somehow still exists in `self.direct` for a token
    /// that gets revoked afterward, `direct_endpoint` must never hand it out.
    #[test]
    fn direct_endpoint_returns_none_for_a_revoked_token_even_with_a_stale_entry_665() {
        let state: EdgeState<u32> = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let t = token(9);
        assert!(state.advertise_direct(t.clone(), addr, vec![7, 7]), "advertised while still live");
        assert_eq!(state.direct_endpoint(&t), Some((addr, vec![7, 7])), "readable before revoke");

        state.revoke_token(&t);
        assert_eq!(
            state.direct_endpoint(&t),
            None,
            "must return the no-endpoint sentinel once revoked, even though revoke_token's own \
             self.direct sweep already independently removes the entry"
        );
    }

    #[tokio::test]
    async fn tcp_agent_park_then_deliver_hands_over_the_stream() {
        // issue #3 / P1.2c-3: a parked TCP agent receives the Client's stream.
        let state: EdgeState<u32> = EdgeState::new();
        let rx = state.park_tcp_agent(token(7));
        assert!(state.has_tcp_agent(&token(7)));
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent(&token(7), client).is_ok(),
            "delivery to a parked agent succeeds"
        );
        assert!(rx.await.is_ok(), "the agent receives the client stream");
        assert!(!state.has_tcp_agent(&token(7)), "registration consumed (single-use)");
    }

    #[tokio::test]
    async fn the_tcp_fallback_path_is_visible_in_metrics_not_silently_invisible() {
        // Live incident, 2026-08-13 (sort.bunsenbrenner.org): the TLS-TCP fallback
        // path used to touch NO metric at all -- park_tcp_agent writes to its own
        // `tcp_agents` map, while only the QUIC `register_locked` bumped
        // registrations/active_tunnels/total_registrations. An Agent reachable only
        // over :4433 (the normal case when a network blocks the QUIC ports) was
        // therefore indistinguishable, in every metric, from an Agent that never
        // connected at all: the counters stayed flat no matter how often it
        // reconnected or served traffic. Two independent observers read those flat
        // counters and drew opposite, equally-wrong conclusions. Pin the fix.
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.tcp_parks_total(), 0);
        assert_eq!(state.tcp_parked(), 0);
        assert_eq!(state.tcp_deliveries_total(), 0);

        let rx = state.park_tcp_agent(token(21));
        assert_eq!(state.tcp_parks_total(), 1, "a park is counted -- this is the churn signal");
        assert_eq!(state.tcp_parked(), 1, "and is visible as currently-waiting");

        // The QUIC-only metrics stay flat, exactly as before -- that is correct
        // (no QUIC registration happened) and is precisely why the fallback needs
        // its own series rather than being folded into theirs.
        assert_eq!(state.active_tunnels(), 0, "fallback parks are not QUIC registrations");
        assert_eq!(state.registrations_total(), 0);

        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(state.deliver_to_tcp_agent(&token(21), client).is_ok());
        assert!(rx.await.is_ok());
        assert_eq!(state.tcp_deliveries_total(), 1, "a consumed slot is counted");
        assert_eq!(state.tcp_parked(), 0, "and no longer counted as waiting");
        assert_eq!(state.tcp_parks_total(), 1, "the cumulative park count does not decrease");

        // Churn is legible: a pool that keeps re-parking drives parks_total up while
        // the gauge oscillates -- the signal that was missing during the incident.
        for _ in 0..3 {
            let _rx = state.park_tcp_agent(token(21));
            let c: BoxedStream = Box::new(tokio::io::duplex(16).0);
            let _ = state.deliver_to_tcp_agent(&token(21), c);
        }
        assert_eq!(state.tcp_parks_total(), 4, "every re-park is visible");
        assert_eq!(state.tcp_parked(), 0);
    }

    #[tokio::test]
    async fn tcp_parked_for_is_per_token_and_never_leaks_across_tokens_589() {
        // #589: `tcp_parked_for` (#544) had zero test coverage before CADS-Tunnel#589
        // started leaning on it in the "no agent tunnel" error enrichment -- the
        // operator-visible pool-depth number at give-up time now depends on this
        // being right per-token, not just in aggregate.
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.tcp_parked_for(&token(40)), 0, "an unknown token has no parked slots");

        let _rx_a1 = state.park_tcp_agent(token(40));
        assert_eq!(state.tcp_parked_for(&token(40)), 1);
        assert_eq!(state.tcp_parked_for(&token(41)), 0, "a different token is unaffected");

        let _rx_a2 = state.park_tcp_agent(token(40));
        assert_eq!(state.tcp_parked_for(&token(40)), 2, "additive -- both parks count (#229)");

        let _rx_b1 = state.park_tcp_agent(token(41));
        assert_eq!(state.tcp_parked_for(&token(40)), 2, "still unaffected by the other token");
        assert_eq!(state.tcp_parked_for(&token(41)), 1);

        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(state.deliver_to_tcp_agent(&token(40), client).is_ok());
        assert_eq!(state.tcp_parked_for(&token(40)), 1, "one slot consumed, one remains");
    }

    #[tokio::test]
    async fn a_parked_slot_whose_agent_vanished_still_leaves_the_gauge_consistent() {
        // The receiver being dropped (agent gone) must not leak the gauge: the slot
        // is consumed either way, otherwise tcp_parked drifts upward forever and
        // becomes as misleading as the missing metric it replaced.
        let state: EdgeState<u32> = EdgeState::new();
        let rx = state.park_tcp_agent(token(22));
        assert_eq!(state.tcp_parked(), 1);
        drop(rx); // the agent went away before a client arrived

        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        let res = state.deliver_to_tcp_agent(&token(22), client);
        assert!(res.is_err(), "a vanished agent hands the stream back");
        assert_eq!(state.tcp_parked(), 0, "the slot is still released -- no gauge leak");
        assert_eq!(state.tcp_deliveries_total(), 0, "but it is NOT counted as a delivery");
    }

    #[tokio::test]
    async fn the_production_park_path_counts_metrics_and_the_gauge_never_wraps_510() {
        // #510: `park_tcp_agent_unless_revoked` -- the path the production 'A'/'K'
        // roles take -- used to skip both counters while `deliver_to_tcp_agent`
        // always decremented the gauge, so the FIRST delivery wrapped tcp_parked
        // to u64::MAX and /metrics reported nonsense from then on.
        let state: EdgeState<u32> = EdgeState::new();
        let rx = state.park_tcp_agent_unless_revoked(token(23)).expect("not revoked");
        assert_eq!(state.tcp_parks_total(), 1, "the production path counts the park");
        assert_eq!(state.tcp_parked(), 1, "and the gauge");

        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(state.deliver_to_tcp_agent(&token(23), client).is_ok());
        assert!(rx.await.is_ok());
        assert_eq!(state.tcp_parked(), 0, "gauge returns to 0 -- no u64 wrap");

        // Even a miscounted extra decrement must saturate at 0, never wrap: the
        // gauge is an operator-facing reading, and u64::MAX reads as an outage.
        let stray: BoxedStream = Box::new(tokio::io::duplex(16).0);
        let _rx2 = state.park_tcp_agent(token(23));
        let _ = state.deliver_to_tcp_agent(&token(23), stray);
        let extra: BoxedStream = Box::new(tokio::io::duplex(16).0);
        let _ = state.deliver_to_tcp_agent(&token(23), extra); // no slot: Err, no decrement
        assert_eq!(state.tcp_parked(), 0, "saturated, not wrapped");
    }

    /// #522: the periodic reaper drops DEAD TCP-fallback parks (dropped receivers)
    /// without touching live ones, keeping the gauge honest -- the fix for corpse
    /// accumulation between browser deliveries (a crash-loop / duplicate-process
    /// flood that eventually left a token with only dead parks and 000'd it).
    #[tokio::test]
    async fn reap_dead_tcp_parks_drops_corpses_keeps_live_and_fixes_the_gauge_522() {
        let state: EdgeState<u32> = EdgeState::new();
        // Two tokens: token 30 gets 3 parks (2 will die), token 31 gets 1 (stays live).
        let d1 = state.park_tcp_agent(token(30));
        let live30 = state.park_tcp_agent(token(30));
        let d2 = state.park_tcp_agent(token(30));
        let live31 = state.park_tcp_agent(token(31));
        assert_eq!(state.tcp_parked(), 4);
        drop(d1);
        drop(d2); // two corpses on token 30

        let reaped = state.reap_dead_tcp_parks();
        assert_eq!(reaped, 2, "exactly the two dropped receivers are reaped");
        assert_eq!(state.tcp_reaped_total(), 2, "the reaped counter tracks it for /metrics");
        assert_eq!(state.tcp_parked(), 2, "gauge reflects only the live pool now");
        assert!(state.has_tcp_agent(&token(30)), "the live park on token 30 survives");
        assert!(state.has_tcp_agent(&token(31)), "the untouched token stays");

        // A live park still delivers after a reap -- the reaper never harmed it.
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(state.deliver_to_tcp_agent(&token(30), client).is_ok());
        assert!(live30.await.is_ok());
        // Reaping again with everything either delivered or live is a no-op.
        drop(live31); // now token 31's only park is a corpse
        assert_eq!(state.reap_dead_tcp_parks(), 1);
        assert!(!state.has_tcp_agent(&token(31)), "the emptied token's queue is dropped");
        assert_eq!(state.tcp_parked(), 0);
    }

    #[tokio::test]
    async fn deliver_draining_consumes_dead_slots_and_hands_back_when_none_live_510() {
        // #510: the drain loop (#505) lived inline on the primary serve paths only;
        // this pins the shared entry point both primary AND recovery paths use now.
        let state: EdgeState<u32> = EdgeState::new();
        let dead = state.park_tcp_agent(token(24));
        drop(dead); // agent vanished -- stale dead slot at the FRONT of the queue
        let live = state.park_tcp_agent(token(24));

        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent_draining(&token(24), client).is_ok(),
            "a dead slot in front must be drained, not fail the delivery"
        );
        assert!(live.await.is_ok(), "the live agent behind it receives the stream");
        assert_eq!(state.tcp_parked(), 0, "both slots consumed, gauge consistent");

        // All slots dead: the stream comes back so the caller can fall through
        // to the QUIC registration instead of failing terminally.
        drop(state.park_tcp_agent(token(24)));
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent_draining(&token(24), client).is_err(),
            "no live slot: the stream is handed back for the QUIC fall-through"
        );
        assert_eq!(state.tcp_parked(), 0);
    }

    #[tokio::test]
    async fn deliver_without_parked_tcp_agent_returns_the_stream() {
        let state: EdgeState<u32> = EdgeState::new();
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent(&token(8), client).is_err(),
            "no parked agent → stream handed back so the caller can fall through"
        );
    }

    #[tokio::test]
    async fn remove_drops_parked_tcp_agent() {
        let state: EdgeState<u32> = EdgeState::new();
        let _rx = state.park_tcp_agent(token(9));
        state.remove(&token(9));
        assert!(!state.has_tcp_agent(&token(9)));
    }

    #[tokio::test]
    async fn wait_for_tcp_agent_returns_immediately_when_already_parked() {
        let state: EdgeState<u32> = EdgeState::new();
        let _rx = state.park_tcp_agent(token(10));
        let waited = tokio::time::timeout(
            Duration::from_millis(50),
            state.wait_for_tcp_agent(&token(10), Duration::from_secs(5)),
        )
        .await
        .expect("must not block when a registration is already parked");
        assert!(waited);
    }

    #[tokio::test]
    async fn wait_for_tcp_agent_wakes_up_when_a_registration_arrives_during_the_wait() {
        // #229 follow-up: a momentarily-exhausted pool (a burst of parallel
        // browser connections) should be caught by a short bounded wait once
        // the Agent's next worker cycles round and parks a fresh registration,
        // rather than the Client failing outright.
        let state: std::sync::Arc<EdgeState<u32>> = std::sync::Arc::new(EdgeState::new());
        assert!(!state.has_tcp_agent(&token(11)));

        let s = state.clone();
        let waiter = tokio::spawn(async move { s.wait_for_tcp_agent(&token(11), Duration::from_secs(5)).await });

        // Give the waiter a moment to actually be polling `notified()` before
        // the registration lands, then park one.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _rx = state.park_tcp_agent(token(11));

        let waited = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("wait_for_tcp_agent must return promptly once a registration lands")
            .expect("task did not panic");
        assert!(waited);
    }

    #[tokio::test]
    async fn wait_for_tcp_agent_times_out_when_nothing_arrives() {
        let state: EdgeState<u32> = EdgeState::new();
        let waited = tokio::time::timeout(
            Duration::from_secs(1),
            state.wait_for_tcp_agent(&token(12), Duration::from_millis(50)),
        )
        .await
        .expect("wait_for_tcp_agent must respect its own timeout");
        assert!(!waited);
    }

    #[test]
    fn is_resolvable_covers_both_quic_and_tcp_fallback_agents_but_not_unknown_tokens() {
        // #472: `is_resolvable` is the known-token gate that must run before
        // the rendezvous rate limiter -- it has to recognize a token
        // registered on EITHER transport, not just QUIC (`is_known` alone),
        // or a legitimate TCP-fallback-only Client would be wrongly rejected.
        let state: EdgeState<u32> = EdgeState::new();

        let quic_token = token(20);
        state.register(quic_token.clone(), 1u32);
        assert!(state.is_resolvable(&quic_token), "known via a live QUIC agent");

        let tcp_token = token(21);
        let _rx = state.park_tcp_agent_unless_revoked(tcp_token.clone());
        assert!(state.is_resolvable(&tcp_token), "known via a parked TCP-fallback agent");

        let unknown_token = token(22);
        assert!(
            !state.is_resolvable(&unknown_token),
            "a token with no registration on either transport is not resolvable"
        );
    }

    #[test]
    fn unknown_token_never_occupies_a_rate_limiter_slot() {
        // #472: the fix's core invariant, isolated from the QUIC/TCP wire
        // protocol -- serve_connection's 'C' arms must check `is_resolvable`
        // before `rendezvous_allowed`, so an unresolvable token never reaches
        // (and never occupies a slot in) the limiter.
        let state: EdgeState<u32> = EdgeState::new();
        state.set_rendezvous_limit(1_000_000); // isolate the gate from the cap itself
        let unknown = token(23);

        for _ in 0..5 {
            if state.is_resolvable(&unknown) {
                state.rendezvous_allowed(&unknown, 0);
            }
        }
        assert_eq!(
            state.rendezvous_tracked_keys(),
            0,
            "an unresolvable token must never touch the rate limiter"
        );

        // A known token, by contrast, does occupy a slot -- confirms the
        // limiter itself still engages normally for tokens that pass the gate.
        state.register(unknown.clone(), 9u32);
        assert!(state.is_resolvable(&unknown));
        assert!(state.rendezvous_allowed(&unknown, 0));
        assert_eq!(state.rendezvous_tracked_keys(), 1);
    }

    #[test]
    fn connection_cap_admits_up_to_max_then_sheds_until_a_permit_frees() {
        // #86 SEC86b: the accept-loop cap admits at most `max` concurrent
        // connections and sheds the rest; dropping a held permit frees a slot.
        let cap = ConnectionCap::new(2);
        assert_eq!(cap.available(), 2);

        let a = cap.try_admit().expect("1st admitted");
        let b = cap.try_admit().expect("2nd admitted");
        assert_eq!(cap.available(), 0, "both slots taken");
        assert!(cap.try_admit().is_none(), "over the cap -> shed");

        // Releasing one held permit frees exactly one slot.
        drop(a);
        assert_eq!(cap.available(), 1);
        let c = cap.try_admit().expect("slot freed -> admits again");
        assert!(cap.try_admit().is_none(), "back at the cap");

        drop(b);
        drop(c);
        assert_eq!(cap.available(), 2, "all permits returned");
    }

    #[test]
    fn connection_cap_clones_share_one_global_budget() {
        // #86 SEC86c: the QUIC and TCP accept loops hold CLONES of one
        // ConnectionCap, so the cap must be global — a permit taken through one
        // handle is unavailable through the other (not a per-loop budget).
        let cap = ConnectionCap::new(1);
        let clone = cap.clone();
        let p = cap.try_admit().expect("global slot admitted via one handle");
        assert!(clone.try_admit().is_none(), "the clone sees the shared budget exhausted");
        drop(p);
        assert!(clone.try_admit().is_some(), "releasing frees the slot for the clone too");
    }

    #[test]
    fn join_refusal_penalty_engages_at_the_budget_and_self_clears_next_window() {
        // The 2026-08-13 storm contract: an IP stays unpenalized through its whole
        // per-window budget of definitive refusals, the budget-exceeding refusal
        // reports the escalation exactly ONCE (the caller's one log line), the IP is
        // then shed for the rest of the window, and the penalty self-clears in the
        // next window -- it is storm absorption, not a durable ban on a NAT IP.
        let p = JoinRefusalPenalty::new();
        let ip: std::net::IpAddr = "89.56.48.254".parse().unwrap();
        let t0 = 1_000_000; // an arbitrary window start (windows are t/60 buckets)

        for i in 0..JOIN_REFUSALS_PER_MINUTE - 1 {
            assert!(!p.penalized(ip, t0), "not penalized before the budget, refusal {i}");
            assert!(
                !p.note_definitive_refusal(ip, t0),
                "an in-budget refusal is not the escalation, refusal {i}"
            );
        }
        assert!(!p.penalized(ip, t0), "one refusal of budget left — still unpenalized");
        assert!(
            p.note_definitive_refusal(ip, t0),
            "the refusal that reaches the budget reports the escalation exactly once"
        );
        assert!(p.penalized(ip, t0), "now shed for the rest of the window");
        assert!(
            !p.note_definitive_refusal(ip, t0),
            "further storm refusals in the same window never re-report the escalation"
        );

        // A different IP behind a different line is completely unaffected.
        let other: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert!(!p.penalized(other, t0), "an unrelated IP shares no budget");

        // The next minute self-clears the penalty.
        let t1 = t0 + JOIN_REFUSAL_WINDOW_SECS;
        assert!(!p.penalized(ip, t1), "the penalty self-clears in the next window");
        assert!(!p.note_definitive_refusal(ip, t1), "and the budget is genuinely fresh");
    }

    #[test]
    fn join_refusal_penalty_is_shared_between_edge_state_and_the_broker_loop_handle() {
        // `EdgeState::join_refusal_penalty()` and the state's own record/enforce
        // methods must act on ONE budget -- the QUIC broker loop holds the Arc, the
        // `:443` arm goes through the state, and a storm that alternates transports
        // must not get double the allowance.
        let state: EdgeState<()> = EdgeState::new();
        let handle = state.join_refusal_penalty();
        let ip: std::net::IpAddr = "89.56.48.254".parse().unwrap();
        for _ in 0..=JOIN_REFUSALS_PER_MINUTE {
            let _ = state.note_definitive_join_refusal(ip, 60);
        }
        assert!(state.join_penalized(ip, 60), "recorded via the state...");
        assert!(handle.penalized(ip, 60), "...and enforced via the broker loop's Arc handle");
    }

    /// #551: the penalty's two observable numbers, and — the point of the exercise — proof
    /// that the tracked-IP bound is a REAL degradation and not a theoretical one.
    #[test]
    fn join_refusal_penalty_exposes_sheds_and_shows_the_table_bound_evicting_a_penalized_ip_551() {
        let p = JoinRefusalPenalty::new();
        let window = 60;

        assert_eq!(p.shed_total(), 0, "a fresh penalty has shed nothing");
        assert_eq!(p.tracked_ips(), 0, "...and tracks nobody");
        p.note_shed();
        p.note_shed();
        assert_eq!(p.shed_total(), 2, "the counter that had no reader now has one");

        // An offender earns its penalty the honest way.
        let victim: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..=JOIN_REFUSALS_PER_MINUTE {
            let _ = p.note_definitive_refusal(victim, window);
        }
        assert!(p.penalized(victim, window), "over budget, so it is shed");
        assert_eq!(p.tracked_ips(), 1);

        // Now a storm from many DISTINCT sources in the same window. Each one is a single
        // refusal -- far under the per-IP budget, so none of them is ever penalized itself.
        for i in 0..JOIN_REFUSAL_MAX_TRACKED_IPS {
            let ip: std::net::IpAddr =
                std::net::Ipv4Addr::from(0x0a00_0000u32 + i as u32).into();
            let _ = p.note_definitive_refusal(ip, window);
        }

        assert_eq!(
            p.tracked_ips(),
            JOIN_REFUSAL_MAX_TRACKED_IPS,
            "the table is capped, which is the memory bound working as designed"
        );
        assert_eq!(p.max_tracked_ips(), JOIN_REFUSAL_MAX_TRACKED_IPS);

        // ...and this is the cost of that bound: the genuinely abusive IP was pushed out
        // FIFO by traffic that was individually harmless, so it is no longer shed even
        // though its behaviour has not changed and the window has not turned over. The
        // penalty is degraded exactly when it is needed most, which is why the gauge above
        // must be read against its max rather than reported as a bare number.
        assert!(
            !p.penalized(victim, window),
            "a saturated table drops an already-penalized IP -- if this ever starts passing \
             as `true`, the eviction policy changed and the #551 metric's documented meaning \
             must change with it"
        );
    }
}
