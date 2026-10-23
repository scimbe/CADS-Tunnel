//! Protocol v2 for A2A channel sessions: end-to-end delivery confirmation (ct-agent#299).
//!
//! **Why.** With the legacy pump ([`crate::noise::noise_pump`]) a session cannot tell "the peer
//! has everything" from "the path was cut", so a lost tail looks exactly like success:
//!
//! * its inbound loop reports every read error -- a reset, an end of stream inside a record --
//!   as a clean end;
//! * a relay that terminates TLS (the edge's `:443` front door) can always produce a valid
//!   clean close, and Noise transport messages carry no authenticated end of stream;
//! * the sender learns nothing about delivery: on `:443` the TCP acknowledgements come from the
//!   edge, and QUIC's `stopped()` only reports the peer's QUIC stack, not its application side.
//!
//! ct-agent#299 lost a pipe member's data that way while both ends reported `ok=true`.
//!
//! **Records.** Under v2 every Noise transport message carries exactly one record, `tag | body`:
//!
//! | tag    | record   | body                         | meaning                                            |
//! |--------|----------|------------------------------|----------------------------------------------------|
//! | `0x00` | DATA     | application bytes            |                                                    |
//! | `0x01` | FIN      | `sent: u64 BE`, `reason: u8` | "I sent `sent` bytes and send no more"             |
//! | `0x02` | FIN_ACK  | `received: u64 BE`           | "your FIN arrived; `received` bytes are delivered" |
//! | `0x03` | PROGRESS | `delivered: u64 BE`          | "`delivered` of your bytes are delivered so far"   |
//!
//! A side whose local input ends sends FIN; it does **not** half-close the transport. The
//! transport stays fully open until both directions are confirmed, so a session no longer
//! depends on how a relay treats a half-close (the park pump before CADS-Tunnel#856 dropped
//! both directions of a leg on one). The receiver of a FIN checks the count, flushes, closes its
//! local write side and answers FIN_ACK with the count it delivered. A FIN whose reason is not
//! [`FinReason::Normal`] ends the whole session at once and tells the peer why (an expired or
//! revoked grant, a failed local side); a normal FIN may still be followed by such an abort.
//!
//! [`noise_pump_v2`] succeeds only when this side's FIN was acknowledged with exactly the count
//! it sent and the peer's FIN arrived with exactly the count received (and was acknowledged).
//! Anything else is an error that names what is missing ([`DeliveryError`]). The wait for the
//! FIN_ACK is bounded by progress: it fails after `fin_ack_idle` without a single record from
//! the peer, and every record restarts that clock. A receiver whose own input has ended sends
//! nothing else while it delivers into a slow local consumer -- in #299's own shape (a member
//! with stdin at EOF receiving a file) the sender would hear nothing until the very end. So a
//! side that delivered more of the peer's bytes since its last PROGRESS sends one, at most every
//! `min(fin_ack_idle / 4, 15 s)`: a slow consumer keeps the sender waiting, a stuck one (no
//! progress at all) still ends the session after `fin_ack_idle`. Waiting for the peer's own FIN
//! has no bound, as before: a peer may keep its direction open as long as it likes.
//!
//! **Extending the protocol.** A pump rejects a record tag it does not know as a protocol
//! violation, so a new record type -- or a changed meaning of an existing one -- needs its own
//! capability flag bit (the next one is `0x0002`), negotiated like [`CAP_DELIVERY_ACK`].
//! [`CAPS_VERSION`] only describes the layout of the capability payload; raising it does not
//! tell a peer anything about the records.
//!
//! **The reason is a claim.** The FIN reason is what the authenticated peer says about itself
//! and cannot be checked here: it is meant for the operator reading the log. It must never by
//! itself drive an authorization or exit decision (e.g. "your grant was revoked" stopping a
//! member for good); that needs the control plane.
//!
//! **What a relay sees.** The records are inside the Noise transport messages, so a relay that
//! terminates TLS (the edge's `:443` front door) learns no content. It can tell a v2 session from
//! the sizes, though: the handshake messages are 6 bytes longer, and FIN, FIN_ACK and PROGRESS
//! are small fixed-size frames (28, 27 and 27 bytes) -- so it can guess when each direction
//! ends, which a legacy session shows it outright through the transport half-close.
//!
//! **Negotiation.** Both ends must speak v2, so it is negotiated inside the A2A handshake
//! ([`crate::a2a::a2a_initiate_with_caps`], [`crate::a2a::a2a_respond_verified_with_caps`]):
//! the initiator puts [`SessionCaps::to_payload`] (`b"CTC" | version | flags`) into Noise
//! message 1 and the responder answers with the intersection in message 2. Every A2A peer
//! before v2 sends empty payloads and ignores what it receives, so an old peer on either side
//! means [`SessionCaps::NONE`] and the legacy pump. Both payloads are encrypted and bound into
//! the handshake hash; a relay can neither read nor strip them without the handshake failing.
//!
//! **Limit.** v2 proves delivery into the peer agent's local side (written and flushed, e.g. to
//! its stdout or to the forward engine), not that the final application processed the bytes --
//! the end-to-end argument; only the application protocol can confirm that. It does make
//! truncation by any relay, and every loss before the peer's local side, visible.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use snow::TransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::noise::{lock_session, read_frame_into, seal_frame, NOISE_MAX_RECORD};

/// Magic of the capability payload in the handshake ("channel capabilities").
const CAPS_MAGIC: &[u8; 3] = b"CTC";

/// Version of the capability payload this crate writes. Any version from 1 up is read the same
/// way -- magic, version, flags, then bytes a later version may add, which are ignored -- so a
/// later version can extend it without breaking this one.
pub const CAPS_VERSION: u8 = 1;

/// Capability bit: end-to-end delivery confirmation ([`noise_pump_v2`]).
pub const CAP_DELIVERY_ACK: u16 = 0x0001;

/// What the two ends of an A2A session agreed to run on top of the Noise transport. Negotiated
/// in the handshake (see the module doc); [`SessionCaps::NONE`] is the legacy session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionCaps {
    flags: u16,
}

impl SessionCaps {
    /// Nothing beyond the legacy byte pump -- what every peer before v2 runs.
    pub const NONE: SessionCaps = SessionCaps { flags: 0 };
    /// End-to-end delivery confirmation ([`noise_pump_v2`]).
    pub const DELIVERY_ACK: SessionCaps = SessionCaps { flags: CAP_DELIVERY_ACK };

    /// The raw flag bits. Bits this crate does not know are kept as received; the intersection
    /// with this side's own set removes them.
    pub const fn from_flags(flags: u16) -> Self {
        Self { flags }
    }

    /// The raw flag bits.
    pub const fn flags(self) -> u16 {
        self.flags
    }

    /// Whether the session runs [`noise_pump_v2`].
    pub const fn delivery_ack(self) -> bool {
        self.flags & CAP_DELIVERY_ACK != 0
    }

    /// The capabilities both sets contain.
    pub const fn intersect(self, other: SessionCaps) -> SessionCaps {
        Self { flags: self.flags & other.flags }
    }

    /// The handshake payload announcing this set: `b"CTC" | CAPS_VERSION | flags (u16 BE)`.
    /// An empty set is the empty payload, byte-identical to a pre-v2 handshake.
    pub fn to_payload(self) -> Vec<u8> {
        if self.flags == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(6);
        out.extend_from_slice(CAPS_MAGIC);
        out.push(CAPS_VERSION);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out
    }

    /// Read a handshake payload. `None` for anything that is not a capability payload -- above
    /// all the empty payload every pre-v2 peer sends.
    pub fn from_payload(payload: &[u8]) -> Option<SessionCaps> {
        if payload.len() < 6 || &payload[..3] != CAPS_MAGIC || payload[3] == 0 {
            return None;
        }
        Some(Self { flags: u16::from_be_bytes([payload[4], payload[5]]) })
    }
}

/// Why a side ended its direction, carried in its FIN record. Anything but [`FinReason::Normal`]
/// ends the whole session and is reported to the peer as the cause -- informational only, see
/// the module doc. Non-exhaustive so a later named reason is not a breaking change downstream
/// (the wire already carries any byte as [`FinReason::Unknown`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FinReason {
    /// The local input ended; the other direction stays open.
    Normal,
    /// The sender's own channel grant expired.
    OwnGrantExpired,
    /// The sender's own channel grant was revoked.
    OwnGrantRevoked,
    /// The sender saw the receiver's grant end (expired, revoked, no longer a member).
    PeerGrantEnded,
    /// The sender's local side failed.
    LocalError,
    /// The sender refused the receiver's grant (missing, invalid or late).
    PeerGrantRefused,
    /// A reason this crate does not know (a later version); still an abnormal end.
    Unknown(u8),
}

impl FinReason {
    /// The wire byte.
    pub const fn to_byte(self) -> u8 {
        match self {
            FinReason::Normal => 0,
            FinReason::OwnGrantExpired => 1,
            FinReason::OwnGrantRevoked => 2,
            FinReason::PeerGrantEnded => 3,
            FinReason::LocalError => 4,
            FinReason::PeerGrantRefused => 5,
            FinReason::Unknown(b) => b,
        }
    }

    /// Read the wire byte.
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => FinReason::Normal,
            1 => FinReason::OwnGrantExpired,
            2 => FinReason::OwnGrantRevoked,
            3 => FinReason::PeerGrantEnded,
            4 => FinReason::LocalError,
            5 => FinReason::PeerGrantRefused,
            other => FinReason::Unknown(other),
        }
    }

    /// The reason as the side that sent it would say it.
    fn local_words(self) -> String {
        match self {
            FinReason::Normal => "the local input ended".into(),
            FinReason::OwnGrantExpired => "this member's channel grant expired".into(),
            FinReason::OwnGrantRevoked => "this member's channel grant was revoked".into(),
            FinReason::PeerGrantEnded => "the peer's channel grant ended".into(),
            FinReason::LocalError => "the local side failed".into(),
            FinReason::PeerGrantRefused => "the peer's grant was refused".into(),
            FinReason::Unknown(b) => format!("reason code {b}"),
        }
    }

    /// The reason as the side that received it reads it: "the peer ... ".
    fn peer_words(self) -> String {
        match self {
            FinReason::Normal => "the peer's input ended".into(),
            FinReason::OwnGrantExpired => "the peer's own channel grant expired".into(),
            FinReason::OwnGrantRevoked => "the peer's own channel grant was revoked".into(),
            FinReason::PeerGrantEnded => "the peer reports that this member's channel grant ended".into(),
            FinReason::LocalError => "the peer's local side failed".into(),
            FinReason::PeerGrantRefused => "the peer refused this member's grant".into(),
            FinReason::Unknown(b) => format!("the peer ended with reason code {b}"),
        }
    }

    /// The `io::ErrorKind` an abort for this reason is reported with.
    fn error_kind(self) -> io::ErrorKind {
        match self {
            FinReason::OwnGrantExpired
            | FinReason::OwnGrantRevoked
            | FinReason::PeerGrantEnded
            | FinReason::PeerGrantRefused => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::Other,
        }
    }
}

/// What a successful [`noise_pump_v2`] confirmed. Non-exhaustive so a later field is not a
/// breaking change downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeliveryReport {
    /// Bytes this side sent, all confirmed by the peer's FIN_ACK.
    pub sent: u64,
    /// Bytes this side received and delivered to its local side, confirmed to the peer.
    pub received: u64,
}

/// Why a v2 session did not complete. Carried inside the `io::Error` that [`noise_pump_v2`]
/// returns; [`delivery_error`] gets it back. Each variant names what is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryError {
    /// The transport ended (or failed) before the session was complete.
    TransportEnded {
        /// Bytes received from the peer.
        received: u64,
        /// Whether the peer's FIN arrived.
        peer_fin: bool,
        /// Bytes this side sent.
        sent: u64,
        /// Whether this side's FIN went out.
        fin_sent: bool,
        /// Whether the peer confirmed this side's bytes.
        confirmed: bool,
        /// The transport's own word for the end.
        cause: String,
    },
    /// The peer's FIN announced a different byte count than arrived.
    Truncated { announced: u64, received: u64 },
    /// The peer's FIN_ACK confirmed a different byte count than this side sent.
    Unconfirmed { sent: u64, confirmed: u64 },
    /// No record from the peer for `idle` while waiting for its FIN_ACK.
    AckTimeout { sent: u64, idle: Duration },
    /// The peer ended the session early and said why.
    PeerEnded { reason: FinReason, announced: u64, received: u64 },
    /// This side ended the session early.
    LocalEnded { reason: FinReason, sent: u64, detail: String },
    /// The peer broke the record protocol.
    Protocol(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Worded by what was actually due: "delivery not confirmed" only where this side's
            // FIN was out and its confirmation is what is missing. A session cut while a
            // direction was still open (an interactive member, a forward) had nothing due yet,
            // and a sender whose bytes were confirmed must not read that they were not.
            DeliveryError::TransportEnded { received, peer_fin, sent, fin_sent, confirmed, cause } => {
                match (*fin_sent, *confirmed, *peer_fin) {
                    (false, _, false) => write!(
                        f,
                        "session cut: the transport ended ({cause}) while both directions were still \
                         open ({sent} bytes sent, {received} received; a direction is confirmed only \
                         when it ends)"
                    ),
                    (false, _, true) => write!(
                        f,
                        "session cut: the transport ended ({cause}) while our direction was still open \
                         ({sent} bytes sent, none of them confirmed yet; the peer's stream ended \
                         complete after {received} bytes)"
                    ),
                    (true, false, false) => write!(
                        f,
                        "delivery not confirmed: the transport ended ({cause}) before the peer's \
                         confirmation of our {sent} bytes and before the end of the peer's stream \
                         ({received} bytes received, then nothing)"
                    ),
                    (true, false, true) => write!(
                        f,
                        "delivery not confirmed: the transport ended ({cause}) before the peer's \
                         confirmation of our {sent} bytes (the peer's stream ended complete after \
                         {received} bytes)"
                    ),
                    (true, true, false) => write!(
                        f,
                        "the peer's stream is incomplete: the transport ended ({cause}) before the end \
                         of the peer's stream ({received} bytes received, then nothing); our {sent} \
                         bytes were confirmed"
                    ),
                    (true, true, true) => write!(
                        f,
                        "the transport ended ({cause}) before our confirmation of the peer's \
                         {received} bytes was out; our {sent} bytes were confirmed"
                    ),
                }
            }
            DeliveryError::Truncated { announced, received } => write!(
                f,
                "delivery truncated: the peer sent {announced} bytes, {received} arrived"
            ),
            DeliveryError::Unconfirmed { sent, confirmed } => write!(
                f,
                "delivery not confirmed: the peer confirmed {confirmed} of our {sent} bytes"
            ),
            DeliveryError::AckTimeout { sent, idle } => write!(
                f,
                "delivery not confirmed: no word from the peer for {}s (no data, no progress \
                 report) while waiting for its confirmation of our {sent} bytes",
                idle.as_secs()
            ),
            DeliveryError::PeerEnded { reason, announced, received } => write!(
                f,
                "the peer ended the session early: {} (it had sent {announced} bytes, \
                 {received} arrived)",
                reason.peer_words()
            ),
            DeliveryError::LocalEnded { reason, sent, detail } => write!(
                f,
                "ended the session early: {} after sending {sent} bytes ({detail})",
                reason.local_words()
            ),
            DeliveryError::Protocol(what) => write!(f, "delivery protocol violated by the peer: {what}"),
        }
    }
}

impl std::error::Error for DeliveryError {}

impl DeliveryError {
    fn into_io(self, kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, self)
    }
}

/// The [`DeliveryError`] inside an error returned by [`noise_pump_v2`], if there is one.
pub fn delivery_error(err: &io::Error) -> Option<&DeliveryError> {
    err.get_ref()?.downcast_ref::<DeliveryError>()
}

/// A sensible bound for the FIN_ACK wait (see [`noise_pump_v2`]): a minute without a single
/// record from a peer that still owes the confirmation. The peer only confirms after it has
/// flushed everything into its local side, which may be a slow consumer; while it still delivers
/// it reports progress (PROGRESS, see the module doc), so this bounds a stuck peer, not a slow one.
pub const DEFAULT_FIN_ACK_IDLE: Duration = Duration::from_secs(60);

/// The longest a side waits before it reports that it delivered more of the peer's bytes
/// (PROGRESS). A side reports every `min(fin_ack_idle / 4, PROGRESS_EVERY_MAX)` of its own, so a
/// peer whose `fin_ack_idle` is at least 4 x this ([`DEFAULT_FIN_ACK_IDLE`]) hears in time from
/// every v2 peer, whatever that peer's own setting.
const PROGRESS_EVERY_MAX: Duration = Duration::from_secs(15);

/// How long an abort may take to put its FIN on the wire, and the local close behind it. An
/// abort ends the session either way; this only keeps a stuck transport from holding it.
const ABORT_GRACE: Duration = Duration::from_secs(2);

const REC_DATA: u8 = 0x00;
const REC_FIN: u8 = 0x01;
const REC_FIN_ACK: u8 = 0x02;
const REC_PROGRESS: u8 = 0x03;

/// Work the inbound direction hands to the outbound one, which owns the transport's write side.
enum ToOutbound {
    /// The peer's FIN arrived and its data is delivered: acknowledge with this count.
    FinAck(u64),
    /// Delivering to the local side failed: end the session with this reason and error.
    Abort(FinReason, io::Error),
}

fn fin_body(sent: u64, reason: FinReason) -> [u8; 9] {
    let mut body = [0u8; 9];
    body[..8].copy_from_slice(&sent.to_be_bytes());
    body[8] = reason.to_byte();
    body
}

fn u64_at(bytes: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(b)
}

/// Encrypt `tag | body` into `ct` and write it as one frame -- for the small control records.
/// `msg` is the caller's reused plaintext scratch buffer (#364: no allocation per record); DATA
/// records skip it and are sealed straight from the read buffer (#114: no extra copy in bulk).
async fn write_record<W: AsyncWrite + Unpin>(
    w: &mut W,
    ts: &Mutex<TransportState>,
    msg: &mut Vec<u8>,
    ct: &mut [u8],
    tag: u8,
    body: &[u8],
) -> io::Result<()> {
    msg.clear();
    msg.push(tag);
    msg.extend_from_slice(body);
    let total = seal_frame(ts, msg, ct)?;
    w.write_all(&ct[..total]).await?;
    w.flush().await
}

/// The v2 pump: [`crate::noise::noise_pump`]'s job (plaintext `plain` <-> Noise records on
/// `cipher`) with records, FIN and FIN_ACK, so that `Ok` means delivered. Run it only when the
/// handshake agreed [`SessionCaps::DELIVERY_ACK`]; the peer must run it too.
///
/// * `Ok(report)`: this side's FIN was acknowledged with exactly the count it sent, and the
///   peer's FIN arrived with exactly the count received and was acknowledged. The transport's
///   write side is shut down only then.
/// * `Err`: anything else, with a [`DeliveryError`] inside ([`delivery_error`]) that names what
///   is missing. After an error nothing waits for the peer any more.
///
/// Without an error, two waits remain. The wait for the peer's own FIN has no bound: a peer may
/// keep its direction open as long as it likes (an interactive member). The wait for the FIN_ACK
/// after this side's FIN is bounded by progress: `fin_ack_idle` bounds it -- the session fails
/// after that long without any record from the peer, every record restarts the clock, and a
/// peer that is still delivering our bytes sends PROGRESS records to say so
/// ([`DEFAULT_FIN_ACK_IDLE`] is a sensible value). `local_end` names the reason for the FIN when
/// the local side ends: it is called with `None` when the local input reaches its end and with
/// the error when reading from or writing to the local side fails. Return
/// [`FinReason::Normal`] for an ordinary end of input; any other reason ends the whole session
/// and is sent to the peer. A failure of the local side is never treated as a normal end.
pub async fn noise_pump_v2<C, P, F>(
    transport: TransportState,
    cipher: C,
    plain: P,
    fin_ack_idle: Duration,
    local_end: F,
) -> io::Result<DeliveryReport>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Option<&io::Error>) -> FinReason,
{
    const CHUNK: usize = 16 * 1024; // same chunking as the legacy pump
    let ts = Mutex::new(transport);
    let (mut c_read, mut c_write) = tokio::io::split(cipher);
    let (mut p_read, mut p_write) = tokio::io::split(plain);

    // Shared between the three futures below, which all run inside this one task. Atomics, not
    // Cells, so the pump stays Send (the same reason as the edge's park pump).
    let start = tokio::time::Instant::now();
    let since_start_ms = || start.elapsed().as_millis() as u64;
    let sent_total = AtomicU64::new(0);
    let received_total = AtomicU64::new(0);
    let fin_sent = AtomicBool::new(false);
    let peer_fin = AtomicBool::new(false);
    let confirmed = AtomicBool::new(false);
    // Milliseconds since `start`: when our FIN was out, and the last sign of life on the receive
    // path (a record arrived, or this side finished handing one to its local side).
    let fin_out_at = AtomicU64::new(0);
    let last_record_at = AtomicU64::new(0);
    // Set while the inbound side waits for its own local side to take data: a slow local
    // consumer holds the next record back, and that time must not count as the peer's silence.
    let delivering = AtomicBool::new(false);
    let fin_out = tokio::sync::Notify::new();
    let acked = tokio::sync::Notify::new();
    let (to_outbound, mut from_inbound) = tokio::sync::mpsc::unbounded_channel::<ToOutbound>();

    // A transport that ends or fails mid-session: report everything still missing.
    let transport_ended = |cause: &io::Error| -> io::Error {
        let cause = if cause.kind() == io::ErrorKind::UnexpectedEof {
            "end of stream".to_string()
        } else {
            cause.to_string()
        };
        DeliveryError::TransportEnded {
            received: received_total.load(Ordering::SeqCst),
            peer_fin: peer_fin.load(Ordering::SeqCst),
            sent: sent_total.load(Ordering::SeqCst),
            fin_sent: fin_sent.load(Ordering::SeqCst),
            confirmed: confirmed.load(Ordering::SeqCst),
            cause,
        }
        .into_io(io::ErrorKind::UnexpectedEof)
    };
    let protocol = |what: String| DeliveryError::Protocol(what).into_io(io::ErrorKind::InvalidData);

    // How often this side reports that it delivered more of the peer's bytes (PROGRESS; see the
    // module doc). Never zero: `interval` would panic on it.
    let progress_every = (fin_ack_idle / 4).min(PROGRESS_EVERY_MAX).max(Duration::from_millis(10));

    // plaintext -> DATA records, then FIN; plus the FIN_ACK the inbound side asks for and the
    // PROGRESS reports while it delivers.
    let outbound = async {
        // `tag | data` in one buffer, so a DATA record is sealed straight from where it was read.
        let mut buf = vec![0u8; 1 + CHUNK];
        buf[0] = REC_DATA;
        let mut msg = Vec::with_capacity(16);
        let mut ct = vec![0u8; 2 + 1 + CHUNK + 256];
        let mut sent: u64 = 0;
        let mut local_open = true;
        let mut fin_ack_out = false;
        let mut inbound_open = true;
        let mut progress = tokio::time::interval_at(tokio::time::Instant::now() + progress_every, progress_every);
        progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut reported: u64 = 0;
        while local_open || !fin_ack_out {
            tokio::select! {
                biased;
                cmd = from_inbound.recv(), if inbound_open => match cmd {
                    Some(ToOutbound::FinAck(received)) => {
                        write_record(&mut c_write, &ts, &mut msg, &mut ct, REC_FIN_ACK, &received.to_be_bytes())
                            .await
                            .map_err(|e| transport_ended(&e))?;
                        fin_ack_out = true;
                    }
                    Some(ToOutbound::Abort(reason, err)) => {
                        let body = fin_body(sent, reason);
                        let _ = tokio::time::timeout(
                            ABORT_GRACE,
                            write_record(&mut c_write, &ts, &mut msg, &mut ct, REC_FIN, &body),
                        )
                        .await;
                        return Err(err);
                    }
                    None => inbound_open = false,
                },
                // #299 review: a receiver whose input has ended sends nothing else while it
                // delivers into a slow consumer, so without this its peer, waiting for the
                // FIN_ACK, would give up on a transfer that is still being delivered. Only
                // growth is reported: a stuck consumer goes quiet and still runs into the bound.
                // Not after our FIN_ACK, which carries the final count.
                _ = progress.tick(), if !fin_ack_out => {
                    let delivered = received_total.load(Ordering::SeqCst);
                    if delivered > reported {
                        write_record(&mut c_write, &ts, &mut msg, &mut ct, REC_PROGRESS, &delivered.to_be_bytes())
                            .await
                            .map_err(|e| transport_ended(&e))?;
                        reported = delivered;
                    }
                }
                r = p_read.read(&mut buf[1..]), if local_open => match r {
                    Ok(0) => {
                        let reason = local_end(None);
                        if reason != FinReason::Normal {
                            let body = fin_body(sent, reason);
                            let _ = tokio::time::timeout(
                                ABORT_GRACE,
                                write_record(&mut c_write, &ts, &mut msg, &mut ct, REC_FIN, &body),
                            )
                            .await;
                            return Err(DeliveryError::LocalEnded {
                                reason,
                                sent,
                                detail: "the local side ended".to_string(),
                            }
                            .into_io(reason.error_kind()));
                        }
                        // Flagged before the write: a FIN_ACK can only come back after the
                        // FIN is out, and must then find the final count in place.
                        sent_total.store(sent, Ordering::SeqCst);
                        fin_sent.store(true, Ordering::SeqCst);
                        write_record(&mut c_write, &ts, &mut msg, &mut ct, REC_FIN, &fin_body(sent, reason))
                            .await
                            .map_err(|e| transport_ended(&e))?;
                        // The FIN_ACK clock starts when the FIN is handed to the transport, not
                        // while a slow peer still holds the write back.
                        fin_out_at.store(since_start_ms(), Ordering::SeqCst);
                        fin_out.notify_one();
                        local_open = false;
                    }
                    Ok(n) => {
                        let total = seal_frame(&ts, &buf[..1 + n], &mut ct)?;
                        let written = async {
                            c_write.write_all(&ct[..total]).await?;
                            c_write.flush().await
                        };
                        written.await.map_err(|e| transport_ended(&e))?;
                        sent += n as u64;
                        sent_total.store(sent, Ordering::SeqCst);
                    }
                    Err(e) => {
                        let reason = match local_end(Some(&e)) {
                            FinReason::Normal => FinReason::LocalError,
                            other => other,
                        };
                        let body = fin_body(sent, reason);
                        let _ = tokio::time::timeout(
                            ABORT_GRACE,
                            write_record(&mut c_write, &ts, &mut msg, &mut ct, REC_FIN, &body),
                        )
                        .await;
                        return Err(DeliveryError::LocalEnded {
                            reason,
                            sent,
                            detail: format!("reading the local side failed: {e}"),
                        }
                        .into_io(e.kind()));
                    }
                },
                else => break,
            }
        }
        Ok::<u64, io::Error>(sent)
    };

    // records -> plaintext; the peer's FIN and FIN_ACK are checked here.
    let inbound = async {
        let mut pt = vec![0u8; NOISE_MAX_RECORD];
        let mut fr = Vec::with_capacity(CHUNK + 256);
        let mut received: u64 = 0;
        let mut their_fin = false;
        let mut our_fin_confirmed = false;
        // A failure to deliver to the local side: tell the peer (through the outbound side,
        // which owns the transport) and end. The outbound side ends the pump as soon as the
        // abort is on the wire; the sleep only covers an outbound side that is stuck.
        let abort = |e: io::Error| {
            let reason = match local_end(Some(&e)) {
                FinReason::Normal => FinReason::LocalError,
                other => other,
            };
            let err = DeliveryError::LocalEnded {
                reason,
                sent: sent_total.load(Ordering::SeqCst),
                detail: format!("delivering to the local side failed: {e}"),
            };
            let _ = to_outbound.send(ToOutbound::Abort(reason, err.clone().into_io(e.kind())));
            let kind = e.kind();
            async move {
                tokio::time::sleep(ABORT_GRACE).await;
                err.into_io(kind)
            }
        };
        loop {
            if their_fin && our_fin_confirmed {
                return Ok::<u64, io::Error>(received);
            }
            let n = match read_frame_into(&mut c_read, &mut fr).await {
                Ok(n) => n,
                Err(e) => return Err(transport_ended(&e)),
            };
            last_record_at.store(since_start_ms(), Ordering::SeqCst);
            let len = lock_session(&ts)?
                .read_message(&fr[..n], &mut pt)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}")))?;
            if len == 0 {
                return Err(protocol("an empty record".to_string()));
            }
            match pt[0] {
                REC_DATA => {
                    if their_fin {
                        return Err(protocol("application data after the peer's FIN".to_string()));
                    }
                    let delivered = async {
                        p_write.write_all(&pt[1..len]).await?;
                        p_write.flush().await
                    };
                    delivering.store(true, Ordering::SeqCst);
                    let delivered = delivered.await;
                    delivering.store(false, Ordering::SeqCst);
                    last_record_at.store(since_start_ms(), Ordering::SeqCst);
                    if let Err(e) = delivered {
                        return Err(abort(e).await);
                    }
                    received += (len - 1) as u64;
                    received_total.store(received, Ordering::SeqCst);
                }
                REC_FIN => {
                    if len != 1 + 9 {
                        return Err(protocol(format!("a FIN record of {len} bytes")));
                    }
                    let announced = u64_at(&pt[1..9]);
                    let reason = FinReason::from_byte(pt[9]);
                    if reason != FinReason::Normal {
                        // The peer is gone for good: whatever arrived is all there is.
                        let _ = tokio::time::timeout(ABORT_GRACE, p_write.shutdown()).await;
                        return Err(DeliveryError::PeerEnded { reason, announced, received }
                            .into_io(io::ErrorKind::ConnectionAborted));
                    }
                    if their_fin {
                        return Err(protocol("a second FIN".to_string()));
                    }
                    if announced != received {
                        return Err(DeliveryError::Truncated { announced, received }
                            .into_io(io::ErrorKind::UnexpectedEof));
                    }
                    // All of the peer's data is here: pass the end on to the local side, and
                    // confirm only once that worked.
                    let closed = async {
                        p_write.flush().await?;
                        p_write.shutdown().await
                    };
                    delivering.store(true, Ordering::SeqCst);
                    let closed = closed.await;
                    delivering.store(false, Ordering::SeqCst);
                    last_record_at.store(since_start_ms(), Ordering::SeqCst);
                    if let Err(e) = closed {
                        return Err(abort(e).await);
                    }
                    their_fin = true;
                    peer_fin.store(true, Ordering::SeqCst);
                    let _ = to_outbound.send(ToOutbound::FinAck(received));
                }
                REC_FIN_ACK => {
                    if len != 1 + 8 {
                        return Err(protocol(format!("a FIN_ACK record of {len} bytes")));
                    }
                    if !fin_sent.load(Ordering::SeqCst) {
                        return Err(protocol("a FIN_ACK before this side's FIN".to_string()));
                    }
                    if our_fin_confirmed {
                        return Err(protocol("a second FIN_ACK".to_string()));
                    }
                    let sent = sent_total.load(Ordering::SeqCst);
                    let got = u64_at(&pt[1..9]);
                    if got != sent {
                        return Err(DeliveryError::Unconfirmed { sent, confirmed: got }.into_io(io::ErrorKind::Other));
                    }
                    our_fin_confirmed = true;
                    confirmed.store(true, Ordering::SeqCst);
                    acked.notify_one();
                }
                REC_PROGRESS => {
                    // A sign of life from a peer still delivering our bytes; the arrival above
                    // already restarted the FIN_ACK clock. The count is advisory -- the FIN_ACK
                    // carries the binding one -- so it is not checked against `sent_total`, which
                    // the outbound side may not have updated yet for its very last write.
                    if len != 1 + 8 {
                        return Err(protocol(format!("a PROGRESS record of {len} bytes")));
                    }
                }
                other => return Err(protocol(format!("an unknown record tag 0x{other:02x}"))),
            }
        }
    };

    // The bound on the FIN_ACK wait: from our FIN on, fail after `fin_ack_idle` without a record.
    // Any record counts, not only a growing PROGRESS: the peer's FIN_ACK may be queued behind its
    // own data on a slow return path, and that data arriving is the sign that it is coming.
    let watchdog = async {
        fin_out.notified().await;
        loop {
            if confirmed.load(Ordering::SeqCst) {
                return Ok::<(), io::Error>(());
            }
            let last = fin_out_at.load(Ordering::SeqCst).max(last_record_at.load(Ordering::SeqCst));
            let deadline = start + Duration::from_millis(last) + fin_ack_idle;
            tokio::select! {
                _ = acked.notified() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    if confirmed.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    if delivering.load(Ordering::SeqCst) {
                        // Our own local side is slow, not the peer: whatever the peer sent next
                        // waits behind it. Count that as a sign of life and look again later.
                        last_record_at.store(since_start_ms(), Ordering::SeqCst);
                        continue;
                    }
                    let last = fin_out_at.load(Ordering::SeqCst).max(last_record_at.load(Ordering::SeqCst));
                    if tokio::time::Instant::now() >= start + Duration::from_millis(last) + fin_ack_idle {
                        return Err(DeliveryError::AckTimeout {
                            sent: sent_total.load(Ordering::SeqCst),
                            idle: fin_ack_idle,
                        }
                        .into_io(io::ErrorKind::TimedOut));
                    }
                }
            }
        }
    };

    let (sent, received, ()) = tokio::try_join!(outbound, inbound, watchdog)?;
    // Both directions are confirmed: only now does the transport end, so a relay that drops a
    // whole leg on a half-close can no longer cost anything.
    let _ = tokio::time::timeout(ABORT_GRACE, c_write.shutdown()).await;
    Ok(DeliveryReport { sent, received })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::{
        a2a_initiate, a2a_initiate_with_caps, a2a_respond_verified, a2a_respond_verified_with_caps,
    };
    use crate::noise::{frame, generate_static_keypair, noise_pump};
    use tokio::io::{duplex, split, DuplexStream};

    const IDLE: Duration = Duration::from_secs(60);

    fn normal_end(_: Option<&io::Error>) -> FinReason {
        FinReason::Normal
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n as u32).map(|i| (i % 251) as u8).collect()
    }

    /// Two v2-capable A2A ends over the given transports: handshake with caps on both sides,
    /// returning `(initiator transport, initiator caps, responder transport, responder caps)`.
    async fn v2_handshake(
        a: &mut DuplexStream,
        b: &mut DuplexStream,
    ) -> (TransportState, SessionCaps, TransportState, SessionCaps) {
        let ka = generate_static_keypair();
        let kb = generate_static_keypair();
        let (a_priv, a_pub, b_priv, b_pub) = (ka.private, ka.public, kb.private, kb.public);
        let (mut ar, mut aw) = split(a);
        let (mut br, mut bw) = split(b);
        let (ini, resp) = tokio::join!(
            a2a_initiate_with_caps(&mut aw, &mut ar, &a_priv, &b_pub, SessionCaps::DELIVERY_ACK),
            a2a_respond_verified_with_caps(&mut bw, &mut br, &b_priv, &a_pub, SessionCaps::DELIVERY_ACK),
        );
        let (ta, ca) = ini.expect("initiator handshake");
        let (tb, cb) = resp.expect("responder handshake");
        (ta, ca, tb, cb)
    }

    /// How the test relay treats one direction, frame by frame -- a relay sees the 2-byte
    /// frame lengths in the clear, and a frame boundary is the only place it can cut a Noise
    /// stream without the receiver's AEAD noticing.
    #[derive(Clone, Copy)]
    enum Cut {
        /// Forward everything; an end of the source becomes an end towards the destination.
        Never,
        /// Forward this many frames, then end the destination cleanly and drop the rest.
        CleanEofAfter(usize),
        /// Forward this many frames, then swallow every later one and never close.
        SwallowAfter(usize),
    }

    async fn relay_dir(mut from: tokio::io::ReadHalf<DuplexStream>, mut to: tokio::io::WriteHalf<DuplexStream>, cut: Cut) {
        let mut frames = 0usize;
        let mut closed = false;
        loop {
            let mut len = [0u8; 2];
            if from.read_exact(&mut len).await.is_err() {
                break;
            }
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            if from.read_exact(&mut body).await.is_err() {
                break;
            }
            frames += 1;
            match cut {
                Cut::CleanEofAfter(k) if frames > k => {
                    if !closed {
                        let _ = to.shutdown().await;
                        closed = true;
                    }
                    continue; // keep draining, so the sender is never blocked by this relay
                }
                Cut::SwallowAfter(k) if frames > k => continue,
                _ => {}
            }
            if to.write_all(&len).await.is_err() || to.write_all(&body).await.is_err() {
                break;
            }
            let _ = to.flush().await;
        }
        if !matches!(cut, Cut::SwallowAfter(_)) {
            let _ = to.shutdown().await;
        } else {
            // A swallowing relay keeps the destination open forever (a silent path).
            std::future::pending::<()>().await;
        }
    }

    /// A relay between member A's transport and member B's, each direction with its own rule.
    /// Returns A's and B's transport ends.
    fn relay(a_to_b: Cut, b_to_a: Cut) -> (DuplexStream, DuplexStream) {
        let (a_end, relay_a) = duplex(64 * 1024);
        let (b_end, relay_b) = duplex(64 * 1024);
        let (ra_r, ra_w) = split(relay_a);
        let (rb_r, rb_w) = split(relay_b);
        tokio::spawn(relay_dir(ra_r, rb_w, a_to_b));
        tokio::spawn(relay_dir(rb_r, ra_w, b_to_a));
        (a_end, b_end)
    }

    /// The park pump before CADS-Tunnel#856 in miniature: forwards both directions until EITHER
    /// side ends its write direction, then drops both legs at once.
    fn teardown_on_half_close_relay() -> (DuplexStream, DuplexStream) {
        let (a_end, relay_a) = duplex(64 * 1024);
        let (b_end, relay_b) = duplex(64 * 1024);
        tokio::spawn(async move {
            let (mut ar, mut aw) = split(relay_a);
            let (mut br, mut bw) = split(relay_b);
            let a_to_b = async {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match ar.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if bw.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            };
            let b_to_a = async {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match br.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if aw.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            };
            // The first direction to end takes the whole pair down.
            tokio::select! {
                _ = a_to_b => {}
                _ = b_to_a => {}
            }
            // Dropping the halves closes both legs in both directions.
        });
        (a_end, b_end)
    }

    /// A relay like the edge since CADS-Tunnel#856, with room for `to_a_capacity` bytes in flight
    /// towards A (socket buffers on both hops plus the edge's own hold several MiB on a real TCP
    /// path): each direction is copied on its own, the end of a source is passed on as a
    /// half-close, and a failed write towards one side does not take the other direction down.
    fn edge_like_relay(to_a_capacity: usize) -> (DuplexStream, DuplexStream) {
        let (a_end, relay_a) = duplex(to_a_capacity);
        let (b_end, relay_b) = duplex(64 * 1024);
        tokio::spawn(async move {
            let (mut ra_r, mut ra_w) = split(relay_a);
            let (mut rb_r, mut rb_w) = split(relay_b);
            let b_to_a = async {
                let _ = tokio::io::copy(&mut rb_r, &mut ra_w).await;
                let _ = ra_w.shutdown().await;
            };
            let a_to_b = async {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match ra_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        // B gone: swallow, as the edge's other leg does after a reset.
                        Ok(n) => {
                            let _ = rb_w.write_all(&buf[..n]).await;
                        }
                    }
                }
                let _ = rb_w.shutdown().await;
            };
            tokio::join!(b_to_a, a_to_b);
        });
        (a_end, b_end)
    }

    #[test]
    fn a_transport_end_is_worded_by_what_was_due_299() {
        // #299 review: "delivery not confirmed" only where this side's FIN was out and the
        // confirmation is what is missing -- not for a session cut while a direction was still
        // open, and never for a sender whose bytes WERE confirmed.
        let end = |fin_sent: bool, confirmed: bool, peer_fin: bool| {
            DeliveryError::TransportEnded {
                received: 7,
                peer_fin,
                sent: 5,
                fin_sent,
                confirmed,
                cause: "end of stream".to_string(),
            }
            .to_string()
        };
        for peer_fin in [false, true] {
            let msg = end(false, false, peer_fin);
            assert!(msg.starts_with("session cut:") && msg.contains("5 bytes sent"), "{msg}");
        }
        let msg = end(true, false, false);
        assert!(msg.starts_with("delivery not confirmed:"), "{msg}");
        assert!(msg.contains("our 5 bytes") && msg.contains("end of the peer's stream (7 bytes received"), "{msg}");
        let msg = end(true, false, true);
        assert!(msg.starts_with("delivery not confirmed:") && msg.contains("our 5 bytes"), "{msg}");
        let msg = end(true, true, false);
        assert!(!msg.contains("not confirmed") && msg.contains("our 5 bytes were confirmed"), "{msg}");
        assert!(msg.contains("end of the peer's stream (7 bytes received"), "{msg}");
        let msg = end(true, true, true);
        assert!(!msg.contains("not confirmed") && msg.contains("our 5 bytes were confirmed"), "{msg}");
    }

    #[test]
    fn session_caps_round_trip_and_ignore_anything_that_is_not_a_caps_payload_299() {
        assert!(SessionCaps::NONE.to_payload().is_empty(), "no caps = the pre-v2 empty payload");
        let p = SessionCaps::DELIVERY_ACK.to_payload();
        assert_eq!(p, b"CTC\x01\x00\x01".to_vec());
        assert_eq!(SessionCaps::from_payload(&p), Some(SessionCaps::DELIVERY_ACK));
        assert_eq!(SessionCaps::from_payload(&[]), None, "an old peer's empty payload");
        assert_eq!(SessionCaps::from_payload(b"CTC\x01\x00"), None, "too short");
        assert_eq!(SessionCaps::from_payload(b"XYZ\x01\x00\x01"), None, "not our magic");
        assert_eq!(SessionCaps::from_payload(b"CTC\x00\x00\x01"), None, "version 0 does not exist");
        // A later version with more flags and extra bytes still reads; unknown bits fall away
        // in the intersection with what this side runs.
        let later = SessionCaps::from_payload(b"CTC\x07\x80\x01extra").expect("a later version reads");
        assert_eq!(later.flags(), 0x8001);
        assert_eq!(later.intersect(SessionCaps::DELIVERY_ACK), SessionCaps::DELIVERY_ACK);
        assert!(!SessionCaps::NONE.delivery_ack() && SessionCaps::DELIVERY_ACK.delivery_ack());
        for b in 0..=255u8 {
            assert_eq!(FinReason::from_byte(b).to_byte(), b, "every reason byte round-trips");
        }
    }

    #[tokio::test]
    async fn two_v2_peers_agree_on_delivery_ack_and_an_opt_out_on_either_side_means_legacy_299() {
        let (mut a, mut b) = duplex(64 * 1024);
        let (_, ca, _, cb) = v2_handshake(&mut a, &mut b).await;
        assert!(ca.delivery_ack() && cb.delivery_ack(), "both ends agree on v2");

        for (offer, own) in [(SessionCaps::NONE, SessionCaps::DELIVERY_ACK), (SessionCaps::DELIVERY_ACK, SessionCaps::NONE)] {
            let ka = generate_static_keypair();
            let kb = generate_static_keypair();
            let (mut a, mut b) = duplex(64 * 1024);
            let (mut ar, mut aw) = split(&mut a);
            let (mut br, mut bw) = split(&mut b);
            let (ini, resp) = tokio::join!(
                a2a_initiate_with_caps(&mut aw, &mut ar, &ka.private, &kb.public, offer),
                a2a_respond_verified_with_caps(&mut bw, &mut br, &kb.private, &ka.public, own),
            );
            assert_eq!(ini.expect("initiator").1, SessionCaps::NONE);
            assert_eq!(resp.expect("responder").1, SessionCaps::NONE);
        }
    }

    #[tokio::test]
    async fn delivery_ack_v2_falls_back_to_legacy_with_an_old_peer_299() {
        // An old responder (`a2a_respond_verified`, as every agent before v2 runs it) reads the
        // offer in message 1, ignores it and answers with an empty payload: the new initiator
        // must land on the legacy pump, and data must flow both ways with the old peer's
        // `noise_pump`. Same for an old initiator (`a2a_initiate`) talking to a new responder.
        let ka = generate_static_keypair();
        let kb = generate_static_keypair();
        let (a_priv, a_pub, b_priv, b_pub) = (ka.private, ka.public, kb.private, kb.public);

        // New initiator, old responder.
        let (mut a, mut b) = duplex(64 * 1024);
        let ((ta, caps), tb) = {
            let (mut ar, mut aw) = split(&mut a);
            let (mut br, mut bw) = split(&mut b);
            let (ini, resp) = tokio::join!(
                a2a_initiate_with_caps(&mut aw, &mut ar, &a_priv, &b_pub, SessionCaps::DELIVERY_ACK),
                a2a_respond_verified(&mut bw, &mut br, &b_priv, &a_pub),
            );
            (ini.expect("the old responder completes the handshake"), resp.expect("old responder"))
        };
        assert_eq!(caps, SessionCaps::NONE, "an old responder means the legacy session");
        let (a_plain, mut a_app) = duplex(64 * 1024);
        let (b_plain, mut b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump(ta, a, a_plain));
        let pb = tokio::spawn(noise_pump(tb, b, b_plain));
        a_app.write_all(b"from the new agent").await.unwrap();
        b_app.write_all(b"from the old agent").await.unwrap();
        let mut got_b = [0u8; 18];
        b_app.read_exact(&mut got_b).await.unwrap();
        let mut got_a = [0u8; 18];
        a_app.read_exact(&mut got_a).await.unwrap();
        assert_eq!(&got_b, b"from the new agent");
        assert_eq!(&got_a, b"from the old agent");
        drop(a_app);
        drop(b_app);
        pa.await.unwrap().unwrap();
        pb.await.unwrap().unwrap();

        // Old initiator, new responder: no offer in message 1, so no answer in message 2 --
        // the old initiator's handshake must complete exactly as against an old responder.
        let (mut a, mut b) = duplex(64 * 1024);
        let (ta, (tb, caps)) = {
            let (mut ar, mut aw) = split(&mut a);
            let (mut br, mut bw) = split(&mut b);
            let (ini, resp) = tokio::join!(
                a2a_initiate(&mut aw, &mut ar, &a_priv, &b_pub),
                a2a_respond_verified_with_caps(&mut bw, &mut br, &b_priv, &a_pub, SessionCaps::DELIVERY_ACK),
            );
            (ini.expect("old initiator"), resp.expect("the new responder accepts an old initiator"))
        };
        assert_eq!(caps, SessionCaps::NONE, "an old initiator means the legacy session");
        let (a_plain, mut a_app) = duplex(64 * 1024);
        let (b_plain, mut b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump(ta, a, a_plain));
        let pb = tokio::spawn(noise_pump(tb, b, b_plain));
        a_app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        b_app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        drop(a_app);
        drop(b_app);
        pa.await.unwrap().unwrap();
        pb.await.unwrap().unwrap();
    }

    /// Run a v2 session between A and B over the given transport ends: A's local input is
    /// `a_input` followed by EOF unless `a_input` is `None` (then A's input stays open), B's
    /// likewise. Returns both pump results and what each side's local output received.
    async fn run_pair(
        mut a_t: DuplexStream,
        mut b_t: DuplexStream,
        a_input: Option<Vec<u8>>,
        b_input: Option<Vec<u8>>,
        idle: Duration,
    ) -> (io::Result<DeliveryReport>, io::Result<DeliveryReport>, Vec<u8>, Vec<u8>) {
        let (ta, ca, tb, cb) = v2_handshake(&mut a_t, &mut b_t).await;
        assert!(ca.delivery_ack() && cb.delivery_ack());
        let (a_plain, a_app) = duplex(64 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, idle, normal_end));
        let pb = tokio::spawn(noise_pump_v2(tb, b_t, b_plain, idle, normal_end));
        // Input and output of one member's local side as two tasks: the write half must outlive
        // the end of the output -- dropping both halves would end the input as well.
        let side = |app: DuplexStream, input: Option<Vec<u8>>| {
            let (mut r, mut w) = split(app);
            tokio::spawn(async move {
                if let Some(bytes) = input {
                    let _ = w.write_all(&bytes).await;
                    let _ = w.shutdown().await;
                }
                std::future::pending::<()>().await;
                let _ = w.flush().await;
            });
            tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = r.read_to_end(&mut got).await;
                got
            })
        };
        let a_side = side(a_app, a_input);
        let b_side = side(b_app, b_input);
        let ra = pa.await.expect("A's pump task");
        let rb = pb.await.expect("B's pump task");
        let a_got = a_side.await.expect("A's app");
        let b_got = b_side.await.expect("B's app");
        (ra, rb, a_got, b_got)
    }

    #[tokio::test]
    async fn delivery_ack_v2_half_closed_member_still_receives_299() {
        // #299's shape: A's local input is at EOF from the start, B sends N bytes and ends.
        // A must receive every byte and both ends must report success with the right counts.
        let data = payload(100_000);
        let (a_t, b_t) = relay(Cut::Never, Cut::Never);
        let (ra, rb, a_got, b_got) = run_pair(a_t, b_t, Some(Vec::new()), Some(data.clone()), IDLE).await;
        assert_eq!(a_got, data, "A, whose input ended at once, still receives everything");
        assert!(b_got.is_empty());
        assert_eq!(ra.expect("A confirmed"), DeliveryReport { sent: 0, received: data.len() as u64 });
        assert_eq!(rb.expect("B confirmed"), DeliveryReport { sent: data.len() as u64, received: 0 });

        // The same over a relay that drops BOTH directions of a leg as soon as one side ends
        // its write direction (the park pump before CADS-Tunnel#856): v2 ends its input with a
        // FIN record instead of a transport half-close, so nothing is lost even there...
        let (a_t, b_t) = teardown_on_half_close_relay();
        let (ra, rb, a_got, _) = run_pair(a_t, b_t, Some(Vec::new()), Some(data.clone()), IDLE).await;
        assert_eq!(a_got, data, "v2 does not depend on the relay passing a half-close on");
        ra.expect("A confirmed over the tearing relay");
        rb.expect("B confirmed over the tearing relay");

        // ...whereas the legacy pump over that relay is exactly #299: A receives nothing and
        // still reports success.
        let (mut a_t, mut b_t) = teardown_on_half_close_relay();
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(64 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump(ta, a_t, a_plain));
        let pb = tokio::spawn(noise_pump(tb, b_t, b_plain));
        let (mut a_r, mut a_w) = split(a_app);
        a_w.shutdown().await.unwrap();
        // As in #299, A's end of input is through before B's bytes are.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (_b_r, mut b_w) = split(b_app);
        let _ = b_w.write_all(&data).await;
        let _ = b_w.shutdown().await;
        let mut legacy_got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), a_r.read_to_end(&mut legacy_got)).await;
        assert!(legacy_got.len() < data.len(), "the legacy pump loses the data over this relay");
        assert!(pa.await.unwrap().is_ok(), "and still reports Ok -- the silent loss v2 removes");
        let _ = pb.await;
    }

    #[tokio::test]
    async fn delivery_ack_v2_detects_a_clean_eof_injected_by_the_relay_299() {
        // A relay that forwards B -> A for a while and then ends A's side with a perfectly clean
        // EOF at a frame boundary -- indistinguishable from "B finished" for the legacy pump.
        // Frames on B -> A: the handshake's message 2, then DATA records. Cut after 3 DATA.
        let data = payload(200_000);
        let (a_t, b_t) = relay(Cut::Never, Cut::CleanEofAfter(1 + 3));
        let (ra, rb, a_got, _) = run_pair(a_t, b_t, Some(Vec::new()), Some(data.clone()), IDLE).await;
        assert!(a_got.len() < data.len(), "the relay really did cut the stream");
        let ea = ra.expect_err("A must not report a truncated stream as success");
        assert_eq!(ea.kind(), io::ErrorKind::UnexpectedEof);
        match delivery_error(&ea) {
            Some(DeliveryError::TransportEnded { peer_fin: false, received, .. }) => {
                assert_eq!(*received, a_got.len() as u64, "names how much did arrive")
            }
            other => panic!("A must name the missing end of B's stream, got {other:?}: {ea}"),
        }
        assert!(ea.to_string().contains("end of the peer's stream"), "{ea}");
        let eb = rb.expect_err("B's data was not confirmed, so B must not report success either");
        assert!(
            matches!(delivery_error(&eb), Some(DeliveryError::TransportEnded { confirmed: false, .. })),
            "B names its unconfirmed bytes: {eb}"
        );

        // The legacy pump over the same relay: a clean Ok with a truncated stream.
        let (mut a_t, mut b_t) = relay(Cut::Never, Cut::CleanEofAfter(1 + 3));
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(64 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump(ta, a_t, a_plain));
        let pb = tokio::spawn(noise_pump(tb, b_t, b_plain));
        let (mut a_r, mut a_w) = split(a_app);
        let (_b_r, mut b_w) = split(b_app);
        let writer = tokio::spawn(async move {
            let _ = b_w.write_all(&data).await;
            let _ = b_w.shutdown().await;
        });
        let mut legacy_got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), a_r.read_to_end(&mut legacy_got)).await;
        a_w.shutdown().await.unwrap(); // A ends too, so its legacy pump can return
        assert!(legacy_got.len() < 200_000);
        assert!(pa.await.unwrap().is_ok(), "the legacy pump reports the cut as a clean end");
        pb.abort();
        writer.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_ack_v2_reports_unacknowledged_bytes_299() {
        // #299 from the sender's side: B's bytes vanish on the way (the relay swallows B -> A
        // after the handshake, as a dead splice does), and B used to exit 0 with `ok=true`.
        // Under v2 B never gets a FIN_ACK and must fail, naming the bytes that were never
        // confirmed -- bounded, not hanging (paused clock: the bound passes in virtual time).
        let data = payload(50_000);
        let (a_t, b_t) = relay(Cut::Never, Cut::SwallowAfter(1));
        let idle = Duration::from_secs(30);
        let started = tokio::time::Instant::now();
        // Bounded on the test side too: if the watchdog ever stops firing, this fails instead of
        // hanging the test binary.
        let (ra, rb, a_got, _) =
            tokio::time::timeout(idle * 3, run_pair(a_t, b_t, Some(Vec::new()), Some(data.clone()), idle))
                .await
                .expect("both pumps end within the FIN_ACK bound, not never");
        assert!(a_got.is_empty(), "nothing of B's reached A");
        let eb = rb.expect_err("B must not report success for bytes nobody confirmed");
        assert_eq!(eb.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            delivery_error(&eb),
            Some(&DeliveryError::AckTimeout { sent: data.len() as u64, idle }),
            "B names its unconfirmed bytes: {eb}"
        );
        assert!(eb.to_string().contains(&format!("our {} bytes", data.len())), "{eb}");
        assert!(ra.is_err(), "A never heard B's FIN either");
        assert!(started.elapsed() >= idle, "the bound is the FIN_ACK idle time");
        assert!(started.elapsed() < idle * 3, "and nothing waits much longer than that");
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_ack_v2_fin_ack_wait_is_bounded_by_progress_not_by_total_time_299() {
        // A peer that keeps sending keeps the FIN_ACK wait alive: the bound is "no record for
        // `idle`", not "FIN_ACK within `idle`". Hand-rolled peer B: it answers A's FIN only
        // after 3 x idle, but sends a DATA record every idle/2 meanwhile.
        let idle = Duration::from_secs(10);
        let (mut a_t, mut b_t) = duplex(64 * 1024);
        let (ta, _, mut tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, idle, normal_end));
        let (mut a_r, mut a_w) = split(a_app);
        a_w.shutdown().await.unwrap(); // A: FIN(0) at once
        let peer = tokio::spawn(async move {
            let (mut r, mut w) = split(b_t);
            let mut seal = |tag: u8, body: &[u8]| {
                let mut pt = vec![tag];
                pt.extend_from_slice(body);
                let mut ct = vec![0u8; pt.len() + 16];
                let n = tb.write_message(&pt, &mut ct).unwrap();
                frame(&ct[..n])
            };
            let mut ticks = 0u64;
            while ticks < 6 {
                tokio::time::sleep(idle / 2).await;
                w.write_all(&seal(REC_DATA, b"x")).await.unwrap();
                ticks += 1;
            }
            w.write_all(&seal(REC_FIN_ACK, &0u64.to_be_bytes())).await.unwrap();
            w.write_all(&seal(REC_FIN, &fin_body(ticks, FinReason::Normal))).await.unwrap();
            // Keep reading A's records (its FIN, then its FIN_ACK) until A closes.
            let mut sink = Vec::new();
            let _ = r.read_to_end(&mut sink).await;
        });
        let started = tokio::time::Instant::now();
        let report = pa.await.unwrap().expect("a peer that keeps sending is never timed out");
        assert!(started.elapsed() >= idle * 3, "the wait outlasted the bound several times over");
        assert_eq!(report, DeliveryReport { sent: 0, received: 6 });
        let mut got = Vec::new();
        a_r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"xxxxxx");
        peer.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_ack_v2_a_slow_local_consumer_is_not_the_peers_silence_299() {
        // B fills the path first, so its outbound is stuck in a DATA write when A's FIN(0)
        // arrives: B's FIN_ACK then queues behind data that A's stalled consumer holds back, for
        // several times the FIN_ACK bound. The stall is on A's side, so A must not give up on B:
        // once A's consumer reads again, everything is delivered and confirmed. (#299 review:
        // with A's FIN out before B's data, B's FIN_ACK overtook that data and the test passed
        // without the logic it is meant to guard.)
        let idle = Duration::from_secs(10);
        let data = payload(200_000);
        let (mut a_t, mut b_t) = duplex(64 * 1024);
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(16 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, idle, normal_end));
        let pb = tokio::spawn(noise_pump_v2(tb, b_t, b_plain, idle, normal_end));
        let (mut a_r, mut a_w) = split(a_app);
        let (_b_r, mut b_w) = split(b_app);
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            b_w.write_all(&sent).await.unwrap();
            b_w.shutdown().await.unwrap();
            b_w
        });
        tokio::time::sleep(Duration::from_millis(10)).await; // B fills the path
        a_w.shutdown().await.unwrap(); // A: FIN(0) only now
        tokio::time::sleep(idle * 4).await; // A's consumer does not read meanwhile
        assert!(!pa.is_finished(), "A must not have timed out on its own slow consumer");
        let mut got = Vec::new();
        a_r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data);
        assert_eq!(pa.await.unwrap().unwrap(), DeliveryReport { sent: 0, received: data.len() as u64 });
        assert_eq!(pb.await.unwrap().unwrap(), DeliveryReport { sent: data.len() as u64, received: 0 });
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn delivery_ack_v2_tells_the_peer_why_the_session_ended_299() {
        // A's local side ends because A's grant was revoked (the caller maps that, e.g. from its
        // grant gate): A sends FIN with that reason, B learns it as the cause, and both end with
        // an error instead of a clean close (#308: the peer can now say why).
        let (mut a_t, mut b_t) = duplex(64 * 1024);
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(64 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, IDLE, |_: Option<&io::Error>| {
            FinReason::OwnGrantRevoked
        }));
        let pb = tokio::spawn(noise_pump_v2(tb, b_t, b_plain, IDLE, normal_end));
        let (_a_r, mut a_w) = split(a_app);
        a_w.write_all(b"partial").await.unwrap();
        a_w.shutdown().await.unwrap();
        let (mut b_r, _b_w) = split(b_app);
        let ea = pa.await.unwrap().expect_err("an aborting side does not report success");
        assert_eq!(ea.kind(), io::ErrorKind::PermissionDenied);
        assert!(matches!(
            delivery_error(&ea),
            Some(DeliveryError::LocalEnded { reason: FinReason::OwnGrantRevoked, sent: 7, .. })
        ));
        let eb = pb.await.unwrap().expect_err("B learns that the session was cut");
        assert_eq!(eb.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            delivery_error(&eb),
            Some(&DeliveryError::PeerEnded { reason: FinReason::OwnGrantRevoked, announced: 7, received: 7 })
        );
        assert!(eb.to_string().contains("the peer's own channel grant was revoked"), "{eb}");
        let mut got = Vec::new();
        b_r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"partial", "what arrived before the abort was delivered, then EOF");
    }

    #[tokio::test]
    async fn delivery_ack_v2_ends_both_sides_promptly_when_delivery_to_the_local_side_fails_299() {
        // A's local output is gone (its reader dropped): A cannot deliver B's bytes. A must end
        // with an error at once and tell B, instead of the legacy pump's half-alive session.
        let (mut a_t, mut b_t) = duplex(64 * 1024);
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        drop(a_app); // nobody reads A's output
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, IDLE, normal_end));
        let pb = tokio::spawn(noise_pump_v2(tb, b_t, b_plain, IDLE, normal_end));
        let (_b_r, mut b_w) = split(b_app);
        let _ = b_w.write_all(&payload(10_000)).await;
        let ea = tokio::time::timeout(Duration::from_secs(5), pa)
            .await
            .expect("A ends promptly")
            .unwrap()
            .expect_err("A could not deliver, so A must not report success");
        assert!(
            matches!(delivery_error(&ea), Some(DeliveryError::LocalEnded { reason: FinReason::LocalError, .. })),
            "{ea}"
        );
        let eb = tokio::time::timeout(Duration::from_secs(5), pb)
            .await
            .expect("B ends promptly")
            .unwrap()
            .expect_err("B's bytes were not delivered");
        assert!(
            matches!(delivery_error(&eb), Some(DeliveryError::PeerEnded { reason: FinReason::LocalError, .. })),
            "B learns that A's local side failed: {eb}"
        );
    }

    #[tokio::test]
    async fn delivery_ack_v2_rejects_a_fin_whose_count_does_not_match_299() {
        // A peer that announces more than it sent (or a path that lost records without the
        // AEAD noticing, which Noise's implicit nonces rule out -- this pins the check anyway).
        let (mut a_t, mut b_t) = duplex(64 * 1024);
        let (ta, _, mut tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, _a_app) = duplex(64 * 1024);
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, IDLE, normal_end));
        let (_r, mut w) = split(b_t);
        for (tag, body) in [(REC_DATA, b"abc".to_vec()), (REC_FIN, fin_body(5, FinReason::Normal).to_vec())] {
            let mut pt = vec![tag];
            pt.extend_from_slice(&body);
            let mut ct = vec![0u8; pt.len() + 16];
            let n = tb.write_message(&pt, &mut ct).unwrap();
            w.write_all(&frame(&ct[..n])).await.unwrap();
        }
        let ea = pa.await.unwrap().expect_err("a short stream is not a delivered stream");
        assert_eq!(delivery_error(&ea), Some(&DeliveryError::Truncated { announced: 5, received: 3 }));
        assert!(ea.to_string().contains("the peer sent 5 bytes, 3 arrived"), "{ea}");
    }

    #[tokio::test]
    async fn delivery_ack_v2_moves_large_payloads_both_ways_and_confirms_both_299() {
        let a_data = payload(300_000);
        let b_data: Vec<u8> = payload(250_000).into_iter().rev().collect();
        let (a_t, b_t) = relay(Cut::Never, Cut::Never);
        let (ra, rb, a_got, b_got) =
            run_pair(a_t, b_t, Some(a_data.clone()), Some(b_data.clone()), IDLE).await;
        assert_eq!(a_got, b_data);
        assert_eq!(b_got, a_data);
        assert_eq!(ra.unwrap(), DeliveryReport { sent: 300_000, received: 250_000 });
        assert_eq!(rb.unwrap(), DeliveryReport { sent: 250_000, received: 300_000 });
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_ack_v2_a_slow_consumer_behind_an_idle_receiver_keeps_the_sender_waiting_299() {
        // #299's own shape -- A, its input at EOF, receives a file from B -- with a consumer behind
        // A that takes 16 KiB a second and a path that holds 8 MiB in flight. B's FIN is out long
        // before A has delivered the 2 MiB, and A, its input ended, has nothing of its own to
        // send. Without PROGRESS B heard nothing for the whole FIN_ACK bound and failed although
        // every byte arrived (#299 review); with it both ends confirm.
        let data = payload(2 * 1024 * 1024);
        let (mut a_t, mut b_t) = edge_like_relay(8 * 1024 * 1024);
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(64 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let started = tokio::time::Instant::now();
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, DEFAULT_FIN_ACK_IDLE, normal_end));
        let pb = tokio::spawn(noise_pump_v2(tb, b_t, b_plain, DEFAULT_FIN_ACK_IDLE, normal_end));
        let (mut a_r, mut a_w) = split(a_app);
        a_w.shutdown().await.unwrap(); // A: input at EOF from the start
        let consumer = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match a_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            (got, a_w)
        });
        let (_b_r, mut b_w) = split(b_app);
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            b_w.write_all(&sent).await.unwrap();
            b_w.shutdown().await.unwrap();
            b_w
        });
        let rb = pb.await.expect("B's pump task");
        let ra = pa.await.expect("A's pump task");
        let (got, _a_w) = consumer.await.expect("A's consumer");
        drop(writer.await.expect("B's writer"));
        assert_eq!(got.len(), data.len(), "A's consumer got every byte");
        assert_eq!(got, data);
        let took = started.elapsed();
        assert!(took > DEFAULT_FIN_ACK_IDLE * 2, "the delivery really outlasted the bound: {took:?}");
        assert_eq!(
            rb.expect("every byte was delivered, so B must not report a failure"),
            DeliveryReport { sent: data.len() as u64, received: 0 }
        );
        assert_eq!(ra.expect("A confirmed"), DeliveryReport { sent: 0, received: data.len() as u64 });
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_ack_v2_a_stuck_consumer_behind_an_idle_receiver_still_ends_the_sender_299() {
        // The other half of PROGRESS: only growth is reported. A consumer that stops reading for
        // good makes A go quiet once its buffers are full, and B still gives up after the FIN_ACK
        // bound -- naming its unconfirmed bytes -- instead of waiting for ever.
        let data = payload(1024 * 1024);
        let (mut a_t, mut b_t) = edge_like_relay(8 * 1024 * 1024);
        let (ta, _, tb, _) = v2_handshake(&mut a_t, &mut b_t).await;
        let (a_plain, a_app) = duplex(64 * 1024);
        let (b_plain, b_app) = duplex(64 * 1024);
        let started = tokio::time::Instant::now();
        let pa = tokio::spawn(noise_pump_v2(ta, a_t, a_plain, DEFAULT_FIN_ACK_IDLE, normal_end));
        let pb = tokio::spawn(noise_pump_v2(tb, b_t, b_plain, DEFAULT_FIN_ACK_IDLE, normal_end));
        let (a_r, mut a_w) = split(a_app);
        a_w.shutdown().await.unwrap(); // A: input at EOF; A's consumer never reads
        let (_b_r, mut b_w) = split(b_app);
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            b_w.write_all(&sent).await.unwrap();
            b_w.shutdown().await.unwrap();
            b_w
        });
        let eb = tokio::time::timeout(DEFAULT_FIN_ACK_IDLE * 3, pb)
            .await
            .expect("B ends within the bound, not never")
            .expect("B's pump task")
            .expect_err("nothing past A's buffers was delivered, so B must not report success");
        assert_eq!(
            delivery_error(&eb),
            Some(&DeliveryError::AckTimeout { sent: data.len() as u64, idle: DEFAULT_FIN_ACK_IDLE }),
            "{eb}"
        );
        let waited = started.elapsed();
        assert!(waited >= DEFAULT_FIN_ACK_IDLE, "{waited:?}");
        assert!(waited < DEFAULT_FIN_ACK_IDLE + 2 * PROGRESS_EVERY_MAX, "one report at most: {waited:?}");
        // A is held by its consumer; letting go of the consumer ends A too.
        drop(a_r);
        drop(a_w);
        let ra = tokio::time::timeout(Duration::from_secs(10), pa)
            .await
            .expect("A ends once its consumer is gone")
            .expect("A's pump task");
        assert!(ra.is_err(), "A could not deliver B's stream either");
        drop(writer.await.expect("B's writer"));
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_ack_v2_waits_for_the_peers_end_as_long_as_its_input_stays_open_299() {
        // A peer whose input stays open keeps the session alive: confirming our FIN does not end
        // it, and no bound applies to the peer's own direction (an interactive member).
        let (a_t, b_t) = relay(Cut::Never, Cut::Never);
        let run = tokio::spawn(run_pair(a_t, b_t, Some(b"done".to_vec()), None, Duration::from_secs(1)));
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(!run.is_finished(), "B's open input keeps the session (and A) alive far past the bound");
        run.abort();
    }
}
