//! Opaque byte relay (ADR-0015 fallback relay path).
//!
//! When a Client and Agent cannot form a direct P2P path, the Edge relays
//! ciphertext between them. The Edge is provider-blind: it copies bytes without
//! inspecting them. P2.4a is the generic bidirectional relay primitive; P2.4b
//! wires it onto paired QUIC streams (Client stream ↔ Agent tunnel).
//
// trace: REQ-0006, AUF-20261005-018

use ct_common::fallback_framing::{
    Frame, FrameReader, FrameWriter, KeepaliveTracker, KEEPALIVE_DEAD_AFTER, KEEPALIVE_INTERVAL,
    POST_PEER_FIN_IDLE_BOUND,
};
use quinn::{RecvStream, SendStream};
use tokio::io::{
    copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};

/// Emit an Edge relay diagnostic when `CT_EDGE_TRACE` is set (issue #2, mode b).
fn relay_trace(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("CT_EDGE_TRACE").is_some() {
        eprintln!("[edge-trace] {args}");
    }
}

/// #257: bound on `accept_bi`/`open_bi` while splicing a relay pair's data streams.
/// Without this, a paired-but-stalling member that never actualizes its data stream
/// (no credit sent, connection alive) hangs the setup `.await` forever, pinning both
/// the relay task and the peer connection for a per-pair DoS on the relay-fallback
/// path. Same 5s value as `serve.rs`'s `RELAY_OPEN_BI_TIMEOUT` for the analogous
/// single-stream open — not shared cross-module since each file in this crate keeps
/// its own local timeout constants (see channel_authorize.rs, relay_gate.rs).
const RELAY_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Relay bytes both directions between `a` and `b` until both sides close.
/// Returns `(bytes a→b, bytes b→a)`. The bytes are never inspected.
pub async fn relay<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional(a, b).await
}

/// Pump one direction: read from `r`, write each chunk to `w`, flushing
/// whenever `r`'s *next* read isn't already sitting ready, until `r` reaches
/// EOF, then shut `w` down. The per-direction byte count + trace make a
/// stalled direction visible in real time (issue #2, mode b: the agent's
/// reply reached the edge but never made it back to the client).
///
/// AUF-20261005-018 / INC-20261005-203: the predecessor rule (#338) flushed
/// only when the just-completed read was **short** (`n < buf.len()`). That
/// conflated "short read" with "source has nothing more right now", which is
/// wrong for a bulk sender whose reads happen to land on exact 16KiB
/// boundaries and then pause without closing (a chunked upload, a paced
/// video feed) — every read is full-buffer, so the old rule never flushed,
/// and the sink stayed silent until the source eventually closed or sent a
/// short tail. The actual signal for "the source has nothing more right now"
/// is whether the *next* read is already ready, not the size of the read
/// that just completed: [`peek_next_read`] races it against an
/// always-ready marker and reports [`NextRead::Idle`] exactly when the
/// source has gone quiet, which is when this function flushes. A run of
/// back-to-back full reads (the #338 bulk case) still coalesces without an
/// intermediate flush, since each one's "next read" is already ready.
///
/// `shutdown()` at EOF is unconditional and, for every concrete writer this
/// crate hands to `pump_dir` in production, already drains any
/// writer-internal buffered output before the underlying transport closes
/// (`quinn::SendStream`'s `poll_flush` is a no-op so this is moot there;
/// `tokio_rustls`'s `poll_shutdown` loops `while session.wants_write() {
/// write_io(cx) }`; `WsByteStream`'s `poll_write` already flushes the
/// WebSocket sink inline) — so EOF needs no separate flush call of its own.
/// Render an error together with its full `source()` chain.
///
/// Without this, a relay failure surfaces as the bare top-level message. For
/// quinn that message is `"connection lost"` — the `WriteError`/`ReadError`
/// variant name — which says a connection died but not *why*: the actual
/// [`quinn::ConnectionError`] (`TimedOut`, `Reset`, `ApplicationClosed`, a
/// transport error) is one `source()` hop down and was being dropped on the
/// floor. That distinction is the whole diagnosis for a mid-flight relay
/// death (#214): an idle-timeout death and a peer reset need opposite fixes,
/// and "connection lost" alone cannot tell them apart.
fn with_cause_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        // quinn re-states the outer message on some hops; don't repeat it.
        if !out.ends_with(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        src = s.source();
    }
    out
}

/// Annotate a relay I/O failure with its direction and full cause chain,
/// keeping the original `ErrorKind` so callers can still match on it.
fn relay_io_error(e: std::io::Error, dir: &str, label: &str) -> std::io::Error {
    let kind = e.kind();
    std::io::Error::new(kind, format!("relay {label} {dir}: {}", with_cause_chain(&e)))
}

/// The exact text a relay leg's end is logged with: which relay (`label`),
/// which side (`a->b` / `b->a`, or the framed relay's `browser->agent`) and
/// why (`"EOF"`, or an I/O error's own rendering). Factored out as a pure
/// function so a test can check the wording directly, without capturing
/// process output (AUF-20261005-018 criterion 7).
fn relay_leg_end_line(label: &str, dir: &str, reason: &str) -> String {
    format!("relay {label} {dir}: leg ended ({reason})")
}

/// Emit the leg-end line. Always on (unlike [`relay_trace`]'s
/// `CT_EDGE_TRACE` gate) — a relay leg ending, especially on error, is
/// operational signal worth keeping visible by default, and it is one line
/// per leg's end, not per chunk.
fn log_relay_leg_end(label: &str, dir: &str, reason: &str) {
    eprintln!("{}", relay_leg_end_line(label, dir, reason));
}

/// Map an I/O error through [`relay_io_error`] and log the leg's end before
/// propagating it, so every error exit from a relay leg is covered by the
/// same line [`log_relay_leg_end`] emits for a clean EOF.
fn log_leg_end_on_err<T>(res: std::io::Result<T>, dir: &str, label: &str) -> std::io::Result<T> {
    res.map_err(|e| {
        let err = relay_io_error(e, dir, label);
        log_relay_leg_end(label, dir, &err.to_string());
        err
    })
}

/// The outcome of racing the next read on `r` against an always-ready
/// marker (see [`peek_next_read`]) — the shared idle-detection primitive
/// behind the AUF-20261005-018 flush-timing fix, used by both `pump_dir` and
/// `framed_relay`'s browser->agent leg.
enum NextRead {
    /// The read already completed — use its result directly. Dropping it
    /// here would silently lose (a real read happened) or duplicate (a
    /// second read would re-consume nothing but still cost a syscall) data
    /// already pulled off the source.
    Data(std::io::Result<usize>),
    /// The read is not ready yet: the source has gone idle. The caller must
    /// flush before it may actually wait for more data, so a paused-but-not-
    /// closed sender's bytes are visible at the sink promptly.
    Idle,
}

/// Race the next read on `r` against an immediately-ready marker. `biased`
/// polls `r.read` FIRST: if that returns `Ready` on the very first poll
/// (data — or EOF — already sitting there), [`NextRead::Data`] wins without
/// ever touching the second branch; only if `r.read` is genuinely `Pending`
/// does the always-ready marker resolve, yielding [`NextRead::Idle`].
/// Dropping the unfinished `read` future in that case is safe: tokio's
/// `AsyncReadExt::read` has not pulled any bytes off `r` while `Pending`, so
/// nothing is lost by awaiting a fresh call to it later.
async fn peek_next_read<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> NextRead {
    tokio::select! {
        biased;
        res = r.read(buf) => NextRead::Data(res),
        () = std::future::ready(()) => NextRead::Idle,
    }
}

async fn pump_dir<R, W>(mut r: R, mut w: W, dir: &str, label: &str) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    let mut n = log_leg_end_on_err(r.read(&mut buf).await, dir, label)?;
    loop {
        if n == 0 {
            let _ = w.shutdown().await;
            log_relay_leg_end(label, dir, "EOF");
            break;
        }
        if total == 0 {
            relay_trace(format_args!("relay {label} {dir}: first {n} bytes"));
        }
        total += n as u64;
        log_leg_end_on_err(w.write_all(&buf[..n]).await, dir, label)?;
        n = match peek_next_read(&mut r, &mut buf).await {
            NextRead::Data(res) => log_leg_end_on_err(res, dir, label)?,
            NextRead::Idle => {
                log_leg_end_on_err(w.flush().await, dir, label)?;
                log_leg_end_on_err(r.read(&mut buf).await, dir, label)?
            }
        };
    }
    relay_trace(format_args!("relay {label} {dir}: {total} bytes total then EOF"));
    Ok(total)
}

/// Relay both directions between an `a` side (`a_recv`/`a_send`) and a `b` side,
/// pumping each direction independently so the reverse direction is never
/// starved by the forward one. Returns `(bytes a→b, bytes b→a)`.
async fn relay_pair<AR, AW, BR, BW>(
    a_recv: AR,
    a_send: AW,
    b_recv: BR,
    b_send: BW,
    label: &str,
) -> std::io::Result<(u64, u64)>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
{
    let fwd = pump_dir(a_recv, b_send, "a->b", label);
    let rev = pump_dir(b_recv, a_send, "b->a", label);
    tokio::try_join!(fwd, rev)
}

/// Relay between a Client's QUIC stream and an Agent's QUIC tunnel stream,
/// pumping `client→agent` and `agent→client` independently (each flushed per
/// chunk) so the agent's reply can't be stranded behind an idle forward
/// direction. `label` (a token hex) tags the per-direction trace.
pub async fn relay_quic(
    client_send: SendStream,
    client_recv: RecvStream,
    agent_send: SendStream,
    agent_recv: RecvStream,
    label: &str,
) -> std::io::Result<(u64, u64)> {
    // a = client, b = agent: a→b is client→agent, b→a is agent→client.
    relay_pair(client_recv, client_send, agent_recv, agent_send, label).await
}

/// Splice two channel members' connections through the edge relay (#72
/// AF4-session-resilience). When two paired agents cannot reach each other on the
/// direct path (NAT / firewall / dial timeout — see `ChannelDialError::Unreachable`),
/// each connects to the edge instead; the edge accepts one bidirectional stream from
/// each connection and forwards **ciphertext** between them via [`relay_quic`], so the
/// Noise_IK session stays end-to-end (the edge sees only opaque bytes). Returns the
/// `(a→b, b→a)` byte counts when either side closes. Reuses the ADR-0015 relay core.
pub async fn relay_two_connections(
    conn_a: &quinn::Connection,
    conn_b: &quinn::Connection,
    label: &str,
) -> std::io::Result<(u64, u64)> {
    relay_two_connections_with_timeout(conn_a, conn_b, label, RELAY_SETUP_TIMEOUT).await
}

/// [`relay_two_connections`] with an injectable setup timeout (#257) — split out so a
/// test can prove the timeout fires without a real 5s wait.
async fn relay_two_connections_with_timeout(
    conn_a: &quinn::Connection,
    conn_b: &quinn::Connection,
    label: &str,
    setup_timeout: std::time::Duration,
) -> std::io::Result<(u64, u64)> {
    // Name the stage as well as the ConnectionError: "connection lost" during
    // stream setup and during the pump are different failures (#214).
    let to_io = |stage: &'static str| {
        move |e: quinn::ConnectionError| {
            std::io::Error::other(format!("{label} {stage}: {e}"))
        }
    };
    let timed_out = |stage: &'static str| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{label} {stage}: relay setup timed out"))
    };
    let (send_a, recv_a) = tokio::time::timeout(setup_timeout, conn_a.accept_bi())
        .await
        .map_err(|_| timed_out("accept_bi(a)"))?
        .map_err(to_io("accept_bi(a)"))?;
    let (send_b, recv_b) = tokio::time::timeout(setup_timeout, conn_b.accept_bi())
        .await
        .map_err(|_| timed_out("accept_bi(b)"))?
        .map_err(to_io("accept_bi(b)"))?;
    relay_quic(send_a, recv_a, send_b, recv_b, label).await
}

/// Splice a channel tunnel through the edge, **preserving the direct-path stream
/// roles** (#72 AF4-session-resilience) so the agents' `run_channel_session` works
/// unchanged over the relay: the **initiator** opens its data bi-stream (the edge
/// *accepts* it), and the **acceptor** accepts a bi-stream (the edge *opens* it). This
/// matters because in `Noise_IK` the responder reads first — it never writes to
/// actualize an opened stream — so a symmetric accept-both relay would hang. The edge
/// forwards ciphertext between the two; the Noise session stays end-to-end.
pub async fn relay_initiator_to_acceptor(
    initiator_conn: &quinn::Connection,
    acceptor_conn: &quinn::Connection,
    label: &str,
) -> std::io::Result<(u64, u64)> {
    relay_initiator_to_acceptor_with_timeout(initiator_conn, acceptor_conn, label, RELAY_SETUP_TIMEOUT).await
}

/// [`relay_initiator_to_acceptor`] with an injectable setup timeout (#257) — split out
/// so a test can prove the timeout fires without a real 5s wait.
async fn relay_initiator_to_acceptor_with_timeout(
    initiator_conn: &quinn::Connection,
    acceptor_conn: &quinn::Connection,
    label: &str,
    setup_timeout: std::time::Duration,
) -> std::io::Result<(u64, u64)> {
    // Initiator opened its data stream (actualised by Noise msg1) — accept it.
    let (send_i, recv_i) = next_session_bi_with_timeout(initiator_conn, true, label, setup_timeout).await?;
    // Open the data stream toward the acceptor; it becomes visible to the acceptor's
    // accept_bi as soon as relay_quic writes the first relayed bytes into it.
    let (send_a, recv_a) = next_session_bi_with_timeout(acceptor_conn, false, label, setup_timeout).await?;
    // a = initiator, b = acceptor: recv_i (msg1…) → send_a, recv_a (msg2…) → send_i.
    relay_quic(send_i, recv_i, send_a, recv_a, label).await
}

/// #591 (#495 U2 slice 2): ONE side's fresh session bi-stream under the direct-path role
/// contract [`relay_initiator_to_acceptor`] has always applied — the **initiator** opened
/// its stream, so the edge `accept_bi()`s it; the **acceptor** expects the edge to open,
/// so the edge `open_bi()`s toward it. Split out of the two-connection splice so the
/// unified pairer (`channel_broker::finish_stream_pair_inner`) can resolve each QUIC
/// side's leg INDEPENDENTLY of what transport the other side arrived on (a `:443` stream
/// member has no bi-stream to open) while keeping the per-side wire behaviour, the
/// [`RELAY_SETUP_TIMEOUT`] bound and the stage-tagged error text (#214/#257) byte-identical
/// to the QUIC-native path — which now goes through this very function.
pub async fn next_session_bi(
    conn: &quinn::Connection,
    initiator: bool,
    label: &str,
) -> std::io::Result<(SendStream, RecvStream)> {
    next_session_bi_with_timeout(conn, initiator, label, RELAY_SETUP_TIMEOUT).await
}

async fn next_session_bi_with_timeout(
    conn: &quinn::Connection,
    initiator: bool,
    label: &str,
    setup_timeout: std::time::Duration,
) -> std::io::Result<(SendStream, RecvStream)> {
    // Name the stage as well as the ConnectionError: "connection lost" during
    // stream setup and during the pump are different failures (#214).
    let to_io = |stage: &'static str| {
        move |e: quinn::ConnectionError| {
            std::io::Error::other(format!("{label} {stage}: {e}"))
        }
    };
    let timed_out = |stage: &'static str| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{label} {stage}: relay setup timed out"))
    };
    if initiator {
        tokio::time::timeout(setup_timeout, conn.accept_bi())
            .await
            .map_err(|_| timed_out("accept_bi(initiator)"))?
            .map_err(to_io("accept_bi(initiator)"))
    } else {
        tokio::time::timeout(setup_timeout, conn.open_bi())
            .await
            .map_err(|_| timed_out("open_bi(acceptor)"))?
            .map_err(to_io("open_bi(acceptor)"))
    }
}

/// Splice two **generic** duplex byte streams through the edge relay (#106
/// relay-splice-generic). Unlike [`relay_quic`] / [`relay_initiator_to_acceptor`],
/// which relay over a *separate* quinn bi-stream opened after admission, a member
/// admitted over a non-quinn transport (e.g. a `:443` TLS-over-TCP front-door stream,
/// for a member whose network blocks the channel UDP/TCP ports) carries its data on the
/// **same** duplex it joined on — there is no second stream to open/accept, so a
/// symmetric split-and-pump is exactly right. Each stream is `tokio::io::split` into
/// halves and pumped through the same per-direction, per-chunk-flushed core as
/// [`relay_quic`] (so a Noise handshake reply isn't stranded behind an idle forward
/// direction). The Noise_IK session stays end-to-end; the edge sees only ciphertext.
/// Returns `(bytes a→b, bytes b→a)` when either side closes.
pub async fn relay_streams<A, B>(a: A, b: B, label: &str) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_recv, a_send) = tokio::io::split(a);
    let (b_recv, b_send) = tokio::io::split(b);
    relay_pair(a_recv, a_send, b_recv, b_send, label).await
}

/// The codec's dead-peer bound ([`KEEPALIVE_DEAD_AFTER`], 24s = 3x the cadence)
/// in the milliseconds the clock-free [`KeepaliveTracker`] speaks. ACKs are
/// cumulative ([`KeepaliveTracker::ack`]), so a crossing ACK can never produce
/// a false dead verdict.
const FRAMED_KEEPALIVE_DEAD_AFTER_MS: u64 = KEEPALIVE_DEAD_AFTER.as_millis() as u64;

/// Cross-leg notifications for [`framed_relay`]: everything the agent->browser
/// (reader) leg learns that the browser->agent (writer-owner) leg must act on.
/// The codec contract mandates ONE writer-owner per direction, so the reader leg
/// never touches the agent-bound writer itself -- it sends these instead.
enum FramedEvent {
    /// A peer keepalive whose [`Frame::Keepalive`]`.should_ack` verdict was
    /// `true` (the reader evaluates the bounded-ACK rule itself): echo it.
    Ack(u64),
    /// The peer acked (cumulatively) every keepalive counter `<=` this value.
    AckSeen(u64),
    /// The peer sent its in-band FIN (data-EOF) -- for the termination rule.
    PeerFin,
}

/// `sleep_until` an optional deadline; `None` never fires. Lets the liveness arm
/// of [`framed_relay`]'s select stay inert while no keepalive is outstanding.
async fn maybe_deadline(d: Option<tokio::time::Instant>) {
    match d {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// Framed fallback relay for an `'F'`-registered TLS-TCP Agent (#528). Only the
/// **edge<->agent** hop speaks the `ct_common::fallback_framing` codec; the
/// browser side stays raw. `agent` is the parked Agent's fallback stream
/// (post-`TCP_PING_STOP`); `browser` is the delivered Client stream.
///
/// Structure (per the codec's normative v4 contract -- read that module doc
/// first):
/// - **One writer-owner per direction.** The browser->agent leg exclusively owns
///   the agent-bound [`FrameWriter`]: browser DATA, keepalive injection on 8s
///   send-silence ([`KEEPALIVE_INTERVAL`], the park phase's cadence), ACK
///   echoes, the own FIN
///   and the final shutdown all go through it, serialized by construction. The
///   agent->browser leg owns the [`FrameReader`] plus the browser write half,
///   and forwards what the writer-owner must know as [`FramedEvent`]s over a
///   bounded channel.
/// - **FIN semantics.** Browser EOF => in-band FIN toward the agent (the TCP
///   stream stays open both ways so keepalives can protect the reply's silent
///   tail). Peer FIN => shutdown toward the browser, relay continues (trailing
///   keepalives stay legal). The clean-EOF **implicit FIN** (an agent ending via
///   TLS close_notify instead of an explicit FIN frame) lands on the same path:
///   the reader leg finishes, the writer leg keeps pumping browser->agent until
///   its own natural end. **Termination is this caller's duty**: once FIN has
///   passed in BOTH directions the writer-owner calls [`FrameWriter::shutdown`]
///   (TLS close_notify, not an abrupt drop) and the relay returns promptly.
/// - **Liveness.** Injected counters are tracked in the codec's
///   [`KeepaliveTracker`] (cumulative acks); the relay fails `TimedOut` when
///   the oldest outstanding exceeds [`FRAMED_KEEPALIVE_DEAD_AFTER_MS`] (24s).
///   Liveness ends at the peer's FIN (tracker discarded -- a peer is not
///   ACK-obliged after its own FIN, so a verdict then would be a guaranteed
///   false positive); injection does NOT end -- post-peer-FIN keepalives keep
///   flowing untracked as pure middlebox state refresh for the still-open
///   sending direction, until FIN has passed both ways (codec contract, #528
///   review I3). The post-peer-FIN phase itself is bounded by
///   [`POST_PEER_FIN_IDLE_BOUND`] (codec contract, #528 review N2): once no
///   browser DATA has been written for that long after the peer's FIN, the
///   relay FINs its own direction and terminates cleanly -- without it, the
///   untracked injection would hold a data-idle half-closed relay open forever
///   (the keepalives reset the TCP idle timer and keep earning transport-level
///   ACKs, so neither the kernel keepalive nor retransmit escalation ever
///   fires). DATA progress resets the clock, so a legitimate long upload past
///   an early-FINning origin is never cut. Peer keepalives are ACKed iff the reader's own `should_ack`
///   verdict says so and are never forwarded -- a keepalive must not corrupt
///   the raw browser stream.
/// - **DATA flushing.** The agent-bound writer flushes once the *next*
///   browser read isn't already ready (AUF-20261005-018, [`peek_next_read`])
///   rather than merely because the read that just completed was short — a
///   browser that pauses mid-upload after a run of full-buffer reads still
///   needs its bytes visible to the agent promptly; back-to-back full reads
///   still coalesce. The codec flushes KA/ACK/FIN inline itself. The browser
///   leg flushes per chunk, since each DATA frame is already a peer-chosen
///   chunk.
///
/// The relay phase is single-use, exactly like the raw one: it ends only with
/// the connection (no return to a park phase; the worker redials).
/// Returns `(bytes browser->agent, bytes agent->browser)`, application bytes
/// only (frame overhead and keepalives excluded).
pub async fn framed_relay<A, B>(agent: &mut A, browser: &mut B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use std::sync::atomic::{AtomicU64, Ordering};

    let (agent_read, agent_write) = tokio::io::split(agent);
    let (mut browser_read, mut browser_write) = tokio::io::split(browser);
    let mut reader = FrameReader::new(agent_read);
    let mut writer = FrameWriter::new(agent_write);
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<FramedEvent>(8);

    // Shared byte counters (atomics, not `Cell`: the enclosing future must stay
    // `Send` for the spawned serve paths). Loaded after the select below while
    // both leg futures are still pinned in scope, so plain shared borrows.
    let fwd_bytes = AtomicU64::new(0);
    let rev_bytes = AtomicU64::new(0);

    // Agent -> browser: decode frames, forward DATA raw, discard keepalives
    // (reporting ACK-worthy ones), map the peer's FIN onto a browser shutdown.
    // Returns `Ok` at the agent's clean EOF (explicit-FIN'd or the implicit
    // kind) -- consuming trailing keepalives until then, per the contract. An
    // `ev_tx.send` failing means the writer leg already terminated (both FINs
    // passed); nothing is left to notify, so end cleanly.
    let rev_leg = async {
        // Rebind the channel sender as a BODY-LOCAL: an async block's captured
        // upvars are dropped when the FUTURE is dropped, not when its body
        // completes -- and this future stays pinned (completed) until the whole
        // relay returns. Without the rebind, `ev_rx.recv()` in the other leg
        // would never observe the channel closing (a real hang caught by the
        // implicit-FIN test). The allow is load-bearing (#528 review I7):
        // clippy flags this as a redundant local, and a future "cleanup" would
        // silently resurrect the hang.
        #[allow(clippy::redundant_locals)]
        let ev_tx = ev_tx;
        loop {
            match reader.next().await.map_err(|e| relay_io_error(e, "agent->browser", "framed"))? {
                None => {
                    // Clean EOF: the contract's IMPLICIT FIN when no explicit
                    // one preceded it -- converge on the exact same downstream
                    // behavior as Frame::Fin (idempotent if it already ran),
                    // including the explicit PeerFin notification so the
                    // writer-owner learns of it promptly.
                    let _ = browser_write.shutdown().await;
                    let _ = ev_tx.send(FramedEvent::PeerFin).await;
                    return Ok::<(), std::io::Error>(());
                }
                Some(Frame::Data(payload)) => {
                    // An empty DATA frame is a wire-legal no-op (never EOF);
                    // write_all(&[]) forwards nothing, exactly right.
                    rev_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    browser_write
                        .write_all(&payload)
                        .await
                        .map_err(|e| relay_io_error(e, "agent->browser", "framed"))?;
                    browser_write
                        .flush()
                        .await
                        .map_err(|e| relay_io_error(e, "agent->browser", "framed"))?;
                }
                Some(Frame::Keepalive { counter, should_ack }) => {
                    // The reader evaluated the bounded-ACK rule already; a
                    // repeated/regressing counter earns nothing (flood bound).
                    // #528 review I4: `try_send`, never a blocking send -- a
                    // full event channel must not wedge this leg (and with it
                    // the agent read side). A dropped Ack is absorbed by the
                    // cumulative-ACK rule (the next, higher ack covers it) and
                    // the 24s verdict tolerance.
                    if should_ack {
                        let _ = ev_tx.try_send(FramedEvent::Ack(counter));
                    }
                }
                Some(Frame::KeepaliveAck { counter }) => {
                    // Same I4 reasoning: a dropped AckSeen is covered by the
                    // next cumulative ack well inside the verdict bound.
                    let _ = ev_tx.try_send(FramedEvent::AckSeen(counter));
                }
                Some(Frame::Fin) => {
                    // In-band data-EOF: half-close toward the browser; keep
                    // reading (trailing keepalives/acks are contract-legal).
                    let _ = browser_write.shutdown().await;
                    if ev_tx.send(FramedEvent::PeerFin).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    };

    // Browser -> agent: the one writer-owner. Every select arm here is
    // cancel-safe (`read`, `recv`, timers); the frame writes run to completion
    // inside the chosen arm's body, so a frame is never torn by arm selection.
    let fwd_leg = async {
        let mut buf = [0u8; 16 * 1024];
        let mut own_fin = false;
        let mut peer_fin = false;
        let mut events_open = true;
        let mut next_counter: u64 = 0;
        let mut tracker = KeepaliveTracker::new();
        let epoch = tokio::time::Instant::now();
        let now_ms = |epoch: tokio::time::Instant| epoch.elapsed().as_millis() as u64;
        let mut last_send = tokio::time::Instant::now();
        // The post-peer-FIN progress clock (#528 review N2): the moment of the
        // last browser DATA write -- reset to "now" when the peer's FIN lands,
        // so the N2 bound measures idleness WITHIN the post-peer-FIN phase.
        // Distinct from `last_send` on purpose: keepalives/ACKs refresh the
        // middlebox (last_send) but are NOT progress -- only DATA is.
        let mut last_fwd_data = tokio::time::Instant::now();
        loop {
            if own_fin && peer_fin {
                // Termination rule: FIN has passed in both directions -- close
                // promptly (close_notify, #229 class) instead of keeping a
                // finished request's corpse alive with mutual pinging. A
                // shutdown error is not a relay failure: the request completed.
                let _ = writer.shutdown().await;
                return Ok::<(), std::io::Error>(());
            }
            let dead_deadline = tracker.oldest_outstanding_age_ms(now_ms(epoch)).map(|age| {
                tokio::time::Instant::now()
                    + std::time::Duration::from_millis(FRAMED_KEEPALIVE_DEAD_AFTER_MS.saturating_sub(age))
            });
            tokio::select! {
                read = browser_read.read(&mut buf), if !own_fin => {
                    let mut n = read.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                    loop {
                        if n == 0 {
                            // In-band half-close: the agent's reply (and the
                            // keepalives protecting it) can keep flowing.
                            writer.fin().await.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                            own_fin = true;
                            break;
                        }
                        fwd_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        writer.data(&buf[..n]).await.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                        last_fwd_data = tokio::time::Instant::now();
                        // AUF-20261005-018: the same idle-detection as
                        // `pump_dir` (the #338 short-read heuristic's
                        // successor) -- flush as soon as the NEXT browser
                        // read isn't already ready, not merely because this
                        // read happened to be short.
                        match peek_next_read(&mut browser_read, &mut buf).await {
                            NextRead::Data(res) => {
                                n = res.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                                continue;
                            }
                            NextRead::Idle => {
                                writer.flush().await.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                                break;
                            }
                        }
                    }
                    last_send = tokio::time::Instant::now();
                }
                ev = ev_rx.recv(), if events_open => match ev {
                    Some(FramedEvent::Ack(counter)) => {
                        writer
                            .keepalive_ack(counter)
                            .await
                            .map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                        // An ACK is real payload on the wire: it refreshes the
                        // middlebox exactly like a keepalive would, so it resets
                        // the injection timer too.
                        last_send = tokio::time::Instant::now();
                    }
                    Some(FramedEvent::AckSeen(counter)) => tracker.ack(counter),
                    Some(FramedEvent::PeerFin) => {
                        // N2: the idle bound measures from the START of the
                        // post-peer-FIN phase (or the last DATA within it) --
                        // guarded so a duplicate PeerFin (explicit FIN followed
                        // by the clean-EOF notification) cannot extend it.
                        if !peer_fin {
                            last_fwd_data = tokio::time::Instant::now();
                        }
                        peer_fin = true;
                        // Liveness ends at the peer's FIN (codec contract,
                        // #528 review I3): a peer is not ACK-obliged after its
                        // own FIN, so counters still outstanding at this
                        // moment would mature into a guaranteed-false dead
                        // verdict over a healthy half-closed peer at t=24s.
                        // Injection continues (see the timer arm) -- only the
                        // verdict ends here.
                        tracker = KeepaliveTracker::new();
                    }
                    // The reader leg finished: the agent's clean EOF, i.e. the
                    // contract's IMPLICIT FIN (e.g. a TLS close_notify ending
                    // instead of an explicit FIN frame). Same path as the
                    // explicit one; this leg keeps pumping browser->agent
                    // toward its own natural end -- and the agent's write
                    // direction is gone, so pending acks can never arrive:
                    // clear the tracker so the dead verdict cannot misfire.
                    None => {
                        events_open = false;
                        if !peer_fin {
                            last_fwd_data = tokio::time::Instant::now();
                        }
                        peer_fin = true;
                        tracker = KeepaliveTracker::new();
                    }
                },
                _ = tokio::time::sleep_until(last_send + KEEPALIVE_INTERVAL) => {
                    // Inject on own send-silence until FIN has passed BOTH ways
                    // (the loop-top check ends this leg then). Before the
                    // peer's FIN this is a liveness probe: tracked, ACK-obliged.
                    // AFTER the peer's FIN it is pure middlebox state refresh
                    // for the still-open sending direction (#528 review I3: an
                    // origin closing early must not strip a still-running
                    // browser upload of its protection; on a blackholing
                    // middlebox, write errors surface only after minutes of
                    // retransmit escalation) -- deliberately UNTRACKED and not
                    // ACK-obliged, per the codec contract: the peer may no
                    // longer be able to answer, so tracking it would
                    // manufacture a false dead verdict. Do not "simplify" the
                    // untracked send away.
                    let counter = next_counter;
                    next_counter += 1;
                    if !peer_fin {
                        tracker.sent(counter, now_ms(epoch));
                    }
                    writer.keepalive(counter).await.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                    last_send = tokio::time::Instant::now();
                }
                _ = tokio::time::sleep_until(last_fwd_data + POST_PEER_FIN_IDLE_BOUND), if peer_fin && !own_fin => {
                    // #528 review N2: the post-peer-FIN progress-idle bound.
                    // The peer has FINed, and this direction has written no
                    // DATA for the whole bound -- only the untracked keepalives
                    // above have kept the connection alive, and they would keep
                    // it alive FOREVER (they reset the TCP idle timer and keep
                    // earning transport ACKs, so neither the kernel keepalive
                    // nor retransmit escalation ever fires). End cleanly: own
                    // FIN now, then the loop-top both-FINs rule performs the
                    // shutdown (close_notify) and the clean return. No A2-style
                    // event drain before THIS verdict, deliberately: every
                    // input (peer_fin -- monotone and already true per the
                    // guard -- plus last_fwd_data and own_fin, both owned by
                    // this leg) is unfalsifiable by a queued event, so a drain
                    // would document a safeguard that does not exist (the A2
                    // comment's own warning). A browser read racing this arm in
                    // the unbiased select does not falsify it either: at firing
                    // time "no DATA written for the whole bound" is a fact.
                    writer.fin().await.map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                    own_fin = true;
                }
                _ = maybe_deadline(dead_deadline) => {
                    // A2 (both-sided review find): this select is deliberately
                    // unbiased, so the deadline arm can win over a
                    // simultaneously-ready `recv` -- i.e. over an ACK that is
                    // already DELIVERED into the event channel but not yet
                    // applied to the tracker. Drain and apply every queued
                    // event FIRST, then judge. (A bare re-check without
                    // draining would be provably always-true: one arm body per
                    // iteration, and the deadline arithmetic guarantees
                    // age == DEAD_AFTER at firing time -- it would document a
                    // safeguard that does not exist.)
                    loop {
                        match ev_rx.try_recv() {
                            Ok(FramedEvent::Ack(counter)) => {
                                writer
                                    .keepalive_ack(counter)
                                    .await
                                    .map_err(|e| relay_io_error(e, "browser->agent", "framed"))?;
                                last_send = tokio::time::Instant::now();
                            }
                            Ok(FramedEvent::AckSeen(counter)) => tracker.ack(counter),
                            Ok(FramedEvent::PeerFin) => {
                                if !peer_fin {
                                    last_fwd_data = tokio::time::Instant::now();
                                }
                                peer_fin = true;
                                tracker = KeepaliveTracker::new();
                            }
                            // Empty or Disconnected: nothing more is queued
                            // (a Disconnected channel is the implicit-FIN path;
                            // its tracker clearing happens via the recv arm or
                            // already cleared the deadline above).
                            Err(_) => break,
                        }
                    }
                    if tracker
                        .oldest_outstanding_age_ms(now_ms(epoch))
                        .is_some_and(|age| age >= FRAMED_KEEPALIVE_DEAD_AFTER_MS)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "framed relay: peer dead -- oldest keepalive unacked for \
                                 {FRAMED_KEEPALIVE_DEAD_AFTER_MS}ms"
                            ),
                        ));
                    }
                    // A queued cumulative ACK (or PeerFin) settled the oldest
                    // counter in time -- no verdict, keep relaying.
                }
            }
        }
    };

    tokio::pin!(rev_leg, fwd_leg);
    tokio::select! {
        // The reader leg ends first on the agent's clean EOF (implicit FIN) or
        // a decode error. On the clean end the writer leg keeps running -- the
        // browser may still be sending on the half-open connection -- so hand
        // control to it; an error tears the relay down immediately.
        r = &mut rev_leg => {
            r?;
            fwd_leg.await?;
        }
        // The writer leg ends on the both-FINs termination rule (having sent
        // close_notify), a write error, or the dead-peer verdict.
        f = &mut fwd_leg => f?,
    }
    Ok((fwd_bytes.load(Ordering::Relaxed), rev_bytes.load(Ordering::Relaxed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #338: a writer double that mimics a writer with **real internal
    /// buffering** (like tokio-rustls's TLS record layer under socket
    /// backpressure) -- unlike `tokio::io::DuplexStream`, whose `poll_flush`
    /// is a no-op because it never buffers, so it can't exercise the EOF
    /// property the fix depends on. Bytes handed to `poll_write` sit in
    /// `pending` and only become visible in `sink` once `poll_flush` or
    /// `poll_shutdown` runs (mirroring `TlsStream::poll_shutdown`, which
    /// drains `session.wants_write()` before closing) -- so a test can prove
    /// bytes survive a skipped per-chunk flush as long as shutdown still
    /// drains them. Also counts `poll_flush` calls, matching this crate's
    /// `Metered<S>` convention (`ct_common::metrics`) of a transparent
    /// counting `AsyncWrite`/`AsyncRead` wrapper.
    struct BufferingCounter {
        pending: Vec<u8>,
        sink: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        flushes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        flushed: std::sync::Arc<tokio::sync::Notify>,
    }

    impl AsyncWrite for BufferingCounter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.pending.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.flushes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let drained: Vec<u8> = self.pending.drain(..).collect();
            self.sink.lock().unwrap().extend(drained);
            self.flushed.notify_one();
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            // Real writers (tokio-rustls's TlsStream) drain any pending
            // buffered output during shutdown before closing -- mirror that
            // here so the EOF-safety test below reflects real behavior.
            self.as_mut().poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn pump_dir_flushes_fewer_times_than_chunks_read_for_bulk_data() {
        // #338: a bulk transfer (bunch of full-16KB-buffer chunks) must NOT
        // flush on every chunk -- that was the whole per-chunk-flush-forever
        // overhead the issue flagged. Feed three full-buffer chunks then EOF
        // and prove the writer's flush count is far below the read count.
        use tokio::io::{duplex, AsyncWriteExt};

        let chunk = vec![0xABu8; 16 * 1024];
        let (mut src_w, src_r) = duplex(4 * 16 * 1024);
        for _ in 0..3 {
            src_w.write_all(&chunk).await.unwrap();
        }
        src_w.shutdown().await.unwrap(); // EOF after three full chunks

        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w = BufferingCounter {
            pending: Vec::new(),
            sink: sink.clone(),
            flushes: flushes.clone(),
            flushed: std::sync::Arc::new(tokio::sync::Notify::new()),
        };

        let total = pump_dir(src_r, w, "a->b", "bulk-test").await.unwrap();

        assert_eq!(total, 3 * 16 * 1024, "all bytes were read from the source");
        assert_eq!(
            flushes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only one flush -- from the unconditional shutdown-drain -- across three full-buffer chunks, not one per chunk"
        );
        assert_eq!(
            sink.lock().unwrap().len(),
            3 * 16 * 1024,
            "every byte still reached the writer's sink despite the skipped per-chunk flushes"
        );
    }

    #[tokio::test]
    async fn pump_dir_flushes_immediately_on_a_short_chunk_no_added_latency() {
        // #338: the case the original per-chunk flush existed for -- a small
        // reply (e.g. a Noise handshake response) -- must still reach the
        // wire immediately, not wait behind more source data that may never
        // come soon. Write a short (< 16KB) chunk and DON'T close the source,
        // then prove the writer flushes before the source ever reaches EOF.
        use tokio::io::AsyncWriteExt;

        let (mut src_w, src_r) = tokio::io::duplex(1024);
        let flushed = std::sync::Arc::new(tokio::sync::Notify::new());
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w = BufferingCounter {
            pending: Vec::new(),
            sink: sink.clone(),
            flushes: flushes.clone(),
            flushed: flushed.clone(),
        };

        let pump_task = tokio::spawn(pump_dir(src_r, w, "a->b", "short-chunk-test"));

        src_w.write_all(b"handshake-reply").await.unwrap();
        // Source deliberately stays open -- pump_dir's next read() blocks.
        // If the flush only happened at EOF/shutdown, this would hang.
        tokio::time::timeout(std::time::Duration::from_secs(2), flushed.notified())
            .await
            .expect("the short chunk was flushed promptly, without waiting for EOF");
        assert_eq!(
            &sink.lock().unwrap()[..],
            b"handshake-reply",
            "the short chunk reached the writer's sink immediately"
        );

        // Clean up: close the source so the still-running pump task finishes.
        src_w.shutdown().await.unwrap();
        let total = tokio::time::timeout(std::time::Duration::from_secs(2), pump_task)
            .await
            .expect("pump_dir finished after EOF")
            .unwrap()
            .unwrap();
        assert_eq!(total, "handshake-reply".len() as u64);
    }

    /// trace: REQ-0006, AUF-20261005-018
    ///
    /// INC-20261005-203, slice 1 (control arm): over a REAL-buffering writer
    /// (a `tokio::io::DuplexStream` can't exercise this -- its `poll_flush`
    /// is a no-op, so a byte is "visible" the instant it's written whether
    /// or not anyone ever flushes), a source that delivers exact full-16KiB
    /// reads and then pauses WITHOUT closing must still have every byte
    /// reach the sink promptly. Against main (a0267e8) this is RED: the old
    /// rule only flushed on a short read, and every read here is exactly
    /// `buf.len()`, so the writer never flushes and the sink stays silent
    /// until the 2s timeout below fires.
    #[tokio::test]
    async fn pump_dir_flushes_when_the_source_pauses_after_full_buffer_reads_without_closing() {
        use tokio::io::{duplex, AsyncWriteExt};

        let chunk = vec![0xCDu8; 16 * 1024];
        let (mut src_w, src_r) = duplex(4 * 16 * 1024);
        for _ in 0..2 {
            src_w.write_all(&chunk).await.unwrap();
        }
        // Deliberately NOT closed: the source pauses, mimicking a bulk
        // transfer mid-flight with nothing more to send right now.

        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flushed = std::sync::Arc::new(tokio::sync::Notify::new());
        let w = BufferingCounter {
            pending: Vec::new(),
            sink: sink.clone(),
            flushes: flushes.clone(),
            flushed: flushed.clone(),
        };

        let pump_task = tokio::spawn(pump_dir(src_r, w, "a->b", "pause-test"));

        tokio::time::timeout(std::time::Duration::from_secs(2), flushed.notified())
            .await
            .expect(
                "the two full-buffer chunks must be flushed promptly even though \
                 the source paused without closing",
            );
        assert_eq!(
            sink.lock().unwrap().len(),
            2 * 16 * 1024,
            "every byte reached the sink despite the source pausing after full reads"
        );

        src_w.shutdown().await.unwrap();
        let total = tokio::time::timeout(std::time::Duration::from_secs(2), pump_task)
            .await
            .expect("pump_dir finished after EOF")
            .unwrap()
            .unwrap();
        assert_eq!(total, 2 * 16 * 1024);
    }

    /// trace: REQ-0006, AUF-20261005-018
    #[test]
    fn relay_leg_end_line_names_the_label_side_and_reason() {
        let line = relay_leg_end_line("chan-1", "a->b", "EOF");
        assert!(line.contains("chan-1"), "names the relay: {line}");
        assert!(line.contains("a->b"), "names the side: {line}");
        assert!(line.contains("EOF"), "names the reason: {line}");
    }

    #[test]
    fn cause_chain_surfaces_the_underlying_reason_not_just_connection_lost() {
        // #214: quinn's WriteError/ReadError::ConnectionLost displays as the
        // bare string "connection lost", which is exactly the message that
        // made this bug undiagnosable -- it says a connection died but hides
        // WHICH ConnectionError killed it. The chain must carry that through.
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "timed out")
            }
        }
        impl std::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "connection lost")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let rendered = with_cause_chain(&Outer(Inner));
        assert!(rendered.contains("connection lost"), "keeps the top-level message: {rendered}");
        assert!(rendered.contains("timed out"), "and reveals the real cause: {rendered}");
    }

    #[test]
    fn relay_io_error_names_the_direction_and_preserves_the_kind() {
        // A stalled direction is half the diagnosis -- which way was dead
        // narrows a mid-flight relay death considerably. The ErrorKind must
        // survive so existing callers can still match on it.
        let src = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "connection lost");
        let e = relay_io_error(src, "a->b", "chan-42");
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "kind is preserved for callers");
        let text = e.to_string();
        assert!(text.contains("a->b"), "names the direction: {text}");
        assert!(text.contains("chan-42"), "names the channel: {text}");
    }

    #[tokio::test]
    async fn relay_streams_splices_two_generic_duplexes_both_directions() {
        // #106 relay-splice-generic: two members admitted over non-quinn streams (the
        // `:443`/TLS-TCP fallback) must be relay-paired end-to-end. Drive two in-memory
        // duplexes through `relay_streams` and prove bytes cross both ways with a
        // per-direction flush (the reverse leg isn't starved by an idle forward leg).
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        let (mut member_a, broker_a) = duplex(1024);
        let (mut member_b, broker_b) = duplex(1024);
        let relay_task =
            tokio::spawn(async move { relay_streams(broker_a, broker_b, "test-443").await });

        // A -> B while A keeps its stream open (mimics a Noise msg1 awaiting msg2).
        member_a.write_all(b"a->b").await.unwrap();
        let mut on_b = [0u8; 4];
        member_b.read_exact(&mut on_b).await.unwrap();
        assert_eq!(&on_b, b"a->b", "A's bytes reach B via the generic splice");

        // B -> A with the forward leg still open — the reply must not be starved.
        member_b.write_all(b"b->a").await.unwrap();
        let mut on_a = [0u8; 4];
        member_a.read_exact(&mut on_a).await.unwrap();
        assert_eq!(&on_a, b"b->a", "B's reply reaches A with the forward leg still open");

        // Both close -> the splice tears down and reports byte counts (no hang).
        member_a.shutdown().await.unwrap();
        member_b.shutdown().await.unwrap();
        let (a2b, b2a) = relay_task.await.unwrap().unwrap();
        assert_eq!((a2b, b2a), (4, 4), "one message each direction");
    }

    /// trace: REQ-0006, AUF-20261005-018
    ///
    /// INC-20261005-203, slice 1 (control arm), two-direction variant: both
    /// legs of `relay_pair` send a multiple of 16KiB and then pause WITHOUT
    /// closing -- the old short-read rule never fires in EITHER direction
    /// (every read is exactly `buf.len()`), so a regression here stalls
    /// both sides at once. Against main (a0267e8) this is RED on both
    /// `flushed_*.notified()` waits below.
    #[tokio::test]
    async fn relay_pair_flushes_both_directions_when_each_side_pauses_after_full_buffer_reads() {
        use tokio::io::{duplex, AsyncWriteExt};

        let chunk = vec![0x11u8; 16 * 1024];

        let (mut a_poke, a_recv) = duplex(4 * 16 * 1024);
        let (mut b_poke, b_recv) = duplex(4 * 16 * 1024);

        let sink_a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let flushes_a = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flushed_a = std::sync::Arc::new(tokio::sync::Notify::new());
        let a_send = BufferingCounter {
            pending: Vec::new(),
            sink: sink_a.clone(),
            flushes: flushes_a.clone(),
            flushed: flushed_a.clone(),
        };

        let sink_b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let flushes_b = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flushed_b = std::sync::Arc::new(tokio::sync::Notify::new());
        let b_send = BufferingCounter {
            pending: Vec::new(),
            sink: sink_b.clone(),
            flushes: flushes_b.clone(),
            flushed: flushed_b.clone(),
        };

        let relay_task =
            tokio::spawn(async move { relay_pair(a_recv, a_send, b_recv, b_send, "test-bidir").await });

        for _ in 0..2 {
            a_poke.write_all(&chunk).await.unwrap();
            b_poke.write_all(&chunk).await.unwrap();
        }
        // Both sides pause WITHOUT closing.

        tokio::time::timeout(std::time::Duration::from_secs(2), flushed_b.notified())
            .await
            .expect("a->b: A's bulk data must be flushed to B promptly despite A pausing");
        tokio::time::timeout(std::time::Duration::from_secs(2), flushed_a.notified())
            .await
            .expect("b->a: B's bulk data must be flushed to A promptly despite B pausing");

        assert_eq!(sink_b.lock().unwrap().len(), 2 * 16 * 1024, "B received all of A's bytes");
        assert_eq!(sink_a.lock().unwrap().len(), 2 * 16 * 1024, "A received all of B's bytes");

        drop(a_poke);
        drop(b_poke);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task).await;
    }

    /// A `ServerCertVerifier` that accepts anything -- these tests only need a real TLS
    /// handshake to actually complete against a self-signed cert, not certificate trust
    /// (same pattern as `relay_gate.rs`'s own `NoVerify`, duplicated here since it's
    /// private to that module's tests).
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// Build a self-signed-cert `TlsAcceptor`/`TlsConnector` pair for `name`, and complete
    /// one handshake over `transport_cap` bytes of in-memory duplex. Mirrors the
    /// acceptor/connector setup `relay_gate.rs:581-590`/`667-707` uses for its own real-TLS
    /// tests.
    async fn real_tls_pair_over_duplex(
        name: &str,
        transport_cap: usize,
    ) -> (
        tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
        tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
    ) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        crate::transport::install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let cert = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));
        let ccfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(ccfg));
        let server_name = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();

        let (server_transport, client_transport) = tokio::io::duplex(transport_cap);
        let (server_res, client_res) = tokio::join!(
            acceptor.accept(server_transport),
            connector.connect(server_name, client_transport)
        );
        (
            server_res.expect("edge-side TLS handshake completes"),
            client_res.expect("peer-side TLS handshake completes"),
        )
    }

    /// trace: REQ-0006, AUF-20261005-018
    ///
    /// INC-20261005-203, slice 1, test (d1): the SINK is a REAL `tokio_rustls` leg (the
    /// exact type/pattern this relay hands to `pump_dir` in production -- see
    /// `relay_gate.rs:581-590`) over a deliberately tiny transport, so it backpressures;
    /// the SOURCE delivers two full-16KiB reads and then pauses WITHOUT closing. Once the
    /// sink resumes reading, every byte must arrive -- including whatever is still
    /// sitting in rustls's own internal send buffer from before the backpressure cleared.
    #[tokio::test]
    async fn pump_dir_delivers_all_bytes_over_a_real_tls_leg_after_the_sink_backpressures_then_drains(
    ) {
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        const SMALL_CAP: usize = 4096;
        let (edge_tls, mut peer_tls) = real_tls_pair_over_duplex("relay-d1.test", SMALL_CAP).await;

        let (mut src_poke, src_r) = duplex(4 * 16 * 1024);
        let chunk = vec![0x55u8; 16 * 1024];
        src_poke.write_all(&chunk).await.unwrap();
        src_poke.write_all(&chunk).await.unwrap();
        // Source pauses WITHOUT closing.

        let pump_task = tokio::spawn(pump_dir(src_r, edge_tls, "a->b", "d1"));

        // The sink deliberately does not read at first -- it backpressures while
        // pump_dir writes into the tiny transport.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut got = vec![0u8; 2 * 16 * 1024];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_tls.read_exact(&mut got),
        )
        .await
        .expect(
            "every byte must arrive once the sink resumes reading, including whatever was \
                 still queued in rustls's own buffer",
        )
        .unwrap();
        assert_eq!(
            got,
            [chunk.clone(), chunk].concat(),
            "both chunks arrived intact"
        );

        src_poke.shutdown().await.unwrap();
        let total = tokio::time::timeout(std::time::Duration::from_secs(2), pump_task)
            .await
            .expect("pump_dir finished after EOF")
            .unwrap()
            .unwrap();
        assert_eq!(total, 2 * 16 * 1024);
    }

    /// trace: REQ-0006, AUF-20261005-018
    ///
    /// INC-20261005-203, slice 1, test (d2) -- labor-com 16:22Z: one side's own peer never
    /// reads what's relayed to it (a permanently backpressured direction), while the
    /// OTHER side keeps sending; the opposite direction must keep delivering regardless.
    /// Per the Rahmenbedingungen's conservative voice: if this is already green against
    /// main, that is itself the finding for this spot, not a defect to correct here.
    #[tokio::test]
    async fn relay_streams_keeps_the_other_direction_moving_when_one_peer_never_reads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (edge_a_tls, mut peer_a_tls) =
            real_tls_pair_over_duplex("relay-d2-a.test", 64 * 1024).await;
        let (edge_b_tls, mut peer_b_tls) = real_tls_pair_over_duplex("relay-d2-b.test", 4096).await;

        let relay_task =
            tokio::spawn(async move { relay_streams(edge_a_tls, edge_b_tls, "d2-test").await });

        // B sends its own data (exercises b->a) but will NEVER read what's relayed to it
        // (a->b stays backpressured forever once A's burst below exceeds B's tiny transport).
        peer_b_tls.write_all(b"b-is-still-sending").await.unwrap();

        // A sends more than B's transport can ever hold, with B never draining it.
        let stuck_chunk = vec![0x77u8; 3 * 16 * 1024];
        let _ = peer_a_tls.write_all(&stuck_chunk).await; // may itself not fully complete; that's fine

        let mut got = [0u8; "b-is-still-sending".len()];
        tokio::time::timeout(std::time::Duration::from_secs(2), peer_a_tls.read_exact(&mut got))
            .await
            .expect("b->a must keep delivering even though a->b is permanently stuck")
            .unwrap();
        assert_eq!(&got, b"b-is-still-sending");

        relay_task.abort();
    }

    #[tokio::test]
    async fn relay_two_connections_splices_two_channel_members_and_tears_down_cleanly() {
        // #72 AF4-session-resilience: two agents that can't go direct both connect to
        // the edge, which splices their streams so the tunnel still flows through it
        // (ciphertext only). Prove bytes cross both ways, and that when one side drops
        // the relay tears down and returns — no hang — the behaviour a fallback needs.
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            let ca = server.accept().await.expect("inc a").await.expect("conn a");
            let cb = server.accept().await.expect("inc b").await.expect("conn b");
            relay_two_connections(&ca, &cb, "test").await
        });

        let ea = build_client_endpoint(cert.clone()).expect("ea");
        let conn_a = ea.connect(addr, "localhost").expect("cfg").await.expect("conn a");
        let eb = build_client_endpoint(cert).expect("eb");
        let conn_b = eb.connect(addr, "localhost").expect("cfg").await.expect("conn b");

        let (mut sa, mut ra) = conn_a.open_bi().await.expect("a bi");
        let (mut sb, mut rb) = conn_b.open_bi().await.expect("b bi");
        // Actualise both streams (open_bi is lazy) so the edge's two accept_bi resolve.
        sa.write_all(b"a->b through the edge").await.expect("a write");
        sb.write_all(b"b->a reply").await.expect("b write");

        let mut on_b = vec![0u8; 21];
        rb.read_exact(&mut on_b).await.expect("b reads a");
        assert_eq!(&on_b, b"a->b through the edge", "A's bytes reach B through the edge");
        let mut on_a = vec![0u8; 10];
        ra.read_exact(&mut on_a).await.expect("a reads b");
        assert_eq!(&on_a, b"b->a reply", "B's bytes reach A through the edge");

        // One side drops -> the relay must return, not hang.
        conn_a.close(0u32.into(), b"gone");
        let done = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task).await;
        assert!(done.is_ok(), "relay tore down when a member dropped (no hang)");
    }

    #[tokio::test]
    async fn relay_two_connections_times_out_when_a_paired_member_never_opens_its_stream_257() {
        // #257: a member that connects and pairs but never actualizes its data stream
        // (no accept_bi/open_bi call at all -- a stall, not a drop) must not pin the
        // relay task and the peer connection forever. Prove the setup timeout fires and
        // the function returns, using a short injected timeout so the test itself stays
        // fast.
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let relay_task = tokio::spawn(async move {
            let ca = server.accept().await.expect("inc a").await.expect("conn a");
            let cb = server.accept().await.expect("inc b").await.expect("conn b");
            relay_two_connections_with_timeout(&ca, &cb, "test", std::time::Duration::from_millis(200)).await
        });

        let ea = build_client_endpoint(cert.clone()).expect("ea");
        let conn_a = ea.connect(addr, "localhost").expect("cfg").await.expect("conn a");
        let eb = build_client_endpoint(cert).expect("eb");
        let _conn_b = eb.connect(addr, "localhost").expect("cfg").await.expect("conn b");
        // conn_b intentionally never calls open_bi/accept_bi -- it just sits connected,
        // exactly the stall this issue describes (paired, alive, no data stream ever
        // actualized).
        let _keep_a_alive = conn_a; // avoid an early drop reading as "connection lost" instead of a timeout

        let done = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task)
            .await
            .expect("the relay task itself must finish promptly")
            .expect("task join");
        let err = done.expect_err("a stalled peer must produce an error, not a byte count");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "the error is a timeout, not some other failure: {err}");
        assert!(err.to_string().contains("relay setup timed out"), "message names the real cause: {err}");
    }

    #[tokio::test]
    async fn relays_bytes_both_directions() {
        use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

        // client <-> edge_client   and   edge_agent <-> agent
        let (mut client, mut edge_client) = duplex(1024);
        let (mut edge_agent, mut agent) = duplex(1024);

        let relay_task =
            tokio::spawn(async move { relay(&mut edge_client, &mut edge_agent).await });

        client.write_all(b"c2a").await.unwrap();
        client.shutdown().await.unwrap();
        agent.write_all(b"a2c").await.unwrap();
        agent.shutdown().await.unwrap();

        let mut got_agent = Vec::new();
        agent.read_to_end(&mut got_agent).await.unwrap();
        let mut got_client = Vec::new();
        client.read_to_end(&mut got_client).await.unwrap();

        assert_eq!(got_agent, b"c2a", "client bytes reach the agent");
        assert_eq!(got_client, b"a2c", "agent bytes reach the client");

        let (a2b, b2a) = relay_task.await.unwrap().unwrap();
        assert_eq!((a2b, b2a), (3, 3), "byte counts in each direction");
    }

    #[tokio::test]
    async fn relay_delivers_the_reply_while_the_request_side_stays_open() {
        // issue #2 (mode b): the forward leg (client→agent) works and the agent
        // writes its reply, but the reply must reach the client even though the
        // client hasn't closed its send (a Noise handshake: send msg1, keep the
        // stream open, await msg2). The reverse direction must not be starved by
        // the idle forward direction. Drives the generic relay_pair core.
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

        let (mut client, edge_client) = duplex(1024);
        let (edge_agent, mut agent) = duplex(1024);
        let (ec_r, ec_w) = split(edge_client);
        let (ea_r, ea_w) = split(edge_agent);

        let relay_task =
            tokio::spawn(async move { relay_pair(ec_r, ec_w, ea_r, ea_w, "test").await });

        // Client sends msg1 and keeps its stream OPEN (no shutdown).
        client.write_all(b"msg1").await.unwrap();
        let mut got = [0u8; 4];
        agent.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"msg1", "forward leg delivers the request");

        // Agent replies while the forward (request) direction is still open.
        agent.write_all(b"msg2").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"msg2", "reply relayed back with the request side still open");

        // Close both ends so the relay finishes and reports byte counts.
        client.shutdown().await.unwrap();
        agent.shutdown().await.unwrap();
        let (fwd, rev) = relay_task.await.unwrap().unwrap();
        assert_eq!((fwd, rev), (4, 4), "one message each direction");
    }

    #[tokio::test]
    async fn edge_relays_client_bytes_to_agent_over_quic() {
        use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // Edge: accept the Agent conn (open the tunnel stream), accept the
        // Client conn (accept its stream), and relay between them. The
        // client->agent direction completes once the client finishes its send;
        // we don't require the reverse direction to close (avoids a teardown
        // race), so the relay future is simply dropped when the test ends.
        let edge_task = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            let (agent_send, agent_recv) = agent_conn.open_bi().await.unwrap();
            let client_conn = server.accept().await.unwrap().await.unwrap();
            let (client_send, client_recv) = client_conn.accept_bi().await.unwrap();
            let _ = relay_quic(client_send, client_recv, agent_send, agent_recv, "test").await;
        });

        // Agent connects first, then reads the relayed stream to end.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let agent_task = tokio::spawn(async move {
            let (_a_send, mut a_recv) = agent_conn.accept_bi().await.unwrap();
            a_recv.read_to_end(1024).await.unwrap()
        });

        // Client connects, sends bytes, finishes its send.
        let client_ep = build_client_endpoint(cert).expect("client ep");
        let client_conn = client_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("client conn");
        let (mut c_send, _c_recv) = client_conn.open_bi().await.unwrap();
        c_send.write_all(b"hello-agent").await.unwrap();
        c_send.finish().unwrap();

        let agent_got = agent_task.await.unwrap();
        assert_eq!(
            agent_got, b"hello-agent",
            "client bytes reach the agent via the relay"
        );

        drop(client_conn); // hold the client connection until the assertion
        edge_task.abort();
    }

    #[tokio::test]
    async fn noise_e2e_through_relay_edge_sees_only_ciphertext() {
        use ct_common::noise::{client_handshake, generate_static_keypair, origin_handshake};
        use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

        async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) {
            w.write_all(&(msg.len() as u16).to_be_bytes()).await.unwrap();
            w.write_all(msg).await.unwrap();
            w.flush().await.unwrap();
        }
        async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Vec<u8> {
            let mut len = [0u8; 2];
            r.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut buf = vec![0u8; n];
            r.read_exact(&mut buf).await.unwrap();
            buf
        }

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let origin_pub = origin_kp.public;

        // client <-> edge_c   and   edge_a <-> origin; the Edge relays between
        // edge_c and edge_a, seeing only opaque bytes.
        let (mut client, mut edge_c) = duplex(8192);
        let (mut edge_a, mut origin) = duplex(8192);

        let relay_task = tokio::spawn(async move {
            let _ = relay(&mut edge_c, &mut edge_a).await;
        });

        // Origin (responder): finish the handshake, decrypt one payload.
        let origin_task = tokio::spawn(async move {
            let mut hs = origin_handshake(&origin_kp.private).unwrap();
            let mut scratch = [0u8; 4096];
            let m1 = read_frame(&mut origin).await;
            hs.read_message(&m1, &mut scratch).unwrap();
            let mut out = [0u8; 4096];
            let n = hs.write_message(&[], &mut out).unwrap();
            write_frame(&mut origin, &out[..n]).await;
            let mut transport = hs.into_transport_mode().unwrap();
            let ct = read_frame(&mut origin).await;
            let mut pt = [0u8; 4096];
            let m = transport.read_message(&ct, &mut pt).unwrap();
            pt[..m].to_vec()
        });

        // Client (initiator): pins the Origin's public key.
        let mut hs = client_handshake(&client_kp.private, &origin_pub).unwrap();
        let mut out = [0u8; 4096];
        let n = hs.write_message(&[], &mut out).unwrap();
        write_frame(&mut client, &out[..n]).await;
        let m2 = read_frame(&mut client).await;
        let mut scratch = [0u8; 4096];
        hs.read_message(&m2, &mut scratch).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();

        let secret = b"provider-blind payload";
        let n = transport.write_message(secret, &mut out).unwrap();
        let ciphertext = out[..n].to_vec();
        assert_ne!(
            ciphertext.as_slice(),
            secret.as_slice(),
            "the relayed bytes must be ciphertext, not plaintext"
        );
        write_frame(&mut client, &ciphertext).await;

        let received = origin_task.await.unwrap();
        assert_eq!(
            received, secret,
            "origin decrypts the E2E payload the edge relayed blindly"
        );
        relay_task.abort();
    }

    /// Spawn `framed_relay` over two in-memory duplexes and hand back the far
    /// (peer) ends: the agent peer speaks the frame codec, the browser peer
    /// speaks raw bytes -- the exact #528 topology.
    #[allow(clippy::type_complexity)]
    fn spawn_framed_relay() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<std::io::Result<(u64, u64)>>,
    ) {
        let (agent_edge, agent_far) = tokio::io::duplex(1 << 16);
        let (browser_edge, browser_far) = tokio::io::duplex(1 << 16);
        let relay = tokio::spawn(async move {
            let mut agent_edge = agent_edge;
            let mut browser_edge = browser_edge;
            framed_relay(&mut agent_edge, &mut browser_edge).await
        });
        (agent_far, browser_far, relay)
    }

    /// trace: REQ-0006, AUF-20261005-018
    ///
    /// INC-20261005-203, slice 1 (control arm), `framed_relay`'s analogue of
    /// (a)/(b) at the browser->agent leg (relay.rs:549): drives the
    /// agent-bound writer through [`BufferingCounter`] (a stand-in for the
    /// production tokio-rustls TLS leg -- a plain `tokio::io::duplex` can't
    /// exercise this, its `poll_flush` is a no-op so a byte is already
    /// "visible" on write regardless of any flush). `tokio::io::join` glues
    /// that buffering writer to an otherwise-idle reader, since `framed_relay`
    /// needs one combined `AsyncRead + AsyncWrite` for its `agent` parameter.
    /// The browser delivers two full-16KiB reads then pauses WITHOUT
    /// closing; against main (a0267e8) this is RED -- the old rule never
    /// flushes a full-buffer read, so the agent-bound sink stays short of
    /// both DATA frames until the 2s timeout below fires (well short of the
    /// 8s keepalive interval, so this isn't "it would have arrived anyway").
    #[tokio::test]
    async fn framed_relay_flushes_browser_to_agent_when_the_browser_pauses_after_full_buffer_reads()
    {
        use tokio::io::AsyncWriteExt;

        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flushed = std::sync::Arc::new(tokio::sync::Notify::new());
        let agent_writer = BufferingCounter {
            pending: Vec::new(),
            sink: sink.clone(),
            flushes: flushes.clone(),
            flushed: flushed.clone(),
        };
        // Held open and never written to: the agent->browser direction is
        // not exercised by this test, only the writer under test.
        let (agent_read_far, agent_read_near) = tokio::io::duplex(1024);
        let mut agent = tokio::io::join(agent_read_near, agent_writer);

        let (mut browser_edge, mut browser_far) = tokio::io::duplex(1 << 16);

        let relay_task = tokio::spawn(async move { framed_relay(&mut agent, &mut browser_edge).await });

        let chunk = vec![0x33u8; 16 * 1024];
        for _ in 0..2 {
            browser_far.write_all(&chunk).await.unwrap();
        }
        // Pauses WITHOUT closing.

        tokio::time::timeout(std::time::Duration::from_secs(2), flushed.notified())
            .await
            .expect("the agent-bound writer must be flushed promptly once the browser pauses");

        // Two DATA frames: 1-byte tag + 4-byte BE length header, then the payload, each.
        let expected_len = 2 * (5 + 16 * 1024);
        assert_eq!(
            sink.lock().unwrap().len(),
            expected_len,
            "both full DATA frames reached the agent-bound sink"
        );

        drop(agent_read_far);
        relay_task.abort();
    }

    #[tokio::test]
    async fn framed_relay_frames_browser_bytes_unframes_agent_frames_and_terminates_on_both_fins() {
        // #528 (i): the edge<->agent hop is FRAMED while the browser side stays
        // raw -- and the relay terminates promptly (contract duty) once FIN has
        // passed in both directions.
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (agent_far, mut browser_far, relay) = spawn_framed_relay();
        let (far_r, far_w) = tokio::io::split(agent_far);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        // Browser -> Agent: raw bytes (deliberately containing every frame
        // discriminator) arrive at the agent as ONE DATA frame -- payload bytes
        // are never re-interpreted as framing.
        const FROM_BROWSER: &[u8] = &[0xF8, 0xFC, 0xFD, 0xFE, 0x00, 0xFF, b'h', b'i'];
        browser_far.write_all(FROM_BROWSER).await.unwrap();
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::Data(FROM_BROWSER.to_vec())),
            "browser bytes reach the agent wrapped in a DATA frame",
        );

        // Agent -> Browser: a DATA frame arrives at the browser as its raw payload.
        far_writer.data(b"reply from the agent").await.unwrap();
        far_writer.flush().await.unwrap();
        let mut got = vec![0u8; b"reply from the agent".len()];
        browser_far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"reply from the agent", "agent DATA payload reaches the browser unframed");

        // Browser EOF -> the edge sends the in-band FIN (not a TCP shutdown).
        browser_far.shutdown().await.unwrap();
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::Fin),
            "browser EOF becomes the codec's in-band half-close toward the agent",
        );

        // Agent FIN -> the browser sees EOF; both FINs passed -> the relay
        // returns promptly with application-byte counts (frame overhead excluded).
        far_writer.fin().await.unwrap();
        let mut rest = Vec::new();
        browser_far.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "the agent's FIN surfaces as a clean browser EOF");
        let (fwd, rev) = relay.await.unwrap().unwrap();
        assert_eq!(fwd, FROM_BROWSER.len() as u64, "browser->agent application bytes");
        assert_eq!(rev, b"reply from the agent".len() as u64, "agent->browser application bytes");
    }

    #[tokio::test]
    async fn framed_relay_discards_keepalives_acks_them_bounded_and_never_corrupts_the_browser() {
        // #528 (ii): keepalives are discarded (never a byte of them reaches the
        // raw browser stream) and ACKed exactly per the reader's bounded
        // verdict -- a repeated counter earns NO second ack.
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter};
        use tokio::io::AsyncReadExt;

        let (agent_far, mut browser_far, relay) = spawn_framed_relay();
        let (far_r, far_w) = tokio::io::split(agent_far);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        // A keepalive around real DATA: the browser must see ONLY the payload.
        far_writer.keepalive(5).await.unwrap();
        far_writer.data(b"chunk").await.unwrap();
        far_writer.flush().await.unwrap();
        let mut got = [0u8; 5];
        browser_far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"chunk", "only the DATA payload reaches the browser");

        // The edge ACKed counter 5 through its one writer-owner.
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::KeepaliveAck { counter: 5 }),
            "a first-seen keepalive counter is ACKed",
        );

        // A REPEATED counter earns nothing (flood bound). Deterministic absence
        // proof: keepalive events flow FIFO through the relay's one
        // writer-owner, so if the repeated 5 wrongly earned an ack, that ack
        // would arrive BEFORE counter 6's -- the next ACK must be exactly {6}.
        far_writer.keepalive(5).await.unwrap();
        far_writer.keepalive(6).await.unwrap();
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::KeepaliveAck { counter: 6 }),
            "the repeated counter 5 earned no second ACK; the next ACK is 6's",
        );

        // And nothing of any keepalive leaked into the raw browser stream: the
        // next browser byte the agent sends is the very next thing it reads.
        far_writer.data(b"y").await.unwrap();
        far_writer.flush().await.unwrap();
        let mut y = [0u8; 1];
        browser_far.read_exact(&mut y).await.unwrap();
        assert_eq!(&y, b"y");

        relay.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn framed_relay_injects_counted_keepalives_on_send_silence() {
        // #528: the whole point -- when the edge's send side toward the agent
        // falls silent past the codec cadence, it injects counted keepalives so
        // the middlebox never sees a quiet connection. Paused time auto-advances,
        // so no real 8s wait is incurred.
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter};

        let (agent_far, _browser_far, relay) = spawn_framed_relay();
        let (far_r, far_w) = tokio::io::split(agent_far);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        // First injected keepalive after one cadence of silence; ack it so the
        // tracker never approaches the dead verdict.
        match far_reader.next().await.unwrap() {
            Some(Frame::Keepalive { counter, .. }) => assert_eq!(counter, 0, "counters start at 0"),
            other => panic!("expected the injected keepalive, got {other:?}"),
        }
        far_writer.keepalive_ack(0).await.unwrap();

        // The next cadence yields the next counter.
        match far_reader.next().await.unwrap() {
            Some(Frame::Keepalive { counter, .. }) => assert_eq!(counter, 1, "the counter advances"),
            other => panic!("expected the second injected keepalive, got {other:?}"),
        }

        relay.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn framed_relay_declares_a_never_acking_peer_dead_after_the_bound() {
        // #528 liveness: a peer that swallows keepalives without ever ACKing is
        // indistinguishable from a middlebox-killed connection -- after the
        // codec's dead bound (oldest outstanding > 24s) the relay must fail
        // TimedOut instead of pumping keepalives into a corpse forever.
        let (agent_far, _browser_far, relay) = spawn_framed_relay();
        // The far agent end stays open but silent: keepalives pile up unacked
        // in the duplex buffer.
        let _hold_far_open = agent_far;

        let err = relay
            .await
            .unwrap()
            .expect_err("a never-acking peer must produce the dead verdict, not an infinite ping loop");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "the verdict is a timeout: {err}");
        assert!(
            err.to_string().contains("keepalive unacked"),
            "the error names the real cause: {err}"
        );
    }

    #[tokio::test]
    async fn framed_relay_treats_agent_clean_eof_as_implicit_fin_and_still_pumps_browser_data() {
        // Contract: a clean EOF without an explicit FIN frame (e.g. the agent
        // ending via TLS close_notify) is an IMPLICIT FIN -- same downstream
        // behavior: browser write side closes, and the browser->agent direction
        // keeps running toward its own natural end.
        use ct_common::fallback_framing::{Frame, FrameReader};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut agent_far, mut browser_far, relay) = spawn_framed_relay();

        // The agent half-closes WITHOUT any FIN frame (a TLS close_notify
        // ending): a clean EOF at a frame boundary = the implicit FIN. Its
        // read direction stays open.
        agent_far.shutdown().await.unwrap();
        let mut far_reader = FrameReader::new(agent_far);
        let mut eof = Vec::new();
        browser_far.read_to_end(&mut eof).await.unwrap();
        assert!(eof.is_empty(), "the agent's clean EOF closes the browser's read side");

        // The browser can still send on the half-open connection...
        browser_far.write_all(b"late upload").await.unwrap();
        assert_eq!(
            far_reader.next().await.unwrap(),
            Some(Frame::Data(b"late upload".to_vec())),
            "browser->agent keeps flowing after the agent's implicit FIN",
        );

        // ...and the browser's own EOF ends the relay (FIN both ways).
        browser_far.shutdown().await.unwrap();
        assert_eq!(far_reader.next().await.unwrap(), Some(Frame::Fin), "own FIN still goes out");
        let (fwd, _rev) = relay.await.unwrap().unwrap();
        assert_eq!(fwd, b"late upload".len() as u64);
    }

    #[tokio::test(start_paused = true)]
    async fn framed_relay_ends_the_data_idle_post_peer_fin_phase_at_the_n2_bound() {
        // #528 review N2: after the peer's FIN, a data-idle surviving direction
        // must not be held open forever by the relay's own untracked keepalives
        // (they reset the TCP idle timer and keep earning transport ACKs, so no
        // kernel backstop ever fires). After POST_PEER_FIN_IDLE_BOUND without a
        // DATA write the relay FINs its own direction and terminates cleanly.
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter, POST_PEER_FIN_IDLE_BOUND};
        use tokio::io::AsyncReadExt;

        let (agent_far, mut browser_far, relay) = spawn_framed_relay();
        let (far_r, far_w) = tokio::io::split(agent_far);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        let start = tokio::time::Instant::now();
        // The agent FINs immediately; the browser stays open but sends NOTHING
        // -- the exact hazard-class shape.
        far_writer.fin().await.unwrap();
        let mut eof = Vec::new();
        browser_far.read_to_end(&mut eof).await.unwrap();
        assert!(eof.is_empty(), "the peer's FIN surfaces as a clean browser EOF");

        // The relay keeps refreshing the middlebox for the whole idle window
        // (untracked keepalives), then ends it: own FIN, then close_notify.
        let mut keepalives = 0u32;
        loop {
            match far_reader.next().await.unwrap() {
                Some(Frame::Keepalive { .. }) => {
                    keepalives += 1;
                    // Without this cap a regressed (never-firing) N2 arm would keep
                    // this loop reading auto-advancing keepalives forever -- the suite
                    // would HANG instead of fail. 60 cadences (~480s) is far past the
                    // bound + one interval, so hitting it can only be the regression.
                    assert!(
                        keepalives <= 60,
                        "the relay never sent its N2 FIN -- {keepalives} keepalives past the bound is the pre-#529 forever-hold"
                    );
                }
                Some(Frame::Fin) => break,
                other => panic!("expected keepalives then the N2 FIN, got {other:?}"),
            }
        }
        assert!(
            keepalives >= 20,
            "the idle window stays middlebox-protected until the bound (got {keepalives} keepalives)"
        );
        assert_eq!(far_reader.next().await.unwrap(), None, "FIN is followed by a clean shutdown");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= POST_PEER_FIN_IDLE_BOUND,
            "the relay must not end before the bound (ended after {elapsed:?})"
        );
        assert!(
            elapsed < POST_PEER_FIN_IDLE_BOUND + KEEPALIVE_INTERVAL,
            "the relay must end promptly AT the bound (ended after {elapsed:?})"
        );
        let (fwd, rev) = relay.await.unwrap().unwrap();
        assert_eq!((fwd, rev), (0, 0), "the N2 ending is a clean return, not an error");
    }

    #[tokio::test(start_paused = true)]
    async fn framed_relay_keeps_a_progressing_upload_alive_past_the_n2_bound() {
        // #528 review N2, the reason the bound gates PROGRESS instead of wall
        // time: an origin may HTTP-legally reply early and FIN while the client
        // is still uploading. Chunks spaced inside the bound but totalling far
        // beyond it must keep the relay alive; every DATA write resets the clock.
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter, POST_PEER_FIN_IDLE_BOUND};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (agent_far, mut browser_far, relay) = spawn_framed_relay();
        let (far_r, far_w) = tokio::io::split(agent_far);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        far_writer.fin().await.unwrap();
        let mut eof = Vec::new();
        browser_far.read_to_end(&mut eof).await.unwrap();
        assert!(eof.is_empty());

        // Three chunks, each 120s (2/3 of the bound) apart: 360s total in the
        // post-peer-FIN phase, twice the bound, never 180s idle.
        for i in 0..3u32 {
            tokio::time::sleep(2 * POST_PEER_FIN_IDLE_BOUND / 3).await;
            browser_far.write_all(b"chunk").await.unwrap();
            loop {
                match far_reader.next().await.unwrap() {
                    Some(Frame::Keepalive { .. }) => {}
                    Some(Frame::Data(d)) => {
                        assert_eq!(d, b"chunk", "chunk {i} still relayed past the bound");
                        break;
                    }
                    other => panic!("upload chunk {i} must still be relayed, got {other:?}"),
                }
            }
        }

        // The upload's own natural end still terminates the relay cleanly.
        browser_far.shutdown().await.unwrap();
        loop {
            match far_reader.next().await.unwrap() {
                Some(Frame::Keepalive { .. }) => {}
                Some(Frame::Fin) => break,
                other => panic!("expected the upload's own FIN, got {other:?}"),
            }
        }
        assert_eq!(far_reader.next().await.unwrap(), None);
        let (fwd, rev) = relay.await.unwrap().unwrap();
        assert_eq!(fwd, 3 * b"chunk".len() as u64, "all upload bytes made it");
        assert_eq!(rev, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn framed_relay_n2_bound_leaves_the_own_fin_only_phase_alone() {
        // The mirror phase (own FIN sent, peer NOT FINed) is governed by the
        // keepalive dead verdict, not the N2 bound: a healthy, acking agent may
        // stay DATA-silent far longer than the bound before its late reply
        // (#388 class -- the exact case the framed keepalive exists for).
        use ct_common::fallback_framing::{Frame, FrameReader, FrameWriter};
        use tokio::io::AsyncReadExt;

        let (agent_far, mut browser_far, relay) = spawn_framed_relay();
        let (far_r, far_w) = tokio::io::split(agent_far);
        let mut far_reader = FrameReader::new(far_r);
        let mut far_writer = FrameWriter::new(far_w);

        // The browser is done uploading immediately -> own FIN toward the agent.
        browser_far.shutdown().await.unwrap();
        assert_eq!(far_reader.next().await.unwrap(), Some(Frame::Fin));

        // The agent acks the edge's tracked keepalives for 40 cadences (320s,
        // well past the 180s bound) without sending any DATA...
        let mut acked = 0u32;
        while acked < 40 {
            match far_reader.next().await.unwrap() {
                Some(Frame::Keepalive { counter, should_ack }) => {
                    assert!(should_ack, "injected counters are strictly increasing");
                    far_writer.keepalive_ack(counter).await.unwrap();
                    acked += 1;
                }
                other => panic!("expected tracked keepalives only, got {other:?}"),
            }
        }

        // ...and its late reply still goes through: the bound never fired here.
        far_writer.data(b"late reply").await.unwrap();
        far_writer.flush().await.unwrap();
        far_writer.fin().await.unwrap();
        let mut got = Vec::new();
        browser_far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"late reply", "the late reply survives 320s of own-FIN-only silence");
        let (fwd, rev) = relay.await.unwrap().unwrap();
        assert_eq!(fwd, 0);
        assert_eq!(rev, b"late reply".len() as u64);
    }
}
