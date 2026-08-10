//! Opaque byte relay (ADR-0015 fallback relay path).
//!
//! When a Client and Agent cannot form a direct P2P path, the Edge relays
//! ciphertext between them. The Edge is provider-blind: it copies bytes without
//! inspecting them. P2.4a is the generic bidirectional relay primitive; P2.4b
//! wires it onto paired QUIC streams (Client stream ↔ Agent tunnel).

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

/// Pump one direction: read from `r`, write each chunk to `w`, flushing only
/// on a **short** read, until `r` reaches EOF, then shut `w` down. The
/// per-direction byte count + trace make a stalled direction visible in real
/// time (issue #2, mode b: the agent's reply reached the edge but never made
/// it back to the client).
///
/// #338: flush only when the just-completed read was short (`n < buf.len()`),
/// not on every chunk. A full-buffer read (`n == buf.len()`) means the source
/// likely has more data immediately ready (a bulk transfer mid-flight, e.g. a
/// large upload or video stream) — skipping the flush there lets the writer's
/// own layer coalesce it with the next write instead of forcing a
/// syscall/round-trip per 16KB chunk. A short read means the source just gave
/// us everything it currently has: small/interactive traffic (the common case
/// for this tunnel's Noise-encrypted application data) or the tail of a bulk
/// transfer — flush immediately there, which is exactly what preserves the
/// original per-chunk-flush's reason to exist: a small reply (e.g. a Noise
/// handshake response) must reach the wire promptly, not wait behind more
/// source data that may never come soon.
///
/// This is safe at EOF even when the last real chunk was a full-buffer read
/// that skipped its own flush: `shutdown()` below is unconditional, and for
/// every concrete writer this crate hands to `pump_dir` in production,
/// `poll_shutdown` drains any writer-internal buffered output before the
/// underlying transport closes (verified against this workspace's pinned
/// crate versions, not assumed — see the #338 commit message for the full
/// evidence trail):
///   - `quinn::SendStream` (`relay_quic`, quinn 0.11.11): `poll_flush` is a
///     hardcoded no-op (`Poll::Ready(Ok(()))`) — flushing this writer type has
///     literally zero observable effect either way. All bytes handed to
///     `poll_write` are already inside quinn's own connection-driver state;
///     transmission is scheduled by quinn's background connection task, not
///     by the application calling flush. `shutdown()` calls `finish()`, which
///     only signals "no more data is coming" — previously written (already
///     buffered-in-quinn) data is still transmitted normally.
///   - `tokio_rustls::server::TlsStream`/`client::TlsStream` (the `:443`
///     TLS-TCP channel-relay fallback, tokio-rustls 0.26.4 / rustls 0.23.43):
///     `poll_write` itself already drains any produced TLS records to the
///     underlying socket in an inner loop (`while session.wants_write() {
///     write_io(cx) }`) before returning — rustls's `ConnectionCommon::write`
///     encrypts application data into ready-to-send records immediately, it
///     does not hold plaintext back awaiting a flush (that only happens
///     mid-handshake). The only way bytes can still be sitting unsent after a
///     `write_all` is if the socket briefly applied backpressure; even then,
///     `poll_shutdown` explicitly loops `while session.wants_write() {
///     write_io(cx) }` before closing the socket, so a skipped flush can never
///     strand data at EOF.
///   - `WsByteStream` (`ws_channel.rs`, the browser `/ws/channel` transport):
///     `poll_write` already calls `poll_flush` on the WebSocket sink inline,
///     before returning — there is never unflushed data left after a
///     `write_all` completes, whether or not the caller flushes separately.
/// A test double modeling a writer with *real* internal buffering (unlike
/// `tokio::io::DuplexStream`, whose `poll_flush` is a no-op and so can't
/// stress this) proves the EOF property directly below.
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

async fn pump_dir<R, W>(mut r: R, mut w: W, dir: &str, label: &str) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = r.read(&mut buf).await.map_err(|e| relay_io_error(e, dir, label))?;
        if n == 0 {
            let _ = w.shutdown().await;
            break;
        }
        if total == 0 {
            relay_trace(format_args!("relay {label} {dir}: first {n} bytes"));
        }
        total += n as u64;
        w.write_all(&buf[..n]).await.map_err(|e| relay_io_error(e, dir, label))?;
        if n < buf.len() {
            w.flush().await.map_err(|e| relay_io_error(e, dir, label))?;
        }
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
    // Initiator opened its data stream (actualised by Noise msg1) — accept it.
    let (send_i, recv_i) = tokio::time::timeout(setup_timeout, initiator_conn.accept_bi())
        .await
        .map_err(|_| timed_out("accept_bi(initiator)"))?
        .map_err(to_io("accept_bi(initiator)"))?;
    // Open the data stream toward the acceptor; it becomes visible to the acceptor's
    // accept_bi as soon as relay_quic writes the first relayed bytes into it.
    let (send_a, recv_a) = tokio::time::timeout(setup_timeout, acceptor_conn.open_bi())
        .await
        .map_err(|_| timed_out("open_bi(acceptor)"))?
        .map_err(to_io("open_bi(acceptor)"))?;
    // a = initiator, b = acceptor: recv_i (msg1…) → send_a, recv_a (msg2…) → send_i.
    relay_quic(send_i, recv_i, send_a, recv_a, label).await
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
}
