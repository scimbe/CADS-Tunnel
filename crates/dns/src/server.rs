//! Authoritative UDP+TCP `:53` responder for the ACME challenge store (#31 AD2).
//!
//! It parses each incoming DNS query, looks up the published TXT value(s) in the
//! [`AcmeDnsStore`], and answers. Malformed datagrams are dropped silently (a
//! resolver simply retries) — never a panic. This is the public-facing half; the
//! record-mutating HTTP API stays localhost-only (AD3).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::message;
use crate::store::AcmeDnsStore;

/// #300: cap on concurrent TCP connections to the public `:53` responder. Without
/// this, an attacker opening many connections and stalling each one (see
/// [`TCP_READ_TIMEOUT`]'s doc comment) accumulates an unbounded number of tasks.
const MAX_TCP_CONNECTIONS: usize = 256;

/// #300: idle-read deadline for each `read_exact` in [`handle_tcp`] -- without this,
/// a client that opens a connection and then stalls (sends the 2-byte length prefix
/// and nothing else, or nothing at all) holds its task and up to
/// [`MAX_TCP_MESSAGE_BYTES`] of buffer forever, wedging the responder for legitimate
/// ACME DNS-01 validation traffic once enough stalled connections accumulate.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// #300: this responder only ever answers `_acme-challenge` TXT queries (a handful
/// of small questions/answers, see `message.rs`'s own 512-byte UDP ceiling) — a
/// claimed message length anywhere near the wire format's 65535 maximum is never
/// legitimate here, so refuse it before allocating a buffer for it.
const MAX_TCP_MESSAGE_BYTES: usize = 512;

/// Build the DNS response for a raw query datagram against `store`, or `None` if
/// the query is malformed (drop it). Pure — the socket loops wrap this.
pub fn respond(store: &AcmeDnsStore, query: &[u8]) -> Option<Vec<u8>> {
    let q = message::parse_query(query)?;
    let txts = store.txt(&q.name);
    Some(message::build_response(&q, &txts))
}

/// Serve DNS over UDP on `listen` until the process ends.
pub async fn serve_udp(store: Arc<AcmeDnsStore>, listen: SocketAddr) -> std::io::Result<()> {
    let sock = tokio::net::UdpSocket::bind(listen).await?;
    udp_loop(store, sock).await
}

/// The UDP receive/answer loop over an already-bound socket (also the test seam).
pub async fn udp_loop(store: Arc<AcmeDnsStore>, sock: tokio::net::UdpSocket) -> std::io::Result<()> {
    // 512 is the classic DNS/UDP message ceiling; ACME TXT answers fit easily.
    let mut buf = vec![0u8; 512];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        if let Some(resp) = respond(&store, &buf[..n]) {
            let _ = sock.send_to(&resp, peer).await;
        }
    }
}

/// Serve DNS over TCP on `listen` until the process ends. TCP DNS messages are
/// length-prefixed with a 2-byte big-endian length.
pub async fn serve_tcp(store: Arc<AcmeDnsStore>, listen: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tcp_loop(store, listener).await
}

/// The TCP accept/answer loop over an already-bound listener (also the test seam).
pub async fn tcp_loop(store: Arc<AcmeDnsStore>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    // #300: shared, not per-connection -- the budget is global across the listener.
    let conn_cap = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, _peer) = listener.accept().await?;
        // Shed over the cap by dropping the socket (closes it) rather than queuing --
        // an attacker holding MAX_TCP_CONNECTIONS stalled connections must not also be
        // able to queue unbounded pending accepts.
        let Ok(permit) = conn_cap.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the connection's lifetime
            let _ = handle_tcp(&store, stream).await;
        });
    }
}

async fn handle_tcp(store: &AcmeDnsStore, mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
    let mut lenb = [0u8; 2];
    read_exact_timed(&mut stream, &mut lenb).await?;
    let len = u16::from_be_bytes(lenb) as usize;
    if len > MAX_TCP_MESSAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TCP DNS message length {len} exceeds the {MAX_TCP_MESSAGE_BYTES}-byte cap"),
        ));
    }
    let mut msg = vec![0u8; len];
    read_exact_timed(&mut stream, &mut msg).await?;
    if let Some(resp) = respond(store, &msg) {
        stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
    Ok(())
}

/// [`tokio::io::AsyncReadExt::read_exact`] bounded by [`TCP_READ_TIMEOUT`] (#300): a
/// stalled peer (accepted, no more bytes ever) times out instead of holding the task
/// and its buffer forever.
async fn read_exact_timed<S: AsyncReadExt + Unpin>(stream: &mut S, buf: &mut [u8]) -> std::io::Result<()> {
    tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP DNS read timed out"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{CLASS_IN, TYPE_TXT};

    /// Minimal raw TXT query for `name`.
    fn txt_query(id: u16, name: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        b.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&TYPE_TXT.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    #[test]
    fn respond_serves_a_stored_txt_and_drops_malformed() {
        let store = AcmeDnsStore::new();
        store.set_txt("_acme-challenge.host.test", "the-token");

        let resp = respond(&store, &txt_query(0x21, "_acme-challenge.host.test")).unwrap();
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x21, "echoes the id");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
        assert!(resp.windows(9).any(|w| w == b"the-token"), "carries the TXT");

        // Unknown name -> valid response, zero answers.
        let resp = respond(&store, &txt_query(1, "_acme-challenge.other.test")).unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);

        // Malformed -> dropped.
        assert!(respond(&store, b"\x00\x01").is_none());
    }

    #[tokio::test]
    async fn udp_server_round_trips_a_query() {
        let store = Arc::new(AcmeDnsStore::new());
        store.set_txt("_acme-challenge.host.test", "tok-xyz");

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(udp_loop(store, server));

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&txt_query(0x42, "_acme-challenge.host.test"), addr).await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("no timeout")
            .unwrap();
        let resp = &buf[..n];
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x42);
        assert!(resp.windows(7).any(|w| w == b"tok-xyz"), "answer over the wire");
    }

    #[tokio::test]
    async fn tcp_server_round_trips_a_query() {
        let store = Arc::new(AcmeDnsStore::new());
        store.set_txt("_acme-challenge.host.test", "tok-tcp");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(tcp_loop(store, listener));

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let q = txt_query(0x77, "_acme-challenge.host.test");
        client.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        client.write_all(&q).await.unwrap();

        let mut lenb = [0u8; 2];
        client.read_exact(&mut lenb).await.unwrap();
        let mut resp = vec![0u8; u16::from_be_bytes(lenb) as usize];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x77);
        assert!(resp.windows(7).any(|w| w == b"tok-tcp"), "answer over the wire");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_handler_times_out_on_a_peer_that_sends_the_length_prefix_then_stalls_300() {
        // #300: exactly the live-observed failure -- the connection is accepted, the
        // 2-byte length prefix arrives, then nothing else ever does. Paused clock ->
        // tokio auto-advances virtual time, so this is deterministic and fast despite
        // the real multi-second TCP_READ_TIMEOUT.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(AcmeDnsStore::new());
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let start = tokio::time::Instant::now();
            let result = handle_tcp(&store, stream).await;
            (result, start.elapsed())
        });

        let mut attacker = tokio::net::TcpStream::connect(addr).await.unwrap();
        attacker.write_all(&10u16.to_be_bytes()).await.unwrap(); // claim a 10-byte message
        // ...then never send it, and never close -- the stall this issue describes.

        let (result, elapsed) = accept_task.await.unwrap();
        assert!(result.is_err(), "a stalled peer must end the handler with an error, not hang forever");
        assert!(elapsed >= TCP_READ_TIMEOUT, "must wait out the read deadline before giving up, elapsed {elapsed:?}");
        drop(attacker);
    }

    #[tokio::test]
    async fn tcp_handler_rejects_a_message_length_over_the_cap_300() {
        let store = Arc::new(AcmeDnsStore::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_tcp(&store, stream).await
        });

        let mut attacker = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Claim a length just over the cap -- never actually send that much.
        attacker.write_all(&((MAX_TCP_MESSAGE_BYTES + 1) as u16).to_be_bytes()).await.unwrap();

        let result = accept_task.await.unwrap();
        assert!(result.is_err(), "an over-cap claimed length must be refused before allocating for it");
    }

    #[tokio::test]
    async fn tcp_loop_sheds_new_connections_once_the_cap_is_reached_300() {
        // #300: MAX_TCP_CONNECTIONS stalled connections must not starve out a
        // legitimate one. Fill the cap with connections that never send anything,
        // then prove a fresh, well-behaved connection is refused (dropped) rather
        // than queued -- the accept loop itself sheds, it doesn't just eventually
        // service everyone.
        let store = Arc::new(AcmeDnsStore::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(tcp_loop(store, listener));

        let mut _holders = Vec::new();
        for _ in 0..MAX_TCP_CONNECTIONS {
            _holders.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        // Give the accept loop a moment to actually accept+spawn each one.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // One more: accepted at the OS/listener level (the backlog), but the accept
        // loop must shed it immediately (drop, no task spawned) rather than serve it
        // once a slot frees -- observable as an immediate clean close, not a hang.
        let mut shed = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), shed.read(&mut buf))
            .await
            .expect("must resolve promptly, not hang waiting for a freed slot");
        assert_eq!(read.unwrap(), 0, "the shed connection is closed (EOF), not silently held open");
    }
}
