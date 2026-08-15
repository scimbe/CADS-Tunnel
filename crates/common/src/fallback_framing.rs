//! TLS-TCP fallback relay framing (#528): a minimal length-prefixed frame layer for the
//! Browser-Plane TLS-TCP fallback's **relay phase**, so a middlebox-surviving keepalive can
//! be interleaved with relayed application bytes *during* an in-flight request.
//!
//! ## Why this exists
//!
//! The fallback already keeps a **parked** connection alive across a hostile middlebox via a
//! real-payload PING/PONG (`transport.rs`, #500) — but that framing ends the moment a client
//! request is delivered (the `TCP_PING_STOP` byte), after which the relay is a *transparent
//! raw byte pump* with no framing. So an in-flight request whose origin is silent longer than
//! the middlebox idle timeout (e.g. an LLM cold-model-load, agent-hugging / #388) has neither
//! relay traffic nor a keepalive → the middlebox drops it → broken pipe. A bare TCP keepalive
//! is an ACK-only segment that such middleboxes ignore; the robust fix is an application-layer
//! keepalive carrying real payload — the model every multiplexed transport uses (HTTP/2 PING
//! RFC 7540 §6.7 incl. its ACK flag, WebSocket ping RFC 6455). The edge↔agent QUIC path already
//! gets this from quinn; the un-framed TLS-TCP fallback did not, until this.
//!
//! ## Wire format (relay phase only, both directions on the edge↔agent hop)
//!
//! Each frame is a 1-byte discriminator, optionally followed by a fixed or length-prefixed
//! payload:
//! - [`FRAME_DATA`] (`0xFC`): a big-endian `u32` length, then that many bytes of relayed
//!   application data. Length-prefixed so a payload byte can equal any discriminator without
//!   ambiguity — the reader only ever inspects a discriminator at a frame boundary.
//! - [`FRAME_KEEPALIVE`] (`0xFD`): a big-endian `u64` counter. Injectable at any time —
//!   including mid-request during origin silence. The receiver MUST answer with
//!   [`FRAME_KEEPALIVE_ACK`] echoing the counter: the park-phase PING/PONG's one empirically
//!   proven property is real payload on **both** legs of a round trip, and the echo also gives
//!   the injector genuine in-flight dead-peer detection (the RFC 7540 §6.7 PING/ACK shape).
//! - [`FRAME_KEEPALIVE_ACK`] (`0xF8`): a big-endian `u64` counter — the echo. Never answered.
//! - [`FRAME_FIN`] (`0xFE`): no payload — the **in-band half-close**. A side that is done
//!   sending application data sends FIN instead of a TCP `shutdown()`, so the TCP stream stays
//!   writable in both directions and that side can KEEP SENDING keepalives/acks — exactly what
//!   the long-silent tail of a request needs. After sending FIN a side MUST NOT send further
//!   DATA; the receiver treats FIN as EOF of the data direction (e.g. propagates a shutdown
//!   toward its local browser/origin leg).
//!
//! ## Contract invariants (both endpoints)
//!
//! - **Writer atomicity/serialization:** every frame write is a single atomic `write_all`
//!   ([`write_data_frame`] builds one buffer), and all frame writes for one direction MUST be
//!   serialized through one owner (one task, or one mutex) — a keepalive injector interleaving
//!   bytes inside another frame's header+payload silently desynchronises the stream.
//! - **EOF discipline:** readers use [`read_frame_opt`]; `Ok(None)` is a clean EOF exactly at a
//!   frame boundary, while an EOF *inside* a frame surfaces as `UnexpectedEof` — a torn frame is
//!   a connection error, never a silent end-of-stream.
//! - **Phase lifetime:** the framed phase begins byte-exactly after the park phase's
//!   `TCP_PING_STOP` (`0xFB`) and **ends only with the connection** — fallback registrations
//!   are single-use, there is no transition back to a park phase.
//! - **Keepalive cadence:** inject after the park phase's own measured interval
//!   (`TCP_PING_INTERVAL`, 8 s — calibrated against a real middlebox that kills idle flows in
//!   ~10–15 s), not a larger guess.
//! - **Discriminator space:** `0xF8`, `0xFC`–`0xFE` are this module's; `0xF9`–`0xFB` are the
//!   park phase's (PING/PONG/STOP) and `0xFF` is the channel phase preamble — never reuse any
//!   of them. All remaining values (`0x00`–`0xF7`) are RESERVED for future frames and are a
//!   hard `InvalidData` error today, so a future frame type fails loudly against an old peer
//!   instead of desynchronising.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Discriminator: a length-prefixed chunk of relayed application data.
pub const FRAME_DATA: u8 = 0xFC;
/// Discriminator: a keepalive carrying a `u64` counter; the receiver must ACK it.
pub const FRAME_KEEPALIVE: u8 = 0xFD;
/// Discriminator: the keepalive echo, same counter; never answered.
pub const FRAME_KEEPALIVE_ACK: u8 = 0xF8;
/// Discriminator: in-band half-close — sender is done with DATA, keepalives continue.
pub const FRAME_FIN: u8 = 0xFE;

/// Upper bound on a single [`FRAME_DATA`] payload. A hostile or desynchronised peer must not be
/// able to make the reader allocate an arbitrary buffer from a claimed length; 256 KiB
/// comfortably exceeds a max TLS record (~16 KiB) so real relay chunks never approach it.
pub const MAX_FRAME_PAYLOAD: usize = 256 * 1024;

/// One decoded relay frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Relayed application bytes to forward on to the browser/origin.
    Data(Vec<u8>),
    /// A keepalive to be answered with [`Frame::KeepaliveAck`] carrying the same counter.
    Keepalive { counter: u64 },
    /// The keepalive echo; consumed for liveness accounting, never answered.
    KeepaliveAck { counter: u64 },
    /// The peer is done sending application data (half-close); keepalives may still follow.
    Fin,
}

/// Write a [`FRAME_DATA`] frame carrying `payload` as ONE atomic `write_all` (header and
/// payload in a single buffer — see the module contract on writer serialization). A payload
/// over [`MAX_FRAME_PAYLOAD`] is an `InvalidInput` **error** (not a debug assertion): the far
/// side would hard-close on it, so failing loudly at the source is the diagnosable behavior.
pub async fn write_data_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("fallback-framing: DATA payload {} exceeds MAX_FRAME_PAYLOAD {MAX_FRAME_PAYLOAD}", payload.len()),
        ));
    }
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(FRAME_DATA);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).await
}

/// Write one [`FRAME_KEEPALIVE`] with `counter` (single atomic `write_all`).
pub async fn write_keepalive_frame<W: AsyncWrite + Unpin>(w: &mut W, counter: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 9];
    buf[0] = FRAME_KEEPALIVE;
    buf[1..9].copy_from_slice(&counter.to_be_bytes());
    w.write_all(&buf).await
}

/// Write one [`FRAME_KEEPALIVE_ACK`] echoing `counter` (single atomic `write_all`).
pub async fn write_keepalive_ack_frame<W: AsyncWrite + Unpin>(w: &mut W, counter: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 9];
    buf[0] = FRAME_KEEPALIVE_ACK;
    buf[1..9].copy_from_slice(&counter.to_be_bytes());
    w.write_all(&buf).await
}

/// Write one [`FRAME_FIN`].
pub async fn write_fin_frame<W: AsyncWrite + Unpin>(w: &mut W) -> std::io::Result<()> {
    w.write_all(&[FRAME_FIN]).await
}

/// Read exactly one [`Frame`], or `Ok(None)` on a clean EOF **at a frame boundary** (zero
/// bytes of a next frame read). An EOF after the discriminator but before a frame's payload
/// completes is `UnexpectedEof` — a torn frame is a connection error, not an end-of-stream.
/// An unknown/reserved discriminator or an over-[`MAX_FRAME_PAYLOAD`] claimed length is
/// `InvalidData`, never guessed past.
pub async fn read_frame_opt<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Frame>> {
    let mut disc = [0u8; 1];
    // Distinguish "no next frame" (clean EOF, 0 bytes) from a torn frame (EOF mid-frame).
    match r.read(&mut disc).await? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!("read into a 1-byte buffer returns 0 or 1"),
    }
    match disc[0] {
        FRAME_FIN => Ok(Some(Frame::Fin)),
        FRAME_KEEPALIVE => {
            let mut c = [0u8; 8];
            r.read_exact(&mut c).await?;
            Ok(Some(Frame::Keepalive { counter: u64::from_be_bytes(c) }))
        }
        FRAME_KEEPALIVE_ACK => {
            let mut c = [0u8; 8];
            r.read_exact(&mut c).await?;
            Ok(Some(Frame::KeepaliveAck { counter: u64::from_be_bytes(c) }))
        }
        FRAME_DATA => {
            let mut len_buf = [0u8; 4];
            r.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_FRAME_PAYLOAD {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("fallback-framing: DATA length {len} exceeds MAX_FRAME_PAYLOAD {MAX_FRAME_PAYLOAD}"),
                ));
            }
            // Follow-up (review finding 5, perf): a `read_frame_into(&mut Vec)` variant can
            // eliminate this per-frame allocation once the real pump shape exists (#114 class).
            let mut payload = vec![0u8; len];
            r.read_exact(&mut payload).await?;
            Ok(Some(Frame::Data(payload)))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("fallback-framing: unexpected/reserved frame discriminator 0x{other:02X}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn all_frame_kinds_round_trip_interleaved_and_end_in_a_clean_eof() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        // A payload that DELIBERATELY contains every discriminator byte: length-prefixing must
        // make that unambiguous (counted payload bytes are never read as discriminators).
        let payload = vec![FRAME_DATA, FRAME_KEEPALIVE, FRAME_KEEPALIVE_ACK, FRAME_FIN, 0x00, 0xFF];
        let p2 = b"second chunk".to_vec();
        let writer = {
            let payload = payload.clone();
            let p2 = p2.clone();
            tokio::spawn(async move {
                write_data_frame(&mut a, &payload).await.unwrap();
                write_keepalive_frame(&mut a, 7).await.unwrap();
                write_keepalive_ack_frame(&mut a, 7).await.unwrap();
                write_data_frame(&mut a, &p2).await.unwrap();
                write_fin_frame(&mut a).await.unwrap();
                // Drop `a` -> EOF exactly at a frame boundary.
            })
        };
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), Some(Frame::Data(payload)));
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), Some(Frame::Keepalive { counter: 7 }));
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), Some(Frame::KeepaliveAck { counter: 7 }));
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), Some(Frame::Data(p2)));
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), Some(Frame::Fin));
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), None, "EOF at a frame boundary is a CLEAN end");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn eof_inside_a_frame_is_a_torn_frame_error_not_a_clean_end() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // A DATA header promising 5 bytes, then only 2 -> the writer dies mid-frame.
            let mut buf = Vec::new();
            buf.push(FRAME_DATA);
            buf.extend_from_slice(&5u32.to_be_bytes());
            buf.extend_from_slice(b"ab");
            let _ = a.write_all(&buf).await;
            // Drop -> EOF inside the frame.
        });
        let err = read_frame_opt(&mut b).await.expect_err("a torn frame must be an error");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn empty_data_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move { write_data_frame(&mut a, b"").await.unwrap() });
        assert_eq!(read_frame_opt(&mut b).await.unwrap(), Some(Frame::Data(Vec::new())));
        w.await.unwrap();
    }

    #[tokio::test]
    async fn an_oversized_claimed_length_is_rejected_not_allocated() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let mut hdr = [0u8; 5];
            hdr[0] = FRAME_DATA;
            hdr[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
            let _ = a.write_all(&hdr).await;
        });
        let err = read_frame_opt(&mut b).await.expect_err("an over-cap length must be a hard error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_oversized_payload_is_refused_at_the_writer_as_invalid_input() {
        // Review finding 2: a release build must FAIL here, not silently truncate the length.
        let (mut a, _b) = tokio::io::duplex(64);
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let err = write_data_frame(&mut a, &big).await.expect_err("over-cap payload is refused at the source");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn park_phase_and_reserved_discriminators_are_hard_errors() {
        for bad in [0xF9u8, 0xFA, 0xFB, 0xFF, 0x00, 0x42] {
            let (mut a, mut b) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let _ = a.write_all(&[bad]).await;
            });
            let err = read_frame_opt(&mut b)
                .await
                .expect_err("park-phase/reserved discriminators must be rejected in the relay framing");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "0x{bad:02X}");
        }
    }
}
