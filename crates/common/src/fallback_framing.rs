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
//! is an ACK-only segment that such middleboxes ignore (RFC 1122 §4.2.3.6 was never the tool
//! for NAT/firewall traversal; RFC 5382/BCP 142's ≥2h TCP-state rule is violated by them). The
//! robust fix is an **application-layer keepalive carrying real payload** — the model every
//! multiplexed transport uses (HTTP/2 PING RFC 7540 §6.7, WebSocket ping RFC 6455), and exactly
//! what lets `cloudflared`'s HTTP/2/QUIC transport avoid this class. The edge↔agent QUIC path
//! already gets it (quinn keepalive during streams); the un-framed TLS-TCP fallback — the path
//! a UDP-blocked origin is forced onto — does not, until this.
//!
//! ## Wire format (relay phase only, both directions on the edge↔agent hop)
//!
//! Each frame is a 1-byte discriminator, optionally followed by a payload:
//! - [`FRAME_DATA`] (`0xFC`): a big-endian `u32` length, then that many bytes of relayed
//!   application data. Length-prefixed so a payload byte can equal any discriminator without
//!   ambiguity — the reader only ever inspects a discriminator at a frame boundary.
//! - [`FRAME_KEEPALIVE`] (`0xFD`): no payload. Injectable at any time (including mid-request,
//!   between DATA frames) and discarded by the receiver; its only job is to put real payload on
//!   the wire so the middlebox keeps the connection's state.
//!
//! Discriminators are chosen distinct from the park-phase magic bytes (`0xF9` PING / `0xFA`
//! PONG / `0xFB` STOP) and the phase-preamble `0xFF`, so the two phases can never be confused.
//! This layer is capability-negotiated (a later #528 slice) so legacy peers keep the raw pump;
//! the codec itself is transport-agnostic and I/O-driven by the caller.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Discriminator: a length-prefixed chunk of relayed application data.
pub const FRAME_DATA: u8 = 0xFC;
/// Discriminator: a payload-less keepalive; injected during silence, discarded on receipt.
pub const FRAME_KEEPALIVE: u8 = 0xFD;

/// Upper bound on a single [`FRAME_DATA`] payload. A hostile or desynchronised peer must not be
/// able to make the reader allocate an arbitrary buffer from a claimed length; 256 KiB
/// comfortably exceeds a max TLS record (~16 KiB) so real relay chunks never approach it.
pub const MAX_FRAME_PAYLOAD: usize = 256 * 1024;

/// One decoded relay frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Relayed application bytes to forward on to the browser/origin.
    Data(Vec<u8>),
    /// A keepalive — no application data; the caller discards it.
    Keepalive,
}

/// Write a [`FRAME_DATA`] frame carrying `payload`. The caller is responsible for chunking to
/// `<= `[`MAX_FRAME_PAYLOAD`]; a longer payload is a caller bug (debug-asserted) and would be
/// rejected by [`read_frame`] on the far side.
pub async fn write_data_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    debug_assert!(payload.len() <= MAX_FRAME_PAYLOAD, "DATA payload exceeds MAX_FRAME_PAYLOAD");
    let mut header = [0u8; 5];
    header[0] = FRAME_DATA;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&header).await?;
    w.write_all(payload).await?;
    Ok(())
}

/// Write a single [`FRAME_KEEPALIVE`] frame.
pub async fn write_keepalive_frame<W: AsyncWrite + Unpin>(w: &mut W) -> std::io::Result<()> {
    w.write_all(&[FRAME_KEEPALIVE]).await
}

/// Read exactly one [`Frame`]. Reads the discriminator, then (for [`FRAME_DATA`]) the length and
/// payload. An unknown discriminator or an over-`MAX_FRAME_PAYLOAD` length is
/// [`std::io::ErrorKind::InvalidData`] rather than a guess — a desynchronised relay stream is a
/// connection error, and the caller's reconnect path is the correct recovery.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Frame> {
    let mut disc = [0u8; 1];
    r.read_exact(&mut disc).await?;
    match disc[0] {
        FRAME_KEEPALIVE => Ok(Frame::Keepalive),
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
            let mut payload = vec![0u8; len];
            r.read_exact(&mut payload).await?;
            Ok(Frame::Data(payload))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("fallback-framing: unexpected frame discriminator 0x{other:02X}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn data_and_keepalive_frames_round_trip_interleaved() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        // A payload that DELIBERATELY contains both discriminator bytes: length-prefixing must
        // make that unambiguous (they are read as counted payload, never as a discriminator).
        let payload = vec![FRAME_DATA, FRAME_KEEPALIVE, 0x00, 0xFF, FRAME_DATA];
        let p2 = b"second chunk".to_vec();
        let writer = {
            let payload = payload.clone();
            let p2 = p2.clone();
            tokio::spawn(async move {
                write_data_frame(&mut a, &payload).await.unwrap();
                write_keepalive_frame(&mut a).await.unwrap();
                write_data_frame(&mut a, &p2).await.unwrap();
                a
            })
        };
        assert_eq!(read_frame(&mut b).await.unwrap(), Frame::Data(payload));
        assert_eq!(read_frame(&mut b).await.unwrap(), Frame::Keepalive);
        assert_eq!(read_frame(&mut b).await.unwrap(), Frame::Data(p2));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn empty_data_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move { write_data_frame(&mut a, b"").await.unwrap(); a });
        assert_eq!(read_frame(&mut b).await.unwrap(), Frame::Data(Vec::new()));
        w.await.unwrap();
    }

    #[tokio::test]
    async fn an_oversized_claimed_length_is_rejected_not_allocated() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Hand-write a DATA header claiming way more than MAX_FRAME_PAYLOAD.
        tokio::spawn(async move {
            let mut hdr = [0u8; 5];
            hdr[0] = FRAME_DATA;
            hdr[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
            let _ = a.write_all(&hdr).await;
            a
        });
        let err = read_frame(&mut b).await.expect_err("an over-cap length must be a hard error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_unknown_discriminator_is_a_hard_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // 0xF9 is the park-phase PING magic -- it must NOT be accepted in the relay framing.
            let _ = a.write_all(&[0xF9]).await;
            a
        });
        let err = read_frame(&mut b).await.expect_err("a non-relay discriminator must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
