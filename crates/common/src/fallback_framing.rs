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
//! RFC 7540 §6.7 incl. its ACK flag, WebSocket ping RFC 6455).
//!
//! ## Wire format (relay phase only, both directions on the edge↔agent hop)
//!
//! - [`FRAME_DATA`] (`0xFC`): big-endian `u32` length, then that many relayed bytes.
//! - [`FRAME_KEEPALIVE`] (`0xFD`): big-endian `u64` counter; the receiver answers with an ACK.
//! - [`FRAME_KEEPALIVE_ACK`] (`0xF8`): the echo, same counter; never answered.
//! - [`FRAME_FIN`] (`0xFE`): no payload — in-band half-close (data-EOF); keepalives continue.
//!
//! ## Contract (normative — both endpoints implement THIS)
//!
//! - **One writer-owner per direction, mandatory.** All frame writes for one direction MUST be
//!   serialized through one [`FrameWriter`] (one task, or one mutex around it). Each write is
//!   ONE `write_all` **call**, but `write_all` is NOT atomic against concurrent writers — it
//!   loops over `poll_write` and can yield under backpressure, and a split `WriteHalf` locks
//!   per `poll_write`, not per call. Interleaving two writers desynchronises the stream.
//! - **EOF discipline.** [`FrameReader::next`]'s `Ok(None)` is a clean EOF exactly at a frame
//!   boundary; an EOF *inside* a frame is `UnexpectedEof` (a torn frame is a connection error).
//!   A clean EOF **without** a preceding [`Frame::Fin`] is an **implicit FIN** (data-EOF of
//!   that direction) — both endings converge on the same downstream behavior.
//! - **FIN rules (enforced by the types).** After sending FIN: no further DATA (writer errors),
//!   keepalives/acks may continue. A second FIN — sent or received — is an error. After
//!   receiving FIN: further DATA from the peer is `InvalidData`.
//! - **Termination.** Keepalives exist to protect an in-flight request; they are only sent
//!   while the counter-direction's FIN is still outstanding. Once FIN has passed in **both**
//!   directions, each side closes its TCP connection promptly — two mutually-FINed sides must
//!   not ping each other forever (the fallback registration is single-use; the worker redials).
//! - **Keepalive cadence + liveness.** Inject after the park phase's measured interval
//!   (`TCP_PING_INTERVAL`, 8 s — calibrated against a real middlebox that kills idle flows in
//!   ~10–15 s). The injector keeps its sent counters outstanding until acked and declares the
//!   peer dead when the OLDEST outstanding counter is older than ~3× the cadence (24 s — under
//!   the ~40 s TCP-keepalive death window). **An ACK acknowledges every counter ≤ the acked
//!   value** (cumulative), so crossing acks can never produce a false dead verdict — the same
//!   reason the park phase deliberately never compares its PONG counter.
//! - **ACK bounding (PING-flood class, cf. CVE-2019-9512).** The receiver ACKs a keepalive only
//!   when its counter is **strictly greater** than the last counter it acked
//!   ([`FrameReader::should_ack`]) — a flood with a constant or regressing counter earns
//!   nothing. ACKs are never answered, so there is no reflection cycle.
//! - **Phase lifetime.** The framed phase begins byte-exactly after the park phase's
//!   `TCP_PING_STOP` (`0xFB`) and ends only with the connection — there is no unframe
//!   transition and no return to a park phase.
//! - **Discriminator space.** `0xF8`, `0xFC`–`0xFE` are this module's; `0xF9`–`0xFB` are the
//!   park phase's and `0xFF` the channel phase preamble; `0x00`–`0xF7` are RESERVED and a hard
//!   `InvalidData` today, so a future frame type fails loudly instead of desynchronising.
//! - **Flushing.** Keepalive/ack/FIN writes flush inline (a keepalive sitting in a buffer never
//!   reaches the middlebox); bulk DATA leaves flushing to the caller's own batching policy.
//!
//! Perf follow-ups, deliberately deferred until the real pump shape exists (#114 class):
//! reader-side `read_frame_into(&mut Vec)` (review finding 5) and writer-side header-in-place
//! encoding to avoid the per-frame copy (finding N7).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Discriminator: a length-prefixed chunk of relayed application data.
pub const FRAME_DATA: u8 = 0xFC;
/// Discriminator: a keepalive carrying a `u64` counter; the receiver must ACK it (bounded).
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
    /// A keepalive; answer via the writer iff [`FrameReader::should_ack`] said so.
    Keepalive { counter: u64 },
    /// The keepalive echo; consumed for liveness accounting, never answered.
    KeepaliveAck { counter: u64 },
    /// The peer is done sending application data (half-close); keepalives may still follow.
    Fin,
}

fn invalid_input(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}
fn invalid_data(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

/// The one writer-owner for a direction (see the module contract): enforces the FIN rules at
/// the type level — DATA after own FIN and a double FIN are `InvalidInput` — and flushes
/// keepalive/ack/FIN frames inline so they actually reach the middlebox.
pub struct FrameWriter<W> {
    w: W,
    sent_fin: bool,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(w: W) -> Self {
        Self { w, sent_fin: false }
    }

    /// Whether FIN was already sent (no further DATA is possible).
    pub fn fin_sent(&self) -> bool {
        self.sent_fin
    }

    /// Write one DATA frame as a single `write_all` call (header+payload in one buffer).
    /// Errors: payload over [`MAX_FRAME_PAYLOAD`] (`InvalidInput` — the far side would
    /// hard-close on it, failing loudly at the source is the diagnosable behavior), or DATA
    /// after own FIN (`InvalidInput`).
    pub async fn data(&mut self, payload: &[u8]) -> std::io::Result<()> {
        if self.sent_fin {
            return Err(invalid_input("fallback-framing: DATA after own FIN".into()));
        }
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(invalid_input(format!(
                "fallback-framing: DATA payload {} exceeds MAX_FRAME_PAYLOAD {MAX_FRAME_PAYLOAD}",
                payload.len()
            )));
        }
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(FRAME_DATA);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        self.w.write_all(&buf).await
    }

    /// Write one keepalive and flush it (a buffered keepalive protects nothing).
    pub async fn keepalive(&mut self, counter: u64) -> std::io::Result<()> {
        let mut buf = [0u8; 9];
        buf[0] = FRAME_KEEPALIVE;
        buf[1..9].copy_from_slice(&counter.to_be_bytes());
        self.w.write_all(&buf).await?;
        self.w.flush().await
    }

    /// Write one keepalive ACK and flush it.
    pub async fn keepalive_ack(&mut self, counter: u64) -> std::io::Result<()> {
        let mut buf = [0u8; 9];
        buf[0] = FRAME_KEEPALIVE_ACK;
        buf[1..9].copy_from_slice(&counter.to_be_bytes());
        self.w.write_all(&buf).await?;
        self.w.flush().await
    }

    /// Write the FIN (data-EOF) and flush it. A second FIN is `InvalidInput`.
    pub async fn fin(&mut self) -> std::io::Result<()> {
        if self.sent_fin {
            return Err(invalid_input("fallback-framing: double FIN".into()));
        }
        self.sent_fin = true;
        self.w.write_all(&[FRAME_FIN]).await?;
        self.w.flush().await
    }
}

/// The reading side of a direction: yields frames, enforces the peer's FIN rules (DATA after
/// FIN and a double FIN are `InvalidData`), distinguishes a clean EOF from a torn frame, and
/// implements the bounded-ACK rule ([`Self::should_ack`]).
pub struct FrameReader<R> {
    r: R,
    peer_fin: bool,
    last_acked: Option<u64>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(r: R) -> Self {
        Self { r, peer_fin: false, last_acked: None }
    }

    /// Whether the peer already sent its FIN (its data direction is over).
    pub fn peer_fin(&self) -> bool {
        self.peer_fin
    }

    /// Bounded-ACK rule (module contract): ACK only a counter strictly greater than the last
    /// one acked. Call it on every [`Frame::Keepalive`]; when it returns `true` the caller
    /// sends the ACK through its [`FrameWriter`] owner (never directly on the stream).
    pub fn should_ack(&mut self, counter: u64) -> bool {
        match self.last_acked {
            Some(last) if counter <= last => false,
            _ => {
                self.last_acked = Some(counter);
                true
            }
        }
    }

    /// Read exactly one [`Frame`], or `Ok(None)` on a clean EOF **at a frame boundary** —
    /// which the module contract defines as an implicit FIN when no explicit one preceded it.
    /// An EOF inside a frame is `UnexpectedEof`; DATA after the peer's FIN, a second FIN, an
    /// over-cap claimed length, or an unknown/reserved discriminator are `InvalidData`.
    pub async fn next(&mut self) -> std::io::Result<Option<Frame>> {
        let mut disc = [0u8; 1];
        // A 1-byte read returning 0 can only mean EOF (an AsyncRead with no data pending
        // returns Poll::Pending, never Ok(0)) — so this cleanly distinguishes "no next frame"
        // from a torn frame, which fails read_exact below with UnexpectedEof instead.
        if self.r.read(&mut disc).await? == 0 {
            return Ok(None);
        }
        match disc[0] {
            FRAME_FIN => {
                if self.peer_fin {
                    return Err(invalid_data("fallback-framing: double FIN from peer".into()));
                }
                self.peer_fin = true;
                Ok(Some(Frame::Fin))
            }
            FRAME_KEEPALIVE => {
                let mut c = [0u8; 8];
                self.r.read_exact(&mut c).await?;
                Ok(Some(Frame::Keepalive { counter: u64::from_be_bytes(c) }))
            }
            FRAME_KEEPALIVE_ACK => {
                let mut c = [0u8; 8];
                self.r.read_exact(&mut c).await?;
                Ok(Some(Frame::KeepaliveAck { counter: u64::from_be_bytes(c) }))
            }
            FRAME_DATA => {
                if self.peer_fin {
                    return Err(invalid_data("fallback-framing: DATA after peer FIN".into()));
                }
                let mut len_buf = [0u8; 4];
                self.r.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_FRAME_PAYLOAD {
                    return Err(invalid_data(format!(
                        "fallback-framing: DATA length {len} exceeds MAX_FRAME_PAYLOAD {MAX_FRAME_PAYLOAD}"
                    )));
                }
                let mut payload = vec![0u8; len];
                self.r.read_exact(&mut payload).await?;
                Ok(Some(Frame::Data(payload)))
            }
            other => Err(invalid_data(format!(
                "fallback-framing: unexpected/reserved frame discriminator 0x{other:02X}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn all_frame_kinds_round_trip_interleaved_and_end_in_a_clean_eof() {
        let (a, b) = tokio::io::duplex(1 << 16);
        // A payload that DELIBERATELY contains every discriminator byte: length-prefixing must
        // make that unambiguous (counted payload bytes are never read as discriminators).
        let payload = vec![FRAME_DATA, FRAME_KEEPALIVE, FRAME_KEEPALIVE_ACK, FRAME_FIN, 0x00, 0xFF];
        let p2 = b"second chunk".to_vec();
        let writer = {
            let payload = payload.clone();
            let p2 = p2.clone();
            tokio::spawn(async move {
                let mut w = FrameWriter::new(a);
                w.data(&payload).await.unwrap();
                w.keepalive(7).await.unwrap();
                w.keepalive_ack(7).await.unwrap();
                w.data(&p2).await.unwrap();
                w.fin().await.unwrap();
                // Keepalives after own FIN stay legal (the long-silent tail).
                w.keepalive(8).await.unwrap();
                // Drop -> EOF exactly at a frame boundary.
            })
        };
        let mut r = FrameReader::new(b);
        assert_eq!(r.next().await.unwrap(), Some(Frame::Data(payload)));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Keepalive { counter: 7 }));
        assert_eq!(r.next().await.unwrap(), Some(Frame::KeepaliveAck { counter: 7 }));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Data(p2)));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Fin));
        assert!(r.peer_fin());
        assert_eq!(r.next().await.unwrap(), Some(Frame::Keepalive { counter: 8 }), "keepalive after FIN is legal");
        assert_eq!(r.next().await.unwrap(), None, "EOF at a frame boundary is a CLEAN end");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn fin_rules_are_enforced_by_the_types() {
        // Writer side: DATA after own FIN + double FIN are InvalidInput.
        let (a, b) = tokio::io::duplex(1 << 12);
        let mut w = FrameWriter::new(a);
        w.fin().await.unwrap();
        assert_eq!(w.data(b"nope").await.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(w.fin().await.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        drop(w);
        // Reader side: a hand-written DATA after FIN is InvalidData; so is a double FIN.
        let mut r = FrameReader::new(b);
        assert_eq!(r.next().await.unwrap(), Some(Frame::Fin));
        let (mut raw, b2) = tokio::io::duplex(64);
        tokio::spawn(async move {
            // FIN, then a hand-crafted DATA frame the typed writer would refuse.
            let _ = raw.write_all(&[FRAME_FIN, FRAME_DATA, 0, 0, 0, 1, b'x']).await;
        });
        let mut r2 = FrameReader::new(b2);
        assert_eq!(r2.next().await.unwrap(), Some(Frame::Fin));
        assert_eq!(r2.next().await.unwrap_err().kind(), std::io::ErrorKind::InvalidData, "DATA after peer FIN");
        let (mut raw3, b3) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = raw3.write_all(&[FRAME_FIN, FRAME_FIN]).await;
        });
        let mut r3 = FrameReader::new(b3);
        assert_eq!(r3.next().await.unwrap(), Some(Frame::Fin));
        assert_eq!(r3.next().await.unwrap_err().kind(), std::io::ErrorKind::InvalidData, "double FIN");
    }

    #[tokio::test]
    async fn should_ack_is_strictly_monotonic() {
        let (_a, b) = tokio::io::duplex(64);
        let mut r = FrameReader::new(b);
        assert!(r.should_ack(1));
        assert!(!r.should_ack(1), "a repeated counter earns no ACK (flood bound)");
        assert!(!r.should_ack(0), "a regressing counter earns no ACK");
        assert!(r.should_ack(5));
        assert!(!r.should_ack(3));
    }

    #[tokio::test]
    async fn eof_inside_any_frame_is_a_torn_frame_error_not_a_clean_end() {
        // DATA with a short payload, and KEEPALIVE/ACK cut before their 8 counter bytes.
        let torn_writes: Vec<Vec<u8>> = vec![
            {
                let mut v = vec![FRAME_DATA];
                v.extend_from_slice(&5u32.to_be_bytes());
                v.extend_from_slice(b"ab");
                v
            },
            vec![FRAME_KEEPALIVE, 0, 0],
            vec![FRAME_KEEPALIVE_ACK],
        ];
        for bytes in torn_writes {
            let (mut a, b) = tokio::io::duplex(64);
            let label = format!("{bytes:02X?}");
            tokio::spawn(async move {
                let _ = a.write_all(&bytes).await;
            });
            let mut r = FrameReader::new(b);
            let err = r.next().await.expect_err("a torn frame must be an error");
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof, "{label}");
        }
    }

    #[tokio::test]
    async fn empty_data_frame_round_trips() {
        let (a, b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move { FrameWriter::new(a).data(b"").await.unwrap() });
        assert_eq!(FrameReader::new(b).next().await.unwrap(), Some(Frame::Data(Vec::new())));
        w.await.unwrap();
    }

    #[tokio::test]
    async fn an_oversized_claimed_length_is_rejected_not_allocated() {
        let (mut a, b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let mut hdr = [0u8; 5];
            hdr[0] = FRAME_DATA;
            hdr[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
            let _ = a.write_all(&hdr).await;
        });
        let err = FrameReader::new(b).next().await.expect_err("an over-cap length must be a hard error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_oversized_payload_is_refused_at_the_writer_as_invalid_input() {
        let (a, _b) = tokio::io::duplex(64);
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let err = FrameWriter::new(a).data(&big).await.expect_err("over-cap payload is refused at the source");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn park_phase_and_reserved_discriminators_are_hard_errors() {
        for bad in [0xF9u8, 0xFA, 0xFB, 0xFF, 0x00, 0x42] {
            let (mut a, b) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let _ = a.write_all(&[bad]).await;
            });
            let err = FrameReader::new(b)
                .next()
                .await
                .expect_err("park-phase/reserved discriminators must be rejected in the relay framing");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "0x{bad:02X}");
        }
    }
}
