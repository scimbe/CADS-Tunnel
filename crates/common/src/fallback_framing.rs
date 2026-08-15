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
//! - [`FRAME_DATA`] (`0xFC`): big-endian `u32` length, then that many relayed bytes. An empty
//!   DATA frame is legal on the wire but a meaningless no-op — it is NEVER an EOF signal, and
//!   receivers must not treat it as one (relevant e.g. for a lazy origin-dial trigger, which
//!   must fire on the first NON-empty payload only).
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
//! - **FIN rules.** The DATA/double-FIN subset is enforced by the types: after sending FIN no
//!   further DATA (writer errors), a second FIN — sent or received — errors, DATA after the
//!   peer's FIN errors. **Termination is a CALLER duty, not type-checked** (the writer knows
//!   `sent_fin`, the reader knows `peer_fin`, neither sees both): once FIN has passed in
//!   **both** directions each side closes promptly via [`FrameWriter::shutdown`] — two
//!   mutually-FINed sides must not ping each other forever (the registration is single-use;
//!   the worker redials).
//! - **Liveness ends at the peer's FIN; injection does not (#528 review I3).** After the
//!   peer's FIN — explicit, or the implicit clean-EOF kind — active liveness monitoring ENDS:
//!   outstanding counters are discarded and no dead verdict is reached anymore. A peer is not
//!   ACK-obliged after its own FIN, and after an implicit FIN it physically cannot answer, so
//!   any verdict then would be a guaranteed false positive. The surviving direction is
//!   protected by its own DATA traffic and, ultimately, by write errors / kernel keepalive.
//!   Injection, however, CONTINUES until FIN has passed in BOTH directions: a keepalive sent
//!   after the peer's FIN is middlebox state refresh for the still-open sending direction, not
//!   a probe — deliberately untracked and not ACK-obliged; do NOT "simplify" it away. An
//!   origin that closes early while the browser still uploads must not strip the surviving
//!   direction of its middlebox protection — on a blackholing middlebox, write errors would
//!   only surface after minutes of retransmit escalation, not seconds.
//! - **Keepalive cadence + liveness.** Inject after [`KEEPALIVE_INTERVAL`] (8 s — the park
//!   phase's measured interval, calibrated against a real middlebox that kills idle flows in
//!   ~10–15 s). Track sent counters in a [`KeepaliveTracker`]; the peer is dead when the
//!   OLDEST outstanding counter is older than [`KEEPALIVE_DEAD_AFTER`] (3× the cadence, 24 s —
//!   independently justified:
//!   it tolerates two lost keepalives before the verdict; for reference, the *agent*-side TCP
//!   keepalive kills at ~40 s today while the edge side takes ~200 s, so the framed verdict
//!   fires first either way). **An ACK acknowledges every counter ≤ the acked value**
//!   (cumulative), so crossing acks can never produce a false dead verdict — the same reason
//!   the park phase deliberately never compares its PONG counter.
//! - **ACK bounding (PING-flood class, cf. CVE-2019-9512).** [`FrameReader::next`] evaluates
//!   the bound itself and delivers it as [`Frame::Keepalive`]`.should_ack`: `true` only when
//!   the counter is strictly greater than the last counter marked for ack — a flood with a
//!   constant or regressing counter earns nothing, and a caller cannot forget the rule. ACKs
//!   are never answered, so there is no reflection cycle.
//! - **Phase lifetime.** The framed phase begins byte-exactly after the park phase's
//!   `TCP_PING_STOP` (`0xFB`) and ends only with the connection — there is no unframe
//!   transition and no return to a park phase.
//! - **Discriminator space.** `0xF8`, `0xFC`–`0xFE` are this module's; `0xF9`–`0xFB` are the
//!   park phase's and `0xFF` the channel phase preamble; `0x00`–`0xF7` are RESERVED and a hard
//!   `InvalidData` today, so a future frame type fails loudly instead of desynchronising.
//! - **Flushing.** Keepalive/ack/FIN writes flush inline (a keepalive sitting in a buffer never
//!   reaches the middlebox). Bulk DATA does not auto-flush; the caller applies the house
//!   short-read heuristic (#338, see `crates/edge/src/relay.rs` `pump_dir` — the
//!   `if n < buf.len()` there is the normative shape): flush after a
//!   read that returned FEWER bytes than the buffer holds — a short read marks a likely
//!   message boundary the far side is waiting on — not after every chunk. This is a LATENCY
//!   rule, not a throughput knob: the failure mode is response bytes stranded in a buffer
//!   while the browser waits, with no FIN due for a long time.
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

/// The keepalive injection cadence (module contract): inject after this much OWN send silence.
/// MUST match `crates/edge/src/serve.rs`'s private `TCP_PING_INTERVAL` (the park phase's
/// measured 8 s — textual coupling, checked by an edge-side test): the relay phase reuses the
/// park phase's calibrated interval rather than guessing a new one.
pub const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(8);

/// The dead-peer verdict bound (module contract): the peer is dead when the oldest outstanding
/// keepalive counter has been unacked for longer than this — 3× [`KEEPALIVE_INTERVAL`], which
/// tolerates two lost keepalives and still fires before either side's kernel TCP-keepalive
/// death window.
pub const KEEPALIVE_DEAD_AFTER: std::time::Duration = std::time::Duration::from_secs(24);

/// One decoded relay frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Relayed application bytes to forward on to the browser/origin. Empty = meaningless
    /// no-op, never an EOF signal.
    Data(Vec<u8>),
    /// A keepalive. `should_ack` is the reader's own bounded-ACK verdict (module contract):
    /// when `true`, send the ACK through the direction's [`FrameWriter`] owner — never
    /// directly on the stream. When `false` (repeated/regressing counter), do nothing.
    Keepalive { counter: u64, should_ack: bool },
    /// The keepalive echo; feed it to [`KeepaliveTracker::ack`], never answer it.
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

    /// Flush the underlying writer. This is how the caller executes the module contract's
    /// DATA-flush duty (the #338 short-read heuristic): [`Self::data`] deliberately does not
    /// auto-flush, so bulk chunks can coalesce, and the caller flushes exactly after a short
    /// read marked a likely message boundary. Keepalive/ack/FIN flush inline already; flushing
    /// again after those is a harmless no-op.
    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush().await
    }

    /// Shut the underlying writer down (delegates `poll_shutdown` — for a TLS stream this
    /// sends close_notify instead of an abrupt drop, the #229-follow class). This is how the
    /// termination contract's "closes its TCP connection promptly" is actually executed.
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.w.shutdown().await
    }

    /// Unwrap the underlying writer (e.g. to hand the stream to a different phase).
    pub fn into_inner(self) -> W {
        self.w
    }
}

/// The reading side of a direction: yields frames, enforces the peer's FIN rules (DATA after
/// FIN and a double FIN are `InvalidData`), distinguishes a clean EOF from a torn frame, and
/// evaluates the bounded-ACK verdict into each [`Frame::Keepalive`] it yields.
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

    /// Unwrap the underlying reader.
    pub fn into_inner(self) -> R {
        self.r
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
                let counter = u64::from_be_bytes(c);
                // Bounded-ACK rule evaluated HERE so a caller cannot forget it: ack only a
                // counter strictly greater than the last one marked for ack. Marking before
                // the caller's ack write is the safe order — if that write fails, the
                // connection is ending anyway, and the cumulative-ACK rule absorbs any
                // single lost ack (a later, higher ack covers it).
                let should_ack = match self.last_acked {
                    Some(last) if counter <= last => false,
                    _ => {
                        self.last_acked = Some(counter);
                        true
                    }
                };
                Ok(Some(Frame::Keepalive { counter, should_ack }))
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

/// The injector-side liveness bookkeeping the module contract requires, shared by both
/// endpoints so the ~30 lines of time-keeping logic exist ONCE (review finding M4) instead of
/// as two divergent copies. Time is caller-supplied milliseconds (any monotonic source), so
/// the tracker is clock-free and trivially testable.
#[derive(Debug, Default)]
pub struct KeepaliveTracker {
    /// Outstanding (counter, sent_at_ms), oldest first (counters are sent monotonically).
    outstanding: Vec<(u64, u64)>,
}

impl KeepaliveTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a keepalive as sent at `now_ms`. The buffer is hard-capped (64 entries; on
    /// overflow the oldest is dropped): the tracker is the module's only unbounded buffer, and
    /// it grows exactly when the non-type-checked contract half (the dead verdict) is
    /// forgotten — bounded so that mistake shows up as a capped list, not as a silent leak.
    pub fn sent(&mut self, counter: u64, now_ms: u64) {
        const OUTSTANDING_CAP: usize = 64;
        if self.outstanding.len() >= OUTSTANDING_CAP {
            self.outstanding.remove(0);
        }
        self.outstanding.push((counter, now_ms));
    }

    /// Apply a received ACK: **cumulative** — it settles every counter ≤ `counter` (the module
    /// contract's crossing-ack rule, one tested line instead of two interpretations).
    pub fn ack(&mut self, counter: u64) {
        self.outstanding.retain(|(c, _)| *c > counter);
    }

    /// Age in ms of the OLDEST still-outstanding keepalive, or `None` when nothing is
    /// outstanding. The caller declares the peer dead when this exceeds ~3× the cadence.
    pub fn oldest_outstanding_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.outstanding.first().map(|(_, sent)| now_ms.saturating_sub(*sent))
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
                // Keepalives AND acks after own FIN stay legal (the long-silent tail).
                w.keepalive(8).await.unwrap();
                w.keepalive_ack(8).await.unwrap();
                w.shutdown().await.unwrap();
            })
        };
        let mut r = FrameReader::new(b);
        assert_eq!(r.next().await.unwrap(), Some(Frame::Data(payload)));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Keepalive { counter: 7, should_ack: true }));
        assert_eq!(r.next().await.unwrap(), Some(Frame::KeepaliveAck { counter: 7 }));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Data(p2)));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Fin));
        assert!(r.peer_fin());
        assert_eq!(
            r.next().await.unwrap(),
            Some(Frame::Keepalive { counter: 8, should_ack: true }),
            "keepalive after FIN is legal"
        );
        assert_eq!(
            r.next().await.unwrap(),
            Some(Frame::KeepaliveAck { counter: 8 }),
            "ack after FIN is legal too"
        );
        assert_eq!(r.next().await.unwrap(), None, "shutdown lands as a CLEAN end at a frame boundary");
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
    async fn keepalive_ack_verdict_is_strictly_monotonic_and_unforgettable() {
        // M6: the reader evaluates the bound itself — repeated/regressing counters arrive with
        // should_ack=false, so a caller cannot ack a flood even by naively acking every frame
        // it is told to.
        let (mut a, b) = tokio::io::duplex(256);
        tokio::spawn(async move {
            for counter in [1u64, 1, 0, 5, 3] {
                let mut buf = [0u8; 9];
                buf[0] = FRAME_KEEPALIVE;
                buf[1..9].copy_from_slice(&counter.to_be_bytes());
                let _ = a.write_all(&buf).await;
            }
        });
        let mut r = FrameReader::new(b);
        let verdicts: Vec<(u64, bool)> = {
            let mut v = Vec::new();
            for _ in 0..5 {
                match r.next().await.unwrap() {
                    Some(Frame::Keepalive { counter, should_ack }) => v.push((counter, should_ack)),
                    other => panic!("expected keepalive, got {other:?}"),
                }
            }
            v
        };
        assert_eq!(
            verdicts,
            vec![(1, true), (1, false), (0, false), (5, true), (3, false)],
            "only strictly-increasing counters earn an ACK"
        );
    }

    #[test]
    fn keepalive_tracker_is_cumulative_and_ages_from_the_oldest() {
        // M4: the liveness bookkeeping exists once, clock-free.
        let mut t = KeepaliveTracker::new();
        assert_eq!(t.oldest_outstanding_age_ms(1_000), None);
        t.sent(1, 1_000);
        t.sent(2, 9_000);
        t.sent(3, 17_000);
        assert_eq!(t.oldest_outstanding_age_ms(18_000), Some(17_000), "age counts from the OLDEST");
        // A cumulative ack for 2 settles 1 and 2 — a crossing ack can't leave a stale oldest.
        t.ack(2);
        assert_eq!(t.oldest_outstanding_age_ms(18_000), Some(1_000), "only 3 (sent 17_000) is left");
        t.ack(3);
        assert_eq!(t.oldest_outstanding_age_ms(99_000), None, "all settled");
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
    async fn empty_data_frame_round_trips_as_a_noop_not_an_eof() {
        let (a, b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move {
            let mut w = FrameWriter::new(a);
            w.data(b"").await.unwrap();
            w.data(b"real").await.unwrap();
        });
        let mut r = FrameReader::new(b);
        assert_eq!(r.next().await.unwrap(), Some(Frame::Data(Vec::new())));
        assert_eq!(r.next().await.unwrap(), Some(Frame::Data(b"real".to_vec())), "the stream continues after an empty DATA");
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
