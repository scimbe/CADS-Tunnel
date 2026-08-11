//! Noise Protocol handshake primitives (ADR-0013).
//!
//! Provider-blind Client↔Origin E2E crypto. P3.1 generates the Origin's static
//! X25519 keypair; its public half is the Origin Identity a Client pins. The
//! handshake (P3.2) and QUIC wiring (P3.3) follow.

use crate::OriginIdentity;
use std::io;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The Noise parameter set for CADS Tunnel's mesh handshake (ADR-0013).
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// A Noise static keypair (X25519). The public half is the Origin Identity;
/// the private half never leaves the Agent.
///
/// #250: `private` is zeroized on drop — without this, the long-lived Origin static
/// secret survives in freed heap memory (recoverable from a core dump or, on some
/// allocators, a later unrelated allocation) after the keypair goes out of scope or the
/// process crashes. Noise_IK gives no forward secrecy against static-key compromise, so
/// a recovered private key lets an attacker impersonate this Origin and decrypt every
/// session pinned to it. `public` is not secret (it IS the Origin Identity clients pin)
/// so it's skipped — zeroizing it would be pointless cost with no security benefit.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct StaticKeypair {
    #[zeroize(skip)]
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl StaticKeypair {
    /// The Origin Identity (public key) a Client pins.
    pub fn origin_identity(&self) -> OriginIdentity {
        OriginIdentity(self.public)
    }
}

/// Generate a fresh Noise static keypair.
///
/// #479: generates the raw X25519 bytes via `x25519_dalek::StaticSecret` (built with
/// its own `zeroize` feature, so ITS internal storage is wiped on drop too) instead of
/// `snow::Builder::generate_keypair()` -- vendored `snow` 0.9.6 has no zeroization
/// anywhere in its source (confirmed: `grep -rn "zeroize\|impl Drop"` over its crate
/// returns nothing), so the intermediate `snow::Keypair` that briefly held the raw
/// private key during generation was freed un-wiped, before this function's own
/// zeroizing `StaticKeypair` was even constructed. `StaticSecret`'s bytes are the same
/// X25519 private scalar `snow`'s own generator would have produced (both are just 32
/// CSPRNG bytes, clamped per RFC 7748) -- this changes nothing about the resulting
/// key's cryptographic properties or wire compatibility, only how it's generated.
pub fn generate_static_keypair() -> StaticKeypair {
    // x25519-dalek's own "zeroize" feature only derives `Zeroize` (a manual, callable
    // wipe), NOT `ZeroizeOnDrop` -- confirmed by reading its vendored source
    // (`grep -rn "ZeroizeOnDrop" x25519-dalek-2.0.1/src/` finds nothing, only
    // `derive(Zeroize)`). A bare `StaticSecret` would still leak on drop exactly like
    // the old `snow::Keypair` did. `zeroize::Zeroizing<T>` (already a dependency)
    // wraps any `Zeroize` type and calls `.zeroize()` for real when IT drops.
    let secret = zeroize::Zeroizing::new(x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng));
    let public_key = x25519_dalek::PublicKey::from(&*secret);
    let mut public = [0u8; 32];
    let mut private = [0u8; 32];
    public.copy_from_slice(public_key.as_bytes());
    private.copy_from_slice(&secret.to_bytes());
    StaticKeypair { public, private }
}

/// Build the Client (initiator) Noise_IK handshake state: it holds its own
/// static key and the Origin's pinned public key (the Origin Identity).
pub fn client_handshake(
    client_private: &[u8; 32],
    origin_public: &[u8; 32],
) -> Result<snow::HandshakeState, snow::Error> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("valid noise params");
    snow::Builder::new(params)
        .local_private_key(client_private)
        .remote_public_key(origin_public)
        .build_initiator()
}

/// Build the Origin (responder) Noise_IK handshake state.
///
/// **#416: this intentionally never checks the Client's static key against anything, and
/// that's correct for THIS (classic Mesh Plane) path specifically** — `client_private`
/// (see `crates/client/src/main.rs`) is a fresh [`generate_static_keypair`] per client
/// process, not a pre-registered identity, so there is no "expected value" for the Origin
/// to compare against even in principle. ADR-0013 calls the Client↔Origin channel
/// "mutually authenticated," which holds in the sense that both sides prove possession
/// of their claimed static key (Noise_IK's own mutual key-confirmation property, real
/// protection against a network MITM that holds neither key) — it does not mean the
/// Origin authorizes a specific, known Client identity. That authorization happens one
/// layer up, at the Edge (Routing Token / Capability / PoW), before a byte of this
/// handshake is ever reached. Contrast [`crate::a2a::a2a_respond_verified`] (the A2A/
/// channel path), where members DO have a persistent, channel-attested identity — there,
/// checking the learned peer key is both meaningful and required.
pub fn origin_handshake(origin_private: &[u8; 32]) -> Result<snow::HandshakeState, snow::Error> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().expect("valid noise params");
    snow::Builder::new(params)
        .local_private_key(origin_private)
        .build_responder()
}

/// Try each candidate Origin private key as the responder against the Client's
/// handshake message 1, returning the handshake state (with `msg1` already read)
/// for whichever key **authenticates** it. In Noise_IK the initiator encrypts to
/// the responder's static key, so only the matching private key decrypts `msg1`;
/// a wrong key fails the AEAD tag. This lets one Agent terminate handshakes for
/// **multiple Origin identities at once** — the basis for zero-downtime key
/// rotation (#12): during the window the Agent holds both the old and new keys.
/// Returns `None` if no candidate matches.
pub fn origin_handshake_any(
    candidates: &[[u8; 32]],
    msg1: &[u8],
) -> Option<snow::HandshakeState> {
    let mut scratch = [0u8; 1024];
    for key in candidates {
        if let Ok(mut hs) = origin_handshake(key) {
            if hs.read_message(msg1, &mut scratch).is_ok() {
                return Some(hs);
            }
        }
    }
    None
}

/// Build a Client (initiator) handshake that pins the Origin Identity carried
/// by `cap` (P3.4). The Client imports a Capability out of band, then uses its
/// Origin Identity as the handshake's pinned remote static key.
pub fn client_handshake_for(
    client_private: &[u8; 32],
    cap: &crate::Capability,
) -> Result<snow::HandshakeState, snow::Error> {
    client_handshake(client_private, &cap.origin.0)
}

/// Length-prefix a message for streaming over a byte transport (2-byte
/// big-endian length + body). Noise messages are variable-length and capped at
/// 65535 bytes, so they are framed before being relayed (P3.3).
pub fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + msg.len());
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// Split one framed message off the front of `buf`, returning
/// `(message, bytes_consumed)` if a complete frame is present, else `None`.
pub fn take_frame(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + n {
        return None;
    }
    Some((&buf[2..2 + n], 2 + n))
}

/// Read exactly one length-prefixed frame (2-byte big-endian length + body) into a
/// **reusable** buffer, returning the body length `n` (the body is `buf[..n]`). `buf`
/// is resized to the frame body, so its capacity is retained across calls and the
/// bulk inbound path allocates no per-frame `Vec` (#114). Returns an error (typically
/// `UnexpectedEof`) when the source closes between frames.
pub async fn read_frame_into<R: AsyncRead + Unpin>(
    recv: &mut R,
    buf: &mut Vec<u8>,
) -> io::Result<usize> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    buf.resize(n, 0);
    recv.read_exact(&mut buf[..n]).await?;
    Ok(n)
}

/// Read exactly one length-prefixed frame (2-byte big-endian length + body) from
/// an async byte source, returning a freshly-allocated body. Convenience wrapper over
/// [`read_frame_into`] for the low-rate handshake paths; the bulk data path in
/// [`noise_pump`] uses `read_frame_into` with a hoisted buffer instead. Returns an
/// error (typically `UnexpectedEof`) when the source closes between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    read_frame_into(recv, &mut body).await?;
    Ok(body)
}

/// Pump a bidirectional plaintext stream over an established Noise transport
/// session (M9.1). Plaintext read from `plain` is encrypted, framed, and written
/// to `cipher`; frames read from `cipher` are decrypted and written to `plain`.
/// Runs until either side closes, propagating the half-close each way.
///
/// The two directions run concurrently; the `TransportState` is shared under a
/// short-held mutex — the send and receive nonces are independent, so
/// serialising only the (synchronous, fast) crypto step is correct and never
/// blocks on I/O.
/// #189: the ONE encrypt-and-frame primitive shared by every pump. Encrypt `plaintext` with `ts` and
/// frame it IN PLACE into `ct` as `2-byte BE len ‖ ciphertext`: `ct` must reserve 2 bytes at the front
/// (`write_message` encrypts into `ct[2..]`), and the returned total (`2 + ciphertext_len`) is the
/// slice the caller writes (`&ct[..total]`). The base pump frames the app bytes directly; the
/// multiplexed pump frames `[tag] ‖ app bytes` — the framing is identical, only the plaintext differs
/// (which is why the base wire carries no tag and the multiplexed wire's tag lives INSIDE the
/// ciphertext). Byte-identical to the inline/closure code it replaces (`noise.rs` golden-vector pinned).
fn seal_frame(ts: &Mutex<snow::TransportState>, plaintext: &[u8], ct: &mut [u8]) -> io::Result<usize> {
    let len = ts
        .lock()
        .unwrap()
        .write_message(plaintext, &mut ct[2..])
        .map_err(|e| io::Error::other(e.to_string()))?;
    ct[0..2].copy_from_slice(&(len as u16).to_be_bytes());
    Ok(2 + len)
}

pub async fn noise_pump<C, P>(
    transport: snow::TransportState,
    cipher: C,
    plain: P,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    const CHUNK: usize = 16 * 1024; // well under Noise's 65519-byte plaintext cap
    let ts = Mutex::new(transport);
    let (mut c_read, mut c_write) = tokio::io::split(cipher);
    let (mut p_read, mut p_write) = tokio::io::split(plain);

    let noise_err = |e: snow::Error| io::Error::other(e.to_string());

    // plaintext -> encrypt -> ciphertext frames
    let outbound = async {
        let mut buf = vec![0u8; CHUNK];
        // Reserve the 2-byte length prefix at the FRONT of `ct`, so `write_message`
        // encrypts in place after it and the frame is sent as one `ct[..2+len]` slice
        // — no per-frame `Vec` alloc and no full-ciphertext copy on the bulk path
        // (#114 #1). The wire bytes are byte-identical to `frame(&ct[..len])`.
        let mut ct = vec![0u8; 2 + CHUNK + 256];
        loop {
            let n = p_read.read(&mut buf).await?;
            if n == 0 {
                let _ = c_write.shutdown().await;
                return Ok::<(), io::Error>(());
            }
            // #189: encrypt+frame the app bytes via the shared primitive (no tag on the base wire).
            let total = seal_frame(&ts, &buf[..n], &mut ct)?;
            c_write.write_all(&ct[..total]).await?;
            c_write.flush().await?;
        }
    };

    // ciphertext frames -> decrypt -> plaintext
    let inbound = async {
        let mut pt = vec![0u8; CHUNK + 256];
        // One reusable ciphertext-frame buffer for the whole inbound loop, so no
        // per-frame `Vec` is allocated on the bulk path (#114 #2).
        let mut fr = Vec::with_capacity(CHUNK + 256);
        loop {
            let n = match read_frame_into(&mut c_read, &mut fr).await {
                Ok(n) => n,
                Err(_) => {
                    let _ = p_write.shutdown().await;
                    return Ok::<(), io::Error>(());
                }
            };
            let len = ts.lock().unwrap().read_message(&fr[..n], &mut pt).map_err(noise_err)?;
            p_write.write_all(&pt[..len]).await?;
            p_write.flush().await?;
        }
    };

    let (o, i) = tokio::join!(outbound, inbound);
    o?;
    i?;
    Ok(())
}

/// Pump-frame tags for the #104-H3 relay→direct cutover: a 1-byte plaintext prefix on every
/// frame marking application `DATA` vs the in-line `CUTOVER` control (and — H3-wire — an
/// opaque in-band `CONTROL` message). Byte-identical wire to [`noise_pump`] otherwise (just one
/// extra plaintext byte).
const PUMP_TAG_DATA: u8 = 0;
const PUMP_TAG_CUTOVER: u8 = 1;
/// An in-band **control** frame (#104 H3-wire): its payload is an opaque control message
/// (e.g. an encoded `UpgradeMsg`) multiplexed on the SAME relay stream as the application byte
/// stream, and delivered to the pump's `control_in` sink instead of the plaintext side. This is
/// what lets the relay→direct upgrade coordination (H1's `Offer`/`Ready`) ride in-band, so a
/// `:443`-only member — which has exactly one stream and cannot open a second control channel —
/// can still negotiate the cutover.
const PUMP_TAG_CONTROL: u8 = 2;

/// An outbound instruction to [`noise_pump_multiplexed`], processed **in order** with the
/// application byte stream. The ordering is the point: a driver that enqueues `Send(Ready)`
/// then `Cutover` is guaranteed the `Ready` control frame lands on the wire *before* the
/// `CUTOVER` marker, so the peer processes the ready-to-upgrade signal on the relay cipher and
/// only then switches — no cross-frame race between coordination and the cipher swap.
pub enum PumpControl {
    /// Send an opaque control message in-band (a `CONTROL` frame) on the current ciphertext side.
    Send(Vec<u8>),
    /// Switch the ciphertext side relay→direct now (writes a `CUTOVER` frame on the relay first,
    /// then encrypts subsequent frames — data and control alike — with the direct transport).
    Cutover,
}

/// A [`noise_pump`] that multiplexes, over the SAME relay stream, three things (#104 H3-wire):
/// the application **byte stream** (`DATA` frames), an in-band bidirectional **control** channel
/// (`CONTROL` frames — the H1 `Offer`/`Ready` upgrade coordination), and a one-way relay→direct
/// **cipher cutover** (`CUTOVER`). The plaintext byte stream stays continuous across the switch —
/// **no byte lost, duplicated, or reordered** — in both directions.
///
/// Why one stream: a `:443`-only member has exactly one relay stream and cannot open a second
/// control channel, so the upgrade must be negotiated in-band. `control_out` (driver → pump) is
/// processed **in order** with the app bytes — enqueue `Send(Ready)` then `Cutover` and the
/// `Ready` frame is guaranteed on the wire before the `CUTOVER` marker. Inbound `CONTROL` payloads
/// are delivered opaquely to `control_in` (pump → driver) — the pump does not parse them, keeping
/// the upgrade-protocol vocabulary out of the crypto layer.
///
/// **Outbound** encrypts on the relay transport until a `Cutover` instruction, which writes a
/// `CUTOVER` frame on the relay and then switches DATA and CONTROL alike to `direct_transport` /
/// `direct_write`. **Inbound** reads from the relay until it decrypts a `CUTOVER` frame, then reads
/// from `direct_read` with `direct_transport`. The direct session must be handshaked (both sides
/// agreed via H1) before `Cutover` is enqueued. Runs until the plaintext or a cipher side closes.
#[allow(clippy::too_many_arguments)]
pub async fn noise_pump_multiplexed<RR, RW, DR, DW, PR, PW>(
    relay_transport: snow::TransportState,
    relay_read: RR,
    mut relay_write: RW,
    mut plain_read: PR,
    mut plain_write: PW,
    mut control_out: tokio::sync::mpsc::UnboundedReceiver<PumpControl>,
    control_in: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    direct: tokio::sync::oneshot::Receiver<(snow::TransportState, DR, DW)>,
) -> io::Result<()>
where
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
    DR: AsyncRead + Unpin,
    DW: AsyncWrite + Unpin,
    PR: AsyncRead + Unpin,
    PW: AsyncWrite + Unpin,
{
    const CHUNK: usize = 16 * 1024;
    let relay_ts = Mutex::new(relay_transport);
    let mut relay_read = relay_read;
    let noise_err = |e: snow::Error| io::Error::other(e.to_string());

    // The direct session is **late-bound** (#104): the relay pump starts with only the relay
    // transport, and the freshly-handshaked direct session is delivered on `direct` once a
    // background dial + direct Noise_IK handshake completes — which in the live flow is *after*
    // the relay pump is already moving bytes. When it arrives, its shared transport (an `Arc<Mutex>`
    // so both directions can use it) plus the two stream halves are routed to the outbound and
    // inbound loops via the internal one-shots below; each loop installs its half at the moment it
    // cuts over. If `direct` is dropped without a session (the dial failed), the halves never
    // arrive and a `Cutover` — which the driver only enqueues once the direct session exists — is
    // treated as a no-op, so the pump simply stays on the relay.
    let (dir_out_tx, dir_out_rx) =
        tokio::sync::oneshot::channel::<(std::sync::Arc<Mutex<snow::TransportState>>, DW)>();
    let (dir_in_tx, dir_in_rx) =
        tokio::sync::oneshot::channel::<(std::sync::Arc<Mutex<snow::TransportState>>, DR)>();
    let installer = async move {
        if let Ok((ts, dr, dw)) = direct.await {
            let arc = std::sync::Arc::new(Mutex::new(ts));
            let _ = dir_out_tx.send((arc.clone(), dw));
            let _ = dir_in_tx.send((arc, dr));
        }
    };

    // Encrypt `[tag ‖ payload]` with `ts` and frame it into `ct` (2-byte len prefix reserved at
    // the front, as `noise_pump`); returns the total framed length.
    //
    // #364: `msg` is a caller-owned scratch buffer, not built fresh per call. The base `noise_pump`
    // already avoids a per-frame allocation on this exact path (#114 #1) by handing `write_message`
    // the app bytes directly; this multiplexed variant needs the extra 1-byte tag prefix, which
    // `seal_frame` (shared with the base pump, #189) can't take separately since it wants one
    // contiguous plaintext slice -- so the tag+payload still has to be assembled somewhere. Doing
    // that into a buffer the caller hoists once (`clear()` + `push()` + `extend_from_slice()` reuses
    // its already-grown capacity every frame) turns what was a fresh `Vec::with_capacity` heap
    // allocation and a full payload memcpy on EVERY outbound frame -- up to 16KiB, hundreds of times
    // per second on a bulk-traffic relay -- into a one-time allocation that then just gets refilled.
    let seal = |ts: &Mutex<snow::TransportState>, tag: u8, payload: &[u8], msg: &mut Vec<u8>, ct: &mut [u8]| -> io::Result<usize> {
        // #189: multiplexed frames `[tag] ‖ payload`; the encrypt+frame is the shared seal_frame, so the
        // wire framing is provably identical to the base pump (only this leading tag byte differs).
        msg.clear();
        msg.push(tag);
        msg.extend_from_slice(payload);
        seal_frame(ts, msg, ct)
    };

    // app bytes + in-band control -> tagged frames, over relay until cutover, then over direct.
    let outbound = async {
        let mut buf = vec![0u8; CHUNK];
        let mut ct = vec![0u8; 2 + 1 + CHUNK + 256];
        let mut msg = Vec::with_capacity(1 + CHUNK);
        let mut control_open = true;
        let mut dir_out_rx = Some(dir_out_rx); // moved into this loop; taken at cutover
        let mut direct: Option<(std::sync::Arc<Mutex<snow::TransportState>>, DW)> = None;
        loop {
            tokio::select! {
                biased;
                ctl = control_out.recv(), if control_open => match ctl {
                    None => control_open = false, // driver done; keep pumping app bytes
                    Some(PumpControl::Cutover) => {
                        // Install the direct send side (the driver only enqueues Cutover once the
                        // background handshake delivered it). If it never arrives — the dial failed
                        // and `direct` was dropped — stay on the relay. The CUTOVER marker itself
                        // travels on the RELAY cipher (the peer still decrypts the relay); only
                        // subsequent frames go direct.
                        if let Some(rx) = dir_out_rx.take() {
                            if let Ok(entry) = rx.await {
                                let total = seal(&relay_ts, PUMP_TAG_CUTOVER, &[], &mut msg, &mut ct)?;
                                relay_write.write_all(&ct[..total]).await?;
                                relay_write.flush().await?;
                                direct = Some(entry);
                            }
                        }
                    }
                    Some(PumpControl::Send(payload)) => {
                        if let Some((dts, dw)) = direct.as_mut() {
                            let total = seal(dts, PUMP_TAG_CONTROL, &payload, &mut msg, &mut ct)?;
                            dw.write_all(&ct[..total]).await?;
                            dw.flush().await?;
                        } else {
                            let total = seal(&relay_ts, PUMP_TAG_CONTROL, &payload, &mut msg, &mut ct)?;
                            relay_write.write_all(&ct[..total]).await?;
                            relay_write.flush().await?;
                        }
                    }
                },
                r = plain_read.read(&mut buf) => {
                    let n = r?;
                    if n == 0 {
                        let _ = relay_write.shutdown().await;
                        if let Some((_, dw)) = direct.as_mut() {
                            let _ = dw.shutdown().await;
                        }
                        return Ok::<(), io::Error>(());
                    }
                    if let Some((dts, dw)) = direct.as_mut() {
                        let total = seal(dts, PUMP_TAG_DATA, &buf[..n], &mut msg, &mut ct)?;
                        dw.write_all(&ct[..total]).await?;
                        dw.flush().await?;
                    } else {
                        let total = seal(&relay_ts, PUMP_TAG_DATA, &buf[..n], &mut msg, &mut ct)?;
                        relay_write.write_all(&ct[..total]).await?;
                        relay_write.flush().await?;
                    }
                }
            }
        }
    };

    // tagged frames -> plaintext / control; switch inbound to the direct read side on CUTOVER.
    let inbound = async {
        let mut pt = vec![0u8; 1 + CHUNK + 256];
        let mut fr = Vec::with_capacity(CHUNK + 256);
        let mut dir_in_rx = Some(dir_in_rx); // moved into this loop; taken at cutover
        let mut direct: Option<(std::sync::Arc<Mutex<snow::TransportState>>, DR)> = None;
        loop {
            let read_res = if let Some((_, dr)) = direct.as_mut() {
                read_frame_into(dr, &mut fr).await
            } else {
                read_frame_into(&mut relay_read, &mut fr).await
            };
            let n = match read_res {
                Ok(n) => n,
                Err(_) => {
                    let _ = plain_write.shutdown().await;
                    return Ok::<(), io::Error>(());
                }
            };
            let len = {
                let mut ts = match direct.as_ref() {
                    Some((dts, _)) => dts.lock().unwrap(),
                    None => relay_ts.lock().unwrap(),
                };
                ts.read_message(&fr[..n], &mut pt).map_err(noise_err)?
            };
            if len == 0 {
                continue; // a frame must carry at least its tag byte
            }
            match pt[0] {
                PUMP_TAG_CUTOVER => {
                    // Install the direct read side, then read subsequent frames from it. The peer
                    // only sends CUTOVER after both sides handshaked direct, so this is present.
                    if let Some(rx) = dir_in_rx.take() {
                        if let Ok(entry) = rx.await {
                            direct = Some(entry);
                        }
                    }
                }
                PUMP_TAG_CONTROL => {
                    // Opaque to the pump — hand the payload to the driver (dropped receiver = no-op).
                    let _ = control_in.send(pt[1..len].to_vec());
                }
                _ => {
                    plain_write.write_all(&pt[1..len]).await?;
                    plain_write.flush().await?;
                }
            }
        }
    };

    let (o, i, ()) = tokio::join!(outbound, inbound, installer);
    o?;
    i?;
    Ok(())
}

/// The H3 cutover primitive (#104-H3): a [`noise_pump_multiplexed`] with no in-band control
/// traffic, whose relay→direct cutover is driven by a single `cutover` signal instead of the
/// ordered control channel. Kept as the focused, frozen proof that the byte stream survives the
/// cipher switch; the live wire-in uses [`noise_pump_multiplexed`] directly so the H1 `Offer`/
/// `Ready` coordination can ride in-band on the one relay stream.
#[allow(clippy::too_many_arguments)]
pub async fn noise_pump_switchable<RR, RW, DR, DW, PR, PW>(
    relay_transport: snow::TransportState,
    direct_transport: snow::TransportState,
    relay_read: RR,
    relay_write: RW,
    direct_read: DR,
    direct_write: DW,
    plain_read: PR,
    plain_write: PW,
    cutover: tokio::sync::oneshot::Receiver<()>,
) -> io::Result<()>
where
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
    DR: AsyncRead + Unpin,
    DW: AsyncWrite + Unpin,
    PR: AsyncRead + Unpin,
    PW: AsyncWrite + Unpin,
{
    // Bridge the one-shot cutover into the ordered control channel (no other outbound control),
    // and drop the inbound-control receiver — this side never receives CONTROL frames.
    let (ctl_tx, ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    // The direct session is known eagerly here — deliver it to the pump's late-bind channel
    // immediately, so a `Cutover` finds it already installed (this is the non-late-bound case).
    let (dir_tx, dir_rx) = tokio::sync::oneshot::channel();
    let _ = dir_tx.send((direct_transport, direct_read, direct_write));
    // Structured (no detached task, so the lib needs no tokio "rt" feature): forward the
    // one-shot into the channel, then park forever so the pump is the sole decider of when the
    // session ends — when it returns, this `select!` drops the parked bridge.
    let bridge = async move {
        if cutover.await.is_ok() {
            let _ = ctl_tx.send(PumpControl::Cutover);
        }
        std::future::pending::<()>().await
    };
    let pump = noise_pump_multiplexed(
        relay_transport,
        relay_read,
        relay_write,
        plain_read,
        plain_write,
        ctl_rx,
        in_tx,
        dir_rx,
    );
    tokio::select! {
        res = pump => res,
        _ = bridge => unreachable!("the cutover bridge parks forever after forwarding"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A completed Noise_IK session as `(initiator_transport, responder_transport)`, handshaked
    /// in memory (no streams) for the pump tests.
    fn transport_pair() -> (snow::TransportState, snow::TransportState) {
        let ini_kp = generate_static_keypair();
        let resp_kp = generate_static_keypair();
        let mut ini = client_handshake(&ini_kp.private, &resp_kp.public).unwrap();
        let mut resp = origin_handshake(&resp_kp.private).unwrap();
        let (mut b1, mut b2, mut t) = ([0u8; 1024], [0u8; 1024], [0u8; 1024]);
        let n = ini.write_message(&[], &mut b1).unwrap();
        resp.read_message(&b1[..n], &mut t).unwrap();
        let m = resp.write_message(&[], &mut b2).unwrap();
        ini.read_message(&b2[..m], &mut t).unwrap();
        (ini.into_transport_mode().unwrap(), resp.into_transport_mode().unwrap())
    }

    #[test]
    fn static_keypair_zeroizes_the_private_key_on_drop() {
        // #250: the private half must not survive in freed memory after the keypair is
        // dropped — a recovered private key breaks impersonation resistance for every
        // session pinned to this Origin (Noise_IK has no forward secrecy against static-key
        // compromise). Heap-allocate so the write survives past drop long enough to observe
        // (a stack slot can be reused/coalesced by the very next instruction, making a
        // stack-based version of this check unreliable regardless of whether zeroize ran;
        // a freed heap block is not touched again until something actually allocates into
        // it, which nothing does between drop and the read below).
        let kp = Box::new(generate_static_keypair());
        let original_private = kp.private;
        assert_ne!(original_private, [0u8; 32], "sanity: a freshly generated key is not all-zero");
        let ptr = std::ptr::addr_of!(kp.private);
        drop(kp);
        // SAFETY: reading (not writing) memory this process just freed, before any other
        // allocation can reuse it -- the standard pattern for asserting ZeroizeOnDrop
        // actually ran, not a claim about safe access to freed memory in general.
        let after = unsafe { std::ptr::read(ptr) };
        assert_ne!(after, original_private, "private key bytes must be wiped, not left in freed memory");
        assert_eq!(after, [0u8; 32], "zeroize overwrites with zero bytes");
    }

    #[test]
    fn generate_static_keypairs_intermediate_secret_also_zeroizes_on_drop_479() {
        // #479: the OLD generator (snow::Builder::generate_keypair()) left the raw private
        // key sitting un-wiped in a freed snow::Keypair for a window before this crate's own
        // StaticKeypair::private (proven zeroizing above) was even constructed. The NEW
        // generator wraps its intermediate x25519_dalek::StaticSecret in
        // zeroize::Zeroizing -- x25519-dalek's own "zeroize" feature only derives
        // `Zeroize` (a manual, callable wipe), confirmed by reading its vendored source
        // (`derive(Zeroize)`, no `ZeroizeOnDrop` anywhere) -- a bare `StaticSecret` does
        // NOT wipe itself on drop, so `Zeroizing` (which DOES run `.zeroize()` in its own
        // real `Drop` impl) is load-bearing here, not decorative.
        //
        // Wrapped in a struct with a leading `[u8; 32]` pad field, matching
        // static_keypair_zeroizes_the_private_key_on_drop's own layout (`public` before
        // `private`) -- an EARLIER version of this test put the target at the very start
        // of its own heap allocation and got spurious garbage in the first ~16 bytes on
        // read-after-free: the global allocator's own free-list bookkeeping writes
        // pointer-sized data into the START of a freed small block immediately on
        // `dealloc`, which can run right after (and clobber) a correct zeroize. Padding
        // keeps the target away from that allocator-owned region, the same way the
        // sibling test already (accidentally) does by having `public` first.
        struct Padded {
            _pad: [u8; 32],
            secret: zeroize::Zeroizing<x25519_dalek::StaticSecret>,
        }
        let boxed = Box::new(Padded {
            _pad: [0u8; 32],
            secret: zeroize::Zeroizing::new(x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng)),
        });
        let original = boxed.secret.to_bytes();
        assert_ne!(original, [0u8; 32], "sanity: a freshly generated secret is not all-zero");
        let ptr = std::ptr::addr_of!(*boxed.secret) as *const [u8; 32];
        drop(boxed);
        // SAFETY: same freed-memory-read pattern as the sibling test above -- reading memory
        // this process just freed, before any other allocation can reuse it.
        let after = unsafe { std::ptr::read(ptr) };
        assert_ne!(after, original, "the intermediate Zeroizing<StaticSecret>'s bytes must be wiped too, not just this crate's own copy");
        assert_eq!(after, [0u8; 32], "zeroize overwrites with zero bytes");
    }

    #[test]
    fn seal_frame_emits_a_2byte_len_frame_that_round_trips_byte_exact() {
        // #189 (frozen): the shared seal_frame primitive emits exactly `2-byte BE len ‖ ciphertext`
        // and the peer decrypts it back to the EXACT plaintext — proven for BOTH caller shapes: the
        // base pump's untagged app bytes, and the multiplexed pump's `[tag] ‖ payload`. A drift in the
        // extraction (wrong prefix, wrong slice) would corrupt every frame on the live wire.
        let (a, mut b) = transport_pair();
        let ats = Mutex::new(a);
        // multi-KiB, non-trivial payload (exercises a real frame, not a toy).
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();

        // base shape: seal_frame(app_bytes)
        let mut ct = vec![0u8; 2 + payload.len() + 256];
        let total = seal_frame(&ats, &payload, &mut ct).unwrap();
        let len = u16::from_be_bytes([ct[0], ct[1]]) as usize;
        assert_eq!(total, 2 + len, "total is 2-byte prefix + ciphertext");
        let mut pt = vec![0u8; payload.len() + 256];
        let dl = b.read_message(&ct[2..total], &mut pt).unwrap();
        assert_eq!(&pt[..dl], &payload[..], "base (untagged) frame round-trips byte-exact");

        // multiplexed shape: seal_frame([tag] ‖ payload) → peer recovers the tag + payload intact.
        let tag = 2u8;
        let mut tagged = Vec::with_capacity(1 + payload.len());
        tagged.push(tag);
        tagged.extend_from_slice(&payload);
        let mut ct2 = vec![0u8; 2 + tagged.len() + 256];
        let total2 = seal_frame(&ats, &tagged, &mut ct2).unwrap();
        let mut pt2 = vec![0u8; tagged.len() + 256];
        let dl2 = b.read_message(&ct2[2..total2], &mut pt2).unwrap();
        assert_eq!(pt2[0], tag, "multiplexed frame preserves the leading tag byte");
        assert_eq!(&pt2[1..dl2], &payload[..], "multiplexed frame round-trips the payload byte-exact");
    }

    #[tokio::test]
    async fn noise_pump_switchable_preserves_byte_stream_across_relay_to_direct_cutover() {
        // #104-H3 (frozen): the live-model byte-stream pump switches its cipher from the relay
        // to a fresh direct Noise session mid-flight, and the plaintext byte stream is continuous
        // across the seam — no byte lost, duplicated, or reordered — regardless of how the bytes
        // happen to split across the two ciphers at the cutover instant.
        let (relay_a, relay_b) = transport_pair(); // A initiator, B responder (relay session)
        let (direct_a, direct_b) = transport_pair(); // ditto (direct session)

        // Cipher duplexes (each direction its own): A→B relay/direct, B→A relay/direct.
        let (ar_w, ar_r) = tokio::io::duplex(1 << 16); // A→B relay
        let (br_w, br_r) = tokio::io::duplex(1 << 16); // B→A relay
        let (ad_w, ad_r) = tokio::io::duplex(1 << 16); // A→B direct
        let (bd_w, bd_r) = tokio::io::duplex(1 << 16); // B→A direct

        // Plaintext endpoints. Test → A's plain (source); B's plain → test (sink).
        let (mut a_plain_feed, a_plain_r) = tokio::io::duplex(1 << 16);
        let (b_plain_w, mut b_plain_out) = tokio::io::duplex(1 << 16);
        // A's plain-write (B→A data, unused) sink; B's plain-read (its own outbound, empty) EOFs.
        let (a_pw, _a_pw_drain) = tokio::io::duplex(64);
        let (b_pr_closed, b_pr) = tokio::io::duplex(64);
        drop(b_pr_closed); // B's outbound sees EOF immediately (no B→A data in this test)

        let (cut_a_tx, cut_a_rx) = tokio::sync::oneshot::channel();
        let (_cut_b_tx, cut_b_rx) = tokio::sync::oneshot::channel();

        // A: relay(read B→A = br_r, write A→B = ar_w), direct(read bd_r, write ad_w), plain(a_plain_r, a_pw)
        let a = tokio::spawn(noise_pump_switchable(
            relay_a, direct_a, br_r, ar_w, bd_r, ad_w, a_plain_r, a_pw, cut_a_rx,
        ));
        // B: relay(read A→B = ar_r, write br_w), direct(read ad_r, write bd_w), plain(b_pr, b_plain_w)
        let b = tokio::spawn(noise_pump_switchable(
            relay_b, direct_b, ar_r, br_w, ad_r, bd_w, b_pr, b_plain_w, cut_b_rx,
        ));

        // A monotonic 2000-byte payload: first 800 pushed, then cut over, then the rest.
        let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        a_plain_feed.write_all(&payload[..800]).await.unwrap();
        a_plain_feed.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await; // let some bytes ride the relay
        cut_a_tx.send(()).unwrap(); // A triggers its outbound cutover
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        a_plain_feed.write_all(&payload[800..]).await.unwrap();
        a_plain_feed.flush().await.unwrap();
        drop(a_plain_feed); // EOF A's plaintext → A outbound shuts the direct cipher

        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), b_plain_out.read_to_end(&mut got))
            .await
            .expect("the receiver drains within 5s")
            .expect("read_to_end");
        assert_eq!(got, payload, "byte stream intact + in order across the relay→direct cutover (#104-H3)");

        let _ = a.await;
        let _ = b.await;
    }

    #[tokio::test]
    async fn noise_pump_multiplexed_carries_inband_control_and_app_bytes_across_cutover() {
        // #104 H3-wire (frozen): the relay pump multiplexes, on ONE relay stream, the application
        // byte stream AND the in-band upgrade coordination (H1 Offer/Ready as CONTROL frames) AND
        // the relay→direct cipher cutover — proving a :443-only member (one stream, no side
        // channel) can negotiate the upgrade in-band while its data keeps flowing byte-exact.
        use crate::upgrade::UpgradeMsg;

        let (relay_a, relay_b) = transport_pair(); // A initiator, B responder (relay session)
        let (direct_a, direct_b) = transport_pair(); // direct session (handshaked ahead, as after H1)

        let (ar_w, ar_r) = tokio::io::duplex(1 << 16); // A→B relay
        let (br_w, br_r) = tokio::io::duplex(1 << 16); // B→A relay
        let (ad_w, ad_r) = tokio::io::duplex(1 << 16); // A→B direct
        let (bd_w, bd_r) = tokio::io::duplex(1 << 16); // B→A direct

        // A's plaintext source; B's plaintext sink (data flows A→B only).
        let (mut a_plain_feed, a_plain_r) = tokio::io::duplex(1 << 16);
        let (b_plain_w, mut b_plain_out) = tokio::io::duplex(1 << 16);
        let (a_pw, _a_pw_drain) = tokio::io::duplex(64); // A's inbound-plain sink (B sends no data)
        // B has no app data to send, but its plaintext must stay OPEN so B's outbound keeps
        // servicing control (the Ready) instead of returning on an immediate EOF.
        let (b_plain_hold, b_plain_r) = tokio::io::duplex(64);

        // Per-side in-band control channels: `ctl_*` = driver→pump (ordered), `in_*` = pump→driver.
        let (ctl_tx_a, ctl_rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_a, mut in_rx_a) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (ctl_tx_b, ctl_rx_b) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_b, mut in_rx_b) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // Direct session known eagerly here — deliver it to each pump's late-bind channel up front.
        let (dir_tx_a, dir_rx_a) = tokio::sync::oneshot::channel();
        dir_tx_a.send((direct_a, bd_r, ad_w)).ok().unwrap();
        let (dir_tx_b, dir_rx_b) = tokio::sync::oneshot::channel();
        dir_tx_b.send((direct_b, ad_r, bd_w)).ok().unwrap();

        let a = tokio::spawn(noise_pump_multiplexed(
            relay_a, br_r, ar_w, a_plain_r, a_pw, ctl_rx_a, in_tx_a, dir_rx_a,
        ));
        let b = tokio::spawn(noise_pump_multiplexed(
            relay_b, ar_r, br_w, b_plain_r, b_plain_w, ctl_rx_b, in_tx_b, dir_rx_b,
        ));

        let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        // Pre-cutover application bytes ride the relay cipher.
        a_plain_feed.write_all(&payload[..800]).await.unwrap();
        a_plain_feed.flush().await.unwrap();

        // The upgrade coordination, entirely in-band on the same relay stream:
        // A offers its direct endpoint; B receives it and replies Ready.
        ctl_tx_a
            .send(PumpControl::Send(UpgradeMsg::Offer { direct_endpoint: "203.0.113.9:7000".into() }.encode()))
            .unwrap();
        let offer = tokio::time::timeout(std::time::Duration::from_secs(5), in_rx_b.recv())
            .await
            .expect("B receives the Offer in-band within 5s")
            .expect("control channel open");
        assert!(
            matches!(UpgradeMsg::decode(&offer), Some(UpgradeMsg::Offer { direct_endpoint }) if direct_endpoint == "203.0.113.9:7000"),
            "the in-band CONTROL frame carried the H1 Offer intact",
        );
        ctl_tx_b.send(PumpControl::Send(UpgradeMsg::Ready.encode())).unwrap();
        let ready = tokio::time::timeout(std::time::Duration::from_secs(5), in_rx_a.recv())
            .await
            .expect("A receives the Ready in-band within 5s")
            .expect("control channel open");
        assert!(
            matches!(UpgradeMsg::decode(&ready), Some(UpgradeMsg::Ready)),
            "the reverse-direction CONTROL frame carried the H1 Ready intact",
        );

        // Both sides ready → A cuts over; ordered channel guarantees the Ready above already
        // landed on the wire before this CUTOVER marker.
        ctl_tx_a.send(PumpControl::Cutover).unwrap();
        a_plain_feed.write_all(&payload[800..]).await.unwrap();
        a_plain_feed.flush().await.unwrap();
        drop(a_plain_feed); // EOF A's plaintext → A outbound shuts the direct cipher

        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), b_plain_out.read_to_end(&mut got))
            .await
            .expect("the receiver drains within 5s")
            .expect("read_to_end");
        assert_eq!(
            got, payload,
            "app byte stream intact + in order across the in-band-negotiated relay→direct cutover (#104 H3-wire)",
        );

        // Release B's outbound (its held-open plaintext) so both pumps terminate.
        drop(b_plain_hold);
        drop(ctl_tx_a);
        drop(ctl_tx_b);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), a).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), b).await;
    }

    #[tokio::test]
    async fn noise_pump_multiplexed_late_binds_the_direct_session_after_the_pump_is_running() {
        // #104 late-bind (frozen): the relay pump starts with ONLY the relay transport; the direct
        // Noise session is delivered on the late-bind one-shot *after* application bytes are already
        // flowing on the relay — exactly the live flow, where a background dial + direct handshake
        // completes mid-session. Once installed, the relay→direct cutover still preserves the byte
        // stream exactly. This is the last pump-level primitive the #104 wire-in needs.
        let (relay_a, relay_b) = transport_pair();
        let (direct_a, direct_b) = transport_pair();

        let (ar_w, ar_r) = tokio::io::duplex(1 << 16); // A→B relay
        let (br_w, br_r) = tokio::io::duplex(1 << 16); // B→A relay
        let (ad_w, ad_r) = tokio::io::duplex(1 << 16); // A→B direct
        let (bd_w, bd_r) = tokio::io::duplex(1 << 16); // B→A direct

        let (mut a_plain_feed, a_plain_r) = tokio::io::duplex(1 << 16);
        let (b_plain_w, mut b_plain_out) = tokio::io::duplex(1 << 16);
        let (a_pw, _a_pw_drain) = tokio::io::duplex(64);
        let (b_pr_closed, b_pr) = tokio::io::duplex(64);
        drop(b_pr_closed); // B outbound EOFs immediately (no B→A data)

        let (ctl_tx_a, ctl_rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_a, _in_rx_a) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (_ctl_tx_b, ctl_rx_b) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_b, _in_rx_b) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // The direct session is NOT delivered at start — the pumps run relay-only until we fire
        // these one-shots mid-stream (modeling the background dial+handshake finishing later).
        let (dir_tx_a, dir_rx_a) = tokio::sync::oneshot::channel();
        let (dir_tx_b, dir_rx_b) = tokio::sync::oneshot::channel();

        let a = tokio::spawn(noise_pump_multiplexed(
            relay_a, br_r, ar_w, a_plain_r, a_pw, ctl_rx_a, in_tx_a, dir_rx_a,
        ));
        let b = tokio::spawn(noise_pump_multiplexed(
            relay_b, ar_r, br_w, b_pr, b_plain_w, ctl_rx_b, in_tx_b, dir_rx_b,
        ));

        let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        // First bytes flow while the pump holds ONLY the relay session (direct not yet bound).
        a_plain_feed.write_all(&payload[..800]).await.unwrap();
        a_plain_feed.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // The background handshake "completes": deliver the direct session LATE, then cut over.
        dir_tx_a.send((direct_a, bd_r, ad_w)).ok().unwrap();
        dir_tx_b.send((direct_b, ad_r, bd_w)).ok().unwrap();
        ctl_tx_a.send(PumpControl::Cutover).unwrap();

        a_plain_feed.write_all(&payload[800..]).await.unwrap();
        a_plain_feed.flush().await.unwrap();
        drop(a_plain_feed); // EOF → A outbound shuts the direct cipher

        let mut got = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), b_plain_out.read_to_end(&mut got))
            .await
            .expect("the receiver drains within 5s")
            .expect("read_to_end");
        assert_eq!(
            got, payload,
            "byte stream intact + in order across a LATE-BOUND direct session and cutover (#104 late-bind)",
        );

        drop(ctl_tx_a);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), a).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), b).await;
    }

    #[test]
    fn origin_handshake_any_selects_the_pinned_identity() {
        // #12 K1: a client pins origin A; an agent holding {B, A} (a rotation
        // window) must terminate the handshake with A, and reject a candidate set
        // that lacks the pinned identity.
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        let client = generate_static_keypair();

        let mut ini = client_handshake(&client.private, &a.public).unwrap();
        let mut buf = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        let msg1 = buf[..n].to_vec();

        // Candidate set contains A (in second position) → matches, and the
        // returned responder state completes the handshake with the client.
        let mut resp = origin_handshake_any(&[b.private, a.private], &msg1)
            .expect("matches the pinned origin key among candidates");
        let mut out = [0u8; 1024];
        let m = resp.write_message(&[], &mut out).unwrap();
        ini.read_message(&out[..m], &mut buf).unwrap();
        assert!(
            resp.into_transport_mode().is_ok() && ini.into_transport_mode().is_ok(),
            "handshake completes on the selected identity"
        );

        // No candidate is the pinned identity → None.
        assert!(
            origin_handshake_any(&[b.private, client.private], &msg1).is_none(),
            "rejects when the pinned origin key is absent"
        );
    }

    #[tokio::test]
    async fn noise_pump_streams_bidirectionally() {
        // Establish two transport states via a real Noise_IK handshake.
        let origin = generate_static_keypair();
        let client = generate_static_keypair();
        let mut ini = client_handshake(&client.private, &origin.public).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();
        let mut b = [0u8; 1024];
        let mut s = [0u8; 1024];
        let n = ini.write_message(&[], &mut b).unwrap();
        resp.read_message(&b[..n], &mut s).unwrap();
        let n = resp.write_message(&[], &mut b).unwrap();
        ini.read_message(&b[..n], &mut s).unwrap();
        let ini_t = ini.into_transport_mode().unwrap();
        let resp_t = resp.into_transport_mode().unwrap();

        let (a_cipher, b_cipher) = tokio::io::duplex(64 * 1024);
        let (a_plain, a_app) = tokio::io::duplex(1024 * 1024);
        let (b_plain, b_app) = tokio::io::duplex(1024 * 1024);

        // Peer B's app is a plaintext echo — reads all, echoes back, closes.
        let echo = async move {
            let (mut r, mut w) = tokio::io::split(b_app);
            let mut all = Vec::new();
            r.read_to_end(&mut all).await.unwrap();
            w.write_all(&all).await.unwrap();
            w.shutdown().await.unwrap();
        };

        // 200 KB → many 16 KB Noise frames, both directions.
        let expected: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let payload = expected.clone();
        let (mut ar, mut aw) = tokio::io::split(a_app);
        let writer = async move {
            aw.write_all(&payload).await.unwrap();
            aw.shutdown().await.unwrap();
        };
        let reader = async move {
            let mut got = Vec::new();
            ar.read_to_end(&mut got).await.unwrap();
            got
        };

        let (pa, pb, _, _, got) = tokio::join!(
            noise_pump(ini_t, a_cipher, a_plain),
            noise_pump(resp_t, b_cipher, b_plain),
            echo,
            writer,
            reader,
        );
        pa.unwrap();
        pb.unwrap();
        assert_eq!(got.len(), expected.len(), "all 200 KB echoed back");
        assert_eq!(got, expected, "payload streams both ways through two Noise pumps");
    }

    #[test]
    fn generates_32_byte_keys() {
        let kp = generate_static_keypair();
        assert_eq!(kp.public.len(), 32);
        assert_eq!(kp.private.len(), 32);
    }

    #[test]
    fn keypairs_are_distinct() {
        let a = generate_static_keypair();
        let b = generate_static_keypair();
        assert_ne!(a.public, b.public, "fresh public keys must differ");
        assert_ne!(a.private, b.private, "fresh private keys must differ");
    }

    #[test]
    fn public_is_origin_identity() {
        let kp = generate_static_keypair();
        assert_eq!(kp.origin_identity(), OriginIdentity(kp.public));
    }

    #[test]
    fn noise_ik_handshake_establishes_e2e() {
        let origin = generate_static_keypair();
        let client = generate_static_keypair();

        let mut ini = client_handshake(&client.private, &origin.public).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();

        // Two-message Noise_IK handshake.
        let mut buf = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        resp.read_message(&buf[..n], &mut scratch).unwrap();
        let n = resp.write_message(&[], &mut buf).unwrap();
        ini.read_message(&buf[..n], &mut scratch).unwrap();

        assert!(ini.is_handshake_finished());
        assert!(resp.is_handshake_finished());

        let mut ini_t = ini.into_transport_mode().unwrap();
        let mut resp_t = resp.into_transport_mode().unwrap();

        // client -> origin
        let mut ct = [0u8; 1024];
        let mut pt = [0u8; 1024];
        let n = ini_t.write_message(b"secret payload", &mut ct).unwrap();
        let m = resp_t.read_message(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"secret payload");

        // origin -> client
        let n = resp_t.write_message(b"reply", &mut ct).unwrap();
        let m = ini_t.read_message(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], b"reply");
    }

    #[test]
    fn wrong_origin_key_fails_handshake() {
        let origin = generate_static_keypair();
        let wrong = generate_static_keypair();
        let client = generate_static_keypair();

        // Client pins the WRONG Origin public key.
        let mut ini = client_handshake(&client.private, &wrong.public).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();

        let mut buf = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        let result = resp.read_message(&buf[..n], &mut scratch);
        assert!(
            result.is_err(),
            "handshake must fail when the client pins the wrong Origin key"
        );
    }

    #[test]
    fn frame_take_roundtrip() {
        let framed = frame(b"noise-msg");
        let (msg, consumed) = take_frame(&framed).unwrap();
        assert_eq!(msg, b"noise-msg");
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn take_frame_needs_full_frame() {
        let framed = frame(b"hello");
        assert!(take_frame(&framed[..1]).is_none(), "fewer than 2 length bytes");
        assert!(take_frame(&framed[..4]).is_none(), "body incomplete");
    }

    #[test]
    fn take_frame_leaves_remainder() {
        let mut buf = frame(b"a");
        buf.extend_from_slice(&frame(b"bb"));
        let (m1, c1) = take_frame(&buf).unwrap();
        assert_eq!(m1, b"a");
        let (m2, _c2) = take_frame(&buf[c1..]).unwrap();
        assert_eq!(m2, b"bb");
    }

    #[tokio::test]
    async fn read_frame_into_reuses_one_buffer_across_varied_frames() {
        // #114 #2 (frozen): the bulk inbound path reads each frame into ONE reused
        // buffer via `read_frame_into` instead of allocating a fresh Vec per frame. It
        // must return exactly the framed bodies across a large -> small -> mid size
        // sequence (so the reused buffer both grows and shrinks), byte-for-byte
        // identical to what `frame()` wrote, and signal EOF cleanly after the last
        // frame. `&[u8]` is an `AsyncRead`, so it stands in for the ciphertext stream.
        let big = vec![0xABu8; 4096];
        let small = vec![0xCDu8; 3];
        let mid = vec![0xEFu8; 1500];
        let mut wire = Vec::new();
        for m in [&big, &small, &mid] {
            wire.extend_from_slice(&frame(m));
        }

        let mut src: &[u8] = &wire;
        let mut buf = Vec::with_capacity(16);
        for want in [&big, &small, &mid] {
            let n = read_frame_into(&mut src, &mut buf).await.expect("frame present");
            assert_eq!(n, want.len(), "reports the body length");
            assert_eq!(&buf[..n], &want[..], "body matches frame() input via the reused buffer");
        }
        assert!(
            read_frame_into(&mut src, &mut buf).await.is_err(),
            "drained source -> EOF, the clean between-frames close signal"
        );

        // The fresh-Vec wrapper `read_frame` still yields identical bodies (handshake path).
        let mut src2: &[u8] = &wire;
        assert_eq!(read_frame(&mut src2).await.unwrap(), big, "read_frame wrapper unchanged");
    }

    #[test]
    fn handshake_from_imported_capability_completes_with_origin() {
        use crate::{Capability, OriginIdentity, RoutingToken};

        let origin = generate_static_keypair();
        let client = generate_static_keypair();

        // Import a Capability carrying the Origin's public key (round-tripped).
        let cap = Capability {
            token: RoutingToken([1u8; 32]),
            origin: OriginIdentity(origin.public),
            edge_addr: "edge:443".into(),
        };
        let cap = Capability::decode(&cap.encode()).unwrap();

        let mut ini = client_handshake_for(&client.private, &cap).unwrap();
        let mut resp = origin_handshake(&origin.private).unwrap();

        let mut buf = [0u8; 1024];
        let mut scratch = [0u8; 1024];
        let n = ini.write_message(&[], &mut buf).unwrap();
        resp.read_message(&buf[..n], &mut scratch).unwrap();
        let n = resp.write_message(&[], &mut buf).unwrap();
        ini.read_message(&buf[..n], &mut scratch).unwrap();

        assert!(
            ini.is_handshake_finished() && resp.is_handshake_finished(),
            "handshake pinned from the imported Capability completes with the matching Origin"
        );
    }
}
