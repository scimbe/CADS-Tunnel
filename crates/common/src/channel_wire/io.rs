//! The stream-generic channel-join exchange: the possession handshake and the ack readers
//! for the broker (rendezvous) leg and the relay leg, over ANY `AsyncRead`/`AsyncWrite`
//! duplex — a quinn bi-stream (see [`crate::channel_quic`]), a `:443` TLS-over-TCP stream,
//! or an in-memory `tokio::io::duplex` in tests.
//!
//! Ported verbatim from ct-agent `native/src/channel.rs` @ v0.7.23 (see the parent module's
//! provenance note). Signatures are ct-agent's exactly, `BoxError` and all — the error
//! STRINGS are contract: ct-agent's `channel_run/errors.rs` classifies them by text and by
//! downcast to [`DroppedLegBeforeAck`], and its tests pin the wording.
//!
//! Native-only: `tokio::time::Instant::now()` compiles but panics on wasm32-unknown-unknown,
//! and no wasm caller exists (the browser member's transport is a WebSocket bridge).

use ed25519_dalek::{Signer, SigningKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::channel::ChannelJoinRequest;

use super::{
    decode_refusal_category, error_names_park_expiry, is_refusal_token_shape, parse_channel_ack,
    ChannelJoinOutcome, DroppedLegBeforeAck, CHANNEL_ACK_MAX_BYTES, PHASE_PREAMBLE_MAGIC,
    POSSESSION_CHALLENGE_LEN, REFUSAL_CATEGORY_MAX_LEN,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ported verbatim from ct-agent native/src/channel.rs:96-113 @ v0.7.23
/// #140: how long the broker admission exchange (open the stream + send the join request + the
/// possession challenge/response + read the ack) may take. It runs *after* `dial_peer_direct`
/// connects but *before* #139 (post-admission stream setup) and #126 (Noise handshake) cover, so a
/// transport-alive-but-stalled admission was previously unbounded — the same hang class as #139/#126,
/// one layer earlier.
///
/// **Why 45s and not the 15s this shipped with**: the edge only sends the ack on the PAIRING
/// paths once a *partner* arrives, and it keeps a lone first-arriving member parked as pairable
/// for its full park TTL (30s server-side). With a 15s client bound, any pairing whose second
/// member takes 15-30s to show up (entirely normal when that member is walking its own dial
/// ladder off a blocked QUIC rung first) failed DETERMINISTICALLY: this side reported the #140
/// "stalled" error on every rung while the edge, at handoff time, found a corpse ("relay
/// handoff failed acking side A ... connection lost" — observed live 2026-08-13 16:48 UTC,
/// matching the field reports of all-rungs-stall). 45s = the server's 30s park window, plus
/// margin for the partner's own ladder walk. The exchange stays bounded — a genuinely dead
/// broker still fails in finite time — it just no longer gives up while the server is still
/// legitimately waiting for the partner on our behalf.
pub const ADMISSION_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

// ported verbatim from ct-agent native/src/channel.rs:255-278 @ v0.7.23
// (in ct-agent this doc block — the fn's description and its `finish_send_after_sig`
// rationale — sits on the constant directly above the fn, exactly as here)
/// The transport-agnostic core of [`crate::channel_quic::present_channel_join`]: run the channel-join wire
/// protocol over an already-open bidirectional stream (#106 client-dial). The QUIC
/// client reaches this via [`crate::channel_quic::present_channel_join`] (a `quinn` bi-stream), but the
/// identical protocol — length-framed request, possession challenge/response, `OK`/`NO`
/// ack — runs over *any* duplex, so a TLS-over-TCP `:443` front-door stream (the
/// fallback when the channel UDP/TCP ports are blocked) speaks it unchanged. `send`/
/// `recv` are the write/read halves.
///
/// `finish_send_after_sig` (#21 follow-up, packet-capture-proven 2026-08-14): whether to
/// close the send half after the possession signature. On QUIC (`true`) this is quinn's
/// clean stream `finish()`. On a TCP/TLS stream leg it MUST be `false`: the "stream
/// finish" there is a close_notify + TCP FIN that half-closes the WHOLE connection, so a
/// parked member waits out its park as a half-closed flow — its unread close_notify then
/// makes the edge's post-reap teardown emit an RST that races (and at real-world RTT
/// beats) the in-flight `EX` record out of the receive buffer, and every stateful
/// middlebox on the path sees a closing flow where a live park is meant to be. The edge
/// never needed the EOF (every read on its side is exact-length).
/// #506: how long a KA leg's parked wait may go without a single byte (NUL tick or
/// ack) before the park is presumed dead. The edge ticks every parked KA leg every
/// 10 s (#500 K2), so 35 s = 3.5 missed ticks — far above jitter, far below the
/// old fixed bound's worst case. This is what lets a KA park outlive the 45 s
/// exchange bound: liveness is per-tick, not per-total (the edge's park TTL for KA
/// legs becomes an operator knob, CT_EDGE_KA_PARK_TTL_SECS).
pub const KA_PARK_INACTIVITY_BOUND: std::time::Duration = std::time::Duration::from_secs(35);

// ported verbatim from ct-agent native/src/channel.rs:289-483 @ v0.7.23
pub async fn present_channel_join_on_stream<W, R>(
    mut send: W,
    mut recv: R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    exchange_timeout: std::time::Duration,
    finish_send_after_sig: bool,
    phase_marker: Option<u8>,
    ka_tick_wait: bool,
) -> Result<ChannelJoinOutcome, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    // #140: bound the stall — a transport-alive-but-stalled admission (broker not
    // responding, half-open connection, early packet loss) fails fast instead of hanging
    // forever, same discipline as #139/#126. Since #506 the bound is TWO-PHASE: the
    // pre-ack phases (request, challenge, possession) always run under the whole
    // `exchange_timeout`; the ACK WAIT is bounded per-read — for a legacy leg by the
    // remaining total budget (exactly the old whole-exchange behavior), for a KA leg
    // (`ka_tick_wait`) by tick INACTIVITY: the edge ticks a parked KA leg every 10 s, so
    // the park is provably alive however long the edge's park TTL runs, and only 35 s of
    // SILENCE (dead park / wedged edge) fails the wait.
    let deadline = tokio::time::Instant::now() + exchange_timeout;
    let pre = async {
    let bytes = request.encode();
    let len = u16::try_from(bytes.len()).map_err(|_| "channel join request too large")?;
    if let Some(phase) = phase_marker {
        // #495 slice 2a: KA-negotiated legs mark their phase so the edge pairs
        // phase-compatibly (see PHASE_PREAMBLE_MAGIC's doc for the wire safety).
        send.write_all(&[PHASE_PREAMBLE_MAGIC, phase]).await?;
    }
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    // Flush before awaiting the challenge. On a quinn stream this is a no-op, but this
    // same function carries the `:443` front-door legs over a tokio-rustls TLS stream
    // (#106), and tokio-rustls documents that `poll_write` does NOT guarantee
    // transmission — buffered TLS records need an explicit flush. Without it, the join
    // request (or its tail) can sit in the TLS writer while both sides wait: the edge's
    // 15s JOIN_READ bound (#105) and this function's 15s exchange bound (#140) then
    // expire together as a mutual stall. The relay leg
    // (`present_channel_relay_join_on_stream`) has flushed at exactly these two points
    // all along — this leg missing it was an oversight, not a difference in contract.
    send.flush().await?;

    // The edge's response is one of: a 32-byte possession challenge (proceed), a short
    // "NO" (a pre-challenge validation refusal), a genuinely-malformed partial (a broken
    // connection), or nothing. #129: the old `read_exact(challenge).is_ok()` silently fell
    // through on ANY read failure and let it all become a generic `Refused`. We now read
    // enough to react to what actually arrived. NOTE: over QUIC an *empty* response is
    // wire-ambiguous — an explicit `NO` can race the connection teardown and arrive empty,
    // so empty stays `Refused` (turning a raced refusal into an error would be worse); the
    // server-side reason logs (#124-#128) are the authoritative diagnostic. Only a partial
    // response that is neither a full challenge nor `NO` is *unambiguously* a broken stream.
    let mut resp = Vec::new();
    let _ = (&mut recv)
        .take(POSSESSION_CHALLENGE_LEN as u64)
        .read_to_end(&mut resp)
        .await;
    if resp.len() != POSSESSION_CHALLENGE_LEN {
        let text = String::from_utf8_lossy(&resp);
        if resp.is_empty() || text.starts_with("NO") {
            // Explicit NO, or an ambiguous empty (raced-NO/closed). #524: a new edge
            // frames a category token after the sentinel (`NO | len(u8) | token`) and
            // the whole refusal stays < 32 bytes by contract (this `take(32)` is WHY —
            // exactly 32 would read as a challenge), so the token, when present, is
            // already in `resp`. Old edge / truncated frame → None → generic message.
            let category = resp.get(2..).and_then(decode_refusal_category);
            return Ok(Some(ChannelJoinOutcome::Refused { category }));
        }
        return Err(format!(
            "channel join: the edge sent a malformed {}-byte response before the possession \
             challenge — a broken connection, not a clean OK/NO (#129)",
            resp.len()
        )
        .into());
    }
    let challenge: [u8; POSSESSION_CHALLENGE_LEN] =
        resp.try_into().expect("length checked above");
    // #36: `holder.sign` here has no domain-separation prefix, unlike this same key's
    // other signing sites (Noise attestations, DHT coordinate records), which are longer
    // and domain-prefixed. Safe today because the edge's challenge generators (verified
    // in CADS-Tunnel: channel_broker.rs, relay_gate.rs) draw 32 fresh CSPRNG bytes per
    // call -- never predictable, never reused -- so a raw 32-byte challenge cannot
    // collide with anything else this key signs. That property lives entirely on the
    // OTHER side of the wire and this code cannot verify it; a domain-separated `H(ctx ‖
    // challenge)` signature would remove the dependency, but changing it here alone
    // would break interop with every edge still verifying the raw challenge -- a
    // protocol-version rollout, not a local hardening change (see #575's KA-fleet floor
    // for why a one-sided flip like this is worse than the risk it fixes).
    let sig = holder.sign(&challenge).to_bytes();
    send.write_all(&sig).await?;
    send.flush().await?;
    if finish_send_after_sig {
        // QUIC only: the clean stream `finish()`. Lenient: on a refusal the edge may
        // already have closed. See the doc comment for why a stream leg must NOT do this.
        let _ = send.shutdown().await;
    }
    Ok::<Option<ChannelJoinOutcome>, BoxError>(None)
    };
    match tokio::time::timeout_at(deadline, pre).await {
        Ok(Ok(None)) => {} // possession complete — proceed to the ack wait
        Ok(Ok(Some(early))) => return Ok(early),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("channel join admission exchange stalled (#140)".into()),
    }

    // This reader implements the module header's ack contract (#23). The #494 history
    // of why it is byte-wise: the old `take(512).read_to_end` completed only at EOF (or
    // 512 bytes) — correct on QUIC (the edge `finish()`es the rendezvous stream), but
    // the `:443` edge acks `OK ...\n` and never sends an EOF on this leg — so two fresh
    // members each sat on a fully-delivered ack waiting for an EOF only the OTHER side's
    // stall-timeout death could produce. Every fresh `:443` pairing paid 45–100 s this
    // way (the whole first-contact class of ct-agent#18/CADS-Tunnel#494).
    let mut ack = Vec::new();
    let mut byte = [0u8; 1];
    // #524: whether the loop ended on a 0x0A byte (vs EOF/error). Needed to recover a
    // refusal category whose length byte IS 0x0A — see `read_refusal_tail_token`.
    let mut ended_by_newline = false;
    loop {
        // #506: bound each read. A KA leg is bounded by tick INACTIVITY — every #500
        // NUL keepalive (or ack byte) restarts the window, so a long-TTL park waits as
        // long as it provably lives. A legacy leg is bounded by the remaining total
        // budget: byte-for-byte the old whole-exchange #140 behavior.
        let bound = if ka_tick_wait {
            KA_PARK_INACTIVITY_BOUND
        } else {
            deadline.saturating_duration_since(tokio::time::Instant::now())
        };
        let read = match tokio::time::timeout(bound, recv.read(&mut byte)).await {
            Ok(r) => r,
            Err(_) if ka_tick_wait => {
                return Err(format!(
                    "KA park went silent — no keepalive tick or ack for {}s; not a refusal, \
                     retry. Cause unknown from here: could be a dead/wedged park on the edge, \
                     or a local uplink loss (#506)",
                    KA_PARK_INACTIVITY_BOUND.as_secs()
                )
                .into())
            }
            Err(_) => return Err("channel join admission exchange stalled (#140)".into()),
        };
        match read {
            // EOF: QUIC finish, a NO/EX teardown — or a leg dropped before any ack
            // byte, classified as [`DroppedLegBeforeAck`] below the loop (#23).
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => {
                ended_by_newline = true;
                break;
            }
            Ok(_) if byte[0] == 0 && ack.is_empty() => continue, // #500 leading park NULs
            Ok(_) => {
                ack.push(byte[0]);
                if ack.len() >= CHANNEL_ACK_MAX_BYTES {
                    return Err(format!(
                        "channel ack exceeded {CHANNEL_ACK_MAX_BYTES} bytes without a terminator — malformed peer"
                    )
                    .into());
                }
            }
            Err(e) => {
                // #21 QUIC half: a reaped park does not write an ack at all — the edge
                // closes the whole connection with the NAMED ApplicationClose reason
                // "park-expired: ...", which quinn surfaces through this read as an
                // error. Recognizing the reason string here is WIRE parsing (the reason
                // IS the wire token, same contract as the stream leg's bare `EX`), not a
                // fragile in-process substring match. Any other read error keeps the
                // lenient behavior: classify from whatever arrived.
                if error_names_park_expiry(&e) {
                    return Ok(ChannelJoinOutcome::ParkExpired);
                }
                break;
            }
        }
    }
    // Empty after a completed possession handshake = dropped leg (#148), mirrored
    // from the relay leg — see the module header's ack contract (#23).
    if ack.is_empty() {
        return Err(Box::new(DroppedLegBeforeAck { leg: "rendezvous" }) as BoxError);
    }
    // #524: a refusal is classified at the BYTE level, before any lossy conversion —
    // the framed category token's length byte is binary, not text.
    if let Some(rest) = ack.strip_prefix(b"NO") {
        let category = if !rest.is_empty() {
            decode_refusal_category(rest)
        } else if ended_by_newline {
            read_refusal_tail_token(&mut recv).await
        } else {
            None // bare `NO` + EOF: an old edge — generic message, exactly as before
        };
        return Ok(ChannelJoinOutcome::Refused { category });
    }
    let ack = String::from_utf8_lossy(&ack);
    Ok(parse_channel_ack(&ack))
}

// ported verbatim from ct-agent native/src/channel.rs:540-543 @ v0.7.23
/// #524: how long the opportunistic tail read in [`read_refusal_tail_token`] may wait.
/// Deliberately short — the category is a diagnosis aid, never worth stalling a rung
/// walk for; a refusal's stream is already shut down, so EOF normally arrives at once.
pub const REFUSAL_TAIL_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

// ported verbatim from ct-agent native/src/channel.rs:570-586 @ v0.7.23
/// #524, the 0x0A-collision recovery: the byte-wise ack readers treat 0x0A as the
/// line terminator, but a category token of exactly 10 bytes (`possession`,
/// `not-member`) has 0x0A as its LENGTH byte — the reader then stops at `NO` with the
/// token still unread. Only ever called after a `NO` line that ended on 0x0A; a
/// refusal's stream is closed right after the frame, so a short bounded read to EOF
/// yields exactly the token (10 bytes, token-shaped) or nothing (a genuine `NO\n`
/// never exists on the wire — the edge never newline-terminates a refusal — but
/// tolerate anything unexpected by falling back to the generic message).
pub async fn read_refusal_tail_token<R: AsyncRead + Unpin>(recv: &mut R) -> Option<String> {
    let mut tail = Vec::new();
    let mut bounded = (&mut *recv).take(REFUSAL_CATEGORY_MAX_LEN as u64 + 1);
    match tokio::time::timeout(REFUSAL_TAIL_BOUND, bounded.read_to_end(&mut tail)).await {
        Ok(Ok(_)) => (tail.len() == 0x0A && is_refusal_token_shape(&tail))
            .then(|| String::from_utf8(tail).expect("charset-checked ASCII")),
        _ => None,
    }
}

// ported verbatim from ct-agent native/src/channel.rs:640-741 @ v0.7.23
//
// KNOWN ASYMMETRIES vs `present_channel_join_on_stream`, carried over UNCHANGED on purpose
// (consolidation design §1(h), §5): this leg has NO timeout at all (neither an exchange
// bound nor a per-read bound), reads the challenge with `read_exact` (so a pre-challenge
// `NO` from the edge surfaces as an `Err`, not `Refused`), never shuts the send half down,
// and has no `ka_tick_wait` branch. These are pre-existing ct-agent behaviours that its
// callers and error classifiers depend on; fixing them is a separate, filed change, not
// something a verbatim port may do silently.
/// Present a channel join over a **relay** stream that then carries the spliced Noise
/// session on the *same* duplex (#106 relay-leg-443). This differs from
/// [`present_channel_join_on_stream`] — the QUIC / front-door **broker** leg, where the
/// join stream is throwaway (it reads the ack to EOF and closes its write half, and the
/// data path is a *separate* connection) — in two ways the `:443` relay leg requires:
/// it must **not** close the send half (the session writes over it next), and it must
/// read the ack **up to its `\n` delimiter and no further**, leaving every subsequent byte
/// for ct-agent's `channel_run::run_channel_session_on_stream`. The edge relay
/// (`ct_edge::channel_broker::finish_relay_pair_over_streams`) now acks the RICH
/// `OK <peer_endpoint> <peer_noise> <peer_holder> <peer_attest>\n` line — conveying the
/// peer's attested Noise key (#122), so a fresh `:443`-only pair with no pre-shared peer key
/// learns it here — then splices the two members' streams. The trailing newline is exactly
/// where the ack ends and the Noise session's first frame begins, so reading up to it never
/// over-reads. `send`/`recv` are borrowed, not consumed, so the caller reuses them for the
/// session. A refusal is a bare `NO` (no newline), surfaced when the read hits EOF first.
pub async fn present_channel_relay_join_on_stream<W, R>(
    send: &mut W,
    recv: &mut R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    phase_marker: Option<u8>,
) -> Result<ChannelJoinOutcome, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let bytes = request.encode();
    let len = u16::try_from(bytes.len()).map_err(|_| "channel join request too large")?;
    if let Some(phase) = phase_marker {
        // #495 slice 2a: see present_channel_join_on_stream -- same preamble, relay leg.
        send.write_all(&[PHASE_PREAMBLE_MAGIC, phase]).await?;
    }
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.flush().await?;

    // Answer the edge's possession challenge, same as the broker leg — but leave the send
    // half OPEN afterward (the spliced session writes over it), so no `shutdown()` here.
    let mut challenge = [0u8; 32];
    recv.read_exact(&mut challenge).await?;
    let sig = holder.sign(&challenge).to_bytes();
    send.write_all(&sig).await?;
    send.flush().await?;

    // Read the ack LINE up to (and consuming) its `\n` delimiter — never past it: the Noise
    // session ciphertext follows immediately on this same relay-spliced stream, so reading a
    // fixed buffer could swallow the session's first frame. Reading byte-by-byte to the
    // newline consumes exactly the ack; the transport buffers the session bytes internally.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    // #524: see the broker leg — needed to recover a refusal category whose length
    // byte is 0x0A (`read_refusal_tail_token`).
    let mut ended_by_newline = false;
    loop {
        match recv.read_exact(&mut byte).await {
            Ok(_) if byte[0] == b'\n' => {
                ended_by_newline = true;
                break;
            }
            // #500 K2 (v0.4.13): LEADING NULs are the edge's park keepalive (one per 10s
            // while this leg waited for its partner) -- skip them before the ack starts.
            // Unconditional and unambiguous: no ack byte is 0x00, and NULs only ever
            // precede the ack, never follow its first byte.
            Ok(_) if byte[0] == 0 && line.is_empty() => continue,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() >= CHANNEL_ACK_MAX_BYTES {
                    return Err(format!(
                        "channel ack exceeded {CHANNEL_ACK_MAX_BYTES} bytes without a terminator — malformed peer"
                    )
                    .into());
                }
            }
            // EOF before a newline — a bare `NO` refusal, or a dropped relay leg. Classify
            // from whatever arrived below (a bare `NO` becomes `Refused`; nothing at all is a race).
            Err(_) => break,
        }
    }
    // Empty after a completed possession handshake = dropped leg / handoff race
    // (#148: `finish_relay_pair_over_streams` writes an explicit `b"NO"` before
    // closing on a genuine refusal, and the edge logs the race server-side) — see
    // the module header's ack contract (#23).
    if line.is_empty() {
        return Err(Box::new(DroppedLegBeforeAck { leg: "relay" }) as BoxError);
    }
    // #524: byte-level refusal classification with the framed category, exactly as on
    // the broker leg. Reading past the line is safe here ONLY because a refusal ends
    // the stream (the edge writes the refusal and shuts down — no session follows a
    // `NO`), so the bounded tail read can never swallow session bytes.
    if let Some(rest) = line.strip_prefix(b"NO") {
        let category = if !rest.is_empty() {
            decode_refusal_category(rest)
        } else if ended_by_newline {
            read_refusal_tail_token(recv).await
        } else {
            None
        };
        return Ok(ChannelJoinOutcome::Refused { category });
    }
    let ack = String::from_utf8_lossy(&line);
    Ok(parse_channel_ack(&ack))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Direction;
    use crate::channel_wire::test_support::{signed_grant, ScriptedBroker};
    use crate::channel_wire::PHASE_MARKER_RELAY;

    // ported verbatim from ct-agent native/src/channel.rs:871-1310 @ v0.7.23
    // (`operator`/`signed_grant` now come from `channel_wire::test_support`; the
    // `phase_marker_switch_disables_only_on_explicit_off_or_zero` test at :844-856 stays
    // in ct-agent with the `phase_marker_enabled_from` switch it tests)
    #[tokio::test]
    async fn present_channel_join_on_stream_bounds_a_stalled_admission_exchange() {
        // #140 (frozen): the admission exchange runs after dial_peer_direct connects but BEFORE
        // #139/#126 cover — an edge that accepts the stream but never sends the possession challenge
        // hung the client forever with no fallback. The bound turns that into a fast error. Here the
        // "edge" end stays open + silent (never writes the challenge), so the client's read blocks;
        // the exchange must time out (~200ms), not hang.
        use tokio::io::split;
        let channel = [0x3Cu8; 32];
        let holder = SigningKey::from_bytes(&[0x21u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, _silent_edge) = tokio::io::duplex(4096); // held open, never responds
        let (cli_r, cli_w) = split(client_end);
        let start = std::time::Instant::now();
        let r = present_channel_join_on_stream(cli_w, cli_r, &request, &holder, std::time::Duration::from_millis(200), false, None, false).await;
        assert!(r.is_err(), "a stalled admission exchange errors, it does not hang (#140)");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "the #140 bound fires fast (~200ms), not after a long hang"
        );
    }

    #[tokio::test]
    async fn present_channel_join_on_stream_speaks_the_protocol_over_a_plain_duplex() {
        // #106 client-dial (frozen): the channel-join wire protocol is transport-agnostic
        // — it runs over a plain in-memory duplex (the stand-in for a TLS-over-TCP :443
        // front-door stream) identically to the QUIC path. A minimal test "edge" reads
        // the framed request, issues a possession challenge, verifies the client's
        // signature under the grant holder, then acks OK + a peer endpoint; the client
        // returns Admitted with it.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x3Cu8; 32];
        let holder = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_pub = holder.verifying_key().to_bytes();
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            // send = write half, recv = read half — no quinn anywhere.
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        // Minimal "edge": read the framed request, challenge, verify possession, ack OK.
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        let challenge = [0x9u8; 32];
        ew.write_all(&challenge).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        VerifyingKey::from_bytes(&holder_pub)
            .unwrap()
            .verify(&challenge, &Signature::from_bytes(&sig))
            .expect("the client proved possession of the holder key over the duplex");
        ew.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("join") {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
                peer_endpoint, "198.51.100.9:8008",
                "the client learns the peer endpoint over a non-QUIC stream",
            ),
            other => panic!("a valid join over the duplex must be Admitted, got {other:?}"),
        }
    }

    /// #494 (CADS-Tunnel): the `:443` front door acks `OK ...\n` and then keeps the SAME
    /// stream open for the relay splice — no EOF ever arrives. The old
    /// `take(512).read_to_end` ack read therefore sat on a fully-delivered ack until the
    /// PEER's stall-timeout death produced an EOF: every fresh `:443` pairing paid
    /// 45–100s (the entire first-contact class). The newline must complete the read
    /// immediately, with leading #500 keepalive NULs still stripped.
    #[tokio::test]
    async fn a_newline_terminated_ack_on_a_held_open_stream_completes_immediately_494() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x3Eu8; 32];
        let holder = SigningKey::from_bytes(&[0x23u8; 32]);
        let holder_pub = holder.verifying_key().to_bytes();
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:8008".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        let challenge = [0xAu8; 32];
        ew.write_all(&challenge).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        VerifyingKey::from_bytes(&holder_pub)
            .unwrap()
            .verify(&challenge, &Signature::from_bytes(&sig))
            .expect("possession");
        // Two leading park-keepalive NULs (#500), then the newline-terminated relay-style
        // ack — and the stream is deliberately HELD OPEN (no shutdown): the #494 shape.
        ew.write_all(b"\0\0OK 198.51.100.10:9009\n").await.expect("ack");

        let start = std::time::Instant::now();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("the ack must complete WITHOUT an EOF -- hanging here is the #494 deadlock")
            .expect("client task")
            .expect("join");
        match outcome {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                assert_eq!(peer_endpoint, "198.51.100.10:9009");
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "the newline completes the ack immediately, not via a timeout"
        );
        drop(ew);
        drop(er);
    }

    /// #506 (tick-based wait contract): a KA leg's parked wait is bounded by tick
    /// INACTIVITY, not by the total exchange bound — the edge's 10 s NUL keepalives
    /// prove the park alive, so a long-TTL park (CT_EDGE_KA_PARK_TTL_SECS) must be
    /// waitable past the 45 s #140 bound. Driven here with a deliberately TINY
    /// exchange_timeout (500 ms) and a park that ticks well past it before acking:
    /// the ticking park must complete Admitted where the old total bound fired #140.
    #[tokio::test]
    async fn a_ticking_ka_park_outlives_the_exchange_bound_506() {
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x66u8; 32];
        let holder = SigningKey::from_bytes(&[0x2Bu8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Accept);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let exchange_timeout = std::time::Duration::from_millis(500);
        let client = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let r = present_channel_join_on_stream(
                cli_w, cli_r, &request, &holder, exchange_timeout, false, None, true,
            )
            .await;
            (r, start.elapsed())
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0xAu8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        // The park ticks every 150 ms for 1.2 s — far past the 500 ms exchange bound —
        // then the partner arrives and the ack lands.
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            ew.write_all(&[0u8]).await.expect("tick");
        }
        ew.write_all(b"OK 198.51.100.9:9009\n").await.expect("ack");

        let (outcome, elapsed) = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("completes")
            .expect("client task");
        assert!(
            elapsed > exchange_timeout,
            "the test only proves something if the wait genuinely outlived the bound"
        );
        match outcome.expect("a ticking park must not time out (#506)") {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                assert_eq!(peer_endpoint, "198.51.100.9:9009");
            }
            other => panic!("expected Admitted after the ticking wait, got {other:?}"),
        }
    }

    /// #23 (ack contract): a leg that closes with ZERO ack bytes after the possession
    /// handshake completed is a dropped leg / handoff race — the typed, retryable
    /// [`DroppedLegBeforeAck`] — and must NOT classify as `Refused`, which the ladder
    /// escalates to `AdmissionRefused` and #231 punishes with the definitive 30 s
    /// backoff. (The relay leg has said so since #148; this pins the same rule on the
    /// rendezvous leg, where the empty ack silently fell through to `Refused`.)
    #[tokio::test]
    async fn an_empty_ack_after_possession_is_a_dropped_leg_not_a_refusal_23() {
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x51u8; 32];
        let holder = SigningKey::from_bytes(&[0x29u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.5:5005".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0xAu8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        // Possession complete — now the leg dies without a single ack byte.
        drop(ew);
        drop(er);

        let err = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("EOF completes the read promptly")
            .expect("client task")
            .expect_err("an empty post-possession ack is an error, not an outcome");
        assert!(
            err.downcast_ref::<DroppedLegBeforeAck>().is_some(),
            "typed as DroppedLegBeforeAck (retryable), got: {err}"
        );
    }

    /// #23 (ack contract): reaching [`CHANNEL_ACK_MAX_BYTES`] without a terminator is a
    /// malformed peer and a hard error — the rendezvous leg used to "classify what
    /// arrived", which let 512 garbage bytes parse into `Refused` (definitive backoff)
    /// or even a bogus `Admitted`.
    #[tokio::test]
    async fn an_oversized_unterminated_ack_is_a_hard_error_23() {
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x52u8; 32];
        let holder = SigningKey::from_bytes(&[0x2Au8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.6:6006".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0xAu8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        // 512 bytes of garbage, no terminator, stream held open (a newline or EOF
        // would end the read legitimately).
        ew.write_all(&[b'X'; CHANNEL_ACK_MAX_BYTES]).await.expect("garbage");

        let err = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("the cap completes the read without needing EOF")
            .expect("client task")
            .expect_err("an unterminated oversized ack is a protocol violation");
        assert!(
            err.to_string().contains("without a terminator"),
            "names the cap violation, got: {err}"
        );
    }

    #[tokio::test]
    async fn present_channel_join_reports_a_malformed_partial_response_as_a_distinct_error() {
        // #129 (frozen): a partial pre-challenge response that is neither a full 32-byte
        // challenge nor an explicit "NO" is UNAMBIGUOUSLY a broken stream — the client must
        // return a DISTINCT Err, not silently conflate it into a generic Refused. (An *empty*
        // response stays Refused: over QUIC an explicit NO can race the teardown to empty, so
        // erroring on empty would misreport genuine refusals — see the fn comment.)
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x3Du8; 32];
        let holder = SigningKey::from_bytes(&[0x22u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        // "edge": read the framed request, then send a malformed partial (neither 32 bytes
        // nor "NO") and close — a broken stream.
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(b"XYZ").await.expect("partial"); // 3 bytes: not a challenge, not "NO"
        let _ = ew.shutdown().await;
        drop(ew);
        drop(er);

        let err = client
            .await
            .expect("client task")
            .expect_err("a malformed partial response must be a DISTINCT error, not Refused");
        assert!(
            err.to_string().contains("#129") && err.to_string().contains("broken connection"),
            "the error must name the broken-connection case, got: {err}",
        );
    }

    #[tokio::test]
    async fn present_channel_join_treats_an_explicit_pre_challenge_no_as_refused() {
        // #129: an explicit pre-challenge "NO" (a policy refusal the edge writes before the
        // challenge) stays Refused — distinct from a dropped connection.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x3Eu8; 32];
        let holder = SigningKey::from_bytes(&[0x23u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(b"NO").await.expect("no");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("an explicit NO is a clean Refused, not an error") {
            // #524: a BARE `NO` (an old edge) must keep yielding the category-less
            // refusal — the generic message path.
            ChannelJoinOutcome::Refused { category: None } => {}
            other => panic!("an explicit bare NO must be Refused without a category, got {other:?}"),
        }
    }

    /// #524 wire fixture: `NO | len(u8) | token` — what a category-aware edge writes
    /// (CADS-Tunnel `encode_channel_refusal`; duplicated bytes here because the dep pin
    /// predates the helper — this test IS the cross-repo contract pin).
    fn framed_refusal(token: &str) -> Vec<u8> {
        let mut v = b"NO".to_vec();
        v.push(token.len() as u8);
        v.extend_from_slice(token.as_bytes());
        v
    }

    #[tokio::test]
    async fn pre_challenge_refusal_category_is_parsed_and_unknown_tokens_survive() {
        // #524: a category-aware edge frames a token after the pre-challenge `NO`. Known
        // and future/unknown tokens both surface; garbage does not.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        for (wire, want) in [
            (framed_refusal("not-member"), Some("not-member".to_string())),
            (framed_refusal("future-x"), Some("future-x".to_string())), // unknown → surfaced raw
            (b"NO\x0apos".to_vec(), None), // truncated frame (raced teardown) → generic
        ] {
            let channel = [0x3Fu8; 32];
            let holder = SigningKey::from_bytes(&[0x24u8; 32]);
            let grant = signed_grant(channel, &holder, Direction::Initiate);
            let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7008".to_string() };

            let (client_end, edge_end) = tokio::io::duplex(4096);
            let (cli_r, cli_w) = split(client_end);
            let client = tokio::spawn(async move {
                present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
            });
            let (mut er, mut ew) = split(edge_end);
            let mut len_buf = [0u8; 2];
            er.read_exact(&mut len_buf).await.expect("len");
            let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            er.read_exact(&mut body).await.expect("request");
            ew.write_all(&wire).await.expect("refusal");
            let _ = ew.shutdown().await;

            match client.await.expect("client task").expect("a framed NO is a clean Refused") {
                ChannelJoinOutcome::Refused { category } => {
                    assert_eq!(category, want, "wire {wire:?}");
                }
                other => panic!("must be Refused, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn post_challenge_refusal_category_survives_the_0x0a_length_byte() {
        // #524, the collision that shaped the reader: `possession` is 10 bytes, so its
        // LENGTH byte is 0x0A — the byte-wise ack reader stops right after `NO` thinking
        // it saw the line terminator. The opportunistic tail read must still recover the
        // token (the edge shuts the stream down after a refusal, so reading on is safe).
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x3Au8; 32];
        let holder = SigningKey::from_bytes(&[0x25u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.7:7009".to_string(),
        };

        let (client_end, edge_end) = duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let req = request.clone();
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &req, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[7u8; 32]).await.expect("challenge"); // possession challenge
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("possession sig");
        ew.write_all(&framed_refusal("possession")).await.expect("refusal");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("a framed NO is a clean Refused") {
            ChannelJoinOutcome::Refused { category } => {
                assert_eq!(category.as_deref(), Some("possession"), "the 0x0A length byte must not eat the token");
            }
            other => panic!("must be Refused, got {other:?}"),
        }
    }

    // ported verbatim from ct-agent native/src/channel.rs:1361-1510 @ v0.7.23
    #[tokio::test]
    async fn present_channel_join_classifies_the_ex_token_as_park_expired_21() {
        // #21: after a fully successful admission (challenge answered), a reaped park's stream
        // carries exactly the bare `EX` token before the close. That must classify as the
        // DISTINCT `ParkExpired` — never as `Refused` (nothing was refused: there was simply no
        // partner within the park TTL) and never as a transport error (the leg worked end to end).
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x21u8; 32];
        let holder = SigningKey::from_bytes(&[0x24u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Accept);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:7008".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0x42u8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("possession signature");
        ew.write_all(b"EX").await.expect("park-expiry token");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("EX is a clean ParkExpired, not an error") {
            ChannelJoinOutcome::ParkExpired => {}
            other => panic!("the bare EX token must classify as ParkExpired (#21), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keepalive_nuls_are_stripped_before_the_ack_on_both_readers_500() {
        // #500 K2 client half (v0.4.13): a KA-negotiated park receives NUL bytes while
        // waiting; the classifiers must see the ack EXACTLY as if the NULs were never
        // there -- on the broker leg (read-to-EOF) and the relay leg (line reader) alike.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        // Broker leg: NULs then EX -> ParkExpired; NULs then OK -> Admitted.
        for (tail, want_ex) in [(&b"EX"[..], true), (&b"OK 198.51.100.9:8008"[..], false)] {
            let channel = [0x77u8; 32];
            let holder = SigningKey::from_bytes(&[0x31u8; 32]);
            let grant = signed_grant(channel, &holder, Direction::Accept);
            let request = ChannelJoinRequest { grant, endpoint: "203.0.113.9:7009".to_string() };
            let (client_end, edge_end) = tokio::io::duplex(4096);
            let (cli_r, cli_w) = split(client_end);
            let client = tokio::spawn(async move {
                present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
            });
            let (mut er, mut ew) = split(edge_end);
            let mut len_buf = [0u8; 2];
            er.read_exact(&mut len_buf).await.expect("len");
            let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            er.read_exact(&mut body).await.expect("request");
            ew.write_all(&[0x42u8; 32]).await.expect("challenge");
            let mut sig = [0u8; 64];
            er.read_exact(&mut sig).await.expect("sig");
            ew.write_all(&[0u8, 0u8, 0u8]).await.expect("keepalive NULs");
            ew.write_all(tail).await.expect("ack tail");
            let _ = ew.shutdown().await;
            let outcome = client.await.expect("client").expect("clean outcome");
            if want_ex {
                assert!(matches!(outcome, ChannelJoinOutcome::ParkExpired), "NULs+EX -> ParkExpired, got {outcome:?}");
            } else {
                assert!(matches!(outcome, ChannelJoinOutcome::Admitted { .. }), "NULs+OK -> Admitted, got {outcome:?}");
            }
        }

        // Relay leg (line reader): NULs before the OK line are skipped, the line parses.
        let channel = [0x78u8; 32];
        let holder = SigningKey::from_bytes(&[0x32u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6052".to_string(),
        };
        let (client, server) = tokio::io::duplex(4096);
        let (mut cr, mut cw) = split(client);
        let srv = tokio::spawn(async move {
            let (mut sr, mut sw) = split(server);
            let mut len = [0u8; 2];
            sr.read_exact(&mut len).await.unwrap();
            let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
            sr.read_exact(&mut req).await.unwrap();
            sw.write_all(&[0u8; 32]).await.unwrap();
            sw.flush().await.unwrap();
            let mut sig = [0u8; 64];
            sr.read_exact(&mut sig).await.unwrap();
            sw.write_all(&[0u8, 0u8]).await.unwrap(); // parked-phase keepalives
            sw.write_all(b"OK 198.51.100.7:7007\n").await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw, &mut cr, &request, &holder, None)
            .await
            .expect("relay join with leading NULs");
        srv.await.unwrap();
        match outcome {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                assert_eq!(peer_endpoint, "198.51.100.7:7007", "the ack parses exactly as without NULs");
            }
            other => panic!("NULs+OK line must be Admitted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn phase_marker_prefixes_the_join_and_absent_marker_stays_byte_identical_495a() {
        // #495 slice 2a client half: with a marker the wire starts [0xFF, phase, len_hi,
        // len_lo, ...]; without one it starts with the length prefix exactly as every
        // release before v0.4.14 -- the edge-side compatibility contract in one assert.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        for marker in [Some(PHASE_MARKER_RELAY), None] {
            let channel = [0x14u8; 32];
            let holder = SigningKey::from_bytes(&[0x41u8; 32]);
            let request = ChannelJoinRequest {
                grant: signed_grant(channel, &holder, Direction::Initiate),
                endpoint: "203.0.113.14:1414".to_string(),
            };
            let expected_len = request.encode().len() as u16;
            let (client, server) = tokio::io::duplex(4096);
            let (mut cr, mut cw) = split(client);
            let m = marker;
            let req = request.clone();
            let hk = SigningKey::from_bytes(&[0x41u8; 32]);
            let presenter = tokio::spawn(async move {
                let _ = present_channel_relay_join_on_stream(&mut cw, &mut cr, &req, &hk, m).await;
            });
            let (mut sr, mut sw) = split(server);
            let mut head = [0u8; 4];
            sr.read_exact(&mut head).await.expect("wire head");
            match marker {
                Some(p) => {
                    assert_eq!(head[0], PHASE_PREAMBLE_MAGIC, "preamble magic first");
                    assert_eq!(head[1], p, "phase byte second");
                    assert_eq!(u16::from_be_bytes([head[2], head[3]]), expected_len, "then the length");
                }
                None => {
                    assert_eq!(
                        u16::from_be_bytes([head[0], head[1]]),
                        expected_len,
                        "no marker: the wire begins with the length prefix, byte-identical to pre-v0.4.14"
                    );
                }
            }
            let _ = sw.shutdown().await;
            let _ = presenter.await;
        }
    }

    // ported verbatim from ct-agent native/src/channel.rs:1979-2091 @ v0.7.23
    #[tokio::test]
    async fn present_relay_join_reports_a_dropped_leg_distinctly_from_a_refusal() {
        // #148 client-facing (frozen): on the relay path a refusal is an explicit `NO`, so an EMPTY
        // ack after the challenge was accepted is a dropped leg / handoff race — a DISTINCT retryable
        // error, not the generic `Refused` that reads like an authorization denial. An explicit `NO`
        // still parses to `Refused`.
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
        let channel = [0xC1u8; 32];
        let holder = SigningKey::from_bytes(&[0x0bu8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6051".to_string(),
        };

        // Play the edge side up to the ack: read the framed request, send a 32-byte challenge, read
        // the 64-byte possession sig — then run `finish` (drop = empty ack, or write an explicit NO).
        async fn edge_until_ack(
            server: tokio::io::DuplexStream,
        ) -> (
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
        ) {
            let (mut sr, mut sw) = split(server);
            let mut len = [0u8; 2];
            sr.read_exact(&mut len).await.unwrap();
            let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
            sr.read_exact(&mut req).await.unwrap();
            sw.write_all(&[0u8; 32]).await.unwrap(); // possession challenge
            sw.flush().await.unwrap();
            let mut sig = [0u8; 64];
            sr.read_exact(&mut sig).await.unwrap();
            (sr, sw)
        }

        // (1) Dropped leg: the edge closes without any OK/NO after admission → a distinct retryable Err.
        let (client, server) = duplex(4096);
        let (mut cr, mut cw) = split(client);
        let srv = tokio::spawn(async move {
            let (_sr, sw) = edge_until_ack(server).await;
            drop(sw); // no OK/NO — the #148 dropped leg
        });
        let err = present_channel_relay_join_on_stream(&mut cw, &mut cr, &request, &holder, None)
            .await
            .expect_err("a dropped relay leg after admission must be a distinct error, not Ok(Refused)");
        srv.await.unwrap();
        let msg = format!("{err}").to_lowercase();
        assert!(msg.contains("race") && msg.contains("retry"), "distinct retryable message: {msg}");
        assert!(
            msg.contains("not an authorization refusal"),
            "must explicitly disclaim being a refusal, not read like one: {msg}"
        );

        // (2) Explicit NO: a genuine post-pairing refusal still parses to Refused.
        let (client2, server2) = duplex(4096);
        let (mut cr2, mut cw2) = split(client2);
        let srv2 = tokio::spawn(async move {
            let (_sr, mut sw) = edge_until_ack(server2).await;
            sw.write_all(b"NO").await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw2, &mut cr2, &request, &holder, None)
            .await
            .expect("an explicit NO is a clean outcome, not an error");
        srv2.await.unwrap();
        assert!(
            matches!(outcome, ChannelJoinOutcome::Refused { category: None }),
            "an explicit BARE post-pairing NO (old edge) stays a category-less Refused"
        );

        // (2b) #524: a category-aware edge frames the `pairing` token after the NO —
        // the line reader pushes the (non-0x0A) length byte + token until EOF and the
        // byte-level classifier recovers the category.
        let (client2b, server2b) = duplex(4096);
        let (mut cr2b, mut cw2b) = split(client2b);
        let srv2b = tokio::spawn(async move {
            let (_sr, mut sw) = edge_until_ack(server2b).await;
            let mut refusal = b"NO".to_vec();
            refusal.push(b"pairing".len() as u8);
            refusal.extend_from_slice(b"pairing");
            sw.write_all(&refusal).await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw2b, &mut cr2b, &request, &holder, None)
            .await
            .expect("a framed NO is a clean outcome, not an error");
        srv2b.await.unwrap();
        match outcome {
            ChannelJoinOutcome::Refused { ref category } => assert_eq!(
                category.as_deref(),
                Some("pairing"),
                "the relay leg surfaces the framed category (#524)"
            ),
            ref other => panic!("must be Refused, got {other:?}"),
        }

        // (3) #21: the bare `EX` park-expiry token on the relay leg classifies as ParkExpired —
        // neither the #148 dropped-leg error nor a Refused.
        let (client3, server3) = duplex(4096);
        let (mut cr3, mut cw3) = split(client3);
        let srv3 = tokio::spawn(async move {
            let (_sr, mut sw) = edge_until_ack(server3).await;
            sw.write_all(b"EX").await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw3, &mut cr3, &request, &holder, None)
            .await
            .expect("the EX token is a clean outcome, not an error");
        srv3.await.unwrap();
        assert!(
            matches!(outcome, ChannelJoinOutcome::ParkExpired),
            "the relay leg's bare EX classifies as ParkExpired (#21), got {outcome:?}"
        );
    }

    // NEW in this port (not from ct-agent): a smoke test for the `test_support::ScriptedBroker`
    // helper the edge contract tests (PR3) and the ct-agent parity test (PR4) will build on.
    // It must play the exchange correctly with AND without the #495 preamble, verify the
    // possession proof under the grant holder, and let the caller script the ack.
    #[tokio::test]
    async fn scripted_broker_plays_the_edge_up_to_the_ack_with_and_without_a_marker() {
        use tokio::io::{duplex, split, AsyncWriteExt};
        for marker in [None, Some(PHASE_MARKER_RELAY)] {
            let channel = [0x5Au8; 32];
            let holder = SigningKey::from_bytes(&[0x4Bu8; 32]);
            let holder_pub = holder.verifying_key().to_bytes();
            let request = ChannelJoinRequest {
                grant: signed_grant(channel, &holder, Direction::Initiate),
                endpoint: "203.0.113.90:9090".to_string(),
            };
            let expected_request = request.encode();

            let (client, server) = duplex(4096);
            let (cr, cw) = split(client);
            let broker = ScriptedBroker::new([0x77u8; 32]);
            let edge = tokio::spawn(async move {
                let mut ex = broker.until_ack(server).await;
                ex.send.write_all(b"OK 198.51.100.90:9091\n").await.unwrap();
                ex.send.flush().await.unwrap();
                (ex.phase_marker, ex.request.clone(), ex.possession_proven_by(&holder_pub))
            });
            let outcome = present_channel_join_on_stream(
                cw, cr, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, marker, false,
            )
            .await
            .expect("join over the scripted broker");
            let (seen_marker, seen_request, proven) = edge.await.expect("edge task");

            assert_eq!(seen_marker, marker, "the broker reports exactly the preamble the client sent");
            assert_eq!(seen_request, expected_request, "the framed request body is handed back intact");
            assert!(proven, "the client's signature verifies under the grant holder");
            match outcome {
                ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                    assert_eq!(peer_endpoint, "198.51.100.90:9091");
                }
                other => panic!("expected Admitted, got {other:?}"),
            }
        }
    }
}
