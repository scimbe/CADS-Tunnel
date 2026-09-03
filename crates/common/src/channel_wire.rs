//! Agent Fabric — agent-side channel-join client (#72 AF4, ADR-0020): the pure
//! byte-protocol layer of the channel join/dial wire protocol.
//!
//! ## Provenance and normative status (Phase 2 of the CADS-Tunnel/ct-agent consolidation)
//!
//! This module is the **normative home** of the channel join wire protocol's client half.
//! Its contents (and those of [`io`] and [`crate::channel_quic`]) are a VERBATIM port of
//! ct-agent `native/src/channel.rs:55-778`, `native/src/transport.rs:52-140` and
//! `native/src/channel_run/session.rs:152-178` @ v0.7.23 — same bodies, same doc comments,
//! same error strings (ct-agent's `channel_run/errors.rs` classifies by string and by
//! `DroppedLegBeforeAck` downcast, so the wording IS part of the contract). Only paths were
//! adjusted (`ct_common::channel::…` → `crate::channel::…`). ct-agent re-exports these
//! names in place of its own bodies (consolidation PR5), so its call sites do not change.
//! Each moved block carries a `// ported verbatim from …` marker naming its origin range.
//!
//! What is deliberately NOT here (stays in ct-agent — policy, environment, tunnel):
//! `phase_marker_enabled(_from)` (the `CT_CHANNEL_PHASE_MARKER` switch), `phase_marker_for`
//! (needs the `:443` TLS stream + `ka_negotiated`), `present_channel_join_marked`,
//! `run_channel_session*`, all of `channel_run/`, the cert-pinned tunnel dialer.
//!
//! Fix history this code carries (the guard tests moved with it, names and issue numbers
//! unchanged): ct-agent#21 (`EX`/park-expiry is neither refusal nor transport error),
//! ct-agent#23 (one ack contract on both legs: cap, empty-after-possession, NULs),
//! ct-agent#28 (grammar-true `OK`-line parse), ct-agent#36 (panic-free hex decode),
//! ct-agent#129 (malformed pre-challenge response is a distinct error), ct-agent#140 (bounded
//! admission exchange), ct-agent#148 (typed `DroppedLegBeforeAck`), CADS-Tunnel#494
//! (newline completes the ack on a held-open `:443` stream), CADS-Tunnel#495 (phase
//! preamble), CADS-Tunnel#500 (leading NUL keepalives), CADS-Tunnel#506 (tick-bounded KA
//! park wait), CADS-Tunnel#524 (length-framed refusal category, 0x0A collision recovery),
//! CADS-Tunnel#557 (park-expiry strings derived from `crate::channel`, not copied).
//!
//! This module is un-gated: it compiles for wasm32 (zero new dependencies — std and
//! `crate::channel` only), so the wasm32 CI job actually compiles the parser the browser
//! member's WebSocket path could adopt later. Everything that needs `tokio::time` lives in
//! [`io`] (native-only); everything that needs `quinn` lives in [`crate::channel_quic`].
//!
//! ---
//!
//! The counterpart to the edge broker's admission gate (`ct_edge::channel_broker`):
//! an agent that holds a `SignedChannelGrant` presents a [`ChannelJoinRequest`] to
//! the edge over QUIC and proves it holds the grant's `holder` private key, then
//! learns its paired peer's advertised endpoint. This module is the wire-protocol
//! client half; dialing the edge endpoint and custody of the channel key are the
//! caller's. (The broker is not yet mounted in the live edge — #81 SEC81c-c — so this
//! drives exactly the protocol the broker's own tests exercise.)
//!
//! ## Ack contract (normative — both ack readers implement THIS, #23)
//!
//! The edge's admission ack is a single line — `OK …` / `NO` / `EX` — terminated by
//! `\n` on stream legs; on QUIC the ack is delimiter-free by design and EOF (quinn's
//! `finish`) terminates it. A reader completes on the FIRST of: a `\n` (consumed,
//! never read past — session bytes may follow on the same stream), EOF, or the
//! [`CHANNEL_ACK_MAX_BYTES`] cap — exceeding the cap without a terminator is a
//! protocol violation and a hard error on both legs. LEADING NULs are the #500 park
//! keepalive and are skipped (no ack byte is 0x00). Classification: a non-empty ack
//! parses via `parse_channel_ack` (`OK…` → `Admitted`, `EX` → `ParkExpired`,
//! anything else → `Refused`). An EMPTY ack AFTER the possession handshake
//! completed is a dropped leg / handoff race ([`DroppedLegBeforeAck`], #148) —
//! retryable, NEVER `Refused`: on every leg a genuine refusal is an explicit `NO`.
//! (Pre-challenge is different: there an empty response stays `Refused`, because
//! over QUIC an explicit `NO` can race the teardown and arrive empty — see the
//! pre-challenge read in [`io::present_channel_join_on_stream`].)
//!
//! ### `OK`-line field grammar (normative — parse by grammar, never by count)
//!
//! ```text
//! OK <endpoint-or-mode> [<peer_noise_hex64> <peer_holder_hex64> <peer_attest_hex128>] [<key>=<value> ...]
//! ```
//!
//! - The `<noise> <holder> <attest>` triple is **optional and all-or-nothing** — present
//!   only when the edge relayed the peer's attested Noise key (#101); absent otherwise
//!   (then "no peer Noise key" is a real registration state, not a parse artifact).
//! - `<key>=<value>` tokens (`r=` reflexive #121, `sp=` same-public-IP #276, and any
//!   FUTURE tag) are **tagged, order-independent, and additively appended** — the line is
//!   deliberately extensible. `parse_channel_ack` therefore takes **bare** tokens as the
//!   positional fields and reads `key=value` tokens **by name**, ignoring unknown ones; it
//!   MUST NOT assume a fixed field count. A consumer that hard-checked the count broke on
//!   the U1 `r=`/`sp=` addition (webconference-demo outage, 2026-08-15); ct-agent#28
//!   hardened this reader to the grammar above. The authoritative producer + the same
//!   grammar live in CADS-Tunnel `channel_broker.rs` (`write_member_ack`) and ADR-0020 §4a.
//!
//! [`ChannelJoinRequest`]: crate::channel::ChannelJoinRequest

/// The stream-generic admission exchange (native-only: needs `tokio::time`).
#[cfg(not(target_arch = "wasm32"))]
pub mod io;

// ported verbatim from ct-agent native/src/channel.rs:53-94 @ v0.7.23
/// Outcome of presenting a channel join to the edge broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelJoinOutcome {
    /// Admitted. `peer_endpoint` is the paired peer's advertised address when the
    /// edge ran a two-party rendezvous, or empty for a single-participant admission.
    /// `peer_noise_pubkey` is the peer's attested Noise key when the edge relayed it
    /// (#72 AF4 / #100) — so an initiator can pin it with no operator-conveyed value.
    Admitted {
        peer_endpoint: String,
        peer_noise_pubkey: Option<[u8; 32]>,
        /// The peer's grant-authenticated holder pubkey, when the edge relayed the
        /// attested-key triple (#101) — the key to verify `peer_attestation` against.
        peer_holder: Option<[u8; 32]>,
        /// The peer's holder-signed attestation over `peer_noise_pubkey` (#101), which
        /// the initiator verifies before pinning the key.
        peer_attestation: Option<[u8; 64]>,
        /// This member's own **reflexive** (post-NAT) address as the edge observed it on
        /// the authenticated join, when the ack carried it (#121 Phase B1 — the AutoNAT
        /// primitive). `None` on an older ack that omits it or on the relay leg (a
        /// relay-only member is behind symmetric NAT, so it has no punchable reflexive).
        /// This is the address the later hole-punch (B2) punches toward and the input to
        /// [`crate::channel::reachability_class`].
        observed_reflexive: Option<std::net::SocketAddr>,
    },
    /// Refused: a bad/expired grant, a non-member holder, an unsafe advertised
    /// endpoint, or a failed possession proof. `category` (CADS-Tunnel#524) is the
    /// edge's refusal category token when the wire carried one — a short
    /// closed-vocabulary ASCII tag (`possession`, `grant-verify`, `not-member`,
    /// `endpoint`, `pairing`, …) naming WHICH class of check refused us, length-framed
    /// after the `NO` sentinel. `None` for an old edge (bare `NO`), a token that raced
    /// the teardown, or a malformed frame — all of which keep today's generic message.
    /// Unknown tokens are surfaced raw (future vocabulary), never dropped.
    Refused { category: Option<String> },
    /// #21: the edge reaped this member's park (no partner arrived within the park TTL)
    /// and SAID SO — the bare `EX` token on a stream leg, or a `park-expired` close reason
    /// on QUIC. Explicitly NOT a refusal and NOT a transport failure: the correct reaction
    /// is to re-park immediately (same transport), not to advance the dial ladder or back
    /// off. Before this variant existed the client read the silent close as a rung failure
    /// — measured live as 271 phantom "rung failures" and a 0–40s first-contact latency
    /// roulette (ct-agent#21).
    ParkExpired,
}

// ported verbatim from ct-agent native/src/channel.rs:140-144 @ v0.7.23
/// One cap, one posture (#23): the bound both ack readers enforce. A well-formed
/// ack line is far below this; reaching it without a terminator is a malformed
/// peer and a hard error on both legs (the readers used to disagree — the
/// rendezvous leg classified whatever arrived, the relay leg errored at 513).
pub const CHANNEL_ACK_MAX_BYTES: usize = 512;

// ported verbatim from ct-agent native/src/channel.rs:146-170 @ v0.7.23
/// #148/#23: a leg closed with ZERO ack bytes AFTER the possession handshake
/// completed — a transport/handoff race (the paired peer's stream died
/// mid-pairing), NOT an authorization refusal: a genuine refusal is always an
/// explicit `NO` (see the module header's ack contract). Typed so retry policies
/// classify it without string-matching; it must never be treated as definitive —
/// before #23 the rendezvous leg fell through to `Refused` here and paid the
/// #231 definitive 30 s backoff for a transport race.
#[derive(Debug)]
pub struct DroppedLegBeforeAck {
    /// Which leg observed it (`"rendezvous"` / `"relay"`), for operator logs.
    pub leg: &'static str,
}

impl std::fmt::Display for DroppedLegBeforeAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} pairing dropped after admission before the edge ack — a transport/handoff race \
             (the peer connection likely died mid-pairing, #148), not an authorization refusal; retry",
            self.leg
        )
    }
}

impl std::error::Error for DroppedLegBeforeAck {}

// ported verbatim from ct-agent native/src/channel.rs:115-128 (doc) + :172-176 @ v0.7.23
// (the doc below sat on ct-agent's `phase_marker_enabled`, which stays in ct-agent as the
// operator switch; the wire facts it states belong to the constant, so they travel with it)
/// #495 slice 2a (v0.4.14): the optional phase preamble a KA-generation client sends
/// before its length-framed join -- [0xFF, phase]. On a `:443` TLS-TCP leg, only ever
/// sent when the TLS negotiation selected a KA id (see ct-agent's `transport::ka_negotiated`): an
/// old edge selected a legacy id and receives byte-identical legacy traffic. On QUIC
/// (CADS-Tunnel#495 U2 (a'), ct-agent's `present_channel_join_marked`) there is no ALPN to gate
/// on at all -- safety instead rests entirely on the length-prefix property below,
/// which holds on every transport equally. The magic 0xFF is unambiguous against the
/// length prefix (it would mean a >=65280-byte join, refused as len-oob by every edge
/// since the field existed).
/// #495 measurement isolation (requested by the tester after the 2a series proved
/// unrunnable with published binaries): `CT_CHANNEL_PHASE_MARKER=off` (or `0`)
/// suppresses the phase preamble on EVERY transport while keeping everything else
/// identical — the only way to vary the marker as a SINGLE variable, since every marked
/// release also carries the #494 ack-reader fix. Default: markers on. (That switch is
/// ct-agent's `phase_marker_enabled`; this crate only defines the bytes.)
pub const PHASE_PREAMBLE_MAGIC: u8 = 0xFF;
/// Phase byte: rendezvous admission (the parked ack-and-close leg).
pub const PHASE_MARKER_RENDEZVOUS: u8 = 0x01;
/// Phase byte: relay leg (ack then spliced session on the same stream).
pub const PHASE_MARKER_RELAY: u8 = 0x02;

// ported verbatim from ct-agent native/src/channel.rs:280-287 @ v0.7.23
/// Length of the edge's possession challenge, and therefore the length that separates
/// "proceed" from "this was a refusal" in the pre-challenge read.
///
/// Named because it is the reason [`REFUSAL_CATEGORY_MAX_LEN`] has the value it has: a
/// refusal frame of exactly this length would be indistinguishable from a challenge. It
/// used to be a bare `32` in three places, which left that dependency unstatable — and so
/// unenforced. See `refusal_frame_can_never_be_mistaken_for_a_possession_challenge`.
pub const POSSESSION_CHALLENGE_LEN: usize = 32;

// ported verbatim from ct-agent native/src/channel.rs:485-517 @ v0.7.23
/// The substring the edge's QUIC park-expiry ApplicationClose reason always carries — the
/// colon-less stem of the prefix the edge writes, so it matches that prefix and any honest
/// human-readable suffix. This is the cross-repo wire contract [`error_names_park_expiry`]
/// classifies on; get it wrong and a benign park reap silently reads as a refusal
/// (rung-ladder advance + refusal backoff instead of re-park).
///
/// **CADS-Tunnel#557: derived, no longer a second copy.** This used to be its own literal,
/// pinned here by one test while the edge pinned its own literal by another. Two tests that
/// each agree with themselves cannot notice the two literals coming apart — a reword on one
/// side updates that side's test and stays green. Both repos now read
/// [`crate::channel::PARK_EXPIRED_REASON_PREFIX`], so a reword arrives here through the
/// shared crate instead of having to be copied by hand.
pub fn quic_park_expired_marker() -> &'static str {
    let prefix = crate::channel::PARK_EXPIRED_REASON_PREFIX;
    prefix.strip_suffix(':').unwrap_or(prefix)
}

/// #21: does this error (anywhere in its source chain) carry the edge's named QUIC park-expiry
/// close reason? The edge reaps an idle QUIC park by closing the connection with the
/// ApplicationClose reason `park-expired: no partner within the park TTL` — quinn flattens that
/// reason into the error `Display` at some nesting depth depending on which read/open call
/// observed the close, so every level of the chain is checked. This is the QUIC analog of the
/// stream leg's bare `EX` token: parsing a wire-carried string, not matching in-process text.
pub fn error_names_park_expiry(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = cur {
        if err.to_string().contains(quic_park_expired_marker()) {
            return true;
        }
        cur = err.source();
    }
    false
}

// ported verbatim from ct-agent native/src/channel.rs:519-538 @ v0.7.23
/// Parse a broker/relay admission ack into a [`ChannelJoinOutcome`]. `ack` is the whole ack
/// text (the relay leg strips its trailing `\n` delimiter first). An `OK`-prefixed ack is
/// `OK[ <endpoint>[ <noise_hex> <holder_hex> <attest_hex>]][ r=<reflexive>]`: the broker
/// appends the peer's attested Noise key, its holder, and the holder-signed attestation
/// (#101) when the registry has them (all-or-nothing), plus (#121 Phase B1) the joining
/// member's OWN edge-observed reflexive address as a tagged `r=<addr>` token. The `r=` token
/// is pulled out first (it is self-addressed, not peer material, and order-independent); a
/// missing field yields `None` — backward-additive. Anything else is a refusal.
/// #524: upper bound on a refusal-category token's length — the edge caps tokens here so
/// the whole `NO | len | token` frame stays strictly under [`POSSESSION_CHALLENGE_LEN`],
/// which this client's pre-challenge read would otherwise mistake for a challenge.
///
/// **Derived, not copied.** This used to be a bare `24` with two claims attached: that the
/// pinned ct-common predated the constant, and that both values were held by tests on both
/// sides. Neither was true any more — the pinned tag carries
/// `CHANNEL_REFUSAL_CATEGORY_MAX_LEN`, and this side had no test naming the value at all.
/// A hand-copied number whose justification has expired is exactly the shape CADS-Tunnel#557
/// removed for the park-expiry strings: two sides that each agree with themselves cannot
/// notice their values coming apart.
pub const REFUSAL_CATEGORY_MAX_LEN: usize = crate::channel::CHANNEL_REFUSAL_CATEGORY_MAX_LEN;

// ported verbatim from ct-agent native/src/channel.rs:545-568 @ v0.7.23
/// #524: is this byte string shaped like a refusal-category token (non-empty, ≤ 24,
/// lowercase ASCII / digits / `-`)? A SHAPE check only — deliberately not a vocabulary
/// check: the vocabulary is closed on the edge (writer) side but open here, so a newer
/// edge's future token still surfaces (raw, with a generic explanation) instead of
/// being dropped.
pub fn is_refusal_token_shape(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= REFUSAL_CATEGORY_MAX_LEN
        && token.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// #524: decode the length-framed category token that follows the `NO` sentinel
/// (`len(u8) | token(ascii)`). `rest` is whatever arrived after the two sentinel
/// bytes. `None` on an old edge (empty), a truncated frame (the token raced the
/// teardown), or malformed bytes — the caller then renders the generic message,
/// exactly as before #524.
pub fn decode_refusal_category(rest: &[u8]) -> Option<String> {
    let (&len, tail) = rest.split_first()?;
    let token = tail.get(..len as usize)?;
    if !is_refusal_token_shape(token) {
        return None;
    }
    Some(String::from_utf8(token.to_vec()).expect("charset-checked ASCII"))
}

// ported verbatim from ct-agent native/src/channel.rs:588-638 @ v0.7.23
pub fn parse_channel_ack(ack: &str) -> ChannelJoinOutcome {
    // #21: the edge's park-expiry token (a reaped park announcing itself) — checked before
    // the OK/Refused fallthrough so it can never be mistaken for a refusal. Wire contract:
    // the bare token, nothing else.
    //
    // CADS-Tunnel#557: this was a bare `"EX"` literal whose only tie to the edge was the
    // comment naming its constant. It now IS that constant, shared through `ct_common`.
    if ack.trim().as_bytes() == crate::channel::PARK_EXPIRED_TOKEN {
        return ChannelJoinOutcome::ParkExpired;
    }
    match ack.strip_prefix("OK") {
        Some(rest) => {
            let mut observed_reflexive = None;
            let mut fields: Vec<&str> = Vec::new();
            for tok in rest.split_whitespace() {
                if let Some(addr) = tok.strip_prefix("r=") {
                    observed_reflexive = addr.parse().ok();
                } else if tok.contains('=') {
                    // Any OTHER tagged `key=value` token (`sp=`, or a future additive
                    // tag) is NOT a positional field. Grammar-true parse per the normative
                    // ack grammar (CADS-Tunnel ADR-0020 4a): bare tokens are positional,
                    // `key=value` tokens are read by name and unknown ones ignored — so
                    // positional decoding stays immune to tag additions/reordering. Before
                    // this, only `r=` was separated and `sp=` leaked into `fields`, harmless
                    // solely by luck (it failed hex-decode / fell off after 4 takes); a
                    // future tag could have misparsed — the exact positional-fragility class
                    // that broke the webconference JS ack parser on the U1 `r=`/`sp=`
                    // addition (2026-08-15 outage).
                } else {
                    fields.push(tok);
                }
            }
            let mut parts = fields.into_iter();
            let peer_endpoint = parts.next().unwrap_or_default().to_string();
            let peer_noise_pubkey = parts.next().and_then(decode_hex_32);
            let peer_holder = parts.next().and_then(decode_hex_32);
            let peer_attestation = parts.next().and_then(decode_hex_64);
            ChannelJoinOutcome::Admitted {
                peer_endpoint,
                peer_noise_pubkey,
                peer_holder,
                peer_attestation,
                observed_reflexive,
            }
        }
        // Anything that is neither `OK…` nor `EX` is a refusal. The category-carrying
        // `NO` frames are intercepted at the byte level BEFORE this string-level parse
        // (#524) — this fallthrough only sees category-less text.
        None => ChannelJoinOutcome::Refused { category: None },
    }
}

// ported verbatim from ct-agent native/src/channel.rs:743-778 @ v0.7.23
/// Decode 64 lowercase-hex chars into 32 bytes (the peer Noise key / holder the
/// broker relays), or `None` if malformed.
///
/// #36: was `s.len()` (byte length, correctly) guarding a **string-slice** index
/// `&s[2*i..2*i+2]` — `str` slicing panics when a byte offset falls inside a multi-byte
/// UTF-8 char rather than on a boundary, and `s.len() == 64` says nothing about where the
/// boundaries are. `U+FFFD` (3 bytes) + 61 ASCII = 64 bytes passes the length guard and
/// then panics on the very first slice. These tokens arrive via
/// `String::from_utf8_lossy` over broker-relayed wire bytes, which is exactly what
/// produces `U+FFFD` from a malformed or malicious peer — under `panic=abort` that is a
/// process DoS. `p2p.rs`'s `relay_node_key_seed` already has the safe shape for the same
/// job: chunk the raw BYTES and `from_utf8` each chunk, so a boundary that splits a
/// multi-byte char fails the chunk's own UTF-8 check instead of ever being sliced.
pub fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Decode 128 lowercase-hex chars into the 64-byte attestation, or `None`. Same fix as
/// [`decode_hex_32`], same reason (#36).
pub fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Test-only helpers shared with DEPENDENT crates' tests (ct-agent's, via the
/// `test-support` feature on its dev-dependency; ct-edge's contract tests in this
/// workspace): the grant/operator fixtures ct-agent's `channel.rs` tests used, plus a
/// scripted stand-in for the broker's admission side over any duplex. Never part of a
/// production build.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use ed25519_dalek::{Signer, SigningKey};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

    use crate::channel::{
        verify_holder_possession, ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant,
    };

    use super::PHASE_PREAMBLE_MAGIC;

    // ported verbatim from ct-agent native/src/channel.rs:838-842, :858-869 @ v0.7.23
    /// Seed of the fixture operator key every [`signed_grant`] is signed under.
    pub const OP_SEED: [u8; 32] = [7u8; 32];

    /// The fixture operator (signs the grants); its public key is what a test edge's
    /// resolver returns as the channel's operator.
    pub fn operator() -> SigningKey {
        SigningKey::from_bytes(&OP_SEED)
    }

    /// A `ReadWrite`, non-delegable grant for `channel` to `holder`, signed by
    /// [`operator`], expiring at unix second 1000.
    pub fn signed_grant(channel: [u8; 32], holder: &SigningKey, dir: Direction) -> SignedChannelGrant {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let signature = operator().sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// Lowercase hex, the encoding the edge's `OK` line uses for the attested-key triple
    /// (`<noise_hex64> <holder_hex64> <attest_hex128>`) — the inverse of
    /// [`super::decode_hex_32`] / [`super::decode_hex_64`], for building ack fixtures.
    pub fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A scripted stand-in for the edge broker's admission side over ANY duplex (no
    /// `ct_edge`, so it can live below the edge in the dependency graph). It plays the
    /// exchange UP TO the ack — reads the (optionally phase-marked, #495) length-framed
    /// join, writes its possession challenge, reads the 64-byte signature — and hands the
    /// stream halves back so the test scripts the ack itself: drop the write half for a
    /// dropped leg (#148), write `NO`/a framed refusal (#524), `EX` (#21), NUL ticks
    /// (#500) or an `OK …` line. Generalised from the `edge_until_ack` helper in ct-agent
    /// `native/src/channel.rs:1995-2011` @ v0.7.23 (which is kept verbatim inside the
    /// #148 test that owns it).
    #[derive(Debug, Clone)]
    pub struct ScriptedBroker {
        /// The 32-byte possession challenge to issue.
        pub challenge: [u8; 32],
    }

    /// What [`ScriptedBroker::until_ack`] observed and the halves it hands back.
    pub struct ScriptedExchange<S> {
        /// The broker-side read half (the client's send direction).
        pub recv: ReadHalf<S>,
        /// The broker-side write half: the test writes the ack here.
        pub send: WriteHalf<S>,
        /// The phase byte of a `[0xFF, phase]` preamble if the client sent one (#495).
        pub phase_marker: Option<u8>,
        /// The raw length-framed join request body (`ChannelJoinRequest::decode`s).
        pub request: Vec<u8>,
        /// The challenge that was issued (copied from the broker).
        pub challenge: [u8; 32],
        /// The client's possession signature over `challenge`.
        pub signature: [u8; 64],
    }

    impl<S> ScriptedExchange<S> {
        /// Whether `signature` is `holder`'s valid ed25519 signature over `challenge` —
        /// the check the real broker makes (`crate::channel::verify_holder_possession`).
        pub fn possession_proven_by(&self, holder: &[u8; 32]) -> bool {
            verify_holder_possession(holder, &self.challenge, &self.signature)
        }
    }

    impl ScriptedBroker {
        /// A broker issuing `challenge`.
        pub fn new(challenge: [u8; 32]) -> Self {
            ScriptedBroker { challenge }
        }

        /// Play the edge side up to (not including) the ack. Panics on a malformed
        /// client (this is a test fixture; a wrong wire shape should fail loudly).
        pub async fn until_ack<S>(&self, server: S) -> ScriptedExchange<S>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            let (mut sr, mut sw) = tokio::io::split(server);
            // The first two bytes are either the `[0xFF, phase]` preamble or the u16-BE
            // length. 0xFF as a length high byte would mean a >= 65280-byte join, which no
            // client ever sends (the wire-safety property PHASE_PREAMBLE_MAGIC rests on).
            let mut head = [0u8; 2];
            sr.read_exact(&mut head).await.expect("join head");
            let (phase_marker, len) = if head[0] == PHASE_PREAMBLE_MAGIC {
                let mut len = [0u8; 2];
                sr.read_exact(&mut len).await.expect("join length after the preamble");
                (Some(head[1]), u16::from_be_bytes(len))
            } else {
                (None, u16::from_be_bytes(head))
            };
            let mut request = vec![0u8; len as usize];
            sr.read_exact(&mut request).await.expect("join request");
            sw.write_all(&self.challenge).await.expect("possession challenge");
            sw.flush().await.expect("flush challenge");
            let mut signature = [0u8; 64];
            sr.read_exact(&mut signature).await.expect("possession signature");
            ScriptedExchange {
                recv: sr,
                send: sw,
                phase_marker,
                request,
                challenge: self.challenge,
                signature,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ported verbatim from ct-agent native/src/channel.rs:787-836 @ v0.7.23
    /// #36: a byte-length-correct but char-boundary-crossing token does not panic.
    ///
    /// `U+FFFD` (3 bytes, the exact replacement character `String::from_utf8_lossy`
    /// produces from malformed wire bytes) + 61 ASCII bytes = 64 bytes: passes the length
    /// guard, and a plain `&s[2*i..2*i+2]` string slice panics on it (byte offset 2 falls
    /// inside the 3-byte char). Under `panic=abort` that is a process DoS reachable from
    /// broker-relayed peer input. The fix decodes bytes, not `str` slices, so a boundary
    /// mismatch fails the chunk's own UTF-8 check and returns `None` instead of panicking.
    #[test]
    fn a_token_with_a_multi_byte_char_at_the_right_byte_length_does_not_panic_36() {
        let replacement = "\u{FFFD}"; // 3 bytes
        let ascii_32 = "a".repeat(61); // 61 bytes: 3 + 61 = 64
        let token_32 = format!("{replacement}{ascii_32}");
        assert_eq!(token_32.len(), 64, "must actually hit the length guard, not undershoot it");
        assert_eq!(
            decode_hex_32(&token_32),
            None,
            "malformed content -- rejected, not panicked"
        );

        let ascii_64 = "a".repeat(125); // 3 + 125 = 128
        let token_64 = format!("{replacement}{ascii_64}");
        assert_eq!(token_64.len(), 128);
        assert_eq!(decode_hex_64(&token_64), None);
    }

    /// #524/#557: a refusal frame must never be as long as a possession challenge.
    ///
    /// This is the invariant the category cap exists for, and until now it was asserted
    /// only in CADS-Tunnel — on the side that WRITES the token. The side that reads it,
    /// and that owns the `take(POSSESSION_CHALLENGE_LEN)` this bound protects, asserted
    /// nothing: the value lived here as a hand-copied `24` with a stale comment claiming
    /// tests on both sides. A cap that only the writer checks is no cap for the reader.
    ///
    /// `<` and not `<=`: a frame of exactly the challenge length would be consumed as a
    /// challenge, which is the failure this bound prevents.
    #[test]
    fn refusal_frame_can_never_be_mistaken_for_a_possession_challenge() {
        // `NO` sentinel + the length byte + the longest token the edge may send.
        let longest_frame = 2 + 1 + REFUSAL_CATEGORY_MAX_LEN;
        assert!(
            longest_frame < POSSESSION_CHALLENGE_LEN,
            "a {longest_frame}-byte refusal frame would be read as a {POSSESSION_CHALLENGE_LEN}-byte challenge"
        );
        // Deliberately NOT asserted here: that the cap equals
        // `ct_common::channel::CHANNEL_REFUSAL_CATEGORY_MAX_LEN`. It is now defined as that
        // constant, so the comparison would be a value against itself — and it would pass
        // just as happily against a re-introduced literal `24`. The derivation is enforced
        // by the definition; a test restating it would only look like protection.
    }

    // ported verbatim from ct-agent native/src/channel.rs:1311-1359 @ v0.7.23
    #[test]
    fn parse_channel_ack_is_grammar_true_and_immune_to_tag_additions() {
        // Positional decoding must be immune to every `key=value` tag (present `r=`/`sp=`
        // and any future one), and `r=` still read by name — the grammar-true invariant that
        // the webconference JS parser lacked when it broke on the U1 `r=`/`sp=` addition.
        let noise = "aa".repeat(32);
        let holder = "bb".repeat(32);
        let attest = "cc".repeat(64);

        // Full ack + r= + sp= + a synthetic FUTURE tag: positional fields unaffected.
        let ack = format!("OK relay-only {noise} {holder} {attest} r=203.0.113.9:41000 sp=1 futuretag=whatever");
        match parse_channel_ack(&ack) {
            ChannelJoinOutcome::Admitted {
                peer_endpoint,
                peer_noise_pubkey,
                peer_holder,
                peer_attestation,
                observed_reflexive,
            } => {
                assert_eq!(peer_endpoint, "relay-only");
                assert_eq!(peer_noise_pubkey, decode_hex_32(&noise));
                assert_eq!(peer_holder, decode_hex_32(&holder));
                assert_eq!(peer_attestation, decode_hex_64(&attest));
                assert_eq!(observed_reflexive, Some("203.0.113.9:41000".parse().unwrap()));
            }
            other => panic!("expected Admitted, got {other:?}"),
        }

        // Tags interleaved BEFORE positional fields must not shift positions (true grammar
        // parse, not "tags happen to be last").
        let reordered = format!("OK sp=1 relay-only {noise} r=203.0.113.9:41000 {holder} {attest}");
        match parse_channel_ack(&reordered) {
            ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, observed_reflexive, .. } => {
                assert_eq!(peer_endpoint, "relay-only");
                assert_eq!(peer_noise_pubkey, decode_hex_32(&noise));
                assert_eq!(observed_reflexive, Some("203.0.113.9:41000".parse().unwrap()));
            }
            other => panic!("expected Admitted, got {other:?}"),
        }

        // No triple (registry lacks the peer's noise key): endpoint only, genuinely no key.
        match parse_channel_ack("OK relay-only r=0.0.0.0:0 sp=1") {
            ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, .. } => {
                assert_eq!(peer_endpoint, "relay-only");
                assert_eq!(peer_noise_pubkey, None, "no triple -> genuinely no peer noise key, not a parse artifact");
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
    }

    // ported verbatim from ct-agent native/src/channel.rs:1553-1600 @ v0.7.23
    /// CADS-Tunnel#557: the marker is DERIVED from the shared prefix, not copied beside it.
    ///
    /// This replaced an arrangement where this repo held its own literal and pinned it with
    /// its own test while the edge did the same on its side — two tests that each agreed
    /// with themselves and could not notice the two literals coming apart. A reword on the
    /// edge now arrives here through `ct_common`, so the only thing left to check is that
    /// the derivation itself stays sane.
    #[test]
    fn the_park_expiry_marker_is_derived_from_the_shared_prefix_557() {
        let prefix = crate::channel::PARK_EXPIRED_REASON_PREFIX;
        let marker = quic_park_expired_marker();

        assert!(!marker.is_empty(), "an empty marker would match EVERY error, not just park expiries");
        assert!(
            prefix.starts_with(marker),
            "the marker must be the stem of the shared prefix: {marker:?} vs {prefix:?}"
        );
        assert!(
            !marker.ends_with(':'),
            "the colon is stripped on purpose -- a close reason is the prefix PLUS a suffix, so \
             matching the colon-terminated form would fail on the very reasons this must catch"
        );

        // The round trip that actually matters: a reason built the way the edge builds it.
        let real_reason = format!("{prefix} no partner within the park TTL");
        assert!(real_reason.contains(marker), "must match a real edge close reason");
    }

    #[test]
    fn error_names_park_expiry_walks_the_source_chain_21() {
        // #21 QUIC half: quinn buries the ApplicationClose reason at a nesting depth that
        // depends on which call observed the close — the classifier must find the wire token
        // at any level of the source chain, and must not fire on unrelated errors.
        // CADS-Tunnel#526 cross-repo contract: the marker must be a substring of the edge's
        // ACTUAL close reasons, so this pins our stem against a copy of what the edge emits.
        assert!(
            "park-expired: no partner within the park TTL".contains(quic_park_expired_marker())
                && "park-expired: superseded by a newer join from the same holder".contains(quic_park_expired_marker()),
            "the client marker must match every edge QUIC park-expiry reason"
        );
        let inner = std::io::Error::other("connection lost: closed by peer: 0: park-expired: no partner within the park TTL");
        let outer = std::io::Error::other(inner);
        assert!(error_names_park_expiry(&outer), "the nested close reason is recognized");
        let direct = std::io::Error::other("park-expired: no partner within the park TTL");
        assert!(error_names_park_expiry(&direct), "the top-level reason is recognized");
        let unrelated = std::io::Error::other("connection reset by peer");
        assert!(!error_names_park_expiry(&unrelated), "an unrelated error never classifies as park expiry");
    }
}
