# 0023. Video-conferencing multicast/room fan-out: full mesh over pairwise channels, not a server-side SFU

## Status

Accepted

## Context

The video-conferencing feature (`ct-agent-wasm`'s channel-join/Noise_IK/WebRTC-signaling
primitives, the edge's `ws_channel.rs` browser listener, cross-transport pairing with the
`:443`/QUIC brokers — see ADR-0020 for the underlying Agent-Fabric channel model) is proven
end to end for **two-party** calls: real OIDC-registered channel, real Noise_IK handshake,
two real browser tabs reaching `RTCPeerConnection` state `connected`
([scimbe/CADS-webconference-demo](https://github.com/scimbe/CADS-webconference-demo)).

The natural next question is a **room** — more than two participants in one call. The
obvious server-side answer, an SFU (Selective Forwarding Unit: every participant sends one
encrypted stream to a server, which decrypts, inspects, and re-encrypts/forwards it to
every other participant), is how most production video-conferencing systems scale past a
handful of participants. It is also **directly incompatible with this project's core
design constraint**: the edge is payload-blind by construction (ADR-0020's whole channel
broker only ever relays opaque Noise ciphertext bytes; `ct-edge` never holds a session key).
An SFU needs to see and route individual RTP streams — it cannot do that job without
becoming a party to the encrypted session, which is exactly the trust boundary this
project's threat model draws the line at.

## Decision

**Rooms are full mesh, not an SFU.** An N-participant room is `C(N,2)` independent
**pairwise** Agent-Fabric channels — each pair derives its own `channel_id_for_link`
(already order-independent and collision-resistant per-pair, ADR-0020), runs its own
independent Noise_IK handshake, and negotiates its own independent `RTCPeerConnection` with
the other member of that pair. No new core primitive is needed for this: the existing
`ChannelPairer`/`SharedChannelPairer` in `channel_broker.rs` is already keyed by
`ChannelId` and already supports arbitrarily many *concurrent, independent* pairwise
channels through **one shared pairer instance** — a room's `C(N,2)` channels pairing
concurrently is not a new code path, just N times as many callers of the same one.
[`boxed_channel_stream_multiple_concurrent_channels_pair_independently_without_cross_talk`](../../crates/edge/src/channel_broker.rs)
verifies this concretely: several pairwise channels (mixed concrete stream types, i.e. a mix
of transports, exactly as a real room mixing a browser participant with a native `:443`
participant would) pairing and relaying **concurrently** through one `SharedChannelPairer`,
with each pair correctly isolated from every other pair's traffic.

What a room *does* need, and does not have yet, is entirely client-side (browser)
orchestration: a participant joining a room of N-1 others opens N-1 WebSocket connections
(one per pairwise channel), runs N-1 concurrent Noise sessions, and manages N-1 concurrent
`RTCPeerConnection`s with N-1 sets of local media tracks attached to each. That belongs in
[scimbe/CADS-webconference-demo](https://github.com/scimbe/CADS-webconference-demo) (the
demo application, not core platform code — see that repo's README "Provenance" section and
CADS-Tunnel's own extraction commit), not in this repository.

## Consequences

- **Confidentiality is preserved uniformly**: every leg of a room call is genuinely
  end-to-end encrypted between exactly two holders; the edge relays ciphertext for a room
  exactly as it does for a two-party call. No new trust boundary, no new code path in
  `ct_edge`/`ct_common` at all.
- **Bandwidth/CPU scale O(N²), not O(N)** — full mesh's well-known cost. This is an
  accepted, deliberate tradeoff for small rooms (a handful of participants; the typical
  target for this kind of self-hosted, zero-knowledge tunnel is closer to a team call than
  a webinar), not a limitation anyone should try to "fix" with a server-side relay without
  first revisiting the payload-blind constraint this ADR is built on. If a genuinely
  large-room use case emerges, the honest options are (a) a dedicated, explicitly
  trusted (not payload-blind) SFU service outside the edge's trust boundary, clearly
  labeled as such, or (b) a peer-relay topology (one participant's browser forwards
  ciphertext to others it can reach, still never decrypting anyone else's leg) — neither is
  in scope now.
- **No further core (`ct-edge`/`ct_common`) changes are required** to support a room
  feature at the demo layer; the multi-channel concurrency this needs was already
  exercised (single specific verification of the general property added by this ADR)
  rather than newly built. (`ct-agent-wasm` itself has since moved to
  [scimbe/ct-agent](https://github.com/scimbe/ct-agent)'s `wasm/` — it's `ct-agent` for
  the browser, not CADS-Tunnel platform code; see that repo's workspace restructure.)
