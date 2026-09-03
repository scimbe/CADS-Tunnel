# ADR-0020 — Agent Fabric: direct agent-to-agent channels with trust chains

## Status
Accepted (implemented; amended 2026-09-03). *The status change is proposed by the
2026-09-03 amendment at the end of this file and is for the operator to confirm — until then
this line read "Proposed (planning)".* First sub-packet of the agent-to-agent networking feature
(issue #72). Builds the transport on ADR-0015 (P2P mesh with rendezvous) and the
payload-blind relay of ADR-0010; deliberately distinct from the existing
tunnel-**sharing** grants (`/portal/tunnels/{id}/grants`). No code lands with this
ADR — it fixes the addressing and trust model **before** any implementation, per
the issue's explicit sequencing.

## Context

A user asked for **direct agent-to-agent communication**: tunnels that address one
another and exchange data **directly**, with the central plane used only as a
fallback when a direct path can't be established — organised by explicit trust
chains and data-exchange rules, **including across user boundaries** (an agent of
user A connects to a "channel" that user B operates).

What exists today does **not** cover this:

- **Tunnel "sharing" is not agent-to-agent.** `/portal/tunnels/{id}/grants`
  (`crates/control-plane/src/portal_api.rs`) is *subject-scoped owner sharing of the
  same tunnel*: a grantee gets read-sight + install right for the **same** tunnel
  and, crucially, the **same `tunnel.routing_token`** as the owner
  (`routing_token_if_authorized`). That is a redundancy/HA primitive ("another
  agent can serve this one tunnel"), not "two different tunnels can talk". There is
  no role/scope separation — whoever holds the token has full access to both ends.
- **Direct-path infra is client↔one-agent only** (true when this ADR was written;
  the specific mechanism named below has since been removed — see the note after
  this bullet). `CT_AGENT_DIRECT_ADVERTISE` (`crates/agent/src/config.rs`,
  `direct_advertise_ip`) + edge rendezvous (`crates/edge/src/rendezvous.rs`:
  `resolve_rendezvous[_gated]`) + the client's direct-then-relay dial
  (`crates/client/src/transport.rs`) let a **client** learn one agent's advertised
  endpoint, connect directly, and fall back to edge relay. There was no
  agent↔agent route anywhere in `crates/` at the time (verified then).

  **2026-08-18 note:** `crates/edge/src/rendezvous.rs` and
  `crates/client/src/rendezvous.rs` were removed as structurally unreachable dead
  code (#580) — superseded pre-dating this ADR by the inline PoW-gated dial in
  `serve.rs`'s `'C'` role handling / `client_tunnel_noise[_tcp]`, which this
  bullet's own `crates/client/src/transport.rs` citation already pointed at.
  `crates/agent` no longer exists in this workspace either: ct-agent was
  extracted to its own repository, and the direct-path capability this bullet
  describes now lives there, in a materially more capable form (DCUtR + reflexive
  address discovery, `ct-agent/native/src/channel_run/connectivity.rs`) than the
  static `CT_AGENT_DIRECT_ADVERTISE` this bullet names. The Agent Fabric this ADR
  proposed was built; its channel-plane rendezvous (`channel_broker.rs`,
  `relay_gate.rs`) is an independent implementation, not a caller of the removed
  functions.
- **The token/identity model is flat.** `RoutingToken` and `Capability`
  (`crates/common/src/lib.rs`) are flat bearer values: possession = full access,
  no direction, no rights, no expiry, no notion of "which agent may address which".
- **Noise is structurally two-party.** `Noise_IK_25519_ChaChaPoly_BLAKE2s`
  (`crates/common/src/noise.rs`) pins one Origin identity a client authenticates —
  no third party, no group session.

**Terminology caveat.** "Mesh Plane" (ADR-0010), "Noise Mesh Handshake" (ADR-0013),
"P2P Mesh with Rendezvous" (ADR-0015) all denote the authenticated **client↔origin
data plane** (as opposed to the SNI-passthrough Browser Plane) — *not* a network of
interconnected agents. To avoid overloading "Mesh", this feature is named the
**Agent Fabric**, and its unit of connectivity is a **Channel**.

## Decision

Introduce an **Agent Fabric** layered on the existing rendezvous transport, with a
new addressing-and-trust model that is explicitly separate from flat routing tokens.

### 1. Channels as the addressing primitive
A **Channel** is a named agent-to-agent rendezvous point that **one agent operates**
(the *channel operator*) and other agents may **join** (the *members*). A channel is
addressed by an opaque **`ChannelId`** (a `[u8; 32]`, like `RoutingToken` — no
hostname, operator-blind), decoupling "who I want to talk to" from any network
address. An agent reaches a peer by naming a channel, never an IP.

### 2. Trust chains as *scoped, expiring, directional* grants
Replace flat bearer access, for the fabric only, with a **`ChannelGrant`**: an
authorization minted by a channel operator for a member, carrying — at minimum —
`channel` (which `ChannelId`), `direction` (`initiate` | `accept` | `both`),
`rights` (e.g. `read` | `write` | `read-write`), a `subject`/holder binding, and an
`expiry`. A *trust chain* is the verifiable path operator → grant → member; a member
may only re-delegate if its grant says so (a `delegable` right), which is how chains
extend without becoming flat bearer tokens. Enforcement lives at the edge (rendezvous
gate) and at each agent (accept/deny by grant), never "possession = full access".

### 3. Cross-user connection is an explicit invitation, not a shared token
For user A's agent to join a channel user B operates, B's operator issues an
**invitation** (a one-time, scoped `ChannelGrant` template) that A redeems through
the control plane to obtain its own member grant. This is *analogous to but
fundamentally different from* tunnel sharing: sharing hands over the **same** token
(same tunnel, full access); an invitation mints a **new, scoped, revocable** grant
into a **different** agent's channel. Failed/expired/revoked trust yields a clean
deny (edge refuses the rendezvous; the peer agent refuses the session) with no
partial access.

### 4. Transport: direct-first, relay-fallback, payload-blind — reuse ADR-0015
Two agents establish connectivity exactly as client↔agent does today: the edge acts
as a **rendezvous/NAT-punch broker** between the two advertised endpoints
(generalising `resolve_rendezvous`), the two agents run a **two-party Noise session**
between themselves (so `Noise_IK` still fits — one initiator, one responder per
channel connection), and the edge **relays only as a fallback**, seeing ciphertext
only (unchanged payload-blindness). A channel is therefore a **hub of pairwise
agent↔agent Noise sessions**, *not* a multi-party group session — which sidesteps the
two-party Noise constraint honestly instead of inventing group crypto.

### 4a. Edge-side pairer topology & transport unification (issue #495)
The edge correlates the two members of a channel connection **per transport**, in
separate pairer instances (`crates/edge/src/channel_broker.rs`, `serve.rs`):

- the `:443` **front-door** broker and the **WebSocket** listener share **one**
  `SharedChannelPairer` (deliberate cross-transport pairing; its member payload is
  `AdmittedStreamMember<BoxedChannelStream>` — ack and relayed session on the same duplex);
- the **QUIC relay** endpoint (`:4436`) and the **QUIC rendezvous** endpoint (`:4435`)
  each have their **own** `SharedQuicChannelPairer` (member payload `AdmittedMember`).

Two members pair **only within one pairer instance**. The consequence — and the origin
of #495 — is that **mixed-transport pairs never meet**: if member A's UDP is blocked (its
ladder falls back to `:443`) while member B's UDP works (its ladder picks a QUIC
endpoint), A parks in the front-door pairer and B in a QUIC pairer, neither finds a
partner, both are reaped at `CHANNEL_PARK_TTL_SECS`, and both sides see a ~30–40 s
"refused" that is really a park-TTL reap. **Operational guidance today:** set
`CT_CHANNEL_FRONT_DOOR_ONLY=1` on **both** members so they deterministically park in the
same (`:443`) pairer.

**Transport unification (#495), in progress, flag-gated `CT_EDGE_UNIFIED_PAIRER`:**
- **U1 (landed):** ack-format unification — stream acks carry `r=`/`sp=` like the QUIC
  completers; and a `SessionSource` abstraction (`SameStream` for `:443`/WS,
  `EndpointSwap` for QUIC rendezvous) so a pair with any EndpointSwap side completes
  ack-then-close.

**Member-ack wire grammar (normative — `write_member_ack`/`member_ack_suffix`).** The ack
a joining member reads before its session is a single `\n`-terminated, space-separated line:

```
OK <endpoint-or-mode> [<peer_noise_hex64> <peer_holder_hex64> <peer_attest_hex128>] r=<reflexive> sp=<0|1>
```

- The `<peer_noise> <peer_holder> <peer_attest>` triple is **optional and all-or-nothing** —
  present only when the registry holds the peer's attested Noise key (#101); absent otherwise
  (then "no peer Noise key" is a real registration state, not a parse failure).
- `r=` (own edge-observed reflexive, #121) and `sp=` (same-public-IP fact, #276) are **tagged,
  order-independent, and appended** — the line is deliberately **additively extensible**. A
  conformant parser reads positional fields up to the optional triple, then reads any trailing
  `key=value` tokens **by name** and ignores unknown ones. It must **never** assert a fixed
  field count: a consumer that hard-checked `length == 5` broke on the U1 `r=`/`sp=` addition
  (webconference-demo outage, 2026-08-15) although every tag-based parser (ct-agent ≥ v0.4.13)
  was unaffected. Anything not beginning `OK ` is a refusal.
- **U2 (next, relay-first — decided 2026-08-15):** unify the **QUIC relay** endpoint
  (`:4436`) into the shared pairer. Chosen over rendezvous-first because cross-transport
  completion is then unambiguous — the edge **relays** between the `:443` stream and the
  QUIC relay connection (its session bi-stream wrapped as a `BoxedChannelStream`), with no
  "how does the `:443` side connect directly?" gap. The **rendezvous** endpoint (`:4435`)
  stays separate: a successful direct rendezvous needs both sides UDP-capable by
  definition, so there is nothing to gain from mixing it into the relay pool.

Until U2+ ship and the flag is enabled, the `FRONT_DOOR_ONLY` guidance above stays
required. See issue #495 for the slice-by-slice plan.

### Key custody (decided 2026-07-17)
The channel operator's grant-signing key is **agent-held**, not control-plane-held.
The operator *agent* generates and holds its channel keypair and signs member
[`ChannelGrant`]s itself; the control-plane channel registry stores only the
operator **public** key + membership/invitations (it never holds a channel signing
key). This keeps the fabric's trust layer consistent with the provider-blind, thin
control plane (ADR-0017) — the operator is the sole authority over who may join its
channel. Trade-off accepted: the operator agent must be reachable to mint grants and
honour invitations (the cross-user flow, AF3, brokers the invitation through the
control plane but the resulting member grant is still agent-signed).

## Consequences

New building blocks the later sub-packets must add (none exist yet):
- `ChannelId` + `ChannelGrant` types in `ct-common` (structured, signed, expiring —
  the antithesis of the flat `RoutingToken`).
- A control-plane **channel registry + membership/invitation** store and API
  (mint channel, issue invitation, redeem → member grant, revoke).
- An **edge agent↔agent rendezvous route** (generalise `rendezvous.rs` to broker two
  agents, gated by a valid `ChannelGrant`).
- An **agent dial-out + accept role** (an agent both serves its origin and joins/
  operates channels), advertising its direct endpoint via the existing
  `CT_AGENT_DIRECT_ADVERTISE` path.

Relationship to existing features: the Agent Fabric is **complementary** to tunnel
sharing (HA redundancy) — sharing stays as-is; the fabric is a new, orthogonal
capability. Provider-blindness is preserved end to end (operator sees opaque
`ChannelId`s and relays ciphertext; grants authorise without revealing payload).

### Alternatives considered
- **Extend the flat `RoutingToken` with a role field** — rejected: bolting scope
  onto a bearer token that already means "full access" invites confused-deputy bugs;
  a distinct `ChannelGrant` keeps the two models cleanly separated.
- **Group/multi-party Noise session per channel** — rejected: `Noise_IK` is
  two-party; multi-party secure group messaging (MLS-style) is a research-grade
  dependency far out of scope. Pairwise sessions under a channel hub give the same
  user-visible behaviour without it.
- **Adopt libp2p / a full P2P stack** — rejected: heavy dependency surface and its
  own addressing/identity assumptions conflict with the provider-blind, opaque-token
  design; the existing rendezvous primitive already does the hard NAT-punch part.

## Decomposition (issue #72)
1. **This ADR** — addressing + trust model (design, no code). ← landed
2. **Same-user minimal prototype** — two agents of one user establish a direct
   channel via the existing rendezvous (edge as broker only, no payload relay);
   feasibility proof on the NAT-punch base, with a real two-agent integration test.
3. **Cross-user invitation model** — operator issues an invitation, another user's
   agent redeems it into a scoped member grant; trust-fail rules enforced.
4. **Fallback + hardening** — edge relay fallback when direct setup fails, with a
   fallback-path integration test, plus revoke/expiry enforcement tests.

`fix-ready` only when the whole acceptance (real direct agent-to-agent data exchange
with trust chains and a tested fallback) is met.

## Amendment (2026-09-03): one normative implementation of the join wire protocol

Records a decision taken by the operator on 2026-09-02 and implemented in CADS-Tunnel
#748 / #751 / #752 / #755 / #756 (tag `v0.4.19`); the ct-agent half of the same plan
(ct-agent #153/#154, see below) landed the same day. Amends §4/§4a; nothing above is withdrawn.

### Decision

The **client half** of the channel join wire protocol — §4a's member-ack grammar, the
possession handshake, both leg variants, the QUIC dial — has exactly **one normative
implementation**, in `ct-common`:

- `ct_common::channel_wire` — the pure byte layer: `ChannelJoinOutcome`,
  `DroppedLegBeforeAck`, `parse_channel_ack`, refusal-category and hex decoders, park-expiry
  classification, the phase-preamble constants. Un-gated, wasm32-portable, no I/O.
- `ct_common::channel_wire::io` — the stream-generic admission exchange over any duplex
  (`present_channel_join_on_stream`, `present_channel_relay_join_on_stream`,
  `ADMISSION_EXCHANGE_TIMEOUT`, `KA_PARK_INACTIVITY_BOUND`). Native-only.
- `ct_common::channel_quic` — the accept-any-cert `quinn` dialer, the QUIC join wrappers,
  `open_channel_streams`. Native-only.

All three are a **verbatim** port of ct-agent `native/src/channel.rs:55-778`,
`transport.rs:52-140` and `channel_run/session.rs:152-178` @ v0.7.23 — same bodies, doc
comments and error strings (ct-agent's `channel_run/errors.rs` classifies by string and by
downcast, so the wording is contract); every block carries a `// ported verbatim from …`
marker. ct-agent re-exports these names in place of its own bodies (ct-agent #154), so
no call site there changes; what stays in ct-agent is policy and environment
(`CT_CHANNEL_PHASE_MARKER`, `phase_marker_for`, `run_channel_session*`, all of `channel_run/`,
the cert-pinned tunnel dialer). The control plane's `ct_common::channel_dial` (#756) is a thin
**policy layer** over the same modules — the two-hop sequence and its budgets, `DialError`,
one adapter, the ct-agent#101 trust gate — and no longer implements the protocol.

### Why

The Agent-bridges dialer (#737) was written as a "faithful port" of ct-agent's exchange with
one deliberate omission, the relay leg. That omission *was* #745: the dialer did the
rendezvous hop on `:4435` (contract: ack, then close), `finish()`ed the admission stream and
ran Noise on it → `closed stream`, while the relay-only acceptor parked on `:4436` reaped with
"park expired with no partner (#21)" on every call. A second copy that agrees with itself
drifts unnoticed — #756's diff shows it already had, in the reflexive `r=` handling and the
post-possession refusal category. One implementation consumed by both binaries is the only
arrangement in which the fix history below stays fixed.

### Invariants carried over, and where they are guarded now

- **In `ct-common`** (moved with the code, names and issue numbers unchanged: 20 ct-agent
  tests + 1 smoke test, #751): ct-agent#21 (`EX`/park expiry is neither refusal nor transport
  error), #23 (one ack contract on both legs: cap, empty-after-possession, NULs), #28
  (grammar-true `OK` parse, never by field count), #36 (panic-free hex), #129 (malformed
  pre-challenge response is a distinct error), #140 (bounded exchange), #148 (typed
  `DroppedLegBeforeAck`); CADS-Tunnel#494 (`\n` completes the ack on a held-open `:443`
  stream), #495 (phase preamble), #500 (leading NUL keepalives), #506 (tick-bounded KA park
  wait), #524 (length-framed refusal category, 0x0A collision), #557 (park-expiry strings
  derived from `crate::channel`, never copied).
- **Against the real edge** — seven `_p2` contract tests in `crates/edge/src/channel_broker.rs`
  (#752; the cycle-free home, since `ct-common` cannot dev-depend on `ct-edge`): possession +
  framed refusal, rendezvous endpoint exchange with exact `r=` and marker toleration, attested
  Noise triple verified under the peer holder (#101/#122), QUIC relay via
  `open_channel_streams` (#139), the `:443` same-stream relay contract (#106/#148),
  post-possession `pairing` refusal (#524/#23), QUIC park-expiry close → `ParkExpired`.
- **Build-time gates:** CI compiles `ct-common` for `wasm32-unknown-unknown` (#748), so the
  un-gated parser is actually built for the browser member. ct-agent #153 added a lockfile guard
  ("exactly one `ct-common` in `Cargo.lock`") and a **parity test** — old body vs re-export
  over the same scripted broker: byte-identical client writes, identical outcome or identical
  `Err` `Display` + downcast. That test could only exist between #153 and #154, which is why the
  pin bump and the deletion are separate PRs.

### Two protocol facts the consolidation surfaced

1. **The QUIC relay leg (`:4436`) is not the `:443` relay leg.** On `:443`/WS the relay join is
   `present_channel_relay_join_on_stream`: the send half stays open, the ack is read only up to
   `\n`, and the session runs on the **same** stream (§4a's `SameStream`). On `:4436` a member
   does what it does on `:4435` — a **throwaway** admission bi-stream (`[0xFF, 0x02]` preamble,
   `finish()` after the signature, EOF-terminated ack) — and then opens the session on the
   **next** `open_bi()`; the edge splices the initiator's next bi-stream to the acceptor
   (`relay::relay_initiator_to_acceptor`, `RELAY_SETUP_TIMEOUT` per side). #745's first fix
   sketch assumed the `:443` shape; #749, `channel_dial` and the `_p2` tests pin the correct one.
2. **A QUIC post-admission refusal must be held until delivered (#753, fixed #755).**
   `finish_quic_pair_inner`'s Err arm wrote the framed `pairing` refusal (#524), `finish()`ed
   and returned — dropping the last `quinn::Connection` handles; quinn sends nothing after an
   implicit close, so the member saw a zero-byte close and, correctly per #23/#148, treated a
   definitive refusal as a retryable dropped leg. The edge now holds both connections
   (`conn.closed()`, bounded 2 s) as the admission-refusal path already did (#129-follow); the
   `_p2` test committed `#[ignore]` in #752 is un-ignored as the regression guard.

### Versioning

CADS-Tunnel tags are the API contract for ct-agent. ct-agent pins **five** crates —
`ct-common`, `ct-control-plane`, `ct-dns`, `ct-edge`, `ct-client` — at one tag and bumps them
**together**: a mixed set resolves two `ct-common` packages (types stop unifying in the
`ct_edge`-driven tests, loud; two copies in the production binary via `ct-control-plane`,
silent). `v0.4.19` (annotated, `ce2979c`, 2026-09-03) is the first tag carrying the shared
modules; it also contains #745 (#749), #747 (#750), #753 (#755) and #756. Tagging is manual —
there is no release workflow.

### Consequences and open items

- **#754** — the `:443`/WS stream-pairing refusal (`finish_stream_pair_inner` Err arm) may be
  lost to the TLS `close_notify` RST race that #511's `graceful_close` guards on the Ok path.
  Not reproduced; contract test first, then decide.
- **ct-agent #153** (pins → `v0.4.19`, lockfile guard, parity test) and **#154** (re-exports,
  deletion of the moved bodies and duplex tests, `channel.rs`'s header pointing at `ct-common`
  as normative) landed on 2026-09-03 and ship as ct-agent 0.7.24. Between them the bodies
  existed twice, deliberately, with the parity test as the bridge; it was retired with #154.
- Any future change to the exchange lands in `ct-common` first, with its guard test, and
  reaches ct-agent through a tag bump — never as a patch on top of a re-export.
