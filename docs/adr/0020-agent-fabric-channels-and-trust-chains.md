# ADR-0020 — Agent Fabric: direct agent-to-agent channels with trust chains

## Status
Proposed (planning). First sub-packet of the agent-to-agent networking feature
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
