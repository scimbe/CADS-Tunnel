# ADR-0021 — Multi-edge mesh relay, and federation across independent core systems

## Status
Proposed (planning + first implementation slice). Fills a gap this repo already
referenced but never wrote down: `crates/control-plane/src/edge_mesh.rs`'s module
doc has called itself "ADR-0021" since it was written, without this file existing.
Builds on ADR-0006 (single-region Edge with a first-class Tunnel Registry, which
explicitly deferred this) and reuses ADR-0020's Agent-Fabric trust-chain model
for the federation question in Part 2.

## Part 1 — Multi-edge mesh relay (one control plane, N edges)

### Context

`SqliteEdgeMesh` already exists and does real work today even with exactly one
edge: it durably records which edge owns which (routing token, hostname) pair,
survives an edge restart (an edge replays its own ownership rows from
`GET /internal/edges/rehydrate/:edge_id` on boot — this fixed a real production
outage, #214), and round-robins new tunnel assignment across every edge that
heartbeated recently (`assign_edge`, least-loaded by ownership-row count).

What is **not** built: when a Client's connection lands on edge A but the
hostname it wants is owned by edge B, A has no way to reach it. Today that's
invisible because there is exactly one edge. It stops being invisible the
moment a second edge is added for real capacity (not just registry-readiness)
— which is precisely the "scaling to more than one \[edge in the] core system"
work this session was asked to finish.

### Decision

Add an edge-to-edge relay leg, reusing primitives that already exist rather
than inventing new transport:

1. **Discovery**: on a local miss (`route_host`/`route` returns `None`), the
   accepting edge calls the control plane's `GET /internal/edges/lookup`
   (already implemented) for the hostname/token. A hit returns the owning
   edge's `(id, peer_addr)`.
2. **Relay transport**: dial the owning edge's `peer_addr` over the **same**
   TLS-over-TCP mechanism already used for the Client TCP-fallback path
   (`crates/edge/src/transport.rs::tcp_tls_connect`), trusting the same internal
   Mesh-Plane CA root every edge already publishes and Agents already trust
   (`crates/edge/src/pki.rs`) — no new PKI machinery. Reuses
   `crates/edge/src/relay.rs::relay` for the actual byte-pump once connected —
   the same opaque, provider-blind relay the Client↔Agent leg already uses.
3. **Framing**: a minimal new role byte (`'M'` for mesh-relay) carrying a shared
   admin-token authenticator + the hostname, mirroring the existing
   `'A'`/`'B'`/`'C'` role-byte protocol in
   `crates/edge/src/serve.rs::serve_tcp_connection` — deliberately the same shape,
   not a new protocol design.
4. **Trust boundary**: this is a new **edge-to-edge** trust relationship distinct
   from Client↔Edge or Agent↔Edge. Authorization is the shared `CT_EDGE_ADMIN_TOKEN`
   every edge already holds (the same secret the control plane uses to push
   `authorize-host`) presented inside the `'M'` frame and checked via the one
   existing constant-time `admin_revoke_ok` comparison — not a distinct PKI
   identity, since the token already scopes "is a trusted peer in this
   deployment" exactly as strictly as a dedicated leaf cert would, with zero
   new PKI surface. The receiving edge additionally requires its OWN local
   `route_host` to resolve `host` before relaying anything — a peer edge cannot
   use this to reach a hostname the receiving edge doesn't already own itself. A
   peer edge cannot be used to enumerate hostnames it wasn't specifically told
   to look for.

### Consequences

- Deliberately **not** attempted with mocks only. Per the existing module doc's
  own bar: tested against two real edge processes on a real (loopback is
  enough) network, hermetically, before this is called done.
- No production topology change ships with this ADR. A second edge is only
  worth deploying once real capacity requires it; until then this is
  dead-but-tested code, same posture as the registry itself today.
- `assign_edge`'s round-robin already works today with zero code changes once
  a second edge starts heartbeating — this ADR only adds the relay leg for the
  cache-miss case.

## Part 2 — Federation across independent core systems

### The question

A maintainer asked: instead of scaling by replicating the *whole* stack
(control-plane + edge) per region and inventing a cross-region control-plane
sync/consensus protocol, should independent **core systems** (each its own
control-plane + edge, potentially on different infrastructure/providers)
connect to each other through a **bridge built on the tunnel system itself**,
and distribute load over that?

### Analysis

This is a materially different question from Part 1. Part 1 is N edges
sharing **one** control-plane's database — a scale-out of the data plane
under one operator's authority. Federation is N **independently operated**
control-planes, each with its own tenants, its own database, its own
zero-knowledge boundary (ADR-0002) — no shared source of truth is available
or desirable.

The proposed mechanism — reuse the Agent-Fabric channel/trust-chain machinery
(ADR-0020) to let core systems address each other, rather than a bespoke
cross-region sync protocol — is the right instinct, for a concrete reason:
**a core system, from another core system's point of view, is structurally
identical to what an Agent already is to an Edge**: an entity that authenticates
with a scoped credential, advertises what it serves, and either gets relayed
through or (when reachable) connects directly. ADR-0020 already had to solve
"two independent trust domains that must address each other, across user
boundaries, with the control plane as fallback, not authority" — federation is
the same shape one level up, not a new problem:

- **A "core-bridge" is an Agent-Fabric channel with a different label**, not a
  fourth transport. Core system X registers a channel-broker identity with
  core system Y (or a neutral rendezvous) the same way a pipeline agent does
  today, advertises which hostnames/tenants it fronts, and requests get
  relayed or handed off exactly like a cross-user A2A channel.
- **This keeps the zero-knowledge boundary intact by construction.** Federation
  built as "yet another Agent-Fabric channel" inherits ADR-0002's guarantee for
  free: a bridge relays opaque bytes between two core systems the same way an
  edge relays opaque bytes between Client and Agent today — no core system
  ever needs to see another's plaintext or private keys. A bespoke
  cross-region control-plane sync protocol would have to re-derive this
  guarantee from scratch and would be a second place it could be gotten wrong.
- **It reuses tested trust-chain primitives instead of inventing consensus.**
  Cross-region control-plane replication (Raft-like sync, shared DB, etc.) is
  a much larger, harder-to-get-right undertaking than "one more kind of
  Agent-Fabric channel member" — and this codebase already explicitly rejected
  building a distributed consensus layer prematurely (no such component exists
  today; the `raft-manager`/`quorum-manager`/`byzantine-coordinator` roles
  visible in this workspace's agent tooling are generic orchestration
  utilities, not something this project has adopted for its own control plane).

### Recommendation

Pursue the tunnel-bridge approach, **after** Part 1 lands and is proven with
two real edges — federation's bridge is naturally Part 1's edge-to-edge relay
protocol, reused with a core-system-scoped identity instead of a peer-edge
identity, exactly the "one more kind of Agent-Fabric channel member" framing
above. Concretely, in order:

1. Ship Part 1 (intra-core multi-edge relay) and run it for real with 2+ edges
   under one control plane first — this is the smaller, lower-risk version of
   the exact same relay problem, and de-risks the transport before federation
   adds a second trust domain on top.
2. Define a "core-bridge" Agent-Fabric channel role (ADR-0020's trust-chain
   model, scoped: "may relay for hostnames belonging to tenants of core system
   Y", nothing broader) as a follow-up ADR once Part 1's relay is live and
   tested — not designed blind before the underlying relay exists.
3. Explicitly do **not** attempt shared-database or consensus-based
   cross-core replication. It solves a problem federation via Agent-Fabric
   channels already solves, at much higher implementation and operational risk.

### Consequences

- No code ships for Part 2 in this ADR — it is a direction and a recommended
  sequencing, matching ADR-0020's own precedent of fixing the trust model
  before implementation.
- Keeps every future core system fully sovereign over its own tenants' data
  and keys — federation never requires trusting another operator with
  plaintext or key material, only with relaying ciphertext it can't read.
