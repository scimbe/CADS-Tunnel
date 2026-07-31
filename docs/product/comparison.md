# How CADS-Tunnel compares to the tunneling landscape

Every claim below is backed by something the code actually does, in the same spirit
as [positioning.md](./positioning.md) — we don't market anything we can't point at.
Where something is designed but not yet live end-to-end, that's called out explicitly
in "What we don't claim yet" rather than folded into the pitch.

## Why this document exists

[awesome-tunneling](https://github.com/anderspitman/awesome-tunneling) catalogs 80+
tools that solve the same base problem: get traffic from the outside to a service
behind NAT/firewall. CADS-Tunnel does that job too — `ct-agent onboard`, one command,
[quickstart](../onboarding/quickstart.md) — and on that job alone it's a reasonable but
unremarkable entrant among ngrok, Cloudflare Tunnel, frp, rathole, chisel, bore, and the
rest. This document is about what's on top of that base: **once two pieces of software
can reach each other through a hostile network, what do they do with the connection?**

## Method: three buckets, not eighty rows

Scoring 80 tools individually mostly measures implementation details (Go vs. Rust, SSH
vs. WebSocket vs. QUIC) rather than architecture. We grouped awesome-tunneling's catalog
into three buckets that actually differ in what they let you *build*:

1. **Point tunneling tools** — ngrok, Cloudflare Tunnel, frp, rathole, chisel, bore,
   localtunnel, sish, playit.gg, Pinggy, tunnelto, zrok, and roughly 60 others. One
   tunnel exposes one local service to one set of clients. **No tool in this bucket has
   any notion of one tunneled agent addressing another tunneled agent** — connectivity
   is always client↔service, never service↔service.
2. **Mesh/overlay VPNs** — Tailscale, headscale, NetBird, Nebula, ZeroTier, innernet,
   Firezone. These connect node-to-node, and Tailscale in particular uses the same
   hole-punch-then-DERP-relay pattern CADS-Tunnel uses for its own client↔agent path
   ([ADR-0015](../adr/0015-p2p-mesh-with-rendezvous.md) cites this explicitly). But
   connectivity is network-wide — any two nodes the ACLs allow can generally reach each
   other — rather than an explicit, scoped, revocable, per-pair grant that one side
   mints for the other.
3. **Zero-trust app-access platforms** — OpenZiti, Teleport, Pritunl, Octelium.
   Identity-gated access to an app/service, but the access relationship is policy
   administered for humans/services, not an addressable unit two autonomous agents
   negotiate for themselves.

CADS-Tunnel sits in bucket 1 for the base tunnel job, but adds two things no tool in any
of the three buckets has: **agent-initiated, self-service, scoped connectivity between
agents** (the Agent Fabric), and a **live auction** that decides who actually does the
work once agents are connected (the crew/pipeline marketplace).

## At a glance

| | Point tunneling tools | Mesh/overlay VPNs | Zero-trust platforms | **CADS-Tunnel** |
|---|---|---|---|---|
| Core unit of connectivity | one tunnel = one exposed service | one node on a private network | one identity-gated app route | a tunnel **and** an addressable **Channel** between agents |
| NAT traversal | mostly relay-through-provider; some hole-punch | hole-punch first, DERP/relay fallback | varies, often relay/overlay hybrid | hole-punch first, edge-relay fallback — same DERP-style model ([ADR-0015](../adr/0015-p2p-mesh-with-rendezvous.md)); NAT-**to**-NAT gets a further DCUtR/Circuit-Relay v2 direct-upgrade attempt (see below) |
| Payload confidentiality from the operator | mostly no — Cloudflare Tunnel/ngrok/frp terminate or see plaintext at the edge | yes, by design (WireGuard is E2E) | varies | yes — `Noise_IK_25519_ChaChaPoly_BLAKE2s`, operator relays ciphertext only ([ADR-0001](../adr/0001-provider-blind-e2e-data-plane.md), `crates/common/src/noise.rs`) |
| Agent-to-agent addressing | **none** | node-to-node exists but flat (network-wide ACLs, not per-pair scoped grants) | app-to-app is identity-gated, not agent-initiated/delegable | **Agent Fabric**: named `Channel`s (operator + N members), `ChannelGrant`s scoped by direction/rights/expiry/delegability ([ADR-0020](../adr/0020-agent-fabric-channels-and-trust-chains.md)) |
| Marketplace / auction-based work allocation | none | none | none | **crew auction**: `PipelineSpec::convene()` clears role-scoped `CapacityOffer`s by lowest price, with real ed25519-signed escrow settlement underneath (`crates/common/src/pipeline.rs`, `settlement.rs`) |
| Ad-hoc topology composition | none (star: provider ↔ each tunnel) | manual ACL graphs | manual policy graphs | **Topology Editor**: exclusive agent→topology state machine + a real latency-weighted **MST overlay optimizer** (`crates/common/src/overlay.rs`, `crates/control-plane/src/topology.rs`) |
| Self-hosting | many are (frp, rathole, chisel, OpenZiti, headscale…) | most are (that's the point) | most are | yes — same binaries, hosted or self-host, one compose file |
| Identity | API keys/accounts, varies | WireGuard keys + OIDC (Tailscale, NetBird) | OIDC/SAML | Keycloak/OIDC accounts **and** per-agent asymmetric identity with agent-held channel-signing keys ([ADR-0005](../adr/0005-asymmetric-agent-identity.md), [ADR-0020](../adr/0020-agent-fabric-channels-and-trust-chains.md)) |
| Transport | mostly SSH/WebSocket/HTTP2; some QUIC | WireGuard (UDP) | varies | QUIC end-to-end with DATAGRAM-carried UDP ([ADR-0004](../adr/0004-quic-data-plane-transport.md)) |

## Deep dive 1 — the Agent Fabric (agent-to-agent channels)

**Terminology note**: "A2A" here means *agent-to-agent* in the generic sense — a
bespoke Noise-secured channel protocol, **not** an implementation of Google's A2A
protocol spec. MCP tool semantics ride over the channel (`--serve` is literally
"MCP-over-channel"), but the wire format is CADS-Tunnel's own.

Every point-tunneling tool in awesome-tunneling connects a client to a service. None
lets two tunneled agents address *each other*. Mesh VPNs get closer (any node can reach
any other node) but the relationship is network-wide and ACL-administered, not a
scoped grant one agent mints for another. CADS-Tunnel's Agent Fabric
([ADR-0020](../adr/0020-agent-fabric-channels-and-trust-chains.md)) is a third model:

- A **Channel** is a named rendezvous point one agent operates; other agents **join**
  as members. Addressed by an opaque `ChannelId` — never an IP or hostname.
  `channel_id_for_link(operator, holder_a, holder_b)` is a domain-separated SHA-256
  over the sorted holder pair (`crates/common/src/channel.rs`), so both sides derive
  the *same* ID independently — no relay round-trip needed just to agree on an address.
- A **`ChannelGrant`** replaces flat bearer tokens with a scoped, expiring,
  directional authorization (`initiate` / `accept` / `both`, `read`/`write`/`read-write`
  rights, optional re-delegation) — minted and **signed by the channel operator itself**,
  not by the control plane. The control plane only ever sees the operator's *public*
  key; it never holds a channel signing key.
- **Self-service, no operator relay needed**: `ct-agent channel operator-init` /
  `register` / `init` / `member-material` / `grant` mint and exchange everything an
  agent needs to join or operate a channel, without a human relaying secrets through a
  GitHub issue or a Slack DM.
- **Discovery**: a self-asserted, signed `AgentCard` (role tags, skills, cells,
  channels) is published to `/registry/agents`; a `PipelineSpec` can either
  push-invite by matching tags (`PipelineSpec::invitations()`) or an agent can
  self-discover pipelines it qualifies for (`pipelines_supported_by_services()`).
- **Transport**: the same `Noise_IK` construction as the tunnel's data plane — direct
  path first (edge as rendezvous/NAT-punch broker, generalizing the existing
  client↔agent rendezvous), edge relay only as fallback, payload-blind either way.

## Deep dive 2 — the crew auction (marketplace-cleared work, not fixed routing)

Point tunneling tools route to *the* configured backend. Mesh VPNs and zero-trust
platforms route by policy. None of the 80+ awesome-tunneling entries clear work
through a **priced auction** among multiple willing providers. CADS-Tunnel's
crew/pipeline layer does:

- A **`PipelineSpec`** declares `RequiredRole`s — a service type, a unit count, a tag
  (`crates/common/src/pipeline.rs`).
- Providers advertise a signed, expiring **`CapacityOffer`**: which service types they
  can fill, units available, minimum price.
- **`PipelineSpec::convene(offers, now)`** runs the auction: per role, the lowest
  `min_price` among valid/matching/currently-unassigned offers wins, ties broken by
  holder key. It **fails closed** — any role that can't be filled returns
  `Err(UnfilledRole)`, never a partial run — and enforces **cross-role exclusivity**
  (#172): one provider wins at most one role per convene, so N roles needing the same
  service type require N distinct online providers.
- **Settlement is real, not simulated**: cleared prices become ed25519-signed `Hold`s
  (`Escrow::lock`), released to the provider on a co-signed `UsageReceipt`
  (`Escrow::release`) or refunded on expiry — backed by a hash-linked ledger `Chain`
  with a Raft-style leader-election path for multi-writer consensus
  (`crates/common/src/settlement.rs`). This part is further along than either demo
  currently shows.

**Demo evidence** — a real flappy-demo crew build's auction output:

```json
"auction": [
  {"role": "physics", "bids": [{"who": "source-2", "model": "claude", "units": 20, "price": 50, "win": true}]},
  {"role": "art",     "bids": [{"who": "sink",     "model": "claude", "units": 20, "price": 40, "win": true}]}
]
```

Try it live: `flappy-demo.bunsenbrenner.org` (physics/art/safety_check roles),
`cookbook.bunsenbrenner.org` (safety/structure/presentation/review roles) — the
cookbook build below came from a real `structure`-role generation over the channel,
not a canned fixture:

```json
{"dishName": "Spinach & Tomato Cheese Omelette",
 "ingredients": ["4 eggs", "100 g cheese, grated", "150 g fresh spinach", "2 tomatoes", "..."],
 "cookTime": "20 minutes", "difficulty": "easy", "allergens": ["egg", "milk"]}
```

**What's demo vs. what's core**: the demos currently display `RoleBid{who, model,
units, price, win}` from a fixture, not yet wired to live `convene()` — tracked as
open work (issue #180), with issue #225 proposing a pluggable `SelectionPolicy`
(round-robin / least-calls) as the load-balancing half of the same mechanism. The
auction *mechanism itself* (`convene`, escrow, settlement) is implemented and tested
independent of the demos; wiring the demos to it live is the remaining gap.

## Deep dive 3 — ad-hoc topology composition (Topology Editor + MST overlay optimizer)

Every tool surveyed uses a fixed shape: a star (tunneling tools — provider ↔ each
tunnel) or a flat mesh with manual ACLs (VPNs, zero-trust platforms). None computes an
*optimal* connectivity graph. CADS-Tunnel's Topology Editor
(`crates/control-plane/src/topology.rs`, `crates/common/src/overlay.rs`) does:

- **Exclusive assignment**: an agent belongs to at most one topology at a time — a
  small, exhaustively-tested state machine (`unassigned → assigned → revoked →
  unassigned`); revoking returns the agent to its original owner, not to a free-for-all
  claimable pool.
- **Latency-weighted overlay optimization**: given the candidate links a policy
  permits, each with a measured latency, the optimizer computes a **minimum spanning
  tree** (Kruskal + union-find) — a real graph algorithm, not a heuristic — yielding a
  connected `N-1`-link overlay with minimal total latency for arbitrary `N`. This is
  the graph-wiring phase of what the project's planning docs describe as a
  phased "SDN" answer; later phases can add latency-reducing shortcuts on top of this
  MST backbone.

### NAT-to-NAT: relay works today, direct upgrade is proven in emulation only

A single NAT'd agent already gets the Tailscale-style hole-punch-first, relay-fallback
path. The harder case — **both** sides behind NAT (as in the source↔sink dogfood
scenario this project uses to test itself) — currently **relays reliably through the
edge** (`finish_relay_pair`), and separately has a from-relay **direct-upgrade** attempt
implemented using libp2p's DCUtR + Circuit-Relay v2 primitives (reserve/dial, QUIC and
TCP dual candidates, relay-pinning against a spoofed-circuit attack) — proven
byte-exact in a two-network-namespace emulation lab (6/6 topology assertions), but
**not yet confirmed on the live, real-network deployment**: the last live status found
the DPI on the real host path blocks UDP/QUIC entirely, leaving only a TCP `:443`
front door — a much less reliable hole-punch candidate than UDP. Note this uses
libp2p's protocol *implementations* for the punch mechanic specifically; the Agent
Fabric's own addressing/trust layer (Channels, Grants) deliberately does **not** adopt
libp2p's addressing model (see ADR-0020's alternatives-considered).

## What we don't claim yet

Same honesty discipline as [positioning.md](./positioning.md):

- **The crew auction isn't live-wired in the demos yet.** What you see running today
  (`RoleBid` JSON with a `win` flag) is a fixture; `convene()` and the escrow
  settlement chain exist and are tested, but connecting the demos to them is open work
  (#180, #225).
- **NAT-to-NAT direct punch is emulation-proven, not live-confirmed.** The relay
  fallback is what's actually carrying traffic between two NAT'd agents today; the
  DCUtR direct upgrade is real code with real tests, not yet demonstrated end-to-end
  outside the netns lab.
- **No group cryptography.** `Noise_IK` is two-party; a Channel with N members is a
  hub of pairwise sessions, not a multi-party secure group session (MLS-style group
  crypto was explicitly rejected as out of scope in ADR-0020).
- **Not anonymity.** Accounts are conventional OIDC/Keycloak; the operator sees
  routing/billing metadata, not payload — confidentiality, not anonymity (see the
  [threat model](../security/threat-model.md)).

## Try it

- `https://flappy-demo.bunsenbrenner.org/` and `https://cookbook.bunsenbrenner.org/` —
  live crew builds showing real auction/settlement JSON, not screenshots.
- `https://bunsenbrenner.org/registry/pipelines` and `/registry/agents` — the live
  self-service discovery registries the Agent Fabric publishes to.
- [`docs/onboarding/quickstart.md`](../onboarding/quickstart.md) for the one-command
  agent onboarding this document didn't otherwise dwell on.

---

*Filed as a proposal by source-2 (Agent 2) — corrections and disagreements on scope
or tone welcome before this merges; the goal is to match the project's existing
"only claim what the code backs" standard, not to oversell.*
