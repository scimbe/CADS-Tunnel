# CADS Tunnel — v1 Product & Architecture Spec

> Status: draft for review. Derived from the grilling session captured in `CONTEXT.md` (glossary) and `docs/adr/0001–0018`. Each decision links to its ADR; rationale lives there and is not repeated here.

## 1. What it is

CADS Tunnel is a **zero-knowledge, censorship-resistant network-tunnel SaaS**. It exposes a service running behind NAT or a firewall to remote clients **without the operator ever being able to read the traffic**, and it is designed to keep working under discretionary takedown pressure.

The operator is deliberately kept out of three things:

- **Content** — always (provider-blind payload, [ADR-0001](adr/0001-provider-blind-e2e-data-plane.md)).
- **Trust** — always (customer-anchored keys, no operator PKI, [ADR-0013](adr/0013-noise-mesh-handshake.md)/[0014](adr/0014-out-of-band-capabilities.md)).
- **The data path** — whenever a peer-to-peer path can be formed ([ADR-0015](adr/0015-p2p-mesh-with-rendezvous.md)).

## 2. Target user (ICP)

Primary: **censorship-resistance–motivated users** — people and organisations who need to expose or reach a service where an infrastructure provider that *can* see or be compelled to cut their traffic is unacceptable ([ADR-0011](adr/0011-censorship-resistant-lawful-floor.md)). Technical, CLI-comfortable, privacy-first. Explicitly **not** optimising for the mass indie-dev "paste a URL" market in v1, nor for compliance enterprises.

## 3. Guarantee & threat model

**Provider-blind, scoped to payload** ([ADR-0002](adr/0002-zero-knowledge-boundary.md)). Concretely:

| The operator CANNOT | The operator CAN see |
|---|---|
| Read or alter payload (E2E to Origin) | That a Tunnel exists / is online |
| Obtain the Origin's key (never leaves Agent) | Rendezvous coordination events |
| Read the routed hostname (opaque token, mesh) | Relay-fallback timing/volume **only** when P2P fails |
| Silently MITM (customer-anchored trust) | Coarse billing/health counters |

- **Enforcement** is a single blunt lever — **Termination** of a Token/Tenant — applied **only at the Lawful Floor**: a binding legal order or verified CSAM ([ADR-0011](adr/0011-censorship-resistant-lawful-floor.md)). No abuse-feed or discretionary takedowns.
- **Identity** is minimal and pseudonymous; crypto payment supported; no mandatory KYC ([ADR-0012](adr/0012-minimal-pseudonymous-identity.md)).

## 4. Components

- **Agent** (Rust) — customer-run, outbound-only. Custodian of the Origin key; mints Capabilities; runs the ACME/BYO cert path for the future Browser Plane; emits its own telemetry.
- **Edge** (Rust) — operator-run, public. Coordinates Rendezvous; relays ciphertext only as fallback; routes by Routing Token via a replicated Tunnel Registry. Cannot decrypt.
- **Control Plane** (thin, self-hostable-ready) — enrollment, Tunnel Registry, Rendezvous endpoint, billing. Holds no trust material or payload ([ADR-0017](adr/0017-thin-self-hostable-control-plane.md)).
- **Client** — runs operator software (Mesh Plane, v1). Holds a Capability; pins the Origin Identity.

Language: **Rust** for the data plane ([ADR-0007](adr/0007-rust-data-plane.md)). Transport: **QUIC/UDP-443 with HTTP/2-over-TCP fallback** ([ADR-0004](adr/0004-quic-data-plane-transport.md)).

## 5. Key flows

1. **Agent enrollment** — one-time join token → Agent generates identity keypair → bound to Tenant; steady-state auth via short-lived mTLS ([ADR-0005](adr/0005-asymmetric-agent-identity.md)).
2. **Capability minting** — Agent generates a self-contained **Capability** (Routing Token + Origin Identity + Edge address); the customer distributes it out of band ([ADR-0014](adr/0014-out-of-band-capabilities.md)).
3. **Connection setup** — Client presents Capability → PoW/rate-gated Rendezvous at the Edge → NAT hole-punch to a **direct P2P path** (fallback to Edge relay under symmetric NAT) → **Noise handshake** Client↔Origin, pinned to the Origin Identity ([ADR-0013](adr/0013-noise-mesh-handshake.md), [ADR-0015](adr/0015-p2p-mesh-with-rendezvous.md)).
4. **Revocation** — rotate the Token and/or Origin key.

## 6. Availability & abuse resistance

- Established P2P connections **survive Edge outage**; only new-connection setup needs Rendezvous. HA = replicated Rendezvous + Tunnel Registry ([ADR-0018](adr/0018-availability-and-blind-dos-resistance.md)).
- Blind DoS/sybil defence is layered: **PoW-gated rendezvous + per-Token rate limits + capacity/anycast**. No upstream scrubbing third party (would be a pressure point).

## 7. Observability

Agent/Client-side, **customer-owned**, exported in open formats (OTel/Prometheus). Operator dashboard shows only structural health + relay-fallback bytes for billing ([ADR-0016](adr/0016-agent-side-observability.md)).

## 8. v1 scope

**In:** Mesh Plane (client-software, any TCP/UDP), Noise E2E, P2P + relay fallback, thin hosted control plane, Agent-side observability, pseudonymous accounts + crypto payment, PoW DoS gating.

**Deferred:** Browser Plane (anonymous-browser SNI-passthrough exposure, [ADR-0003](adr/0003-agent-held-certificates.md)/[0010](adr/0010-mesh-plane-first.md)); full self-hosting & decentralised coordination; Agent redundancy; enterprise features.

## 9. Open risks (must resolve before/at build)

1. **Billing-side sybil/abuse** — PoW deters floods but not a funded adversary; KYC-free free-tier/billing fraud is unsolved ([ADR-0018](adr/0018-availability-and-blind-dos-resistance.md)).
2. **Jurisdiction, hosting & payment rails** — incorporation, censorship-tolerant upstreams, crypto billing. Counsel-adjacent; determines whether the posture is operable at all.
3. **CSAM operational process** — the mandatory Lawful-Floor obligation needs a concrete report-intake → Termination → metadata-preservation procedure ([ADR-0011](adr/0011-censorship-resistant-lawful-floor.md)).

## 10. Suggested build order

1. Agent ⇄ Edge QUIC transport + enrollment/identity.
2. Tunnel Registry + Rendezvous (relay path first, correctness before NAT traversal).
3. Noise Client↔Origin E2E + Capability mint/import.
4. P2P hole-punching with relay fallback.
5. PoW gating + rate limits; thin control plane + billing.
6. Agent-side telemetry/export.
7. (Post-v1) Browser Plane, self-hostable packaging.
