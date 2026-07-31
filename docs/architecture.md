# Codebase overview

A map of the source base: the crates, what lives in each, and how a request flows
through them. For the *why* behind each decision, follow the linked ADRs; for the
full specification see [`SPEC.md`](SPEC.md).

## Workspace

A Rust Cargo workspace of six crates. The dependency graph is acyclic — the five
tunnel crates each depend only on `ct-common`; `ct-dns` is standalone.

```
ct-client ─┐
ct-agent  ─┤
ct-edge   ─┼─► ct-common
ct-control-plane ─┘
```

| Crate | Responsibility | Key modules |
|-------|----------------|-------------|
| `ct-common` | shared wire types & primitives | `noise`, `pow`, `credential`, `ratelimit`, `metrics` |
| `ct-edge` | provider-blind relay | `transport` (QUIC/TLS), `pki` (internal CA), `serve`, `relay`, `rendezvous`, `state` |
| `ct-agent` | customer-run node, origin-key custodian | `onboard`, `identity`, `serve`, `origin`, `capability`, `transport` |
| `ct-control-plane` | coordination & billing | `service` (HTTP), `storage` (SQLite), `oidc`, `payment_provider`, `enrollment`, `registry`, `billing` |
| `ct-client` | tunnel setup & benchmarking | `rendezvous`, `noise`, `transport`, `bench` |
| `ct-dns` | authoritative DNS-01 responder (ACME, front door #31) | `server` (`:53`), `store`, `api`, `provider` (deSEC) |

## Data path (payload)

The payload is end-to-end encrypted; the edge and control plane only ever see
ciphertext ([ADR-0001](adr/0001-provider-blind-e2e-data-plane.md),
[ADR-0002](adr/0002-zero-knowledge-boundary.md)).

```
client ──Noise(IK)── origin        # end-to-end, terminates at the endpoints
   │                    ▲
   └── QUIC/TLS ── edge ── QUIC/TLS ── agent ── local ── origin
                    (relays ciphertext; direct P2P when possible, relay fallback)
```

- Transport is QUIC (TLS 1.3) with a TLS-over-TCP fallback
  ([ADR-0004](adr/0004-quic-data-plane-transport.md)).
- The inner session is Noise `Noise_IK_25519_ChaChaPoly_BLAKE2s`
  ([ADR-0013](adr/0013-noise-mesh-handshake.md)); the agent mints a Capability
  carrying the origin's public identity, imported out of band
  ([ADR-0014](adr/0014-out-of-band-capabilities.md)).
- Connectivity prefers direct peer-to-peer with a relay fallback
  ([ADR-0015](adr/0015-p2p-mesh-with-rendezvous.md)).

## Control path

The thin, self-hostable control plane
([ADR-0017](adr/0017-thin-self-hostable-control-plane.md)) exposes an HTTP API
backed by durable SQLite:

- **Enrollment** — single-use join tokens bind an agent's public key to a tenant.
- **Registry / rendezvous** — routing tokens resolve to a tunnel; a proof-of-work
  gate and per-account rate limit protect availability
  ([ADR-0018](adr/0018-availability-and-blind-dos-resistance.md)).
- **Identity** — OIDC (Keycloak) bearer verification; the account is derived from
  the token subject.
- **Billing** — a credit ledger; credits are applied only from a
  signature-verified payment-provider webhook.
- **Health** — `/healthz` (liveness) and `/readyz` (DB readiness).

## Productionization

The transition from testbed to operable service is documented end-to-end in the
[security whitepaper](security/whitepaper.md), the [threat model](security/threat-model.md),
and the thesis chapter *Produktivierung*. In the code it spans persistence
(`storage.rs`), identity (`oidc.rs`), PKI (`pki.rs`), the payment webhook
(`payment_provider.rs`), and the deployment bundles under `docker/deploy/`.

## Where to read next

- Decisions in depth: [`docs/adr/`](adr/) (20 ADRs).
- The specification: [`SPEC.md`](SPEC.md).
- The development process the code was built by: [`DEVELOPMENT-PROCESS.md`](DEVELOPMENT-PROCESS.md).

## Known gaps between documented intent and current behavior

- **Declarative network policy doesn't gate anything live yet (#235).** The topology/overlay
  store and its `Policy`/`authorized_channels` predicate (see `docs/planning/v1-first-task-packets.md`'s
  `#107-enforce` entries) are real, tested code, but the edge broker's live admission path
  (`channel_authorize`) doesn't consult them — the "(ii-b) live wiring" step described there
  remains open even though the parent epics (#102, #107) are closed. Today, the only
  live-enforced mechanism restricting which agents can talk to which is channel admission
  itself, not the declarative overlay/policy language.
- **The workflow-pipelines auction/marketplace demo path uses a hardcoded fixture, not a live
  clearing (#180, open).** See #180 for the concrete gap and scope.
- **The topology/overlay editor has no HTTP endpoint for authenticated operator-binding yet
  (#237, open).** The enforcement predicate and the authenticated binding primitives are real and
  tested (`docs/planning/v1-first-task-packets.md`'s `#107-enforce` entries), but there is no REST
  route to actually bind a topology to an operator key from outside the control plane, so a drawn
  overlay authorizes nothing today even before #235's live-wiring gap.
- **Agent-Fabric NAT traversal (DCUtR hole-punch) is validated against a single 2-NAT lab setup
  only, not the diversity of real-world NAT types (#238, open).**
