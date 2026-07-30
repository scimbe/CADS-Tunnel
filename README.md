# CADS Tunnel

A tunnel that exposes a local service (any TCP/UDP) to clients through a thin
hosted control plane, with the payload **end-to-end encrypted** so the operator
can route your traffic but never read it.

> Honesty note: this provides payload **confidentiality**, not anonymity.
> Accounts are conventional (Keycloak/OIDC); the operator sees routing and
> billing metadata, just not your bytes. See the [threat model](docs/security/threat-model.md).

## Highlights

- **Provider-blind payload** — Noise (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) end-to-end.
- **Agent-to-agent overlay** — direct, Noise-secured channels between agents, edge-brokered (rendezvous or relay), composed into a best-connectivity mesh by a latency-weighted overlay optimizer and a per-user Topology Editor.
- **One-command onboarding** — a guided setup script: install → enroll → tunnel.
- **Deploy your way** — hosted Kubernetes bundle or a self-host Docker Compose file.
- **Durable & self-healing** — SQLite-backed state, liveness/readiness probes.
- **Rotating PKI** — internal CA, clients trust the CA root (no re-pinning).
- **Abuse-resistant** — proof-of-work gate + per-account rate limits.
- **Trustworthy payment** — credits apply only from a signature-verified provider webhook.

## Related projects

`ct-agent` — the customer-run agent (custodian of your origin's private key) — is its
**own separate repository**, [scimbe/ct-agent](https://github.com/scimbe/ct-agent), with
its own releases and guided setup scripts. This repo (CADS-Tunnel) is the core system:
control plane, edge, and the tunnel/client crates it's built from.

## Architecture

A Rust Cargo workspace of five crates (`ct-agent` lives in its own repo, see above).
Four form the tunnel core and depend only on `ct-common`; `ct-dns` is a standalone
DNS-01 responder for the front door's certs:

| Crate | Responsibility |
|-------|----------------|
| `ct-common` | wire types, Noise, PoW, framing, metrics, overlay optimizer |
| `ct-edge` | provider-blind relay (role dispatch, QUIC/TLS), A2A channel broker |
| `ct-control-plane` | enrollment, tunnel registry/rendezvous, billing, Topology Editor API |
| `ct-client` | tunnel setup, operating modes, bench harness |
| `ct-dns` | authoritative DNS-01 responder for ACME (front door certs) |

## Documentation

Five entry points, depending on what you need:

**1. The source base** — how the code is organized
[**→ Codebase overview**](docs/architecture.md): the six crates, the data path,
the control path, and where each piece lives.

**2. Using it** — easy install notes and scripts
[**→ Install & use**](docs/install.md): clone, hermetic build/test, self-host or
Kubernetes deploy, one-command agent onboarding, headless-pipeline
authorization, and the helper scripts. Plus the
[onboarding quickstart](docs/onboarding/quickstart.md) and the
[operations runbook](docs/ops/runbook.md).

**3. For AI agents** — bring yourself up, no human required beyond one OIDC step
[**→ Agent onboarding**](docs/agent-onboarding.md): register as a discoverable
agent, join a workflow pipeline's channels and serve a role, publish your own
pipeline, and publish a browser-reachable site — every step a shell command or
plain HTTP call. See also
[self-service channel provisioning](docs/ops/self-service-channel-provisioning.md).

**4. Deep detail** — the reasoning and specification
The 20 [Architecture Decision Records](docs/adr/), the [specification](docs/SPEC.md),
and the security set: [whitepaper](docs/security/whitepaper.md) ·
[threat model](docs/security/threat-model.md) ·
[TLS everywhere](docs/security/tls-everywhere.md) ·
[dependency audit](docs/security/dependency-audit.md) ·
[payment integration](docs/payment/integration.md) ·
[product positioning](docs/product/positioning.md).

**5. The bachelor thesis (draft)** — the academic write-up
[**→ thesis PDF**](docs/thesis/thesis.pdf) (German, HAW template); LaTeX sources
under [`docs/thesis/`](docs/thesis/).

## Build & test

Everything runs in a hermetic container — no host toolchain required:

```bash
docker run --rm -v "$PWD":/work -w /work rust:1-slim \
  sh -c 'cargo build --workspace && cargo test --workspace'
```

Building natively instead (no container) works too, but needs a **recent stable
Rust — 1.85 or newer** (a transitive dependency requires the `edition2024` Cargo
feature, stabilized in 1.85): `rustup update stable && cargo build --workspace`.

## Deploy

```bash
# Self-host (Docker Compose) — scripted, idempotent, the whole core system:
./scripts/deploy-selfhost.sh --frontdoor --sso --help-site

# Hosted (Kubernetes)
kubectl apply -k docker/deploy/k8s
```

See [docs/install.md](docs/install.md) for the script's flags and the manual
step-by-step, and the [runbook](docs/ops/runbook.md) for configuration and
operations.

## Status

Research / academic project. The core protocol, productionization (persistence,
identity, PKI, deployment, onboarding, hardening, payment) and documentation are
implemented and tested; see [`docs/planning/PROGRESS.md`](docs/planning/PROGRESS.md).

## Support the project

Bunsenbrenner (the live deployment) is free to use and runs on donated time and
server costs. If it helped you get something live, a small contribution keeps it going:

- [Support as a member](https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413)
- [Buy me a coffee](https://buymeacoffee.com/bunsenbrenner)
