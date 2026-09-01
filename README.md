# CADS Tunnel

A tunnel that exposes a local service (any TCP/UDP) to clients through a thin
hosted control plane, with the payload **end-to-end encrypted** so the operator
can route your traffic but never read it — plus an **Agent-Fabric channel
layer** for direct, Noise-secured agent-to-agent communication (grants,
self-service provisioning, a Topology Editor for composing multi-agent
networks) built on the same core.

> Honesty note: this provides payload **confidentiality**, not anonymity.
> Accounts are conventional (Keycloak/OIDC); the operator sees routing and
> billing metadata, just not your bytes. See the [threat model](docs/security/threat-model.md).

## What it actually does today

- **Provider-blind payload** — Noise (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) end-to-end
  between client and origin; the edge and control plane relay only ciphertext.
- **Unified `:443` front door** — one public port, real Let's Encrypt certs, TLS-SNI
  dispatch between the tunnel data plane and the browser-facing plane.
- **Agent-Fabric channels** — operator-signed grants bind a member's Agent-Fabric
  identity to a channel; sessions are Noise_IK-secured, relay-brokered or direct.
  Fully self-service from the `ct-agent` CLI (`channel init`, `grant`, `register`,
  `allowlist`) or over HTTP (`channel rest-server`, opt-in, loopback-only).
- **Topology Editor** — a per-user canvas for composing multi-agent overlay
  networks out of those channels, with a latency-weighted connectivity optimizer.
- **Progressive TLS for your own hostname** — every tunnel starts on a shared
  cert (Rot), can self-service upgrade to a shared-domain cert (Gelb), and then
  to its own dedicated Let's Encrypt cert (Grün) — no operator step required.
- **One-command onboarding** — `ct-agent onboard`: the agent generates its own
  identity, redeems a join token, and starts serving.
- **Portal self-service** — sign in, create/rename/revoke tunnels, see live
  connection status and quota, gate a hostname behind login, link tunnels into
  topologies, and (v0.7.15+) discover and toggle **Agent bridges** — tunnels
  running `ct-agent`'s REST channel-management interface.
- **RFC 9298 (MASQUE) fallback** — a CONNECT-UDP transport rung for networks
  that block plain UDP, so QUIC still has a path.
- **Admin console** — multi-domain/tenant management, live traffic and tunnel
  overview, certificate-admission control, without shelling into a container.
- **Deploy your way** — hosted Kubernetes bundle or a self-host Docker Compose
  file; same binaries, same protocol either way.
- **Durable & self-healing** — SQLite-backed state, liveness/readiness probes.
- **Rotating internal PKI** — clients trust the CA root, so edge certs rotate
  without any client-side re-pinning.
- **Abuse-resistant** — a proof-of-work gate plus per-account rate limits.
- **Trustworthy payment** — credits apply only from a signature-verified
  provider webhook; the control plane can never credit an account on its own.

Every claim above maps to real code and (for the live deployment) something you
can go click on — see [Documentation](#documentation) for exactly where.

## Use cases

- **Expose a local service without trusting the operator with your traffic.**
  A dev server, an internal API, a demo — reachable at a stable public
  hostname, payload encrypted end-to-end so the tunnel operator (self-hosted
  or hosted) only ever sees ciphertext and routing metadata.
- **Give a fleet of AI agents a secure way to talk to each other.** Agent-Fabric
  channels are a general-purpose, discoverable, Noise-secured messaging layer
  between agents — used for things like a workflow pipeline's role assignments,
  a multi-agent marketplace, or an agent publishing a browser-reachable site of
  its own. See [Agent onboarding](docs/agent-onboarding.md) — every step is a
  shell command or a plain HTTP call, no human required beyond one OIDC step.
- **Self-host your own tunnel infrastructure** instead of routing traffic
  through a third-party SaaS you have to trust blindly — the whole core system
  (control plane + edge) is one Docker Compose file or a Kubernetes bundle.
- **Run real-time services (video calls, low-latency agent coordination)**
  over the same relay/direct-P2P data plane the tunnel itself uses — the
  [CADS-webconference-demo](https://github.com/scimbe/CADS-webconference-demo)
  is one concrete example built on this core.

## Related projects

`ct-agent` — the customer-run agent (custodian of your origin's private key) — is its
**own separate repository**, [scimbe/ct-agent](https://github.com/scimbe/ct-agent), with
its own releases, opt-in background self-update, and guided setup scripts. This repo
(CADS-Tunnel) is the core system: control plane, edge, and the tunnel/client crates it's
built from.

## Architecture

A Rust Cargo workspace of five crates (`ct-agent` lives in its own repo, see above).
Four form the tunnel core and depend only on `ct-common`; `ct-dns` is a standalone
DNS-01 responder for the front door's certs:

| Crate | Responsibility |
|-------|----------------|
| `ct-common` | wire types, Noise, PoW, framing, metrics, overlay optimizer |
| `ct-edge` | provider-blind relay (role dispatch, QUIC/TLS), A2A channel broker |
| `ct-control-plane` | enrollment, tunnel registry/rendezvous, billing, Agent-Fabric channels, Topology Editor API, admin console |
| `ct-client` | tunnel setup, operating modes, bench harness |
| `ct-dns` | authoritative DNS-01 responder for ACME (front door certs) |

## Documentation

**[→ docs.bunsenbrenner.org](https://docs.bunsenbrenner.org)** — the full documentation
site (tutorials, how-to guides, explanations, reference — with real screenshots):
installing `ct-agent`, managing tunnels, Agent-Fabric channels, the Topology Editor,
workflow pipelines, and everything else the live deployment does. Start here if you
just want to *use* the thing rather than read source.

Four more entry points into this repo itself, depending on what you need:

**1. The source base** — how the code is organized
[**→ Codebase overview**](docs/architecture.md): the crates, the data path,
the control path, and where each piece lives.

**2. Using it** — easy install notes and scripts
[**→ Install & use**](docs/install.md): clone, hermetic build/test, self-host or
Kubernetes deploy, one-command agent onboarding, headless-pipeline
authorization, and the helper scripts. Plus the
[onboarding quickstart](docs/onboarding/quickstart.md), the
[self-service channel provisioning](docs/ops/self-service-channel-provisioning.md)
guide, and the [operations runbook](docs/ops/runbook.md).

**3. For AI agents** — bring yourself up, no human required beyond one OIDC step
[**→ Agent onboarding**](docs/agent-onboarding.md): register as a discoverable
agent, join a workflow pipeline's channels and serve a role, publish your own
pipeline, and publish a browser-reachable site — every step a shell command or
plain HTTP call.

**4. Deep detail** — the reasoning and specification
The 25 [Architecture Decision Records](docs/adr/) — notably
[Agent-Fabric channels](docs/adr/0020-agent-fabric-channels-and-trust-chains.md),
[MASQUE fallback](docs/adr/0024-masque-connect-udp-fallback.md), and the
[admin console](docs/adr/0025-admin-console-and-multi-domain-management.md) —
the [specification](docs/SPEC.md), and the security set:
[whitepaper](docs/security/whitepaper.md) ·
[threat model](docs/security/threat-model.md) ·
[TLS everywhere](docs/security/tls-everywhere.md) ·
[dependency audit](docs/security/dependency-audit.md) ·
[payment integration](docs/payment/integration.md) ·
[product positioning](docs/product/positioning.md) ·
[comparison to the tunneling landscape](docs/product/comparison.md).

## Quick install

**Just want a tunnel?** You don't need this repo at all — install `ct-agent` directly
against the live deployment (or your own self-host) and point it at your local service:

```bash
curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash
```

That checks your environment, walks you through a `.env` file (from your tunnel's
Install page on the portal), and installs + onboards for you. See
[scimbe/ct-agent](https://github.com/scimbe/ct-agent) for prebuilt binaries, the
Docker image, and `setup.ps1` for Windows.

**Self-hosting the core system yourself?**

```bash
git clone https://github.com/scimbe/CADS-Tunnel.git
cd CADS-Tunnel

# Hermetic build/test — no host toolchain required:
docker run --rm -v "$PWD":/work -w /work rust:1-slim \
  sh -c 'cargo build --workspace && cargo test --workspace'

# Bring the whole stack up (base + public :443 + SSO login):
DESEC_TOKEN=<token> ./scripts/deploy-selfhost.sh --frontdoor --sso
```

`deploy-selfhost.sh` is scripted and idempotent — it installs Docker if needed,
obtains real Let's Encrypt certs via deSEC DNS-01, brings the stack up, and waits
for `/readyz`. See [docs/install.md](docs/install.md) for every flag (`--help-site`,
`--staging`, `--skip-cert`, `--fresh`), the manual step-by-step, and the
[Kubernetes path](docs/install.md#hosted-kubernetes).

## Build & test

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
identity, PKI, deployment, onboarding, hardening, payment), the Agent-Fabric
channel layer, and documentation are implemented and tested; see
[`docs/planning/PROGRESS.md`](docs/planning/PROGRESS.md). Some documented
capabilities (declarative topology policy's live enforcement, the workflow-pipeline
auction demo's real clearing) are intentionally ahead of their live wiring — see
[docs/architecture.md](docs/architecture.md#known-gaps-between-documented-intent-and-current-behavior)
for the current, honest list.

## Support the project

Bunsenbrenner (the live deployment) is free to use and runs on donated time and
server costs. If it helped you get something live, a small contribution keeps it going:

- [Support as a member](https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413)
- [Buy me a coffee](https://buymeacoffee.com/bunsenbrenner)
