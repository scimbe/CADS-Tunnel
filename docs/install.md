# Install & use

## Just want to run `ct-agent`? Skip the repo entirely.

`ct-agent` lives in its own repo, [scimbe/ct-agent](https://github.com/scimbe/ct-agent) —
if you're exposing a tunnel, serving a pipeline role, or publishing a pipeline (not
running the core system yourself), that's the only place you need. Its guided setup
script checks your environment, walks you through a `.env` file (from your tunnel's
Install page on the portal), and installs + onboards for you:

```bash
curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.ps1 | iex
```

Add `--docker`/`-Docker` to run it as a container instead of directly on the host. See
that repo's README for all flags, prebuilt binaries (no Docker, no Rust toolchain, no
repo checkout needed on any path), and a minimal Docker image if you'd rather run it
that way from the start.

The rest of this page is for the **operator** side — building/running the control
plane + edge themselves (self-hosting, or contributing to core development).

## 1. Get the code

```bash
git clone https://github.com/scimbe/CADS-Tunnel.git
cd CADS-Tunnel
```

## 2. Build & test (hermetic — no host toolchain)

```bash
docker run --rm -v "$PWD":/work -w /work rust:1-slim \
  sh -c 'cargo build --workspace && cargo test --workspace'
```

That builds all six crates and runs the full test suite in a throwaway
container.

Prefer a native build (no container)? It works too, but needs a **recent stable
Rust — 1.85 or newer**: a transitive dependency (`idna_adapter`) requires the
`edition2024` Cargo feature, stabilized in Rust 1.85, so older toolchains fail to
parse the manifest. Then `rustup update stable && cargo build --workspace`.

## 3. Run it

### Self-host (Docker Compose) — one file, durable state

**Scripted (recommended)** — `scripts/deploy-selfhost.sh` is the single,
idempotent entry point for the whole core system: the base stack, the `:443`
front door, Keycloak SSO, and the `help.<zone>` demo. It installs Docker if
needed, generates `docker/deploy/.env` (random `CT_EDGE_ADMIN_TOKEN`, and
`KC_ADMIN_PASSWORD`/`KC_PORTAL_CLIENT_SECRET` when `--sso` is used), obtains
real Let's Encrypt certs for each public hostname via deSEC DNS-01, brings the
stack up, and waits for `/readyz`:

```bash
./scripts/deploy-selfhost.sh                                       # base stack only (:4433)
DESEC_TOKEN=<token> ./scripts/deploy-selfhost.sh --frontdoor        # + public :443 with a real cert
./scripts/deploy-selfhost.sh --frontdoor --sso                     # + Keycloak SSO login on the portal
./scripts/deploy-selfhost.sh --frontdoor --help-site                # + the help.<zone> demo
./scripts/deploy-selfhost.sh --frontdoor --sso --help-site --fresh  # the whole core system, clean
```

`--sso` and `--help-site` both require `--frontdoor` (Keycloak and the demo are
both served through it) and are independent — pick any combination. Idempotent
and re-runnable — after a failed run, re-run it (optionally with `--fresh`)
rather than patching by hand. `--staging` uses the Let's Encrypt staging CA to
validate the flow without risking the production rate limit; `--skip-cert`
reuses certs already on disk. `./scripts/deploy-selfhost.sh --help` for every
flag/env var (including `AUTH_PUBLIC_HOST`, `AUTH_CERT_DIR`, `KC_ADMIN_USER`).

> **One manual step the script does NOT do for you.** `CT_ADMIN_SUPER_EMAIL`
> (ADR-0025 — the one Google account allowed into the admin console) is
> **required and fail-closed**: the control plane refuses to boot at all
> without it, and `deploy-selfhost.sh` neither generates nor prompts for it
> the way it does `CT_EDGE_ADMIN_TOKEN`. Add it to `docker/deploy/.env`
> yourself before the first run: `CT_ADMIN_SUPER_EMAIL=you@example.com`. See
> the [runbook's Configuration table](ops/runbook.md#configuration) for this
> and every other env var, including which ones (like the optional
> Agent-bridges-v2 identity) degrade gracefully instead.

Deep-dive references for what each piece does under the hood: the front door
and its `.env` keys are in the [runbook](ops/runbook.md#deploy); SSO's realm/
client setup is in [keycloak-sso.md](deploy/keycloak-sso.md); the DNS-01
mechanism (and the `acme.sh` `DEDYN_TOKEN` naming gotcha) is in
[dns01-desec.md](dns01-desec.md); the help demo's own design is in
[examples/help-site/README.md](../examples/help-site/README.md). The script
supersedes running each of those manual procedures by hand — read them for
the *why*, run the script for the *how*.

**Manual** — the same stack, one step at a time:

```bash
cp docker/deploy/.env.example docker/deploy/.env   # edit ports / OIDC issuer / webhook secret
docker compose -f docker/deploy/compose.selfhost.yml --env-file docker/deploy/.env up --build -d
```

The control plane persists to a named volume and restarts on failure; the edge
comes up once the control plane is healthy.

> **Build caching (needs BuildKit/buildx).** The image (`docker/Dockerfile`) uses
> BuildKit cache mounts for the cargo registry and `target/`, so an incremental
> rebuild after a small change takes ~20 s instead of recompiling the whole
> dependency tree (5–20 min). This needs BuildKit — modern `docker` enables it by
> default; otherwise export `DOCKER_BUILDKIT=1` or install the `docker-buildx`
> plugin. The **legacy builder silently ignores** `--mount=type=cache` (you'll see
> a "legacy builder is deprecated" warning and rebuilds stay cold).

### Hosted (Kubernetes)

```bash
kubectl kustomize docker/deploy/k8s     # review the rendered manifests
kubectl apply -k docker/deploy/k8s      # namespace ct-system: control plane + edge + TLS ingress
```

## 4. Onboard an agent (one command)

With a control-plane URL and a single-use join token:

```bash
CT_AGENT_CP_URL="$CP_URL" \
CT_AGENT_JOIN_TOKEN="<token>" \
CT_AGENT_ID="agent-1" \
CT_AGENT_EDGE="edge.example.com:4433" \
CT_AGENT_ORIGIN="127.0.0.1:8080" \
  ct-agent onboard
```

Full walkthrough: [onboarding quickstart](onboarding/quickstart.md).

## 5. Onboard a headless workflow pipeline

A pipeline agent with no portal/Keycloak account (e.g. a demo maintainer's own
host) can't self-serve host authorization — `scripts/authorize-pipeline.sh
<hostname> [tenant]` does it from the operator side: authorizes the hostname at
the edge, issues it a real Let's Encrypt cert (the pipeline never holds
`DESEC_TOKEN` — that stays on the operator's host, #219/#221), and optionally
mints a join token. Full walkthrough, including the self-service Agent-Fabric
**channel** provisioning an agent needs to join a pipeline's roles (no
per-pipeline core changes required, #214): [runbook §Authorize a new pipeline
hostname](ops/runbook.md#authorize-a-new-pipeline-hostname-headless-agents-214)
and [docs/ops/self-service-channel-provisioning.md](ops/self-service-channel-provisioning.md).
For an AI agent bringing itself up end-to-end (register, join a pipeline,
publish its own pipeline, serve a browser-reachable site), see
[docs/agent-onboarding.md](agent-onboarding.md) — every command there is a
plain shell command or HTTP call, no human required beyond the one OIDC-account
step.

## Helper scripts

| Script | What it does |
|--------|--------------|
| `scripts/verify-tunnel-only.sh` | guard that a pipeline's compose file never publishes a host port that bypasses the tunnel (#219) |
| `scripts/authorize-pipeline.sh` | authorize a headless pipeline's hostname + issue its cert (see §5 above) |
| `scripts/security-audit.sh` | `cargo audit` against the pinned `Cargo.lock` in a container |
| `scripts/check-no-secrets.sh` | guard that no credential material is committed |
| `scripts/sweep.sh` | run the latency benchmark matrix (edge netem × modes) |
| `scripts/plot.sh`, `scripts/tabulate.py` | turn benchmark output into figures / tables |
| `scripts/thesis-haw-build.sh` | build the thesis PDF in a TeX Live container |
| `scripts/claude-resume.sh` | development session helper |

## Configuration reference

Environment variables, monitoring endpoints, rotation and incident procedures are
in the [operations runbook](ops/runbook.md).

## Troubleshooting

- **`/readyz` returns 503** — the control plane can't reach its database; check the
  data volume mount.
- **Webhooks return 401** — `CT_PAYMENT_WEBHOOK_SECRET` doesn't match the provider.
- **`/me/*` returns 404** — OIDC isn't configured; set `CT_OIDC_ISSUER` (the realm
  JWKS is fetched at startup; `CT_OIDC_PUBKEY_PATH` is an optional offline override).

More in the runbook's incident-response table.
