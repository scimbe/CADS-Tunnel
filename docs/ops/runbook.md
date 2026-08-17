# Operations runbook

How to deploy, operate, and respond to incidents for a CADS Tunnel deployment.
Commands assume the repo root.

## Deploy

### Self-host (Docker Compose)

```bash
cp docker/deploy/.env.example docker/deploy/.env   # then edit secrets
docker compose -f docker/deploy/compose.selfhost.yml --env-file docker/deploy/.env up --build -d
```

Brings up the control plane (durable `cpdata` volume) and one edge, both with
`restart: unless-stopped` and a `/readyz` healthcheck. The base stack publishes
the **mesh-plane relay on `:4433`** and the **Agent-Fabric channel
rendezvous/relay on `:4435`/`:4436`** (all udp+tcp), plus metrics on `:9600` — but
**no `:443`**. The channel-broker ports are mapped but the edge only binds them
once `CT_EDGE_ADMIN_TOKEN` is set (#100/#105), so they sit idle until then. Add the
overlays below for the public-facing planes.

**Scripted end-to-end** (recommended): `./scripts/deploy-selfhost.sh --frontdoor
[--sso] [--help-site]` handles Docker install, `.env` generation, a Let's
Encrypt cert per public hostname (via `acme.sh` + deSEC DNS-01, see
[dns01-desec.md](../dns01-desec.md)), the `compose up` below, and — with
`--sso`/`--help-site` — the SSO and help-demo overlays further down this
section too, all in one idempotent, re-runnable command. `--help` for every
flag. The manual steps below are what it automates; read them for the *why*,
run the script for the *how*.

**Optional `:443` front door** (`compose.frontdoor.yml`, #60) — publishes one
`:443` that serves the **Portal landing page**, **Browser-Plane subdomains**
(`help.<zone>`), the tunnel data-plane relay, and the **Agent-Fabric channel
fallback** (ALPN `ct-edge-channel`) for members whose network blocks the
`:4435`/`:4436` channel ports (#106), all SNI/ALPN-multiplexed, plus a
redirect-only `:80` that 308-bounces plain `http://<zone>/` to `https` (#66). The
channel fallback has a second, low-visibility route to the same broker for members
behind DPI that drops the distinctive `ct-edge-channel` ALPN: SNI
`edge-cdn.invalid` with an ordinary `h2` ALPN, so the handshake looks like any
other HTTPS connection on the wire. That hostname is an RFC 2606 `.invalid` name —
never resolved via DNS, identical on every deployment, and impossible to collide
with a real tunnel or terminate host. Point
the Portal hostname's DNS at the edge, get a BYO cert for it (LE via deSEC DNS-01),
then set these in `.env`:

```dotenv
PORTAL_PUBLIC_HOST=bunsenbrenner.org
PORTAL_CERT_DIR=/etc/ct/certs/portal    # holds fullchain.pem + privkey.pem
CT_EDGE_ADMIN_TOKEN=<64-hex, generated>  # same value used by both edge + control plane
```

```bash
docker compose -f docker/deploy/compose.selfhost.yml \
  -f docker/deploy/compose.frontdoor.yml \
  --env-file docker/deploy/.env up --build -d
```

`https://<PORTAL_PUBLIC_HOST>/` then serves the operator page, `/portal` the
customer portal, and `help.<zone>` (a bound Browser-Plane tunnel) passes through;
plain `http://<PORTAL_PUBLIC_HOST>/` 308-redirects to the `https` URL.

**Optional SSO overlay** — add a real Keycloak login to the portal with
`docker/deploy/compose.sso.yml` (a Keycloak IdP + `CT_OIDC_*`; Keycloak itself is
served via the front door on `auth.<zone>`, #48). Stack it **on top of** the front
door: `-f compose.selfhost.yml -f compose.frontdoor.yml -f compose.sso.yml`. See
the [Keycloak SSO runbook](../deploy/keycloak-sso.md). The base stack runs
unchanged without either overlay.

### Hosted (Kubernetes)

Before `apply`, create the two out-of-band Secrets the base needs (never
committed — see `docker/deploy/k8s/kustomization.yaml`'s header for details):

```bash
kubectl -n ct-system create secret generic ct-edge-admin-token \
  --from-literal=token="$(openssl rand -hex 32)"
# ct-edge-portal-tls (tls.crt/tls.key) is auto-created by edge-certificate.yaml
# if you run cert-manager with a DNS-01 ClusterIssuer configured; otherwise
# create it yourself the same way as above (`kubectl create secret tls ...`).
```

```bash
kubectl kustomize docker/deploy/k8s   # review
kubectl apply -k docker/deploy/k8s
```

Deploys into namespace `ct-system`: control plane (PVC-backed, liveness/readiness
probes) and edge (LoadBalancer UDP+TCP+the front door — see below). Also update
`edge-config.yaml`'s `CT_EDGE_PORTAL_HOST` and `control-plane-config.yaml`'s
`CT_PORTAL_BASE_URL`/`CT_OIDC_ISSUER` placeholders with your real values first.

**Front door (#309)**: the edge runs the SAME unified `:443` front door as the
self-host compose deployment (`compose.frontdoor.yml`, ADR-0019) — it is the
sole public TLS-terminating entry point for the Portal, reverse-proxying to
`ct-control-plane:8090` in-cluster. This **replaced** a separate TLS-terminating
`Ingress` (`control-plane-ingress.yaml`) that used to do this job; that file is
kept in the directory as a documented, opt-in alternative (see its header) for
operators who'd rather use a conventional `ingress-nginx` + `cert-manager`
HTTP-01 setup instead of the edge's own `:443` mux — but not both at once for
the same hostname. The edge Service also publishes the Agent-Fabric channel
broker (`4435`/`4436`, UDP+TCP) and keeps its admin API (`9601`) cluster-internal
only (`ct-edge-admin`, a separate `ClusterIP` Service, not on the public
LoadBalancer — mirroring the self-host stack's loopback-only publish of the
same port).

**Deliberately out of scope (#309)**: Keycloak/OIDC login — there is no
Keycloak Deployment/Service in this kustomize base yet, so `CT_EDGE_AUTH_*` and
`CT_OIDC_CLIENT_*` are left unset rather than half-wired against infrastructure
that doesn't exist. `CT_OIDC_ISSUER` alone (already present) only enables
JWKS-verified `/me/*` for bearer tokens minted elsewhere; it does not turn on
browser login. A follow-up should add a Keycloak k8s Deployment (mirroring
`compose.sso.yml`'s Postgres-backed setup) before wiring the rest.

## Configuration

| Variable | Component | Purpose |
|----------|-----------|---------|
| `CT_CONTROL_PLANE_LISTEN` | control plane | bind address (default `0.0.0.0:8090`) |
| `CT_CONTROL_PLANE_DB` | control plane | SQLite path (put it on durable storage) |
| `CT_CP_SHUTDOWN_GRACE_SECS` | control plane | on SIGTERM/Ctrl-C, how long (seconds) in-flight HTTP requests are given to finish before the process force-exits regardless; **default 30** (#400). Stops accepting new connections immediately; a stuck/slow request past this bound is cut off rather than hanging shutdown forever |
| `CT_OIDC_ISSUER` | control plane | Keycloak realm issuer URL; **alone** enables OIDC — the realm JWKS is fetched at startup to mount `/me/*` (#42) |
| `CT_OIDC_PUBKEY_PATH` | control plane | PEM of the realm's RSA public key; an **offline override** of the JWKS fetch (takes precedence when set) |
| `CT_OIDC_ACCESS_AUD` | control plane | **opt-in** access-token `aud` enforcement for `/me/*` (#82); set to your realm's field-checked access-token audience so a token whose `aud` omits it is rejected. Unset ⇒ audience not checked |
| `CT_PAYMENT_WEBHOOK_SECRET` | control plane | provider webhook signing secret (unset ⇒ payment disabled) |
| `CT_CP_UNAUTH_WRITE_PER_MIN` | control plane | **opt-in** per-IP rate cap on the unauthenticated DB-writer endpoints, bounding disk-DoS from a single address (#87); positive integer ⇒ on, unset ⇒ off |
| `CT_CP_EDGE_ADMIN_TOKEN` | control plane | **opt-in** 64-hex shared admin token gating the machine/operator writer endpoints (`/enroll/issue`, `/registry/register`, `POST /registry/agents`, `/accounts/open`, `/payment/intent`, `/billing/issue`, `/bootstrap/mint`) (#87/#90/#161); unset ⇒ those routes stay open (dev/back-compat). Reads, customer `/me/*`, and the portal are unaffected. The front-door overlay sets it from `CT_EDGE_ADMIN_TOKEN`, so the edge and control plane share one value |
| `CT_PORTAL_BASE_URL` | control plane | public base URL embedded in the customer install one-liner (`/portal/tunnels/{id}/install`), e.g. `https://<zone>`; **unset ⇒ silently defaults to `https://localhost`** (warned at startup, #68). The front-door overlay wires it from `PORTAL_PUBLIC_HOST` |
| `CT_RELEASE_BASE` | control plane | base URL the served `/install.sh` + `/install.ps1` scripts download the `ct-agent` binary from (#75); unset ⇒ GitHub Releases `latest/download`. Point at a mirror or pinned tag to override |
| `CT_EDGE_LISTEN` | edge | bind address (default `0.0.0.0:4433`) |
| `CT_EDGE_POW_DIFFICULTY` | edge | rendezvous PoW cost |
| `CT_EDGE_RENDEZVOUS_MAX_PER_MIN` | edge | per-token rendezvous rate limit (rendezvous attempts per routing token per minute); **on by default at 600/min** (#95) — set a positive value to tune, or `0`/`off` to disable (#86/#95) |
| `CT_EDGE_MAX_CONNECTIONS` | edge | cap on concurrent connections, shared globally across the QUIC + TCP accept loops; **on by default at 8192** (#95) — set a positive value to tune, or `0`/`off` to disable (#86/#95) |
| `CT_EDGE_SHUTDOWN_GRACE_SECS` | edge | on SIGTERM/Ctrl-C, how long (seconds) already-admitted connections/tunnels are given to finish before the process force-exits regardless; **default 30** (#400). Every listener (QUIC front door, TCP fallback, `:443` front door, `:80` redirect, Browser-Plane SNI, ws-channel, both Agent-Fabric channel-broker endpoints) stops accepting new connections immediately; a still-open connection past this bound is force-closed rather than hanging shutdown forever |
| `CT_EDGE_CERT_OUT` | edge | path the edge writes its CA root to |
| `CT_EDGE_METRICS_LISTEN` | edge | bind address for `GET /metrics` (unset ⇒ off, issue #10) |
| `CT_FRONT_DOOR` | edge | bind address for the unified :443 front door (SNI/ALPN-multiplexed relay + Portal + browser tunnels); unset ⇒ off, additive to `:4433`/`:8090` (#31) |
| `CT_EDGE_PORTAL_HOST` | edge | SNI hostname the front door treats as the Portal (terminate + reverse-proxy); other SNIs stay passthrough tunnels |
| `CT_CP_PROXY_ADDR` | edge | control-plane address the front door reverse-proxies the Portal to — a hostname (`control-plane:8090`) or literal `IP:port` (required to serve the Portal on :443; a set-but-unresolvable value logs a warning and disables the Portal route) |
| `CT_EDGE_PORTAL_CERT` / `CT_EDGE_PORTAL_KEY` | edge | PEM cert+key so the front door terminates the Portal's TLS and reverse-proxies HTTP to the control plane (FD4-a, #31); absent ⇒ raw-proxy needing a TLS-speaking upstream |
| `CT_EDGE_AUTH_HOST` | edge | a second front-door terminate host (e.g. `auth.<zone>`) — routes that SNI to the IdP (Keycloak) behind the same `:443`, no separate published port (#48) |
| `CT_EDGE_AUTH_ADDR` | edge | upstream the Auth host reverse-proxies to (e.g. `keycloak:8080`); a hostname or `IP:port` |
| `CT_EDGE_AUTH_CERT` / `CT_EDGE_AUTH_KEY` | edge | PEM cert+key for `CT_EDGE_AUTH_HOST` so the front door terminates its TLS (same BYO-cert story as the Portal) |
| `CT_EDGE_HTTP_REDIRECT` | edge | optional `:80` listener (e.g. `0.0.0.0:80`) that 308-redirects to `:443` (unset ⇒ off) |
| `CT_CP_EDGE_CERT_PATH` | control plane | path it reads the edge CA root from to publish at `/pki/ca` (default `/shared/edge-cert.der`, issue #11) |
| `CT_AGENT_EDGE_CERT_URL` | agent | fetch the edge CA root from this control-plane URL instead of a local file (issue #11) |
| `CT_AGENT_STATE_DIR` | agent | **opt-in** persistent directory for the bound identity/tenant (#141); first boot redeems the join token and persists there, later boots **restore** instead of re-redeeming — so a container restart never replays an already-spent single-use token. Point it at a durable volume; unset ⇒ every boot redeems again (prior behaviour) |
| `CT_AGENT_ONBOARD_TIMEOUT_SECS` | agent | bound the one-shot onboarding flow (#73); **unset ⇒ wait indefinitely** — a spent single-use join token can't re-onboard, so production stays patient. Set for fail-fast (CI/smoke) |
| `CT_AGENT_EDGE_CERT_WAIT_SECS` | agent | bound the shared-volume edge-cert wait (#73); **unset ⇒ wait indefinitely** (same resilience reason). Set for fail-fast |
| `CT_AGENT_EDGE_CERT_LOG_INTERVAL_SECS` | agent | throttle the "waiting for edge cert" log line (default 5s, #73) — cosmetic; does not affect the wait |
| `CT_CLIENT_EDGE_CERT_WAIT_SECS` | client | bound the edge-cert wait (default 30s, #73); the client is a bench/test tool, so it fails fast rather than hanging |
| `CT_CLIENT_CAPABILITY_WAIT_SECS` | client | bound the capability wait (default 60s, #73); fail-fast with a precise error instead of an indefinite poll |

Secrets come from `.env` (self-host, gitignored) or Kubernetes Secrets (hosted) —
never commit them. Verify with `./scripts/check-no-secrets.sh`.

### Distribute the edge CA root cross-host (issue #11)
On a single host the edge CA root reaches agents/clients via the shared Docker
volume. **Cross-host**, the control plane serves the current root at `GET /pki/ca`
(public key material only — the CA signing key never leaves the edge; the root is
stable across edge redeploys thanks to the persisted CA). A remote agent/client
fetches it self-serve instead of an out-of-band copy.

Reach it over the **`:443` front door** (`compose.frontdoor.yml`), which terminates
TLS and reverse-proxies the control plane. The base stack's plain-HTTP `:8090` is
bound to **loopback** (#85), so it is not reachable cross-host — and fetching a
trust root over plain HTTP would be MITM-able anyway. Use the HTTPS front-door URL:

```bash
# agent — fetches the root automatically, no local file needed:
CT_AGENT_EDGE_CERT_URL=https://<zone> ct-agent onboard
# client (kept HTTP-client-free) — fetch once with curl, then point it at the file:
curl -s https://<zone>/pki/ca -o edge-cert.der
CT_CLIENT_EDGE_CERT=edge-cert.der ct-client
```

## Monitor

- **Dashboard**: `GET /` on the control plane — a self-contained operator
  landing page showing health plus live counts (tunnels, agents, accounts,
  published pipelines, discoverable agents, uptime), plus the actual lists of
  published workflow pipelines and directory agents (each linking to its full
  spec / agent card) and buttons to the raw `/registry/pipelines` and
  `/registry/agents` endpoints — auto-refreshing. `:8090` is loopback-bound
  (#85), so open it locally at `http://localhost:8090/`, or publicly via the
  `:443` front door at `https://<zone>/`. It shows metadata and health only;
  the payload is end-to-end encrypted and never visible here.
- **Status (JSON)**: `GET /status` — the machine-readable data behind the
  dashboard: `{ready, tunnels, agents, accounts, payments_confirmed,
  pipelines_published, agents_directory, uptime_seconds}`. Scrape or alert on it.
- **Liveness**: `GET /healthz` on the control plane (always 200 while up).
- **Readiness**: `GET /readyz` (200 only when the database is reachable; 503
  otherwise — orchestrators route around it).
- **Metrics**: agent-side Prometheus `/metrics` (per ADR-0016; customer-owned).

Alert on: `/readyz` flapping (DB reachability), edge TCP-listener down,
sustained `429`s on `/me/issue` (a client hitting the rate limit), and webhook
`401`s (misconfigured `CT_PAYMENT_WEBHOOK_SECRET` or a forgery attempt).

## Routine procedures

### Authorize a new pipeline hostname (headless agents, #214)

**When you need this**: a remote pipeline maintainer's agent (flappy-demo,
cookbook-demo, or any future headless pipeline with no portal/Keycloak account)
tries to bind a hostname and the agent log shows:

```
ct-agent: hostname binding for '<host>' failed (edge rejected hostname binding)
```

This is expected, not a bug — it's caused by `CT_EDGE_REQUIRE_HOST_AUTH=1`
(set by `compose.frontdoor.yml`, on for this deployment), which requires every
hostname bind to be explicitly authorized by an operator (#23 BP4b) before the
edge will route it. It's the price of the front door being public: without
this gate, anyone could claim any hostname. Two ways an agent gets past it:

- **It has a portal/Keycloak account** → uses the self-serve `POST
  /portal/tunnels` flow, which authorizes automatically. Nothing for the
  operator to do.
- **It doesn't** (a headless pipeline agent, e.g. flappy-demo/cookbook-demo)
  → needs the steps below, **once per hostname**.

**One-time setup, not per pipeline**: give the pipeline maintainer the shared
`CT_CP_EDGE_ADMIN_TOKEN` (find it in `docker/deploy/.env` as
`CT_EDGE_ADMIN_TOKEN` — same value) **directly, out of band** (chat, not a
GitHub issue/comment — this repo is public). With that one token they can call
`POST /enroll/issue` themselves over the public HTTPS API to mint their own
join tokens for any future pipeline — no further relay needed for that half.

**Per-hostname** (the part a remote agent still can't self-serve — the edge's
own admin API is loopback-only on the operator's host): run, from an operator
checkout with `docker/deploy/.env` present:

```bash
./scripts/authorize-pipeline.sh <hostname> [tenant]
# e.g.:
./scripts/authorize-pipeline.sh cookbook.bunsenbrenner.org cookbook-demo
./scripts/authorize-pipeline.sh <hostname> [tenant] --staging     # LE staging cert, testing only
./scripts/authorize-pipeline.sh <hostname> [tenant] --skip-cert   # host-auth + token only, no cert
```

> **#322 — this step is a documented exception to ADR-0001/0003, not the
> zero-knowledge path.** Running ACME DNS-01 here means the operator's own
> machine generates and transiently holds this hostname's real TLS **private**
> key before handing it off — for the window it exists locally, the "the
> operator cannot read your bytes" claim does not hold for this tunnel. This
> is accepted because headless pipeline agents (no portal/Keycloak account)
> have no path today to the properly zero-knowledge agent-side ACME flow
> ADR-0003 describes. See `docs/security/threat-model.md` residual risk #6 for
> the full rationale and the real (unimplemented) fix. Use this for demo/
> pipeline hostnames you control the risk tolerance for — not as the general
> onboarding path.

It authorizes `<hostname>` at the edge (via the public, admin-gated `POST
/registry/authorize-host/:token/:host`, #214 — no loopback access needed),
**issues a real Let's Encrypt cert for that single hostname** (DNS-01 via the
operator's own `DESEC_TOKEN`, run HERE — the pipeline never sees or holds it,
#219/#221) into `CERT_DIR` (default `~/ct-pipeline-certs/<hostname>/`), and, if
`[tenant]` is given, mints a single-use join token too. It prints the
`CT_AGENT_TOKEN` (routing token), the cert file paths, and, if minted, the join
token response — **relay all of it to the pipeline maintainer out of band**,
never to GitHub. They point their origin's Caddyfile at the delivered
`fullchain.pem`/`privkey.pem` as static files (no ACME client, no DNS plugin,
no `DESEC_TOKEN` in their repo, ever), then onboard with:

```bash
CT_AGENT_HOSTNAME=<hostname> CT_AGENT_TOKEN=<routing token> \
CT_AGENT_JOIN_TOKEN=<join token> CT_AGENT_CP_URL=https://<zone> \
CT_AGENT_EDGE=<zone>:4433 CT_AGENT_EDGE_CERT_URL=https://<zone> \
  ct-agent onboard
```

(`CT_AGENT_EDGE_CERT_URL` is the bare control-plane base URL — `ct-agent`
appends `/pki/ca` itself; a stray extra `/pki/ca` 404s, see `examples/help-site/run-demo.sh`'s history.)

Confirm it worked from anywhere: `curl -I https://<hostname>/` should return
`200` with a real (non-staging) Let's Encrypt cert — `openssl s_client -connect
<hostname>:443 -servername <hostname> </dev/null 2>/dev/null | openssl x509
-noout -issuer` should **not** say `STAGING`.

Before telling the pipeline maintainer their compose file is ready, run
`./scripts/verify-tunnel-only.sh <their-compose-file>` against it — it exits
non-zero and lists every offending line if their origin/bridge publishes a
host port instead of using `expose:` (#219), the same invariant the cert
hand-off above depends on (the browser must reach the origin only through the
tunnel, never directly).

### Rotate the edge certificate
Restart the edge. It mints a fresh CA leaf under its internal CA on startup;
clients trust the CA root, so no client change is needed.

### Rotate the origin key (zero-downtime, issue #12)
Rotate the origin's static Noise key **without breaking clients that still hold
the old capability**. The routing token is preserved, so old clients keep
rendezvousing; only the origin identity changes, and the agent serves both the
old and new identity during the window.

```bash
# 1. Rotate: re-mint the capability (SAME token, new origin) and retire the old key.
CT_AGENT_ORIGIN_KEY=/shared/origin.key CT_AGENT_CAPABILITY_OUT=/shared/capability.bin \
  CT_AGENT_ORIGIN_KEY_DIR=/shared/retired ct-agent rotate
# 2. Restart the agent WITH the retired-key dir so it serves both identities:
CT_AGENT_ORIGIN_KEY=/shared/origin.key CT_AGENT_ORIGIN_KEY_DIR=/shared/retired \
  CT_AGENT_CAPABILITY_OUT=/shared/capability.bin … ct-agent onboard
# 3. Distribute the new /shared/capability.bin to clients (same token, new origin).
# 4. Close the window: once clients are on the new capability, delete the retired
#    key and restart the agent so only the new identity is served.
rm /shared/retired/retired-*.key
```

During steps 2–3 an old capability (old origin, same token) and the new
capability (new origin, same token) both complete the tunnel. Verify with
`./scripts/rotation-smoke.sh`. Keep the retired key files owner-only.

### Rotate the payment webhook secret
Update it in the provider dashboard and in `CT_PAYMENT_WEBHOOK_SECRET`, then
restart the control plane. Expect brief webhook `401`s until both sides match;
providers retry, and delivery is idempotent, so no credit is lost.

### Back up state
Snapshot the control-plane database (the `cpdata` volume / PVC). It holds
enrollment, the tunnel registry, and the credit ledger. Restores are a file copy.

### Audit dependencies
`./scripts/security-audit.sh` — run before each release and on any `Cargo.lock`
change; a non-zero exit means a new advisory affects a pinned crate.

### Verify a deployment end to end (smoke)
`./scripts/e2e-smoke.sh` — the standard one-command cross-host check. It mints a
join token, onboards an agent against the central control plane + edge, runs a
client through the tunnel to a local echo origin, and prints `SMOKE OK via=<quic|tcp>`
(exit 0) or `SMOKE FAIL: <reason>` (exit 1). Run it from the agent host after a
deploy or change:

```bash
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/e2e-smoke.sh
# force the TCP fallback (UDP blocked):
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der CT_CLIENT_FORCE_TCP=1 ./scripts/e2e-smoke.sh
```

Requires the built binaries (`docker run --rm -v "$PWD":/work -w /work rust:1-slim
cargo build --workspace`), plus `socat`, `curl`, and `jq`. `EDGE_CERT` is the edge CA
root (public trust material) copied from the central host.

If the control plane has `CT_EDGE_ADMIN_TOKEN`/`CT_CP_EDGE_ADMIN_TOKEN` set (the
front-door overlay requires it, see above), `POST /enroll/issue` is admin-gated
and the script's own token-minting call gets `401`. Mint one yourself with the
admin header and pass it in:

```bash
TOKEN=$(curl -sS -X POST http://127.0.0.1:8090/enroll/issue \
  -H 'content-type: application/json' -H "x-ct-admin-token: $CT_EDGE_ADMIN_TOKEN" \
  -d '{"tenant":"t1"}' | jq -r .token)
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der CT_JOIN_TOKEN="$TOKEN" ./scripts/e2e-smoke.sh
```

### Demo in 2 minutes (show a human the tunnel works)
Where the smoke above prints a machine verdict for operators, `./scripts/demo.sh`
*shows* a person that real client traffic reaches a **private** origin only through
the tunnel, and how fast. It starts a private echo origin bound to `127.0.0.1`
(unreachable from outside), narrates that contrast, onboards the agent, sends a
recognizable payload through the tunnel, then measures live latency over the same
path. Same prerequisites as the smoke (built binaries, `socat`, `curl`, the edge
CA root):

```bash
BIN=./target/debug CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
# show the TCP fallback path instead of QUIC:
CT_CLIENT_FORCE_TCP=1 BIN=./target/debug CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
# more samples for the latency read:
CT_CLIENT_ITERATIONS=50 BIN=./target/debug CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/demo.sh
```

Example output:

```text
=== CADS-Tunnel demo: reaching a PRIVATE origin through the tunnel ===
▶ Starting a PRIVATE origin on 127.0.0.1:8080 (echo; logs each request)
✓ Origin is up on 127.0.0.1:8080 — bound to loopback, so it is NOT reachable from another host.
▶ Contrast — is the origin reachable directly from outside loopback?
✓ Direct connection to the origin from the public side is refused — it is genuinely private.
▶ Onboarding the agent against the central control plane + edge
✓ Agent onboarded and registered on the edge (<central-host>:4433).
▶ A client sends "private-origin-1752570000" through the tunnel (path: QUIC) …
✓ The client received "private-origin-1752570000" back THROUGH the tunnel — via=quic, round-trip 6 ms.
   ↳ The PRIVATE origin's own log confirms it was reached only via the tunnel:
     [origin] served a request at 14:20:03
▶ Measuring live performance — 20 round-trips through the tunnel (path: QUIC) …
✓ Live latency over the tunnel — 20/20: mean 1.83ms p95 3.10ms.
=== DEMO OK — real client traffic reached the private origin over the tunnel (via=quic) ===
```

Cross-host `via=quic` requires the agent-side keepalive (issue #2, on `main`);
without it the demo can still run locally/loopback.

### Run redundant agents (HA origin, issue #8)
Run **two or more agents for one tunnel** so it survives an agent (or host) dying.
Redundant agents must share **one identity** (same routing token + origin key), so
point them at the same `CT_AGENT_ORIGIN_KEY` + `CT_AGENT_CAPABILITY_OUT` paths on a
shared volume. The **first** agent generates and persists the identity; later
agents load it. Start the primary first so the shared files exist:

```bash
# agent 1 (primary — creates the shared identity):
CT_AGENT_JOIN_TOKEN=<tok> CT_AGENT_ORIGIN_KEY=/shared/origin.key \
  CT_AGENT_CAPABILITY_OUT=/shared/capability.bin CT_AGENT_ORIGIN=127.0.0.1:8081 ct-agent onboard
# agent 2+ (redundant — load the same identity, same origin):
CT_AGENT_JOIN_TOKEN=<tok2> CT_AGENT_ORIGIN_KEY=/shared/origin.key \
  CT_AGENT_CAPABILITY_OUT=/shared/capability.bin CT_AGENT_ORIGIN=127.0.0.1:8081 ct-agent onboard
```

The edge tracks every agent registered for the token and **routes to the most
recent**, failing over to a survivor when one drops — evicting only the dropped
agent's registration, never the others. Verify it end to end with:

```bash
CENTRAL=<central-host> EDGE_CERT=/path/to/edge-cert.der ./scripts/redundancy-smoke.sh
```

which brings up two agents on one origin, establishes a client round-trip, kills
the serving agent, and confirms the client still gets `via=quic` off the survivor
(`REDUNDANCY OK`). With `CT_EDGE_TRACE=1` on the edge you'll see the `agent 2/2`
failover line. Keep the shared `origin.key` owner-only — it's the origin's static
Noise secret.

### Edge data-plane metrics (issue #10)
The edge exposes Prometheus metrics for the relay itself (complementing the
control-plane landing page and the agent `/metrics`). Enable with
`CT_EDGE_METRICS_LISTEN` (off by default) and scrape `GET /metrics`:

```bash
CT_EDGE_METRICS_LISTEN=0.0.0.0:9101 ct-edge   # or set it in the edge container env
curl -s http://<edge-host>:9101/metrics
```

Exposed series (metadata only — the edge stays provider-blind):

| metric | type | meaning |
|--------|------|---------|
| `ct_edge_active_tunnels` | gauge | distinct routing tokens with ≥1 live agent |
| `ct_edge_active_agents` | gauge | live agent registrations (redundant agents #8 counted) |
| `ct_edge_registrations_total` | counter | agent registrations accepted since start |
| `ct_edge_relays_total` | counter | client relays served |
| `ct_edge_relay_bytes_total` | counter | bytes relayed (both directions) |
| `ct_edge_failovers_total` | counter | relays that failed over to a non-primary agent (#8) |

The compose overlay `docker/docker-compose.metrics.yml` sets it for the testbed
(edge on `:9101`, agent on `:9100`). With redundant agents (#8) up you'll see
`ct_edge_active_agents` exceed `ct_edge_active_tunnels`.

### Per-listener connection caps

`CT_EDGE_MAX_CONNECTIONS` (8192, documented in the threat model) bounds the edge as a whole.
Four **sub-caps** bound the individual public listeners; each defaults to **half** the global
default (**4096**) so no single listener can consume the whole budget:

| variable | bounds | issue |
|---|---|---|
| `CT_EDGE_MAX_BROWSER_TUNNEL_CONNECTIONS` | Browser-Plane tunnel connections | #254 |
| `CT_EDGE_MAX_TCP_AGENT_CONNECTIONS` | TLS-TCP fallback agent registrations (reachable with a bare token, no PoW) | #410 |
| `CT_EDGE_MAX_WS_CHANNEL_CONNECTIONS` | browser WebSocket channel joins (`:4437`) | #451 |
| `CT_EDGE_MAX_CHANNEL_BROKER_CONNECTIONS` | `:443` front-door channel-broker arm | #450 |

**`0` does not mean "allow nothing" — it switches the cap OFF.** `0`, `off`, `false` and
`none` all disable the control entirely; that is the deliberate opt-out. An *unset* variable
gives the safe default, and an unparseable value also falls back to the default rather than
disabling protection — a typo must never open the flood gate. Reading `0` as "block
everything" is the misunderstanding this paragraph exists to prevent.

Each cap prints its resolved value at startup (`ct-edge: max N concurrent …`), so the running
configuration is readable from the log rather than inferred from the environment.

### How much channel traffic actually bypasses the edge (#517 V1)

The offload figure is a **pair of counters**, never a single number:

| metric | meaning |
|---|---|
| `ct_edge_channel_rendezvous_pairs_total` | pairings where the edge handed each side the other's endpoint and left the data path |
| `ct_edge_channel_splices_total` | pairings the edge ended up relaying itself |

| reading | meaning |
|---|---|
| `pairs > 0`, `splices == 0` | the channel plane offloaded completely |
| `pairs > 0`, `splices > 0` | mixed; the ratio is the offload figure over the window |
| **both `0`** | **nothing was measured** — not evidence of successful offload |

The last row is the reason the pair exists. `splices == 0` on its own means both
"everything went direct" and "nothing happened", which are opposite conclusions.

Caveat, stated rather than hidden: a peer whose direct dial fails re-joins over the relay,
so a fallback appears in *both* counters. This is a figure over a window, not a partition.

**Two traps when measuring** (both hit on 2026-08-17):

- **It counts pairings, not runs.** A run over an already-established session pairs nothing,
  and a participant that is served in-process (the sort arena's `reference-sorter`) never
  opens a channel at all. To see the counter move, drive a **remote** participant after a
  fresh session — e.g. `POST /run/<remote-participant>` following an edge restart.
- **Which pairer carries the traffic.** The `:443` front door runs the **stream** completer
  family (`finish_stream_pair_inner`), the QUIC broker ports run the **quic** family
  (`finish_quic_pair_inner`). Since agents are pinned to `CT_CHANNEL_FRONT_DOOR_ONLY=1`
  until #495 unifies the pairers, the QUIC family carries almost nothing in this deployment
  — instrumenting only that side measures a near-empty path, which is exactly what the first
  version of this counter did.

First field measurement (2026-08-17, remote participant `fbsd-0816`): `pairs=1, splices=0` —
that session was paired at the edge and then ran entirely past it.

## Incident response

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `/readyz` returns 503 | DB unreachable / volume detached | check the `cpdata` volume mount; restart once storage is back |
| All webhooks `401` | wrong/blank `CT_PAYMENT_WEBHOOK_SECRET` | set it to match the provider; restart |
| Portal SSO login `502 sign-in failed` right after a successful Keycloak login | `KC_PORTAL_CLIENT_SECRET` unset, or `.env` change not picked up (#65) | set `KC_PORTAL_CLIENT_SECRET` in `.env`; check `docker compose logs control-plane` for `OIDC code exchange failed`; recreate with `docker compose ... up -d control-plane keycloak` — **not** `docker restart` (it reuses baked-in env and won't re-read `.env`) |
| Clients can't connect after cert change | should not happen (CA-root trust) | confirm clients hold the CA root, not a pinned leaf |
| One account floods issuance | working as designed | per-account rate limit returns `429`; adjust the cap if legitimate |
| Suspected committed secret | credential in a commit | run `./scripts/check-no-secrets.sh`; rotate the exposed secret |
| Channel joins broker-wide stalled/refused; edge log **completely silent** on the broker (no admits, no `channel-join NO`, no handshake errors) while clients keep retrying | wedged broker accept loop (2026-08-13 incident, edge silent 19:12→19:34 UTC). Since **#497/#498** `/healthz` gates on the two QUIC broker-loop heartbeats (beaten every iteration incl. the 10 s idle tick; stale > `BROKER_HEALTH_MAX_AGE_SECS` = 60 s ⇒ 503), so a long-running loop that wedges now turns the container **unhealthy** and Compose restarts it — the "stays healthy forever" mode this row was written for is closed. Documented gap: a loop that wedges **before its first beat**, or never starts (the #103 address-collision non-start), is deliberately still invisible to `/healthz` | mostly self-healing now — Compose restarts the unhealthy edge. If it recurs, or you suspect the before-first-beat gap, or you're on a pre-#498 build: `curl -sf localhost:9600/healthz` (503 names each stale loop + its age), confirm broker silence with `docker logs <edge> --since 10m \| grep -c 'channel'`, recreate the edge, and follow the redeploy-aftermath checklist below |
| Two channel members both look healthy, both park, **never pair**; each reaped after ~30 s; client-side reads as `edge relay refused the channel join` ~32–41 s in | disjoint per-transport pairers ([#495], transport-unification slice still open) — one member came in over `:443`, the other over QUIC | put **both** halves on `CT_CHANNEL_FRONT_DOOR_ONLY=1`; the reap log names channel+holder of the lone member. Within `:443`, #495 slices 1/2a/2b are live (park queue, phase-marked pairing, rendezvous ack-then-close): clients ≥ v0.4.14 pair phase-deterministically (field-proven 2026-08-14, p=0.013 — unmarked members hit an N×10 s retry staircase on ~5/8 of pairings) |
| `[quic-handshake] handshake not completed` flood right after an edge redeploy | since 2026-08-14 ([#496] fixed) the CA is **byte-stable across redeploys** (cert + notAfter persisted beside the key; field-verified identical `/pki/ca` hash across a deliberate restart) — a post-redeploy handshake flood therefore indicates clients that pinned something other than the CA root, not normal churn | confirm `/pki/ca` is unchanged (`sha256sum` before/after); investigate the flooding clients |
| Fresh channel first contacts stall 45–100 s while held sessions are fast | clients older than **ct-agent v0.4.16**: their rendezvous-ack read waits for an EOF the `:443` edge never sends (CADS-Tunnel#494) | upgrade clients to ≥ v0.4.16 (one fixed side heals each pair); edge-side, #495-2b additionally closes marked rendezvous pairs |
| One IP hammering doomed channel joins (`channel-join NO [not-member]` storm) | stale/orphaned client retrying a dead grant | the per-IP penalty (30 definitive refusals/min, 2026-08-13) sheds it pre-handshake automatically; `grep penalty` in the edge log to confirm engagement |

## Redeploy the edge — aftermath checklist

Since 2026-08-14, edge redeploys are **self-healing for Browser-Plane tunnels**: hostname
authorizations rehydrate before the listeners open (#503) from durably recorded ownership
(#502), stale dead TCP-fallback parks are drained instead of bricking delivery (#505), and
≥ v0.4.15 agents retry a refused hostname bind. The 2026-08-13-era duties — serialized agent
restarts, re-running `run-demo.sh` for help — are gone. What remains:

1. **Always deploy with the full flag set** — `./scripts/deploy-selfhost.sh --frontdoor --sso
   --skip-cert`. A flagless invocation recreates the stack WITHOUT the `:443` overlay (front
   door gone, every tunnel down — a ~15-minute full outage on 2026-08-14 came from exactly
   this); `--skip-cert` avoids Let's Encrypt rate-limit exposure. `compose.relay.yml` is
   auto-included when `CT_RELAY_NODE_PEER` is set in `.env`; if you deploy manually, pass every
   overlay the deployment normally runs.
2. **Verify, don't repair**: after the stack reports up, curl each public hostname once
   (200/302 expected within ~30 s as agents reconnect). Pre-v0.4.7 agent binaries are the one
   remaining exception — they cache the edge container IP and never recover (ct-agent#16);
   none should remain deployed.
3. **The CA is byte-stable** across redeploys ([#496] fixed): cert + notAfter persist beside
   the key, `/pki/ca` hashes identically. Announce redeploys to channel operators anyway:
   in-flight sessions drop and their serve loops re-admit (sub-second on ≥ v0.4.16).
4. **Hostname authorization writes go through the control plane** — `POST
   /registry/authorize-host` (#214), never the edge admin API directly: only the CP path
   records the ownership that rehydration replays, and for a hostname owned by a portal
   tunnel the proxy now answers `409` instead of being silently reverted by the Gelb/ACME
   re-authorize loop (#504). The edge's own `/admin/authorize-host` route is the shared
   write primitive underneath — the CP proxy itself calls it, so the edge cannot flag
   direct human use (#513); the guarantees (persistence for rehydration, the #504
   conflict check) exist only on the CP path, which is why humans must never call the
   edge route directly.

[#495]: https://github.com/scimbe/CADS-Tunnel/issues/495
[#496]: https://github.com/scimbe/CADS-Tunnel/issues/496

## Enabling authenticated endpoints

The `/me/*` endpoints (OIDC bearer verification, account derived from the token
subject) are mounted when `CT_OIDC_ISSUER` is set: the control plane fetches the
realm's JWKS at startup and builds the RS256 verifier — no manual key export (#42).
`CT_OIDC_PUBKEY_PATH` (a PEM of the realm's RSA public key) is an optional offline
override and takes precedence when set. With `CT_OIDC_ISSUER` unset the endpoints
are absent (any `/me/*` request → `404`); the unauthenticated billing/webhook flow
works regardless.

### The gate and portal login knobs

Four more variables shape login and the tunnel gate. All were read from the code for this
entry rather than inferred from their names:

| variable | default | meaning |
|---|---|---|
| `CT_OIDC_REALM` | the project's own realm (`ct-demo`) | which Keycloak realm the admin client works against (`keycloak_admin.rs`); an empty value falls back to the default rather than to an empty realm name |
| `CT_GATE_COOKIE_DOMAIN` | unset | the gate's session-cookie domain, set to the zone so **one** login covers every `*.<zone>` subdomain. **Until it is set, every gate handler answers `503`** — the gate is opt-in-until-configured, not silently open |
| `CT_GATE_REDIRECT_URI` | derived | the gate's OIDC redirect target. Unset, it is the portal's `redirect_uri` with `/portal/callback` swapped for `/gate/callback` — correct whenever both live on the same host, so it usually needs no value at all |
| `CT_PORTAL_SOCIAL_PROVIDERS` | unset ⇒ **none shown** | comma-separated allowlist (`google`, `github`) of social-login buttons on the logged-out portal |

Two things worth knowing before touching them:

- **`CT_GATE_COOKIE_DOMAIN` unset means the gate refuses, not that it waves traffic through.**
  A `503` from `/gate/*` on a fresh deployment is that state, not a fault.
- **Listing a social provider does not create it.** The buttons are gated on this variable, but
  each provider must also exist in the Keycloak realm. On 2026-08-02 both buttons led to a raw
  502 because the realm's `google`/`github` entries were absent — the allowlist advertised a
  login path that did not exist. Add the provider in the realm first, then to this list.

### The control plane's two background loops

Both are **off unless switched on**, and both are switched on by the literal `1`:

| variable | default | meaning |
|---|---|---|
| `CT_CP_ACME_BROKER_ENABLED` | off | the Rot/Gelb/Grün certificate-admission broker. A deployment that never sets it simply never promotes a tunnel past Rot — turning the feature on is a deliberate operator action, not a side effect of upgrading |
| `CT_CP_ACME_BROKER_TICK_SECS` | `60` | how often that broker runs |
| `CT_CP_DIRECT_PROBE` | off | the direct-serving reachability probe (#517 V3, slice 3). It **only probes and records** the hysteresis state — no DNS is touched, so enabling it changes no live routing; it makes the probe decisions observable before a later slice wires them to records |
| `CT_CP_DIRECT_PROBE_TICK_SECS` | `30` | how often that probe runs |

**Only the exact string `1` counts.** `true`, `yes` and `on` leave the loop off, silently — the
vocabulary differs from the flood-control limits, which do accept `off`/`false`/`none` as an
opt-out. Do not assume one convention covers both.

Because a mistyped value fails quietly, **confirm from the log rather than from the
environment**: each loop prints one line at startup when it is on
(`ct-cp: acme_broker …`, `ct-cp: direct-serving reachability probe loop ON (…s, CT_CP_DIRECT_PROBE)`).
No line means off — whether that was intended or a typo.

Current deployment (checked 2026-08-17): broker **on** at the 60 s default, direct probe
**off**.

## Escalation & scope

Availability against a **funded** abuser and censorship/lawful-process handling
are operational/jurisdictional, not covered by the software — see
[SPEC §9](../SPEC.md) and the [threat model](../security/threat-model.md).

## Edge-Wächter (`scripts/edge-watch.sh`)

Läuft per Cron alle 10 Minuten und meldet sich nur bei einer Störung — geprüft wird der
**laufende** Edge, nicht die Konfiguration:

| Signal | Anlass |
|---|---|
| Container weg / nicht laufend / Neustartzähler gestiegen | verlässliches Down-Signal |
| `/healthz` antwortet nicht oder meldet Fehler | hängender Prozess; seit #539 auch „vorgesehener Broker-Loop nie angelaufen" |
| Park-Gauge > 80 | #522: Leichen sammeln sich, TCP-Park-Reaper arbeitet nicht mehr |
| `refused-111`-Signatur im Log (15-Minuten-Fenster) | #522: Auslieferung an einen toten Park |
| Broker-Loop-Schlag älter als 60 s | Channel-Joins über diesen Transport bleiben stehen |
| Ein kanonischer Hostname liefert nicht seinen erwarteten Code | verlorener Hostname-Anspruch (#502), Agent mit veralteter Edge-IP, fehlgeschlagene Rehydrierung |
| Portal (`bunsenbrenner.org/`) oder Keycloak-**Realm** (`auth…/realms/ct-demo`) antwortet falsch | die beiden Kernadressen; der Realm-Pfad ist bewusst gewählt (siehe unten) |

Zwei Entwurfsentscheidungen, beide aus Fehlschlägen gelernt:

- **Ein fehlgeschlagenes `docker exec` ist kein Down-Signal.** Der Vorgänger hat damit
  zweimal bei gesundem Edge fehlgefeuert; maßgeblich ist `State.Running` bzw. der
  Neustartzähler.
- **Antwortet die Sonde nicht, obwohl der Container läuft, ist das ein Befund** und kein
  Grund zu schweigen. Eine Prüfung, die nicht laufen konnte, darf nicht wie eine bestandene
  aussehen.

Die Dienstprüfung ist bewusst der wichtigste Punkt der Liste: Die Zeilen darüber prüfen den
**Prozess**, und jeder reale Ausfall dieses Betriebs hat den Edge gesund gelassen und die
Tunnel totgelegt. Zwei Vorkehrungen gegen Falschalarme, beide aus Fehlern gelernt:

- **Kein Urteil im Rehydrations-Fenster.** Lief der Edge weniger als 90 s, wird nicht
  geprüft — und das wird ausdrücklich gesagt („das ist kein Freispruch"), statt still
  übersprungen zu werden.
- **Zwei Durchgänge mit 30 s Abstand statt einer Salve.** Nur was beide Male fällt, ist ein
  Alarm; dichtes Nachfassen hat am 15.08. einen 70-Prozent-Ausfall vollständig verdeckt.

**Warum die Realm-URL und nicht die Keycloak-Startseite:** gemessen am 17.08. antwortet
`auth.bunsenbrenner.org/` mit 302, `…/realms/ct-demo` mit 200 und ein nicht existierender
Realm mit 404. Nur der Realm-Pfad unterscheidet also den Fall, der hier tatsächlich eingetreten
ist — am 16.08. lag die Auth-Ebene ~6 Minuten, weil die Realm-Importdatei den Start verhinderte.
Eine Sonde auf die Startseite hätte dabei geschwiegen.

**Der Hinweistext richtet sich auch nach der ART des Fehlschlags**, nicht nur nach der
Adresse — der Unterschied entscheidet, wo man sucht:

| beobachtet | Bedeutung | wo suchen |
|---|---|---|
| `000` | keine Antwort | Transportebene: Hostname-Anspruch, Agent mit veralteter Edge-IP, fehlgeschlagene Rehydrierung |
| `5xx` | der Tunnel hat **zugestellt**, der Origin meldet einen Fehler | beim Dienst hinter dem Agenten — der gehört oft einem Peer, nicht diesem Host |
| sonstige Abweichung | weder Transport noch Origin | meist geänderte Weiterleitung oder Login-Gate; erwarteten Wert prüfen |

Am 17.08. um 06:00 schlug der Wächter zum ersten Mal echt an: `llm-34a13a96` lieferte zweimal
im Abstand von 30 s eine `500`. Der damalige Hinweis riet zu Tunnel-Ursachen — die erzeugen
aber eine `000` und niemals eine `500`. Wer daraufhin am Tunnel gesucht hätte, hätte an der
falschen Stelle gesucht; daher die Aufschlüsselung oben.

**Der Hinweistext richtet sich außerdem nach der Klasse der Adresse.** Fällt eine Kernadresse, verweist die Meldung
auf Keycloak-Start und Realm-Import; fällt ein Demo-Tunnel, auf Hostname-Anspruch, Agent-IP und
Rehydrierung. Ein Hinweis, der bei einem Keycloak-Ausfall nach dem Hostname-Anspruch suchen
lässt, schickt in die falsche Richtung und ist schlechter als gar keiner.

Ein sinkender Neustartzähler gilt als Deploy (der Container wurde neu erzeugt) und setzt nur
den Bezugspunkt neu. Gleiche Meldungen werden für 6 Stunden nicht erneut gemailt; Logzeile
und Exit-Code bleiben davon unberührt.

    tail /var/tmp/cads-edge-watch/cron.log     # Verlauf
    ./scripts/edge-watch.sh                    # von Hand, Exit 0 = still
