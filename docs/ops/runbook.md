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
redirect-only `:80` that 308-bounces plain `http://<zone>/` to `https` (#66). Point
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

```bash
kubectl kustomize docker/deploy/k8s   # review
kubectl apply -k docker/deploy/k8s
```

Deploys into namespace `ct-system`: control plane (PVC-backed, liveness/readiness
probes), edge (LoadBalancer UDP+TCP), and a TLS-terminating ingress.

## Configuration

| Variable | Component | Purpose |
|----------|-----------|---------|
| `CT_CONTROL_PLANE_LISTEN` | control plane | bind address (default `0.0.0.0:8090`) |
| `CT_CONTROL_PLANE_DB` | control plane | SQLite path (put it on durable storage) |
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
```

It authorizes `<hostname>` at the edge (via the public, admin-gated `POST
/registry/authorize-host/:token/:host`, #214 — no loopback access needed) and,
if `[tenant]` is given, mints a single-use join token too. It prints a
`CT_AGENT_TOKEN` (the routing token) and, if minted, the join token response —
**relay both to the pipeline maintainer out of band**, never to GitHub. They
onboard with:

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

## Incident response

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `/readyz` returns 503 | DB unreachable / volume detached | check the `cpdata` volume mount; restart once storage is back |
| All webhooks `401` | wrong/blank `CT_PAYMENT_WEBHOOK_SECRET` | set it to match the provider; restart |
| Portal SSO login `502 sign-in failed` right after a successful Keycloak login | `KC_PORTAL_CLIENT_SECRET` unset, or `.env` change not picked up (#65) | set `KC_PORTAL_CLIENT_SECRET` in `.env`; check `docker compose logs control-plane` for `OIDC code exchange failed`; recreate with `docker compose ... up -d control-plane keycloak` — **not** `docker restart` (it reuses baked-in env and won't re-read `.env`) |
| Clients can't connect after cert change | should not happen (CA-root trust) | confirm clients hold the CA root, not a pinned leaf |
| One account floods issuance | working as designed | per-account rate limit returns `429`; adjust the cap if legitimate |
| Suspected committed secret | credential in a commit | run `./scripts/check-no-secrets.sh`; rotate the exposed secret |

## Enabling authenticated endpoints

The `/me/*` endpoints (OIDC bearer verification, account derived from the token
subject) are mounted when `CT_OIDC_ISSUER` is set: the control plane fetches the
realm's JWKS at startup and builds the RS256 verifier — no manual key export (#42).
`CT_OIDC_PUBKEY_PATH` (a PEM of the realm's RSA public key) is an optional offline
override and takes precedence when set. With `CT_OIDC_ISSUER` unset the endpoints
are absent (any `/me/*` request → `404`); the unauthenticated billing/webhook flow
works regardless.

## Escalation & scope

Availability against a **funded** abuser and censorship/lawful-process handling
are operational/jurisdictional, not covered by the software — see
[SPEC §9](../SPEC.md) and the [threat model](../security/threat-model.md).
