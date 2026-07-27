# Demo: `https://help.bunsenbrenner.org` through the Browser Plane

A single-page overview of the project that links to the (LLM-generated) BA thesis,
served **through a CADS-Tunnel demo tunnel** with a **publicly-trusted HTTPS
certificate** — an end-to-end demo of the Browser Plane (#23) + deSEC DNS-01 (#31).

## How it works (payload-blind, cert at the origin)
```
Browser ──TLS(SNI=help.bunsenbrenner.org)──▶ Plane edge :443 (SNI passthrough, blind)
                                                   │ host → routing token
                                                   ▼
                                          ct-agent (browser mode) ──raw TLS──▶ Caddy origin
                                                                               (terminates TLS,
                                                                                LE cert via deSEC DNS-01,
                                                                                serves index.html)
```
The edge never sees plaintext — TLS terminates at the Caddy **origin**, which holds
the Let's Encrypt certificate. Caddy gets that cert itself via **DNS-01 against
deSEC**, so this demo does **not** depend on the in-tree ACME work (#31 FD4) yet.

## Prerequisites (the transition setup)
1. **DNS**: `help.bunsenbrenner.org` (and `A *.bunsenbrenner.org` / the apex)
   resolves to the plane IP. During the deSEC transition, host the zone at deSEC
   (`ns1.desec.io` / `ns2.desec.org`) — see `docs/dns01-desec.md`.
2. **deSEC token** in `docker/deploy/.env` (`DESEC_TOKEN=...`), scoped to
   `_acme-challenge*` if possible.
3. A **running plane**: `ct-edge` with `CT_EDGE_BROWSER_LISTEN=0.0.0.0:443`, and a
   `ct-control-plane` to onboard the agent against. `:443` open inbound on the host.

## Deploy — one command (central/agent, on the plane)
With the plane already running (ct-edge + ct-control-plane) and `DESEC_TOKEN` in
`docker/deploy/.env`, the driver mints the join token, brings up the origin +
agent, and waits until the page is served over HTTPS:
```bash
# on the plane host:
examples/help-site/run-demo.sh
# override targets if needed:
CP_URL=http://127.0.0.1:8090 EDGE=127.0.0.1:4433 examples/help-site/run-demo.sh
```
It prints `✓ LIVE` when `https://help.bunsenbrenner.org/` serves the demo with a
valid certificate, or actionable hints (DNS / cert / agent / edge) if not.

### With hostname authorization on a public `:443` (recommended, #23 BP4b)
Before exposing `:443`, enable authorization on the edge and give the control
plane's admin config to the driver — it then authorizes `help.` and pins the
agent's routing token so the bind is accepted:
```bash
# edge:  CT_EDGE_REQUIRE_HOST_AUTH=1  CT_EDGE_ADMIN_TOKEN=<64-hex>  CT_EDGE_ADMIN_LISTEN=127.0.0.1:9443
# in docker/deploy/.env (same values the control plane uses):
#   CT_CP_EDGE_ADMIN_URL=http://127.0.0.1:9443
#   CT_CP_EDGE_ADMIN_TOKEN=<same 64-hex as CT_EDGE_ADMIN_TOKEN>
examples/help-site/run-demo.sh    # authorizes help. at the edge, then deploys
```
Without those vars the driver falls back to the BP4a-only path (takeover-safe;
fine for a single hostname, but leave `CT_EDGE_REQUIRE_HOST_AUTH` **off** then).

### Manual (equivalent)
```bash
# mint a single-use join token from the control plane:
TOKEN=$(curl -fsS -X POST http://127.0.0.1:8090/enroll/issue \
          -H 'content-type: application/json' -d '{"tenant":"help-demo"}' \
          | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p')
HELP_JOIN_TOKEN=$TOKEN HELP_AGENT_EDGE=127.0.0.1:4433 HELP_AGENT_CP_URL=http://127.0.0.1:8090 \
  docker compose -f examples/help-site/compose.help-site.yml --env-file docker/deploy/.env up --build -d
```

## Verify it's retrievable
```bash
# real cert, no --cacert needed:
curl -v https://help.bunsenbrenner.org/ | head
# or open it in a browser — a normal HTTPS page, no warning.
```
First load may take a moment while Caddy completes the DNS-01 challenge (deSEC
propagation). While testing, uncomment the staging CA line in `Caddyfile` to avoid
Let's Encrypt rate limits, then switch to production once it works.

> Tuning note: this demo terminates TLS at the origin (payload-blind). It is the
> Browser Plane's intended shape; the unified `:443` gateway (#31) additionally
> multiplexes the operator portal on the same port.
