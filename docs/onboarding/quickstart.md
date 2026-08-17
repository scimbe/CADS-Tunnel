# Agent onboarding — quickstart

Bring a tunnel agent online in **one command**. The operator handles a single
secret (a single-use join token); the agent generates its own identity, enrolls
itself, and starts tunnelling. The private key never leaves the agent, and the
data path stays end-to-end encrypted (Noise) — the operator can route your
traffic but cannot read it.

## What you need

- The **control-plane URL** (from the hosted portal, or your self-hosted
  deployment — e.g. `https://cp.example.com`).
- A **tenant** name you enroll under.
- The `ct-agent` binary — its own repo, [scimbe/ct-agent](https://github.com/scimbe/ct-agent).
- The address of the **edge** to dial and the **local origin** service you want
  to expose.

## Step 1 — issue a single-use join token (operator / portal)

The portal does this for you. To do it by hand, ask the control plane to mint a
token for your tenant — `/enroll/issue` is admin-token gated (the same
`CT_CP_EDGE_ADMIN_TOKEN` the edge/operator already hold), confirmed live: a call
without it returns `401`, not a token:

```bash
curl -sS -X POST "$CP_URL/enroll/issue" \
  -H 'content-type: application/json' \
  -H "x-ct-admin-token: $CT_CP_EDGE_ADMIN_TOKEN" \
  -d '{"tenant":"my-tenant"}'
# => {"token":"<64 hex chars>"}
```

The token is **single-use**: it enrolls exactly one agent and cannot be reused.

## Step 2 — onboard the agent (one command)

Point the agent at the control plane and hand it the token. It generates a fresh
identity, redeems the token (binding its public key to your tenant), and serves
the tunnel:

```bash
CT_AGENT_CP_URL="$CP_URL" \
CT_AGENT_JOIN_TOKEN="<token from step 1>" \
CT_AGENT_ID="agent-1" \
CT_AGENT_EDGE="edge.example.com:4433" \
CT_AGENT_ORIGIN="127.0.0.1:8080" \
  ct-agent onboard
# => ct-agent: onboarded agent=agent-1 tenant=my-tenant via https://cp.example.com (edge=...)
```

That's it — install → enroll → tunnel in a single step. Setting
`CT_AGENT_JOIN_TOKEN` alone also triggers onboarding, so the explicit `onboard`
argument is optional.

## Optional knobs

| Variable | Default | Purpose |
|----------|---------|---------|
| `CT_AGENT_ORIGIN_PROTO` | `tcp` | Origin transport (`tcp` or `udp`). |
| `CT_AGENT_DIRECT_ADVERTISE` | unset | IP to advertise for a direct P2P path (bypasses the relay). |
| `CT_AGENT_METRICS_LISTEN` | unset | Address to serve Prometheus `/metrics` on. |
| `CT_AGENT_EDGE_CERT` | `/shared/edge-cert.der` | Path to the edge CA certificate. |
| `CT_AGENT_FALLBACK_443` | `false` | If the configured edge port is blocked, also try the edge's unified `:443` front door (TLS-TCP, `ALPN=ct-edge`) (#46). |
| `CT_AGENT_RECONNECT_MAX_ATTEMPTS` | **unbounded** | Reconnect attempts before the agent exits. **The default is retry-forever, not `10`** — that was the pre-#36 default and it caused a real multi-hour outage: `sort.bunsenbrenner.org`'s agent burned its 10-attempt budget (≈2 minutes of backoff) during an edge redeploy that took longer, exited, and stayed dead until a human restarted it. An onboarded agent *is* the tunnel, so exiting takes the service down permanently rather than failing over to anything; a supervisor cannot heal it either, because the single-use join token is already spent. Set an explicit count only for short-lived or scripted runs where failing fast is genuinely better than waiting; `0` also means retry forever. |
| `CT_AGENT_RECONNECT_BASE_MS` | `500` | First reconnect delay in milliseconds; raised to a `100`ms floor if set lower. Each retry applies equal jitter (uniform in `[d/2, d]`) so a fleet coming back from one edge restart does not resynchronise into a thundering herd. |
| `CT_AGENT_RECONNECT_MAX_MS` | `30000` | Cap on the reconnect delay. Raised to the effective base if set below it, so the pair can never describe a cap that sits under the first delay. Unset/empty/unparsable values fall back to the default rather than to some third behaviour — a typo must not change the timing silently. |
| `CT_AGENT_STATE_DIR` | unset | Persist the bound identity/tenant to this directory after the first onboard, so a container restart **restores** it instead of re-redeeming the (now-spent) single-use join token (#141). Point it at a durable volume for restart-safe deployments; unset ⇒ every boot redeems again. |

`CT_AGENT_EDGE` and `CT_AGENT_ORIGIN` accept either `IP:port` or `host:port` — a
hostname (e.g. a Compose service name) is resolved via DNS (#45).

## What just happened

1. The agent generated an ed25519 identity locally — only the **public** key was
   sent to the control plane.
2. It redeemed the join token, which **bound that public key to your tenant**.
   The token is now spent.
3. It began serving your origin through the tunnel; payload bytes are encrypted
   end-to-end, so the edge and control plane only ever see ciphertext.
