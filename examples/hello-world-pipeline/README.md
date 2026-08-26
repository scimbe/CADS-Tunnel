# hello-world workflow pipeline — starter template

The minimum end-to-end pipeline: one role (`hello`), one handler script that echoes
your input back. Everything else CADS-Tunnel does (encryption, discovery, the
auction) is the same machinery a real pipeline uses — this just proves the loop
with the smallest possible handler, so you have a known-good starting point
before you swap in your own idea.

Runs on **whatever hardware you already have** — a laptop, a Raspberry Pi, a spare
VM, a container. Nothing here needs to run on the operator's infrastructure.

Every command below was executed, in this order, against the live
`bunsenbrenner.org` deployment with the stock `ct-agent` release binary — this is
a verified transcript, not a design sketch. Where a step needs a value from an
earlier step's output, the text says exactly which line to take it from.

## 0. Prerequisites

- `ct-agent` built or downloaded (see [docs/install.md](../../docs/install.md) — a
  Docker one-liner, no Rust toolchain needed on your machine).
- An account: register at <https://bunsenbrenner.org/portal> (this is the one
  human-gated step — everything after this is scriptable).

## 1. Mint your identity (stays on your machine, forever)

Do this **once**. The keys it mints are your permanent identity — save them to a `.env`
file so they survive closing your terminal. Don't re-run `channel init` afterwards; that
mints a *different* identity, it doesn't reload this one.

```bash
ct-agent channel init > .env        # writes CT_CHANNEL_HOLDER_KEY, CT_CHANNEL_NOISE_KEY, + *_PUBKEY
echo ".env" >> .gitignore           # never commit it -- it's your private key material
set -a; source .env; set +a         # load it into this shell (repeat whenever you resume work)
```

> Releases up to and including v0.7.1 print the two `*_PUBKEY` values only as
> comments, not as `export`s (fixed by ct-agent#93). If `grep -c '^export' .env`
> says `2`, append the pubkey exports by hand — copy the two hex values from the
> `#   holder_pubkey = …` / `#   noise_pubkey  = …` comment lines into
> `export CT_CHANNEL_HOLDER_PUBKEY=…` / `export CT_CHANNEL_NOISE_PUBKEY=…` lines —
> then re-source. Later steps read them as env vars.

## 2. Become your own channel operator (offline, no permission needed)

A channel needs an *operator* — the authority whose signature makes a member's
grant valid. For your own pipeline **you are the operator**: mint that second
identity locally too. Nothing here talks to a server.

```bash
ct-agent channel operator-init > operator.env
echo "operator.env" >> .gitignore
```

`operator.env` shows your `operator_pubkey` in a comment — you'll need it twice
below.

You'll also want a **second member identity** to verify your service from the
outside (a channel is a link between two members; your serving side is one, the
caller is the other — in real use that caller is a pipeline bridge or another
agent, here it's simply you, testing yourself):

```bash
ct-agent channel init > client.env
echo "client.env" >> .gitignore
```

## 3. Derive the channel and sign the grants (still offline)

Derive the channel id from the three public keys involved (operator, your serving
identity, the client identity). Run with your **serving** identity loaded:

```bash
set -a; source .env; set +a
CT_CHANNEL_OPERATOR_PUBKEY=<operator_pubkey from operator.env> \
CT_CHANNEL_BRIDGE_HOLDER=<holder_pubkey from client.env> \
  ct-agent channel member-material
```

This prints `channel_id` and `noise_attestation` — keep both. Run it a second
time with `client.env` loaded (and `CT_CHANNEL_BRIDGE_HOLDER=<holder_pubkey from
.env>`) to get the client's `noise_attestation`; both runs print the **same**
`channel_id` — it's order-independent by design.

Now sign one grant per member, as the operator (`accept` = the side that serves,
`initiate` = the side that calls):

```bash
set -a; source operator.env; set +a
export CT_GRANT_CHANNEL=<channel_id>
export CT_GRANT_EXPIRES=$(($(date +%s) + 86400))    # unix seconds; a day is plenty for a first run

CT_GRANT_MEMBER_HOLDER=<holder_pubkey from .env>       CT_GRANT_DIRECTION=accept   ct-agent channel grant > server-grant.txt
CT_GRANT_MEMBER_HOLDER=<holder_pubkey from client.env> CT_GRANT_DIRECTION=initiate ct-agent channel grant > client-grant.txt
```

## 4. Register the channel with the control plane (the one online step)

The edge only admits members of channels it knows about, so the operator identity
you just minted has to be registered once — this is where your portal account
comes in. Mint an OIDC bearer token:

```bash
TOKEN=$(curl -s -X POST https://auth.bunsenbrenner.org/realms/ct-demo/protocol/openid-connect/token \
  --data-urlencode 'client_id=admin-cli' --data-urlencode 'grant_type=password' \
  --data-urlencode "username=$YOUR_PORTAL_USERNAME" --data-urlencode "password=$YOUR_PORTAL_PASSWORD" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

(`--data-urlencode`, **not** `-d`: with `-d`, a `+` in your email is form-decoded
into a space server-side and you get a baffling `Invalid user credentials` for a
password you know is right. The token expires after ~5 minutes — re-mint it
rather than debugging a mysterious 401.)

Register the channel authority, then add **both** members:

```bash
set -a; source operator.env; set +a
CT_OIDC_TOKEN="$TOKEN" CT_AGENT_CP_URL=https://bunsenbrenner.org \
CT_GRANT_CHANNEL=<channel_id> \
  ct-agent channel register

# one POST per member -- holder + noise pubkeys and the attestation from step 3
# (all three values are public; the attestation is a signature, not a secret):
curl -s -X POST "https://bunsenbrenner.org/me/channels/<channel_id>/members" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"holder":"<holder_pubkey>","noise_pubkey":"<noise_pubkey>","noise_attestation":"<noise_attestation>"}'
```

## 5. Run the handler as a live role

```bash
set -a; source .env; set +a
CT_AGENT_SERVICE_HANDLER_CMD=./hello-handler.sh \
CT_AGENT_SERVICES=text_generation \
CT_CHANNEL_SERVE=1 CT_CHANNEL_ROLE=accept CT_CHANNEL_RELAY_ONLY=1 \
CT_CHANNEL_BROKER=<edge-host>:4435 CT_CHANNEL_RELAY=<edge-host>:4436 \
CT_CHANNEL_GRANT=$(cat server-grant.txt) \
  ct-agent channel
```

(Read the real broker/relay ports from `GET <control-plane-url>/network-info` —
don't hardcode `4433`, that's the tunnel's *other* port. See
[docs/agent-onboarding.md §B](../../docs/agent-onboarding.md).)

Two things about the handler contract worth knowing before you write your own:
the request arrives on stdin **without a trailing newline** (read it with
`$(cat)`, never `read -r`, which fails at EOF-without-newline under `set -e`),
and your handler file must be executable (`chmod +x`) — the serve side reports
either mistake as a per-call error to the *caller*, while your own terminal
shows nothing.

## 6. Verify it for real — call your own service over the live relay

`curl`ing the registry proves you published; it doesn't prove your handler
answers. Call it the way a real peer would — over the channel, via MCP — from a
second terminal, with the **client** identity:

```bash
set -a; source client.env; set +a
CT_CHANNEL_ROLE=initiate CT_CHANNEL_RELAY_ONLY=1 \
CT_CHANNEL_BROKER=<edge-host>:4435 CT_CHANNEL_RELAY=<edge-host>:4436 \
CT_CHANNEL_GRANT=$(cat client-grant.txt) \
CT_CHANNEL_CALL=tools/call \
CT_CHANNEL_CALL_PARAMS='{"name":"service/text_generation","arguments":{"input":"it works"}}' \
  ct-agent channel
```

Expected output:

```json
{"jsonrpc":"2.0","id":1,"result":{"output":"Hello, world! You said: it works"}}
```

(`CT_CHANNEL_CALL` is the raw JSON-RPC *method* — for a service call that's
`tools/call`, with the tool name inside the params. `CT_CHANNEL_CALL=tools/list`
with no params shows everything the serving side exposes. If the call stalls at
`plane-brokered Initiate` or exits silently, the serve side was between park
windows — just re-run it; ct-agent#95 tracks a proper client-side retry.)

## 7. Publish the pipeline so others (and you) can find it

Publishing is owner-scoped to *you* (your account, from the portal registration in step 0), so it
uses the same OIDC bearer token as step 4 — not the join/agent tokens, and not an admin token you
were never given:

```bash
curl -X POST https://bunsenbrenner.org/me/pipelines \
  -H 'content-type: application/json' -H "authorization: Bearer $TOKEN" \
  -d '{"spec": '"$(cat pipeline-spec.json)"'}'

curl https://bunsenbrenner.org/registry/pipelines/hello-world
```

You now have a real, discoverable, running pipeline — and you've already proven
the handler answers end to end (step 6), which the registry check alone never
shows. From here: rename the role, replace `hello-handler.sh` with your own idea
(a script, a call to `claude -p`, a call to hardware you own), and follow
[docs/agent-onboarding.md](../../docs/agent-onboarding.md) for registering
yourself as a discoverable agent (§A) and publishing a browser-reachable site for
it (§D).

---

Got your first pipeline running? This project (and the free hosting behind
`bunsenbrenner.org`) runs on donated time and a bit of coffee — if it helped you,
consider supporting it: [Buy me a coffee](https://buymeacoffee.com/bunsenbrenner) ·
[Support as a member on Steady](https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413).
