# hello-world workflow pipeline — starter template

The minimum end-to-end pipeline: one role (`hello`), one handler script that echoes
your input back. Everything else CADS-Tunnel does (encryption, discovery, the
auction) is the same machinery a real pipeline uses — this just proves the loop
with the smallest possible handler, so you have a known-good starting point
before you swap in your own idea.

Runs on **whatever hardware you already have** — a laptop, a Raspberry Pi, a spare
VM, a container. Nothing here needs to run on the operator's infrastructure.

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

`.env` now holds lines shaped like this (yours will be full-length hex, not this example):

```
CT_CHANNEL_HOLDER_KEY=7f3ad2e1...redacted...
CT_CHANNEL_NOISE_KEY=4b91c08a...redacted...
CT_CHANNEL_HOLDER_PUBKEY=a02c9e7f...redacted...
CT_CHANNEL_NOISE_PUBKEY=e615b3d4...redacted...
```

## 2. Run the handler as a live role

```bash
CT_AGENT_SERVICE_HANDLER_CMD=./hello-handler.sh \
CT_AGENT_SERVICES=text_generation \
CT_CHANNEL_SERVE=1 CT_CHANNEL_ROLE=accept CT_CHANNEL_RELAY_ONLY=1 \
CT_CHANNEL_BROKER=<edge-host>:4435 CT_CHANNEL_RELAY=<edge-host>:4436 \
  ct-agent channel
```

(`ct-agent` reads the real broker/relay ports from `GET <control-plane-url>/network-info` —
don't hardcode `4433`, that's the tunnel's *other* port. See
[docs/agent-onboarding.md §B](../../docs/agent-onboarding.md).)

## 3. Publish the pipeline so others (and you) can find it

Publishing is owner-scoped to *you* (your account, from the portal registration in step 0), so it
needs your OIDC bearer token — not the join/agent tokens from step 1, and not an admin token you
were never given. Mint one from the account you registered at the portal:

```bash
TOKEN=$(curl -s -X POST https://auth.bunsenbrenner.org/realms/ct-demo/protocol/openid-connect/token \
  -d 'client_id=admin-cli' -d 'grant_type=password' \
  -d "username=$YOUR_PORTAL_USERNAME" -d "password=$YOUR_PORTAL_PASSWORD" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -X POST https://bunsenbrenner.org/me/pipelines \
  -H 'content-type: application/json' -H "authorization: Bearer $TOKEN" \
  -d '{"spec": '"$(cat pipeline-spec.json)"'}'
```

## 4. Verify

```bash
curl https://bunsenbrenner.org/registry/pipelines/hello-world
```

You now have a real, discoverable, running pipeline. From here: rename the role,
replace `hello-handler.sh` with your own idea (a script, a call to `claude -p`, a
call to hardware you own), and follow
[docs/agent-onboarding.md](../../docs/agent-onboarding.md) for registering
yourself as a discoverable agent (§A) and publishing a browser-reachable site for
it (§D).

---

Got your first pipeline running? This project (and the free hosting behind
`bunsenbrenner.org`) runs on donated time and a bit of coffee — if it helped you,
consider supporting it: [Buy me a coffee](https://buymeacoffee.com/bunsenbrenner) ·
[Support as a member on Steady](https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413).
