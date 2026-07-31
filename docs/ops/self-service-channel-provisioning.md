# Self-service Agent-Fabric channel provisioning (#117)

The concrete, end-to-end procedure for provisioning a pairwise Agent-Fabric link
channel — e.g. a pipeline bridge dialing a role-serving agent — without any
operator relay of secret material. Everything below was actually executed against
the live `bunsenbrenner.org` deployment while wiring flappy-demo/cookbook-demo's
crew roles; see `scripts/channel-ops/` for the scripts this doc walks through.

This is the concrete companion to `docs/agent-onboarding.md` §B/§C (which describes
the mechanism in the abstract) — read that first if you want the full design
rationale; this doc is the realistic runbook.

## Prerequisites

- `ct-agent` on `PATH`, or extracted from a built image (`docker cp` the binary out
  — see "No Rust toolchain?" below) and invoked directly. `channel init`,
  `channel operator-init`, `channel member-material`, and `channel grant` are all
  **pure local compute** — no network calls, no CP/edge round-trip.
- An OIDC account on the deployment's realm (self-register via the realm's public
  signup if your email domain is allowed, or ask the maintainer). This is the one
  human-gated step (#117's honesty note).
- `curl`, `python3` (used for safe JSON encode/decode throughout — never hand-rolled
  string concatenation into JSON, matching this repo's #199 convention).

### No Rust toolchain? Extract `ct-agent` from an already-built image

If a workspace image already exists on the host (e.g. a demo's `flappy-agent`
image), you don't need to build `ct-agent` from source to run the local-compute
subcommands:

```bash
CID=$(docker create <image-with-ct-agent> true)
docker cp "$CID:/usr/local/bin/ct-agent" ./ct-agent
docker rm "$CID" >/dev/null
chmod +x ./ct-agent
```

**Do not** invoke these subcommands as `docker run --rm <image> ct-agent ...` with
env vars set as a shell prefix — `docker run` does **not** forward host-shell
environment variables into the container (needs explicit `-e VAR` flags), so
`CT_CHANNEL_OPERATOR_PUBKEY` etc. silently never reach the process. Extract the
binary and run it natively instead; it's a small, self-contained static-ish binary.

## Step 1 — mint an OIDC bearer token

```bash
OIDC_ISSUER_BASE=https://auth.<zone>/realms/<realm> \
OIDC_USERNAME=you@example.com \
OIDC_PASSWORD='...' \
  ./scripts/channel-ops/mint-oidc-token.sh
```

Prints the bare `access_token` to stdout. **Short-lived** (a Keycloak realm default
is minutes) — mint fresh for each provisioning batch rather than caching it across
a long session. `client_id` defaults to `admin-cli` (the public client
`docs/agent-onboarding.md` §A.2 documents for headless token minting via
`grant_type=password`).

## Step 2 — mint an operator identity (once)

```bash
ct-agent channel operator-init
# prints: operator_pubkey = <64-hex>
#         export CT_CHANNEL_OPERATOR_KEY=<64-hex, PRIVATE, keep secret>
```

You do **not** need the deployment's existing/shared operator identity — mint your
own. The channel-registration endpoint (`POST /me/channels`) only ever needs the
operator's **public** key; ownership of the channel is proven by your OIDC bearer
token, not by possessing any particular operator private key. Keep
`CT_CHANNEL_OPERATOR_KEY` local — it never needs to leave this host.

## Step 3 — provision one link channel per role

Each side of the link needs a channel identity from `ct-agent channel init`
(prints both private keys **and** both public keys — keep the full block, you need
the noise **public** key later and `ct-agent` has no separate
"derive-pubkey-from-private" subcommand):

```bash
ct-agent channel init
# holder_pubkey = ...   noise_pubkey = ...
# export CT_CHANNEL_HOLDER_KEY=...
# export CT_CHANNEL_NOISE_KEY=...
```

Do this once per side (e.g. once for the bridge that dials, once for the agent
that serves the role), then provision the pairwise channel:

```bash
CT_AGENT_CP_URL=https://<zone> \
OIDC_TOKEN=$(./scripts/channel-ops/mint-oidc-token.sh ...) \
OPERATOR_KEY=<from step 2>   OPERATOR_PUBKEY=<from step 2> \
SIDE_A_NAME=bridge \
  SIDE_A_HOLDER_KEY=<side A priv>  SIDE_A_NOISE_KEY=<side A priv>  SIDE_A_NOISE_PUBKEY=<side A pub> \
SIDE_B_NAME=serve \
  SIDE_B_HOLDER_KEY=<side B priv>  SIDE_B_NOISE_KEY=<side B priv>  SIDE_B_NOISE_PUBKEY=<side B pub> \
  ./scripts/channel-ops/provision-link-channel.sh
```

This derives the (order-independent) `channel_id` via `channel_id_for_link` and
each side's Noise attestation via `member_noise_attest_bytes` — both through
`ct-agent channel member-material`, never hand-rolled — then:

1. `POST /me/channels` `{channel, operator_pubkey}` (a 409 on retry is fine, not fatal).
2. `POST /me/channels/:channel/members` for both sides (same — 409 on retry is fine).
3. `ct-agent channel grant` twice, locally, signing an `initiate`-direction grant for
   side A and an `accept`-direction grant for side B.

Prints `CHANNEL_ID=...`, `<SIDE_A_NAME>_GRANT=...`, `<SIDE_B_NAME>_GRANT=...`.

## Step 4 — bring up a serve process for the accepting side

```bash
CT_AGENT_EDGE_BROKER=<edge host>:4435   CT_AGENT_EDGE_RELAY=<edge host>:4436 \
HOLDER_KEY=<accept side priv>   NOISE_KEY=<accept side priv> \
GRANT=<the accept-direction grant from step 3> \
SERVICE=text_generation   HANDLER_CMD=/path/to/role-handler.sh \
  ./scripts/channel-ops/serve-role.sh
```

`4435`/`4436` are the channel broker/relay ports (`GET /network-info`'s
`channel_broker_port`/`channel_relay_port` — confirm against a live deployment rather
than hardcoding, since an operator can override the defaults via
`CT_CP_CHANNEL_BROKER_PORT`/`CT_CP_CHANNEL_RELAY_PORT`). **Not** `4433` — that's the
Mesh-Plane tunnel rendezvous port (`mesh_edge_port`), a different listener/protocol
entirely; pointing at it fails every join immediately and consistently, not with an
auth/membership refusal.

Runs relay-only (`CT_CHANNEL_RELAY_ONLY=1` — no dialable address needed, #173),
re-admitting successive peers automatically (#179/#200 — up to 8 concurrent
sessions), piping each request through `HANDLER_CMD` (stdin request → stdout JSON,
per `docs/agent-onboarding.md`'s handler I/O contract).

`CT_CHANNEL_BROKER`/`CT_CHANNEL_RELAY` accept a `host:port` directly since #214
(`6d85644`) — a bare IP is no longer required.

## Known gap: no CLI to mint a cross-account `SignedChannelInvitation` (#234)

Everything above (`operator-init`, `channel init`, `provision-link-channel.sh`) provisions a
channel between two sides that already coordinate their key material directly — it's not the
same mechanism as a `SignedChannelInvitation` (the cross-account invitation type documented in
`docs/reference` — the API endpoint shapes are real and verified, but there is currently no
`ct-agent` CLI subcommand to actually *issue* one, only the `ct_common::channel` library
primitives). If you need to invite an account you don't otherwise coordinate with directly, there
is no tool for that today; see #234.

## Known open issue: "edge broker refused the channel join"

At the time of writing, steps 1–3 above are verified working end-to-end against
the live deployment (both `POST`s return 2xx, both sides derive the same
`channel_id`). **Step 4 currently fails** — the edge broker refuses the join
immediately, in a tight retry loop, for a freshly-provisioned channel. Root cause
not yet identified from the client side; see `CADS-Tunnel#214` for the live
repro (exact commands, channel ids, and the working/non-working pieces isolated)
— needs core-side investigation (likely somewhere between the public
`POST /me/channels/:channel/members` write path and the edge's internal
`/internal/channel/authorize` read path). Update this doc once resolved.
