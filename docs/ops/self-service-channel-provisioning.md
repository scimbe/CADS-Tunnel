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

Preferred: `ct-agent login` (ct-agent#114), an RFC 8628 device-code flow against the
realm's public `ct-agent-cli` client — no password ever touches a script or the
command line, and the token is stored + refreshed automatically for every later
`ct-agent channel register`/`allowlist` call in this doc:

```bash
CT_OIDC_ISSUER=https://auth.<zone>/realms/<realm> ct-agent login
```

`mint-oidc-token.sh` (ROPC via the `admin-cli` client, `docs/agent-onboarding.md` §A.2)
still works and remains useful for a headless box with no browser to complete the
device flow, or for a one-off `curl` you don't want `ct-agent` involved in at all:

```bash
OIDC_ISSUER_BASE=https://auth.<zone>/realms/<realm> \
OIDC_USERNAME=you@example.com \
OIDC_PASSWORD='...' \
  ./scripts/channel-ops/mint-oidc-token.sh
```

Prints the bare `access_token` to stdout. **Short-lived** (a Keycloak realm default
is minutes) — mint fresh for each provisioning batch rather than caching it across
a long session.

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
auth/membership refusal. `/network-info`'s fourth port, `channel_relay_gate_port`
(default `443`, override via `CT_CP_CHANNEL_RELAY_GATE_PORT`), is the #330 Circuit-Relay
gate's shared front door — a member still needs QUIC admission first; see `docs/channel.md`
in the `ct-agent` repo (`CT_CHANNEL_RELAY_GATE`/`_CERT`) for the client side.

Runs relay-only (`CT_CHANNEL_RELAY_ONLY=1` — no dialable address needed, #173),
re-admitting successive peers automatically (#179/#200 — up to 8 concurrent
sessions), piping each request through `HANDLER_CMD` (stdin request → stdout JSON,
per `docs/agent-onboarding.md`'s handler I/O contract).

`CT_CHANNEL_BROKER`/`CT_CHANNEL_RELAY` accept a `host:port` directly since #214
(`6d85644`) — a bare IP is no longer required.

### The relay-**gate** is a third, separate thing (#330) — and it does **not** replace the QUIC channel admission

`CT_CHANNEL_RELAY_GATE` (+ `CT_CHANNEL_RELAY_GATE_CERT`) configures the **:443 front
door's relay-gate leg** (`crates/edge/src/relay_gate.rs`) — a *different protocol* from
plain `CT_CHANNEL_RELAY`, **not interchangeable** with it, and easy to confuse because
both have "relay" in the name:

- `CT_CHANNEL_RELAY` (`:4436`) is the **QUIC** channel relay — the edge splices two
  members' QUIC connections.
- `CT_CHANNEL_RELAY_GATE` is the pre-auth gate in front of the **libp2p
  Circuit-Relay-v2 + DCUtR hole-punch** path (`ct-agent`'s `p2p.rs` client side): a
  member behind NAT that cannot reach the broker/relay ports directly presents its
  grant **over the TLS-TCP front door on `:443`** (the gate's own dedicated ALPN — no
  UDP involved *for this leg*; see the two-authentications note below), proves possession
  with the same `verify_stateless` +
  challenge-signature primitives channel admission uses, and only then is byte-spliced
  to the internal-only relay-node. The relay-node itself is never publicly reachable;
  the gate IS its only door — that is what makes running a relay safe (an unguarded
  public relay would be an open proxy).

**Discovery** (#330 is exactly this gap — docs are the discovery path today): the gate
address is the deployment's unified front-door host with
`GET /network-info` → `channel_relay_gate_port` (same host as `CT_AGENT_CP_URL`), and
`CT_CHANNEL_RELAY_GATE_CERT` is the DER from `GET /pki/ca` — the same CA fetch every
other leg uses.

**Two authentications, on two different ports — this is the part that misleads.** An
earlier version of this heading said the gate's admission "runs over TLS-TCP on `:443`, not
QUIC". That reads as "the gate path needs no QUIC reachability", and it is wrong. Traced in
`ct-agent`'s `join_via_relay_gate_dcutr` (`native/src/channel_run/mod.rs`), the order is:

1. **Channel admission over QUIC `:4436`** — `present_channel_join` on the connection from
   `dial_relay_preferring_direct(cfg.relay_addr…)`, i.e. the plain QUIC relay port. This is
   the step that yields the peer's Noise key; **without reachable `:4436` the gate path does
   not start at all.**
2. **Gate pre-auth over TLS-TCP `:443`** — only afterwards, `dial_relay_gate_over_443`
   presents the grant under ALPN `ct-edge-relay` and signs the edge's fresh 32-byte
   challenge. That authorises the **circuit**, not the channel membership.

So the gate has its own possession check, and it is genuinely on `:443` — but it is the
second of two, not a replacement for the first. Closing `:4436` because "the gate is on 443"
produces exactly the silent, downstream `early-eof` this section warns about below.

**When you need it:** only when a deployment pairs members through the DCUtR
hole-punch path and your member sits behind NAT without direct broker/relay
reachability. **When it's misconfigured, the failure is silent and downstream** — a
channel pairing that needed the gate dies as an unhelpful `early-eof` later, not as an
auth refusal at the gate — so ask the operator whether the deployment needs it rather
than inferring from an error message. (A bare TCP probe against `:4435`/`:4436` proves
nothing either way — those are UDP/QUIC listeners; probing them with TCP was a
documented false lead, retracted on CADS-DEMO-sort#22.)

## Cross-account invitations: `ct-agent channel invite` (was #234, now scimbe/ct-agent#9)

Everything above (`operator-init`, `channel init`, `provision-link-channel.sh`) provisions a
channel between two sides that already coordinate their key material directly. For a genuinely
cross-account case — inviting an identity you don't otherwise coordinate holder/noise material
with — use `ct-agent channel invite` (fixed in `scimbe/ct-agent@2bbdd2e`, released `v0.4.1`+):

```bash
CT_CHANNEL_OPERATOR_KEY=<operator private key, from channel operator-init> \
CT_INVITE_CHANNEL=<64-hex channel id> \
CT_INVITE_IDENTITY=<64-hex invitee IDENTITY pubkey — not a holder key you already have> \
CT_INVITE_DIRECTION=initiate|accept|both \
CT_INVITE_RIGHTS=read|write|readwrite   # optional, default readwrite \
CT_INVITE_DELEGABLE=true|false          # optional, default false \
CT_INVITE_EXPIRES=<unix seconds> \
  ct-agent channel invite
```

Pure local compute, same shape as `channel grant` — no network call, no private key leaves the
box. Prints the signed invitation hex; the invitee redeems it against
`ct_common::channel::redeem_invitation` (receiving-side flow, already real and unchanged).

## Known open issue: "edge broker refused the channel join" — fixed (CADS-Tunnel#231)

Historically, step 4 above failed with the edge broker refusing the join immediately in a tight
retry loop for a freshly-provisioned channel (originally tracked as `CADS-Tunnel#214` in this
doc — that issue number was later repurposed for something unrelated; the actual fix landed
under `CADS-Tunnel#231`). Root-caused and fixed 2026-08-10: exponential backoff on definitive
refusals, a negative-cache for repeated refusals, and a timeout-budget-mismatch fix in
`channel_authorize`. Live-verified against the real deployment with a freshly-built `ct-agent`
client. **If you hit this today, first confirm you're on a client built past that fix** — a
client built against an older attestation-format pin (anything before `ct-agent` v0.4.0) fails
differently, with `POST /me/channels/:channel/members` itself returning `noise_attestation does
not verify against the holder key` rather than reaching step 4 at all; see `scimbe/ct-agent#12`.
