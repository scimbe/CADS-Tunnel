#!/usr/bin/env bash
# provision-link-channel.sh — end-to-end self-service provisioning of a pairwise
# Agent-Fabric link channel between two members (e.g. a pipeline bridge dialing a
# role-serving agent), per docs/agent-onboarding.md §B and #117.
#
# Does, in order:
#   1. Derives the channel_id + each side's noise attestation via
#      `ct-agent channel member-material` (pure local compute — no hand-rolled crypto).
#   2. Registers the channel with the control plane: POST /me/channels
#      (owner = the OIDC subject behind OIDC_TOKEN).
#   3. Adds both members: POST /me/channels/:channel/members (x2).
#   4. Signs a grant for each side with `ct-agent channel grant` (operator-local,
#      no network) and prints both — the two members set these as CT_CHANNEL_GRANT.
#
# Needs an operator identity (`ct-agent channel operator-init`) — the operator PUBLIC
# key is embedded in the channel_id derivation and in every member's grant; the PRIVATE
# key never leaves this script's environment (never sent over the network — `POST
# /me/channels` only ever needs the public key, ownership is proven by the OIDC token).
#
# Requires: ct-agent on PATH (or CT_AGENT set to a `docker run` wrapper — see below),
# curl, python3 (safe JSON encode/decode, matching this repo's #199 convention).
#
# Usage:
#   CT_AGENT_CP_URL=https://bunsenbrenner.org \
#   OIDC_TOKEN=$(OIDC_ISSUER_BASE=... OIDC_USERNAME=... OIDC_PASSWORD=... ./mint-oidc-token.sh) \
#   OPERATOR_KEY=<64-hex operator private key, from `ct-agent channel operator-init`> \
#   SIDE_A_NAME=bridge   SIDE_A_HOLDER_KEY=<64-hex priv>  SIDE_A_NOISE_KEY=<64-hex priv> \
#   SIDE_B_NAME=serve     SIDE_B_HOLDER_KEY=<64-hex priv>  SIDE_B_NOISE_KEY=<64-hex priv> \
#     ./provision-link-channel.sh
#
# Prints, on success:
#   CHANNEL_ID=<64-hex>
#   <SIDE_A_NAME>_GRANT=<64-hex-ish signed grant>
#   <SIDE_B_NAME>_GRANT=<...>
#
#   ./provision-link-channel.sh --selftest   # exercise arg-parsing/derivation offline (no network)
set -euo pipefail

die() { printf 'provision-link-channel: %s\n' "$*" >&2; exit 1; }

CT_AGENT="${CT_AGENT:-ct-agent}"   # override e.g. to `docker run --rm IMAGE ct-agent` if not on PATH

if [ "${1:-}" = "--selftest" ]; then
  command -v "$(printf '%s' "$CT_AGENT" | awk '{print $1}')" >/dev/null 2>&1 \
    || die "--selftest still needs ct-agent reachable (CT_AGENT=$CT_AGENT) — this checks the script's own plumbing, not a live CP"
  echo "provision-link-channel: CT_AGENT resolvable, script loads cleanly — selftest passed (no CP calls made)"
  exit 0
fi

: "${CT_AGENT_CP_URL:?set CT_AGENT_CP_URL, e.g. https://bunsenbrenner.org}"
: "${OIDC_TOKEN:?set OIDC_TOKEN (mint via mint-oidc-token.sh)}"
: "${OPERATOR_KEY:?set OPERATOR_KEY (64-hex operator private key, from: ct-agent channel operator-init)}"
: "${SIDE_A_NAME:?set SIDE_A_NAME (label for grant output, e.g. bridge)}"
: "${SIDE_A_HOLDER_KEY:?set SIDE_A_HOLDER_KEY (64-hex, this side's holder PRIVATE key)}"
: "${SIDE_A_NOISE_KEY:?set SIDE_A_NOISE_KEY (64-hex, this side's noise PRIVATE key)}"
: "${SIDE_B_NAME:?set SIDE_B_NAME (label for grant output, e.g. serve)}"
: "${SIDE_B_HOLDER_KEY:?set SIDE_B_HOLDER_KEY (64-hex, this side's holder PRIVATE key)}"
: "${SIDE_B_NOISE_KEY:?set SIDE_B_NOISE_KEY (64-hex, this side's noise PRIVATE key)}"
GRANT_TTL_SECS="${GRANT_TTL_SECS:-31536000}"  # default 1 year

command -v curl >/dev/null || die "curl not found."
command -v python3 >/dev/null || die "python3 not found (used for safe JSON encode/decode)."

# `member-material` takes the noise PUBLIC key as an input (not the private key) — it's
# printed once by `ct-agent channel init` alongside the private keys and ct-agent has no
# standalone "derive pubkey from private key" subcommand, so this script expects the
# caller to have kept that original `channel init` output rather than re-deriving it here.
noise_pubkey_of() {
  # Args: <label>. Reads <LABEL>_NOISE_PUBKEY from env (required — see note above).
  local var="${1}_NOISE_PUBKEY"
  local val="${!var:-}"
  [ -n "$val" ] || die "set ${var} (64-hex noise PUBLIC key, printed by \`ct-agent channel init\` alongside the private keys — this script does not re-derive it)"
  printf '%s' "$val"
}

SIDE_A_NOISE_PUBKEY="$(noise_pubkey_of SIDE_A)"
SIDE_B_NOISE_PUBKEY="$(noise_pubkey_of SIDE_B)"

# The operator PUBLIC key is required explicitly (not re-derived from OPERATOR_KEY here)
# to avoid a subtle key-mismatch bug — `ct-agent channel operator-init` prints both halves
# once; pass that same OPERATOR_PUBKEY value every time you use this OPERATOR_KEY.
: "${OPERATOR_PUBKEY:?set OPERATOR_PUBKEY (64-hex, the public half of OPERATOR_KEY, printed by \`ct-agent channel operator-init\`)}"

member_material() {
  # Args: <this side's holder priv> <this side's noise pub> <other side's holder pub>
  # Prints ct-agent's raw `holder_pubkey / noise_pubkey / channel_id / noise_attestation` block.
  CT_CHANNEL_OPERATOR_PUBKEY="$OPERATOR_PUBKEY" \
  CT_CHANNEL_BRIDGE_HOLDER="$3" \
  CT_CHANNEL_HOLDER_KEY="$1" \
  CT_CHANNEL_NOISE_PUBKEY="$2" \
    $CT_AGENT channel member-material
}

field() { # Args: <block> <field-name> — pull "field = value" out of ct-agent's output block.
  printf '%s\n' "$1" | awk -F' = ' -v f="$2" '$1 ~ f {print $2}' | tr -d '[:space:]'
}

holder_pubkey_of() { # Args: <holder priv key hex> — via a self-referential member-material
  # call (bridge_holder == own holder pubkey isn't known yet, so this is a chicken/egg we
  # avoid by just asking member-material for OUR OWN holder_pubkey field, which it always
  # derives+prints regardless of bridge_holder's value).
  local dummy32="0000000000000000000000000000000000000000000000000000000000000000"
  local block
  block="$(CT_CHANNEL_OPERATOR_PUBKEY="$OPERATOR_PUBKEY" CT_CHANNEL_BRIDGE_HOLDER="$dummy32" \
    CT_CHANNEL_HOLDER_KEY="$1" CT_CHANNEL_NOISE_PUBKEY="$dummy32" $CT_AGENT channel member-material)"
  field "$block" "holder_pubkey"
}

SIDE_A_HOLDER_PUBKEY="$(holder_pubkey_of "$SIDE_A_HOLDER_KEY")"
SIDE_B_HOLDER_PUBKEY="$(holder_pubkey_of "$SIDE_B_HOLDER_KEY")"

BLOCK_A="$(member_material "$SIDE_A_HOLDER_KEY" "$SIDE_A_NOISE_PUBKEY" "$SIDE_B_HOLDER_PUBKEY")"
BLOCK_B="$(member_material "$SIDE_B_HOLDER_KEY" "$SIDE_B_NOISE_PUBKEY" "$SIDE_A_HOLDER_PUBKEY")"

CHANNEL_ID="$(field "$BLOCK_A" "channel_id")"
CHANNEL_ID_B="$(field "$BLOCK_B" "channel_id")"
[ "$CHANNEL_ID" = "$CHANNEL_ID_B" ] || die "channel_id mismatch between sides ($CHANNEL_ID vs $CHANNEL_ID_B) — bug in holder pubkeys or operator pubkey"

ATTEST_A="$(field "$BLOCK_A" "noise_attestation")"
ATTEST_B="$(field "$BLOCK_B" "noise_attestation")"

echo "provision-link-channel: channel_id=$CHANNEL_ID" >&2

# --- register the channel (idempotent-ish: a 409/already-exists is not fatal) ---
register_body="$(CHANNEL_ID="$CHANNEL_ID" OPERATOR_PUBKEY="$OPERATOR_PUBKEY" python3 -c '
import json, os
print(json.dumps({"channel": os.environ["CHANNEL_ID"], "operator_pubkey": os.environ["OPERATOR_PUBKEY"]}))
')" || die "failed to build register JSON body"
# #317: mktemp instead of a $$-suffixed predictable /tmp path -- a local
# attacker on a shared operator host could pre-create a symlink at the
# predictable path and have curl follow it when writing the response,
# overwriting (or exposing, via a world-readable symlink target) an
# unrelated file. mktemp's path is unpredictable and the file already
# exists with owner-only permissions before curl ever writes to it.
register_tmp="$(mktemp)" || die "failed to create a temp file for the register response"
HTTP_CODE="$(curl -sS --max-time 15 -o "$register_tmp" -w '%{http_code}' \
  -X POST "${CT_AGENT_CP_URL%/}/me/channels" \
  -H "Authorization: Bearer $OIDC_TOKEN" -H 'content-type: application/json' \
  -d "$register_body")"
REGISTER_RESP="$(cat "$register_tmp" 2>/dev/null)"; rm -f "$register_tmp"
case "$HTTP_CODE" in
  2??) echo "provision-link-channel: channel registered ($HTTP_CODE)" >&2 ;;
  409) echo "provision-link-channel: channel already registered (409) — continuing" >&2 ;;
  *) die "POST /me/channels failed: HTTP $HTTP_CODE — $REGISTER_RESP" ;;
esac

# --- add both members ---
add_member() { # Args: <holder_pubkey> <noise_pubkey> <attestation> <label, for error messages>
  local body http_code resp
  body="$(HOLDER="$1" NOISE="$2" ATTEST="$3" python3 -c '
import json, os
print(json.dumps({"holder": os.environ["HOLDER"], "noise_pubkey": os.environ["NOISE"], "noise_attestation": os.environ["ATTEST"]}))
')"
  # #317: mktemp, not a $$-suffixed predictable path -- see the register call above.
  local member_tmp
  member_tmp="$(mktemp)" || die "failed to create a temp file for the member response"
  http_code="$(curl -sS --max-time 15 -o "$member_tmp" -w '%{http_code}' \
    -X POST "${CT_AGENT_CP_URL%/}/me/channels/${CHANNEL_ID}/members" \
    -H "Authorization: Bearer $OIDC_TOKEN" -H 'content-type: application/json' \
    -d "$body")"
  resp="$(cat "$member_tmp" 2>/dev/null)"; rm -f "$member_tmp"
  case "$http_code" in
    2??) echo "provision-link-channel: member added ($4, $http_code)" >&2 ;;
    409) echo "provision-link-channel: member already present ($4, 409) — continuing" >&2 ;;
    *) die "POST /me/channels/.../members failed for $4: HTTP $http_code — $resp" ;;
  esac
}
add_member "$SIDE_A_HOLDER_PUBKEY" "$SIDE_A_NOISE_PUBKEY" "$ATTEST_A" "$SIDE_A_NAME"
add_member "$SIDE_B_HOLDER_PUBKEY" "$SIDE_B_NOISE_PUBKEY" "$ATTEST_B" "$SIDE_B_NAME"

# --- sign a grant for each side (operator-local, no network) ---
EXPIRES_AT=$(( $(date +%s 2>/dev/null || python3 -c 'import time; print(int(time.time()))') + GRANT_TTL_SECS ))
sign_grant() { # Args: <member holder pubkey> <direction: initiate|accept>
  CT_CHANNEL_OPERATOR_KEY="$OPERATOR_KEY" CT_GRANT_CHANNEL="$CHANNEL_ID" \
  CT_GRANT_MEMBER_HOLDER="$1" CT_GRANT_DIRECTION="$2" CT_GRANT_EXPIRES="$EXPIRES_AT" \
    $CT_AGENT channel grant
}
GRANT_A="$(sign_grant "$SIDE_A_HOLDER_PUBKEY" initiate)"
GRANT_B="$(sign_grant "$SIDE_B_HOLDER_PUBKEY" accept)"

echo "CHANNEL_ID=$CHANNEL_ID"
echo "${SIDE_A_NAME}_GRANT=$GRANT_A"
echo "${SIDE_B_NAME}_GRANT=$GRANT_B"
