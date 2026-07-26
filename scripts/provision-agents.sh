#!/usr/bin/env bash
# provision-agents.sh (#145 Gap 2) — bulk-provision N agents in one command.
#
# Turns "provision N agents" from N rounds of manual work into a single control-plane call plus N
# ready-to-run agent env blocks. Mints COUNT single-use join tokens via the batch endpoint
# (`POST /enroll/issue-batch`, #145) and emits one runnable `ct-agent onboard` block per token, each
# with a distinct agent id + its own restart-safe state dir (#141).
#
# This covers the join-token + agent-config half of provisioning. Bulk **Keycloak account** creation
# is a separate step (blocked on no-SMTP → the admin-API path) and NOT done here; the multi-host
# capacity ceiling (#145 Gap 1) is likewise out of scope.
#
#   COUNT=25 TENANT=acme CP_URL=http://127.0.0.1:8090 CT_CP_EDGE_ADMIN_TOKEN=<hex> \
#     ./scripts/provision-agents.sh > agents.env
#
# Env:
#   COUNT                   required — how many agents to provision (1..=100, the endpoint's cap)
#   TENANT                  required — tenant the agents enrol under
#   CP_URL                  control-plane URL         (default http://127.0.0.1:8090)
#   CT_CP_EDGE_ADMIN_TOKEN  admin token gating issuance (#87); required if the CP is gated
#   ID_PREFIX               agent id prefix           (default "agent" → agent-0, agent-1, …)
#   EDGE                    edge host:port            (default 127.0.0.1:4433)
#   STATE_BASE              base dir for per-agent CT_AGENT_STATE_DIR (default /var/lib/ct-agent)
#
#   ./scripts/provision-agents.sh --selftest   # exercise the emission logic offline (no CP)
set -euo pipefail

die() { printf 'provision-agents: %s\n' "$*" >&2; exit 1; }

# Emit one ready-to-run agent env block per token read from stdin (one 64-hex token per line).
# Args: <prefix> <cp_url> <edge> <state_base>. Pure (no network) — this is what --selftest exercises.
emit_blocks() {
  local prefix="$1" cp="$2" edge="$3" state_base="$4" i=0 token
  while read -r token; do
    [ -n "$token" ] || continue
    printf '# agent %s-%s\n' "$prefix" "$i"
    printf 'CT_AGENT_CP_URL=%s CT_AGENT_JOIN_TOKEN=%s CT_AGENT_ID=%s-%s CT_AGENT_EDGE=%s CT_AGENT_STATE_DIR=%s/%s-%s ct-agent onboard\n\n' \
      "$cp" "$token" "$prefix" "$i" "$edge" "$state_base" "$prefix" "$i"
    i=$((i + 1))
  done
}

# Build the POST /enroll/issue-batch request body SAFELY (#199). Args: <tenant> <count>. A real JSON
# encoder (python's json) escapes the operator-supplied tenant, so a stray `"` or `\` (a fat-finger in
# a tenant name) can't splice extra/modified fields into the payload — it becomes one string value.
# count is emitted as a real JSON number (already validated numeric by the caller). Pure (no network).
build_batch_body() {
  CT_TENANT="$1" CT_COUNT="$2" python3 -c '
import json, os
print(json.dumps({"tenant": os.environ["CT_TENANT"], "count": int(os.environ["CT_COUNT"])}))
'
}

# Extract join tokens by PARSING the {"tokens":[...]} response (#199), not regex-scanning the raw body
# for 64-hex substrings — a scan would silently pick up an unrelated 64-hex field (a trace id, an
# echoed hash) as a bogus extra "token". Reads the response on stdin, prints one token per line; exits
# non-zero if the body is not the expected JSON shape. Pure (no network).
parse_tokens() {
  python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
toks = d.get("tokens") or []
print("\n".join(t for t in toks if isinstance(t, str)))
'
}

if [ "${1:-}" = "--selftest" ]; then
  # Emission logic only (no CP): three fake tokens → three distinct blocks, distinct ids + tokens.
  t0="$(printf 'aa%.0s' $(seq 1 32))"
  t1="$(printf 'bb%.0s' $(seq 1 32))"
  t2="$(printf 'cc%.0s' $(seq 1 32))"
  out="$(printf '%s\n%s\n%s\n' "$t0" "$t1" "$t2" | emit_blocks demo http://cp:8090 edge:4433 /var/lib/ct-agent)"
  [ "$(printf '%s\n' "$out" | grep -c '^# agent demo-')" -eq 3 ] || die "selftest: expected 3 agent blocks"
  printf '%s\n' "$out" | grep -q "CT_AGENT_ID=demo-0 " || die "selftest: demo-0 block missing"
  printf '%s\n' "$out" | grep -q "CT_AGENT_ID=demo-2 " || die "selftest: demo-2 block missing"
  printf '%s\n' "$out" | grep -q "CT_AGENT_JOIN_TOKEN=$t0 " || die "selftest: token 0 not placed in its block"
  printf '%s\n' "$out" | grep -q "CT_AGENT_STATE_DIR=/var/lib/ct-agent/demo-1 " || die "selftest: per-agent state dir missing"

  # #199 (frozen): the request body is built with a real JSON encoder, so an injection-y tenant is
  # ESCAPED into a single string value, never spliced into extra fields, and count stays the caller's.
  mal='acme","count":999,"evil":"'
  body="$(build_batch_body "$mal" 25)"
  printf '%s' "$body" | CT_MAL="$mal" python3 -c '
import sys, json, os
d = json.load(sys.stdin)
assert d["tenant"] == os.environ["CT_MAL"], ("tenant not preserved verbatim", d)
assert d["count"] == 25, ("count was overridden — injection!", d)
assert set(d) == {"tenant", "count"}, ("unexpected keys — injection spliced a field", d)
' || die "selftest: tenant injection was not neutralised (#199)"

  # #199 (frozen): tokens come from .tokens[] ONLY — an unrelated 64-hex field elsewhere in the
  # response (a trace id) must NOT be picked up as a bogus token.
  real="$(printf 'aa%.0s' $(seq 1 32))"
  noise="$(printf 'ff%.0s' $(seq 1 32))"
  got="$(printf '{"trace_id":"%s","tokens":["%s"]}' "$noise" "$real" | parse_tokens)"
  [ "$got" = "$real" ] || die "selftest: token parser must read .tokens[] only, not stray 64-hex (#199)"

  echo "provision-agents: selftest OK (3 distinct blocks; JSON body inject-safe; tokens parsed from .tokens[])"
  exit 0
fi

COUNT="${COUNT:-}"
TENANT="${TENANT:-}"
CP_URL="${CP_URL:-http://127.0.0.1:8090}"
ADMIN_TOKEN="${CT_CP_EDGE_ADMIN_TOKEN:-}"
ID_PREFIX="${ID_PREFIX:-agent}"
EDGE="${EDGE:-127.0.0.1:4433}"
STATE_BASE="${STATE_BASE:-/var/lib/ct-agent}"

[ -n "$COUNT" ] || die "COUNT is required (how many agents to provision, 1..=100)"
[ -n "$TENANT" ] || die "TENANT is required"
# #199: validate COUNT is a plain integer in range BEFORE it reaches the JSON body — so it's a real
# number field, and a non-numeric fat-finger fails clearly here instead of corrupting the payload.
case "$COUNT" in ''|*[!0-9]*) die "COUNT must be a positive integer (1..=100)";; esac
{ [ "$COUNT" -ge 1 ] && [ "$COUNT" -le 100 ]; } || die "COUNT must be 1..=100 (the endpoint's cap)"
command -v curl >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found (needed to build/parse JSON safely, #199)"

# Mint COUNT single-use join tokens in ONE admin call (#145 /enroll/issue-batch). The admin-token
# header (#87) is presented when set; an ungated dev CP ignores it, a gated one requires it. The body
# is built by build_batch_body (#199) so the tenant is JSON-escaped, never string-interpolated.
body="$(build_batch_body "$TENANT" "$COUNT")" || die "failed to build the request body"
resp="$(curl -fsS -X POST "$CP_URL/enroll/issue-batch" \
  -H 'content-type: application/json' \
  -H "x-ct-admin-token: $ADMIN_TOKEN" \
  -d "$body")" \
  || die "batch mint failed at $CP_URL/enroll/issue-batch (if gated per #87, set CT_CP_EDGE_ADMIN_TOKEN; count must be 1..=100)"

# Extract the tokens by PARSING {"tokens":[...]} (#199), not regex-scanning the raw body, then emit
# one runnable agent block each.
tokens="$(printf '%s' "$resp" | parse_tokens || true)"
[ -n "$tokens" ] || die "no tokens in the batch response: $resp"
printf '%s\n' "$tokens" | emit_blocks "$ID_PREFIX" "$CP_URL" "$EDGE" "$STATE_BASE"
