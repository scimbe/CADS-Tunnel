#!/usr/bin/env bash
# CADS-Tunnel — authorize a hostname for a headless (no-portal-account) pipeline
# agent, and optionally mint it a join token, via the public admin-token-gated
# control-plane API (#214). Run this on the operator's machine (needs
# docker/deploy/.env); no edge loopback access required.
#
#   ./scripts/authorize-pipeline.sh <hostname> [tenant]
#
# Examples:
#   ./scripts/authorize-pipeline.sh cookbook.bunsenbrenner.org cookbook-demo
#   ./scripts/authorize-pipeline.sh flappy-demo.bunsenbrenner.org   # authorize only, no token mint
#
# Reads CT_EDGE_ADMIN_TOKEN from docker/deploy/.env (the same value the control
# plane holds as CT_CP_EDGE_ADMIN_TOKEN). Prints:
#   CT_AGENT_TOKEN       the routing token authorized for <hostname> — the agent
#                        must onboard with this exact value so its bind is accepted
#   CT_AGENT_JOIN_TOKEN  a single-use join token for [tenant], if given
#
# Relay BOTH values to the pipeline maintainer out of band (direct message, not a
# GitHub issue/comment/PR — this repo is public). See docs/ops/runbook.md
# "Authorizing a new pipeline hostname" for the full walkthrough.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/docker/deploy/.env"
PORTAL_PUBLIC_HOST="${PORTAL_PUBLIC_HOST:-bunsenbrenner.org}"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
[ $# -ge 1 ] || usage 1
case "$1" in -h|--help) usage 0 ;; esac

HOST="$1"
TENANT="${2:-}"

log()  { printf "\033[1m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[32m  ✓\033[0m %s\n" "$*"; }
die()  { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "no $ENV_FILE — run this from an operator checkout with the deployment's .env"
ADMIN_TOKEN="$(grep -E '^CT_EDGE_ADMIN_TOKEN=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
[ -n "$ADMIN_TOKEN" ] || die "CT_EDGE_ADMIN_TOKEN not found in $ENV_FILE"

ROUTING_TOKEN="$(openssl rand -hex 32)"

log "authorizing $HOST at the edge (routing token: newly generated)"
curl -fsS -X POST "https://$PORTAL_PUBLIC_HOST/registry/authorize-host/$ROUTING_TOKEN/$HOST" \
  -H "x-ct-admin-token: $ADMIN_TOKEN" \
  || die "authorize-host failed — check the host resolves to this edge and CT_EDGE_ADMIN_TOKEN is current"
echo
ok "authorized"

JOIN_TOKEN=""
if [ -n "$TENANT" ]; then
  log "minting a single-use join token for tenant=$TENANT"
  JOIN_TOKEN="$(curl -fsS -X POST "https://$PORTAL_PUBLIC_HOST/enroll/issue" \
    -H 'content-type: application/json' \
    -H "x-ct-admin-token: $ADMIN_TOKEN" \
    -d "{\"tenant\":\"$TENANT\"}")"
  ok "minted"
fi

echo
echo "Relay these to the pipeline maintainer OUT OF BAND (never GitHub/public):"
echo
echo "CT_AGENT_TOKEN=$ROUTING_TOKEN"
[ -n "$JOIN_TOKEN" ] && echo "CT_AGENT_JOIN_TOKEN response: $JOIN_TOKEN"
echo
echo "They onboard with: CT_AGENT_HOSTNAME=$HOST CT_AGENT_TOKEN=<above> CT_AGENT_JOIN_TOKEN=<above> ct-agent onboard"
