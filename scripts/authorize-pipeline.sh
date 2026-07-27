#!/usr/bin/env bash
# CADS-Tunnel — authorize a hostname for a headless (no-portal-account) pipeline
# agent, issue it a Let's Encrypt cert, and optionally mint a join token — via
# the public admin-token-gated control-plane API (#214) plus core's own
# deSEC DNS-01 tooling (#219). Run this on the operator's machine (needs
# docker/deploy/.env); no edge loopback access required.
#
#   ./scripts/authorize-pipeline.sh <hostname> [tenant]
#   ./scripts/authorize-pipeline.sh <hostname> [tenant] --staging     # LE staging cert, testing only
#   ./scripts/authorize-pipeline.sh <hostname> [tenant] --skip-cert   # host-auth + token only, no cert
#
# Examples:
#   ./scripts/authorize-pipeline.sh cookbook.bunsenbrenner.org cookbook-demo
#   ./scripts/authorize-pipeline.sh flappy-demo.bunsenbrenner.org   # authorize + cert only, no token mint
#
# Reads CT_EDGE_ADMIN_TOKEN and DESEC_TOKEN from docker/deploy/.env (the same
# values the control plane / core deploy already use). Prints:
#   CT_AGENT_TOKEN       the routing token authorized for <hostname> — the agent
#                        must onboard with this exact value so its bind is accepted
#   CT_AGENT_JOIN_TOKEN  a single-use join token for [tenant], if given
#   cert files           written to CERT_DIR (default ~/ct-pipeline-certs/<hostname>/)
#
# WHY THE PIPELINE NEVER NEEDS DESEC_TOKEN (#219): a pipeline's own Caddy
# previously ran its own ACME client with the deSEC zone-wide token baked into
# its container — a core-authority credential (can rewrite ANY record on the
# zone) handed to every pipeline repo. This script does the DNS-01 exchange
# HERE, with the token staying on the operator's host, and hands the pipeline
# only the resulting fullchain.pem/privkey.pem — a single-hostname artifact,
# not a zone-wide credential. The pipeline's Caddyfile then just points `tls`
# at static files (no ACME client, no DNS plugin, no DESEC_TOKEN, ever).
#
# Relay CT_AGENT_TOKEN, the join token, and the cert files to the pipeline
# maintainer out of band (direct message, not a GitHub issue/comment/PR — this
# repo is public). See docs/ops/runbook.md "Authorize a new pipeline hostname".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/docker/deploy/.env"
PORTAL_PUBLIC_HOST="${PORTAL_PUBLIC_HOST:-bunsenbrenner.org}"
ACME_EMAIL="${ACME_EMAIL:-scimbe@gmail.com}"
STAGING=0
SKIP_CERT=0

log()  { printf "\033[1m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[32m  ✓\033[0m %s\n" "$*"; }
warn() { printf "\033[33m  !\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

usage() { sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
[ $# -ge 1 ] || usage 1
case "$1" in -h|--help) usage 0 ;; esac

HOST="$1"; shift
TENANT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --staging)   STAGING=1 ;;
    --skip-cert) SKIP_CERT=1 ;;
    *)           TENANT="$1" ;;
  esac
  shift
done

CERT_DIR="${CERT_DIR:-$HOME/ct-pipeline-certs/$HOST}"

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

# --- cert (#219): issued HERE with the operator's DESEC_TOKEN; the pipeline
# never sees that token, only the resulting single-hostname cert files. -------
if [ "$SKIP_CERT" = "1" ]; then
  warn "--skip-cert given — no cert issued; the pipeline's origin needs one to serve HTTPS"
else
  DESEC_TOKEN="$(grep -E '^DESEC_TOKEN=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
  [ -n "$DESEC_TOKEN" ] || die "DESEC_TOKEN not found in $ENV_FILE (needed to issue the cert; see docs/dns01-desec.md)"
  export DESEC_TOKEN
  # shellcheck source=lib-acme.sh
  . "$ROOT/scripts/lib-acme.sh"
  issue_cert "$HOST" "$CERT_DIR" true "$ACME_EMAIL"
fi

echo
echo "Relay these to the pipeline maintainer OUT OF BAND (never GitHub/public):"
echo
echo "CT_AGENT_TOKEN=$ROUTING_TOKEN"
[ -n "$JOIN_TOKEN" ] && echo "CT_AGENT_JOIN_TOKEN response: $JOIN_TOKEN"
if [ "$SKIP_CERT" != "1" ]; then
  echo "cert:  $CERT_DIR/fullchain.pem"
  echo "key:   $CERT_DIR/privkey.pem   (paste the contents — this is the sensitive one)"
fi
echo
echo "They onboard with: CT_AGENT_HOSTNAME=$HOST CT_AGENT_TOKEN=<above> CT_AGENT_JOIN_TOKEN=<above> ct-agent onboard"
[ "$SKIP_CERT" != "1" ] && echo "Their Caddyfile serves the two files above directly: tls /certs/fullchain.pem /certs/privkey.pem — no DESEC_TOKEN, no ACME client needed on their side."
