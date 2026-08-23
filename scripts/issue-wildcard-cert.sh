#!/usr/bin/env bash
# CADS-Tunnel — issue (or renew) the shared front-door WILDCARD certificate
# for the Rot/Gelb/Grün admission broker's Gelb tier (#233). This is the
# single, low-volume, operator-owned certificate the edge terminates with for
# any hostname the control plane has marked Gelb — see
# crates/edge/src/serve.rs's `serve_gelb_terminated` and
# crates/control-plane/src/acme_broker.rs.
#
# Deliberately reuses the SAME acme.sh + deSEC DNS-01 mechanism already used
# for the Portal/Auth-IdP certs (scripts/lib-acme.sh) — a wildcard identifier
# (`*.<zone>`) is still exactly one ACME identifier, so it needs no new
# tooling. Uses Let's Encrypt specifically: this is one shared, low-volume
# asset, not per-customer issuance, so there is no rate-limit reason to
# diversify it across the multi-CA rotation the admission broker uses for
# individual customer certificates.
#
#   ./scripts/issue-wildcard-cert.sh                 # production Let's Encrypt
#   ./scripts/issue-wildcard-cert.sh --staging        # LE staging, testing only
#   ./scripts/issue-wildcard-cert.sh --skip-cert       # reuse existing cert, don't re-issue
#
# Reads DESEC_TOKEN from docker/deploy/.env (the same value the core deploy
# already uses for the Portal/Auth certs). Writes fullchain.pem/privkey.pem to
# WILDCARD_CERT_DIR (default ~/ct-certs/wildcard) — the directory
# docker/deploy/compose.frontdoor.yml will bind-mount into the edge container
# once the Phase F redeploy wires CT_EDGE_WILDCARD_CERT/_KEY (not done by
# this script — issuing the cert is deliberately separate from, and safe to
# run well before, that redeploy).
#
# The reload command is a no-op (`true`): nothing reads this cert file yet
# (Phase F hasn't redeployed the edge), so there is nothing to restart on
# first issuance. A future renewal, once Phase F has landed, should update
# this script's reload command to restart the edge the same way
# scripts/deploy-selfhost.sh's ensure_portal_cert does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/docker/deploy/.env"
PORTAL_PUBLIC_HOST="${PORTAL_PUBLIC_HOST:-bunsenbrenner.org}"
ACME_EMAIL="${ACME_EMAIL:-scimbe@gmail.com}"
WILDCARD_CERT_DIR="${WILDCARD_CERT_DIR:-$HOME/ct-certs/wildcard}"
STAGING=0
SKIP_CERT=0

log()  { printf "\033[1m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[32m  ✓\033[0m %s\n" "$*"; }
warn() { printf "\033[33m  !\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

# Derived, not a hardcoded line range -- same class as #626/#627: this one
# silently dropped lines 25-33 (the WILDCARD_CERT_DIR/Phase-F-redeploy note
# and the reload-command TODO for whoever revisits this after Phase F lands).
usage() {
  awk 'NR>=2 && (/^#/||/^$/){sub(/^# ?/,""); print; next} NR>=2{exit}' "${BASH_SOURCE[0]}"
  exit "${1:-0}"
}
case "${1:-}" in -h|--help) usage 0 ;; esac
while [ $# -gt 0 ]; do
  case "$1" in
    --staging)   STAGING=1 ;;
    --skip-cert) SKIP_CERT=1 ;;
    *)           die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

[ -f "$ENV_FILE" ] || die "no $ENV_FILE — run this from an operator checkout with the deployment's .env"
DESEC_TOKEN="$(grep -E '^DESEC_TOKEN=' "$ENV_FILE" | tail -1 | cut -d= -f2-)"
[ -n "$DESEC_TOKEN" ] || die "DESEC_TOKEN not found in $ENV_FILE (see docs/dns01-desec.md)"
export DESEC_TOKEN

WILDCARD_HOST="*.$PORTAL_PUBLIC_HOST"
log "issuing the shared wildcard cert for $WILDCARD_HOST"

# shellcheck source=lib-acme.sh
. "$ROOT/scripts/lib-acme.sh"
issue_cert "$WILDCARD_HOST" "$WILDCARD_CERT_DIR" true "$ACME_EMAIL"

ok "wildcard cert ready at $WILDCARD_CERT_DIR (fullchain.pem / privkey.pem)"
log "NOT wired into the edge yet (Phase F) — this is deliberately additive-only; \
nothing live reads this file until compose.frontdoor.yml is updated with \
WILDCARD_CERT_DIR + CT_EDGE_WILDCARD_CERT/_KEY and the edge is redeployed."
