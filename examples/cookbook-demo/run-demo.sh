#!/usr/bin/env bash
# Enable/disable the cookbook.bunsenbrenner.org demo — same publishing shape as
# examples/help-site/run-demo.sh, so it's easy to bring ONLINE and take OFFLINE.
#
#   examples/cookbook-demo/run-demo.sh up      # enable  (default) — mint token, deploy, wait for HTTPS
#   examples/cookbook-demo/run-demo.sh down    # disable — take the demo offline (stop origin + agent)
#   examples/cookbook-demo/run-demo.sh status  # show container status
#
# `up` assumes a RUNNING plane on this host: ct-edge (with CT_EDGE_BROWSER_LISTEN=:443)
# and ct-control-plane. It mints a join token, brings up the Caddy origin (real LE
# cert via deSEC DNS-01) + a Browser-Plane agent bound to the hostname, then polls
# until the page is served over HTTPS. Prereqs: see docs/dns01-desec.md.
set -euo pipefail
cd "$(dirname "$0")"

CMD="${1:-up}"
COMPOSE="docker compose -f compose.cookbook-demo.yml"
ENV_FILE="${ENV_FILE:-../../docker/deploy/.env}"
[ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a || true

HOSTNAME_FQDN="${HOSTNAME_FQDN:-cookbook.bunsenbrenner.org}"
CP_URL="${CP_URL:-${COOKBOOK_AGENT_CP_URL:-http://127.0.0.1:8090}}"
EDGE="${EDGE:-${COOKBOOK_AGENT_EDGE:-127.0.0.1:4433}}"
TENANT="${TENANT:-cookbook-demo}"
EDGE_ADMIN_URL="${CT_CP_EDGE_ADMIN_URL:-}"
EDGE_ADMIN_TOKEN="${CT_CP_EDGE_ADMIN_TOKEN:-}"

say() { printf '\033[36m▶ %s\033[0m\n' "$*"; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- disable / offline ---------------------------------------------------------
if [ "$CMD" = "down" ] || [ "$CMD" = "disable" ] || [ "$CMD" = "off" ]; then
  say "Taking the cookbook-demo offline (stopping origin + agent)"
  $COMPOSE down
  printf '\033[32m✓ cookbook-demo is OFFLINE.\033[0m\n'
  exit 0
fi
if [ "$CMD" = "status" ]; then
  $COMPOSE ps
  exit 0
fi
[ "$CMD" = "up" ] || [ "$CMD" = "enable" ] || [ "$CMD" = "on" ] || die "unknown command '$CMD' (use: up | down | status)"

# --- enable / online -----------------------------------------------------------
say "Checking prerequisites"
[ -n "${DESEC_TOKEN:-}" ] || die "DESEC_TOKEN is not set (Caddy needs it for the cert). See docs/dns01-desec.md; put it in $ENV_FILE."
command -v docker >/dev/null || die "docker not found."
curl -fsS "$CP_URL/healthz" >/dev/null 2>&1 || curl -fsS "$CP_URL/status" >/dev/null 2>&1 \
  || die "control-plane not reachable at $CP_URL (is the plane running?). Set CP_URL."

RESOLVED="$(getent hosts "$HOSTNAME_FQDN" 2>/dev/null | awk '{print $1; exit}')" || true
[ -n "$RESOLVED" ] && echo "   $HOSTNAME_FQDN -> $RESOLVED" \
  || echo "   ! $HOSTNAME_FQDN does not resolve yet (deSEC NS may still be propagating)."

say "Minting a join token at $CP_URL/enroll/issue"
if [ -n "$EDGE_ADMIN_TOKEN" ]; then
  TOKEN="$(curl -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
            -H "x-ct-admin-token: $EDGE_ADMIN_TOKEN" -d "{\"tenant\":\"$TENANT\"}" \
            | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p')"
else
  TOKEN="$(curl -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
            -d "{\"tenant\":\"$TENANT\"}" | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p')"
fi
[ -n "$TOKEN" ] || die "could not mint a join token (if the CP gates /enroll/issue per #87, set CT_CP_EDGE_ADMIN_TOKEN in $ENV_FILE)"
echo "   token minted (single-use; not printed)"

COOKBOOK_AGENT_TOKEN=""
if [ -n "$EDGE_ADMIN_URL" ] && [ -n "$EDGE_ADMIN_TOKEN" ]; then
  command -v openssl >/dev/null || die "openssl needed to mint a routing token (or unset CT_CP_EDGE_ADMIN_URL to use BP4a)."
  COOKBOOK_AGENT_TOKEN="$(openssl rand -hex 32)"
  say "Authorizing $HOSTNAME_FQDN at the edge (hostname-ownership, BP4b)"
  curl -fsS -X POST "${EDGE_ADMIN_URL%/}/admin/authorize-host/$COOKBOOK_AGENT_TOKEN/$HOSTNAME_FQDN" \
       -H "x-ct-admin-token: $EDGE_ADMIN_TOKEN" >/dev/null \
    || die "edge authorize-host failed (check CT_CP_EDGE_ADMIN_URL / token / edge admin listener)."
  echo "   authorized — agent registers under this routing token."
else
  echo "   ! edge host-auth not configured — relying on BP4a (fine for one hostname)."
fi

# --- write the untracked gate.json the page fetches (ONLY the SHA-256 hash, #168) --
# The plaintext demo password is provided out-of-band (COOKBOOK_DEMO_PASSWORD in the
# untracked $ENV_FILE) and NEVER stored — only its hash is written to gate.json
# (which is gitignored). The page compares sha256(input) to this hash client-side.
if [ -n "${COOKBOOK_DEMO_PASSWORD:-}" ]; then
  command -v sha256sum >/dev/null || die "sha256sum needed to derive the gate hash."
  HASH="$(printf %s "$COOKBOOK_DEMO_PASSWORD" | sha256sum | awk '{print $1}')"
  printf '{"sha256":"%s"}\n' "$HASH" > gate.json
  echo "   gate.json written (hash only — plaintext is never stored on disk or in git)"
elif [ -f gate.json ]; then
  echo "   using existing gate.json"
else
  die "no demo password configured — set COOKBOOK_DEMO_PASSWORD in $ENV_FILE (out-of-band), or create gate.json from gate.json.example."
fi

say "Starting the Caddy origin + Browser-Plane agent"
COOKBOOK_JOIN_TOKEN="$TOKEN" \
COOKBOOK_AGENT_TOKEN="$COOKBOOK_AGENT_TOKEN" \
COOKBOOK_AGENT_EDGE="$EDGE" \
COOKBOOK_AGENT_CP_URL="$CP_URL" \
COOKBOOK_AGENT_EDGE_CERT_URL="${COOKBOOK_AGENT_EDGE_CERT_URL:-$CP_URL/pki/ca}" \
  $COMPOSE up --build -d

say "Waiting for https://$HOSTNAME_FQDN/ (Caddy completes the deSEC DNS-01 challenge first) …"
for i in $(seq 1 60); do
  if curl -fsS --max-time 5 "https://$HOSTNAME_FQDN/" >/dev/null 2>&1; then
    printf '\033[32m✓ LIVE — https://%s/ serves the Flappy Pipeline Studio (unlock with the configured demo password).\033[0m\n' "$HOSTNAME_FQDN"
    exit 0
  fi
  sleep 5
done
echo "   Not reachable yet. Check:"
echo "     - DNS:   dig +short A $HOSTNAME_FQDN @1.1.1.1   (must be this host)"
echo "     - cert:  $COMPOSE logs cookbook-origin   (deSEC DNS-01 progress)"
echo "     - agent: $COMPOSE logs cookbook-agent     (onboard + hostname bind)"
echo "     - edge:  CT_EDGE_BROWSER_LISTEN=:443 set and :443 open inbound?"
die "demo not live within the timeout (see hints above)."
