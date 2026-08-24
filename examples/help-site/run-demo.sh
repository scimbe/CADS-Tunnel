#!/usr/bin/env bash
# Drive the help.bunsenbrenner.org demo to "live" in one command.
#
# Assumes a RUNNING plane on this host: ct-edge (with CT_EDGE_BROWSER_LISTEN=:443)
# and ct-control-plane. This script mints a join token, brings up the Caddy origin
# (real LE cert via deSEC DNS-01) + a Browser-Plane agent bound to the hostname,
# then polls until the page is served over HTTPS.
#
# Run it on the plane host (not a restricted client). Prereqs (see docs/dns01-desec.md):
#   - DNS: help.bunsenbrenner.org -> this host's public IP (via deSEC)
#   - :443 open inbound; deSEC token available
#
# Config (env or docker/deploy/.env):
#   HOSTNAME_FQDN   default help.bunsenbrenner.org
#   CP_URL          control-plane URL for enrollment   (e.g. http://127.0.0.1:8090)
#   EDGE            edge host:port for the agent        (e.g. 127.0.0.1:4433)
#   DESEC_TOKEN     deSEC API token (for Caddy's cert)
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE="${ENV_FILE:-../../docker/deploy/.env}"
[ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a || true

HOSTNAME_FQDN="${HOSTNAME_FQDN:-help.bunsenbrenner.org}"
CP_URL="${CP_URL:-${HELP_AGENT_CP_URL:-http://127.0.0.1:8090}}"
EDGE="${EDGE:-${HELP_AGENT_EDGE:-127.0.0.1:4433}}"
TENANT="${TENANT:-help-demo}"
# help-agent joins the plane's ct-selfhost_default network (see the networks:
# block in compose.help-site.yml), so its OWN CT_AGENT_CP_URL/CT_AGENT_EDGE must
# use the internal service names (control-plane:8090, edge:4433) — NOT the
# host-loopback CP_URL/EDGE above, which only this script (running on the host)
# can reach. Reusing those for the container was the bug: 127.0.0.1 inside the
# container means the container itself, so the agent could never reach the
# plane and crash-looped on /enroll/redeem.
AGENT_CP_URL="${AGENT_CP_URL:-http://control-plane:8090}"
AGENT_EDGE="${AGENT_EDGE:-edge:4433}"
# CT_AGENT_EDGE_CERT_URL (below, at the compose invocation) must be this bare
# control-plane base URL, not .../pki/ca — ct-agent's ControlPlaneClient::
# fetch_edge_cert() (crates/control-plane/src/client.rs) appends /pki/ca itself,
# so appending it here too produced a double .../pki/ca/pki/ca path (404 loop).
COMPOSE="docker compose -p help-site -f compose.help-site.yml"
# Edge admin endpoint for hostname-ownership authorization (#23 BP4b). Reuses the
# same URL+secret the control plane uses for the revoke/authorize push. When set,
# the demo authorizes `help.` and pins the agent's routing token so it works with
# CT_EDGE_REQUIRE_HOST_AUTH enabled. When unset, relies on BP4a (fine for one host).
EDGE_ADMIN_URL="${CT_CP_EDGE_ADMIN_URL:-}"
EDGE_ADMIN_TOKEN="${CT_CP_EDGE_ADMIN_TOKEN:-}"

say() { printf '\033[36m▶ %s\033[0m\n' "$*"; }
ok()  { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m  !\033[0m %s\n' "$*" >&2; }
log() { say "$@"; }
die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- Prereq checks (fail early, actionable) ------------------------------------
say "Checking prerequisites"
command -v docker >/dev/null || die "docker not found."
curl -fsS "$CP_URL/healthz" >/dev/null 2>&1 || curl -fsS "$CP_URL/status" >/dev/null 2>&1 \
  || die "control-plane not reachable at $CP_URL (is the plane running?). Set CP_URL."

RESOLVED="$(getent hosts "$HOSTNAME_FQDN" 2>/dev/null | awk '{print $1; exit}')" || true
if [ -z "$RESOLVED" ]; then
  echo "   ! $HOSTNAME_FQDN does not resolve yet (deSEC NS may still be propagating)."
  echo "     The agent/edge will work locally, but a browser needs public DNS -> this host."
else
  echo "   $HOSTNAME_FQDN -> $RESOLVED"
fi

# --- Mint a single-use join token ----------------------------------------------
# #87 (SEC87b-auth): the live CP gates POST /enroll/issue behind `x-ct-admin-token`,
# sourced from CT_CP_EDGE_ADMIN_TOKEN — the SAME shared secret used for the edge
# host-auth call below. Present it when set; an ungated dev CP ignores the header.
# (This script predated the gate, so a gated CP returned 401 here — #141.)
say "Minting a join token at $CP_URL/enroll/issue"
if [ -n "$EDGE_ADMIN_TOKEN" ]; then
  TOKEN="$(curl -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
            -H "x-ct-admin-token: $EDGE_ADMIN_TOKEN" \
            -d "{\"tenant\":\"$TENANT\"}" | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p')"
else
  TOKEN="$(curl -fsS -X POST "$CP_URL/enroll/issue" -H 'content-type: application/json' \
            -d "{\"tenant\":\"$TENANT\"}" | sed -n 's/.*"token":"\([0-9a-f]\{64\}\)".*/\1/p')"
fi
[ -n "$TOKEN" ] || die "could not mint a join token at $CP_URL/enroll/issue (if the CP gates /enroll/issue per #87, set CT_CP_EDGE_ADMIN_TOKEN in $ENV_FILE)"
echo "   token minted (single-use; not printed)"

# --- Authorize the hostname at the edge (#23 BP4b), if configured ---------------
HELP_AGENT_TOKEN=""
if [ -n "$EDGE_ADMIN_URL" ] && [ -n "$EDGE_ADMIN_TOKEN" ]; then
  command -v openssl >/dev/null || die "openssl needed to mint a routing token (or unset CT_CP_EDGE_ADMIN_URL to use BP4a)."
  HELP_AGENT_TOKEN="$(openssl rand -hex 32)"
  say "Authorizing $HOSTNAME_FQDN (hostname-ownership, BP4b)"
  # #502: prefer the control plane's proxy (/registry/authorize-host, #214) over the
  # edge admin endpoint -- ONLY the CP path records mesh ownership, and an edge
  # restart rehydrates exclusively recorded pairs. The old direct edge-admin call
  # left the authorization in edge RAM alone: every edge restart silently dropped
  # this hostname and took the demo down until a human re-ran this script.
  if curl -fsS -X POST "${CP_URL%/}/registry/authorize-host/$HELP_AGENT_TOKEN/$HOSTNAME_FQDN" \
       -H "x-ct-admin-token: $EDGE_ADMIN_TOKEN" >/dev/null 2>&1; then
    echo "   authorized via the control plane — ownership recorded, survives edge restarts."
  else
    curl -fsS -X POST "${EDGE_ADMIN_URL%/}/admin/authorize-host/$HELP_AGENT_TOKEN/$HOSTNAME_FQDN" \
         -H "x-ct-admin-token: $EDGE_ADMIN_TOKEN" >/dev/null \
      || die "authorize-host failed (check CT_CP_EDGE_ADMIN_URL / token / that the edge admin listener is up)."
    echo "   ! authorized directly at the edge (CP lacks /registry/authorize-host) —"
    echo "     ownership is NOT recorded: an edge restart drops it until this script re-runs."
  fi
  echo "   agent will register under this routing token (CT_AGENT_TOKEN)."
else
  echo "   ! edge host-auth not configured (CT_CP_EDGE_ADMIN_URL/TOKEN) — relying on BP4a (fine for one hostname)."
fi

# --- Cert (#219): issued HERE via the shared lib, using the operator's own
# DESEC_TOKEN — Caddy itself never sees the zone-wide token, only the resulting
# single-hostname fullchain.pem/privkey.pem it mounts read-only.
say "Obtaining the origin's TLS cert (core-side deSEC DNS-01)"
export HELP_CERT_DIR="${HELP_CERT_DIR:-$HOME/ct-certs/help}"
[ -n "${DESEC_TOKEN:-}" ] || die "DESEC_TOKEN is not set (needed to issue the cert; see docs/dns01-desec.md; put it in $ENV_FILE)."
export DESEC_TOKEN
ACME_EMAIL="${ACME_EMAIL:-scimbe@gmail.com}"
# shellcheck source=../../scripts/lib-acme.sh
. "../../scripts/lib-acme.sh"
issue_cert "$HOSTNAME_FQDN" "$HELP_CERT_DIR" true "$ACME_EMAIL"

# --- Bring up origin + browser agent -------------------------------------------
say "Starting the Caddy origin + Browser-Plane agent"
HELP_JOIN_TOKEN="$TOKEN" \
HELP_AGENT_TOKEN="$HELP_AGENT_TOKEN" \
HELP_AGENT_EDGE="$AGENT_EDGE" \
HELP_AGENT_CP_URL="$AGENT_CP_URL" \
HELP_AGENT_EDGE_CERT_URL="${HELP_AGENT_EDGE_CERT_URL:-$AGENT_CP_URL}" \
  $COMPOSE up --build -d

# --- Wait for it to serve over HTTPS -------------------------------------------
say "Waiting for https://$HOSTNAME_FQDN/ (Caddy completes the deSEC DNS-01 challenge first) …"
for i in $(seq 1 60); do
  if curl -fsS --max-time 5 "https://$HOSTNAME_FQDN/" >/dev/null 2>&1; then
    printf '\033[32m✓ LIVE — https://%s/ serves the demo with a valid certificate.\033[0m\n' "$HOSTNAME_FQDN"
    exit 0
  fi
  sleep 5
done

echo "   Not reachable yet. Check:"
echo "     - DNS: dig +short A $HOSTNAME_FQDN @1.1.1.1   (must be this host)"
echo "     - cert: $COMPOSE logs help-origin   (deSEC DNS-01 progress)"
echo "     - agent: $COMPOSE logs help-agent    (onboard + hostname bind)"
echo "     - edge:  CT_EDGE_BROWSER_LISTEN=:443 set and :443 open inbound?"
die "demo not live within the timeout (see hints above)."
