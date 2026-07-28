#!/usr/bin/env bash
# mint-oidc-token.sh — mint a short-lived OIDC bearer token via the realm's admin-cli
# client (Resource Owner Password Credentials grant), per docs/agent-onboarding.md §A.2.
# Prints the bare access_token to stdout (nothing else) so it composes in scripts:
#   TOKEN=$(OIDC_USERNAME=you@example.com OIDC_PASSWORD=... ./mint-oidc-token.sh)
#
# The token is typically short-lived (a Keycloak realm default is minutes, not hours) —
# mint fresh for each script that needs one rather than caching it.
#
# Env:
#   OIDC_ISSUER_BASE   required — realm base, e.g. https://auth.bunsenbrenner.org/realms/ct-demo
#   OIDC_USERNAME       required — the account's email/username
#   OIDC_PASSWORD       required — the account's password
#   OIDC_CLIENT_ID      optional — default "admin-cli" (the public client agent-onboarding.md uses)
set -euo pipefail

die() { printf 'mint-oidc-token: %s\n' "$*" >&2; exit 1; }

: "${OIDC_ISSUER_BASE:?set OIDC_ISSUER_BASE, e.g. https://auth.bunsenbrenner.org/realms/ct-demo}"
: "${OIDC_USERNAME:?set OIDC_USERNAME}"
: "${OIDC_PASSWORD:?set OIDC_PASSWORD}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-admin-cli}"

command -v curl >/dev/null || die "curl not found."
command -v python3 >/dev/null || die "python3 not found (used for safe JSON parsing)."

RESP="$(curl -fsS --max-time 15 -X POST "${OIDC_ISSUER_BASE%/}/protocol/openid-connect/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  --data-urlencode "client_id=${OIDC_CLIENT_ID}" \
  --data-urlencode "username=${OIDC_USERNAME}" \
  --data-urlencode "password=${OIDC_PASSWORD}")" \
  || die "token request failed (bad credentials, wrong realm, or direct-access-grants disabled for ${OIDC_CLIENT_ID})"

printf '%s' "$RESP" | python3 -c '
import sys, json
d = json.load(sys.stdin)
tok = d.get("access_token")
if not tok:
    sys.stderr.write("mint-oidc-token: response had no access_token\n")
    sys.exit(1)
sys.stdout.write(tok)
' || die "could not parse access_token from response"
