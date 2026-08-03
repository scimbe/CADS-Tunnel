#!/usr/bin/env bash
# Apply loginTheme/accountTheme (and other simple top-level realm fields) to an
# ALREADY-RUNNING Keycloak's persisted realm via the Admin REST API.
#
# Why this exists: docker/deploy/keycloak/ct-demo-realm.json is only imported at
# Keycloak boot, and Keycloak's own import strategy is IGNORE_EXISTING -- once a
# realm already exists in the persisted data (docker/deploy/compose.sso.yml's
# keycloak_data volume, #307), re-importing on a restart is a no-op. A field added
# to the committed realm JSON (like accountTheme, #337) therefore does NOT reach an
# already-deployed Keycloak just by restarting it -- the only way to apply it to
# real, already-registered accounts' realm without wiping their data is a targeted
# Admin API PATCH, which is what this script does.
#
#   ./scripts/apply-realm-theme.sh                    # apply accountTheme (default)
#   ./scripts/apply-realm-theme.sh --field loginTheme --value some-theme
#
# Reads KEYCLOAK_PUBLIC_URL, KC_ADMIN_USER, KC_ADMIN_PASSWORD from
# docker/deploy/.env (same vars compose.sso.yml itself uses). Idempotent: setting
# a field to the value it already has is a safe no-op.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/docker/deploy/.env"
REALM="${REALM:-ct-demo}"
FIELD="accountTheme"
VALUE="ct-bunsenbrenner"

log()  { printf "\033[1m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[32m  ✓\033[0m %s\n" "$*"; }
warn() { printf "\033[33m  !\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --field) FIELD="$2"; shift 2 ;;
    --value) VALUE="$2"; shift 2 ;;
    --realm) REALM="$2"; shift 2 ;;
    *) die "unknown arg: $1 (use --field/--value/--realm)" ;;
  esac
done

[ -f "$ENV_FILE" ] || die "$ENV_FILE not found"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

: "${KEYCLOAK_PUBLIC_URL:?set KEYCLOAK_PUBLIC_URL in $ENV_FILE}"
: "${KC_ADMIN_USER:?set KC_ADMIN_USER in $ENV_FILE}"
: "${KC_ADMIN_PASSWORD:?set KC_ADMIN_PASSWORD in $ENV_FILE}"
command -v jq >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

log "Authenticating to Keycloak admin ($KEYCLOAK_PUBLIC_URL, realm master)"
TOKEN="$(curl -fsS -X POST "$KEYCLOAK_PUBLIC_URL/realms/master/protocol/openid-connect/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "username=$KC_ADMIN_USER" \
  --data-urlencode "password=$KC_ADMIN_PASSWORD" \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'client_id=admin-cli' \
  | jq -r '.access_token // empty')"
[ -n "$TOKEN" ] || die "could not obtain an admin token -- check KC_ADMIN_USER/KC_ADMIN_PASSWORD"
ok "admin token obtained"

log "Fetching current '$REALM' realm representation"
CURRENT="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM")"
[ -n "$CURRENT" ] || die "could not fetch realm '$REALM'"

CURRENT_VALUE="$(printf '%s' "$CURRENT" | jq -r --arg f "$FIELD" '.[$f] // "<unset>"')"
if [ "$CURRENT_VALUE" = "$VALUE" ]; then
  ok "'$FIELD' is already '$VALUE' on realm '$REALM' -- nothing to do"
  exit 0
fi
log "'$FIELD' is currently '$CURRENT_VALUE' -- setting to '$VALUE'"

PATCHED="$(printf '%s' "$CURRENT" | jq --arg f "$FIELD" --arg v "$VALUE" '.[$f] = $v')"
curl -fsS -X PUT "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "$PATCHED" >/dev/null
ok "applied"

log "Verifying"
NEW_VALUE="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM" | jq -r --arg f "$FIELD" '.[$f] // "<unset>"')"
[ "$NEW_VALUE" = "$VALUE" ] || die "verification failed: '$FIELD' reads back as '$NEW_VALUE', expected '$VALUE'"
ok "confirmed: realm '$REALM' now has $FIELD=$VALUE"
