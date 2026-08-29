#!/usr/bin/env bash
# Create (or reset the password on) a Keycloak test account on the live realm via the
# Admin REST API — for docs screenshots, feature verification, etc. Same auth pattern
# as apply-realm-theme.sh/apply-realm-cli-client.sh (KEYCLOAK_PUBLIC_URL/KC_ADMIN_USER/
# KC_ADMIN_PASSWORD from docker/deploy/.env).
#
#   ./scripts/create-realm-test-account.sh --email docs-test@bunsenbrenner.org --password '...'
#
# Idempotent: if the account already exists, only the password is (re)set, not a
# duplicate account created. Prints nothing sensitive to stdout beyond the email itself.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/docker/deploy/.env"
REALM="${REALM:-ct-demo}"
EMAIL=""
PASSWORD=""

log()  { printf "\033[1m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[32m  ✓\033[0m %s\n" "$*"; }
die()  { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --realm) REALM="$2"; shift 2 ;;
    *) die "unknown arg: $1 (use --email/--password/--realm)" ;;
  esac
done
[ -n "$EMAIL" ] || die "--email required"
[ -n "$PASSWORD" ] || die "--password required"

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
[ -n "$TOKEN" ] || die "could not obtain an admin token"
ok "admin token obtained"

log "Checking for an existing account: $EMAIL"
EXISTING_ID="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/users?email=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$EMAIL")&exact=true" \
  | jq -r '.[0].id // empty')"

if [ -n "$EXISTING_ID" ]; then
  log "account exists (id=$EXISTING_ID) -- resetting password only"
  USER_ID="$EXISTING_ID"
else
  log "creating account"
  USER_REP="$(jq -n --arg email "$EMAIL" '{
    username: $email, email: $email, enabled: true, emailVerified: true
  }')"
  LOCATION="$(curl -fsS -D - -o /dev/null -X POST "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/users" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$USER_REP" \
    | grep -i '^location:' | tr -d '\r' | awk '{print $2}')"
  [ -n "$LOCATION" ] || die "user creation did not return a Location header"
  USER_ID="${LOCATION##*/}"
  ok "created (id=$USER_ID)"
fi

log "Setting password"
CRED_REP="$(jq -n --arg pw "$PASSWORD" '{type: "password", value: $pw, temporary: false}')"
curl -fsS -X PUT "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/users/$USER_ID/reset-password" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d "$CRED_REP" >/dev/null
ok "password set"
ok "account ready: $EMAIL (id=$USER_ID)"
