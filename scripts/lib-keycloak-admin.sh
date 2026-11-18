# CADS-Tunnel — shared Keycloak admin-API login for the realm-apply scripts
# (apply-realm-cli-client.sh, apply-realm-theme.sh, create-realm-test-account.sh).
# #1027: each script repeated the same log/ok/die helpers, .env loading, the
# three `:?` checks, the jq/curl presence checks and the identical
# password-grant curl against /realms/master/protocol/openid-connect/token.
#
# Not executable on its own — `source` it. Callers must set ENV_FILE before
# sourcing (the path to their docker/deploy/.env) and define warn() themselves
# if they use it (not every caller does); log()/ok()/die() are provided here.

log()  { printf "\033[1m==>\033[0m %s\n" "$*"; }
ok()   { printf "\033[32m  ✓\033[0m %s\n" "$*"; }
die()  { printf "\033[31merror:\033[0m %s\n" "$*" >&2; exit 1; }

# kc_admin_login: load ENV_FILE, validate KEYCLOAK_PUBLIC_URL/KC_ADMIN_USER/
# KC_ADMIN_PASSWORD are set, confirm jq+curl are present, then authenticate
# and set TOKEN (a plain variable, not a function return -- bash has no other
# cheap way to hand back a secret value to the caller's own scope). Also sets
# KEYCLOAK_PUBLIC_URL (already exported into the caller's scope via `set -a`
# below) so callers don't need to source ENV_FILE a second time themselves.
kc_admin_login() {
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
  TOKEN="$(curl -fsS --max-time 30 -X POST "$KEYCLOAK_PUBLIC_URL/realms/master/protocol/openid-connect/token" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "username=$KC_ADMIN_USER" \
    --data-urlencode "password=$KC_ADMIN_PASSWORD" \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_id=admin-cli' \
    | jq -r '.access_token // empty')"
  [ -n "$TOKEN" ] || die "could not obtain an admin token -- check KC_ADMIN_USER/KC_ADMIN_PASSWORD"
  ok "admin token obtained"
}
