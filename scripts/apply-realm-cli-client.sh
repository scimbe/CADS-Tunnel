#!/usr/bin/env bash
# Create (or update) the `ct-agent-cli` public device-flow client on an
# ALREADY-RUNNING Keycloak's persisted realm via the Admin REST API.
#
# Why this exists: docker/deploy/keycloak/ct-demo-realm.json is only imported at
# Keycloak boot, and Keycloak's own import strategy is IGNORE_EXISTING -- once a
# realm already exists in the persisted data (docker/deploy/compose.sso.yml's
# keycloak_data volume, #307), re-importing on a restart is a no-op. A client
# added to the committed realm JSON (like ct-agent-cli, RFC 8628 device flow for
# `ct-agent login`) therefore does NOT reach an already-deployed Keycloak just by
# restarting it -- the only way to apply it to a real, already-registered realm
# without wiping account data is a targeted Admin API call, which is what this
# script does. Same pattern as apply-realm-theme.sh (#337).
#
#   ./scripts/apply-realm-cli-client.sh
#
# Reads KEYCLOAK_PUBLIC_URL, KC_ADMIN_USER, KC_ADMIN_PASSWORD from
# docker/deploy/.env (same vars compose.sso.yml itself uses). Idempotent: if the
# client already exists, its settings are PUT-updated to match rather than
# duplicated.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/docker/deploy/.env"
REALM="${REALM:-ct-demo}"
CLIENT_ID="ct-agent-cli"

warn() { printf "\033[33m  !\033[0m %s\n" "$*" >&2; }

# shellcheck disable=SC1091
. "$ROOT/scripts/lib-keycloak-admin.sh"
kc_admin_login

CLIENT_REP="$(jq -n --arg cid "$CLIENT_ID" '{
  clientId: $cid,
  name: "ct-agent CLI (device code login)",
  protocol: "openid-connect",
  enabled: true,
  publicClient: true,
  standardFlowEnabled: false,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: false,
  serviceAccountsEnabled: false,
  fullScopeAllowed: true,
  redirectUris: [],
  webOrigins: [],
  attributes: { "oauth2.device.authorization.grant.enabled": "true" },
  defaultClientScopes: ["email", "profile"],
  protocolMappers: [{
    name: "sub",
    protocol: "openid-connect",
    protocolMapper: "oidc-usermodel-property-mapper",
    consentRequired: false,
    config: {
      "user.attribute": "id",
      "claim.name": "sub",
      "jsonType.label": "String",
      "access.token.claim": "true",
      "id.token.claim": "false",
      "userinfo.token.claim": "false"
    }
  }]
}')"

log "Checking for an existing '$CLIENT_ID' client on realm '$REALM'"
EXISTING_UUID="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  | jq -r '.[0].id // empty')"

if [ -n "$EXISTING_UUID" ]; then
  log "'$CLIENT_ID' already exists (id=$EXISTING_UUID) -- updating in place"
  curl -fsS -X PUT "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/clients/$EXISTING_UUID" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d "$CLIENT_REP" >/dev/null
  ok "updated"
else
  log "'$CLIENT_ID' does not exist yet -- creating"
  curl -fsS -X POST "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/clients" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d "$CLIENT_REP" >/dev/null
  ok "created"
fi

log "Verifying"
DEVICE_FLOW="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_PUBLIC_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  | jq -r '.[0].attributes["oauth2.device.authorization.grant.enabled"] // "<unset>"')"
[ "$DEVICE_FLOW" = "true" ] || die "verification failed: device grant attribute reads back as '$DEVICE_FLOW', expected 'true'"
ok "confirmed: client '$CLIENT_ID' on realm '$REALM' has device authorization grant enabled"
