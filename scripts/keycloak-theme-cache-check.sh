#!/usr/bin/env bash
# Read-only check: does Keycloak serve the SAME theme CSS/JS to browsers (gzip) as on disk?
#
# Keycloak 26 keeps gzip copies of theme resources in java.io.tmpdir
# (/opt/keycloak/data/tmp/kc-gzip-cache/<resources-version>/...). The copy is written once and
# never compared with the file again. Browsers always send Accept-Encoding: gzip, so after a
# CSS change on disk they keep getting the OLD content, while curl without --compressed shows
# the new one. compose.sso.yml keeps /opt/keycloak/data on the keycloak_data volume, so the
# cache also survives `docker compose up -d --force-recreate keycloak`.
#
# For every CSS/JS file that the given sign-in pages link from a ct-* theme, this fetches the
# file twice (identity, gzip) and compares. Exit 1 if any differs, with the cache file to delete.
# Only GET requests; nothing is submitted, nothing is changed.
#
#   scripts/keycloak-theme-cache-check.sh                       # auth.bunsenbrenner.org, 3 clients
#   KC=https://auth.example.org/realms/ct-demo scripts/keycloak-theme-cache-check.sh URL...
set -euo pipefail

KC="${KC:-https://auth.bunsenbrenner.org/realms/ct-demo}"
ORIGIN="$(printf '%s' "$KC" | sed -E 's#^(https?://[^/]+).*#\1#')"
if [ $# -eq 0 ]; then
  CH="$(head -c 32 /dev/urandom | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  set -- \
    "$KC/protocol/openid-connect/registrations?response_type=code&scope=openid&client_id=ct-portal&redirect_uri=https%3A%2F%2Fbunsenbrenner.org%2Fportal%2Fcallback" \
    "$KC/protocol/openid-connect/registrations?response_type=code&scope=openid&client_id=praktikum-creator&redirect_uri=https%3A%2F%2Friisc.bunsenbrenner.org%2Foauth2%2Fcallback" \
    "$KC/protocol/openid-connect/registrations?response_type=code&scope=openid&client_id=mydailyidea&redirect_uri=https%3A%2F%2Fbunsenbrenner.org%2Fgate%2Fcallback&code_challenge=$CH&code_challenge_method=S256"
fi

paths="$(for u in "$@"; do curl -fsS -m 20 "$u"; done \
  | grep -oE '/resources/[a-z0-9]+/(login|account)/ct-[a-z-]+/[^"]+\.(css|js)' | sort -u)"
[ -n "$paths" ] || { echo "no ct-* theme resources found on the given pages" >&2; exit 2; }

stale=0
while read -r p; do
  plain="$(curl -fsS -m 20 -H 'Accept-Encoding: identity' "$ORIGIN$p" | shasum | cut -c1-12)"
  gz="$(curl -fsS -m 20 --compressed -H 'Accept-Encoding: gzip' "$ORIGIN$p" | shasum | cut -c1-12)"
  if [ "$plain" = "$gz" ]; then
    printf 'ok      %s\n' "$p"
  else
    stale=1
    # /resources/<ver>/<rest> -> /opt/keycloak/data/tmp/kc-gzip-cache/<ver>/<rest>.gz
    printf 'STALE   %s  (disk %s, gzip %s)\n        cache file: /opt/keycloak/data/tmp/kc-gzip-cache/%s.gz\n' \
      "$p" "$plain" "$gz" "${p#/resources/}"
  fi
done <<<"$paths"
exit "$stale"
