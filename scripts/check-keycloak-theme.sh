#!/usr/bin/env bash
# Prueft, dass das Login-Theme `ct-daily` (My-Daily-Idea-Look fuer den Client
# ct-portal) in Keycloak tatsaechlich LAEDT -- nicht nur, dass die Dateien da
# sind. Ein Tippfehler in theme.properties, ein falscher Parent oder ein
# fehlender Mount faellt in Keycloak still auf das Standard-Theme zurueck; die
# Anmeldung funktioniert dann weiter, sieht aber fremd aus. Genau das soll hier
# auffallen.
#
# Verfahren: ein Wegwerf-Keycloak (dasselbe Image wie compose.sso.yml) mit den
# Theme-Ordnern aus docker/deploy/keycloak/themes und einem Mini-Realm `ct-demo`,
# dessen Client ct-portal das login_theme aus der ECHTEN Realm-Datei bekommt.
# Dann per HTTP:
#   1. Login-Seite von ct-portal bindet ct-daily.css ein, Formular #kc-form-login da
#   2. ct-daily.css wird ausgeliefert (200) und traegt Schrift + Papierfarbe
#   3. die Anton-Schrift wird ausgeliefert (200, WOFF2-Signatur)
#   4. Registrierungsseite bindet ct-daily.css ein, Formular #kc-register-form da
# Ohne Docker laufen nur die statischen Pruefungen (Realm-Attribut, Lizenzdatei).
#
#   ./scripts/check-keycloak-theme.sh          # pruefen, Container danach weg
#   ./scripts/check-keycloak-theme.sh --keep   # Container laufen lassen (Vorschau)
#   PORT=18080 ./scripts/check-keycloak-theme.sh --keep
#
# Braucht kein Geheimnis: kein Admin-Konto, keine .env, kein Netz ausser dem
# Image-Pull. Exit 0 = Theme laedt. Exit 1 = es wuerde nicht (oder nur teilweise).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KC_DIR="$ROOT/docker/deploy/keycloak"
THEME="ct-daily"
CLIENT="ct-portal"
REDIRECT="http://localhost:8090/gate/callback"
PORT="${PORT:-18089}"
NAME="ct-kc-theme-check-$$"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

fail=0
ok()   { printf "  ok    %s\n" "$*"; }
bad()  { printf "  FEHLT %s\n" "$*" >&2; fail=1; }
die()  { printf "error: %s\n" "$*" >&2; exit 1; }

command -v jq >/dev/null || die "jq wird gebraucht"

echo "== statisch"
lt="$(jq -r --arg c "$CLIENT" '.clients[] | select(.clientId==$c) | .attributes.login_theme // empty' "$KC_DIR/ct-demo-realm.json")"
if [ "$lt" = "$THEME" ]; then ok "Realm-Datei: $CLIENT.login_theme = $THEME"; else bad "Realm-Datei: $CLIENT.login_theme ist '${lt:-<leer>}', erwartet $THEME"; fi
props="$KC_DIR/themes/$THEME/login/theme.properties"
if [ -f "$props" ]; then ok "theme.properties vorhanden"; else bad "$props fehlt"; fi
parent="$(sed -n 's/^parent=//p' "$props" 2>/dev/null || true)"
if [ "$parent" = "keycloak" ] || { [ -n "$parent" ] && [ -d "$KC_DIR/themes/$parent" ]; }; then
  ok "Parent '$parent' vorhanden"
else
  bad "Parent '${parent:-<leer>}' nicht unter themes/"
fi
if grep -q "SIL Open Font License" "$KC_DIR/themes/$THEME/login/resources/fonts/Anton-OFL.txt" 2>/dev/null; then
  ok "Anton-Lizenz (OFL 1.1) liegt bei"
else
  bad "fonts/Anton-OFL.txt fehlt"
fi
if grep -q "themes/$THEME:" "$ROOT/docker/deploy/compose.sso.yml"; then ok "compose.sso.yml mountet $THEME"; else bad "compose.sso.yml mountet $THEME nicht"; fi

if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo "== Keycloak: uebersprungen (kein Docker) -- das ist KEIN Bestehen der Ladepruefung"
  exit "$fail"
fi

IMAGE="$(sed -n 's/^ *image: *\(quay.io\/keycloak\/keycloak:[^ ]*\).*/\1/p' "$ROOT/docker/deploy/compose.sso.yml" | head -1)"
[ -n "$IMAGE" ] || die "Keycloak-Image nicht in compose.sso.yml gefunden"

work="$(mktemp -d)"
cleanup() {
  [ "$KEEP" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/import"
jq -n --arg c "$CLIENT" --arg t "$lt" --arg r "$REDIRECT" '{
  realm: "ct-demo", enabled: true, registrationAllowed: true, resetPasswordAllowed: true,
  loginWithEmailAllowed: true, internationalizationEnabled: true,
  supportedLocales: ["en", "de"], defaultLocale: "en", loginTheme: "ct-bunsenbrenner",
  clients: [{clientId: $c, enabled: true, publicClient: true, standardFlowEnabled: true,
             redirectUris: [$r], attributes: {login_theme: $t}}]
}' > "$work/import/ct-demo.json"
chmod -R a+rX "$work"

mounts=()
for d in "$KC_DIR"/themes/*/; do
  n="$(basename "$d")"
  mounts+=(-v "${d%/}:/opt/keycloak/themes/$n:ro")
done

echo "== Keycloak ($IMAGE) auf 127.0.0.1:$PORT"
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" "${mounts[@]}" \
  -v "$work/import:/opt/keycloak/data/import:ro" \
  "$IMAGE" start-dev --import-realm >/dev/null
BASE="http://127.0.0.1:$PORT"
up=0
for _ in $(seq 1 90); do
  if curl -fs -o /dev/null "$BASE/realms/ct-demo/.well-known/openid-configuration"; then up=1; break; fi
  sleep 2
done
[ "$up" = 1 ] || { docker logs --tail 40 "$NAME" >&2; die "Keycloak kam nicht hoch"; }

jar="$work/jar"
auth="$BASE/realms/ct-demo/protocol/openid-connect/auth?client_id=$CLIENT&redirect_uri=$(jq -rn --arg r "$REDIRECT" '$r|@uri')&response_type=code&scope=openid"
login="$(curl -fsS -c "$jar" -b "$jar" "$auth")"
css="$(printf '%s' "$login" | grep -o "/resources/[^\"]*/login/$THEME/css/$THEME.css" | head -1 || true)"
if [ -n "$css" ]; then ok "Login-Seite bindet $THEME.css ein"; else bad "Login-Seite ohne $THEME.css (Fallback auf ein anderes Theme?)"; fi
if printf '%s' "$login" | grep -q 'id="kc-form-login"'; then ok "Login-Formular #kc-form-login da"; else bad "Login-Formular fehlt"; fi

if [ -n "$css" ]; then
  body="$(curl -fsS "$BASE$css" || true)"
  if printf '%s' "$body" | grep -q '@font-face' && printf '%s' "$body" | grep -qi '#fff6dc'; then
    ok "$THEME.css ausgeliefert (Schrift + Papier #fff6dc)"
  else
    bad "$THEME.css leer oder ohne Schrift/Papierfarbe"
  fi
  font="${css%/css/$THEME.css}/fonts/anton-latin-400-normal.woff2"
  magic="$(curl -fsS "$BASE$font" | head -c 4 || true)"
  if [ "$magic" = "wOF2" ]; then ok "Anton-Schrift ausgeliefert (WOFF2)"; else bad "Anton-Schrift nicht ausgeliefert"; fi
fi

reg="$(printf '%s' "$login" | grep -o 'href="[^"]*login-actions/registration[^"]*"' | head -1 | sed 's/^href="//; s/"$//; s/&amp;/\&/g' || true)"
if [ -n "$reg" ]; then
  page="$(curl -fsS -c "$jar" -b "$jar" "$BASE$reg")"
  if printf '%s' "$page" | grep -q "/login/$THEME/css/$THEME.css"; then ok "Registrierung bindet $THEME.css ein"; else bad "Registrierung ohne $THEME.css"; fi
  if printf '%s' "$page" | grep -q 'id="kc-register-form"'; then ok "Registrierungsformular #kc-register-form da"; else bad "Registrierungsformular fehlt"; fi
else
  bad "kein Registrierungs-Link auf der Login-Seite"
fi

if [ "$KEEP" = 1 ]; then
  echo "== laeuft weiter: $auth"
  echo "   beenden mit: docker rm -f $NAME"
fi
if [ "$fail" = 0 ]; then echo "== Theme $THEME laedt"; else echo "== Theme $THEME laedt NICHT vollstaendig" >&2; fi
exit "$fail"
