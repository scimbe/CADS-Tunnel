#!/usr/bin/env bash
# Prüft die Keycloak-Realm-Importdatei, BEVOR sie einen Neustart verhindert.
#
# Anlass (2026-08-16): Erklärende `_comment`-Felder in der Importdatei liessen
# Keycloak nicht mehr starten -- JSON kennt keine Kommentare, und Keycloaks
# Representations lehnen unbekannte Felder hart ab. Da der Import bei JEDEM
# Start läuft, war die Auth-Ebene ~6 Minuten offline. Nichts hatte die Datei
# vorher angesehen; `python -m json.tool` hätte sie für gültig erklärt, weil
# sie syntaktisch gültiges JSON ist. Geprüft werden muss das SCHEMA, und das
# kennt nur Keycloak selbst.
#
# Verfahren: `kc.sh import` in einem Wegwerf-Container gegen eine
# Wegwerf-Datenbank. Platzhalter (`${VAR}`) werden vorher durch syntaktisch
# gültige Attrappen ersetzt -- ihre echten Werte kommen aus der Umgebung und
# sind für die Schema-Frage ohne Belang, aber unaufgelöst scheitert die
# Validierung an "Root URL is not a valid URL" statt am echten Fehler.
#
# Wird von CI aufgerufen (.github/workflows/ci.yml, Job `realm-import`), aber nur
# wenn die Realm-JSON oder dieses Skript sich geändert hat -- der Lauf zieht das
# Keycloak-Image und kostet ~30 s. Die Run-Summary schreibt in BEIDEN Fällen eine
# Zeile, damit "nicht geprüft" nicht wie "bestanden" aussieht.
#
# Exit 0 = importierbar. Exit 1 = würde den Start verhindern.
#
# Attrappen fuer Absender-Platzhalter (2026-09-18, Folgeauftrag zu #811):
# Keycloak 26.7.3 validiert Absenderadressen beim Import, 25.0 tat das nicht --
# eine Hex-Attrappe wie fuer Secrets liess 26.7.3 daher scheitern, obwohl der
# echte Produktionswert eine gueltige Adresse ist. Platzhalter, deren Name
# FROM/MAIL/EMAIL/SENDER enthaelt, bekommen deshalb `validate@example.org`
# statt der Hex-Attrappe; substitute_placeholders() unten dokumentiert die
# Pruefreihenfolge. `--selftest` (oder VALIDATE_REALM_SELFTEST=1) prueft diese
# Zuordnung ohne Docker.
set -euo pipefail

# Ersetzt Platzhalter (`${VAR}`) in $1 durch syntaktisch gueltige Attrappen und
# schreibt das Ergebnis nach $2. Reihenfolge der Pruefung -- zuerst greift die
# erste zutreffende Regel:
#   1. Name enthaelt FROM, MAIL, EMAIL oder SENDER (ohne Gross-/Kleinschreibung)
#      -> `validate@example.org` (Keycloak 26.7.3 validiert Absenderadressen)
#   2. Name enthaelt URL oder URI -> `https://validate.example.org`
#   3. alles uebrige (Secrets, IDs, ...) -> Hex-Attrappe
substitute_placeholders() {
  local src="$1" dst="$2"
  python3 - "$src" "$dst" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
count = [0]
def sub(m):
    count[0] += 1
    name = m.group(1)
    if re.search(r"FROM|MAIL|EMAIL|SENDER", name, re.I):
        return "validate@example.org"
    if re.search(r"URL|URI", name, re.I):
        return "https://validate.example.org"
    return "0123456789abcdef0123456789abcdef"
s = re.sub(r"\$\{([A-Za-z0-9_]+)(?::[^}]*)?\}", sub, s)
open(dst, "w").write(s)
print(f"Platzhalter ersetzt: {count[0]} Stellen")
PY
}

# Selbsttest ohne Docker: prueft die Namens->Attrappe-Zuordnung von
# substitute_placeholders() direkt, unabhaengig von Realm-Datei und Image.
run_selftest() {
  local src dst
  src="$(mktemp)"; dst="$(mktemp)"
  trap 'rm -f "$src" "$dst"' RETURN
  cat > "$src" <<'JSON'
{
  "a": "${KC_SMTP_FROM}",
  "b": "${SMTP_MAIL}",
  "c": "${ADMIN_EMAIL}",
  "d": "${NOTIFY_SENDER}",
  "e": "${KC_HOSTNAME_URL}",
  "f": "${KC_PORTAL_CLIENT_SECRET}"
}
JSON
  substitute_placeholders "$src" "$dst" >/dev/null
  python3 - "$dst" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
checks = {
    "a": ("KC_SMTP_FROM", "validate@example.org"),
    "b": ("SMTP_MAIL", "validate@example.org"),
    "c": ("ADMIN_EMAIL", "validate@example.org"),
    "d": ("NOTIFY_SENDER", "validate@example.org"),
    "e": ("KC_HOSTNAME_URL", "https://validate.example.org"),
    "f": ("KC_PORTAL_CLIENT_SECRET", "0123456789abcdef0123456789abcdef"),
}
ok = True
for key, (name, expected) in checks.items():
    got = data[key]
    status = "OK" if got == expected else "FEHLER"
    if got != expected:
        ok = False
    print(f"{status}: {name} -> {got!r} (erwartet {expected!r})")
sys.exit(0 if ok else 1)
PY
}

if [ "${1:-}" = "--selftest" ] || [ "${VALIDATE_REALM_SELFTEST:-0}" = "1" ]; then
  run_selftest
  exit $?
fi

FILE="${1:-$(dirname "$0")/../docker/deploy/keycloak/ct-demo-realm.json}"
COMPOSE_FILE="${KC_COMPOSE_FILE:-$(dirname "$0")/../docker/deploy/compose.sso.yml}"

# Einzige Quelle der Wahrheit für das Default-Image: der `keycloak`-Dienst in
# compose.sso.yml (nicht der erste image-Eintrag der Datei -- postgres:16-alpine
# steht davor). KC_IMAGE überschreibt weiterhin; ohne Override und ohne Fund
# gibt es keinen stillen Rückfall auf eine feste Version.
DEFAULT_IMAGE="$(python3 - "$COMPOSE_FILE" <<'PY'
import re, sys
path = sys.argv[1]
try:
    text = open(path).read()
except OSError:
    print("")
    sys.exit(0)
in_service = False
image = ""
for line in text.splitlines():
    if re.match(r'^  keycloak:\s*(#.*)?$', line):
        in_service = True
        continue
    if in_service:
        if re.match(r'^  \S', line):
            break
        m = re.match(r'^\s{4,}image:\s*(\S+)\s*$', line)
        if m:
            image = m.group(1).strip('"\'')
            break
print(image)
PY
)"
if [ -z "${KC_IMAGE:-}" ] && [ -z "$DEFAULT_IMAGE" ]; then
  echo "FEHLER: kein image-Eintrag für den keycloak-Dienst in $COMPOSE_FILE gefunden."
  echo "        (Ein stiller Rückfall auf eine feste Version ist kein Freispruch.)"
  exit 1
fi
IMAGE="${KC_IMAGE:-$DEFAULT_IMAGE}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

command -v docker >/dev/null || {
  # Ohne Docker kann nur Keycloak selbst nicht befragt werden -- und eine
  # Pruefung, die nicht laufen kann, darf nicht wie eine bestandene aussehen.
  echo "FEHLER: docker fehlt -- die Schema-Pruefung braucht das Keycloak-Image."
  echo "        (Eine uebersprungene Pruefung ist kein Freispruch.)"
  exit 1
}
[ -r "$FILE" ] || { echo "FEHLER: $FILE nicht lesbar"; exit 1; }
python3 -c "import json,sys; json.load(open('$FILE'))" || { echo "FEHLER: kein gültiges JSON"; exit 1; }

# Attrappen: Absender-Platzhalter (FROM/MAIL/EMAIL/SENDER) brauchen eine
# gueltige Adresse, URL-artige Platzhalter eine echte URL, Secrets nur
# irgendeinen nichtleeren Wert. Die Unterscheidung anhand des Namens ist grob,
# aber sie muss nur die Validierung passieren lassen -- geprüft wird das
# Schema. Reihenfolge siehe substitute_placeholders() oben.
substitute_placeholders "$FILE" "$WORK/realm.json"

echo "validiere $(basename "$FILE") mit $IMAGE ..."
OUT="$WORK/out.txt"
if timeout 300 docker run --rm --entrypoint sh -v "$WORK/realm.json":/tmp/realm.json:ro "$IMAGE" \
     -c '/opt/keycloak/bin/kc.sh import --file /tmp/realm.json --db dev-file' > "$OUT" 2>&1; then
  echo "OK: die Datei ist importierbar"
  exit 0
fi
echo "FEHLGESCHLAGEN -- Keycloak würde damit NICHT starten:"
grep -iE "ERROR" "$OUT" | grep -viE "Failed to start server|For more details" | head -5 | sed 's/^/  /'
exit 1
