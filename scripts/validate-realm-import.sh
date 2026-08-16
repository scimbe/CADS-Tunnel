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
set -euo pipefail

FILE="${1:-$(dirname "$0")/../docker/deploy/keycloak/ct-demo-realm.json}"
IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:25.0}"
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

# Attrappen: URL-artige Platzhalter brauchen eine echte URL, Secrets nur
# irgendeinen nichtleeren Wert. Die Unterscheidung anhand des Namens ist grob,
# aber sie muss nur die Validierung passieren lassen -- geprüft wird das Schema.
python3 - "$FILE" "$WORK/realm.json" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
def sub(m):
    name = m.group(1)
    return "https://validate.example.org" if re.search(r"URL|URI", name, re.I) else "0123456789abcdef0123456789abcdef"
s = re.sub(r"\$\{([A-Za-z0-9_]+)(?::[^}]*)?\}", sub, s)
open(dst, "w").write(s)
print(f"Platzhalter ersetzt: {len(re.findall(r'validate.example.org|0123456789abcdef', s))} Stellen")
PY

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
