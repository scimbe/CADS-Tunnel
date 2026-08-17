#!/usr/bin/env bash
# Prüft, ob sich die neueste Sicherung tatsächlich AUSWERTEN lässt.
#
# Warum das zusätzlich zu `backup-freshness-check.sh` nötig ist: Jene Prüfung
# schaut auf Alter und Größe. Beides kann stimmen, während die Datei unbrauchbar
# ist -- eine falsche Passphrase, ein abgebrochener Upload, ein beschädigter
# Datenstrom. Man merkt es dann an dem einen Tag, an dem es darauf ankommt.
# "Eine Sicherung existiert" und "eine Sicherung lässt sich zurückspielen" sind
# zwei verschiedene Aussagen, und nur die zweite ist die, die zählt.
#
# Geprüft wird ohne jeden Eingriff in den laufenden Betrieb:
#   1. entschlüsseln           (Passphrase passt, Datenstrom unversehrt)
#   2. Archiv auflisten        (kein abgeschnittener tar-Strom)
#   3. Pflichtdateien da       (Keycloak-Dump, Control-Plane-DB, Manifest)
#   4. pg_restore --list       (liest das Inhaltsverzeichnis des Dumps; ein
#                               abgeschnittener Dump scheitert hier, ohne dass
#                               irgendetwas eingespielt wird)
#   5. sqlite integrity_check  (die Control-Plane-DB wirklich lesen)
#
# Exit 0 = wiederherstellbar. Exit 1 = Alarm (Mail + Logzeile).
set -euo pipefail

REPO="${CADS_BACKUP_REPO:-https://github.com/scimbe/CADS-Tunnel-backups.git}"
PASSFILE="${CADS_BACKUP_PASSFILE:-/home/becke/.config/cads-backup/passphrase}"
SRC="${CADS_TUNNEL_SRC:-/home/becke/workspace/CADS-Tunnel}"
ENVFILE="$SRC/docker/deploy/.env"
TO="${CADS_RECOVERY_TO:-scimbe@gmail.com}"
PGIMAGE="${CADS_PG_IMAGE:-postgres:16-alpine}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { ALARM="$*"; }

# Ausfallrichtung: Fehlt ein Werkzeug, ist die Prüfung NICHT gelaufen -- und das
# ist ein Befund, kein Freispruch. Sonst läse sich ein fehlendes gpg wie eine
# bestandene Prüfung.
for tool in gpg docker git; do
  command -v "$tool" >/dev/null || { log "FEHLER: $tool fehlt -- die Wiederherstellbarkeit ist damit UNGEPRUEFT"; exit 1; }
done
[ -r "$PASSFILE" ] || { log "FEHLER: keine Passphrase unter $PASSFILE -- ungeprueft"; exit 1; }

if ! git clone -q --depth 1 "$REPO" "$WORK/r" 2>/dev/null; then
  fail "Das Backup-Repository ist nicht erreichbar -- die Wiederherstellbarkeit konnte nicht geprueft werden."
fi

if [ -z "${ALARM:-}" ]; then
  NEWEST=$(ls -1 "$WORK/r/snapshots"/*.tar.gz.gpg 2>/dev/null | sort | tail -1 || true)
  [ -n "$NEWEST" ] || fail "Im Backup-Repository liegt kein Snapshot, der sich pruefen liesse."
fi

if [ -z "${ALARM:-}" ]; then
  STAMP=$(basename "$NEWEST" .tar.gz.gpg)
  log "pruefe $STAMP"

  # 1. Entschluesseln
  if ! gpg --batch --quiet --decrypt --passphrase-file "$PASSFILE" \
        --output "$WORK/snap.tar.gz" "$NEWEST" 2>"$WORK/gpg.err"; then
    fail "Der neueste Snapshot ($STAMP) laesst sich NICHT entschluesseln: $(tr -d '\n' < "$WORK/gpg.err" | head -c 200). Entweder passt die Passphrase nicht mehr, oder die Datei ist beschaedigt."
  fi
fi

if [ -z "${ALARM:-}" ]; then
  # 2./3. Archiv lesen und Pflichtdateien nachweisen
  if ! tar tzf "$WORK/snap.tar.gz" > "$WORK/list.txt" 2>"$WORK/tar.err"; then
    fail "Der entschluesselte Snapshot ($STAMP) ist kein lesbares Archiv: $(tr -d '\n' < "$WORK/tar.err" | head -c 200)."
  else
    MISSING=""
    for f in ./keycloak.pgdump ./control-plane.db ./MANIFEST.json; do
      grep -qx -- "$f" "$WORK/list.txt" || MISSING="$MISSING ${f#./}"
    done
    [ -z "$MISSING" ] || fail "Im Snapshot ($STAMP) fehlen Pflichtdateien:$MISSING. Ohne sie ist keine vollstaendige Wiederherstellung moeglich."
  fi
fi

if [ -z "${ALARM:-}" ]; then
  tar xzf "$WORK/snap.tar.gz" -C "$WORK" ./keycloak.pgdump ./control-plane.db 2>/dev/null || true

  # 4. Den Keycloak-Dump wirklich parsen lassen. `pg_restore --list` liest das
  #    Inhaltsverzeichnis des custom-format-Archivs -- ein abgeschnittener oder
  #    beschaedigter Dump scheitert hier, und es wird nichts eingespielt.
  if ! docker run --rm -v "$WORK/keycloak.pgdump":/d.pgdump:ro "$PGIMAGE" \
        pg_restore --list /d.pgdump > "$WORK/toc.txt" 2>"$WORK/pg.err"; then
    fail "Der Keycloak-Dump im Snapshot ($STAMP) laesst sich nicht lesen: $(tr -d '\n' < "$WORK/pg.err" | head -c 200). Ein Zurueckspielen wuerde scheitern."
  else
    ENTRIES=$(grep -c "TABLE DATA" "$WORK/toc.txt" || true)
    # Ein gueltiges, aber praktisch leeres Inhaltsverzeichnis ist kein brauchbarer
    # Stand -- die Groessenpruefung allein wuerde das nicht bemerken.
    [ "${ENTRIES:-0}" -ge 20 ] || fail "Der Keycloak-Dump im Snapshot ($STAMP) enthaelt nur ${ENTRIES:-0} Tabellen mit Daten -- zu wenig fuer einen vollstaendigen Realm-Stand."
  fi
fi

if [ -z "${ALARM:-}" ]; then
  # 5. Die Control-Plane-Datenbank wirklich lesen (nicht nur ihre Groesse ansehen).
  # Geprueft wird die Integritaet UND das Vorhandensein der Kerntabellen. Die
  # Zeilenzahlen daneben sind zum Ansehen, nicht als Schwelle: `tunnels` steht in
  # diesem Betrieb legitim auf 1 (die Hostnamen-Ansprueche liegen in
  # `mesh_ownership`), und eine Schwelle auf der falschen Tabelle waere ein
  # Dauerfehlalarm oder, schlimmer, ein Dauer-Freispruch.
  OUT=$(docker run --rm -v "$WORK/control-plane.db":/d.db:ro alpine sh -c \
        'apk add -q sqlite && sqlite3 /d.db "pragma integrity_check; select count(*) from mesh_ownership; select count(*) from channels; select count(*) from accounts;"' 2>"$WORK/sq.err" || true)
  if ! printf '%s' "$OUT" | grep -q "^ok"; then
    fail "Die Control-Plane-Datenbank im Snapshot ($STAMP) besteht die Integritaetspruefung nicht: $(printf '%s' "$OUT" | head -c 200)$(tr -d '\n' < "$WORK/sq.err" | head -c 120)."
  else
    # Kerntabellen: eine strukturell leere Datei besteht `integrity_check` klaglos --
    # genau der Fall, den die Groessenpruefung ebenfalls nicht sieht.
    # `.tables` statt eines SELECT mit Zeichenketten-Literal: in der einfach
    # gequoteten `sh -c`-Zeile bliebe `\"table\"` woertlich stehen, sqlite3 bekaeme
    # ungueltiges SQL und lieferte NICHTS -- woraufhin alle Kerntabellen als
    # "fehlend" galten. Beim ersten Probelauf genau so passiert: ein Fehlalarm aus
    # dem Zitieren, nicht aus den Daten. Die Sonde darf nicht daran scheitern, wie
    # sie geschrieben ist.
    TABLES=$(docker run --rm -v "$WORK/control-plane.db":/d.db:ro alpine sh -c \
        'apk add -q sqlite && sqlite3 /d.db .tables' 2>/dev/null || true)
    CORE_MISSING=""
    for t in tunnels mesh_ownership channels accounts join_tokens; do
      printf '%s\n' $TABLES | grep -qx "$t" || CORE_MISSING="$CORE_MISSING $t"
    done
    # Und wenn die Abfrage selbst nichts liefert, ist das ein Befund und kein
    # Freispruch -- sonst haette eine kaputte Sonde spaeter wie ein Fund ausgesehen.
    [ -n "$TABLES" ] || fail "Die Tabellenliste der Control-Plane-Datenbank im Snapshot ($STAMP) liess sich nicht auslesen -- die Pruefung konnte nicht stattfinden."
    [ -z "$CORE_MISSING" ] || fail "Der Control-Plane-Datenbank im Snapshot ($STAMP) fehlen Kerntabellen:$CORE_MISSING -- die Datei ist lesbar, aber kein vollstaendiger Stand."
    COUNTS=$(printf '%s' "$OUT" | tail -3 | tr '\n' '/')
    log "Keycloak-Dump: $(grep -c 'TABLE DATA' "$WORK/toc.txt") Tabellen mit Daten; Control-Plane: integrity ok, mesh_ownership/channels/accounts = ${COUNTS%/}"
  fi
fi

if [ -z "${ALARM:-}" ]; then
  log "Sicherung ist wiederherstellbar"
  exit 0
fi

log "ALARM: $ALARM"
if [ -r "$ENVFILE" ]; then
  SMTP_HOST=$(grep -E '^KC_SMTP_HOST=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_PORT=$(grep -E '^KC_SMTP_PORT=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_USER=$(grep -E '^KC_SMTP_USER=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_PASS=$(grep -E '^KC_SMTP_PASSWORD=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_FROM=$(grep -E '^KC_SMTP_FROM=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  export SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM TO ALARM
  python3 - <<'PY' || log "Warnung: Mailversand fehlgeschlagen"
import os, smtplib, ssl
from email.message import EmailMessage
m = EmailMessage()
m["From"] = os.environ["SMTP_FROM"]; m["To"] = os.environ["TO"]
m["Subject"] = "CADS-Tunnel: Sicherung ist NICHT wiederherstellbar"
m.set_content(
    os.environ["ALARM"] + "\n\n"
    "Geprueft wurde die neueste Sicherung: entschluesseln, Archiv lesen, Pflichtdateien,\n"
    "Keycloak-Dump parsen (pg_restore --list), Integritaet der Control-Plane-Datenbank.\n"
    "Es wurde nichts eingespielt und nichts am laufenden Betrieb veraendert.\n\n"
    "Eine Sicherung, die es gibt, und eine, die sich zurueckspielen laesst, sind zwei\n"
    "verschiedene Dinge. Diese Meldung betrifft die zweite.\n\n"
    "Nachsehen:\n"
    "  ./scripts/backup-verify.sh            # von Hand wiederholen\n"
    "  ./scripts/restore-selfhost.sh --list  # vorhandene Staende auflisten\n"
)
port = int(os.environ.get("SMTP_PORT") or 465)
ctx = ssl.create_default_context()
s = smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, context=ctx, timeout=30) if port == 465 else smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=30)
if port != 465: s.starttls(context=ctx)
s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"]); s.send_message(m); s.quit()
print("Alarm-Mail gesendet")
PY
fi
exit 1
