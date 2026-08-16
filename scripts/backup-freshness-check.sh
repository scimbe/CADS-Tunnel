#!/usr/bin/env bash
# Alarm, wenn die nächtliche Sicherung ausbleibt.
#
# Warum das nötig ist: Eine Sicherung, die still aufhört zu laufen, ist
# schlechter als keine -- man glaubt, abgesichert zu sein. Der Cron-Job selbst
# meldet einen Fehlschlag nur ins Log, das niemand liest; ein Host, der aus
# ist, meldet gar nichts. Diese Prüfung schaut auf das ERGEBNIS (liegt im
# Backup-Repository ein frischer Snapshot?) statt auf den Prozess, und ist
# damit auch dann aussagekräftig, wenn der Backup-Lauf gar nicht erst startete.
#
# Läuft absichtlich als EIGENER Cron-Job zu einer anderen Zeit: prüfte die
# Sicherung sich selbst, würde ihr Ausfall auch die Prüfung mitnehmen.
set -euo pipefail

REPO="${CADS_BACKUP_REPO:-https://github.com/scimbe/CADS-Tunnel-backups.git}"
MAX_AGE_H="${CADS_BACKUP_MAX_AGE_H:-30}"   # ein Tageslauf + Reserve
SRC="${CADS_TUNNEL_SRC:-/home/becke/workspace/CADS-Tunnel}"
ENVFILE="$SRC/docker/deploy/.env"
TO="${CADS_RECOVERY_TO:-scimbe@gmail.com}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

git clone -q --depth 1 "$REPO" "$WORK/r" 2>/dev/null || {
  log "ALARM: Backup-Repository nicht erreichbar ($REPO)"
  ALARM="Das Backup-Repository ist nicht erreichbar. Entweder fehlt der Zugang, oder es existiert nicht mehr."
}

if [ -z "${ALARM:-}" ]; then
  NEWEST=$(ls -1 "$WORK/r/snapshots"/*.tar.gz.gpg 2>/dev/null | sort | tail -1 || true)
  if [ -z "$NEWEST" ]; then
    ALARM="Im Backup-Repository liegt kein einziger Snapshot."
  else
    STAMP=$(basename "$NEWEST" .tar.gz.gpg)
    # Zeitstempel steckt im Dateinamen (2026-08-16T174828Z) -- unabhaengig von
    # Dateisystem-mtimes, die ein frischer Clone ohnehin neu setzt.
    EPOCH=$(date -u -d "$(echo "$STAMP" | sed -E 's/T([0-9]{2})([0-9]{2})([0-9]{2})Z/ \1:\2:\3/')" +%s 2>/dev/null || echo 0)
    AGE_H=$(( ( $(date -u +%s) - EPOCH ) / 3600 ))
    SIZE=$(stat -c%s "$NEWEST" 2>/dev/null || echo 0)
    log "neuester Snapshot: $STAMP (${AGE_H}h alt, $((SIZE/1024)) KB)"
    [ "$EPOCH" -eq 0 ] && ALARM="Der Zeitstempel des neuesten Snapshots ($STAMP) ist nicht lesbar."
    [ -z "${ALARM:-}" ] && [ "$AGE_H" -gt "$MAX_AGE_H" ] && \
      ALARM="Der neueste Snapshot ist ${AGE_H} Stunden alt (Grenze: ${MAX_AGE_H}h). Die naechtliche Sicherung laeuft offenbar nicht mehr."
    # Eine Datei, die zu klein ist, ist kein Snapshot -- sie ist ein Fehlschlag,
    # der es bis in das Repository geschafft hat.
    [ -z "${ALARM:-}" ] && [ "$SIZE" -lt 100000 ] && \
      ALARM="Der neueste Snapshot ist nur $((SIZE/1024)) KB gross -- das ist zu klein fuer einen vollstaendigen Stand."

    # Absolute Schranke allein reicht nicht: ein abgebrochener pg_dump liefert
    # eine Datei, die kleiner ist als sie sein sollte und trotzdem weit ueber
    # 100 KB liegt. Deshalb zusaetzlich der Vergleich mit dem VORIGEN Snapshot.
    # Am 16.08. halbierte sich die Groesse (2,4M -> 1,2M) -- damals harmlos (ein
    # herausgenommener Cache), aber dieselbe Signatur haette auch ein
    # abgeschnittenes Backup gehabt, und die absolute Schranke haette geschwiegen.
    PREV=$(ls -1 "$WORK/r/snapshots"/*.tar.gz.gpg 2>/dev/null | sort | tail -2 | head -1)
    if [ -z "${ALARM:-}" ] && [ -n "$PREV" ] && [ "$PREV" != "$NEWEST" ]; then
      PSIZE=$(stat -c%s "$PREV" 2>/dev/null || echo 0)
      if [ "$PSIZE" -gt 0 ] && [ "$((SIZE * 100 / PSIZE))" -lt 60 ]; then
        ALARM="Der neueste Snapshot ist $((SIZE/1024)) KB, der vorige war $((PSIZE/1024)) KB -- ein Rueckgang um $((100 - SIZE * 100 / PSIZE)) %. Entweder wurde absichtlich etwas herausgenommen, oder eine Sicherung ist unvollstaendig."
      fi
    fi
  fi
fi

if [ -z "${ALARM:-}" ]; then
  log "Sicherung in Ordnung"
  exit 0
fi

log "ALARM: $ALARM"
# Mail ueber denselben Weg wie die Wiederherstellungs-Mail; scheitert der Versand,
# bleibt der Alarm wenigstens im Log und der Exit-Code ungleich 0.
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
m["Subject"] = "CADS-Tunnel: Sicherung veraltet oder ausgefallen"
m.set_content(
    os.environ["ALARM"] + "\n\n"
    "Geprueft wird das Ergebnis im privaten Backup-Repository, nicht der Lauf selbst --\n"
    "diese Meldung kommt also auch dann, wenn der Backup-Job gar nicht erst gestartet ist.\n\n"
    "Nachsehen:\n"
    "  tail /var/tmp/cads-backup/cron.log\n"
    "  ./scripts/backup-selfhost.sh          # von Hand nachholen\n"
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
