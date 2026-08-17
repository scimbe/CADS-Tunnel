#!/usr/bin/env bash
# Wächter für die Edge-Signale, die einen stillen Ausfall anzeigen.
#
# Warum als Cron-Job und nicht als Sitzungsmonitor: Der bisherige #522-Wächter lief
# in einer Assistenten-Sitzung und wäre mit ihr verschwunden -- ein Wächter, dessen
# Ende niemandem auffällt, ist schlechter als keiner, weil sein Schweigen wie
# "alles in Ordnung" aussieht. Dieselbe Klasse, gegen die die geprüften Signale
# selbst gerichtet sind (#539, #541).
#
# Geprüft werden sechs Dinge, jedes davon aus einem echten Vorfall abgeleitet:
#
#   1. Container läuft / Neustartzähler  (verlässliches Down-Signal; ein
#      fehlgeschlagenes `docker exec` allein ist KEINES -- der Vorgänger hat
#      damit am 15.08. zweimal bei gesundem Edge fehlgefeuert)
#   2. /healthz                          (#539: sagt jetzt auch "vorgesehener
#                                         Broker-Loop nie angelaufen")
#   3. Park-Gauge > 80                   (#522: Leichen-Ansammlung, Reaper tot)
#   4. refused-111 im Log                (#522: Auslieferung an toten Park)
#   5. Broker-Loop-Stillstand            (letzter Schlag älter als 60s)
#   6. Die Dienste selbst                (die kanonischen Hostnamen; 1.-5. prüfen
#                                         nur den Prozess, und die realen Ausfälle
#                                         dieses Betriebs liessen den Edge gesund
#                                         und die Tunnel tot)
#
# Exit 0 = still, Exit 1 = Alarm (Mail + Logzeile).
set -euo pipefail

CONTAINER="${CT_EDGE_CONTAINER:-ct-selfhost-edge-1}"
METRICS="${CT_EDGE_METRICS_URL:-http://localhost:9600}"
PARK_MAX="${CT_EDGE_PARK_MAX:-80}"
BEAT_MAX_AGE="${CT_EDGE_BEAT_MAX_AGE:-60}"
STATE_DIR="${CT_EDGE_WATCH_STATE:-/var/tmp/cads-edge-watch}"
RENOTIFY_H="${CT_EDGE_RENOTIFY_H:-6}"     # gleiche Meldung höchstens alle N Stunden
SRC="${CADS_TUNNEL_SRC:-/home/becke/workspace/CADS-Tunnel}"
ENVFILE="$SRC/docker/deploy/.env"
TO="${CADS_RECOVERY_TO:-scimbe@gmail.com}"

mkdir -p "$STATE_DIR"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
ALARMS=()

command -v docker >/dev/null || { log "FEHLER: docker fehlt -- der Waechter kann nichts pruefen"; exit 1; }

# --- 1. Läuft der Container überhaupt? -------------------------------------
if ! RUNNING=$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null); then
  ALARMS+=("Der Edge-Container '$CONTAINER' existiert nicht mehr.")
elif [ "$RUNNING" != "true" ]; then
  ALARMS+=("Der Edge-Container laeuft nicht (State.Running=$RUNNING).")
else
  RESTARTS=$(docker inspect -f '{{.RestartCount}}' "$CONTAINER" 2>/dev/null || echo 0)
  PREV_FILE="$STATE_DIR/restarts"
  PREV=$(cat "$PREV_FILE" 2>/dev/null || echo "$RESTARTS")
  # Ein Rückgang bedeutet: der Container wurde neu erzeugt (Deploy) -- kein Alarm,
  # nur der neue Bezugspunkt. Ein Anstieg ist ein echter Absturz-Neustart.
  if [ "$RESTARTS" -gt "$PREV" ]; then
    ALARMS+=("Der Edge ist neu gestartet worden (Neustartzaehler $PREV -> $RESTARTS) -- ein Absturz, kein Deploy.")
  fi
  echo "$RESTARTS" > "$PREV_FILE"

  # --- 2..5 brauchen die Metrics/Health-Ebene ------------------------------
  # Ausfallrichtung: Wenn der Container LAEUFT, die Sonde aber nicht antwortet,
  # ist das ein Befund und kein Grund zu schweigen (#539/#541).
  HEALTH=$(docker exec "$CONTAINER" curl -fsS --max-time 5 "$METRICS/healthz" 2>&1 || echo "__UNREACHABLE__")
  if [ "$HEALTH" = "__UNREACHABLE__" ]; then
    ALARMS+=("Der Container laeuft, aber /healthz antwortet nicht -- der Prozess haengt vermutlich.")
  elif ! printf '%s' "$HEALTH" | grep -q "^ok"; then
    ALARMS+=("/healthz meldet einen Fehler: $(printf '%s' "$HEALTH" | head -c 300)")
  fi

  MET=$(docker exec "$CONTAINER" curl -fsS --max-time 5 "$METRICS/metrics" 2>/dev/null || true)
  if [ -z "$MET" ]; then
    [ "$HEALTH" != "__UNREACHABLE__" ] && \
      ALARMS+=("/metrics liefert nichts, obwohl /healthz antwortet -- die Messwerte fehlen, also ist ab hier nichts geprueft.")
  else
    # 3. Park-Gauge (#522)
    PARK=$(printf '%s' "$MET" | awk '/^ct_edge_tcp_fallback_parked /{print $2}' | head -1)
    if [ -n "${PARK:-}" ] && [ "${PARK%.*}" -gt "$PARK_MAX" ]; then
      ALARMS+=("Park-Gauge bei $PARK (Schwelle $PARK_MAX) -- Leichen sammeln sich an, der TCP-Park-Reaper arbeitet vermutlich nicht mehr (#522).")
    fi

    # 5. Broker-Loop-Stillstand; #539 unterscheidet dabei "nie vorgesehen" von
    #    "vorgesehen, aber nie angelaufen" -- beides steht in den Gauges.
    NOW=$(date +%s)
    # Ein Edge, der das #539-Gauge nicht kennt, ist aelter als der Fix. Ohne diese
    # Pruefung liefe die Schleife unten in `EXP=0` = "nicht vorgesehen" und bliebe
    # still -- ein Waechterzweig, der nicht feuern KANN, sieht aus wie einer, der
    # nichts findet. Genau die Verwechslung, gegen die #539 gebaut wurde.
    if ! printf '%s' "$MET" | grep -q "^ct_edge_channel_broker_loop_expected_since_seconds"; then
      ALARMS+=("Der laufende Edge kennt das Gauge 'expected_since' nicht (Stand vor #539). Der Waechter kann einen nie angelaufenen Broker-Loop deshalb NICHT erkennen -- das ist kein Freispruch, sondern eine fehlende Pruefung. Abhilfe: Edge neu ausrollen.")
    fi
    for LOOP in relay rendezvous; do
      LAST=$(printf '%s' "$MET" | awk -v l="$LOOP" '$0 ~ "^ct_edge_channel_broker_loop_last_seen_seconds\\{loop=\""l"\"\\}" {print $2}' | head -1)
      EXP=$(printf '%s' "$MET" | awk -v l="$LOOP" '$0 ~ "^ct_edge_channel_broker_loop_expected_since_seconds\\{loop=\""l"\"\\}" {print $2}' | head -1)
      [ -n "${LAST:-}" ] || continue
      LAST=${LAST%.*}; EXP=${EXP:-0}; EXP=${EXP%.*}
      if [ "$LAST" -gt 0 ]; then
        AGE=$(( NOW - LAST ))
        [ "$AGE" -gt "$BEAT_MAX_AGE" ] && \
          ALARMS+=("Broker-Loop '$LOOP' haengt: letzter Schlag vor ${AGE}s (Grenze ${BEAT_MAX_AGE}s). Channel-Joins ueber diesen Transport bleiben stehen.")
      elif [ "$EXP" -gt 0 ] && [ $(( NOW - EXP )) -gt "$BEAT_MAX_AGE" ]; then
        ALARMS+=("Broker-Loop '$LOOP' ist vorgesehen, aber nie angelaufen (seit $(( NOW - EXP ))s) -- vermutlich belegter Port oder Zertifikatsproblem beim Start (#539).")
      fi
    done
  fi

  # 4. refused-111-Signatur (#522). Nur das jüngste Fenster ansehen: die Zeilen
  #    sind der Beleg fuer eine Auslieferung an einen toten Park.
  REFUSED=$(docker logs --since 15m "$CONTAINER" 2>&1 | grep -ciE "os error 111|connection refused|no live park" || true)
  [ "${REFUSED:-0}" -gt 0 ] && \
    ALARMS+=("$REFUSED Zeile(n) mit der refused-111-Signatur in den letzten 15 Minuten (Basiswert 0) -- Browser-Auslieferung an einen toten Park (#522).")
fi

# --- 6. Die Dienste selbst -------------------------------------------------
# Warum das hier dazugehoert: Alles oben prueft den PROZESS. Genau die Ausfaelle,
# die diesen Betrieb bisher getroffen haben, liessen den Edge gesund und die
# Tunnel tot -- der verlorene Hostname-Anspruch (#502), Agenten mit
# zwischengespeicherter Edge-IP nach einem Recreate, eine fehlgeschlagene
# Rehydrierung. In all diesen Faellen haette dieser Waechter "Edge in Ordnung"
# gemeldet, waehrend die Seiten nicht erreichbar waren. Ein Waechter, der nur den
# Prozess kennt, prueft nicht das, wofuer es die Anlage gibt.
SITES="${CT_WATCH_SITES:-sort=200 help=200 llm-34a13a96=200 game2048=200 a2a-demo=200 auction-demo=200 cookbook=200 flappy-demo=200 devsystem-demo=302}"
ZONE="${CT_WATCH_ZONE:-bunsenbrenner.org}"
SETTLE="${CT_WATCH_SETTLE_SECS:-90}"

# Nur die kanonischen Namen aus dem Runbook -- Kurznamen wie `llm` haben keinen
# DNS-Eintrag, und ein "konnte nicht aufloesen" darauf waere ein Falschalarm
# (zweimal am 15.08. passiert).
SITES_CHECKED=0
if [ -n "${RUNNING:-}" ] && [ "$RUNNING" = "true" ]; then
  STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null || true)
  AGE=$(( $(date +%s) - $(date -d "${STARTED:-now}" +%s 2>/dev/null || date +%s) ))
  if [ "$AGE" -lt "$SETTLE" ]; then
    # Uebersprungen -- und das wird GESAGT. Nach einem Deploy brauchen die Tunnel
    # rund 25-45 s zur Rehydrierung; eine Messung darin erzeugt einen Falschalarm.
    # Schweigen waere hier aber schlimmer als der Falschalarm, weil es sich wie
    # "geprueft und in Ordnung" liest.
    log "Dienste NICHT geprueft: der Edge lief erst ${AGE}s (Rehydrierung bis ~${SETTLE}s) -- das ist kein Freispruch"
  else
    DOWN=""
    for ENTRY in $SITES; do
      HOST="${ENTRY%%=*}"; WANT="${ENTRY##*=}"
      GOT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "https://$HOST.$ZONE/" 2>/dev/null || echo 000)
      [ "$GOT" = "$WANT" ] || DOWN="$DOWN $HOST:$GOT(erwartet $WANT)"
      SITES_CHECKED=$((SITES_CHECKED + 1))
    done
    # Zweiter Durchgang mit echtem Abstand statt einer Salve: eine Momentaufnahme
    # unterscheidet einen Aussetzer nicht von einem Ausfall, und dichtes Nachfassen
    # hat am 15.08. einen 70-Prozent-Ausfall komplett verdeckt. Nur was BEIDE Male
    # faellt, ist ein Alarm.
    if [ -n "$DOWN" ]; then
      sleep 30
      STILL=""
      for ENTRY in $SITES; do
        HOST="${ENTRY%%=*}"; WANT="${ENTRY##*=}"
        case "$DOWN" in *" $HOST:"*) ;; *) continue;; esac
        GOT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "https://$HOST.$ZONE/" 2>/dev/null || echo 000)
        [ "$GOT" = "$WANT" ] || STILL="$STILL $HOST:$GOT(erwartet $WANT)"
      done
      if [ -n "$STILL" ]; then
        ALARMS+=("Dienste nicht erreichbar (zweimal im Abstand von 30s geprueft):$STILL. Der Edge selbst laeuft -- typische Ursachen: verlorener Hostname-Anspruch, ein Agent mit veralteter Edge-IP, fehlgeschlagene Rehydrierung.")
      else
        log "voruebergehender Aussetzer, beim zweiten Durchgang wieder erreichbar:$DOWN"
      fi
    fi
  fi
fi

if [ "${#ALARMS[@]}" -eq 0 ]; then
  log "Edge in Ordnung (Dienste geprueft: $SITES_CHECKED)"
  rm -f "$STATE_DIR/last-alarm"
  exit 0
fi

BODY=$(printf '%s\n' "${ALARMS[@]}")
log "ALARM: $(printf '%s' "$BODY" | tr '\n' ' ')"

# Wiederholungen dämpfen: dieselbe Meldung nicht alle 10 Minuten erneut senden.
# Der Alarm bleibt im Log und im Exit-Code -- gedämpft wird nur die Mail.
SIG=$(printf '%s' "$BODY" | cksum | awk '{print $1}')
LAST_FILE="$STATE_DIR/last-alarm"
if [ -r "$LAST_FILE" ]; then
  read -r LAST_SIG LAST_TS < "$LAST_FILE" || true
  if [ "${LAST_SIG:-}" = "$SIG" ] && [ $(( $(date +%s) - ${LAST_TS:-0} )) -lt $(( RENOTIFY_H * 3600 )) ]; then
    log "(gleiche Meldung wie zuletzt, Mail unterdrueckt bis ${RENOTIFY_H}h vergangen sind)"
    exit 1
  fi
fi
echo "$SIG $(date +%s)" > "$LAST_FILE"

if [ -r "$ENVFILE" ]; then
  SMTP_HOST=$(grep -E '^KC_SMTP_HOST=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_PORT=$(grep -E '^KC_SMTP_PORT=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_USER=$(grep -E '^KC_SMTP_USER=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_PASS=$(grep -E '^KC_SMTP_PASSWORD=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  SMTP_FROM=$(grep -E '^KC_SMTP_FROM=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
  export SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM TO BODY
  python3 - <<'PY' || log "Warnung: Mailversand fehlgeschlagen"
import os, smtplib, ssl
from email.message import EmailMessage
m = EmailMessage()
m["From"] = os.environ["SMTP_FROM"]; m["To"] = os.environ["TO"]
m["Subject"] = "CADS-Tunnel: Edge meldet eine Stoerung"
m.set_content(
    os.environ["BODY"] + "\n\n"
    "Geprueft wird der laufende Edge (Containerzustand, /healthz, Messwerte, Log-Signaturen).\n"
    "Diese Meldung wiederholt sich fruehestens nach 6 Stunden, solange sich nichts aendert.\n\n"
    "Nachsehen:\n"
    "  docker logs --tail 200 ct-selfhost-edge-1\n"
    "  docker exec ct-selfhost-edge-1 curl -s localhost:9600/healthz\n"
    "  tail /var/tmp/cads-edge-watch/cron.log\n"
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
