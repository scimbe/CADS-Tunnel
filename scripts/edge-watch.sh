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

# --- 0. Die Control-Plane ---------------------------------------------------
# Das Runbook schreibt "Alert on: /readyz flapping (DB reachability)" -- bis
# hierher stand das nur da. Der Waechter kannte die CP ueberhaupt nicht, obwohl
# sie unter dem Edge liegt: Ist ihre Datenbank nicht erreichbar, scheitern die
# Kanal-Autorisierung, die Rehydrierung nach einem Neustart (#548) und jede
# dynamische Portalseite -- waehrend `/healthz` und die statische Startseite
# weiter 200 liefern und dieser Waechter still bliebe.
#
# `/readyz` ist bewusst die gepruefte Adresse und nicht `/healthz`: seit #541
# liest sie aus einer echten Tabelle, ist also ein Aussage ueber die DATENBANK
# und nicht nur darueber, dass der Prozess Sockets annimmt.
CP_CONTAINER="${CT_WATCH_CP_CONTAINER:-ct-selfhost-control-plane-1}"
CP_READYZ="${CT_WATCH_CP_READYZ:-http://127.0.0.1:8090/readyz}"
if CP_RUNNING=$(docker inspect -f '{{.State.Running}}' "$CP_CONTAINER" 2>/dev/null); then
  if [ "$CP_RUNNING" != "true" ]; then
    ALARMS+=("Die Control-Plane '$CP_CONTAINER' laeuft nicht (State.Running=$CP_RUNNING) -- Kanal-Autorisierung und Rehydrierung haengen daran.")
  else
    CP_RESTARTS=$(docker inspect -f '{{.RestartCount}}' "$CP_CONTAINER" 2>/dev/null || echo 0)
    CP_PREV_FILE="$STATE_DIR/cp-restarts"
    CP_PREV=$(cat "$CP_PREV_FILE" 2>/dev/null || echo "$CP_RESTARTS")
    if [ "$CP_RESTARTS" -gt "$CP_PREV" ]; then
      # Der Container-Healthcheck der CP probt selbst /readyz, ein anhaltend
      # unbereiter Prozess wird also von Docker neu gestartet. Genau deshalb ist
      # ein STEIGENDER Zaehler das Flapping-Signal aus dem Runbook -- ein
      # Momentan-200 verdeckt es.
      ALARMS+=("Die Control-Plane wurde neu gestartet ($CP_PREV -> $CP_RESTARTS) -- ihr Healthcheck probt /readyz, ein Anstieg ist also das Flapping-Signal fuer die DB-Erreichbarkeit.")
    fi
    printf '%s' "$CP_RESTARTS" > "$CP_PREV_FILE"
    CP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$CP_READYZ" 2>/dev/null || true)
    [ -n "$CP_CODE" ] || CP_CODE=000
    [ "$CP_CODE" = "200" ] || \
      ALARMS+=("Control-Plane /readyz antwortet $CP_CODE (erwartet 200) -- die Datenbank ist nicht erreichbar; /healthz und die statische Startseite koennen dabei weiter 200 liefern.")
  fi
else
  # Wie ueberall hier: eine Pruefung, die nicht laufen kann, wird gesagt.
  ALARMS+=("Die Control-Plane '$CP_CONTAINER' existiert nicht -- /readyz konnte NICHT geprueft werden. Kein Freispruch, sondern eine fehlende Pruefung (Name via CT_WATCH_CP_CONTAINER anpassbar).")
fi

# --- 0b. Abgewiesene Anfragen an der Control-Plane (#561) -------------------
# Das Runbook verlangt Alarme bei anhaltenden 429ern auf `/me/issue` und bei
# Webhook-401ern. Beides war bis #561 UNMOEGLICH: alle drei Abweisungswege gaben
# ihren Fehler an den Aufrufer zurueck und hinterliessen sonst nichts -- kein
# Log, kein Zaehler. Die Vorschrift hatte also nichts zu beobachten, was sich
# von "es passiert nichts" nicht unterscheiden liess.
#
# Die beiden Ratenbegrenzer werden nur GEZAEHLT (eine Zeile je Abweisung wuerde
# die Flut, gegen die sie existieren, im Log wiederholen), der Webhook zusaetzlich
# geloggt -- er ist keine Flutflaeche, und eine seiner beiden Ursachen ist ein
# Faelschungsversuch.
CP_STATUS_URL="${CT_WATCH_CP_STATUS:-http://127.0.0.1:8090/status}"
CP_STATUS_JSON=$(curl -s --max-time 10 "$CP_STATUS_URL" 2>/dev/null || true)
CP_REFUSALS=$(printf '%s' "$CP_STATUS_JSON" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
k=("issue_rate_limited","unauth_write_rate_limited","payment_webhook_rejected")
if not all(x in d for x in k): sys.exit(2)
# uptime_seconds kommt mit: ohne sie liesse sich ein Neustart der CP nicht von
# "keine neuen Abweisungen" unterscheiden.
print(" ".join(str(int(d[x])) for x in k), int(d.get("uptime_seconds", 0)))
' 2>/dev/null) && CP_REFUSALS_OK=1 || CP_REFUSALS_OK=0

if [ "$CP_REFUSALS_OK" = "1" ]; then
  # Bewusst kein `set --`: die Positionsparameter des Skripts bleiben unberuehrt.
  ISSUE_NOW=$(printf '%s' "$CP_REFUSALS" | cut -d' ' -f1)
  UNAUTH_NOW=$(printf '%s' "$CP_REFUSALS" | cut -d' ' -f2)
  HOOK_NOW=$(printf '%s' "$CP_REFUSALS" | cut -d' ' -f3)
  UP_NOW=$(printf '%s' "$CP_REFUSALS" | cut -d' ' -f4)
  REF_FILE="$STATE_DIR/cp-refusals"
  # Erster Lauf: den Stand merken und NICHT alarmieren -- die Zaehler sind
  # prozessweite Summen seit Prozessstart, ihr Absolutwert sagt nichts ueber
  # jetzt. Alarmiert wird auf den Zuwachs seit dem letzten Lauf.
  ISSUE_PREV=$ISSUE_NOW; UNAUTH_PREV=$UNAUTH_NOW; HOOK_PREV=$HOOK_NOW; UP_PREV=$UP_NOW
  # `read` meldet bei einer Datei OHNE abschliessendes Zeilenende einen
  # Fehlschlag, obwohl es die Variablen korrekt gesetzt hat. Ein `|| default`
  # daran haette die gelesenen Werte wieder verworfen -- jeder Zuwachs waere
  # dann dauerhaft null gewesen und dieser Waechter haette NIE ausgeloest.
  # Deshalb wird die Datei unten MIT Zeilenende geschrieben und hier nur
  # gelesen, wenn sie existiert.
  if [ -s "$REF_FILE" ]; then
    read -r ISSUE_PREV UNAUTH_PREV HOOK_PREV UP_PREV < "$REF_FILE" || true
    UP_PREV=${UP_PREV:-0}
  fi
  # Ein Neustart der Control-Plane setzt die Zaehler auf null zurueck. Ohne
  # diese Erkennung verschwindet der Zuwachs genau dann, wenn der neue Stand
  # zufaellig wieder den alten erreicht -- am 18.08. real passiert: der Waechter
  # blieb bei zwei abgewiesenen Webhooks still, weil vor dem Rollout ebenfalls
  # zwei gezaehlt worden waren. Eine gefallene Laufzeit ist der eindeutige
  # Beleg; danach zaehlt der volle aktuelle Stand als Zuwachs.
  if [ "${UP_NOW:-0}" -lt "${UP_PREV:-0}" ]; then
    ISSUE_PREV=0; UNAUTH_PREV=0; HOOK_PREV=0
  fi
  # Ein Neustart der CP setzt die Zaehler zurueck; ein negativer Zuwachs ist
  # also kein Fehler, sondern genau das -- dann wird nur neu verankert.
  # Ein negativer Zuwachs bleibt zusaetzlich abgefangen: faellt die Laufzeit
  # einmal nicht (Uhrenspruenge, fehlendes Feld), ist ein gesunkener Zaehler
  # trotzdem nur als Ruecksetzung erklaerbar und nie als Alarm.
  D_ISSUE=$(( ISSUE_NOW - ISSUE_PREV )); [ "$D_ISSUE" -lt 0 ] && D_ISSUE=0
  D_UNAUTH=$(( UNAUTH_NOW - UNAUTH_PREV )); [ "$D_UNAUTH" -lt 0 ] && D_UNAUTH=0
  D_HOOK=$(( HOOK_NOW - HOOK_PREV )); [ "$D_HOOK" -lt 0 ] && D_HOOK=0

  # Schwellen: die Ratenbegrenzer duerfen vereinzelt greifen (ein hektischer
  # Client, ein Doppelklick) -- erst eine Haeufung im 10-Minuten-Fenster ist das
  # "sustained" aus dem Runbook. Der Webhook dagegen hat KEINE gutartige
  # Erklaerung im laufenden Betrieb: entweder ist das Geheimnis falsch
  # konfiguriert oder jemand faelscht. Deshalb Schwelle 1.
  [ "$D_ISSUE" -ge 20 ] && \
    ALARMS+=("$D_ISSUE abgewiesene /me/issue-Anfragen seit dem letzten Lauf (429) -- entweder laeuft ein Client Amok oder jemand probiert die Issue-Schnittstelle durch (#561).")
  [ "$D_UNAUTH" -ge 20 ] && \
    ALARMS+=("$D_UNAUTH abgewiesene unauthentisierte Schreibzugriffe seit dem letzten Lauf (429, #87) -- der Pro-IP-Begrenzer haelt gerade etwas zurueck.")
  [ "$D_HOOK" -ge 1 ] && \
    ALARMS+=("$D_HOOK Zahlungs-Webhook(s) mit ungueltiger Signatur abgewiesen (401) -- entweder ist das Webhook-Geheimnis falsch konfiguriert ODER jemand faelscht Webhooks. Beide Faelle brauchen eine Antwort; im Log der Control-Plane steht der Grund je Vorfall (#561).")
  printf '%s %s %s %s\n' "$ISSUE_NOW" "$UNAUTH_NOW" "$HOOK_NOW" "$UP_NOW" > "$REF_FILE"
elif [ -n "$CP_STATUS_JSON" ]; then
  # Gleiches Muster wie bei den Edge-Kennzahlen: eine Pruefung, die mangels
  # Feld nicht laufen kann, wird GESAGT. Sonst liest sich ihr Schweigen wie
  # "keine Abweisungen" -- und genau das war der Zustand vor #561.
  ALARMS+=("Die laufende Control-Plane liefert die Abweisungs-Zaehler auf /status nicht (Stand vor #561). 429-Haeufungen und Webhook-401er koennen deshalb NICHT geprueft werden -- kein Freispruch, sondern eine fehlende Pruefung. Abhilfe: Control-Plane neu ausrollen.")
fi

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

  # 5. Saettigung der Join-Straftabelle (#551). Das Runbook schreibt vor, auf das
  #    VERHAELTNIS zu alarmieren und nicht auf den Shed-Zaehler -- der bleibt in
  #    genau dem Fall bei null, den man fangen will: Verteilt sich ein Sturm auf
  #    mehr Quellen als die Tabelle fasst, verdraengt sie aelteste zuerst, keine
  #    IP erreicht je ihr Budget, und die Abwehr greift nie. Bis hierher stand
  #    diese Vorschrift nur in der Doku; sie hatte keinen Durchsetzer.
  TRACKED=$(printf '%s' "$MET" | awk '/^ct_edge_channel_join_penalty_tracked_ips / {print $2}' | head -1)
  TRACKED_MAX=$(printf '%s' "$MET" | awk '/^ct_edge_channel_join_penalty_tracked_ips_max / {print $2}' | head -1)
  TRACKED=${TRACKED%.*}; TRACKED_MAX=${TRACKED_MAX%.*}
  if [ -n "${TRACKED:-}" ] && [ "${TRACKED_MAX:-0}" -gt 0 ]; then
    # Ganzzahlig gerechnet (kein bc auf diesem Host): 10*belegt >= 9*Kapazitaet.
    if [ $(( TRACKED * 10 )) -ge $(( TRACKED_MAX * 9 )) ]; then
      ALARMS+=("Join-Straftabelle zu $(( TRACKED * 100 / TRACKED_MAX ))% belegt ($TRACKED/$TRACKED_MAX) -- an der Obergrenze verdraengt sie aelteste Eintraege, keine Quell-IP erreicht mehr ihr Budget, und die Pro-IP-Strafe greift dann gar nicht. Ein hoher Wert ist hier eine Warnung, keine Beruhigung (#551).")
    fi
  else
    # Gleiches Muster wie beim #539-Gauge oben: eine Pruefung, die mangels
    # Kennzahl nicht laufen kann, wird GESAGT und nicht verschwiegen -- sonst
    # liest sich ihr Schweigen wie ein Bestehen.
    ALARMS+=("Der laufende Edge kennt 'ct_edge_channel_join_penalty_tracked_ips' nicht (Stand vor #551). Die Saettigung der Join-Straftabelle kann deshalb NICHT geprueft werden -- kein Freispruch, sondern eine fehlende Pruefung. Abhilfe: Edge neu ausrollen.")
  fi
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
# Vollstaendige URLs, die keine Demo-Subdomain sind -- und die beiden wichtigsten
# Adressen ueberhaupt: das Portal (das Produkt selbst) und die Realm-Auskunft von
# Keycloak. Letztere ist mit Bedacht die Realm-URL und nicht die Startseite: am
# 16.08. lag die Auth-Ebene ~6 Minuten, weil die Realm-Importdatei den Start
# verhinderte -- ein Zustand, in dem Keycloak durchaus antworten kann, der Realm
# aber fehlt. Ohne diese beiden Zeilen haette der Waechter jenen Ausfall nicht
# gesehen (die Liste oben enthaelt nur die Demo-Tunnel).
URLS="${CT_WATCH_URLS:-https://bunsenbrenner.org/=200 https://auth.bunsenbrenner.org/realms/ct-demo=200}"

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
    # Eine gemeinsame Liste "url=code", damit Demo-Tunnel und Kernadressen durch
    # denselben Pruef- und Nachfass-Pfad laufen (zwei Schleifen driften auseinander).
    TARGETS=""
    for ENTRY in $SITES; do
      TARGETS="$TARGETS https://${ENTRY%%=*}.$ZONE/=${ENTRY##*=}"
    done
    TARGETS="$TARGETS $URLS"

    DOWN=""
    for ENTRY in $TARGETS; do
      URL="${ENTRY%=*}"; WANT="${ENTRY##*=}"
      # `curl -w '%{http_code}'` gibt bei einem Verbindungsfehler bereits "000" aus. Ein
      # zusaetzliches `|| echo 000` haengte ein zweites an ("000000") -- die Einstufung
      # unten fand darin ihr Muster nicht mehr und riet falsch. Beim ersten Probelauf so
      # aufgefallen.
      GOT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "$URL" 2>/dev/null || true)
      [ -n "$GOT" ] || GOT=000
      [ "$GOT" = "$WANT" ] || DOWN="$DOWN $URL:$GOT(erwartet $WANT)"
      SITES_CHECKED=$((SITES_CHECKED + 1))
    done
    # Zweiter Durchgang mit echtem Abstand statt einer Salve: eine Momentaufnahme
    # unterscheidet einen Aussetzer nicht von einem Ausfall, und dichtes Nachfassen
    # hat am 15.08. einen 70-Prozent-Ausfall komplett verdeckt. Nur was BEIDE Male
    # faellt, ist ein Alarm.
    if [ -n "$DOWN" ]; then
      sleep 30
      STILL=""
      for ENTRY in $TARGETS; do
        URL="${ENTRY%=*}"; WANT="${ENTRY##*=}"
        case "$DOWN" in *" $URL:"*) ;; *) continue;; esac
        GOT=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "$URL" 2>/dev/null || true)
        [ -n "$GOT" ] || GOT=000
        [ "$GOT" = "$WANT" ] || STILL="$STILL $URL:$GOT(erwartet $WANT)"
      done
      if [ -n "$STILL" ]; then
        # Der Hinweis muss zur Sache passen. Ein ausgefallener Demo-Tunnel und eine
        # ausgefallene Kernadresse haben nichts miteinander zu tun, und ein Text, der
        # bei einem Keycloak-Ausfall nach dem Hostname-Anspruch suchen laesst, schickt
        # den Betreiber in die falsche Richtung -- schlechter als gar kein Hinweis.
        HINT=""
        for U in $URLS; do
          case "$STILL" in *" ${U%=*}:"*) HINT="Betroffen ist eine KERNADRESSE (Portal bzw. Keycloak-Realm), nicht ein Demo-Tunnel: zuerst Keycloak-Start und Realm-Import pruefen (eine unbrauchbare Realm-Datei verhindert den Start).";; esac
        done
        # Der Hinweis muss zur ART des Fehlschlags passen, nicht nur zur Adresse.
        # Am 17.08. schlug der Waechter zum ersten Mal echt an (llm-34a13a96 lieferte
        # zweimal 500) und riet zu "verlorener Hostname-Anspruch / veraltete Edge-IP /
        # fehlgeschlagene Rehydrierung" -- lauter Ursachen, die eine 000 erzeugen und
        # niemals eine 500. Eine 5xx heisst das Gegenteil: der Tunnel HAT zugestellt,
        # und der Origin dahinter hat mit einem Fehler geantwortet. Wer daraufhin am
        # Tunnel sucht, sucht an der falschen Stelle.
        case "$STILL" in
          *":000("*)
            HINT="$HINT${HINT:+ }Mindestens ein Ziel antwortet gar nicht (000): das ist die Transportebene — verlorener Hostname-Anspruch, ein Agent mit veralteter Edge-IP, oder eine fehlgeschlagene Rehydrierung." ;;
        esac
        case "$STILL" in
          *":5"[0-9][0-9]"("*)
            HINT="$HINT${HINT:+ }Mindestens ein Ziel antwortet mit 5xx: der Tunnel hat ZUGESTELLT und der Origin dahinter meldet einen Fehler. Nicht am Tunnel suchen, sondern beim Dienst hinter dem Agenten (er gehoert oft einem Peer, nicht diesem Host)." ;;
        esac
        # Alles andere (z. B. 302 statt 200) ist weder Transport noch Origin-Fehler,
        # sondern meist eine Gate-/Weiterleitungsaenderung.
        case "$STILL" in
          *":000("*|*":5"[0-9][0-9]"("*) ;;
          *) HINT="$HINT${HINT:+ }Der Code weicht ab, ist aber weder 000 noch 5xx — meist eine geaenderte Weiterleitung oder ein Login-Gate; erwarteten Wert in CT_WATCH_SITES pruefen." ;;
        esac
        ALARMS+=("Dienste nicht erreichbar (zweimal im Abstand von 30s geprueft):$STILL. ${HINT:-Der Edge selbst laeuft.}")
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
