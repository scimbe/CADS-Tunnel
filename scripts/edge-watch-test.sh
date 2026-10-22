#!/usr/bin/env bash
# Test fuer die Zustandswechsel-Meldungen von scripts/edge-watch.sh.
# Hermetisch: `docker` und `curl` sind Attrappen im PATH, es wird nichts versendet
# (CT_EDGE_WATCH_NO_MAIL=1) und kein echter Dienst angefragt.
#
#   bash scripts/edge-watch-test.sh        # Exit 0 = alle Aussagen halten
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
FAIL=0
ok()   { printf 'ok   %s\n' "$*"; }
bad()  { printf 'FAIL %s\n' "$*"; FAIL=1; }

# --- Attrappen -----------------------------------------------------------
cat > "$T/bin/docker" <<'SH'
#!/usr/bin/env bash
case "$1" in
  inspect) case "$*" in *RestartCount*) echo 0;; *StartedAt*) echo 2026-01-01T00:00:00Z;; *) echo true;; esac ;;
  exec) case "${*: -1}" in
          */healthz) printf 'ok\nchecked: relay, rendezvous\n' ;;
          */metrics) cat "$FAKE/metrics" ;;
        esac ;;
  logs) : ;;
esac
SH
cat > "$T/bin/curl" <<'SH'
#!/usr/bin/env bash
# Mit -w '%{http_code}': Code aus $FAKE/codes ("teilstring code"), sonst 200. Ohne -w: leer.
url="${*: -1}"
case "$*" in *"%{http_code}"*) ;; *) exit 0;; esac
while read -r pat code; do
  [ -n "$pat" ] || continue
  case "$url" in *"$pat"*) printf '%s' "$code"; exit 0;; esac
done < "$FAKE/codes"
printf 200
SH
chmod +x "$T/bin/docker" "$T/bin/curl"
export FAKE="$T" PATH="$T/bin:$PATH"
: > "$T/codes"
metrics() { cat > "$T/metrics" <<M
ct_edge_channel_broker_loop_expected_since_seconds{loop="relay"} 0
ct_edge_channel_join_penalty_tracked_ips 1
ct_edge_channel_join_penalty_tracked_ips_max 100
ct_edge_listener_loop_health_gating{listener="x"} 1
ct_edge_tcp_fallback_parked $1
ct_edge_tcp_fallback_reaped_total 7
M
}
metrics 5

export CT_EDGE_WATCH_STATE="$T/state" CT_EDGE_WATCH_NO_MAIL=1 CADS_TUNNEL_SRC="$T/none"
# Negative Anlaufzeit: auf Systemen ohne GNU-`date -d` (macOS) ist das Alter des Containers
# 0 oder -1 s; so gilt der Edge in beiden Faellen als eingelaufen.
export CT_WATCH_SETTLE_SECS=-60 CT_WATCH_RETRY_SLEEP=0 CT_WATCH_ZONE=test.invalid
export CT_WATCH_URLS="https://core.test.invalid/=200"
printf '# Kommentar\nalpha=200\nbeta=200   # eintrag mit Kommentar\n' > "$T/sites"
export CT_WATCH_SITES_FILE="$T/sites"

run() { OUT="$(${EWSH:-} "$HERE/edge-watch.sh" 2>&1)"; RC=$?; [ -z "${DEBUG:-}" ] || { echo "--- rc=$RC"; echo "$OUT"; }; }
has()  { printf '%s' "$OUT" | grep -qF -- "$1"; }
alarm_has() { printf '%s' "$OUT" | grep -F 'ALARM:' | grep -qF -- "$1"; }

# 1. alles gesund
run
[ "$RC" -eq 0 ] && has "Edge in Ordnung (Dienste geprueft: 3)" && ok "gesund: still, 3 Ziele aus Datei+URLS" || { bad "gesund: rc=$RC"; echo "$OUT"; }

# 2. beta faellt: erster Lauf alarmiert
echo "beta.test.invalid 503" > "$T/codes"
run
[ "$RC" -eq 1 ] && alarm_has "beta.test.invalid" && ok "ok->fehler: Alarm fuer beta" || { bad "ok->fehler rc=$RC"; echo "$OUT"; }
alarm_has "alpha.test.invalid" && bad "alpha faelschlich gemeldet" || ok "gesundes Ziel alpha nicht gemeldet"

# 3. beta bleibt tot: zweiter Lauf schweigt, nennt den Dauerfehler aber im Log
run
if [ "$RC" -eq 0 ] && ! has "ALARM:" && has "bekannte Dauerfehler: 1"; then ok "Dauerfehler: kein Alarm, aber sichtbar im Log"; else bad "Dauerfehler wiederholt: rc=$RC"; echo "$OUT"; fi

# 4. gleichzeitig faellt ein NEUES Ziel: nur dieses wird gemeldet (geht nicht im Dauerton unter)
printf 'beta.test.invalid 503\nalpha.test.invalid 000\n' > "$T/codes"
run
if alarm_has "alpha.test.invalid" && ! alarm_has "beta.test.invalid"; then ok "neuer Ausfall alpha wird gemeldet, alter beta nicht erneut"; else bad "neuer Ausfall"; echo "$OUT"; fi

# 5. Erinnerung: bei REMIND_H=0 kommt der Dauerfehler einmal wieder
CT_EDGE_REMIND_H=0 run
alarm_has "Erinnerung, Dauerfehler" && alarm_has "beta.test.invalid" && ok "Erinnerung an Dauerfehler nach Intervall" || { bad "Erinnerung"; echo "$OUT"; }
run
has "Erinnerung" && bad "Erinnerung vor Ablauf des Intervalls (24h)" || ok "keine Erinnerung innerhalb von 24h"

# 6. beide erholen sich: genau eine Entwarnung je Ziel, Exit 0
: > "$T/codes"
run
if [ "$RC" -eq 0 ] && has "ENTWARNUNG: https://beta.test.invalid/ wieder erreichbar" && has "ENTWARNUNG: https://alpha.test.invalid/ wieder erreichbar"; then ok "fehler->ok: Entwarnung, Exit 0"; else bad "Entwarnung rc=$RC"; echo "$OUT"; fi
run
has "ENTWARNUNG" && bad "Entwarnung doppelt" || ok "Entwarnung nur einmal"

# 7. Park-Regel: Wechsel statt Dauerton
metrics 94
rm -f "$T/state/tcp-reaped"
run   # kein Vorwert fuer die Reaps -> kein Urteil
has "ALARM:" && bad "Park: Alarm ohne Vorwert" || ok "Park: ohne Vorwert kein Urteil"
run   # Vorwert 7, Zaehler steht weiter bei 7
alarm_has "Park-Gauge bei 94" && ok "Park: Leichen-Signatur wird einmal gemeldet" || { bad "Park erster Alarm"; echo "$OUT"; }
run
has "ALARM:" && bad "Park: Dauerton" || ok "Park: Wiederholung bleibt still"
metrics 5
run
has "ENTWARNUNG: Park-Regel" && ok "Park: Entwarnung bei Rueckgang" || { bad "Park Entwarnung"; echo "$OUT"; }

# 8. unlesbare Zieldatei faellt laut auf statt still auf die Vorgabe zu springen
CT_WATCH_SITES_FILE="$T/gibt-es-nicht" run
alarm_has "nicht lesbar" && ok "unlesbare CT_WATCH_SITES_FILE wird gemeldet" || { bad "Zieldatei"; echo "$OUT"; }

exit "$FAIL"
