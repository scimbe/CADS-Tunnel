#!/usr/bin/env bash
# watchdog-serve-roles.sh — detect a hung/dead bare-host `serve-role.sh` process for a demo
# and restart it. A hung process is NOT distinguishable from a healthy-but-idle one by process
# liveness alone (ct-agent's own process stays running even when its handler calls are
# silently stalling — see CADS-Tunnel#214's degradation writeup), so health is judged by an
# actual end-to-end build against the real, live page — the same thing a real user hitting a
# hang would see — not by pinging the process.
#
# Usage (one demo per invocation):
#   DEMO_URL=https://flappy-demo.bunsenbrenner.org BUILD_PATH=/crew/build \
#   BUILD_BODY='{"prompt":"watchdog health check"}' \
#   ROLES="SAFETY:safety_check:safety-check-handler.sh PHYSICS:text_generation:physics-handler.sh ART:text_generation:art-handler.sh" \
#   SERVE_PREFIX=SERVE_FLAPPY HANDLERS_DIR=/path/to/CADS-flappy-demo/handlers \
#   SHARED_ENV=/path/to/shared.env CT_AGENT=/path/to/ct-agent \
#     ./watchdog-serve-roles.sh
#
#   ./watchdog-serve-roles.sh --selftest   # verify inputs resolve, no network calls
set -euo pipefail

die() { printf 'watchdog: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] watchdog %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

: "${ROLES:?set ROLES, e.g. 'SAFETY:safety_check:safety-check-handler.sh PHYSICS:text_generation:physics-handler.sh'}"
: "${SERVE_PREFIX:?set SERVE_PREFIX, e.g. SERVE_FLAPPY or SERVE_COOKBOOK (matches shared.env var prefix)}"
: "${HANDLERS_DIR:?set HANDLERS_DIR, the demo repo handlers directory}"
: "${SHARED_ENV:?set SHARED_ENV, the operator env file with holder/noise/grant material}"
CT_AGENT="${CT_AGENT:-ct-agent}"
CT_AGENT_EDGE_BROKER="${CT_AGENT_EDGE_BROKER:-57.131.133.91:4435}"
CT_AGENT_EDGE_RELAY="${CT_AGENT_EDGE_RELAY:-57.131.133.91:4436}"
LOG_DIR="${SERVE_LOG_DIR:-/tmp}"

if [ "${1:-}" = "--selftest" ] || [ "${WATCHDOG_SELFTEST:-0}" = "1" ]; then
  command -v "$(printf '%s' "$CT_AGENT" | awk '{print $1}')" >/dev/null 2>&1 || die "ct-agent not resolvable"
  [ -f "$SHARED_ENV" ] || die "SHARED_ENV=$SHARED_ENV not found"
  [ -d "$HANDLERS_DIR" ] || die "HANDLERS_DIR=$HANDLERS_DIR not found"
  for entry in $ROLES; do
    role="${entry%%:*}"; rest="${entry#*:}"; handler="${rest#*:}"
    [ -x "$HANDLERS_DIR/$handler" ] || die "handler $HANDLERS_DIR/$handler (role $role) not executable"
  done
  echo "watchdog: selftest passed — ct-agent, shared env, and all handlers resolvable"
  exit 0
fi

: "${DEMO_URL:?set DEMO_URL, e.g. https://flappy-demo.bunsenbrenner.org}"
: "${BUILD_PATH:?set BUILD_PATH, e.g. /crew/build}"
: "${BUILD_BODY:?set BUILD_BODY, e.g. '{\"prompt\":\"watchdog health check\"}'}"

# A real build is the only trustworthy health signal (see header). "built" appearing anywhere
# in the streamed NDJSON response means every role answered; an "unreachable"/timeout/hang means
# at least one didn't. Bounded wait so a genuinely stuck watchdog run can't itself hang forever.
HEALTH_TIMEOUT="${WATCHDOG_HEALTH_TIMEOUT:-45}"
RESULT="$(timeout "$HEALTH_TIMEOUT" curl -fsS --max-time "$HEALTH_TIMEOUT" -X POST "$DEMO_URL$BUILD_PATH" \
  -H 'content-type: application/json' -d "$BUILD_BODY" 2>/dev/null || true)"

if printf '%s' "$RESULT" | grep -q '"stage":"built"'; then
  log "healthy — build completed for $DEMO_URL$BUILD_PATH"
  exit 0
fi

log "UNHEALTHY — build did not complete within ${HEALTH_TIMEOUT}s for $DEMO_URL$BUILD_PATH, restarting all roles"

# Kill every currently-running serve process for this demo's roles (matched by holder-key env
# value baked into each process's command line is not visible via ps; instead we track PIDs
# this script itself started via a pidfile per role, falling back to a best-effort pattern kill
# if no pidfile exists yet, e.g. on first run).
PIDFILE_DIR="${WATCHDOG_PIDFILE_DIR:-/tmp/ct-serve-pids}"
mkdir -p "$PIDFILE_DIR"

for entry in $ROLES; do
  role="${entry%%:*}"
  rest="${entry#*:}"
  service="${rest%%:*}"
  handler="${rest#*:}"
  pidfile="$PIDFILE_DIR/${SERVE_PREFIX}_${role}.pid"

  if [ -f "$pidfile" ]; then
    oldpid="$(cat "$pidfile" 2>/dev/null || true)"
    if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
      log "role=$role stopping stale serve pid=$oldpid"
      kill "$oldpid" 2>/dev/null || true
      sleep 1
      kill -9 "$oldpid" 2>/dev/null || true
    fi
  fi

  holder_var="${SERVE_PREFIX}_${role}_HOLDER_KEY"
  noise_var="${SERVE_PREFIX}_${role}_NOISE_KEY"
  grant_var="${SERVE_PREFIX}_${role}_GRANT"
  holder="$(grep "^${holder_var}=" "$SHARED_ENV" | cut -d= -f2-)"
  noise="$(grep "^${noise_var}=" "$SHARED_ENV" | cut -d= -f2-)"
  grant="$(grep "^${grant_var}=" "$SHARED_ENV" | cut -d= -f2-)"
  [ -n "$holder" ] && [ -n "$noise" ] && [ -n "$grant" ] \
    || { log "role=$role SKIPPED — missing $holder_var/$noise_var/$grant_var in $SHARED_ENV"; continue; }

  log "role=$role restarting (service=$service handler=$handler)"
  nohup env \
    CT_AGENT="$CT_AGENT" \
    CT_AGENT_EDGE_BROKER="$CT_AGENT_EDGE_BROKER" \
    CT_AGENT_EDGE_RELAY="$CT_AGENT_EDGE_RELAY" \
    HOLDER_KEY="$holder" NOISE_KEY="$noise" GRANT="$grant" \
    SERVICE="$service" HANDLER_CMD="$HANDLERS_DIR/$handler" \
    "$(dirname "$0")/serve-role.sh" > "$LOG_DIR/serve-${role}.log" 2>&1 &
  newpid=$!
  disown
  echo "$newpid" > "$pidfile"
  log "role=$role started pid=$newpid"
done

sleep 5
RECHECK="$(timeout "$HEALTH_TIMEOUT" curl -fsS --max-time "$HEALTH_TIMEOUT" -X POST "$DEMO_URL$BUILD_PATH" \
  -H 'content-type: application/json' -d "$BUILD_BODY" 2>/dev/null || true)"
if printf '%s' "$RECHECK" | grep -q '"stage":"built"'; then
  log "recovered — build completed after restart"
  exit 0
else
  log "STILL UNHEALTHY after restart — this is a NEW problem, not the known bare-host degradation pattern; escalate"
  exit 1
fi
