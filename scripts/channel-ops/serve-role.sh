#!/usr/bin/env bash
# serve-role.sh — bring up a long-lived `ct-agent channel` accept/serve process for
# one role, wired to a handler script, relay-only (no dialable address needed — #173).
# Runs in the foreground; the caller backgrounds it (nohup/&, a systemd unit, a
# supervisor, docker, etc. — this script itself does none of that).
#
# Usage:
#   CT_AGENT_EDGE_BROKER=bunsenbrenner.org:4435 \
#   CT_AGENT_EDGE_RELAY=bunsenbrenner.org:4436 \
#   HOLDER_KEY=<64-hex priv> NOISE_KEY=<64-hex priv> GRANT=<hex signed grant> \
#   SERVICE=text_generation HANDLER_CMD=/path/to/physics-handler.sh \
#     ./serve-role.sh
#
#   ./serve-role.sh --selftest   # verify ct-agent + handler are resolvable, no network
set -euo pipefail

die() { printf 'serve-role: %s\n' "$*" >&2; exit 1; }

CT_AGENT="${CT_AGENT:-ct-agent}"

if [ "${1:-}" = "--selftest" ]; then
  command -v "$(printf '%s' "$CT_AGENT" | awk '{print $1}')" >/dev/null 2>&1 || die "ct-agent not resolvable (CT_AGENT=$CT_AGENT)"
  [ -n "${HANDLER_CMD:-}" ] || die "--selftest still needs HANDLER_CMD set, to check it exists"
  [ -x "$HANDLER_CMD" ] || die "HANDLER_CMD=$HANDLER_CMD not executable"
  echo "serve-role: ct-agent + handler resolvable — selftest passed (no CP/edge calls made)"
  exit 0
fi

: "${CT_AGENT_EDGE_BROKER:?set CT_AGENT_EDGE_BROKER (edge rendezvous host:port)}"
: "${CT_AGENT_EDGE_RELAY:?set CT_AGENT_EDGE_RELAY (edge relay host:port, often same as broker)}"
: "${HOLDER_KEY:?set HOLDER_KEY (64-hex, the serving holder PRIVATE key)}"
: "${NOISE_KEY:?set NOISE_KEY (64-hex, the serving noise PRIVATE key)}"
: "${GRANT:?set GRANT (hex signed grant for this role, accept direction)}"
: "${SERVICE:?set SERVICE (text_generation | safety_check | code_generation | security_review)}"
: "${HANDLER_CMD:?set HANDLER_CMD (path to the handler script for this role)}"

[ -x "$HANDLER_CMD" ] || die "HANDLER_CMD=$HANDLER_CMD not found or not executable"

echo "serve-role: starting SERVICE=$SERVICE HANDLER_CMD=$HANDLER_CMD via broker=$CT_AGENT_EDGE_BROKER" >&2
exec env \
  CT_CHANNEL_ROLE=accept \
  CT_CHANNEL_SERVE=1 \
  CT_CHANNEL_RELAY_ONLY=1 \
  CT_CHANNEL_BROKER="$CT_AGENT_EDGE_BROKER" \
  CT_CHANNEL_RELAY="$CT_AGENT_EDGE_RELAY" \
  CT_CHANNEL_HOLDER_KEY="$HOLDER_KEY" \
  CT_CHANNEL_NOISE_KEY="$NOISE_KEY" \
  CT_CHANNEL_GRANT="$GRANT" \
  CT_AGENT_SERVICE_HANDLER_CMD="$HANDLER_CMD" \
  CT_AGENT_SERVICES="$SERVICE" \
  $CT_AGENT channel
