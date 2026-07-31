#!/usr/bin/env bash
# Sets CT_RELAY_NODE_PEER in docker/deploy/.env (idempotent): replaces an existing
# CT_RELAY_NODE_PEER= line (placeholder or stale value) if present, else appends one.
#
# Run this yourself -- .env is intentionally Read-denied for the agent
# (.claude/settings.json: Read(./.env), Read(./.env.*)), so it can't do this step itself.
#
# Usage:
#   ./set-relay-node-peer.sh [PEER_ID]
# With no argument, defaults to the relay-node identity derived from the current
# CT_RELAY_NODE_KEY (printed on its first boot, e.g. via `docker compose logs relay-node`).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PEER_ID="${1:-12D3KooWHtMnQTdJKP6gegRX4ZQkNwwiVaPFdnzKJbAnLVwR3hMe}"
ENV_FILE=.env

if [ ! -f "$ENV_FILE" ]; then
  echo "error: $ENV_FILE not found in $(pwd)" >&2
  exit 1
fi

if grep -q '^CT_RELAY_NODE_PEER=' "$ENV_FILE"; then
  sed -i "s|^CT_RELAY_NODE_PEER=.*|CT_RELAY_NODE_PEER=${PEER_ID}|" "$ENV_FILE"
  echo "updated existing CT_RELAY_NODE_PEER line in $ENV_FILE"
else
  printf 'CT_RELAY_NODE_PEER=%s\n' "$PEER_ID" >> "$ENV_FILE"
  echo "appended CT_RELAY_NODE_PEER line to $ENV_FILE"
fi
