#!/usr/bin/env bash
# serve-role-container.sh — run serve-role.sh inside a container instead of bare-host,
# reusing an already-built pipeline agent image (any image with `ct-agent` on PATH,
# e.g. the demo agent images built from the CADS-Tunnel docker/Dockerfile) and bind-mounting
# a host-installed `claude` CLI binary + its credentials into it, rather than installing
# Node/claude-code inside the image.
#
# Why bind-mount instead of baking claude into the image: `claude` here is a standalone
# glibc-linked native binary (no bundled Node runtime needed — verified via `ldd` and a
# bare `env -i claude --version`), so a read-only bind mount is enough; it also avoids
# ever putting `~/.claude/.credentials.json` into an image layer.
#
# POSIX/portable: no GNU-only flags, works under bash on Linux or macOS (paths must
# resolve — on macOS `readlink -f` needs coreutils or an equivalent `greadlink -f`).
#
# Usage:
#   IMAGE=cads-flappy-demo-flappy-agent:latest \
#   CLAUDE_BIN_PATH="$(command -v claude)" \
#   CLAUDE_HOME="$HOME/.claude" CLAUDE_JSON="$HOME/.claude.json" \
#   CT_AGENT_EDGE_BROKER=1.2.3.4:4433 CT_AGENT_EDGE_RELAY=1.2.3.4:4433 \
#   HOLDER_KEY=<64-hex> NOISE_KEY=<64-hex> GRANT=<hex> \
#   SERVICE=text_generation \
#   HANDLER_CMD_HOST=/abs/path/to/physics-handler.sh \
#   CONTAINER_NAME=flappy-physics-serve \
#     ./serve-role-container.sh
#
#   ./serve-role-container.sh --selftest   # verify docker/image/claude/handler resolvable, no network, no container started
set -euo pipefail

die() { printf 'serve-role-container: %s\n' "$*" >&2; exit 1; }

# Resolve a symlink to its real target; falls back to the path itself if `readlink -f`
# is not available (e.g. some macOS toolchains) and the path is not a symlink.
resolve_real_path() {
  if command -v readlink >/dev/null 2>&1 && readlink -f "$1" >/dev/null 2>&1; then
    readlink -f "$1"
  elif command -v greadlink >/dev/null 2>&1; then
    greadlink -f "$1"
  else
    printf '%s\n' "$1"
  fi
}

IMAGE="${IMAGE:?set IMAGE (a built pipeline agent image with ct-agent on PATH)}"
CLAUDE_BIN_PATH="${CLAUDE_BIN_PATH:-$(command -v claude 2>/dev/null || true)}"
CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"
CLAUDE_JSON="${CLAUDE_JSON:-$HOME/.claude.json}"
HANDLER_CMD_HOST="${HANDLER_CMD_HOST:?set HANDLER_CMD_HOST (host path to the role handler script)}"
CONTAINER_NAME="${CONTAINER_NAME:?set CONTAINER_NAME (unique docker container name for this role)}"

if [ "${1:-}" = "--selftest" ]; then
  command -v docker >/dev/null 2>&1 || die "docker not found"
  [ -n "$CLAUDE_BIN_PATH" ] || die "claude CLI not resolvable — set CLAUDE_BIN_PATH"
  [ -x "$CLAUDE_BIN_PATH" ] || die "CLAUDE_BIN_PATH=$CLAUDE_BIN_PATH not executable"
  [ -d "$CLAUDE_HOME" ] || die "CLAUDE_HOME=$CLAUDE_HOME not found (expected e.g. .credentials.json inside)"
  [ -x "$HANDLER_CMD_HOST" ] || die "HANDLER_CMD_HOST=$HANDLER_CMD_HOST not found or not executable"
  docker image inspect "$IMAGE" >/dev/null 2>&1 || die "IMAGE=$IMAGE not found locally (docker image inspect failed)"
  echo "serve-role-container: docker + image + claude + handler all resolvable — selftest passed (no CP/edge calls made, no container started)"
  exit 0
fi

: "${CT_AGENT_EDGE_BROKER:?set CT_AGENT_EDGE_BROKER (edge rendezvous host:port — MUST be an IP, hostnames are rejected, see #214)}"
: "${CT_AGENT_EDGE_RELAY:?set CT_AGENT_EDGE_RELAY (edge relay host:port)}"
: "${HOLDER_KEY:?set HOLDER_KEY (64-hex, the serving holder PRIVATE key)}"
: "${NOISE_KEY:?set NOISE_KEY (64-hex, the serving noise PRIVATE key)}"
: "${GRANT:?set GRANT (hex signed grant for this role, accept direction)}"
: "${SERVICE:?set SERVICE (text_generation | safety_check | code_generation | security_review)}"

[ -n "$CLAUDE_BIN_PATH" ] || die "claude CLI not resolvable — set CLAUDE_BIN_PATH"
CLAUDE_REAL_BIN="$(resolve_real_path "$CLAUDE_BIN_PATH")"
[ -x "$CLAUDE_REAL_BIN" ] || die "resolved claude binary $CLAUDE_REAL_BIN not executable"
[ -x "$HANDLER_CMD_HOST" ] || die "HANDLER_CMD_HOST=$HANDLER_CMD_HOST not found or not executable"

# The handler script itself is bind-mounted in (not baked into IMAGE), same reasoning as
# the claude binary — this script works with whatever handler the caller points at,
# without needing a per-handler image.
HANDLER_BASENAME="$(basename "$HANDLER_CMD_HOST")"
HANDLER_CMD_IN_CONTAINER="/opt/handler/$HANDLER_BASENAME"

echo "serve-role-container: starting $CONTAINER_NAME SERVICE=$SERVICE HANDLER=$HANDLER_BASENAME via broker=$CT_AGENT_EDGE_BROKER (image=$IMAGE)" >&2

# #320: run as the CALLING host user, not root. The container's role handler needs
# read access to $CLAUDE_HOME to invoke `claude` at all (that's the whole point of
# this bind mount), so a compromised/prompt-injected handler can still read and
# exfiltrate the credentials it's legitimately handed — no `--user` change closes
# that; only a credentials-proxy that never exposes the raw secret would (a real
# architecture change, out of scope here, see the issue). What running as the host
# UID *does* close is the broader root-in-container blast radius: without it the
# container process is real root (host UID 0, full CAP_DAC_OVERRIDE), able to read
# the credentials regardless of their host file permissions and with every other
# root-only privilege besides. Running as the host UID means the kernel's own
# permission check on the bind-mounted files applies same as on the host — no
# capability bypass — and confines the process to exactly the access its owning
# user already has, matching this repo's other "don't run containers as root"
# findings (#305).
RUNTIME_UID="$(id -u)"
RUNTIME_GID="$(id -g)"
RUNTIME_HOME="/home/ct-role"

RUNTIME_ENV="$(mktemp)"
trap 'rm -f "$RUNTIME_ENV"' EXIT
{
  printf 'CT_CHANNEL_ROLE=accept\n'
  printf 'CT_CHANNEL_SERVE=1\n'
  printf 'CT_CHANNEL_RELAY_ONLY=1\n'
  printf 'CT_CHANNEL_BROKER=%s\n' "$CT_AGENT_EDGE_BROKER"
  printf 'CT_CHANNEL_RELAY=%s\n' "$CT_AGENT_EDGE_RELAY"
  printf 'CT_CHANNEL_HOLDER_KEY=%s\n' "$HOLDER_KEY"
  printf 'CT_CHANNEL_NOISE_KEY=%s\n' "$NOISE_KEY"
  printf 'CT_CHANNEL_GRANT=%s\n' "$GRANT"
  printf 'CT_AGENT_SERVICE_HANDLER_CMD=%s\n' "$HANDLER_CMD_IN_CONTAINER"
  printf 'CT_AGENT_SERVICES=%s\n' "$SERVICE"
  printf 'HOME=%s\n' "$RUNTIME_HOME"
  # Optional (ct-agent v0.4.7+): pin channel sessions onto the :443 TLS-TCP front door
  # instead of QUIC, for deployments hitting the QUIC idle-timeout signature (a session
  # dies ~10-15s after admission even mid-traffic, because a quiet in-flight LLM call
  # sends no QUIC packets -- see ct-agent v0.4.7's own changelog and CADS-Tunnel#494).
  # Backward compatible: passthrough only, no-op unless the caller sets these.
  [ -n "${CT_CHANNEL_FRONT_DOOR:-}" ] && printf 'CT_CHANNEL_FRONT_DOOR=%s\n' "$CT_CHANNEL_FRONT_DOOR"
  [ -n "${CT_CHANNEL_FRONT_DOOR_CERT:-}" ] && printf 'CT_CHANNEL_FRONT_DOOR_CERT=%s\n' "$CT_CHANNEL_FRONT_DOOR_CERT"
  [ -n "${CT_CHANNEL_FRONT_DOOR_ONLY:-}" ] && printf 'CT_CHANNEL_FRONT_DOOR_ONLY=%s\n' "$CT_CHANNEL_FRONT_DOOR_ONLY"
} > "$RUNTIME_ENV"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  --network "${DOCKER_NETWORK:-bridge}" \
  --user "$RUNTIME_UID:$RUNTIME_GID" \
  --env-file "$RUNTIME_ENV" \
  -v "$CLAUDE_REAL_BIN:/usr/local/bin/claude:ro" \
  -v "$CLAUDE_HOME:$RUNTIME_HOME/.claude:ro" \
  $([ -f "$CLAUDE_JSON" ] && printf -- '-v %s:%s/.claude.json:ro' "$CLAUDE_JSON" "$RUNTIME_HOME") \
  -v "$HANDLER_CMD_HOST:$HANDLER_CMD_IN_CONTAINER:ro" \
  "$IMAGE" \
  ct-agent channel

echo "serve-role-container: $CONTAINER_NAME started — 'docker logs -f $CONTAINER_NAME' to watch it" >&2
