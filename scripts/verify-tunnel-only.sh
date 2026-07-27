#!/usr/bin/env bash
# CADS-Tunnel — verify a pipeline's compose file never publishes a port that
# would bypass the tunnel (the "origin/bridge is never publicly reachable
# except through the tunnel" invariant, #219).
#
# A Browser-Plane origin/bridge must use `expose:` (container-network-only),
# never `ports:` (host-published) — the browser reaches it ONLY via the edge's
# SNI-passthrough agent tunnel. A stray `ports:` line silently punches a hole
# straight through that guarantee without the tunnel software ever knowing.
#
#   ./scripts/verify-tunnel-only.sh <compose-file> [more-compose-files...]
#
# Exit 0 and prints nothing if clean; exit 1 and lists every offending
# `ports:` mapping otherwise. Checks every service in the file — an agent's
# own service block legitimately has neither `expose` nor `ports` (outbound
# only), which is also fine; this script only flags `ports:` specifically.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <compose-file> [more...]" >&2; exit 2; }

fail=0
for f in "$@"; do
  [ -f "$f" ] || { echo "error: no such file: $f" >&2; exit 2; }
  # A `ports:` mapping key at any indent, not inside a comment.
  hits="$(grep -nE '^\s*ports:\s*$' "$f" || true)"
  if [ -n "$hits" ]; then
    fail=1
    echo "✗ $f publishes a host port (breaks the tunnel-only invariant, #219):"
    while IFS= read -r line; do
      lineno="${line%%:*}"
      echo "  line $lineno:"
      sed -n "${lineno},$((lineno + 3))p" "$f" | sed 's/^/    /'
    done <<< "$hits"
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "✓ tunnel-only invariant holds: no service publishes a host port in $*"
else
  exit 1
fi
