#!/usr/bin/env sh
# Committed-secrets guard (M23.3).
#
# Scans git-tracked files for credential material and verifies that real secret
# files stay untracked. Exit 0 = clean, non-zero = a likely secret is committed
# (wire into CI / a pre-commit hook). Detects only genuine credential shapes
# (PEM private keys, cloud access-key ids, GitHub tokens, tracked .env files), so
# ordinary test payloads containing the word "secret" do not trip it.
set -eu

# Credential shapes to detect in tracked text files:
#   - PEM private key headers
#   - AWS-style access key ids (AKIA + 16 upper/digits)
#   - Google API keys (AIza + 35 chars)
#   - GitHub tokens (#79): classic/OAuth/user/server/refresh (gh[o/p/r/s/u]_ + 36)
#     and fine-grained PATs (github_pat_ + long) — this repo's primary credential
#     (.mcp.json injects ${GITHUB_PERSONAL_ACCESS_TOKEN}; every gh call uses it).
pattern='-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[oprsu]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{30,}'
# #198: this project's OWN primary credential shape — a raw 64-hex (32-byte) ed25519/X25519 private
# scalar assigned to a SECRET channel key env var (CT_CHANNEL_HOLDER/NOISE/OPERATOR_KEY, from
# `ct-agent channel init`). Anchored to the var name (with `=`/`:`, optional quotes) so it catches a
# real committed key assignment WITHOUT false-positiving on the codebase's many bare 64-hex values —
# SHA-256 hashes, test vectors (which are separate `hk = "…"` variables, not `VAR=<hex>` literals),
# commit refs. Verified 0 matches across the current tree.
pattern="$pattern|CT_CHANNEL_(HOLDER|NOISE|OPERATOR)_KEY[\"']?[[:space:]]*[=:][[:space:]]*[\"']?[0-9a-fA-F]{64}"

# Self-test (#79 regression guard): prove the pattern catches each credential shape
# and does not false-positive on benign text. Synthetic placeholders only — this
# file is excluded from the scan below, so they never trip the guard itself.
#   Run: scripts/check-no-secrets.sh --selftest
if [ "${1:-}" = "--selftest" ]; then
  rc=0
  for s in \
    'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    'gho_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    'github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    'AKIAAAAAAAAAAAAAAAAA' \
    'AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    '-----BEGIN RSA PRIVATE KEY-----' \
    'CT_CHANNEL_HOLDER_KEY=9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0' \
    'export CT_CHANNEL_NOISE_KEY="9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"'
  do
    printf '%s\n' "$s" | grep -Eq -e "$pattern" || { echo "SELFTEST FAIL: pattern missed a credential shape: $s"; rc=1; }
  done
  printf 'a benign line that mentions a secret token value in prose\n' | grep -Eq -e "$pattern" \
    && { echo "SELFTEST FAIL: false positive on benign text"; rc=1; }
  # #198: a BARE 64-hex value not anchored to a secret key var (a SHA-256 hash, a test vector) must
  # NOT trip — else every push would false-positive on the codebase's many hashes/test keys.
  printf 'gate.json sha256 = a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\n' \
    | grep -Eq -e "$pattern" && { echo "SELFTEST FAIL: false positive on a bare 64-hex hash (#198)"; rc=1; }
  [ "$rc" -eq 0 ] && echo "SELFTEST OK: PEM/AWS/Google/GitHub + raw channel-key shapes detected, no false positive"
  exit "$rc"
fi

cd "$(cd "$(dirname "$0")/.." && pwd)"
status=0

fail() { echo "SECRET-GUARD FAIL: $1"; status=1; }

# All git-tracked files -- captured ONCE, with the failure explicitly checked.
# #316: `git ls-files | while … ; done` (the old shape) silently swallows a
# non-zero `git ls-files` exit under `set -eu` (no pipefail in POSIX sh) --
# the while loop just reads nothing and exits 0, so a guard that couldn't even
# run (missing .git, corrupt index, git unavailable) still printed
# "SECRET-GUARD OK" having scanned zero files. A guard that can't run must
# fail loudly, never report clean.
if ! tracked_files=$(git ls-files); then
  echo "SECRET-GUARD FAIL: git ls-files failed -- cannot verify no secrets are committed"
  exit 1
fi

# 1. No real .env files may be tracked (only *.example templates).
env_tracked=$(printf '%s\n' "$tracked_files" | grep -E '(^|/)\.env($|\.)' | grep -v '\.example$' || true)
if [ -n "$env_tracked" ]; then
  fail "tracked .env file(s) with real values:"
  echo "$env_tracked"
fi

# 2. .gitignore must ignore .env.
if ! git check-ignore -q docker/deploy/.env 2>/dev/null; then
  fail ".env is not gitignored"
fi

# 3. Scan tracked text files for the credential shapes in $pattern.
hits=$(printf '%s\n' "$tracked_files" | while IFS= read -r f; do
  case "$f" in
    *.example|scripts/check-no-secrets.sh) continue ;;  # templates + this scanner
  esac
  if grep -EIlq -e "$pattern" "$f" 2>/dev/null; then echo "$f"; fi
done)
if [ -n "$hits" ]; then
  fail "credential material in tracked file(s):"
  echo "$hits"
fi

[ "$status" -eq 0 ] && echo "SECRET-GUARD OK: no committed secrets"
exit "$status"
