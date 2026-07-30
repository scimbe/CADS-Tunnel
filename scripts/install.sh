#!/usr/bin/env bash
# CADS-Tunnel — from-bare-machine install routine.
#
# One command to take a fresh Linux/macOS box to a working core system: install
# the build dependencies + a recent Rust toolchain, build the Cargo workspace,
# and install the core `ct-*` binaries onto PATH. `ct-agent` itself now lives in
# its own repo (github.com/scimbe/ct-agent, with its own scripts/setup.sh) — see
# that repo to bring up an **agent**; this script builds the **core** binaries
# (control-plane/edge/dns/client) or run a **pipeline** (a bridge that
# orchestrates role agents, e.g. the CADS-flappy-demo / CADS-cookbook-demo
# reference pipelines).
#
# Idempotent and re-runnable. Safe to run repeatedly; `--force`-installs binaries
# so a re-run always lands the current source.
#
#   ./scripts/install.sh                 # deps + toolchain + build + install (release)
#   ./scripts/install.sh --debug         # faster build, unoptimized binaries
#   ./scripts/install.sh --prefix ~/.local   # install binaries under ~/.local/bin
#   ./scripts/install.sh --no-toolchain  # assume Rust is already present (>= 1.85)
#   ./scripts/install.sh --no-deps       # skip the system-package step
#   ./scripts/install.sh --crates client,dns   # install a subset
#
# Env overrides: CADS_PREFIX (install root, default ~/.cargo), NO_COLOR (disable colour).
set -euo pipefail

# --- resolve the repo root regardless of where we're invoked from -------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- defaults -----------------------------------------------------------------
PROFILE="release"
PREFIX="${CADS_PREFIX:-$HOME/.cargo}"
INSTALL_TOOLCHAIN=1
INSTALL_DEPS=1
MIN_RUST_MAJOR=1
MIN_RUST_MINOR=85           # idna_adapter needs the edition2024 Cargo feature (Rust 1.85+)
CRATES=(client control-plane edge dns agent-tools)

# --- pretty output ------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B="\033[1m"; C_G="\033[32m"; C_Y="\033[33m"; C_R="\033[31m"; C_0="\033[0m"
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi
log()  { printf "${C_B}==>${C_0} %s\n" "$*"; }
ok()   { printf "${C_G}  ✓${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}  !${C_0} %s\n" "$*" >&2; }
die()  { printf "${C_R}error:${C_0} %s\n" "$*" >&2; exit 1; }

usage() {
  sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# --- args ---------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --debug)        PROFILE="debug" ;;
    --release)      PROFILE="release" ;;
    --no-toolchain) INSTALL_TOOLCHAIN=0 ;;
    --no-deps)      INSTALL_DEPS=0 ;;
    --prefix)       shift; [ $# -gt 0 ] || die "--prefix needs a directory"; PREFIX="$1" ;;
    --crates)       shift; [ $# -gt 0 ] || die "--crates needs a comma list"; IFS=',' read -r -a CRATES <<< "$1" ;;
    -h|--help)      usage 0 ;;
    *)              die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# --- privilege helper for system-package installs -----------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    warn "not root and no sudo — system packages may fail; re-run as root or use --no-deps"
  fi
fi

# --- 1. system build dependencies --------------------------------------------
install_system_deps() {
  [ "$INSTALL_DEPS" -eq 1 ] || { log "skipping system deps (--no-deps)"; return; }
  log "installing system build dependencies"
  if   command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev ca-certificates curl git
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y gcc gcc-c++ make pkgconfig openssl-devel ca-certificates curl git
  elif command -v brew >/dev/null 2>&1; then
    brew install openssl@3 pkg-config git || true
  else
    warn "no supported package manager (apt/dnf/brew) found."
    warn "ensure these are present manually: a C toolchain, pkg-config, OpenSSL headers, git, curl."
    return
  fi
  ok "system dependencies present"
}

# --- 2. Rust toolchain (>= 1.85) ---------------------------------------------
rust_new_enough() {
  command -v rustc >/dev/null 2>&1 || return 1
  local v; v="$(rustc --version | awk '{print $2}')"
  local maj min; maj="${v%%.*}"; min="${v#*.}"; min="${min%%.*}"
  [ "$maj" -gt "$MIN_RUST_MAJOR" ] || { [ "$maj" -eq "$MIN_RUST_MAJOR" ] && [ "$min" -ge "$MIN_RUST_MINOR" ]; }
}

ensure_rust() {
  # Make an existing rustup/cargo visible even if the shell hasn't sourced it yet.
  [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
  if rust_new_enough; then ok "Rust $(rustc --version | awk '{print $2}') (>= ${MIN_RUST_MAJOR}.${MIN_RUST_MINOR})"; return; fi

  if [ "$INSTALL_TOOLCHAIN" -eq 0 ]; then
    die "Rust >= ${MIN_RUST_MAJOR}.${MIN_RUST_MINOR} required but not found (you passed --no-toolchain)."
  fi
  if command -v rustup >/dev/null 2>&1; then
    log "updating the Rust toolchain via rustup"
    rustup update stable && rustup default stable
  else
    log "installing the Rust toolchain via rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    . "$HOME/.cargo/env"
  fi
  rust_new_enough || die "Rust is still older than ${MIN_RUST_MAJOR}.${MIN_RUST_MINOR} after update — check your rustup channel."
  ok "Rust $(rustc --version | awk '{print $2}') ready"
}

# --- 3. build + install the core binaries ------------------------------------
build_and_install() {
  local debug_flag=()
  [ "$PROFILE" = "debug" ] && debug_flag=(--debug)
  log "building + installing core binaries (${PROFILE}) into ${PREFIX}/bin"
  for c in "${CRATES[@]}"; do
    [ -f "$ROOT/crates/$c/Cargo.toml" ] || die "no crate at crates/$c"
    log "  cargo install: crates/$c"
    cargo install --path "$ROOT/crates/$c" --root "$PREFIX" --locked --force "${debug_flag[@]}"
  done
  ok "core binaries installed"
}

# --- 4. next steps ------------------------------------------------------------
print_next_steps() {
  local bindir="$PREFIX/bin"
  echo
  log "done — core system installed"
  echo "  binaries: ${bindir}  (ct-client, ct-control-plane, ct-edge, ct-dns, ct-crew-bridge, ct-cookbook-bridge, + tools)"
  case ":$PATH:" in
    *":$bindir:"*) : ;;
    *) warn "add it to PATH:  export PATH=\"$bindir:\$PATH\"" ;;
  esac
  cat <<EOF

  Bring up an AGENT (ct-agent now lives in its own repo, github.com/scimbe/ct-agent):
    curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash
    # or: git clone https://github.com/scimbe/ct-agent && (cd ct-agent && ./scripts/setup.sh)

  Run a PIPELINE (reference demos, now their own repos):
    git clone https://github.com/scimbe/CADS-flappy-demo   && (cd CADS-flappy-demo   && ./run-demo.sh)
    git clone https://github.com/scimbe/CADS-cookbook-demo && (cd CADS-cookbook-demo && ./run-demo.sh)

  Self-host the control plane instead:  see docs/install.md (Docker Compose / k8s).
EOF
}

main() {
  log "CADS-Tunnel install — profile=${PROFILE}, prefix=${PREFIX}, crates=${CRATES[*]}"
  [ -f "$ROOT/Cargo.toml" ] || die "run from the CADS-Tunnel checkout (no Cargo.toml at $ROOT)"
  install_system_deps
  ensure_rust
  build_and_install
  print_next_steps
}
main
