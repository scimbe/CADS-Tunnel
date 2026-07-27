#!/usr/bin/env bash
# CADS-Tunnel — scripted self-host bring-up (Docker Compose + optional :443 front
# door with a real Let's Encrypt cert via deSEC DNS-01).
#
# Idempotent and re-runnable: safe to run again after a failure. `--fresh` tears
# the compose stack down (incl. volumes) first for a clean slate instead of
# patching a half-up deployment.
#
#   ./scripts/deploy-selfhost.sh                  # base stack only (:4433, loopback :8090)
#   ./scripts/deploy-selfhost.sh --frontdoor       # + :443/:80 front door with a real cert
#   ./scripts/deploy-selfhost.sh --frontdoor --staging   # LE staging cert (no rate-limit risk)
#   ./scripts/deploy-selfhost.sh --fresh --frontdoor     # tear down + fresh bring-up
#   ./scripts/deploy-selfhost.sh --frontdoor --skip-cert # reuse an existing cert in PORTAL_CERT_DIR
#
# Required env for --frontdoor (first run only — persisted into docker/deploy/.env
# after that): DESEC_TOKEN=<deSEC API token scoped to the zone>
# Optional env: PORTAL_PUBLIC_HOST (default bunsenbrenner.org), DESEC_DOMAIN
# (defaults to PORTAL_PUBLIC_HOST), PORTAL_CERT_DIR (default ~/ct-certs/portal),
# ACME_EMAIL (default scimbe@gmail.com), NO_COLOR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT/docker/deploy"
ENV_FILE="$DEPLOY_DIR/.env"
ENV_EXAMPLE="$DEPLOY_DIR/.env.example"
DESEC_EXAMPLE="$ROOT/config/desec.env.example"
COMPOSE_BASE="$DEPLOY_DIR/compose.selfhost.yml"
COMPOSE_FRONTDOOR="$DEPLOY_DIR/compose.frontdoor.yml"

FRESH=0
FRONTDOOR=0
STAGING=0
SKIP_CERT=0
PORTAL_PUBLIC_HOST="${PORTAL_PUBLIC_HOST:-bunsenbrenner.org}"
PORTAL_CERT_DIR="${PORTAL_CERT_DIR:-$HOME/ct-certs/portal}"
DESEC_DOMAIN="${DESEC_DOMAIN:-$PORTAL_PUBLIC_HOST}"
ACME_EMAIL="${ACME_EMAIL:-scimbe@gmail.com}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B="\033[1m"; C_G="\033[32m"; C_Y="\033[33m"; C_R="\033[31m"; C_0="\033[0m"
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi
log()  { printf "${C_B}==>${C_0} %s\n" "$*"; }
ok()   { printf "${C_G}  ✓${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}  !${C_0} %s\n" "$*" >&2; }
die()  { printf "${C_R}error:${C_0} %s\n" "$*" >&2; exit 1; }

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --fresh)       FRESH=1 ;;
    --frontdoor)   FRONTDOOR=1 ;;
    --staging)     STAGING=1 ;;
    --skip-cert)   SKIP_CERT=1 ;;
    -h|--help)     usage 0 ;;
    *)             die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# --- privilege helper (mirrors scripts/install.sh) ---------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 && SUDO="sudo"
fi

USE_SG=0
docker_() {
  if [ "$USE_SG" = "1" ]; then
    sg docker -c "$(printf '%q ' docker "$@")"
  else
    docker "$@"
  fi
}
compose_() {
  local files=(-f "$COMPOSE_BASE")
  [ "$FRONTDOOR" = "1" ] && files+=(-f "$COMPOSE_FRONTDOOR")
  docker_ compose "${files[@]}" --env-file "$ENV_FILE" "$@"
}

# --- 1. Docker + Buildx + Compose plugin -------------------------------------
ensure_docker() {
  log "checking Docker"
  if ! command -v docker >/dev/null 2>&1; then
    log "installing docker.io + buildx + compose plugin"
    if command -v apt-get >/dev/null 2>&1; then
      $SUDO apt-get update -qq
      $SUDO apt-get install -y docker.io docker-buildx docker-compose-v2
    else
      die "no apt-get found — install Docker manually (docker.com/get-started) and re-run"
    fi
  fi
  $SUDO systemctl enable --now docker >/dev/null 2>&1 || true

  if docker info >/dev/null 2>&1; then
    USE_SG=0
  elif command -v sg >/dev/null 2>&1 && sg docker -c "docker info" >/dev/null 2>&1; then
    USE_SG=1
    warn "using 'sg docker' — log out/in once to drop this workaround"
  else
    log "adding $(id -un) to the docker group"
    $SUDO usermod -aG docker "$(id -un)" || die "could not join the docker group (run: sudo usermod -aG docker $(id -un))"
    if command -v sg >/dev/null 2>&1 && sg docker -c "docker info" >/dev/null 2>&1; then
      USE_SG=1
    else
      die "docker still unusable after usermod — log out/in (or newgrp docker) and re-run"
    fi
  fi
  docker_ compose version >/dev/null 2>&1 || die "docker compose plugin missing (docker-compose-v2)"
  docker_ buildx version >/dev/null 2>&1 || warn "buildx missing — builds will be slow (no cache mounts)"
  ok "Docker ready"
}

# --- 2. docker/deploy/.env ----------------------------------------------------
env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true; }
env_set() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    local tmp; tmp="$(mktemp)"
    awk -v k="$key" -v v="$val" -F= 'BEGIN{OFS="="} $1==k{$0=k"="v} {print}' "$ENV_FILE" > "$tmp"
    mv "$tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
}

ensure_env() {
  log "preparing $ENV_FILE"
  [ -f "$ENV_EXAMPLE" ] || die "missing $ENV_EXAMPLE"
  [ -f "$ENV_FILE" ] || cp "$ENV_EXAMPLE" "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  env_set PORTAL_PUBLIC_HOST "$PORTAL_PUBLIC_HOST"
  env_set PORTAL_CERT_DIR "$PORTAL_CERT_DIR"

  local tok; tok="$(env_get CT_EDGE_ADMIN_TOKEN)"
  if [ -z "$tok" ] || [ "$tok" = '${CT_EDGE_ADMIN_TOKEN}' ]; then
    tok="$(openssl rand -hex 32)"
    env_set CT_EDGE_ADMIN_TOKEN "$tok"
    ok "generated CT_EDGE_ADMIN_TOKEN"
  fi

  if [ "$FRONTDOOR" = "1" ]; then
    env_set CT_ACME_DNS_PROVIDER desec
    env_set DESEC_DOMAIN "$DESEC_DOMAIN"
    local cur_token; cur_token="$(env_get DESEC_TOKEN)"
    if [ -n "${DESEC_TOKEN:-}" ]; then
      env_set DESEC_TOKEN "$DESEC_TOKEN"
    elif [ -z "$cur_token" ] || [ "$cur_token" = "replace-with-your-desec-token" ]; then
      die "DESEC_TOKEN not set — export DESEC_TOKEN=<deSEC API token> and re-run (needed for the ACME DNS-01 cert; see $DESEC_EXAMPLE)"
    fi
  fi
  ok "$ENV_FILE ready"
}

# --- 3. Portal TLS cert via acme.sh + deSEC DNS-01 ---------------------------
ensure_portal_cert() {
  [ "$FRONTDOOR" = "1" ] || return 0
  local full="$PORTAL_CERT_DIR/fullchain.pem" key="$PORTAL_CERT_DIR/privkey.pem"
  mkdir -p "$PORTAL_CERT_DIR"

  if [ "$SKIP_CERT" = "1" ]; then
    [ -f "$full" ] && [ -f "$key" ] || die "--skip-cert given but $full / $key missing"
    ok "using existing cert in $PORTAL_CERT_DIR (--skip-cert)"
    return 0
  fi

  if [ -f "$full" ] && [ -f "$key" ] && openssl x509 -in "$full" -checkend 604800 -noout >/dev/null 2>&1; then
    ok "existing cert in $PORTAL_CERT_DIR is valid for >7 days — skipping issuance"
    return 0
  fi

  log "obtaining a Let's Encrypt cert for $PORTAL_PUBLIC_HOST via deSEC DNS-01 (acme.sh)"
  if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
    curl -fsS https://get.acme.sh | sh -s email="$ACME_EMAIL" >/dev/null
  fi
  export DESEC_TOKEN="${DESEC_TOKEN:-$(env_get DESEC_TOKEN)}"
  [ -n "$DESEC_TOKEN" ] || die "DESEC_TOKEN unavailable for acme.sh (check $ENV_FILE)"
  # acme.sh's dns_desec hook uses the legacy dedyn.io variable name, not DESEC_TOKEN.
  export DEDYN_TOKEN="$DESEC_TOKEN"

  local server_flag=(--server letsencrypt)
  [ "$STAGING" = "1" ] && server_flag=(--server letsencrypt_test)

  "$HOME/.acme.sh/acme.sh" --issue --dns dns_desec -d "$PORTAL_PUBLIC_HOST" "${server_flag[@]}" \
    || die "acme.sh issuance failed for $PORTAL_PUBLIC_HOST"
  # The reloadcmd only matters on RENEWAL (restart the already-running edge so it
  # picks up the new cert); on first issuance there's nothing running yet to
  # restart, and the reload also needs real docker-group access (not the `sg
  # docker` workaround this shell may be using) — so a reload failure here is not
  # fatal as long as the cert files themselves landed.
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$PORTAL_PUBLIC_HOST" \
    --fullchain-file "$full" --key-file "$key" \
    --reloadcmd "docker compose -f '$COMPOSE_BASE' -f '$COMPOSE_FRONTDOOR' --env-file '$ENV_FILE' restart edge" \
    || warn "acme.sh install-cert reload step failed (fine on first issuance — verifying cert files below)"
  [ -f "$full" ] && [ -f "$key" ] || die "cert files missing after acme.sh install-cert"
  chmod 600 "$key"
  ok "cert installed at $PORTAL_CERT_DIR ($([ "$STAGING" = "1" ] && echo staging || echo production))"
}

# --- 4. bring the stack up ----------------------------------------------------
compose_up() {
  if [ "$FRESH" = "1" ]; then
    log "tearing down any existing stack (--fresh)"
    compose_ down -v --remove-orphans || true
  fi
  log "docker compose up --build -d ($([ "$FRONTDOOR" = "1" ] && echo "base+frontdoor" || echo "base only"))"
  compose_ up --build -d
}

wait_healthy() {
  log "waiting for the control plane to become ready (timeout ${HEALTH_TIMEOUT}s)"
  local waited=0
  until curl -fsS -m 3 http://127.0.0.1:8090/readyz >/dev/null 2>&1; do
    waited=$((waited + 3))
    if [ "$waited" -ge "$HEALTH_TIMEOUT" ]; then
      warn "control-plane logs:"; compose_ logs --tail 40 control-plane || true
      warn "edge logs:"; compose_ logs --tail 40 edge || true
      die "control plane did not become ready within ${HEALTH_TIMEOUT}s"
    fi
    sleep 3
  done
  ok "control plane /readyz is 200"
}

verify() {
  curl -fsS -m 5 http://127.0.0.1:8090/healthz >/dev/null || die "healthz check failed"
  ok "healthz OK"
  if [ "$FRONTDOOR" = "1" ]; then
    local code insecure_flag=()
    [ "$STAGING" = "1" ] && insecure_flag=(-k)   # staging cert isn't in the trust store
    code="$(curl -sS -m 10 "${insecure_flag[@]}" -o /dev/null -w '%{http_code}' "https://$PORTAL_PUBLIC_HOST/" 2>/dev/null)"
    code="${code:-000}"
    if [ "$code" = "200" ]; then
      ok "https://$PORTAL_PUBLIC_HOST/ -> 200"
    else
      warn "https://$PORTAL_PUBLIC_HOST/ -> $code (DNS propagation or firewall — check manually)"
    fi
  fi
}

main() {
  log "CADS-Tunnel self-host deploy — frontdoor=${FRONTDOOR} staging=${STAGING} fresh=${FRESH}"
  [ -f "$ROOT/Cargo.toml" ] || die "run from the CADS-Tunnel checkout"
  ensure_docker
  ensure_env
  ensure_portal_cert
  compose_up
  wait_healthy
  verify
  echo
  ok "self-host stack is up"
  echo "  Dashboard:      http://127.0.0.1:8090/  (loopback)"
  [ "$FRONTDOOR" = "1" ] && echo "  Public portal:  https://$PORTAL_PUBLIC_HOST/"
  echo "  Logs:           docker compose -f $COMPOSE_BASE $([ "$FRONTDOOR" = "1" ] && echo "-f $COMPOSE_FRONTDOOR") --env-file $ENV_FILE logs -f"
}
main
