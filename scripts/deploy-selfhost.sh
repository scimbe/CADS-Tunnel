#!/usr/bin/env bash
# CADS-Tunnel — scripted self-host bring-up: the base Docker Compose stack plus
# every optional overlay this operator runs as part of "the core system" —
# the :443 front door (real Let's Encrypt cert via deSEC DNS-01), Keycloak SSO,
# and the help.<zone> Browser-Plane demo.
#
# Idempotent and re-runnable: safe to run again after a failure. `--fresh` tears
# the compose stack down (incl. volumes) first for a clean slate instead of
# patching a half-up deployment.
#
#   ./scripts/deploy-selfhost.sh                          # base stack only (:4433, loopback :8090)
#   ./scripts/deploy-selfhost.sh --frontdoor               # + :443/:80 front door with a real cert
#   ./scripts/deploy-selfhost.sh --frontdoor --sso         # + Keycloak SSO login on the portal
#   ./scripts/deploy-selfhost.sh --frontdoor --help-site   # + the help.<zone> demo
#   ./scripts/deploy-selfhost.sh --frontdoor --sso --help-site --fresh  # the whole core system, clean
#   ./scripts/deploy-selfhost.sh --frontdoor --staging     # LE staging certs (no rate-limit risk)
#   ./scripts/deploy-selfhost.sh --frontdoor --skip-cert   # reuse existing certs, don't re-issue
#
# --sso and --help-site both imply/require --frontdoor (Keycloak and the demo
# are both served through it). Each optional piece issues its own Let's
# Encrypt cert (front door: PORTAL_PUBLIC_HOST; SSO: AUTH_PUBLIC_HOST) via the
# SAME acme.sh + deSEC DNS-01 mechanism — see docs/dns01-desec.md.
#
# Required env for --frontdoor/--sso/--help-site (first run only — persisted
# into docker/deploy/.env after that): DESEC_TOKEN=<deSEC API token scoped to
# the zone>
# Optional env: PORTAL_PUBLIC_HOST (default bunsenbrenner.org), DESEC_DOMAIN
# (defaults to PORTAL_PUBLIC_HOST), PORTAL_CERT_DIR (default ~/ct-certs/portal),
# AUTH_PUBLIC_HOST (default auth.<PORTAL_PUBLIC_HOST>), AUTH_CERT_DIR (default
# ~/ct-certs/auth), KC_ADMIN_USER (default admin), ACME_EMAIL (default
# scimbe@gmail.com), NO_COLOR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT/docker/deploy"
ENV_FILE="$DEPLOY_DIR/.env"
ENV_EXAMPLE="$DEPLOY_DIR/.env.example"
DESEC_EXAMPLE="$ROOT/config/desec.env.example"
COMPOSE_BASE="$DEPLOY_DIR/compose.selfhost.yml"
COMPOSE_FRONTDOOR="$DEPLOY_DIR/compose.frontdoor.yml"
COMPOSE_SSO="$DEPLOY_DIR/compose.sso.yml"

FRESH=0
FRONTDOOR=0
SSO=0
HELP_SITE=0
STAGING=0
SKIP_CERT=0
PORTAL_PUBLIC_HOST="${PORTAL_PUBLIC_HOST:-bunsenbrenner.org}"
PORTAL_CERT_DIR="${PORTAL_CERT_DIR:-$HOME/ct-certs/portal}"
AUTH_PUBLIC_HOST="${AUTH_PUBLIC_HOST:-auth.$PORTAL_PUBLIC_HOST}"
AUTH_CERT_DIR="${AUTH_CERT_DIR:-$HOME/ct-certs/auth}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
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

usage() { sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --fresh)       FRESH=1 ;;
    --frontdoor)   FRONTDOOR=1 ;;
    --sso)         SSO=1 ;;
    --help-site)   HELP_SITE=1 ;;
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
  [ "$SSO" = "1" ] && files+=(-f "$COMPOSE_SSO")
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

  if [ "$SSO" = "1" ]; then
    [ "$FRONTDOOR" = "1" ] || die "--sso requires --frontdoor (Keycloak is served through the front door)"
    env_set AUTH_PUBLIC_HOST "$AUTH_PUBLIC_HOST"
    env_set KEYCLOAK_PUBLIC_URL "https://$AUTH_PUBLIC_HOST"
    env_set AUTH_CERT_DIR "$AUTH_CERT_DIR"
    env_set PORTAL_PUBLIC_URL "https://$PORTAL_PUBLIC_HOST"
    env_set KC_ADMIN_USER "$KC_ADMIN_USER"
    local kc_pw; kc_pw="$(env_get KC_ADMIN_PASSWORD)"
    if [ -z "$kc_pw" ] || [ "$kc_pw" = "change-me" ]; then
      kc_pw="$(openssl rand -hex 20)"
      env_set KC_ADMIN_PASSWORD "$kc_pw"
      ok "generated KC_ADMIN_PASSWORD"
    fi
    local kc_secret; kc_secret="$(env_get KC_PORTAL_CLIENT_SECRET)"
    if [ -z "$kc_secret" ]; then
      kc_secret="$(openssl rand -hex 32)"
      env_set KC_PORTAL_CLIENT_SECRET "$kc_secret"
      ok "generated KC_PORTAL_CLIENT_SECRET"
    fi
  fi

  if [ "$HELP_SITE" = "1" ]; then
    [ "$FRONTDOOR" = "1" ] || die "--help-site requires --frontdoor (it's a Browser-Plane hostname demo)"
  fi
  ok "$ENV_FILE ready"
}

# --- 3. TLS certs via acme.sh + deSEC DNS-01 (portal + auth) -----------------
# shared with scripts/authorize-pipeline.sh — see scripts/lib-acme.sh.
# shellcheck source=lib-acme.sh
. "$ROOT/scripts/lib-acme.sh"

ensure_portal_cert() {
  [ "$FRONTDOOR" = "1" ] || return 0
  export DESEC_TOKEN="${DESEC_TOKEN:-$(env_get DESEC_TOKEN)}"
  [ -n "$DESEC_TOKEN" ] || die "DESEC_TOKEN unavailable for acme.sh (check $ENV_FILE)"
  issue_cert "$PORTAL_PUBLIC_HOST" "$PORTAL_CERT_DIR" \
    "docker compose -f '$COMPOSE_BASE' -f '$COMPOSE_FRONTDOOR' --env-file '$ENV_FILE' restart edge" \
    "$ACME_EMAIL"
}

ensure_auth_cert() {
  [ "$SSO" = "1" ] || return 0
  export DESEC_TOKEN="${DESEC_TOKEN:-$(env_get DESEC_TOKEN)}"
  [ -n "$DESEC_TOKEN" ] || die "DESEC_TOKEN unavailable for acme.sh (check $ENV_FILE)"
  issue_cert "$AUTH_PUBLIC_HOST" "$AUTH_CERT_DIR" \
    "docker compose -f '$COMPOSE_BASE' -f '$COMPOSE_FRONTDOOR' -f '$COMPOSE_SSO' --env-file '$ENV_FILE' restart edge" \
    "$ACME_EMAIL"
}

# --- 4. bring the stack up ----------------------------------------------------
compose_up() {
  if [ "$FRESH" = "1" ]; then
    log "tearing down any existing stack (--fresh)"
    compose_ down -v --remove-orphans || true
  fi
  log "docker compose up --build -d (base$([ "$FRONTDOOR" = "1" ] && echo "+frontdoor")$([ "$SSO" = "1" ] && echo "+sso"))"
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

# Keycloak's own healthcheck only proves ITS http server answers — the
# control-plane may have raced it at boot and failed its one-shot JWKS fetch
# (logged as "no usable RS256 key — /me/* disabled", docs/deploy/keycloak-sso.md).
# One `restart` (compose subcommand, not `docker restart`, which reuses stale
# baked-in env) makes it re-fetch; harmless no-op if OIDC was already fine.
restart_control_plane_for_jwks() {
  [ "$SSO" = "1" ] || return 0
  log "restarting control-plane once to (re)fetch the Keycloak JWKS"
  compose_ restart control-plane
  wait_healthy
}

ensure_help_site() {
  [ "$HELP_SITE" = "1" ] || return 0
  log "bringing up the help.$PORTAL_PUBLIC_HOST demo (examples/help-site)"
  "$ROOT/examples/help-site/run-demo.sh" \
    || warn "help-site demo did not come up cleanly — check its container logs (docker compose -f docker/deploy/compose.selfhost.yml -f examples/help-site/compose.help-site.yml logs)"
}

verify() {
  curl -fsS -m 5 http://127.0.0.1:8090/healthz >/dev/null || die "healthz check failed"
  ok "healthz OK"
  local insecure_flag=()
  [ "$STAGING" = "1" ] && insecure_flag=(-k)   # staging certs aren't in the trust store
  if [ "$FRONTDOOR" = "1" ]; then
    verify_url "https://$PORTAL_PUBLIC_HOST/" "${insecure_flag[@]}"
  fi
  if [ "$SSO" = "1" ]; then
    verify_url "https://$AUTH_PUBLIC_HOST/realms/ct-demo" "${insecure_flag[@]}"
  fi
  if [ "$HELP_SITE" = "1" ]; then
    verify_url "https://help.$PORTAL_PUBLIC_HOST/" "${insecure_flag[@]}"
  fi
}

verify_url() {
  local url="$1"; shift
  local code
  code="$(curl -sS -m 10 "$@" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)"
  code="${code:-000}"
  if [ "$code" = "200" ]; then
    ok "$url -> 200"
  else
    warn "$url -> $code (DNS propagation, cert issuance still in progress, or firewall — check manually)"
  fi
}

main() {
  log "CADS-Tunnel self-host deploy — frontdoor=${FRONTDOOR} sso=${SSO} help_site=${HELP_SITE} staging=${STAGING} fresh=${FRESH}"
  [ -f "$ROOT/Cargo.toml" ] || die "run from the CADS-Tunnel checkout"
  ensure_docker
  ensure_env
  ensure_portal_cert
  ensure_auth_cert
  compose_up
  wait_healthy
  restart_control_plane_for_jwks
  ensure_help_site
  verify
  echo
  ok "self-host stack is up"
  echo "  Dashboard:      http://127.0.0.1:8090/  (loopback)"
  [ "$FRONTDOOR" = "1" ] && echo "  Public portal:  https://$PORTAL_PUBLIC_HOST/"
  [ "$SSO" = "1" ] && echo "  SSO login:      https://$AUTH_PUBLIC_HOST/ (realm ct-demo)"
  [ "$HELP_SITE" = "1" ] && echo "  Help demo:      https://help.$PORTAL_PUBLIC_HOST/"
  echo "  Logs:           docker compose -f $COMPOSE_BASE $([ "$FRONTDOOR" = "1" ] && echo "-f $COMPOSE_FRONTDOOR") $([ "$SSO" = "1" ] && echo "-f $COMPOSE_SSO") --env-file $ENV_FILE logs -f"
}
main
