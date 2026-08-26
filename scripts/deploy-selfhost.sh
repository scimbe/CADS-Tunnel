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
# Safeguards that are armed only through the environment of the deploy call are
# checked before anything is recreated: if the running stack has one armed and
# this call would leave it unset, the deploy REFUSES rather than quietly
# recreating a less protected system. Pass --allow-security-downgrade to turn
# one off on purpose. Currently checked: CT_EDGE_REQUIRE_ATTESTED_ENDPOINT
# (#546), CT_CP_EDGE_ADMIN_TOKEN (#543).
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
COMPOSE_RELAY="$DEPLOY_DIR/compose.relay.yml"
COMPOSE_MASQUE="$DEPLOY_DIR/compose.masque.yml"

FRESH=0
FRONTDOOR=0
SSO=0
HELP_SITE=0
STAGING=0
SKIP_CERT=0
ALLOW_SEC_DOWNGRADE=0
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

# Derived, not a hardcoded line range: the header comment block above has grown
# past its original bounds at least once already (a prior `sed -n '2,27p'` cut
# the "Required env"/"Optional env" paragraphs -- lines 28-38 -- silently out of
# `--help`'s output, and would keep doing so on the next header edit too). Print
# every line from line 2 through the end of the leading `#`/blank-line block,
# stopping at the first real code line (`set -euo pipefail`) -- self-updating,
# same "derive it, don't list it" reasoning check_no_silent_security_downgrade
# already uses for its own watched-variable list below.
usage() {
  awk 'NR>=2 && (/^#/||/^$/){sub(/^# ?/,""); print; next} NR>=2{exit}' "${BASH_SOURCE[0]}"
  exit "${1:-0}"
}

# Kept verbatim so an error message can hand the operator the exact command to
# re-run. Inside a function `$*` would be that function's arguments, not these.
SCRIPT_ARGS=("$@")

while [ $# -gt 0 ]; do
  case "$1" in
    --fresh)       FRESH=1 ;;
    --frontdoor)   FRONTDOOR=1 ;;
    --sso)         SSO=1 ;;
    --help-site)   HELP_SITE=1 ;;
    --staging)     STAGING=1 ;;
    --skip-cert)   SKIP_CERT=1 ;;
    --allow-security-downgrade) ALLOW_SEC_DOWNGRADE=1 ;;
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
  # Relay-gate overlay (#330): auto-included whenever the deployment has provisioned a
  # relay-node peer id in its .env. This overlay used to be applied only by hand, so every
  # scripted redeploy silently DROPPED CT_EDGE_RELAY_UPSTREAM/CT_EDGE_RELAY_NODE_PEER from
  # the recreated edge -- the relay gate then answered every NAT'd channel member with
  # "relay gate not configured" while the rest of the edge looked perfectly healthy.
  # Live incident 2026-08-13 19:34 UTC: one such redeploy took the gate away mid-testing;
  # accept-side members waited out their whole park window and surfaced it as a bogus
  # "edge relay refused the channel join" ~40s later. Keying on the .env value keeps
  # gate-less deployments byte-identical to before.
  if grep -q '^CT_RELAY_NODE_PEER=..*' "$ENV_FILE" 2>/dev/null; then
    files+=(-f "$COMPOSE_RELAY")
  fi
  # MASQUE overlay (ADR-0024 M4): same auto-include convention as the relay-gate
  # overlay above, for the same reason -- masque-proxy runs `network_mode:
  # service:edge` (compose.masque.yml), so leaving this overlay out of a redeploy
  # doesn't just fail to update it, it ORPHANS the existing masque-proxy container
  # against the now-dead network namespace of the edge container that redeploy
  # just recreated (found live, 2026-08-26: a redeploy without --masque left
  # masque-proxy "Up" but netns-dead). Keying on CT_MASQUE_PROXY_TOKEN keeps
  # deployments that never opted into MASQUE byte-identical to before.
  if grep -q '^CT_MASQUE_PROXY_TOKEN=..*' "$ENV_FILE" 2>/dev/null; then
    files+=(-f "$COMPOSE_MASQUE")
  fi
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

# --- 3b. refuse to silently disarm a safeguard that is currently armed --------
#
# Some safeguards are configured only through the environment of the deploy
# CALL, not through the .env file. Re-running this script without that variable
# then recreates the container with the safeguard OFF -- the deployment looks
# identical, comes up healthy, and is quietly less protected than it was a
# minute earlier.
#
# This is not hypothetical. On 2026-08-18 three consecutive redeploys turned
# CT_EDGE_REQUIRE_ATTESTED_ENDPOINT (#546) back off, unnoticed; the only reason
# it surfaced at all is that #552 makes the edge SAY which way it came up. The
# relay-gate overlay above carries a comment about the very same class of
# accident from 2026-08-13. Two independent occurrences are a pattern, so the
# script now checks instead of relying on whoever types the command.
#
# The rule is deliberately narrow: it never decides policy, it only refuses to
# take away something that is running right now. Turning a safeguard off stays
# possible -- with --allow-security-downgrade, i.e. on purpose and in writing.
effective_setting() {   # what THIS deploy would set: shell env wins over .env
  local name="$1" from_shell="${!1:-}"
  if [ -n "$from_shell" ]; then printf '%s' "$from_shell"; return 0; fi
  sed -n "s/^${name}=//p" "$ENV_FILE" 2>/dev/null | tail -1
}
running_setting() {     # what the container that is up right now actually has
  local cid
  cid=$(compose_ ps -q "$1" 2>/dev/null | head -1)
  [ -n "$cid" ] || return 1
  docker_ inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
    | sed -n "s/^${2}=//p" | tail -1
}
check_no_silent_security_downgrade() {
  # WHICH variables are watched is derived, not listed.
  #
  # The first version carried a table of two. That table was a snapshot: the compose files
  # define five switches that can silently vanish (`"${VAR:-}"` -- unset in the environment
  # and the container comes up without them), and the two it named were the two I happened to
  # be thinking about. One of the three it missed is `CT_EDGE_ADMIN_TOKEN`, whose absence
  # disables tunnel revocation outright -- the very capability #554/#566 spent this night
  # making reliable, switched off by a deploy nobody would question.
  #
  # So: read the switches out of the compose files this deploy actually uses. A switch added
  # to a compose file is watched the day it is added, without anyone remembering this script.
  local composes=("$COMPOSE_BASE")
  [ "$FRONTDOOR" = "1" ] && composes+=("$COMPOSE_FRONTDOOR")
  [ "$SSO" = "1" ] && composes+=("$COMPOSE_SSO")
  grep -q '^CT_RELAY_NODE_PEER=..*' "$ENV_FILE" 2>/dev/null && composes+=("$COMPOSE_RELAY")
  grep -q '^CT_MASQUE_PROXY_TOKEN=..*' "$ENV_FILE" 2>/dev/null && composes+=("$COMPOSE_MASQUE")
  local watched
  watched=$(grep -hoE '^[[:space:]]+CT_[A-Z_]+: "\$\{CT_[A-Z_]+:-\}"' "${composes[@]}" 2>/dev/null \
            | grep -oE 'CT_[A-Z_]+' | sort -u)

  # Annotations only -- never the scope. An unannotated switch is still watched; it just gets
  # a generic sentence instead of a specific one. That is the whole point: a switch nobody
  # annotated must not thereby become invisible.
  local rows=(
    "CT_EDGE_REQUIRE_ATTESTED_ENDPOINT|exactly-1|endpoint attestation (#546): a channel join from an address that contradicts the advertised one is refused"
    "CT_CP_EDGE_ADMIN_TOKEN|non-empty|the control plane's admin gate (#543): without a token it does not fail -- it is simply absent"
    "CT_EDGE_ADMIN_TOKEN|non-empty|tunnel revocation on the edge (#27 RB3): absent, the edge cannot cut a revoked tunnel at all"
    "CT_PORTAL_SESSION_KEY|non-empty|a stable portal session key: absent, every restart signs sessions with a fresh random key and logs everyone out"
    "CT_OIDC_ISSUER|non-empty|OIDC/SSO on the portal: absent, /me/* stays disabled"
  )
  local downgrades=() row var how what now next armed_now armed_next svc
  for var in $watched; do
    how=non-empty
    what="the switch $var (no annotation in this script -- watched anyway)"
    for row in "${rows[@]}"; do
      case "$row" in "$var|"*) IFS='|' read -r _ how what <<<"$row" ;; esac
    done
    # Which service carries it is derived too: ask both, take the one that has it. A
    # hand-kept service column would be a second snapshot next to the first.
    now=""
    for svc in edge control-plane; do
      now=$(running_setting "$svc" "$var") && [ -n "$now" ] && break
    done
    [ -n "${now:-}" ] || continue                      # not set anywhere now -> nothing to lose
    next=$(effective_setting "$var")
    case "$how" in
      exactly-1) [ "$now" = "1" ] && armed_now=1 || armed_now=0
                 [ "$next" = "1" ] && armed_next=1 || armed_next=0 ;;
      *)         [ -n "$now" ] && armed_now=1 || armed_now=0
                 [ -n "$next" ] && armed_next=1 || armed_next=0 ;;
    esac
    # Only the arming direction matters. Values are never printed: one of these
    # is a secret, and the answer the operator needs is on/off, not its content.
    if [ "$armed_now" = "1" ] && [ "$armed_next" != "1" ]; then
      downgrades+=("$var is armed on the running stack, and this deploy would leave it unset -- losing $what")
    fi
  done
  [ ${#downgrades[@]} -eq 0 ] && return 0
  local d
  for d in "${downgrades[@]}"; do warn "$d"; done
  if [ "$ALLOW_SEC_DOWNGRADE" = "1" ]; then
    warn "proceeding anyway: --allow-security-downgrade was passed"
    return 0
  fi
  die "refusing to disarm a safeguard that is currently armed. Re-run with the variable(s) set, e.g.
       CT_EDGE_REQUIRE_ATTESTED_ENDPOINT=1 $0 ${SCRIPT_ARGS[*]}
     or, if turning it off is really intended, pass --allow-security-downgrade."
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
  # Before anything is recreated: a deploy must not take away a safeguard that
  # the running stack has armed. Placed after ensure_env so .env exists, and
  # before compose_up so the refusal costs nothing.
  check_no_silent_security_downgrade
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
