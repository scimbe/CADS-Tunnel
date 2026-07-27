# CADS-Tunnel — shared Let's Encrypt cert issuance via acme.sh + deSEC DNS-01.
# Sourced by scripts/deploy-selfhost.sh and scripts/authorize-pipeline.sh so
# there is one implementation, not two that can drift. See docs/dns01-desec.md.
#
# Not executable on its own — `source` it. Callers must already have
# log()/ok()/warn()/die() defined. Reads STAGING/SKIP_CERT if set (default 0).

ensure_acme_sh() {
  local acme_email="${1:?ensure_acme_sh needs an ACME account email}"
  if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
    curl -fsS https://get.acme.sh | sh -s email="$acme_email" >/dev/null
  fi
  [ -n "${DESEC_TOKEN:-}" ] || die "DESEC_TOKEN not set for acme.sh"
  # acme.sh's dns_desec hook uses the legacy dedyn.io variable name, not DESEC_TOKEN.
  export DEDYN_TOKEN="$DESEC_TOKEN"
}

# issue_cert HOST DIR RELOAD_CMD ACME_EMAIL
# Issues (or reuses) a Let's Encrypt cert for HOST into DIR/{fullchain,privkey}.pem.
issue_cert() {
  local host="$1" dir="$2" reload_cmd="$3" acme_email="$4"
  local full="$dir/fullchain.pem" key="$dir/privkey.pem"
  mkdir -p "$dir"

  if [ "${SKIP_CERT:-0}" = "1" ]; then
    [ -f "$full" ] && [ -f "$key" ] || die "--skip-cert given but $full / $key missing"
    ok "using existing cert in $dir (--skip-cert)"
    return 0
  fi
  if [ -f "$full" ] && [ -f "$key" ] && openssl x509 -in "$full" -checkend 604800 -noout >/dev/null 2>&1; then
    ok "existing cert in $dir is valid for >7 days — skipping issuance"
    return 0
  fi

  log "obtaining a Let's Encrypt cert for $host via deSEC DNS-01 (acme.sh)"
  ensure_acme_sh "$acme_email"

  local server_flag=(--server letsencrypt)
  [ "${STAGING:-0}" = "1" ] && server_flag=(--server letsencrypt_test)

  "$HOME/.acme.sh/acme.sh" --issue --dns dns_desec -d "$host" "${server_flag[@]}" \
    || die "acme.sh issuance failed for $host"
  # The reloadcmd only matters on RENEWAL (restart whatever's serving the cert so
  # it picks up the new one); on first issuance there's nothing running yet to
  # restart, so a reload failure here is not fatal as long as the files landed.
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$host" \
    --fullchain-file "$full" --key-file "$key" \
    --reloadcmd "$reload_cmd" \
    || warn "acme.sh install-cert reload step failed (fine on first issuance — verifying cert files below)"
  [ -f "$full" ] && [ -f "$key" ] || die "cert files missing after acme.sh install-cert"
  chmod 600 "$key"
  ok "cert installed at $dir ($([ "${STAGING:-0}" = "1" ] && echo staging || echo production))"
}
