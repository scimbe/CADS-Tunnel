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
  # Owner-only key perms (#668): not 644 (world-readable -- more permissive than
  # every other secret in this repo, which is 600) and not 600 either -- 600
  # silently breaks TLS termination on the next container recreate, because
  # whatever serves this cert (edge, control-plane) reads it via a host bind
  # mount as its own non-root container uid 65532 (compose.selfhost.yml's
  # `user: "65532:65532"`), not as the host user issuing it (found live,
  # 2026-08-25, ADR-0024 M4: the masque cert this same function issued came up
  # with the edge logging "MASQUE TLS cert configured but UNUSABLE (Permission
  # denied)" and falling back to unterminated/plaintext proxying -- #657/#658).
  # 640 + group-owned by that same uid/gid closes both gaps: the container
  # matches on group and can still read it, but no other local account can.
  # uid/gid 65532 has no corresponding host account (getent passwd/group 65532
  # both empty), so the host user issuing the cert can't chgrp there directly
  # without root -- route it through a throwaway root container instead (the
  # Docker daemon runs as root regardless of the invoking host user, the same
  # pattern backup-verify.sh/backup-selfhost.sh already use). Deliberately only
  # chgrp, never chown: acme.sh's own renewal path does an in-place `cat >
  # "$_real_key"` truncate-write, which needs the file's *owner* write bit --
  # chowning the key itself to the container's uid would silently break every
  # future renewal run as this host user.
  if command -v docker >/dev/null 2>&1 \
      && docker run --rm -v "$dir":/certs alpine chgrp 65532 /certs/privkey.pem >/dev/null 2>&1; then
    chmod 640 "$key"
  else
    warn "could not chgrp $key to the container gid via docker -- falling back to 644 (world-readable, see #668)"
    chmod 644 "$key"
  fi
  ok "cert installed at $dir ($([ "${STAGING:-0}" = "1" ] && echo staging || echo production))"
}
