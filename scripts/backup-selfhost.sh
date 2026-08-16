#!/usr/bin/env bash
# Nightly encrypted snapshot of the self-host deployment's STATE.
#
# What this exists for: the compose files, themes and sources are in git, but the
# state that makes this deployment *this* deployment is not -- Keycloak's user
# database, the control-plane's tunnels/grants, the edge CA (whose stability
# gated pinned clients, #496), the BYO certificates, and .env's secrets. Losing
# those means every account, tunnel and pinned anchor is gone even though every
# line of code survived.
#
# Everything here is encrypted BEFORE it leaves the host: the snapshot contains
# password hashes, client secrets, an SMTP password and CA key material, and a
# private GitHub repository is access-controlled, not encrypted. The passphrase
# lives only in $PASSFILE (0600) and in whatever the operator keeps it in -- it
# is deliberately NOT in the backup repository, because a backup that carries
# its own key protects against disk failure and nothing else.
#
# Usage:
#   backup-selfhost.sh            # snapshot + push
#   backup-selfhost.sh --no-push  # snapshot only, leave it in $WORK
set -euo pipefail

REPO_SSH="${CADS_BACKUP_REPO:-https://github.com/scimbe/CADS-Tunnel-backups.git}"
PASSFILE="${CADS_BACKUP_PASSFILE:-/home/becke/.config/cads-backup/passphrase}"
SRC="${CADS_TUNNEL_SRC:-/home/becke/workspace/CADS-Tunnel}"
CERT_DIRS="${CADS_CERT_DIRS:-/home/becke/ct-certs}"
WORK="${CADS_BACKUP_WORK:-/var/tmp/cads-backup}"
KEEP="${CADS_BACKUP_KEEP:-7}"          # snapshots retained in the repo
PUSH=1
[ "${1:-}" = "--no-push" ] && PUSH=0

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "FEHLER: $*"; exit 1; }

[ -r "$PASSFILE" ] || die "keine Passphrase unter $PASSFILE"
command -v gpg >/dev/null || die "gpg fehlt"

STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
STAGE="$WORK/stage-$STAMP"
rm -rf "$STAGE"; mkdir -p "$STAGE/volumes"

# --- Keycloak: logical dump, not a file copy. Copying a live Postgres data
# directory yields a torn image; pg_dump is consistent by construction.
log "Keycloak-Datenbank sichern"
docker exec ct-selfhost-keycloak-postgres-1 pg_dump -U keycloak -d keycloak --format=custom \
  > "$STAGE/keycloak.pgdump" || die "pg_dump fehlgeschlagen"

# --- Control-plane: SQLite with WAL. `.backup` takes a consistent snapshot of a
# database that is being written to; copying the .db file alone would miss the WAL.
log "Control-Plane-Datenbank sichern"
docker run --rm -v ct-selfhost_cpdata:/d -v "$STAGE":/out alpine sh -c \
  'apk add -q sqlite && sqlite3 /d/control-plane.db ".backup /out/control-plane.db"' \
  || die "sqlite-Backup fehlgeschlagen"

# --- Volumes that hold identity/state. Deliberately enumerated rather than
# globbed: a new volume should be a conscious addition here, not silently
# included (or silently missed) depending on what happens to exist.
for v in ct-selfhost_shared ct-selfhost_keycloak_data \
         help-site_help_agent_state cads-a2a-demo_a2a_demo_agent_state \
         cads-auction-demo_auction_demo_agent_state; do
  if docker volume inspect "$v" >/dev/null 2>&1; then
    log "Volume $v"
    docker run --rm -v "$v":/d -v "$STAGE/volumes":/out alpine \
      tar czf "/out/$v.tar.gz" -C /d . || die "tar für $v fehlgeschlagen"
  else
    log "Volume $v fehlt — übersprungen"
  fi
done

# --- Secrets and certificates that live on the host filesystem.
[ -f "$SRC/docker/deploy/.env" ] && cp "$SRC/docker/deploy/.env" "$STAGE/deploy.env"
[ -d "$CERT_DIRS" ] && tar czf "$STAGE/certs.tar.gz" -C "$(dirname "$CERT_DIRS")" "$(basename "$CERT_DIRS")"

# --- Manifest: what a restore needs to reproduce THIS deployment, including the
# source commits. Restoring state onto a different code revision is the failure
# mode this pins down.
{
  echo "{"
  echo "  \"taken_at\": \"$STAMP\","
  echo "  \"host\": \"$(hostname)\","
  echo "  \"cads_tunnel_commit\": \"$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)\","
  echo "  \"ct_agent_release\": \"$(cat "$SRC/CT_AGENT_RELEASE" 2>/dev/null || echo unknown)\","
  echo "  \"images\": ["
  docker ps --format '{{.Names}}|{{.Image}}' | sed 's/^/    "/; s/$/",/' | sed '$ s/,$//'
  echo "  ]"
  echo "}"
} > "$STAGE/MANIFEST.json"

# --- One archive, one encryption step.
log "verschlüsseln"
TAR="$WORK/$STAMP.tar.gz"
tar czf "$TAR" -C "$STAGE" .
gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase-file "$PASSFILE" \
    --output "$TAR.gpg" "$TAR" || die "gpg fehlgeschlagen"
SIZE=$(du -h "$TAR.gpg" | awk '{print $1}')
shred -u "$TAR" 2>/dev/null || rm -f "$TAR"
rm -rf "$STAGE"
log "Snapshot fertig: $TAR.gpg ($SIZE)"

[ "$PUSH" -eq 1 ] || { log "--no-push: Ende"; exit 0; }

# --- Publish. Each push replaces history with a single commit: the payload is
# encrypted, so git cannot delta-compress it -- keeping history would grow the
# repository by a full snapshot every night. The retained snapshots ARE the
# history, bounded by $KEEP.
log "in das private Repository schieben"
CLONE="$WORK/repo"
rm -rf "$CLONE"; mkdir -p "$CLONE"
cd "$CLONE"
git init -q -b main
git remote add origin "$REPO_SSH"
git fetch -q --depth 1 origin main 2>/dev/null && git checkout -q FETCH_HEAD -- . 2>/dev/null || true
mkdir -p snapshots
cp "$TAR.gpg" "snapshots/$STAMP.tar.gz.gpg"
ls -1 snapshots/*.tar.gz.gpg 2>/dev/null | sort | head -n "-$KEEP" | xargs -r rm -f
cat > README.md <<EOF
# CADS-Tunnel — verschlüsselte Sicherungen

Automatisch erzeugt von \`scripts/backup-selfhost.sh\` auf $(hostname).
Letzter Lauf: $STAMP · aufbewahrt: $KEEP Snapshots.

**Der Inhalt ist mit GPG (AES-256) verschlüsselt.** Die Passphrase liegt NICHT in
diesem Repository — ohne sie sind diese Dateien unbrauchbar, auch für den, der
Zugriff auf das Repository hat. Das ist beabsichtigt: ein privates Repository ist
zugriffsbeschränkt, nicht verschlüsselt.

## Wiederherstellen

\`\`\`
git clone https://github.com/scimbe/CADS-Tunnel.git
cd CADS-Tunnel
./scripts/restore-selfhost.sh            # neuester Snapshot
./scripts/restore-selfhost.sh <STAMP>    # bestimmter Snapshot
\`\`\`

Das Skript holt die Quellen, entschlüsselt den Snapshot, spielt Datenbanken,
Volumes, Zertifikate und \`.env\` zurück und startet den Stack neu.

## Was enthalten ist

| Datei | Inhalt |
|---|---|
| \`keycloak.pgdump\` | Keycloak-Datenbank (Konten, Realm, Clients) |
| \`control-plane.db\` | Tunnel, Kanäle, Grants, Allowlists |
| \`volumes/*.tar.gz\` | Edge-CA und Agent-Identitäten |
| \`certs.tar.gz\` | BYO-Zertifikate (Portal, Auth) |
| \`deploy.env\` | Deploy-Secrets |
| \`MANIFEST.json\` | Quell-Commit, Release-Pin, laufende Images |
EOF
git add -A
git -c user.email=backup@bunsenbrenner.org -c user.name="CADS backup" \
    commit -q -m "snapshot $STAMP"
git push -q --force origin HEAD:main || die "push fehlgeschlagen"
log "gepusht: snapshots/$STAMP.tar.gz.gpg"
cd /; rm -rf "$CLONE"
find "$WORK" -maxdepth 1 -name '*.tar.gz.gpg' -mtime +2 -delete 2>/dev/null || true
log "fertig"
