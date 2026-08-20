#!/usr/bin/env bash
# Rebuild the self-host deployment from sources plus an encrypted snapshot.
#
# Assumes only: Docker, git, gpg, and the backup passphrase. Everything else --
# the sources, the images, the state -- is fetched or rebuilt. Intended for the
# case where the host is gone, not just a bad deploy.
#
# Usage:
#   restore-selfhost.sh                 # newest snapshot
#   restore-selfhost.sh 2026-08-16T173917Z
#   restore-selfhost.sh --list          # what is available
#   restore-selfhost.sh --dry-run       # decrypt + verify, change nothing
set -euo pipefail

# #598: the decrypted snapshot (Keycloak DB, control-plane grants, deploy.env,
# CA/cert material) lands in $WORK in the clear -- without this, mkdir inherits the
# host's ambient umask (0002 here), leaving it world-readable for the whole restore,
# longer still under --dry-run. Mirrors the backup-side fix.
umask 077

BACKUP_REPO="${CADS_BACKUP_REPO:-https://github.com/scimbe/CADS-Tunnel-backups.git}"
SRC_REPO="${CADS_SRC_REPO:-https://github.com/scimbe/CADS-Tunnel.git}"
PASSFILE="${CADS_BACKUP_PASSFILE:-/home/becke/.config/cads-backup/passphrase}"
SRC="${CADS_TUNNEL_SRC:-/home/becke/workspace/CADS-Tunnel}"
CERT_PARENT="${CADS_CERT_PARENT:-/home/becke}"
WORK="${CADS_RESTORE_WORK:-/var/tmp/cads-restore}"

log() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { log "FEHLER: $*"; exit 1; }

WANT=""; DRY=0
case "${1:-}" in
  --list) WANT=LIST ;;
  --dry-run) DRY=1 ;;
  "") ;;
  *) WANT="$1" ;;
esac

[ -r "$PASSFILE" ] || die "keine Passphrase unter $PASSFILE — ohne sie ist der Snapshot unbrauchbar"
command -v docker >/dev/null || die "docker fehlt"

rm -rf "$WORK"; mkdir -p "$WORK"; chmod 700 "$WORK"
log "Sicherungen holen"
git clone -q --depth 1 "$BACKUP_REPO" "$WORK/backups" || die "clone des Backup-Repos fehlgeschlagen"

if [ "$WANT" = "LIST" ]; then
  ls -1 "$WORK/backups/snapshots" | sed 's/\.tar\.gz\.gpg$//' | sort
  exit 0
fi

SNAP=$(ls -1 "$WORK/backups/snapshots"/*.tar.gz.gpg | sort | tail -1)
[ -n "$WANT" ] && SNAP="$WORK/backups/snapshots/$WANT.tar.gz.gpg"
[ -f "$SNAP" ] || die "Snapshot nicht gefunden: ${WANT:-<neuester>}"
log "Snapshot: $(basename "$SNAP")"

mkdir -p "$WORK/state"
gpg --batch --quiet --decrypt --passphrase-file "$PASSFILE" "$SNAP" \
  | tar xz -C "$WORK/state" || die "Entschlüsselung fehlgeschlagen (falsche Passphrase?)"
COMMIT=$(python3 -c "import json;print(json.load(open('$WORK/state/MANIFEST.json'))['cads_tunnel_commit'])" 2>/dev/null || echo "")
log "Snapshot gehört zu Quell-Commit ${COMMIT:0:12}"

if [ "$DRY" -eq 1 ]; then
  log "--dry-run: Inhalt geprüft, nichts verändert"
  ls -la "$WORK/state" | tail -n +2 | awk '{print "  "$NF" ("$5" Bytes)"}'
  exit 0
fi

# --- Sources at the exact revision the state came from. Restoring a database
# onto a newer schema is the failure this pins down; the operator can still
# fast-forward afterwards, deliberately.
if [ -d "$SRC/.git" ]; then
  log "Quellen vorhanden: $SRC"
else
  log "Quellen klonen nach $SRC"
  git clone -q "$SRC_REPO" "$SRC" || die "clone der Quellen fehlgeschlagen"
fi
if [ -n "$COMMIT" ] && [ "$COMMIT" != "unknown" ]; then
  git -C "$SRC" fetch -q origin && git -C "$SRC" checkout -q "$COMMIT" \
    || log "WARNUNG: Commit $COMMIT nicht auscheckbar — es wird der aktuelle Stand benutzt"
fi

log "Stack stoppen (falls er läuft)"
docker compose -f "$SRC/docker/deploy/compose.selfhost.yml" \
  -f "$SRC/docker/deploy/compose.frontdoor.yml" -f "$SRC/docker/deploy/compose.sso.yml" \
  --env-file "$SRC/docker/deploy/.env" down 2>/dev/null || true

log "Secrets und Zertifikate zurückspielen"
[ -f "$WORK/state/deploy.env" ] && install -m 600 "$WORK/state/deploy.env" "$SRC/docker/deploy/.env"
[ -f "$WORK/state/certs.tar.gz" ] && tar xzf "$WORK/state/certs.tar.gz" -C "$CERT_PARENT"

log "Volumes zurückspielen"
for f in "$WORK/state/volumes"/*.tar.gz; do
  [ -f "$f" ] || continue
  v=$(basename "$f" .tar.gz)
  docker volume create "$v" >/dev/null
  docker run --rm -v "$v":/d -v "$(dirname "$f")":/in alpine \
    sh -c "rm -rf /d/* /d/..?* 2>/dev/null; tar xzf /in/$(basename "$f") -C /d" || die "Volume $v"
  log "  $v"
done

# --- Databases need their servers running, so bring the stack up first and
# restore into it. Keycloak is stopped again around its own restore: replaying a
# dump under a running Keycloak fights its connection pool and its caches.
log "Stack starten (baut die Images aus den Quellen)"
( cd "$SRC" && ./scripts/deploy-selfhost.sh --frontdoor --sso --skip-cert ) || die "Deploy fehlgeschlagen"

log "Control-Plane-Datenbank zurückspielen"
docker stop ct-selfhost-control-plane-1 >/dev/null
docker run --rm -v ct-selfhost_cpdata:/d -v "$WORK/state":/in alpine \
  sh -c 'rm -f /d/control-plane.db*; cp /in/control-plane.db /d/control-plane.db'
docker start ct-selfhost-control-plane-1 >/dev/null

log "Keycloak-Datenbank zurückspielen"
docker stop ct-selfhost-keycloak-1 >/dev/null
docker cp "$WORK/state/keycloak.pgdump" ct-selfhost-keycloak-postgres-1:/tmp/kc.pgdump
docker exec ct-selfhost-keycloak-postgres-1 sh -c \
  'dropdb -U keycloak --if-exists keycloak && createdb -U keycloak keycloak && pg_restore -U keycloak -d keycloak /tmp/kc.pgdump' \
  || die "pg_restore fehlgeschlagen"
docker exec ct-selfhost-keycloak-postgres-1 rm -f /tmp/kc.pgdump
docker start ct-selfhost-keycloak-1 >/dev/null

log "warten, bis die Dienste antworten"
for i in $(seq 30); do
  R=$(docker exec ct-selfhost-control-plane-1 sh -c 'curl -s -o /dev/null -w "%{http_code}" http://localhost:8090/readyz' 2>/dev/null || echo 000)
  [ "$R" = "200" ] && break
  sleep 5
done
log "control-plane readyz: ${R:-?}"
log "fertig — Hostnamen prüfen und Agenten ggf. neu starten"
