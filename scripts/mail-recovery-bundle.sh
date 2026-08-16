#!/usr/bin/env bash
# Mail an encrypted recovery bundle (the secrets a restore needs) to the operator.
#
# Why this exists: `backup-selfhost.sh` protects the deployment's state, but the
# passphrase that unlocks it lives only on this host. If the host is gone, so is
# the key to its own backups. This puts a copy of the keys somewhere else --
# encrypted under a passphrase the operator types here and nowhere else stores.
#
# The passphrase is NEVER read from a file, an argument or the environment: it is
# prompted for, used, and dropped. That is deliberate. If it were readable from
# this host, mailing the bundle would move the secrets without moving the risk.
#
# A note on using your login password here: you may, but consider not to. It is
# also your sudo password, so an attacker who ever obtains this attachment gets
# an offline guessing target against your system account rather than against one
# throwaway secret. A separate, written-down passphrase is strictly safer.
#
# Usage:
#   mail-recovery-bundle.sh                 # build, encrypt, send
#   mail-recovery-bundle.sh --dry-run       # build + encrypt, do not send
#   mail-recovery-bundle.sh --test-mail     # send a harmless test mail only
set -euo pipefail

TO="${CADS_RECOVERY_TO:-scimbe@gmail.com}"
SRC="${CADS_TUNNEL_SRC:-/home/becke/workspace/CADS-Tunnel}"
ENVFILE="$SRC/docker/deploy/.env"
PASSFILE="${CADS_BACKUP_PASSFILE:-/home/becke/.config/cads-backup/passphrase}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { printf '%s\n' "$*"; }
die() { printf 'FEHLER: %s\n' "$*" >&2; exit 1; }

MODE="${1:-send}"

# SMTP settings come from the deployment's own .env -- the same account Keycloak
# already sends from. Read here, at run time, by the operator's own shell.
[ -r "$ENVFILE" ] || die "kann $ENVFILE nicht lesen"
# shellcheck disable=SC1090
SMTP_HOST=$(grep -E '^KC_SMTP_HOST=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
SMTP_PORT=$(grep -E '^KC_SMTP_PORT=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
SMTP_USER=$(grep -E '^KC_SMTP_USER=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
SMTP_PASS=$(grep -E '^KC_SMTP_PASSWORD=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
SMTP_FROM=$(grep -E '^KC_SMTP_FROM=' "$ENVFILE" | cut -d= -f2- | tr -d '"')
[ -n "${SMTP_HOST:-}" ] && [ -n "${SMTP_PASS:-}" ] || die "SMTP-Daten fehlen in $ENVFILE"

send_mail() { # $1=subject $2=body-file $3=attachment(optional)
  python3 - "$1" "$2" "${3:-}" <<'PY'
import os, smtplib, ssl, sys
from email.message import EmailMessage
subject, bodyfile, attach = sys.argv[1], sys.argv[2], sys.argv[3]
m = EmailMessage()
m["From"] = os.environ["SMTP_FROM"]; m["To"] = os.environ["TO"]; m["Subject"] = subject
m.set_content(open(bodyfile, encoding="utf-8").read())
if attach:
    with open(attach, "rb") as fh:
        m.add_attachment(fh.read(), maintype="application", subtype="pgp-encrypted",
                         filename=os.path.basename(attach))
port = int(os.environ.get("SMTP_PORT") or 465)
ctx = ssl.create_default_context()
if port == 465:
    s = smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, context=ctx, timeout=30)
else:
    s = smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=30); s.starttls(context=ctx)
s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"]); s.send_message(m); s.quit()
print("gesendet an", os.environ["TO"])
PY
}
export SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM TO

if [ "$MODE" = "--test-mail" ]; then
  printf 'Testnachricht vom CADS-Tunnel-Host.\n\nWenn du das liest, funktioniert der Versandweg.\nEs sind KEINE Geheimnisse in dieser Mail.\n' > "$WORK/body.txt"
  send_mail "CADS-Tunnel: Testnachricht (keine Geheimnisse)" "$WORK/body.txt"
  exit 0
fi

# --- Collect what a restore genuinely needs. Nothing here is optional-nice: each
# item is something a rebuilt host cannot derive on its own.
mkdir -p "$WORK/bundle"
[ -r "$PASSFILE" ] && cp "$PASSFILE" "$WORK/bundle/backup-passphrase.txt"
cp "$ENVFILE" "$WORK/bundle/deploy.env"
docker inspect ct-selfhost-keycloak-1 --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
  | grep -E '^KEYCLOAK_ADMIN' > "$WORK/bundle/keycloak-admin.txt" || true
cat > "$WORK/bundle/WIEDERHERSTELLUNG.md" <<EOF
# Wiederherstellung in Kürze

1. Docker, git, gpg auf dem neuen Host installieren.
2. \`backup-passphrase.txt\` nach \`~/.config/cads-backup/passphrase\` legen (chmod 600).
3. \`git clone https://github.com/scimbe/CADS-Tunnel.git && cd CADS-Tunnel\`
4. \`./scripts/restore-selfhost.sh\`

Das Skript holt den neuesten Snapshot aus dem privaten Backup-Repository,
entschlüsselt ihn mit dieser Passphrase, baut die Images aus den Quellen und
spielt Datenbanken, Volumes, Zertifikate und .env zurück.

Erstellt: $(date -u +%Y-%m-%dT%H:%M:%SZ) auf $(hostname)
EOF

BUNDLE="$WORK/cads-recovery-$(date -u +%Y%m%d).tar.gz"
tar czf "$BUNDLE" -C "$WORK/bundle" .

# --- The passphrase: prompted, confirmed, never persisted.
printf 'Passphrase für die Verschlüsselung (Eingabe bleibt unsichtbar): '
read -rs PASS1; echo
printf 'Passphrase wiederholen: '
read -rs PASS2; echo
[ "$PASS1" = "$PASS2" ] || die "Passphrasen stimmen nicht überein"
[ ${#PASS1} -ge 12 ] || die "zu kurz: mindestens 12 Zeichen (dieser Anhang ist offline angreifbar)"

printf '%s' "$PASS1" | gpg --batch --yes --symmetric --cipher-algo AES256 \
  --passphrase-fd 0 --output "$BUNDLE.gpg" "$BUNDLE" || die "Verschlüsselung fehlgeschlagen"
unset PASS1 PASS2
shred -u "$BUNDLE" 2>/dev/null || rm -f "$BUNDLE"

cat > "$WORK/body.txt" <<EOF
Verschlüsseltes Wiederherstellungs-Paket für die bunsenbrenner.org-Installation.

Der Anhang ist mit GPG (AES-256) und der Passphrase verschlüsselt, die du beim
Erzeugen eingegeben hast. Sie steht NICHT in dieser Mail -- ohne sie ist der
Anhang wertlos, auch für jeden, der Zugriff auf dieses Postfach bekommt.

Entschlüsseln:

    gpg --decrypt $(basename "$BUNDLE.gpg") > paket.tar.gz
    tar xzf paket.tar.gz

Inhalt: Passphrase der nächtlichen Sicherungen, deploy-.env, Keycloak-Admin-Zugang,
Kurzanleitung zur Wiederherstellung.

Erzeugt: $(date -u +%Y-%m-%dT%H:%M:%SZ) auf $(hostname)
EOF

if [ "$MODE" = "--dry-run" ]; then
  log "--dry-run: verschlüsseltes Paket liegt unter $BUNDLE.gpg (wird beim Beenden gelöscht)"
  log "Größe: $(du -h "$BUNDLE.gpg" | awk '{print $1}')"
  exit 0
fi

send_mail "CADS-Tunnel: verschlüsseltes Wiederherstellungs-Paket" "$WORK/body.txt" "$BUNDLE.gpg"
log "Hinweis: bewahre die Passphrase getrennt von diesem Postfach auf."
