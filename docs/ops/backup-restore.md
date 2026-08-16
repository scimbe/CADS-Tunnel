# Sicherung und Wiederherstellung

Der Code liegt in git; der Zustand, der diese Installation zu *dieser* Installation
macht, nicht: Keycloaks Benutzerdatenbank, die Tunnel und Grants der Control-Plane,
die Edge-CA (deren Stabilitaet gepinnte Clients traegt, #496), die BYO-Zertifikate
und die Secrets in `.env`. Gehen die verloren, sind alle Konten, Tunnel und Anker
weg, obwohl jede Zeile Code noch da ist.

## Naechtliche Sicherung

`scripts/backup-selfhost.sh` laeuft per Cron um 03:17 UTC und legt einen
verschluesselten Snapshot in das **private** Repository `scimbe/CADS-Tunnel-backups`.

Verschluesselt wird **vor** dem Hochladen (GPG, AES-256). Ein privates Repository ist
zugriffsbeschraenkt, nicht verschluesselt: GitHub kann den Inhalt lesen, und ein
versehentliches Umschalten auf oeffentlich waere eine Vollkompromittierung. Der
Snapshot enthaelt Passworthashes, Client-Secrets, das SMTP-Passwort und CA-Material.

Die Passphrase liegt in `~/.config/cads-backup/passphrase` (0600) und ausdruecklich
**nicht** im Backup-Repository — eine Sicherung, die ihren eigenen Schluessel
mitfuehrt, schuetzt gegen Plattenausfall und sonst nichts.

Aufbewahrt werden die letzten 7 Snapshots. Jeder Push ersetzt die Historie durch
einen einzelnen Commit: verschluesselte Daten lassen sich nicht delta-komprimieren,
eine wachsende Historie wuerde das Repository jede Nacht um einen vollen Snapshot
vergroessern. Die aufbewahrten Snapshots *sind* die Historie.

## Wiederherstellung

```
git clone https://github.com/scimbe/CADS-Tunnel.git && cd CADS-Tunnel
./scripts/restore-selfhost.sh --list       # verfuegbare Snapshots
./scripts/restore-selfhost.sh --dry-run    # entschluesseln und pruefen, nichts aendern
./scripts/restore-selfhost.sh              # neuester Snapshot
```

Voraussetzung ist nur Docker, git, gpg und die Passphrase. Das Skript checkt die
Quellen auf den Commit aus, aus dem der Snapshot stammt (Zustand auf ein neueres
Schema zurueckzuspielen ist der Fehlerfall, den das verhindert), baut die Images,
spielt Volumes, Zertifikate und `.env` zurueck und danach die beiden Datenbanken —
Keycloak per `pg_restore` bei gestopptem Keycloak, die Control-Plane als Dateikopie
bei gestoppter Control-Plane.

## Schluessel ausser Haus

`scripts/mail-recovery-bundle.sh` schickt ein verschluesseltes Paket (Backup-Passphrase,
`.env`, Keycloak-Admin-Zugang, Kurzanleitung) an den Operator. Die Passphrase dafuer
wird beim Aufruf abgefragt und nirgends gespeichert — waere sie auf diesem Host
lesbar, wuerde der Versand die Geheimnisse verschieben, ohne das Risiko zu verschieben.

```
./scripts/mail-recovery-bundle.sh --test-mail   # nur Versandweg pruefen
./scripts/mail-recovery-bundle.sh --dry-run     # bauen und verschluesseln, nicht senden
./scripts/mail-recovery-bundle.sh               # bauen, verschluesseln, senden
```

## Wird die Sicherung ueberwacht?

Ja: `scripts/backup-freshness-check.sh` laeuft per Cron um 09:42 UTC und prueft das
**Ergebnis** -- liegt im Backup-Repository ein Snapshot, der juenger als 30 Stunden und
groesser als 100 KB ist? Schlaegt das fehl, geht eine Mail an den Operator und der
Exit-Code ist 1.

Bewusst als eigener Job zu anderer Zeit: pruefte die Sicherung sich selbst, wuerde ihr
Ausfall auch die Pruefung mitnehmen. Und bewusst gegen das Ergebnis statt gegen den
Prozess -- ein Host, der aus ist, meldet keinen Fehlschlag, aber sein fehlender Snapshot
faellt auf.

## Wurde der Restore je ausprobiert?

Ja, am 2026-08-16 gegen einen echten Snapshot, in Wegwerf-Containern (ohne Risiko fuer den
laufenden Stack):

```
pg_restore in ein frisches Postgres  -> 73 Benutzer, 2 Realms, 67 Credentials
sqlite pragma integrity_check        -> ok, 32 Tunnel, 111 Kanaele
```

Das ist der Unterschied zwischen einer Sicherung und der Hoffnung auf eine: eine
Wiederherstellung, die nie gelaufen ist, ist unbewiesen. Der Test ist billig genug, um ihn
nach groesseren Schema-Aenderungen zu wiederholen.

## Was NICHT gesichert wird

Docker-Images (werden aus den Quellen neu gebaut), die Cargo-Build-Caches, und die
Zustaende der Demo-Origins (Caddy-Daten) — alles reproduzierbar. Neue Volumes mit
echtem Zustand muessen bewusst in die Liste in `backup-selfhost.sh` aufgenommen
werden; die Aufzaehlung ist absichtlich explizit statt globbend.
