#!/usr/bin/env bash
# Shared between backup-verify.sh and restore-selfhost.sh: the single source of
# truth for which snapshot members a restore actually needs.
#
# Before this, backup-verify.sh's own mandatory list (keycloak.pgdump,
# control-plane.db, MANIFEST.json) and restore-selfhost.sh's hard requirements
# (those plus deploy.env and certs.tar.gz) had silently drifted apart -- verify
# could declare a snapshot "wiederherstellbar" that restore would then refuse
# outright for a member verify never even looked for. Sourcing this one array
# from both scripts means a new mandatory artefact only ever needs adding here.
CADS_BACKUP_REQUIRED_MEMBERS=(
  keycloak.pgdump
  control-plane.db
  MANIFEST.json
  deploy.env
  certs.tar.gz
)
