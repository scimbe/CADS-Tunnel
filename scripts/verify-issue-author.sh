#!/usr/bin/env bash
# #77 SEC77a — pin the issue-author trust anchor to scimbe's STABLE GitHub account
# id, not the mutable `author.login`. GitHub allows a username to be renamed and the
# freed login reused on a different account; the account node id (which encodes the
# immutable numeric account id) cannot be recycled. The developer/central/agent
# loops MUST run this before acting on an issue — a non-zero exit means DO NOT
# PROCESS (treat as a foreign or recycled author, at most add `needs-human`).
#
#   scripts/verify-issue-author.sh <issue-number>   # exit 0 iff authored by scimbe
#   scripts/verify-issue-author.sh --selftest
set -euo pipefail

# Pinned trust anchor: scimbe's stable account node id.
# base64("04:User1279912") — numeric account id 1279912, login "scimbe".
SCIMBE_NODE_ID="MDQ6VXNlcjEyNzk5MTI="
REPO="scimbe/CADS-Tunnel"

usage() { echo "usage: ${0##*/} <issue-number> | --selftest" >&2; exit 2; }

author_ok() { [ "${1:-}" = "$SCIMBE_NODE_ID" ]; }

if [ "${1:-}" = "--selftest" ]; then
  # The pinned id passes; a different account id (e.g. a recycled "scimbe" login on
  # a NEW account, which would carry a different node id) fails; and the bare login
  # string must never be accepted in place of the id.
  author_ok "$SCIMBE_NODE_ID"      || { echo "SELFTEST FAIL: pinned id rejected" >&2; exit 1; }
  author_ok "MDQ6VXNlcjE5OTk5OTk=" && { echo "SELFTEST FAIL: foreign/recycled id accepted" >&2; exit 1; }
  author_ok "scimbe"               && { echo "SELFTEST FAIL: login string accepted as id" >&2; exit 1; }
  author_ok ""                     && { echo "SELFTEST FAIL: empty id accepted" >&2; exit 1; }
  echo "SELFTEST OK: author guard pins stable account id ($SCIMBE_NODE_ID)"
  exit 0
fi

[ $# -eq 1 ] || usage
author_id="$(gh issue view "$1" --repo "$REPO" --json author --jq '.author.id')"
if author_ok "$author_id"; then
  echo "AUTHOR OK: issue #$1 authored by the pinned scimbe account"
else
  echo "AUTHOR REJECTED: issue #$1 author id '${author_id}' != pinned scimbe account" \
       "(a login can be recycled, the account id cannot) — do not process" >&2
  exit 1
fi
