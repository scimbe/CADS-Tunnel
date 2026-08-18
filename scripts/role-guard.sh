#!/usr/bin/env bash
# #77 SEC77b — programmatic enforcement of the role trust boundary. The field roles
# (agent, central) must NOT modify the codebase; only the developer role may edit/write
# (the skills describe this, but prose is not a control — #77 gaps 1, 8).
#
# Wire this as a Claude Code **PreToolUse hook** in the LOCAL `.claude/settings.json`
# (which is machine-specific and untracked — see the note in each role SKILL.md), e.g.:
#
#   "hooks": { "PreToolUse": [ { "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
#     "hooks": [ { "type": "command", "command": "scripts/role-guard.sh" } ] } ] }
#
# The active role is signalled by the CT_ROLE env var (developer|agent|central), set at
# skill launch. The hook reads the tool call as JSON on stdin; **exit 2 = BLOCK the tool**,
# exit 0 = allow. So a field role's Edit/Write — and Bash that writes files or mutates git
# (the `> file` / `tee` / `sed -i` bypass) — is denied by a shim, not by prompt compliance.
set -euo pipefail

if [ "${1:-}" = "--selftest" ]; then
  check() { # $1=role  $2=tool-call-json  $3=expected exit (0 allow / 2 block)
    CT_ROLE="$1" bash "$0" <<<"$2" >/dev/null 2>&1 && rc=0 || rc=$?
    [ "$rc" = "$3" ] || { echo "SELFTEST FAIL: role=$1 json=$2 got=$rc want=$3" >&2; exit 1; }
  }
  check agent     '{"tool_name":"Edit","tool_input":{}}'                        2
  check agent     '{"tool_name":"Write","tool_input":{}}'                       2
  check central   '{"tool_name":"MultiEdit","tool_input":{}}'                   2
  check central   '{"tool_name":"Bash","tool_input":{"command":"echo x > f"}}'  2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"sed -i s/a/b/ f"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"git commit -m x"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"ls -la && grep x f"}}' 0
  check agent     '{"tool_name":"Read","tool_input":{}}'                        0
  # #196: interpreter one-liners / download-to-file / patch|rsync|wget are blocked for field roles.
  check agent     '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"open('\''crates/x.rs'\'','\''w'\'').write(p)\""}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"perl -e '\''open(F,\">f\");print F $x'\''"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"node -e \"require('\''fs'\'').writeFileSync('\''f'\'',x)\""}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"ruby -e \"File.write('\''f'\'',x)\""}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"php -r \"file_put_contents('\''f'\'',$x);\""}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"curl -o crates/x.rs http://h/x"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"curl --output f http://h/x"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"wget http://h/x"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"patch -p1 < d.patch"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"ls; rsync a b"}}'  2
  # #196 false-positive guards: reads that merely mention or run these tools must stay ALLOWED.
  check agent     '{"tool_name":"Bash","tool_input":{"command":"python3 scripts/analyze.py"}}' 0
  check agent     '{"tool_name":"Bash","tool_input":{"command":"node --version"}}' 0
  check agent     '{"tool_name":"Bash","tool_input":{"command":"curl -sSL http://h/x"}}' 0
  check agent     '{"tool_name":"Bash","tool_input":{"command":"grep -r \"patch\" ."}}' 0
  check agent     '{"tool_name":"Bash","tool_input":{"command":"ls node_modules && sed -e s/a/b/ f"}}' 0
  # #196: the `rm` COMMAND stays blocked, but the `--rm` flag (docker/podman) must NOT trip it.
  check agent     '{"tool_name":"Bash","tool_input":{"command":"rm crates/x.rs"}}'  2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"ls; rm f"}}'        2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"docker run --rm rust:1-slim bash -c cargo"}}' 0
  # #585: find -delete / git clean / bun|deno eval are common, non-adversarial ways to delete or
  # write files that missed every earlier pattern -- confirmed against the unfixed script first
  # (all four returned 0/allowed there).
  check agent     '{"tool_name":"Bash","tool_input":{"command":"find . -name \"*.rs\" -delete"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"git clean -fdx"}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"bun -e \"require('\''fs'\'').writeFileSync('\''f'\'',x)\""}}' 2
  check agent     '{"tool_name":"Bash","tool_input":{"command":"deno eval \"Deno.writeTextFileSync('\''f'\'',x)\""}}' 2
  # #585 false-positive guards: reads that merely use find/git/deno without deleting/writing stay allowed.
  check agent     '{"tool_name":"Bash","tool_input":{"command":"find . -name \"*.rs\""}}' 0
  check agent     '{"tool_name":"Bash","tool_input":{"command":"git status && git log -1"}}' 0
  check agent     '{"tool_name":"Bash","tool_input":{"command":"deno --version"}}' 0
  check agent     '{"tool_name":"Read","tool_input":{}}'                        0
  check developer '{"tool_name":"Edit","tool_input":{}}'                        0
  check developer '{"tool_name":"Bash","tool_input":{"command":"echo x > f"}}'  0
  check developer '{"tool_name":"Bash","tool_input":{"command":"python3 -c \"open('\''f'\'','\''w'\'')\""}}' 0
  echo "SELFTEST OK: field-role writes blocked; developer + read-only allowed"
  exit 0
fi

role="${CT_ROLE:-developer}"
# Only the field roles are restricted; developer (or an unset role) may edit.
case "$role" in
  agent | central) ;;
  *) exit 0 ;;
esac

CT_GUARD_INPUT="$(cat)" CT_ROLE="$role" python3 -c '
import os, sys, json, re
role = os.environ["CT_ROLE"]
try:
    data = json.loads(os.environ.get("CT_GUARD_INPUT") or "{}")
except Exception:
    data = {}
tool = data.get("tool_name", "")
ti = data.get("tool_input", {}) or {}

def block(msg):
    sys.stderr.write("CT_ROLE=%s: %s — field roles cannot modify the codebase (#77 SEC77b)\n" % (role, msg))
    sys.exit(2)

if tool in {"Edit", "Write", "MultiEdit", "NotebookEdit"}:
    block(tool + " denied")
if tool == "Bash":
    cmd = ti.get("command", "") or ""
    # Reject shell that writes files or mutates git — the ways Bash bypasses the Edit/Write deny.
    # A text denylist can only block what it names, so beyond shell redirection / tee / sed -i / the
    # named file + git commands we also block the general *interpreter one-liner* route (#196):
    #   - python/perl/ruby/node/php with an eval flag (-c/-e/-E/-r/--eval) run ARBITRARY code, so they
    #     can write any file with no shell `>` — the most concerning bypass (general-purpose). Gated on
    #     the eval flag so `python3 script.py`, `node --version`, etc. stay allowed.
    #   - curl writing to a file (-o/-O/--output/--remote-name); plain curl-to-stdout stays allowed.
    #   - wget / patch / rsync in COMMAND position (start, or after ; & | ( ) — so `grep "patch" f`
    #     and other read commands that merely mention the word are not falsely blocked.
    # This is defence-in-depth, not airtight (an adversary with shell metaprogramming can always find
    # another route — the trust boundary is ultimately social); it closes the easy/accidental holes.
    if re.search(
        r">>?(?![>&])|\btee\b|\bsed\b[^|]*-i|\bdd\b|\btruncate\b|\bcp\b|\bmv\b|(?<!-)\brm\b"
        r"|git\s+(add|commit|apply|checkout|restore|reset|push|rm|mv|clean)"
        r"|\bfind\b[^|]*-delete\b"
        r"|\b(python3?|perl|ruby|node|nodejs|php|bun)\b[^|]*\s-{1,2}(c|e|E|r|eval)\b"
        r"|\bdeno\b[^|]*\beval\b"
        r"|\bcurl\b[^|]*\s-{1,2}(o|O|output|remote-name)\b"
        r"|(^|[;&|(]\s*)(wget|patch|rsync)\b",
        cmd,
    ):
        block("Bash command writes files or mutates git")
sys.exit(0)
'
