#!/usr/bin/env bash
# service/safety_check reference handler for the REVIEW role (#201 safety addenda) — the
# post-generation recipe reviewer.
#
# Input on STDIN (JSON): {"prompt": "<the user's request>", "recipe": { the assembled RecipeCard }}
# Output on STDOUT (JSON): {"ok": <bool>, "reason": "<short>"}
#
# A holistic LLM review of the FINISHED recipe (NOT a keyword blocklist): reject if it contains any
# inedible/poisonous/unsafe item, contradicts a dietary constraint stated in the request (e.g.
# "vegetarian" but contains meat), or is otherwise implausible/unsafe to eat. The crew bridge refuses
# the recipe (terminal `rejected`) on ok=false. Isolated, NO tool access. FAILS CLOSED (ok=false) on
# any LLM/parse failure — an unreviewed recipe must never be served. Requires: jq.
# Point CT_LLM_CMD at your LLM CLI (default: `claude`).
set -uo pipefail
LLM="${CT_LLM_CMD:-claude}"
IN="$(cat)"
PROMPT="$(printf '%s' "$IN" | jq -r '.prompt // ""' 2>/dev/null)"
RECIPE="$(printf '%s' "$IN" | jq -c '.recipe // {}' 2>/dev/null)"

SYS="You are a food-safety and consistency reviewer for a finished recipe. Reason holistically about the ACTUAL recipe — do not just match keywords. REJECT if: it contains any inedible, poisonous, or unsafe-to-eat item; it contradicts a dietary constraint stated in the user's request (e.g. request says vegetarian/vegan but the recipe contains meat/fish); or the combination is genuinely implausible to eat. Otherwise ACCEPT. Respond with EXACTLY one line: 'ACCEPT: <one short reason>' or 'REJECT: <one short reason>'. Nothing else."

VERDICT="$($LLM -p "User request: ${PROMPT}
Recipe to review (JSON): ${RECIPE}" --output-format text \
  --disallowedTools "Edit,Write,Bash,Read,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS" 2>/dev/null)" || VERDICT=""

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\r' '  '; }
if printf '%s' "$VERDICT" | grep -qi '^[[:space:]]*ACCEPT:'; then
  REASON="$(printf '%s' "$VERDICT" | sed -E 's/^[[:space:]]*ACCEPT:[[:space:]]*//I')"
  printf '{"ok":true,"reason":"%s"}\n' "$(json_escape "$REASON")"
else
  REASON="$(printf '%s' "$VERDICT" | sed -E 's/^[[:space:]]*REJECT:[[:space:]]*//I')"
  [ -n "$REASON" ] || REASON="the recipe could not be safety-reviewed"
  printf '{"ok":false,"reason":"%s"}\n' "$(json_escape "$REASON")"
fi
