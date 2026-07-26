#!/usr/bin/env bash
# service/text_generation reference handler for sink's PRESENTATION role (#201 cookbook).
#
# Input on STDIN (JSON): {"prompt": "<text>", "structure": { the IngredientsFragment from source-2 }}
# Output on STDOUT (JSON): the ct_common::cookbook::RecipeFragment shape —
#   {"dishName":"<str>","theme":"<str>","garnish":"<str>","moodDescription":"<str>"}
#
# Names / themes / plates the ACTUAL recipe (so it takes source-2's structured output as context).
# Isolated, NO tool access — pure generation. Requires: jq. Point CT_LLM_CMD at your LLM CLI
# (default: `claude`). Falls back to a sensible default if the LLM misbehaves.
set -uo pipefail

# #204: extract the JSON object from the LLM output, FLATTENING newlines first (`tr -d '\n'`) so the
# match spans a pretty-printed / ```json-fenced multi-line response. `grep` is line-oriented, so
# without the flatten a multi-line object (the LLM emits one ~1 in 3 calls) matched NOTHING on every
# line and the handler silently fell through to its fallback — the "ask for eggs, get plain pasta" bug.
extract_json_object() { tr -d '\n' | grep -o '{.*}' | head -1; }

if [ "${1:-}" = "--selftest" ]; then
  sample='```json
{
  "k": ["eggs", "spinach"],
  "n": 2
}
```'
  got="$(printf '%s' "$sample" | extract_json_object)"
  [ -n "$got" ] || { echo "SELFTEST FAIL (#204): multi-line/fenced JSON yielded an EMPTY match" >&2; exit 1; }
  printf '%s' "$got" | python3 -c 'import sys,json; json.loads(sys.stdin.read())' 2>/dev/null \
    || { echo "SELFTEST FAIL (#204): extracted text is not valid JSON" >&2; exit 1; }
  echo "SELFTEST OK (#204): multi-line/fenced JSON extraction recovers a valid object"
  exit 0
fi
LLM="${CT_LLM_CMD:-claude}"
IN="$(cat)"
PROMPT="$(printf '%s' "$IN" | jq -r '.prompt // ""' 2>/dev/null)"
STRUCTURE="$(printf '%s' "$IN" | jq -c '.structure // {}' 2>/dev/null)"
RLANG="$(printf '%s' "$IN" | jq -r '.lang // "en"' 2>/dev/null)"   # #201 i18n: output language

SYS="You are the recipe-presentation agent. Given the user's request and the structured recipe (ingredients + steps) as JSON context, output ONLY a compact JSON object, no prose, with EXACTLY: dishName (a short, appetising on-topic name, <= 40 chars), theme (one word mood, e.g. rustic/fresh/cozy/elegant), garnish (a short finishing touch), moodDescription (one short sentence about the vibe). Match the actual recipe. Respond with the JSON object and nothing else."

OUT="$($LLM -p "Request: ${PROMPT}
Recipe (JSON): ${STRUCTURE}" --output-format text \
  --disallowedTools "Edit,Write,Bash,Read,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS Write the dishName, garnish and moodDescription in this language: $RLANG (theme stays a single English mood word). Only values are translated, not the JSON keys." 2>/dev/null)" || OUT=""

JSON="$(printf '%s' "$OUT" | extract_json_object)"
if printf '%s' "$JSON" | grep -q '"dishName"'; then
  printf '%s\n' "$JSON"
else
  printf '{"dishName":"House Special","theme":"rustic","garnish":"a sprig of fresh herbs","moodDescription":"a simple, comforting plate."}\n'
fi
