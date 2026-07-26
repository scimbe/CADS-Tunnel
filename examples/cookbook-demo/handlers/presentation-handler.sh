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
LLM="${CT_LLM_CMD:-claude}"
IN="$(cat)"
PROMPT="$(printf '%s' "$IN" | jq -r '.prompt // ""' 2>/dev/null)"
STRUCTURE="$(printf '%s' "$IN" | jq -c '.structure // {}' 2>/dev/null)"

SYS="You are the recipe-presentation agent. Given the user's request and the structured recipe (ingredients + steps) as JSON context, output ONLY a compact JSON object, no prose, with EXACTLY: dishName (a short, appetising on-topic name, <= 40 chars), theme (one word mood, e.g. rustic/fresh/cozy/elegant), garnish (a short finishing touch), moodDescription (one short sentence about the vibe). Match the actual recipe. Respond with the JSON object and nothing else."

OUT="$($LLM -p "Request: ${PROMPT}
Recipe (JSON): ${STRUCTURE}" --output-format text \
  --disallowedTools "Edit,Write,Bash,Read,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS" 2>/dev/null)" || OUT=""

JSON="$(printf '%s' "$OUT" | grep -o '{.*}' | head -1)"
if printf '%s' "$JSON" | grep -q '"dishName"'; then
  printf '%s\n' "$JSON"
else
  printf '{"dishName":"House Special","theme":"rustic","garnish":"a sprig of fresh herbs","moodDescription":"a simple, comforting plate."}\n'
fi
