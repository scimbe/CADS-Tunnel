#!/usr/bin/env bash
# service/text_generation reference handler for source-2's STRUCTURE role (#201 cookbook).
#
# Input on STDIN (JSON): {"prompt": "<text>", "image": "<base64 or null>"}
# Output on STDOUT (JSON): the ct_common::cookbook::IngredientsFragment shape —
#   {"ingredients":[...],"steps":[...],"cookTime":"<str>","difficulty":"<easy|medium|hard>","allergens":[...]}
#
# The photo bytes travel over the Agent-Fabric channel and arrive here as base64; this handler decodes
# them to a LOCAL temp file ON THIS BOX and references that path in `claude -p` (which reads an image
# when its local path is mentioned). Per #201's error-handling addendum, if NO ingredients can be
# recognized this returns a safe FALLBACK dish, never a hard failure. Requires: jq, base64.
# Point CT_LLM_CMD at your LLM CLI (default: `claude`).
set -uo pipefail
LLM="${CT_LLM_CMD:-claude}"
IN="$(cat)"
PROMPT="$(printf '%s' "$IN" | jq -r '.prompt // ""' 2>/dev/null)"
IMG_B64="$(printf '%s' "$IN" | jq -r '.image // empty' 2>/dev/null)"
RLANG="$(printf '%s' "$IN" | jq -r '.lang // "en"' 2>/dev/null)"   # #201 i18n: output language

IMG_NOTE=""
IMG_FILE=""
if [ -n "$IMG_B64" ]; then
  IMG_FILE="$(mktemp "${TMPDIR:-/tmp}/cookbook-XXXXXX.img")"
  if printf '%s' "$IMG_B64" | base64 -d > "$IMG_FILE" 2>/dev/null && [ -s "$IMG_FILE" ]; then
    IMG_NOTE="A photo of the available ingredients is saved locally at: $IMG_FILE — look at it and identify what's actually there. "
  else
    rm -f "$IMG_FILE"; IMG_FILE=""
  fi
fi

SYS="You are the recipe-structure agent. From the user's text and (if given) the ingredient photo, output ONLY a compact JSON object, no prose, with EXACTLY these keys: ingredients (array of strings), steps (array of strings, in order), cookTime (a string like '30 minutes'), difficulty (one of: easy, medium, hard), allergens (array of strings; [] if none). Base it on the ingredients you can actually see/read. If you genuinely cannot identify any ingredients at all, DO NOT fail — return a simple, safe fallback dish built from common pantry staples and say so in the first step. Never include inedible or unsafe items. Respond with the JSON object and nothing else."

# Read is allowed here (the image); write/exec/network tools are not.
OUT="$($LLM -p "${IMG_NOTE}${PROMPT}" --output-format text \
  --disallowedTools "Edit,Write,Bash,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS Write ALL output text (ingredient names, steps, etc.) in this language: $RLANG. The JSON keys stay in English; only the values are translated." 2>/dev/null)" || OUT=""
[ -n "$IMG_FILE" ] && rm -f "$IMG_FILE"

JSON="$(printf '%s' "$OUT" | grep -o '{.*}' | head -1)"
if printf '%s' "$JSON" | grep -q '"ingredients"'; then
  printf '%s\n' "$JSON"
else
  # FALLBACK (#201 error-handling): the LLM failed or recognized nothing — a safe pantry default,
  # not an error, so the customer still gets a usable recipe.
  printf '{"ingredients":["pasta","olive oil","garlic","salt"],"steps":["We could not read specific ingredients, so here is a reliable pantry dish.","Boil the pasta until al dente","Warm the olive oil with sliced garlic, toss and season"],"cookTime":"15 minutes","difficulty":"easy","allergens":["gluten"]}\n'
fi
