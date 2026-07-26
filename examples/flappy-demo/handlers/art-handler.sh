#!/usr/bin/env bash
# service/<slug> reference handler for sink's ART role (#171/#173).
#
# Contract: the customer's free-text prompt on STDIN → ONE JSON object on STDOUT:
#   {"theme": "<day|night|sunset|retro|candy>", "birdColor": "#rrggbb",
#    "birdEmoji": "<emoji or empty>", "title": "<short>"}
# These are the field names `ct_common::crew::ArtFragment` parses. birdEmoji may be ANY emoji
# (the studio's bird accepts arbitrary emoji since #169) or "" for the classic tinted bird.
# Isolated, NO tool access — pure generation. Point CT_LLM_CMD at your LLM CLI (default: `claude`).
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
INPUT="$(cat)"

SYS="You art-direct a Flappy Bird clone from a free-text prompt. Output ONLY a compact JSON object, no prose, with these keys: theme (one of: day, night, sunset, retro, candy — the closest mood, a fallback), birdColor (a #rrggbb hex), birdEmoji (a single emoji that fits the prompt, or an empty string for a plain tinted bird), title (a short on-topic game title, <= 28 chars), and — IMPORTANT (#176) — a 'palette' object so you can invent a FULL custom colour scheme instead of only picking a preset: palette has exactly skyTop, skyBottom, pipe, pipeEdge, ground, groundEdge, accent, each a #rrggbb hex. Design the palette to match the prompt (e.g. 'cozy autumn forest at dusk' -> warm dusk sky gradient, amber pipes, dark-earth ground). Always include palette. Optionally (#177) also include 'pipeEmoji': a SINGLE emoji used as the obstacle shape when it fits the theme (🌲 forest, 🌵 desert, 🧊 ice, 🏭 industrial), or omit it for classic pipes. Optionally (#178) also include 'bgEffect': an animated background named 'matrix-rain' (falling green glyphs), 'snow', or 'stars' when it fits the prompt (e.g. 'matrix' -> matrix-rain), or omit it for a static sky. Match the prompt's vibe (e.g. 'matrix' -> green #00ff41 bird, 🕶️, dark palette, matrix-rain background, a Matrix-y title). Respond with the JSON object and nothing else."

OUT="$($LLM -p "$INPUT" --output-format text \
  --disallowedTools "Edit,Write,Bash,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS" 2>/dev/null)" || OUT=""

JSON="$(printf '%s' "$OUT" | extract_json_object)"
if printf '%s' "$JSON" | grep -q '"theme"'; then
  printf '%s\n' "$JSON"
else
  printf '{"theme":"day","birdColor":"#f7d51d","birdEmoji":"","title":"My Flappy Bird"}\n'
fi
