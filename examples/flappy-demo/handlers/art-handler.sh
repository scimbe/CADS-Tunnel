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
LLM="${CT_LLM_CMD:-claude}"
INPUT="$(cat)"

SYS="You art-direct a Flappy Bird clone from a free-text prompt. Output ONLY a compact JSON object, no prose, with these keys: theme (one of: day, night, sunset, retro, candy — the closest mood, a fallback), birdColor (a #rrggbb hex), birdEmoji (a single emoji that fits the prompt, or an empty string for a plain tinted bird), title (a short on-topic game title, <= 28 chars), and — IMPORTANT (#176) — a 'palette' object so you can invent a FULL custom colour scheme instead of only picking a preset: palette has exactly skyTop, skyBottom, pipe, pipeEdge, ground, groundEdge, accent, each a #rrggbb hex. Design the palette to match the prompt (e.g. 'cozy autumn forest at dusk' -> warm dusk sky gradient, amber pipes, dark-earth ground). Always include palette. Match the prompt's vibe (e.g. 'matrix' -> green #00ff41 bird, 🕶️, dark palette, a Matrix-y title). Respond with the JSON object and nothing else."

OUT="$($LLM -p "$INPUT" --output-format text \
  --disallowedTools "Edit,Write,Bash,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS" 2>/dev/null)" || OUT=""

JSON="$(printf '%s' "$OUT" | grep -o '{.*}' | head -1)"
if printf '%s' "$JSON" | grep -q '"theme"'; then
  printf '%s\n' "$JSON"
else
  printf '{"theme":"day","birdColor":"#f7d51d","birdEmoji":"","title":"My Flappy Bird"}\n'
fi
