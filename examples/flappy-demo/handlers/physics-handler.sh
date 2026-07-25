#!/usr/bin/env bash
# service/<slug> reference handler for source-2's PHYSICS role (#171/#173).
#
# Contract: the customer's free-text prompt on STDIN → ONE JSON object on STDOUT:
#   {"gravity": <int>, "flapPower": <int>, "pipeGap": <int>, "pipeSpeed": <int>}
# These are the field names `ct_common::crew::PhysicsFragment` parses (the bridge maps
# flapPower→jump, pipeGap→gap, pipeSpeed→speed). Isolated, NO tool access — pure generation.
# Point CT_LLM_CMD at your non-interactive LLM CLI (default: `claude`).
set -uo pipefail
LLM="${CT_LLM_CMD:-claude}"
INPUT="$(cat)"

SYS="You tune the PHYSICS of a Flappy Bird clone from a free-text prompt. Output ONLY a compact JSON object, no prose, with exactly these integer keys and ranges: gravity (900-2600), flapPower (280-620), pipeGap (90-200), pipeSpeed (90-260). Read the prompt's difficulty intent: 'hard/insane' -> higher gravity+speed and tighter (smaller) pipeGap; 'easy/chill' -> the reverse; 'fast/slow' adjust pipeSpeed. If the prompt implies nothing about difficulty, return balanced defaults (gravity 1800, flapPower 430, pipeGap 140, pipeSpeed 130). Respond with the JSON object and nothing else."

OUT="$($LLM -p "$INPUT" --output-format text \
  --disallowedTools "Edit,Write,Bash,WebFetch,WebSearch,Agent" \
  --append-system-prompt "$SYS" 2>/dev/null)" || OUT=""

# Extract the first {...} block; fall back to balanced defaults if the LLM misbehaves (the
# bridge fails closed on a malformed fragment, but a sane default keeps the demo resilient).
JSON="$(printf '%s' "$OUT" | grep -o '{[^}]*}' | head -1)"
if printf '%s' "$JSON" | grep -q '"gravity"'; then
  printf '%s\n' "$JSON"
else
  printf '{"gravity":1800,"flapPower":430,"pipeGap":140,"pipeSpeed":130}\n'
fi
