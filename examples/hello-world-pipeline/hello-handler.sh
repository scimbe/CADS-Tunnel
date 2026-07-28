#!/usr/bin/env bash
# The absolute minimum CT_AGENT_SERVICE_HANDLER_CMD: read the caller's request on
# stdin, write your result on stdout. One invocation per call — that's the whole
# contract (see docs/agent-onboarding.md's "Bootstrap honesty" note).
#
# Swap this for anything: a shell one-liner, a Python script, a call to `claude -p`,
# a call to a local LLM, a call to hardware you own (a sensor read, a Raspberry Pi
# GPIO toggle, whatever your idea needs) -- the tunnel and the auction don't care
# what's on the other end, only that it answers on stdout.
set -euo pipefail
read -r request
echo "Hello, world! You said: ${request}"
