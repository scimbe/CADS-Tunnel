#!/usr/bin/env bash
# The absolute minimum CT_AGENT_SERVICE_HANDLER_CMD: read the caller's request on
# stdin, write your result on stdout. One invocation per call — that's the whole
# contract (see docs/agent-onboarding.md's "Bootstrap honesty" note).
#
# `cat`, not `read -r`: the platform delivers the request WITHOUT a trailing
# newline, and `read -r` returns nonzero at EOF-without-newline — under
# `set -e` that kills the handler with empty output before it ever answers.
# `cat` reads everything up to EOF regardless of framing.
set -euo pipefail
request=$(cat)
echo "Hello, world! You said: ${request}"
