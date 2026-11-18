#!/bin/sh
# Apply tc netem link impairment to eth0 (egress) if configured, then exec the
# node binary. Configured via CT_NETEM_DELAY / CT_NETEM_LOSS / CT_NETEM_RATE
# (e.g. "30ms", "1%", "10mbit"). Requires NET_ADMIN.
set -e

if [ -n "${CT_NETEM_DELAY}${CT_NETEM_LOSS}${CT_NETEM_RATE}" ]; then
    ARGS=""
    [ -n "${CT_NETEM_DELAY}" ] && ARGS="${ARGS} delay ${CT_NETEM_DELAY}"
    [ -n "${CT_NETEM_LOSS}" ] && ARGS="${ARGS} loss ${CT_NETEM_LOSS}"
    [ -n "${CT_NETEM_RATE}" ] && ARGS="${ARGS} rate ${CT_NETEM_RATE}"
    echo "netem: applying${ARGS} on eth0"
    # #963: impairment was explicitly requested -- a benchmark run recorded
    # with these labels must actually BE impaired, or the measured numbers
    # are silently wrong. Fail loudly (set -e) instead of starting the node
    # unimpaired with no non-zero exit anywhere to catch it.
    tc qdisc add dev eth0 root netem ${ARGS}
fi

exec "$@"
