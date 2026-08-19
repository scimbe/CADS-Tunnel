# The internal-only Circuit-Relay v2 + DCUtR relay-node (#136/#134): built from the
# standalone scimbe/ct-agent repo (same pattern as examples/help-site/Agent.Dockerfile),
# not from CADS-Tunnel's own workspace source -- ct-agent is a separate project.
#
# This process's own protocol-level acceptance is deliberately unguarded (see
# ct_agent::p2p::nat_lab_relay's doc comment) -- the edge's :443 relay-gate leg
# (crates/edge/src/relay_gate.rs) is what gates every connection with grant + possession
# BEFORE ever splicing a byte here. This container must NEVER be given a published port;
# it is reachable only from the edge, over the internal-only `relay_internal` network
# (see compose.relay.yml). CT_RELAY_NODE_KEY gives it a stable identity across restarts
# (SwarmBuilder::with_new_identity() would otherwise mint a fresh PeerId every boot,
# breaking every client's pinned CT_EDGE_RELAY_NODE_PEER).

FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Pin to the commit that added the missing Protocol::P2pCircuit to the relay-gate's
# circuit address (found while E2E-verifying this very relay-node) -- bump deliberately.
#
# 2026-08-02 (#248): bumped to 72394eb -- ct-agent main's current tip as of this bump,
# which carries every #248 fix landed since the d264869 event-logging fix (this relay
# node's own logging gap), including the real DCUtR-candidate-pool fix
# (ecf7460/aad49fb), the widened one-shot upgrade grace window (d443d64), the SSRF
# guard on nat-lab's observed_addr (e366210), the ct-agent-supervisor crash-reason
# reporting (b7f6f2a), and #276's "prefer direct over relay" behavior (f2506b1) -- the
# explicit design guidance that a relay/super-peer path should always try direct
# communication first and treat relay as the last line of defense. Keeping this
# container current with that same line of fixes matters because it IS the last line
# of defense CT_CHANNEL_RELAY falls back to.
#
# 2026-08-19: bumped to the v0.5.5 tag (4d6f781) -- this pin had drifted over 100
# commits behind main, predating the whole v0.4.11 -> v0.5.5 line (module splits,
# the v0.4.13-0.5.0 channel-protocol hardening series, #24's DCUtR loops now obeying
# the admission retry policy, #40's TLS-handshake-EOF backoff, #36's secret-file
# permission hardening + hex-decode panic fix, and the h2 RUSTSEC-2026-0258 bump).
# Using the tag (not another bare commit) from here on: it's a real, CI-gated,
# version-checked release (ct-agent#29's guard) with published binaries, not just a
# convenient main-branch snapshot.
ARG CT_AGENT_REF=v0.5.5
RUN git clone https://github.com/scimbe/ct-agent.git /build && cd /build && git checkout "${CT_AGENT_REF}"
WORKDIR /build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked \
    && cp target/release/ct-agent /tmp/ct-agent

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/ct-agent /usr/local/bin/ct-agent
CMD ["ct-agent", "relay-node"]
