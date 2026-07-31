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
ARG CT_AGENT_REF=3f60db3
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
