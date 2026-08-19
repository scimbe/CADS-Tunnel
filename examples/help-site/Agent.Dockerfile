# help-agent's ct-agent binary, built from the standalone scimbe/ct-agent repo
# (extracted from this monorepo -- see docs/adr for the extraction rationale) rather
# than from workspace source. This is deliberately closer to how a real customer
# installs ct-agent: clone/build (or, once a tagged release exists, just download a
# prebuilt binary) from that repo directly, not from CADS-Tunnel's own build.

FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Which ct-agent tag/branch/commit to build -- bump deliberately. The default MUST
# match the repo-root `CT_AGENT_RELEASE` file (#512, the one pin source; a portal
# test asserts this file agrees with it), so a release bump updates both together.
ARG CT_AGENT_REF=v0.5.8
RUN git clone https://github.com/scimbe/ct-agent.git /build && cd /build && git checkout "${CT_AGENT_REF}"
WORKDIR /build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked \
    && cp target/release/ct-agent /tmp/ct-agent \
    && cp target/release/ct-agent-supervisor /tmp/ct-agent-supervisor

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/ct-agent /usr/local/bin/ct-agent
# `cargo build` already produced this beside ct-agent; until now it was compiled on every
# image build and discarded (#331). Shipping it makes "run the agent under a supervisor that
# reports WHY it exited" a one-word change to the command below, instead of a rebuild.
# The default stays the bare agent: this adds a capability, it does not switch one on.
COPY --from=builder /tmp/ct-agent-supervisor /usr/local/bin/ct-agent-supervisor
CMD ["ct-agent"]
