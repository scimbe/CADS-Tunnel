# help-agent's ct-agent binary, built from the standalone scimbe/ct-agent repo
# (extracted from this monorepo -- see docs/adr for the extraction rationale) rather
# than from workspace source. This is deliberately closer to how a real customer
# installs ct-agent: clone/build (or, once a tagged release exists, just download a
# prebuilt binary) from that repo directly, not from CADS-Tunnel's own build.

FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Which ct-agent tag/branch/commit to build -- bump deliberately. No tagged release
# exists yet (see crates/agent-tools/Cargo.toml's comment), so this defaults to a
# pinned commit; switch to a `vX.Y.Z` tag once one exists.
ARG CT_AGENT_REF=56a1db44ee93c07ae8763bad4243ecd1611ce6c3
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
CMD ["ct-agent"]
