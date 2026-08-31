# ops-agent's ct-agent binary, built from the standalone scimbe/ct-agent repo --
# same pattern as examples/help-site/Agent.Dockerfile (clone/build the real
# customer-facing artifact, not workspace source).

FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Must match the repo-root CT_AGENT_RELEASE file (#502/#512) -- a repo-wide test
# (every_ct_agent_pin_matches_the_release) scans every Agent.Dockerfile, not just
# help-site's, and fails the gate if any of them disagree. Bump this file only
# together with CT_AGENT_RELEASE and every other pin, never on its own.
ARG CT_AGENT_REF=v0.6.9
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
