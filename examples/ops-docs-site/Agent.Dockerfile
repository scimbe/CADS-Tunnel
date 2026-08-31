# ops-agent's ct-agent binary, built from the standalone scimbe/ct-agent repo --
# same pattern as examples/help-site/Agent.Dockerfile (clone/build the real
# customer-facing artifact, not workspace source).

FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# Bump deliberately when a new ct-agent release ships -- this site isn't scanned
# by the repo-root CT_AGENT_RELEASE pin test (that test's scope is help-site and
# the install docs), so track the latest security-hardening release by hand.
ARG CT_AGENT_REF=v0.7.13
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
