# syntax=docker/dockerfile:1
# CADS Tunnel testbed image (M5.4).
#
# Multi-stage: build all node binaries in release, then ship them in a slim
# runtime. docker compose runs this one image with per-node commands
# (ct-edge / ct-client / ct-control-plane). Build context is the repo root:
#   docker build -f docker/Dockerfile -t ct-testbed .
#
# Build caching (#47): the release compile of the whole workspace + its dep tree
# (rustls, quinn, jsonwebtoken, rsa, …) is cached across rebuilds via BuildKit
# cache mounts for the cargo registry and target/ — ~16x faster on the common
# "small change, rebuild to test" case (a one-line change rebuilds in ~20s instead
# of 5-20 min). REQUIRES BuildKit/buildx: `DOCKER_BUILDKIT=1 docker build …`, or a
# docker with the buildx plugin. The LEGACY builder silently IGNORES
# `--mount=type=cache` (you'll see a "legacy builder is deprecated" warning and get
# no caching), so install the `docker-buildx` plugin if rebuilds stay cold. Cache
# mounts are not part of the built image layer, so the binaries are copied out to
# /build/bin for the runtime stage to COPY --from.
#
# ct-agent itself was extracted to its own repo (scimbe/ct-agent) and is NOT built
# here -- no self-host compose service ever ran it ("customers run their own agents,
# outbound-only"). What stayed behind in crates/agent-tools (ct-crew-bridge,
# ct-cookbook-bridge, metrics_probe, udp_echo) is still built as part of this
# workspace, same as before.
#
# #165: the builder is pinned to `-bookworm` explicitly, matching the runtime's
# `debian:bookworm-slim` glibc (2.36). The unsuffixed `rust:1-slim` tag floats to
# whatever Debian release upstream currently ships — it moved to trixie (glibc 2.41)
# partway through this project, silently producing runtime-broken binaries (a fresh
# `GLIBC_2.39' not found crash) for every build until this pin. If the runtime stage
# below is ever bumped to a newer Debian release, bump this tag's `-bookworm` suffix
# to match in the same change — the two stages' glibc must never drift apart again.

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --workspace --bins \
    && mkdir -p /build/bin \
    && cp target/release/ct-edge target/release/ct-client \
          target/release/ct-control-plane target/release/cp_selftest \
          target/release/metrics_probe target/release/udp_echo \
          target/release/quic_echo target/release/direct_bench \
          target/release/ct-crew-bridge target/release/ct-cookbook-bridge /build/bin/

FROM debian:bookworm-slim AS runtime
# iproute2 for tc/netem inside the node containers; ca-certificates is harmless.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/bin/ct-edge /usr/local/bin/ct-edge
COPY --from=builder /build/bin/ct-client /usr/local/bin/ct-client
COPY --from=builder /build/bin/ct-control-plane /usr/local/bin/ct-control-plane
COPY --from=builder /build/bin/cp_selftest /usr/local/bin/cp_selftest
COPY --from=builder /build/bin/metrics_probe /usr/local/bin/metrics_probe
COPY --from=builder /build/bin/udp_echo /usr/local/bin/udp_echo
COPY --from=builder /build/bin/quic_echo /usr/local/bin/quic_echo
COPY --from=builder /build/bin/direct_bench /usr/local/bin/direct_bench
# #173 flappy-demo crew: the HTTP bridge the demo's Caddy origin reverse-proxies /crew/build to.
COPY --from=builder /build/bin/ct-crew-bridge /usr/local/bin/ct-crew-bridge
# #201 cookbook-demo crew: the HTTP bridge for /cookbook/build.
COPY --from=builder /build/bin/ct-cookbook-bridge /usr/local/bin/ct-cookbook-bridge
COPY docker/netem-entrypoint.sh /usr/local/bin/netem-entrypoint.sh
RUN chmod +x /usr/local/bin/netem-entrypoint.sh
# #305: run as non-root by default -- matches the k8s base's runAsNonRoot/
# runAsUser 65532 posture (docker/deploy/k8s/*.yaml), which this compose-based
# self-host image previously fell short of despite sharing the same binaries.
# An RCE in ct-edge/ct-control-plane (e.g. via an unauthenticated endpoint, #87)
# no longer lands as root in the container. uid/gid 65532 is the same
# "nobody"-style convention distroless/k8s use; no /etc/passwd entry is needed
# since nothing here does username lookups.
#
# Testbed-only tooling (iproute2/iptables, installed above for tc/netem in
# hermetic multi-node network-emulation tests, #315) still needs root/
# NET_ADMIN to actually configure netfilter -- netem-entrypoint.sh already
# tolerates that gracefully (`tc ... || echo "... failed (need NET_ADMIN)"`)
# for the (test-only) compose overlays that invoke it; production self-host
# never does. A test topology that genuinely needs netem to apply (not just
# degrade gracefully) can override with `user: root` / `cap_add: [NET_ADMIN]`
# on that specific service -- this default only changes the default, not what's
# possible to opt back into for testing.
RUN groupadd -g 65532 ctuser && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin ctuser
USER 65532:65532
CMD ["ct-edge"]
