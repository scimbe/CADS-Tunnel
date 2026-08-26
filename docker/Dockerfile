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
# The native ct-agent binary itself was extracted to its own repo (scimbe/ct-agent) and is
# NOT built here -- no self-host compose service ever ran it ("customers run their own
# agents, outbound-only"). What stayed behind in crates/agent-tools (metrics_probe, udp_echo)
# is still built as part of this workspace, same as before. ct-crew-bridge/
# ct-cookbook-bridge were removed in #232: both demos migrated to their own thin
# Node.js bridges weeks before this image's side of the cleanup landed.
#
# ct-agent-WASM is a narrow exception to the above (see the `wasm-builder` stage below): the
# BROWSER build of scimbe/ct-agent's shared crypto core, embedded into ct-control-plane so the
# portal's self-service channel-claim page can generate a real holder/Noise identity and sign
# its join attestation entirely client-side -- no ct-agent CLI install needed for that one
# step. This does not change the "customers run their own agent" model above; it only moves
# ONE onboarding step (identity generation + attestation signing) into the browser.
#
# #165: the builder is pinned to `-bookworm` explicitly, matching the runtime's
# `debian:bookworm-slim` glibc (2.36). The unsuffixed `rust:1-slim` tag floats to
# whatever Debian release upstream currently ships — it moved to trixie (glibc 2.41)
# partway through this project, silently producing runtime-broken binaries (a fresh
# `GLIBC_2.39' not found crash) for every build until this pin. If the runtime stage
# below is ever bumped to a newer Debian release, bump this tag's `-bookworm` suffix
# to match in the same change — the two stages' glibc must never drift apart again.

# ct-agent-wasm build stage: the compiled `ct-agent-wasm` bundle (in-browser Agent-Fabric
# channel identity generation + attestation signing) the portal's self-service channel-claim
# page (`GET /portal/channels/:channel/claim`, `claim_html` in
# crates/control-plane/src/portal_api.rs) loads client-side and the control plane serves back
# out at `GET /portal/static/ct_agent_wasm{.js,_bg.wasm}` -- built from a pinned
# scimbe/ct-agent commit's own wasm/ workspace member via `wasm-bindgen --target web`. Same
# recipe as scripts/build-ct-agent-wasm.sh (used for a manual/local rebuild outside Docker);
# duplicated here rather than shelled out to, since a nested `docker run` doesn't work inside
# a Docker build -- this way a plain `docker build` produces a fully self-contained image with
# no separate pre-build step required. A SEPARATE stage (not folded into `builder` below) so
# BuildKit can build it in parallel and cache it independently of the much-larger native
# workspace compile. Bump CT_AGENT_REF here AND in scripts/build-ct-agent-wasm.sh together.
FROM rust:1-slim-bookworm AS wasm-builder
ARG CT_AGENT_REF=v0.6.9
RUN apt-get update -qq && apt-get install -y -qq git && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install wasm-bindgen-cli --version 0.2.126
RUN git clone https://github.com/scimbe/ct-agent /agent-src \
    && git -C /agent-src checkout "$CT_AGENT_REF"
WORKDIR /agent-src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/agent-src/target \
    cargo build -p ct-agent-wasm --release --target wasm32-unknown-unknown \
    && mkdir -p /out \
    && wasm-bindgen --target web --out-dir /out target/wasm32-unknown-unknown/release/ct_agent_wasm.wasm

FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY . .
COPY --from=wasm-builder /out/ct_agent_wasm.js crates/control-plane/wasm-pkg/ct_agent_wasm.js
COPY --from=wasm-builder /out/ct_agent_wasm_bg.wasm crates/control-plane/wasm-pkg/ct_agent_wasm_bg.wasm
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --workspace --bins \
    && mkdir -p /build/bin \
    && cp target/release/ct-edge target/release/ct-client \
          target/release/ct-control-plane target/release/cp_selftest \
          target/release/metrics_probe target/release/udp_echo \
          target/release/quic_echo target/release/direct_bench \
          target/release/masque-proxy /build/bin/

# Shared non-root setup both runtime stages below apply identically -- kept as one
# place so the uid/gid convention (#305) can never drift between them.
FROM debian:bookworm-slim AS runtime-base
RUN groupadd -g 65532 ctuser && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin ctuser
COPY --from=builder /build/bin/ct-edge /usr/local/bin/ct-edge
COPY --from=builder /build/bin/ct-client /usr/local/bin/ct-client
COPY --from=builder /build/bin/ct-control-plane /usr/local/bin/ct-control-plane
COPY --from=builder /build/bin/cp_selftest /usr/local/bin/cp_selftest
COPY --from=builder /build/bin/metrics_probe /usr/local/bin/metrics_probe
COPY --from=builder /build/bin/udp_echo /usr/local/bin/udp_echo
COPY --from=builder /build/bin/quic_echo /usr/local/bin/quic_echo
COPY --from=builder /build/bin/direct_bench /usr/local/bin/direct_bench
COPY --from=builder /build/bin/masque-proxy /usr/local/bin/masque-proxy

# #315: the real production/self-host image -- ca-certificates + curl only, no
# iproute2/iptables. Not the default target (see `runtime` below, which stays the
# default so every existing testbed compose file keeps working unchanged) --
# `docker/deploy/compose.selfhost.yml` opts into this explicitly via `target:
# production`. #305's non-root posture applies equally here.
#
# #376: ct-edge/ct-control-plane run with NO signal handler at all (grep-confirmed
# -- no tokio::signal anywhere in either crate) and, until now, no init process
# either -- as PID 1, an unhandled SIGTERM is a no-op on Linux, so every real
# k8s rollout/compose restart/node-drain ran the process undisturbed until the
# grace period expired and SIGKILL hard-killed it: in-flight tunnels and any
# unflushed writes ended abruptly, and a generous grace period bought nothing
# without something to actually forward/act on the signal. `tini` as a real
# init (PID 1 itself) fixes the *delivery* half: SIGTERM now reaches the real
# process promptly instead of being silently dropped, and `tini` also reaps
# zombies correctly (irrelevant today with one process per container, but the
# textbook reason an init belongs at PID 1 regardless). `STOPSIGNAL SIGTERM`
# is Docker's own default already -- set explicitly so it's not accidental.
# The other real half -- an actual `tokio::signal` handler with a bounded,
# correct graceful-drain path in ct-edge/ct-control-plane's own application
# logic -- is real, separate, larger work on a live production service's
# shutdown behavior, deliberately not attempted in this same change (#376
# tracks it as a distinct, explicitly-scoped follow-up).
FROM runtime-base AS production
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini bash openssl \
    && rm -rf /var/lib/apt/lists/*
# ADR-0025 Decision 4 (multi-domain onboarding, `crates/control-plane/src/
# cert_issuer.rs`): `POST /admin-ui/domains/:zone/hostnames` shells out to this
# SAME script (bash + openssl are installed above for exactly this -- acme.sh's
# own installer/issuance both need them). `bash`, not just `sh`, because
# `lib-acme.sh` uses bash-array syntax (`local server_flag=(...)`) internally.
COPY scripts/lib-acme.sh /app/scripts/lib-acme.sh
# `CT_CP_ACME_HOME` (default `/data/acme`, `service.rs`) must be writable by
# this image's non-root uid 65532 for acme.sh to install itself + keep its
# account state there -- `/data` is already the control-plane's own named
# volume (see compose.selfhost.yml's `cpdata:/data`), so this directory
# persists across restarts the same way the rest of its durable state does.
RUN mkdir -p /data/acme && chown 65532:65532 /data/acme
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["ct-edge"]

# The default target (must stay LAST in this file -- `docker build`/`docker compose
# build` with no `--target`/`target:` picks whichever stage is textually last).
# Every existing testbed/netem compose file (docker-compose.baseline.yml,
# docker-compose.tcp.yml, docker-compose.yml) builds without specifying a target and
# genuinely needs `tc`/`iptables` for network-emulation tests -- this stage is
# unchanged from before #315 so none of them need to change.
FROM runtime-base AS runtime
# iproute2 for tc/netem inside the node containers; ca-certificates is harmless.
# tini (#376, see the `production` target above for the full reasoning) -- every
# real testbed/netem compose service using this target already overrides
# `entrypoint:` with `netem-entrypoint.sh`, so this only matters if the image is
# ever run directly without that override; kept consistent with `production`
# regardless, matching this Dockerfile's own "shared setup stays one place"
# convention (see `runtime-base`'s own comment).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*
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
# never does (it now uses the `production` target above, which never ships these
# binaries at all -- #315). A test topology that genuinely needs netem to apply
# (not just degrade gracefully) can override with `user: root` /
# `cap_add: [NET_ADMIN]` on that specific service -- this default only changes the
# default, not what's possible to opt back into for testing.
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["ct-edge"]
