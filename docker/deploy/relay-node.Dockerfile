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

# ct-agent comes from the verified public release asset, not from a source build:
# no Rust toolchain in this build, and the version is a build argument, so a different
# ct-agent can be swapped in without touching CADS-Tunnel code
# (`docker build --build-arg CT_AGENT_REF=vX.Y.Z ...`). The default below must equal the
# repo-root CT_AGENT_RELEASE file (a repo-wide test enforces that). This build context
# is docker/deploy, so the file itself is not readable from here.
#
# Fail closed: the binary is downloaded together with the `.sha256` file published with
# the same release; any mismatch, missing file or unknown architecture aborts the build.
# Pass CT_AGENT_SHA256=<hex> to additionally pin the expected digest out of band.
FROM debian:bookworm-slim AS fetch
ARG CT_AGENT_REF=v0.8.0
ARG CT_AGENT_SHA256=
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) asset=ct-agent-linux-x86_64 ;; \
      arm64) asset=ct-agent-linux-aarch64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/scimbe/ct-agent/releases/download/${CT_AGENT_REF}"; \
    curl --proto =https --tlsv1.2 -fsSL "$base/$asset" -o /tmp/ct-agent; \
    curl --proto =https --tlsv1.2 -fsSL "$base/$asset.sha256" -o /tmp/ct-agent.sha256; \
    want="$(cut -d" " -f1 /tmp/ct-agent.sha256)"; \
    [ "${#want}" -eq 64 ] || { echo "malformed published digest" >&2; exit 1; }; \
    if [ -n "$CT_AGENT_SHA256" ] && [ "$CT_AGENT_SHA256" != "$want" ]; then \
      echo "digest differs from CT_AGENT_SHA256" >&2; exit 1; \
    fi; \
    echo "$want  /tmp/ct-agent" | sha256sum -c -; \
    chmod 0755 /tmp/ct-agent

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /tmp/ct-agent /usr/local/bin/ct-agent
# #667: was the sole deviation from #305's non-root baseline (docker/Dockerfile) --
# ran as root with a writable rootfs despite terminating protocol bytes from
# semi-trusted relayed peers (this process's own protocol-level acceptance is
# deliberately unguarded, see the top-of-file comment). uid/gid 65532 is the
# same "nobody"-style convention #305 already established; nothing here does
# username lookups, so no /etc/passwd entry is needed. Binds only unprivileged
# tcp/4437 and needs no elevated capabilities.
USER 65532:65532
CMD ["ct-agent", "relay-node"]
