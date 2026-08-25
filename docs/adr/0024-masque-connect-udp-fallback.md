# ADR-0024 — MASQUE/CONNECT-UDP (RFC 9298) as a third transport rung for UDP-blocked networks

## Status
Proposed; **M1 (feasibility spike) and M2 (proxy backend + edge registration)
complete**, 2026-08-25 — see their own sections below. Builds on ADR-0004 (QUIC
data-plane transport with TCP fallback), ADR-0010 (Mesh-Plane-first / Browser-Plane
SNI), ADR-0019 (unified :443 gateway). Tracked by ct-agent#81 (design-tracking
issue, recon already done there) and this ADR's own decomposition below. Operator
green-lit real design + implementation work 2026-08-25.

## Context
ADR-0004 already anticipates UDP-blocked networks and falls back to a TCP-framed
transport when QUIC/UDP dialing fails. That fallback works, but it is *not* QUIC: no
connection migration (RFC 9000), and — live-diagnosed tonight on
`kali.bunsenbrenner.org` (CADS-kali-desktop#1) — measurably more fragile under active
interactive load in a hostile-NAT/restrictive-network environment than QUIC's own
loss/migration handling would be. The agent in that environment cannot dial UDP at all
(confirmed: DPI-level UDP block, not just a slow path), so today it has exactly one
transport once QUIC fails: the raw-TCP framed fallback.

RFC 9298 (MASQUE / CONNECT-UDP) lets a client reach a proxy over a connection the
network *does* allow, and tunnel arbitrary UDP datagrams through it — including a real
QUIC connection, restoring connection migration and QUIC's loss-recovery properties
even though the network still never sees raw UDP. Production-proven at scale
(Cloudflare WARP, iCloud Private Relay, MS Edge Secure Network).

**The crucial constraint this design must get right**: those production deployments
mostly run CONNECT-UDP over **HTTP/3** (itself QUIC/UDP), because their clients *can*
reach the proxy over UDP and want perf, not because HTTP/3 is required by RFC 9298. Our
actual failure case is the opposite — the client's network blocks UDP outright, so an
HTTP/3-native MASQUE proxy is exactly as unreachable as raw QUIC. RFC 9298's CONNECT-UDP
method is built on Extended CONNECT (RFC 9220), which **is also defined for HTTP/2**
(over ordinary TCP/TLS/443) — the same port and transport already open in this
environment. **This project only solves the stated problem if the MASQUE tunnel itself
runs over HTTP/2-over-TCP/443, not HTTP/3.** Getting this backwards produces a feature
that cannot help the one environment it was built for.

Recon (ct-agent#81, no code changes yet): nothing exists in either repo today —
`grep` across both `Cargo.lock` trees for `h3`/`masque`/`webtransport`/`quiche` returns
nothing; both repos use bare `quinn 0.11` with custom framing, no HTTP layer at all.
`native/src/ladder.rs` models exactly two rung kinds (`EdgeRung::Quic`/`EdgeRung::TlsTcp`).
Whether the Rust ecosystem's HTTP/2 stack (`h2`) has usable Extended CONNECT / RFC 9298
Capsule Protocol support today is **unverified** — this is a real technical risk, not
an implementation detail, and must be spiked before the rest of this plan is trusted.

## Decision
1. **Transport for the MASQUE tunnel itself: HTTP/2 CONNECT-UDP over TCP/443**, not
   HTTP/3. The proxy endpoint is reachable exactly where the existing TLS-TCP fallback
   already is (same port, same TLS posture) — MASQUE adds a *third* rung, it does not
   replace the existing TCP/443 reachability story.
2. **Proxy component: a new local backend the edge fronts, same shape as Portal —
   not new edge-binary code, and not a new public deploy unit.** (Revised 2026-08-25,
   during M2 groundwork: reading `crates/edge/src/serve.rs`'s existing
   `FrontDoorRoute::Proxy(host)` arm showed it's *already* exactly "TLS-terminate,
   then `copy_bidirectional` raw bytes to a plaintext upstream" — the identical
   pattern the Portal (`CT_EDGE_PORTAL_HOST`/`CT_CP_PROXY_ADDR`) and Auth IdP
   (`CT_EDGE_AUTH_HOST`/`CT_EDGE_AUTH_ADDR`) already use. Portal itself is not part
   of the edge binary; it's the control-plane process, fronted by the edge's
   existing terminate-and-forward logic.) The CONNECT-UDP handler is a **new local
   process** (own crate, own binary) that speaks h2 + the Capsule Protocol on a
   plain TCP port, registered into the SAME `proxies` map via a third
   `CT_EDGE_MASQUE_HOST`/`CT_EDGE_MASQUE_ADDR` pair, mirroring the Portal/Auth-IdP
   registration block in `serve.rs` verbatim. This needed **zero changes** to the
   front-door SNI/ALPN classification hot path (`sni.rs::classify_front_door`) or
   the dispatch match in `serve.rs` — MASQUE traffic is indistinguishable, at the
   TLS-termination layer, from Portal traffic; the two are told apart only by which
   hostname/cert the agent's ClientHello names, exactly like Portal vs. Auth IdP are
   today.
3. **Client side (ct-agent): a new `EdgeRung::Masque(SocketAddr)` ladder variant**,
   tried between `Quic` and `TlsTcp` — attempt real QUIC first (fastest, works whenever
   UDP isn't blocked), then MASQUE-tunneled QUIC (recovers QUIC's properties over an
   HTTPS-reachable path), and only fall through to bare framed TLS-TCP as the last
   resort if the MASQUE proxy path itself is also unreachable (DPI blocking Extended
   CONNECT, proxy overloaded, etc.) — the existing fallback is never removed, only
   given a better option ahead of it.
4. **Opt-in, not default-on.** A new env knob (name TBD at implementation time,
   following this codebase's established `CT_AGENT_*`/`CT_EDGE_*` convention) gates
   whether an agent attempts the MASQUE rung at all. No existing deployment's behavior
   changes until explicitly configured — consistent with every other opt-in knob added
   this session (`CT_EDGE_TCP_FALLBACK_DELIVER_WAIT_MS`, `CT_CHANNEL_CALL_RECONNECT`,
   etc.).
5. **Bounded from day one.** The edge's CONNECT-UDP handler must not become an open UDP
   relay (#559 security baseline: "the user must not be compromisable through any of
   our services") — rate-limited, scoped to only proxy toward this agent's own known
   edge-facing QUIC listener (never arbitrary destination UDP), sized/timeout-bounded
   the same way every other edge listener in this codebase already is (missing-timeout
   sweep, #54 family).

## Why HTTP/2, specifically (not "MASQUE" generically)
Every public reference the operator cited (Cloudflare WARP, iCloud Private Relay, Edge
Secure Network) is a UDP-capable-client-wants-perf deployment. Copying that shape
verbatim here would ship a feature that silently does nothing for kali's actual
environment — the one case motivating this ADR. This is the single most
easily-gotten-wrong part of the whole project, hence called out as its own section
rather than left implicit in "use RFC 9298."

## Consequences
- A genuinely new transport class: new dependency family, new edge listener behavior,
  new client dial path, new fallback ordering — not a config change.
- Real feasibility risk at the crate-ecosystem level (HTTP/2 Extended CONNECT support
  in Rust), which is why the decomposition below puts a spike first, before any
  production-facing code.
- The edge's `:443` gateway (ADR-0019) needs **no new classification branch at all**
  (revised, see Decision 2) — MASQUE registers as a third `proxies` entry
  (`CT_EDGE_MASQUE_HOST`/`CT_EDGE_MASQUE_ADDR`) through the *existing*
  `FrontDoorRoute::Proxy(host)` arm, the same one Portal and Auth IdP already use.
  The ordering-guard principle ADR-0019 established (refuse anything not explicitly
  configured) is inherited for free, not re-implemented.
- Observability: the #533 benign-abort log family and the per-hostname breakdown gap
  noted during tonight's kali incident should be extended to cover the new rung too,
  not left as a blind spot from day one.

## Decomposition (phased, mirrors ADR-0019's GW1-GW4 slicing)
- **M1 — Feasibility spike — DONE, PASSED (2026-08-25, `ct-agent` `spike-masque-h2/`,
  branch `fix/81-m1-masque-h2-spike`).** Real, standalone workspace-member crate (not
  wired into `native`): `varint.rs`/`capsule.rs` hand-implement RFC 9297's Capsule
  Protocol (Type/Length/Value framing) and RFC 9298's UDP Proxying HTTP Datagram
  payload (Context ID + raw UDP bytes) over the `h2` crate's existing `:protocol`
  pseudo-header support (`h2::ext::Protocol`, confirms RFC 9220 Extended CONNECT is
  supported out of the box). `tests/roundtrip.rs` drives a real client+server exchange
  over an actual loopback TCP socket: Extended CONNECT with `:protocol=connect-udp`,
  a 200 response, one capsule-framed UDP datagram sent, echoed back, decoded, and
  byte-compared -- **passes**. No off-the-shelf Rust crate implements RFC 9298 over
  HTTP/2 specifically (the one Rust MASQUE implementation found, `jromwu/masquerade`,
  is HTTP/3-only via `quiche`) -- this had to be hand-rolled, confirming the ADR's
  own risk callout was real, not hypothetical.

  Two real findings surfaced by getting a working implementation, both relevant to M2/M3:
  1. **SETTINGS race**: a client's `SendRequest::ready()` resolving does *not*
     guarantee the server's `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` frame has already been
     processed -- `is_extended_connect_protocol_enabled()` must be polled with a bounded
     wait before attempting Extended CONNECT, not checked once.
  2. **Flush requires continued driving**: `send_data(..., end_of_stream: true)` only
     *buffers* the final frame -- `h2::server::Connection` must keep being polled (its
     own accept loop, same handle used to receive the original request) to actually
     flush buffered writes to the socket. Returning/dropping the connection immediately
     after the last `send_data` call closed the TCP socket out from under a still-
     buffered response in early iterations of this spike (client saw a broken-pipe
     reset instead of its data) -- a real proxy (M2) naturally avoids this by virtue of
     running a persistent accept loop, but it is a sharp edge worth remembering
     explicitly rather than rediscovering it in M2.

  If this had failed, Decision 1 would need revisiting before M2+; it didn't, so M2 is
  unblocked.
- **M2 — CONNECT-UDP proxy backend + edge registration — DONE (2026-08-25,
  `crates/masque-proxy`, #651/PR#652 + PR#653).** Built exactly as revised in
  Decision 2: a new local process (`crates/masque-proxy`) speaking h2 + Capsule
  Protocol on a plain TCP port, pumping datagrams bidirectionally to/from a real
  UDP socket. **Hard-restricted by construction, not allowlist**: every CONNECT-UDP
  request's path is compared byte-for-byte against one path precomputed from the
  single configured target (this edge's own `CT_EDGE_LISTEN`) -- there is no code
  path that can proxy anywhere else. Registered into `serve.rs`'s `proxies` map via
  `CT_EDGE_MASQUE_HOST`/`CT_EDGE_MASQUE_ADDR`, mirroring Portal/Auth-IdP verbatim
  (PR#653) -- zero changes to `sni.rs` or the dispatch `match`, confirmed. Bounded
  per #559/#54 (concurrent-tunnel semaphore, idle timeout, declared-capsule-length
  cap against a peer claiming an absurd size). Two real end-to-end tests: a
  datagram round-tripping through a live `masque_proxy::run` instance to a real UDP
  target, and a dedicated rejection test for the security-critical property (any
  other target gets `RST_STREAM`, never proxied). Opt-in -- both env vars unset by
  default, no existing deployment affected.

  One process/deploy hygiene note for whoever picks up M4: `CT_MASQUE_PROXY_TARGET_ADDR`
  (on the `masque-proxy` binary) and `CT_EDGE_LISTEN` (on the edge binary) must be
  kept in sync by the operator at deploy time -- nothing in code enforces the two
  configs agree, since they're two separate processes/binaries with no shared
  config source today.
- **M3 — ct-agent client side.** New `EdgeRung::Masque` in `ladder.rs`; QUIC-over-
  MASQUE-tunnel dial reusing the existing `quinn` stack against the tunneled UDP path;
  wired into the existing ladder-walk/registration-role logic between `Quic` and
  `TlsTcp`; opt-in env knob; unit tests mirroring the existing ladder test style.
- **M4 — Field trial + docs.** Opt-in deploy against kali.bunsenbrenner.org
  specifically (the motivating live case), real-world A/B against the current
  TLS-TCP-only fallback, observability parity, docs update (mirrors this session's
  Task #9 docs-overhaul pattern), then a deliberate decision on wider rollout.
