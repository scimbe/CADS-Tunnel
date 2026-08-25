# ADR-0024 — MASQUE/CONNECT-UDP (RFC 9298) as a third transport rung for UDP-blocked networks

## Status
Proposed. Builds on ADR-0004 (QUIC data-plane transport with TCP fallback), ADR-0010
(Mesh-Plane-first / Browser-Plane SNI), ADR-0019 (unified :443 gateway). Tracked by
ct-agent#81 (design-tracking issue, recon already done there) and this ADR's own
decomposition below. Operator green-lit real design + implementation work 2026-08-25.

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
2. **Proxy component: extend the edge, not a new service.** The edge already owns
   `:443` as an SNI-multiplexed gateway (ADR-0019) with live TLS/ACME infra; adding a
   CONNECT-UDP handler there avoids a new deploy unit, a new cert story, and a new
   discovery mechanism — a MASQUE-capable agent dials the *same* edge host it already
   knows, just requesting Extended CONNECT instead of (or after) a raw QUIC/TCP dial.
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
- The edge's `:443` gateway (ADR-0019) gains a third classification branch (portal /
  tunnel-passthrough / **now MASQUE CONNECT-UDP**) — must stay strictly fenced, same
  ordering-guard principle ADR-0019 already established (refuse anything not
  explicitly authorized).
- Observability: the #533 benign-abort log family and the per-hostname breakdown gap
  noted during tonight's kali incident should be extended to cover the new rung too,
  not left as a blind spot from day one.

## Decomposition (phased, mirrors ADR-0019's GW1-GW4 slicing)
- **M1 — Feasibility spike (do this first, before committing further).** Prove, with
  a minimal standalone Rust program (not integrated into either production crate yet),
  that an HTTP/2 Extended CONNECT (RFC 9220) request can be made and a CONNECT-UDP
  (RFC 9298) Capsule-Protocol UDP datagram tunnel established end-to-end using
  available crates (`h2` + hand-rolled capsule framing if no higher-level crate exists).
  If this is not cleanly buildable, this ADR's Decision 1 needs revisiting before M2+.
- **M2 — Edge-side CONNECT-UDP handler.** New branch in the edge's `:443` SNI/protocol
  demux (alongside ADR-0019's portal/tunnel branches); datagram encapsulation/
  decapsulation; bounded per #559/#54 conventions; unit + integration tests.
- **M3 — ct-agent client side.** New `EdgeRung::Masque` in `ladder.rs`; QUIC-over-
  MASQUE-tunnel dial reusing the existing `quinn` stack against the tunneled UDP path;
  wired into the existing ladder-walk/registration-role logic between `Quic` and
  `TlsTcp`; opt-in env knob; unit tests mirroring the existing ladder test style.
- **M4 — Field trial + docs.** Opt-in deploy against kali.bunsenbrenner.org
  specifically (the motivating live case), real-world A/B against the current
  TLS-TCP-only fallback, observability parity, docs update (mirrors this session's
  Task #9 docs-overhaul pattern), then a deliberate decision on wider rollout.
