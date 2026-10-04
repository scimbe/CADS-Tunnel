# ADR-0026: OpenNHP (Network-infrastructure Hiding Protocol) — variant comparison and decision template

trace: REQ-0006, AUF-20261004-016

## Status

Proposed — design-slice only, per DEC-0059 P1. This ADR decides **nothing**
about what gets deployed; it is the decision template the CTO asked for
(2026-10-04) so a variant can be *chosen*. Implementation of whichever
variant is chosen is an explicit follow-up task, not part of this slice.

## Context

CTO mandate (2026-10-04): evaluate integrating OpenNHP
(github.com/OpenNHP/opennhp, Apache-2.0, Go, tag `v1.0.2`) into the
CADS-Tunnel architecture. The 2026-10-04 review attached four conditions
to that mandate, all of which this ADR must answer before any rollout is
credible:

1. **Maturity is unproven.** The repo's pre-2023 history is an unrelated
   JS UI library; its 13,940 GitHub stars measure that library's old
   popularity, not NHP's. `v1.0.2` is three weeks old (tagged
   2026-09-10/11), carries zero security advisories, and has had no
   independent audit. The only specification is a CSA (Cloud Security
   Alliance) reference document; no IETF draft was found.
2. **The NHP server is itself a pre-authentication parser (in Go).**
   Adopting it moves the attack surface that currently sits at `:443`
   (already hardened, ADR-0019) onto a new daemon; it does not remove an
   attack surface.
3. **The NHP Access Controller (AC) writes firewall rules at runtime.**
   On `core`, Docker already owns `iptables` for ~20 containers.
4. **Fail-closed by design.** If the knock daemon goes down, every agent
   is locked out. Nothing today watches for that failure mode or
   provides an operating mode without total lockout.

### Measured baseline (core, 2026-10-04)

Publicly reachable today: `:22` (SSH, admin), `:80`/`:443` (HTTP(S),
visitors), `4433–4437`/udp+tcp (ct-agents only — mesh edge, channel
broker/relay, WS channel; see `docker/deploy/compose.selfhost.yml`),
`5333`/udp (agent/admin-only operational port), `3478` (TURN, browsers).
Origins already have **no** inbound port — `ct-agent` always dials out —
so NHP's only possible benefit is on the ports only agents and admins
use, never on `:443` itself.

## Threat model and port classification

| Port(s) | Who reaches it today | Hide behind a knock? | Why |
|---|---|---|---|
| `22`/tcp (SSH) | Human admins only | **Candidate** | Narrowest, highest-value target: interactive shell access. Every variant below treats this as in-scope; V3 treats it as the *only* in-scope port. |
| `4433–4437`/udp+tcp | `ct-agent` fleet only | **Candidate** | This is the mandate's actual target: these ports are scanned by the same internet that scans `:22`/`:443`, but carry zero visitor traffic, so hiding them costs nothing in product terms. |
| `5333`/udp | Agents/admin only | **Candidate** | Same reasoning as above — no visitor path touches it. |
| `80`/`443` | Visitors (the product) | **Stays visible** | This is the product. ADR-0019's unified `:443` gateway exists precisely so visitor traffic and agent traffic share one hardened front door; hiding it defeats the point of having a public tunnel service at all. |
| `3478` (TURN) | Browsers doing WebRTC ICE | **Stays visible** | Third-party browsers (video-call participants, ADR-0023) do not and cannot speak an NHP knock — TURN is reached by stock WebRTC stacks we don't control. Hiding it would break call connectivity for exactly the audience TURN exists to serve. |

## Evidence base: OpenNHP at a pinned commit

All statements about OpenNHP below are grounded in a read-only, unauthenticated
clone of the public upstream repository at tag `v1.0.2`, commit
`1f1daad0a02e3f3ecfe341ef94dfb9bdbd59109c` (merged 2026-09-11 09:34:01 +0800).
This clone was used only to read source for this ADR; it is **not** vendored
into this repository and no dependency on it has been added anywhere in
`Cargo.toml`/`Cargo.lock`.

### Packet format of the knock

- A fixed 24-byte common header (`HeaderCommonSize = 24`,
  `nhp/core/constants.go:60`) precedes a per-cipher-scheme extended header;
  `type` and payload `size` are read directly off the wire, in cleartext,
  by `RecvPrecheck` (`nhp/core/packet.go:249`) — **before** any key lookup
  or decryption happens. `CheckRecvHeaderType` (`nhp/core/packet.go:215`)
  then dispatches on that cleartext type, still pre-authentication.
- Crypto field sizes are fixed: `GCMNonceSize = 12`, `GCMTagSize = 16`
  (`nhp/core/constants.go:68-69`), `CookieSize = 32`
  (`nhp/core/constants.go:66`).
- The knock's application payload is `AgentKnockMsg`
  (`nhp/common/nhpmsg.go:63-71`): a JSON object —
  `{headerType, usrId, devId, orgId, aspId, resId, results, usrData}` —
  carried as the AEAD-encrypted body once the handshake has derived a
  session key. So "the knock" is not one opaque blob: it is a cleartext
  24-byte header (type/size/counter) wrapping an AEAD-encrypted JSON
  message.

### Replay protection

This is **not** a WireGuard-style sliding replay window/bitmap.
`nhp/core/responder.go:536-608`: the responder decrypts an embedded
timestamp using a key derived from ECDH with the claimed peer identity,
then enforces `remoteSendTime < ppd.ConnData.LastRemoteSendTime` as a
**monotonic, per-connection** ordering check (`responder.go:562`), a
20 ms minimum re-send interval (`MinimalRecvIntervalMs`,
`nhp/core/constants.go:33`, enforced at `responder.go:577`), and a
600-second staleness ceiling against local time
(`responder.go:592`). Replay state therefore lives **per tracked
connection** (keyed by remote UDP address/peer entry — see below), not
in a global nonce cache: a new UDP 4-tuple (NAT rebind, agent restart,
address change) starts a fresh monotonic counter. Separately, an
HMAC-derived **stateless cookie** mechanism exists for DoS/overload
defense (`endpoints/server/config.go`, `CookieSigningKeyBase64` /
`CookieTimeWindowSeconds`, documented around lines 109–130), which
upstream's own comment ties to the `remoteConnectionMap` crossing an
"~16k concurrent connections" overload threshold
(`endpoints/server/config.go:139`) — i.e., the authors already needed a
second, stateless mechanism because the per-connection model alone
isn't DoS-safe at scale.

### State of the server (why "pre-auth parser" is literal)

`RecvPrecheck`/`CheckRecvHeaderType` run before any identity is
established (above). Both daemons hold live, network-populated state
ahead of authentication: `nhp-server` keeps a `remoteConnectionMap`
keyed by remote UDP address (`endpoints/server/msghandler.go:884-885`);
`nhp-ac` keeps three such structures — `remoteConnectionMap` (by UDP
addr), `serverPeerMap` (by server public key), and a `tokenStore`
(`endpoints/ac/udpac.go:43,46,48`). Upstream's own doc-comment names the
consequence directly: a misbehaving relay can "inject any private-range
SourceAddr it wants into the server's connection map and the downstream
AC ipset whitelist" (`endpoints/server/config.go`, comment above
`AllowPrivateRelaySource`, lines 91-107). The attack surface moves to
this state machine; it does not disappear.

### How the AC sets firewall rules

`nhp-ac`, run with `FilterMode_IPTABLES` (the default; an alternate
`FilterMode_EBPFXDP` also exists — `endpoints/ac/config.go:30-31` — but
was not examined here and is not evaluated by this ADR), constructs an
`*utils.IPTables` (`endpoints/ac/udpac.go:113`, requires root, probes via
`iptables -L`) and an `*utils.IPSet` (`endpoints/ac/udpac.go:119`) at
startup. The actual **per-knock** action is not an iptables rule
insert/delete at all: it is a timed `ipset` membership write —
`a.ipset.Add(ipType, 1, openTimeSec, ipHashStr)`
(`endpoints/ac/msghandler.go:163`, and five further call sites at lines
212, 263, 725, 846, 893) — an entry in an ipset `hash:ip,port,ip` set
that the kernel itself expires after `openTimeSec`. Two blunter
primitives also exist in `nhp/utils/iptables.go` and are used for
global lock/unlock, not per-knock opening: `changePolicy`
(`iptables.go:168-218`) runs `iptables -P INPUT|FORWARD|OUTPUT
ACCEPT|DROP|REJECT` — i.e., it rewrites a chain's **default policy**,
host-wide (`iptables.go:180` for INPUT) — and `changeIptablesRule`
(`iptables.go:220-274`) inserts/deletes a single blanket `-I/-D INPUT -d
<dest> -j ACCEPT|DROP` (`iptables.go:236`) or the FORWARD equivalent
(`iptables.go:252`). The shipped bootstrap,
`release/nhp-ac/iptables_default.sh`, is what wires these primitives
into a working firewall: run with `-f` it executes `iptables -F;
iptables -X` (lines 8-9 — flush **every** rule and delete **every**
custom chain, not just NHP's), creates an `NHP_DENY` chain, appends
match-set-based ACCEPT rules to the **shared** `INPUT` and `FORWARD`
chains, and finishes with `iptables -P INPUT DROP` (line 177) and
`iptables -P FORWARD DROP` (line 179) — a host-wide default-deny
posture, not a rule scoped to a dedicated chain.

## Interplay with Docker

OpenNHP's shipped bootstrap has **zero** `DOCKER-USER` awareness: it
flushes all chains (under `-f`) and resets the global `INPUT`/`FORWARD`
default policy to `DROP`. On `core`, Docker already manages `iptables`
for ~20 containers — it inserts its own jump to the `DOCKER-USER` chain
near the top of `FORWARD` every time `dockerd` (re)starts, and manages
per-published-port `ACCEPT`/`DROP` logic in its own chains. Concretely,
deploying the stock AC as-is risks exactly the "looks healthy, isn't
reachable" failure class the mandate calls out, in three distinct ways:

1. Running the bootstrap with `-f` flushes Docker's own `DOCKER*`/
   `DOCKER-USER` chains outright — an immediate outage for all 20
   containers the first time anyone runs it.
2. Even without `-f`: NHP's match-set rules are **appended** (`-A`, tail
   of chain) rather than inserted ahead of Docker's own jump. A
   `dockerd` restart or `docker compose up` re-inserts Docker's
   `FORWARD` jump at a fixed early position each time, which can
   resequence which rule wins for a given packet without either side
   erroring — neither `iptables -L` nor compose's own health checks
   would show anything wrong.
3. Rewriting the chain **default policy** to `DROP` is host-wide blast
   radius: it only fires once every explicit rule in the chain falls
   through, so a rule misordered by (2) now fails *closed* at the
   policy level instead of failing *open*.

**Any variant that touches the host firewall (V1, and V2/V4 if they
reimplement firewall manipulation) must, at minimum:** (a) operate
inside a dedicated chain referenced by exactly one idempotent jump rule
at a fixed position, re-asserted — not re-created — both at NHP startup
and whenever Docker (re)starts, and (b) never issue a global chain
flush or global default-policy change as part of normal operation.
Neither property is true of what OpenNHP ships today.

## Ausfallmodus (knock-server failure)

If the knock/AC path is the only way in, an outage of either daemon
locks out SSH and every agent simultaneously — including whoever would
otherwise fix the outage. **Required operating mode:** a documented,
reversible, out-of-band exception path that keeps at least SSH
reachable independent of the knock daemon's liveness — e.g., a
standing, narrowly-scoped admin-source allow-list or a separate bastion
credential that does **not** depend on `nhp-server`/`nhp-ac` being up.
**The security price, stated explicitly:** that exception path is, by
construction, a standing opening that NHP's entire value proposition
(port invisible until an authenticated knock) does not cover. It must
be sized as small as operationally tolerable — ideally break-glass,
audited, and rotated — precisely because it is the one thing a
fail-closed-everywhere design cannot survive. On the agent side, a dead
knock server must not produce a silent, infinite hot-retry loop against
the host; the existing bounded exponential reconnect backoff must
surface the outage to operators rather than mask it as ordinary
connection churn.

## Agent-side knocking (ct-agent)

Because the AC's opened window is address-specific (an ipset
`hash:ip,port,ip` entry, scoped to the knocking source, with its own
TTL — see "How the AC sets firewall rules" above) and all server-side
replay state is tracked per remote address (see "Replay protection"),
**every dial attempt — including every reconnect after a drop, and
every reconnect after an address change — must knock first.** There is
no "knock once per device, reuse forever" option under this model: a
stale "we already knocked this address" cache must be invalidated the
instant the resolved address changes.

This sits directly on top of reconnection work already in this
codebase's two-repo mandate: the DNS re-resolution hardening (#229) and
the `:443` channel front door's parked-member reaping (#256) already
mean `ct-agent` re-resolves and redials when its target address
changes; `#245` tracks the broader tunneling-landscape comparison this
mandate extends, and `AUF-20260929-006` is the most recent task to touch
that redial path. A knock-before-connect step is an **additional**
network round trip inserted in front of that existing path, not a
replacement for it: every redial becomes *resolve → knock → (wait for
the opened window) → dial*. Whichever variant is chosen, the
follow-up implementation task must account for the added latency and
the new failure mode (knock timeout/rejection) in the existing
reconnect backoff logic — this ADR does not design that logic, only
flags that it must change.

## Key management

This repository already has: Noise static X25519 keypairs for the mesh
handshake (`StaticKeypair`, `crates/common/src/noise.rs:26-64`), a
`RoutingToken` used for relayed-path admission at the edge, and
whatever device/holder credential issues agent certificates (ADR-0003,
ADR-0005). OpenNHP introduces its **own**, independent device identity:
a keypair registered via `NHP_REG`/`AgentRegisterMsg`
(`nhp/common/nhpmsg.go`), scoped by `(UserId, DeviceId,
OrganizationId, AuthServiceId)`, persisted server-side in its own
SQLite database (`endpoints/server/config.go`, `DatabasePath`, default
`<exe_dir>/data/nhp_server.db`), with its own expiry semantics
(`ServerRegisterAckMsg.ExpiresAt`) unrelated to this repo's existing key
rotation story.

**Recommendation: do not reuse the Noise static keypair as the NHP
device key**, even under V1/V2. The two protocols make different
replay and rotation assumptions, and OpenNHP keeps its own
registration/expiry/trust-store model that has nothing to do with this
repo's existing key custody. A shared *root* identity (the same agent,
the same operator-issued credential bundle) deriving two independent
subkeys is acceptable; a literal byte-for-byte shared static key is
not — compromise of one protocol's key material must not automatically
hand over the other's. V4 (native knock on existing keys) sidesteps
this question entirely by construction: no second keypair, no second
trust store, no SQLite registration database to operate.

## Variants

### V1 — Upstream OpenNHP daemons (`nhp-server`, `nhp-ac`) as Compose services

- **Cost:** a new Go toolchain in the build/deploy pipeline, new
  container(s) that must run privileged (root, `iptables`/`ipset`, or
  `--cap-add=NET_ADMIN`), a new SQLite database to operate and back up,
  a new protocol surface end to end.
- **Risk:** all four 2026-10-04 review findings apply directly and in
  full — unproven maturity, a pre-auth Go parser with network-populated
  state, the Docker-interplay hazard above, and fail-closed-by-design.
- **Reversibility:** HIGH *if* scoped correctly (containers only, the
  host-level `iptables_default.sh` bootstrap never run directly on
  `core`) — stop/remove the containers and the prior firewall posture
  returns. Note this is a real precondition, not a given: containerizing
  `nhp-ac` still requires it to manipulate the **host's** netfilter
  tables (privileged container, `NET_ADMIN`), so "just a Compose
  service" does not by itself avoid the Docker-interplay risk above.

### V2 — NHP knock reimplemented natively in Rust, in `ct-edge`/`ct-agent`, to spec

- **Cost:** the highest of the four — a from-scratch, spec-compliant
  reimplementation of the wire protocol (header, AEAD scheme,
  cookie/overload path, registration flow), validated against whatever
  upstream interop/test vectors exist.
- **Risk:** still a pre-auth parser (now in memory-safe Rust instead of
  Go — removes the memory-corruption risk class, keeps logic-level
  DoS/resource-exhaustion risk), and now depends on a single vendor's
  unaudited, single-implementation spec staying stable enough to track
  without drift. Firewall-rule application still needs its own answer
  to the Docker-interplay problem — V2 does not avoid that question,
  it just relocates who writes the code that must solve it.
- **Reversibility:** MEDIUM — it is this repo's own code, so removable,
  but represents real sunk engineering cost V1 does not.

### V3 — Only host SSH (`:22`/tcp) behind a knock

- **Cost:** lowest of the four — either V1's `nhp-ac` scoped to guard
  only port 22, or (preferred if V3 is chosen) a minimal, narrowly
  scoped port-knocking/SPA tool protecting exactly one port.
- **Risk:** smallest blast radius by far. A failure or compromise of
  the knock path affects only interactive admin SSH access — never the
  agent fleet, never `:80`/`:443` visitor traffic, never TURN. Does
  **not** address the mandate's stated goal of hiding `4433-4437`/`5333`
  from scanners at all.
- **Reversibility:** HIGHEST — one port, trivially reverted.
- This is the review's genuine counter-variant, not a strawman: it
  spends the entire port-knocking budget on the one port that is both
  the highest-value human target and the cheapest to protect, while
  declining all exposure to the ports that actually carry agent
  traffic today.

### V4 — Native knock on existing Noise-holder keys, no foreign protocol

- **Cost:** moderate — an original, intentionally small design: a UDP
  pre-connect challenge/response authenticated with the agent's
  *existing* identity key (signed or HMAC'd nonce over
  timestamp+destination), verified server-side to open a short,
  per-source firewall window — the same *mechanism* OpenNHP uses,
  without adopting OpenNHP's protocol, registration flow, or trust
  store.
- **Risk:** a homegrown protocol always carries "did we get the
  replay/DoS story right" risk that an established (even unaudited)
  spec partially discharges simply by having existed and been read by
  more eyes. In exchange, the attack surface is exactly as large as
  this team chooses to make it, reviewed to the same bar as the rest
  of this codebase, with no second keypair, no second database, no
  second toolchain, and no exposure to upstream drift.
- **Reversibility:** HIGH — same containment as V2 (local code), and
  strictly smaller in scope than V2 (no external spec-compliance
  obligation to track).

## Entscheidungsvorlage

| Option | Cost | Risk | Reversibility | Addresses the mandate's stated goal? |
|---|---|---|---|---|
| V1 — upstream daemons | High (new runtime, root, DB) | All four review findings apply in full | High, if host bootstrap is never run directly | Yes |
| V2 — native Rust, to spec | Highest (reimplementation + spec tracking) | Pre-auth parser persists; Docker question unresolved | Medium | Yes |
| V3 — SSH only | Lowest | Lowest (scope limited to one port) | Highest | No — does not hide agent ports |
| V4 — native knock, own keys | Moderate | No upstream-drift/second-store risk; homegrown-crypto review burden | High | Yes |

**Empfehlung:** V4 as the design direction to carry into an
implementation task, with V3 as the fallback if even V4's engineering
cost is not currently justified. The 2026-10-04 review's strongest
findings — unproven upstream maturity (Auflage 1) and the Docker/
fail-closed interplay (Auflagen 3–4) — are weakest exactly where V1 is
weakest and where V4 is strongest by construction (no foreign runtime,
no foreign trust store, smallest fail-closed blast radius to engineer
around).

**Default bei Schweigen (if the CTO does not pick an option):** **V3**.
It is the narrowest, cheapest, and most reversible option — protect
`:22` only, change nothing about how the agent fleet reaches
`4433-4437`/`5333` — and it is the only option whose adoption costs
essentially nothing to undo. Absent an explicit decision, ops proceeds
with V3 only; V1 (`nhp-ac` on `core`) is not deployed.

**Thresholds at which V1 becomes viable** (any one of the following
moves V1 from "not yet" to "revisit"):

- An independent, third-party security audit of `nhp-server`/`nhp-ac`
  is published, **or**
- A second, independently maintained implementation of the NHP wire
  protocol exists and interoperates, **or**
- An IETF (or equivalent open standards body) draft for NHP is
  published and is being tracked toward adoption, **or**
- A multi-quarter advisory/CVE history demonstrates the project
  patching real-world findings in production use.

Today, none of these are met: `v1.0.2` is three weeks old, has zero
advisories, no known independent audit, one implementation, and a CSA
reference document as its only specification. Zero advisories at this
age is an absence of signal, not evidence of safety.

## Consequences

- This ADR ships no code and changes no running behavior on `core`; it
  exists solely so the CTO can choose a variant.
- Whichever variant is chosen becomes its own follow-up ADR/task
  packet with its own task-packet ID; this document does not authorize
  deployment of any of V1–V4.
- Absent an explicit choice, the default per this ADR is V3-or-nothing:
  no OpenNHP daemon is deployed on `core`, and no existing firewall
  posture for `4433-4437`/`5333` changes.
