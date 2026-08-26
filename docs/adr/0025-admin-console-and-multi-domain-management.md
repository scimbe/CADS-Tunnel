# ADR-0025: Admin Console — Traffic Monitor, Multi-Admin, Multi-Domain Management

## Status

Proposed → In progress (2026-08-25).

## Context

The operator asked for an admin monitor: per-agent visibility into how much
traffic each registered ct-agent routes through the edge relay versus direct
end-to-end (P2P), plus admin powers (grant credits, unlock more subdomains,
delete/block users, disable (sub-)domains), served as its own subdomain
reached over a tunnel like every other Browser-Plane surface. Access is
gated to a specific Google account (`scimbe@gmail.com`), configured at
startup. Only that account may add or remove other admins, and it can never
itself be removed. The operator also asked for the system to support
managing domains beyond `bunsenbrenner.org`, and for both to be designed as
additional admin capabilities beyond what was explicitly requested, wherever
that serves the tunnel/agent/topology model.

An investigation before implementation found this is far less greenfield
than it looks:

- **Credit ledger** already exists and is tested (`crates/control-plane/src/
  accounts.rs`, `storage.rs`'s `SqliteLedger`, `billing.rs`). No new ledger
  logic is needed — only an admin-facing handler that calls `Ledger::credit`
  directly instead of going through the self-service payment-intent flow.
- **Per-tunnel relay-byte metrics already exist**: `crates/edge/src/
  state.rs`'s `tunnel_bytes: Mutex<HashMap<RoutingToken, (u64, u64)>>`,
  already exposed via the edge's own `GET /admin/tunnel-status/:token`.
- **Subdomain-quota unlock already exists**: `POST /admin/accounts/:subject/
  max-tunnels` on the control-plane's Portal admin routes.
- **Host authorization already exists** as a per-token model (`authorize_
  hostname`, pushed to the edge's `/admin/authorize-host/:token/:host`);
  "disable this (sub)domain" is a natural sibling of the existing revoke
  call, not a new subsystem.
- **Portal is a real, server-rendered Rust HTML app** (`portal.rs`/
  `portal_api.rs`, axum), not a separate frontend stack — an admin UI is
  more pages/routes on the same router, mounted the same way `/portal/*`
  already is.
- **Keycloak already brokers Google login** (`KC_GOOGLE_CLIENT_ID`/`_SECRET`
  in `compose.sso.yml`, scaffolded but needing real Google OAuth app
  credentials to work live), and `gate.rs` already has the exact primitive
  needed for "is this session's verified email X": OIDC token validation →
  verified `email` claim → allow-list check. No admin-identity check exists
  today — the current admin surface (`x-ct-admin-token` on both the edge
  and control-plane) is a single shared bearer secret with no per-admin
  identity or RBAC concept at all.
- **DNS/cert/edge-routing are already parameterized per call, not
  hardcoded to one zone**: `scripts/lib-acme.sh`'s `issue_cert(host, ...)`
  takes an arbitrary hostname; the edge's `proxies: HashMap<String,
  ProxyTarget>` is keyed by exact hostname string with no suffix
  assumption; `DesecClient` operations are per-record, not zone-locked
  beyond whatever the deSEC account token is scoped to.

## Decisions

### Decision 1 — Admin identity is a narrow, explicit carve-out on the pseudonymous account model, not a re-architecture of it

ADR-0012 deliberately keeps this system's accounts pseudonymous (opaque
`AccountId`, no PII by default). Binding admin privilege to a real Google
email is a legitimate, narrow exception — mirroring the precedent `gate.rs`
already sets for individual tunnels' optional email-gated access — not a
signal to weaken the pseudonymous model for ordinary users. Admin identity
lives in its own small `admins` table (`email TEXT PRIMARY KEY, added_by
TEXT, added_at INTEGER`), entirely separate from `AccountId`/the ledger.

### Decision 2 — The super-admin is a startup-configured invariant, not just the first row

`CT_ADMIN_SUPER_EMAIL` (required, no default, same fail-closed posture as
`CT_EDGE_ADMIN_TOKEN`) names the one account that can never be deleted and
is the only account allowed to add or remove *other* admin rows. This is
enforced in code (not just by convention): the super-admin's row is seeded
idempotently at every startup if missing, and every delete-admin/
demote-admin code path explicitly refuses when the target email equals
`CT_ADMIN_SUPER_EMAIL`, regardless of who's asking. A second admin can never
promote themselves to override this, since only the super-admin's own
verified-email session can call the admin-management routes at all.

### Decision 3 — Traffic visibility is honest about what the server can and cannot see

Relay-plane bytes (an agent's traffic that actually passed through the edge)
are real, already-measured numbers — surfaced per token, per direction. A
direct/P2P connection (`ct-agent`'s own `direct_advertise_ip` path)
deliberately bypasses the edge entirely, so the edge structurally cannot
count those bytes — no code change makes that measurable server-side without
either a weaker self-reported number from the agent (unverifiable) or the
Client's own report (same problem). The admin UI shows relay bytes as real
counts and represents "currently using direct/P2P" as a boolean derived from
whether a direct advertisement is active for that tunnel — not a byte count
it doesn't have. This is called out explicitly in the UI copy, not glossed
over.

### Decision 4 — Multi-domain management ships now for admin-side onboarding; per-domain end-user sessions are explicitly deferred

The genuinely new work for "manage domains beyond bunsenbrenner.org" is
small given how parameterized the underlying DNS/cert/edge-routing code
already is: a `managed_domains` table (`zone TEXT PRIMARY KEY, added_by,
added_at, status`) plus an admin flow wrapping the existing `DesecClient`/
`issue_cert`/edge-proxies-registration calls for an operator-supplied new
zone. One step cannot be automated at all: delegating a new zone's
nameservers to deSEC happens at the domain's registrar, outside this system,
and is documented as a manual prerequisite the admin performs once per new
domain before onboarding it here (same as the existing deSEC setup docs
already describe for the first zone).

**Explicitly out of scope for this pass**: giving a second onboarded domain
its *own* independent end-user login/session (the way `bunsenbrenner.org`'s
Portal has one today). `CT_GATE_COOKIE_DOMAIN` scopes the control-plane's
session cookie to a single apex domain — browsers cannot share cookies
across different apex domains, so a genuinely separate self-service Portal
under a second domain needs either (a) the control-plane resolving its
session-cookie domain per-request from the incoming Host header
(`HashMap<zone, CookieConfig>` instead of one scalar), or (b) one
control-plane process per domain. Both are real structural changes deserving
their own decision once a second domain's *end users* (not just its
admin-side DNS/cert/routing) are actually needed — the admin dashboard
itself does not need this, since the admin always authenticates at one fixed
`admin.<primary-zone>` regardless of how many other zones they manage.

### Decision 5 — The admin console is a new hostname on the EXISTING control-plane process, not a new service

Mirrors Portal's own front-door registration exactly: a new
`CT_EDGE_ADMIN_UI_HOST`/`_ADDR`/`_CERT`/`_KEY` entry in the edge's proxies
map (same shape as tonight's `CT_EDGE_MASQUE_*`), pointed at the same
`control-plane:8090` backend, with new routes mounted under `/admin-ui/*`
on the existing axum router. No second container, no second database, no
second source of truth for tunnels/accounts/ledger — the admin console
reads and writes through the same storage the rest of control-plane already
uses.

**Addendum, found during the admin-identity foundation's implementation
(2026-08-25):** `admin_identity::admin_session_from_headers` resolves the
current request's verified email via `portal::session_claims_for`, i.e. the
existing `ct_portal_session` cookie. That cookie is deliberately host-only —
`portal.rs`'s `session_cookie()` sets no `Domain=` attribute at all — so it is
only ever sent back to the exact host that set it. Decision 5 puts the admin
console on its *own* new hostname (`CT_EDGE_ADMIN_UI_HOST`), distinct from
Portal's own front door (`CT_EDGE_PORTAL_HOST`); per RFC 6265, a browser never
attaches a host-only cookie minted on one host to a request against a
different host. As specified today, an admin who is genuinely logged into
Portal would still get `401` visiting `admin.<zone>` — the session simply
never arrives. This does not block the identity/authorization logic itself
(its tests exercise `admin_session_from_headers` directly against a
hand-signed cookie, which is a valid unit-level proof of the check), but
whichever later phase wires up the real `/admin-ui/*` login flow must resolve
it before the extractor works end-to-end. Two options, not decided here:
(a) widen `ct_portal_session` to a `Domain=`-scoped cookie shared across the
whole zone (mirroring `CT_GATE_COOKIE_DOMAIN`/`ct_gate_session` in `gate.rs`),
reusing Portal's existing login as-is; or (b) give the admin console its own
dedicated OIDC login and its own `Domain=`-scoped session cookie, fully
mirroring `gate.rs`'s shape rather than reusing Portal's. (a) is less new
code but widens the blast radius of Portal's session cookie to every current
and future `*.<zone>` subdomain — a real tradeoff the next phase should weigh
explicitly rather than pick by default. `admin_session_from_headers` itself
needs no change either way; only which cookie/domain-scoping mints the
session it reads is still open.

### Decision 6 — Additional admin capabilities beyond what was explicitly asked

Per the operator's own request to add capabilities "important for
bunsenbrenner and the idea of tunnels, agents, and topologies" beyond what
they'd thought to ask for, this pass also adds:

- **Audit log**: every privileged admin action (credit grant, block/delete
  account, domain disable, admin add/remove, domain onboarding) is recorded
  immutably with actor email, timestamp, and target — matching this
  codebase's own established "operator must be able to see everything"
  convention (#127-style loud logging) applied to the admin surface itself.
  A privileged console with no record of who did what is a real gap in a
  system whose whole premise is auditable trust.
- **Live tunnel/topology overview**: every currently-registered agent/
  tunnel, its transport (relay vs. direct), which edge it's on, uptime,
  last-seen — a natural superset of the existing per-token `tunnel-status`
  call, surfaced as a real dashboard instead of a one-token-at-a-time API.
- **Certificate expiry dashboard**: with now several front-door hostnames
  (Portal/Auth/MASQUE/Admin, soon per-domain), surfacing days-until-renewal
  per hostname directly prevents a repeat of tonight's own #142-class
  incident (a cert silently unusable after a permissions mistake) by making
  the state visible before it becomes an outage.

**Deliberately not attempted in this pass** (documented as real follow-up
work, not half-built here): an abuse-report inbox (ADR-0008's own
"responsive, not proactive policing" posture argues for building this once
there's a real reporting channel to feed it, not speculatively), a
per-account quota/rate-limit visualization dashboard, and a one-click
"kill all this account's tunnels" action (the existing per-token revoke
already covers the mechanism; a bulk wrapper is a small, separable future
addition once the core console is live and used).

## Consequences

- New tables: `admins`, `managed_domains`. No changes to the existing
  pseudonymous `AccountId`/ledger schema.
- New required env var: `CT_ADMIN_SUPER_EMAIL` (fail-closed — control-plane
  refuses to start without it, same posture as `CT_EDGE_ADMIN_TOKEN`).
- Real, working Google login requires the operator to create a real Google
  Cloud OAuth 2.0 Client (Client ID + secret) and supply `KC_GOOGLE_CLIENT_
  ID`/`KC_GOOGLE_CLIENT_SECRET` — this cannot be self-serviced by an agent;
  it is a one-time human step in Google Cloud Console. The admin console's
  code and deployment ship regardless; the login step fails closed (no
  admin can authenticate) until those credentials are supplied.
- A second domain's *DNS/cert/routing* can be onboarded through the admin
  console once built; giving that domain independent end-user sessions is
  explicitly future work per Decision 4.
