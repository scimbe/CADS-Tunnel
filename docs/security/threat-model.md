# Threat model & secrets management (production)

Production security posture for the hosted + self-hostable service. Updates the
v1 academic posture (SPEC §7–§9) for the productionization pivot: conventional
Keycloak/OIDC accounts everywhere (the pseudonymity marketing claim is dropped),
while the end-to-end Noise payload encryption is retained.

## Assets

- **Payload traffic** between a client and its origin.
- **Account / identity** data (Keycloak subject ↔ tunnel account, credit ledger).
- **Enrollment + registry state** (join tokens, agent bindings, tunnel routes).
- **Signing material**: the edge's internal CA key, the Keycloak realm keys.

## Trust boundaries & what each party sees

| Party | Sees | Does **not** see |
|-------|------|------------------|
| Edge / control plane (operator) | Ciphertext, routing metadata, account id, billing | **Payload plaintext** (Noise E2E terminates at client↔origin) |
| Control plane | Keycloak subject, credit balance, tunnel registry | Origin private key, payload |
| Client | Its own payload, the edge CA root | Other tenants' traffic |

The operator can route and bill your traffic but cannot read it — the honest
claim is "we can't read what you send", not anonymity.

## Adversaries & controls

| Adversary / abuse | Control | Status |
|-------------------|---------|--------|
| On-path eavesdropper | Noise_IK E2E; QUIC/TLS transport; edge sees only ciphertext | shipped (M8, M20) |
| Rogue/rotated edge cert | Internal CA, clients trust the CA root (rotation without re-pinning) | shipped (M20) |
| Unauthenticated actor | OIDC bearer verification on `/me/*`; account derived from the token subject | shipped (M19) |
| Rendezvous flood (unfunded) | PoW gate (always on) + per-token rendezvous rate limit (600/min) and per-edge connection cap (8192), both **on by default** since #95 — tune via `CT_EDGE_RENDEZVOUS_MAX_PER_MIN` / `CT_EDGE_MAX_CONNECTIONS`, `0`/`off` disables either | shipped (ADR-0018; #86, defaults flipped on in #95) |
| Single account exhausting issuance | Per-subject issuance rate limit → 429 before any ledger touch | shipped (M23.1) |
| Vulnerable dependency | `cargo audit` against a committed, pinned `Cargo.lock` | shipped (M23.2) |
| Committed credential leak | `scripts/check-no-secrets.sh` guard (PEM keys, cloud keys, tracked `.env`) | shipped (M23.3) |
| State loss on restart | Durable SQLite (enrollment/registry/ledger) | shipped (M18) |
| Poisoned local build (gate write-mount) | Server-side CI (`.github/workflows/ci.yml`) re-runs build+test+audit+secret-guard on `main`, independent of the local gate | accepted residual (#78 SEC78c; mitigated by SEC78b) |
| Funded sybil / billing fraud | **unresolved** — PoW does not deter a paying adversary | open (SPEC §9.1) |

## Secrets inventory & handling

| Secret | Where it lives | Handling |
|--------|----------------|----------|
| Keycloak realm signing key | Keycloak; the verifier fetches/holds the public half | never in this repo; issuer URL is public config, not a secret |
| Edge internal CA key | Generated on first boot, **persisted to disk** beside the published root cert (`edge-ca-key.pem`, owner-only `0600`, on the Edge's runtime/shared volume — `Ca::load_or_create` in `crates/edge/src/pki.rs`) | never committed; a fresh volume (or a wiped one) generates a new CA, which rotates the root under every pinned Agent/Client (issue #2) — back up or persist that volume across redeploys the same way `cpdata` is |
| Origin Noise private key | Agent process (custodian) | only the public half travels (in the Capability) |
| Deployment env (`CT_OIDC_ISSUER`, ports) | `docker/deploy/.env` (self-host) / K8s Secret (hosted) | `.env` is **gitignored**; only `.env.example` templates are committed; K8s secrets supplied out-of-band (sealed-secrets / external-secrets) |
| Join token | Operator → agent, single-use | short-lived, consumed on first redeem |
| **Headless-pipeline customer TLS private key (#322)** | Generated transiently on the **operator's own machine** by `scripts/authorize-pipeline.sh` (real Let's Encrypt cert via DNS-01 against the operator's `DESEC_TOKEN`), then handed to the pipeline maintainer out of band | **Documented exception to ADR-0001/0003**, not an oversight — see Residual risk 6 below for why this exists and its actual exposure |

**Rules:** no real secret is ever committed; `Cargo.lock` is committed and pinned;
`scripts/check-no-secrets.sh` runs in CI to enforce the no-committed-secrets rule;
the edge CA key is **stable across restarts/redeploys** by design (`Ca::load_or_create`
reloads the persisted key so pinned Agents/Clients keep working, matching
`docs/ops/runbook.md`) — a restart does **not** rotate it. To actually rotate the CA,
delete `edge-ca-key.pem` from the Edge's runtime volume before restart; every Agent/Client
pinned to the old root must then re-pin against the new one, so treat this as a
break-glass operation, not routine maintenance. The self-host `docker-compose` case keeps
this file on the same volume as the published cert; the Kubernetes case is tracked
separately (#308: an `emptyDir`-mounted CA key does not survive pod rescheduling, which
silently forces this same rotation-and-re-pin path on every reschedule).

## Residual risks

1. **Funded sybil / billing fraud** — accounts are now real (Keycloak), which
   raises the bar, but a paying adversary is still not deterred (SPEC §9.1).
2. **Control-plane metadata** — the operator sees account id, routing and billing
   metadata (not payload). Minimize retention; document in the privacy policy.
3. **Jurisdiction / lawful-floor process** — operational, not code (SPEC §9.2–9.3).
4. **Trust-primitive clock skew (#88 SEC88d)** — `credential::verify`/`verify_fresh`
   and `channel::verify`/`verify_fresh` (`SignedCredential`, `ChannelGrant`) take a
   caller-supplied `now`, so a **backwards-skewed edge clock extends a token's
   validity window** beyond its `expires_at`. There is no fix inside `ct-common` —
   the verifying host owns its clock — so this is an operational control: run edge
   hosts under NTP with monotonic-time discipline and alert on large steps.
   *Replay* itself is bounded independently of skew: the channel broker gates every
   join on a fresh single-use possession challenge (#81), the `ReplayCache` /
   `verify_fresh` primitive (#88 SEC88a/b) is available for any future live
   `SignedCredential` path, and enrollment now requires proof-of-possession (#88
   SEC88c). accepted residual.
5. **Unverified-email / open-registration accounts (#89 SEC89b)** — the Keycloak
   realm runs with `verifyEmail=false` + `registrationAllowed=true` (and
   `trustEmail=true` for social IDPs), so an account can be created without a
   verified email address. This is **accepted as residual**: the deployment has
   **no SMTP** to send verification mail, so email verification cannot be enforced
   operationally, and — critically — **email is not the billing identity**. Billing
   and all per-subject authorization key off the Keycloak `sub` (#82/#92 sub
   mapper), never the email claim, and free token issuance is closed (#87 SEC87a:
   a routing token costs ≥ `TOKEN_PRICE`; #87 SEC87b-auth: the durable-writer
   surface is gated). So an unverified-email account still cannot mint value for
   free; the exposure it adds over a verified-email realm is bounded to **funded
   sybil abuse**, which is already residual #1 above. If SMTP is added later,
   flip `verifyEmail=true` to raise the bar; until then, accepted residual.
6. **Operator-generated TLS keys for headless pipelines (#322)** — `docs/ops/runbook.md`'s
   "Authorize a new pipeline hostname (headless agents)" procedure has the operator run
   ACME DNS-01 (via their own `DESEC_TOKEN`) and generate a real Let's Encrypt cert +
   private key **on the operator's own machine**, then hand `fullchain.pem`/`privkey.pem`
   to the pipeline maintainer out of band. This is a genuine, acknowledged violation of
   ADR-0001 ("TLS private keys and certificates live only on the customer's Agent/Origin,
   never on the Edge") and ADR-0003 ("Operator-issued certificates are prohibited: they
   would place the decrypting key on the operator side") — for every tunnel onboarded
   this way, the "the operator cannot read your bytes" claim does not hold during the
   transient window the key exists on the operator's machine, until the pipeline
   maintainer rotates it themselves (they never do, in practice, since the delivered key
   is what their origin's Caddyfile serves indefinitely). This exists because headless
   pipeline agents (flappy-demo, cookbook-demo — no portal/Keycloak account, so no
   session to drive the self-serve `POST /portal/tunnels` flow) have no path to the
   properly zero-knowledge agent-side ACME flow ADR-0003 describes (the Agent generates
   its own keypair and drives its own ACME client; the operator only satisfies the DNS-01
   challenge, whose value derives from the ACME account-key thumbprint, never the
   certificate key). **The real fix is agent-side**: `authorize()` in
   `crates/control-plane/src/acme_broker.rs` gates the admission broker purely on
   routing-token ownership, not a Keycloak session — so a headless pipeline agent that
   already has a routing token (which `authorize-pipeline.sh` already mints) may already
   be able to drive `ct-agent`'s own ACME client against this control plane's existing
   `/agent/acme-admission/*` + DNS-01-challenge broker instead of the operator running
   certbot locally. **Not verified or implemented this pass** — it needs real testing
   against a live headless pipeline (flappy-demo or cookbook-demo) to confirm `ct-agent`'s
   ACME orchestration actually works unattended for a static-Caddyfile origin, which is a
   deliberate scope/testing decision, not a code change I want to make speculatively
   against a runbook procedure live pipeline maintainers currently depend on. Until that's
   done: accepted residual, now honestly documented instead of silently contradicting
   ADR-0001/0003.
