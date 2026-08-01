# 0022. Hosted-deployment identity & payment pivot (supersedes ADR-0012 for the hosted default)

Status: accepted (supersedes ADR-0012 for the hosted default deployment; ADR-0012's
architecture remains available to self-hosters who choose not to enable the Keycloak/OIDC
overlay, see Consequences)

## Context

ADR-0012 committed to pseudonymous-by-default accounts, no mandatory government-ID KYC,
and crypto-friendly payment, reasoning that a censorship-resistance ICP cannot require the
risk-based KYC of the superseded ADR-0009. Productionization needed a real payment-provider
relationship (`crates/control-plane/src/payment_provider.rs`, HMAC-signed webhooks) —
exactly the "mainstream card processors may decline the account" friction ADR-0012 itself
predicted — and `docs/security/threat-model.md` and `docs/security/whitepaper.md` now both
describe the hosted deployment's actual identity model as "conventional Keycloak/OIDC
accounts everywhere." ADR-0012 was never formally superseded to reflect this, so the ADR
set contradicted the shipped system in a load-bearing identity property (#323).

## Decision

For the **hosted default deployment**, ADR-0012's pseudonymous-account model is superseded:
logging in and authorizing `/me/*` requires a real Keycloak/OIDC bearer token
(`crates/control-plane/src/oidc.rs`), typically backed by an email-based identity provider.

This is narrower than "pseudonymity is gone," though — two things did **not** change:

- The **ledger/billing identity stays pseudonymous**: `crates/control-plane/src/accounts.rs`
  addresses every account by an opaque, random `AccountId` and stores no PII in the ledger
  itself. What changed is that *reaching* that pseudonymous account now requires passing
  through a real-identity gate (Keycloak `sub`, mapped via
  `SqliteLedger::account_for_subject`) — the gate is new, not the ledger.
- Per the accepted residual in `threat-model.md` #5 (SEC89b), the Keycloak realm doesn't
  even enforce *verified* email — billing and authorization key off the `sub` claim, never
  the email, specifically so an unverified account still can't be more valuable to a sybil
  than a pseudonymous one was.

What genuinely and materially changed from ADR-0012's stated consequences:

- **Payment**: no cryptocurrency rail is implemented. Payment is exclusively
  provider-signed webhooks (`docs/payment/integration.md`) — a real payment processor
  relationship, which typically implies real-world payment-instrument identity upstream of
  this system even though CADS Tunnel itself never stores it.
- **Law-enforcement identifiability**: ADR-0012 said this "drops to whatever a Lawful Floor
  order can compel from thin metadata." With a real OIDC identity provider in front of the
  account, a Lawful Floor order can now compel whatever *that* IdP holds (email, sign-up IP,
  etc.) — a real increase in identifiability versus ADR-0012's original design, not just a
  documentation update.

**Crypto payment's roadmap status is explicitly left open by this ADR** — not decided
either way. This is a product decision for the operator, not something to resolve by
documentation fiat; a future ADR (or an amendment to this one) should record that decision
if/when it's made.

**Reconciling ADR-0011**: the finding that prompted this ADR read ADR-0011's
censorship-resistance framing as built on ADR-0012's pseudonymity. On re-reading ADR-0011
itself, its actual mechanism — terminating only at a binding Lawful Floor order, refusing
discretionary/third-party-pressure takedowns — is a statement about the **operator's
enforcement policy**, not about the identity model. That policy is unaffected by this
pivot: a Keycloak-authenticated account is terminated under exactly the same Lawful-Floor-
only rule a pseudonymous one would have been. ADR-0011 does not need superseding here; only
the identifiability *consequence* noted above changes.

## Consequences

- Update ADR-0012's own status line to reference this ADR (done, see that file).
- The whitepaper and threat model already describe the post-pivot reality accurately; no
  further doc changes needed beyond this ADR and ADR-0012's status-line update.
- **Self-hosted deployments retain the choice**: the Keycloak/OIDC overlay
  (`docker/deploy/compose.sso.yml`) is off by default — "a separate overlay you opt into by
  naming it explicitly" per its own header comment — so a self-hoster who doesn't enable it
  runs the control plane's pseudonymous-account path largely as ADR-0012 originally
  described (modulo whatever payment mechanism they configure). This ADR is specifically
  about the *hosted default*'s posture, not a claim that ADR-0012's architecture was deleted.
- If crypto payment is later decided for-or-against, record that decision explicitly rather
  than leaving it implicit in what shipped.
