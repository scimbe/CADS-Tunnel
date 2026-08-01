# 0012. Minimal, pseudonymous, crypto-friendly identity

Status: accepted for self-hosted deployments that don't enable Keycloak/OIDC; superseded
for the **hosted default** by [ADR-0022](0022-hosted-identity-pivot.md), which requires a
real Keycloak/OIDC account to reach the (still-pseudonymous, still-PII-free) ledger
identity described below, and drops the cryptocurrency payment rail in favor of
provider-signed webhooks. (supersedes ADR-0009)

A censorship-resistance ICP cannot require the risk-based KYC of the superseded ADR-0009 — those users are fleeing identification. Accounts are therefore pseudonymous by default (email or a generated account identity), and payment accepts privacy-preserving methods including cryptocurrency. No government-ID KYC is mandated. Because a payment card is no longer required, sybil resistance shifts from payment-instrument identity to other levers.

## Consequences

- Mainstream card processors may decline the account; crypto and privacy-friendly rails become primary, shaping billing design.
- Identifiability for law enforcement drops to whatever a Lawful Floor order can compel from thin metadata; this is an accepted property, not a defect.
- Sybil/abuse control must not rely on KYC — an alternative (proof-of-work, modest prepaid credit, or resource/rate caps) is an open sub-branch.
