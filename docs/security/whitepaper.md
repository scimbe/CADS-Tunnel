# CADS Tunnel — security whitepaper

A concise, customer-facing account of how CADS Tunnel protects your traffic and
your account. Every mechanism named here is implemented and tested; deeper detail
lives in the linked documents.

## Summary

- Payload is **end-to-end encrypted** (Noise) — the operator relays ciphertext
  and cannot read your bytes.
- Transport is **TLS everywhere** — QUIC/TLS 1.3 to the edge, HTTPS to the
  control plane; nothing external is plaintext.
- Access is **authenticated** with Keycloak/OIDC bearer tokens.
- Certificates come from an **internal CA** and rotate without client changes.
- **Abuse controls** (proof-of-work + per-account rate limits) protect
  availability.
- **Payments are provider-signed** — the control plane can never credit an
  account on its own.
- Dependencies are **audited and pinned**; no secrets are committed.

## 1. Payload confidentiality (end-to-end)

The client and your origin establish a Noise session
(`Noise_IK_25519_ChaChaPoly_BLAKE2s`) and exchange only ciphertext through the
edge and control plane. The operator can route and bill your traffic but cannot
decrypt it — this is a cryptographic property, not a policy promise.
_Detail: `crates/common/src/noise.rs`, [threat model](threat-model.md)._

## 2. Transport security (TLS everywhere)

- Client/agent ↔ edge: QUIC (TLS 1.3), with a TLS-over-TCP fallback.
- External ↔ control plane: HTTPS terminated at the ingress; HTTP is redirected.
- The control plane's plain HTTP never leaves the cluster.
_Detail: [TLS everywhere](tls-everywhere.md)._

## 3. Identity & authentication

The `/me/*` endpoints require a Keycloak/OIDC bearer token, verified as **RS256**
against the realm's public key (issuer and expiry checked). The account is derived
from the token subject, so a caller can only ever act on their own account.
_Detail: `crates/control-plane/src/oidc.rs`._

## 4. Public-key infrastructure

The edge runs an internal certificate authority; clients trust the **CA root**,
not a pinned leaf, so the edge can rotate its certificate with no client change.
_Detail: `crates/edge/src/pki.rs`._

## 5. Availability & abuse resistance

- A proof-of-work gate raises the cost of rendezvous floods.
- Per-account (per-subject) fixed-window rate limiting stops one account from
  exhausting token issuance (`429` before any ledger access).
_Detail: `crates/common/src/ratelimit.rs`._

## 6. Payment integrity

Credits are applied only when a payment-provider webhook's HMAC-SHA256 signature
verifies against the shared secret and its timestamp is fresh (replay-protected).
The control plane cannot self-credit; if no webhook secret is configured, every
webhook is rejected (fail-safe).
_Detail: `crates/control-plane/src/payment_provider.rs`, [payment integration](../payment/integration.md)._

## 7. Supply chain & secrets

- `cargo audit` runs against a committed, pinned `Cargo.lock`.
- A committed-secrets guard blocks credential material from entering the repo;
  real secrets live only in the deployment environment.
_Detail: [dependency audit](dependency-audit.md), `scripts/check-no-secrets.sh`._

## What is out of scope

Consistent with our [positioning](../product/positioning.md), we do not claim
anonymity, metadata blindness (the operator sees routing and billing metadata),
or immunity from censorship or lawful process. See the
[threat model](threat-model.md) for residual risks (e.g. funded sybil abuse).
