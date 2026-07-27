# CADS Tunnel — what it is and why it's different

A tunnel that exposes a local service (any TCP/UDP) to clients through a thin
hosted control plane, with the payload encrypted end-to-end so the operator can
route your traffic but never read it.

Every claim below is backed by something the code actually does — see the linked
proof. We deliberately do **not** market anything we can't stand behind (see
"What we don't claim").

## Selling points

### We can't read what you send
Payload is encrypted **end-to-end** with Noise (client ↔ origin). The edge and
control plane relay only ciphertext — operator access to your bytes is
cryptographically impossible, not a policy promise.
_Proof: `crates/common/src/noise.rs`; [threat model](../security/threat-model.md)._

### Onboard in one command
Install → enroll → tunnel in a single step: the agent generates its own identity,
redeems a join token, and starts serving. The operator handles one short-lived
secret.
_Proof: `ct-agent onboard`; [quickstart](../onboarding/quickstart.md)._

### Deploy your way
Run it fully hosted, or self-host the core with one compose file. Same binaries,
same protocol.
_Proof: `docker/deploy/k8s/` (hosted) and `docker/deploy/compose.selfhost.yml` (self-host)._

### Durable and self-healing
State (accounts, enrollment, tunnel registry, credit ledger) is persisted and
survives restarts; liveness/readiness probes keep unhealthy instances out of
rotation.
_Proof: SQLite stores in `crates/control-plane/src/storage.rs`; `/healthz` + `/readyz`._

### Certificate rotation without re-pinning
The edge runs an internal CA; clients trust the CA root, so edge certificates
rotate without any client change.
_Proof: `crates/edge/src/pki.rs`; [TLS everywhere](../security/tls-everywhere.md)._

### Abuse-resistant
A proof-of-work gate plus per-account rate limits keep a single account from
exhausting the service.
_Proof: `crates/common/src/ratelimit.rs`; `pow` gate; per-subject limit on `/me/issue`._

### Payments you can trust
Credits are applied only from a payment-provider webhook whose signature we
verify — the control plane can never credit an account on its own.
_Proof: `crates/control-plane/src/payment_provider.rs`; [payment integration](../payment/integration.md)._

## What we don't claim

Honesty is part of the pitch. We do **not** claim:

- **Anonymity / pseudonymity.** Accounts are conventional (Keycloak/OIDC). The
  operator knows who you are for billing; the honest claim is confidentiality of
  the payload, not anonymity of the user.
- **Metadata blindness.** The control plane sees routing and billing metadata
  (account, tunnel, byte counts) — just not payload contents.
- **Censorship immunity or immunity from lawful process.** Those are operational
  and jurisdictional questions, out of scope for the software (SPEC §9).

## Who it's for

Teams that need to expose a service to clients over untrusted networks and want
provider-blind payload confidentiality, simple onboarding, and the choice to
self-host — without buying into anonymity claims they can't verify.
