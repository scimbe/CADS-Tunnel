# 0003. Agent-held certificates via ACME, with bring-your-own-cert fallback

Status: accepted, implemented

To keep the operator provider-blind, the TLS private key for every public hostname must live only on the customer's Agent. By default the Agent generates the keypair and obtains a publicly-trusted certificate via ACME (Let's Encrypt); the operator assists only by satisfying the DNS-01 challenge in the operator-controlled zone. The DNS-01 challenge value derives from the ACME account-key thumbprint, not the certificate key, so the operator never sees key material that could decrypt traffic. Strict or air-gapped customers may instead supply their own certificate and key directly to the Agent. Operator-issued certificates are prohibited: they would place the decrypting key on the operator side and break Decision 1.

## Consequences

- The operator must run authoritative DNS for the tunnel apex and expose an authenticated API letting an Agent place DNS-01 TXT records for its own hostnames only.
- The Agent must implement an ACME client with auto-renewal, plus a bring-your-own-cert loader.
- Custom domains require the customer to delegate `_acme-challenge` (CNAME) so the Agent can complete DNS-01 for their domain.

## Implementation

- `crates/agent/src/acme_jws.rs` — ES256 JWS signing (RFC 7515) for every ACME
  protocol request, plus the account key's RFC 7638 JWK thumbprint (the input to
  the DNS-01 `keyAuthorization`).
- `crates/agent/src/acme_client.rs` — the full RFC 8555 order state machine:
  directory discovery, account registration, order/authorization/challenge,
  polling, finalize, certificate download. Hermetically tested against a mock
  ACME server (no network, no rate limits); a live smoke test against Let's
  Encrypt's **staging** directory is the separate manual check before ever
  pointing this at production for a new deployment.
- `crates/dns/src/provider.rs`'s `Dns01Provider::RemoteAgent` — the piece that
  actually satisfies "an authenticated API letting an Agent place DNS-01 TXT
  records for its own hostnames only": the agent proves ownership with its
  tunnel's own **routing token**, never a DNS credential.
- `crates/control-plane/src/dns01_challenge.rs` — the control-plane side of that
  API (`POST /agent/dns01-challenge(/clear)`), authorized via
  `edge_mesh::token_owns_hostname` (the same durable ownership registry every
  hostname authorization already feeds) — so it can only ever touch
  `_acme-challenge.<hostname-the-caller-owns>`.
- `crates/agent/src/acme_orchestrate.rs` + the `ct-agent certificate` subcommand
  — obtain-or-renew (file-age based) and writes `fullchain.pem`/`privkey.pem`
  where the origin's own webserver already expects a static cert pair; no new
  TLS-termination code was added to `ct-agent` itself. See
  `docs/dns01-desec.md`'s "Self-service agent certificates" section for the
  operator-facing walkthrough.
- The bring-your-own-cert fallback (an Agent loading a certificate/key supplied
  directly, not via ACME) remains exactly as documented — nothing about it
  changed.
