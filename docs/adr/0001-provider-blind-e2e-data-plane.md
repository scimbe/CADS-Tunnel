# 0001. Provider-blind, end-to-end encrypted data plane

Status: accepted

CADS Tunnel's core differentiator is zero-knowledge: the operator must never be able to read customer traffic. We therefore terminate encryption at the customer's Origin, and the Edge relays ciphertext only — it never holds the customer's TLS private keys and never decrypts payloads. This is the deliberate opposite of Cloudflare Tunnel, whose edge terminates TLS in order to offer WAF, caching, and inspection.

## Consequences

- We forgo all L7 edge features (WAF, caching, request-level routing, operator-managed TLS certificates).
- Edge routing must operate on data visible without decryption (e.g. the TLS SNI in the ClientHello, or connection-level metadata) — see later ADRs.
- TLS private keys and certificates live only on the customer's Agent/Origin, never on the Edge.
