# 0002. Zero-knowledge boundary: payload-blind, metadata-visible

Status: accepted

The zero-knowledge guarantee is scoped to **payload** confidentiality and integrity: the operator can never read or alter tunneled bytes, once a tunnel has reached its steady state. In browser mode the Edge must read the TLS SNI from the ClientHello to route the connection, and it can observe per-tunnel timing and byte volume. We therefore document that hostname and traffic-shape metadata are visible to the operator, rather than claim total blindness.

## Consequences

- Marketing and docs must state the metadata caveat plainly; overclaiming "we see nothing" is prohibited.
- Encrypted Client Hello (ECH) is incompatible with browser-mode routing, since the Edge needs the SNI to route.
- Metadata-sensitive customers are directed to the v2 client-software mesh plane, which can conceal the hostname via opaque routing tokens.
- **Gelb-tier admission window is a real, narrower exception to the payload-confidentiality guarantee above, not just metadata visibility.** Before a hostname's own certificate is issued (Rot → Gelb → Grün, #233), the Edge terminates the browser's TLS itself using a shared front-door wildcard certificate (`serve_gelb_terminated`, `crates/edge/src/serve.rs`) and relays the DECRYPTED bytes onward — the customer's own origin serves plain HTTP during this window. This is not a passive observation like SNI/timing: the operator's edge process actively holds the private key that decrypts the customer's traffic for the duration the hostname stays Gelb. Verified against the actual deployment (2026-08-30): `CT_EDGE_WILDCARD_KEY` (`docker/deploy/compose.frontdoor.yml`) mounts a host-path private key file directly into the edge container, and `scripts/issue-wildcard-cert.sh`'s own header names it "the single, low-volume, **operator-owned** certificate". Once the control plane flips a hostname to Grün (`state.set_cert_tier`), new connections revert to `serve_sni_passthrough` (raw-TLS passthrough, no operator decryption) and the origin serves its own, now-issued certificate again — the exception is time-bounded to the admission window, not permanent, but it is real and must be disclosed alongside the metadata caveat above, not folded into it.
