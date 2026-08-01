# CADS Tunnel

CADS Tunnel is a zero-knowledge, censorship-resistant network-tunnel SaaS: it exposes services running behind NAT or firewalls **without the operator ever being able to read the tunneled traffic**, and it resists discretionary takedown. The primary (v1) access model is a client-software **Mesh Plane** that also hides routing metadata; anonymous-browser exposure is a later plane.

## Language

**Tunnel**:
A persistent, provider-blind channel carrying traffic between a private Origin and public Clients via the Edge. The Edge relays ciphertext only.
_Avoid_: Connection, pipe, link

**Zero-Knowledge (Provider-Blind)**:
The property that the operator can never read or alter tunneled **payload**. Payload encryption terminates at the customer's Origin, never at the Edge. Scoped to payload only: in browser mode the operator still observes routing metadata (SNI hostname, per-tunnel timing and byte volume).
_Avoid_: End-to-end (ambiguous), secure, encrypted-in-transit

**Metadata (observable)**:
The connection facts the operator can still see despite provider-blindness. In the Mesh Plane (v1), opaque-token routing hides the hostname; and when a direct peer-to-peer path is established the operator sees only the brief Rendezvous coordination, not per-connection timing or volume. Only when traffic falls back to Edge relay does the operator observe per-tunnel timing and byte counts. In the Browser Plane (later), the SNI hostname is additionally visible because the Edge must read it to route.
_Avoid_: Logs, headers, sidechannel

**Agent**:
The customer-run software that opens outbound connections from the private network to the Edge and forwards traffic to the local Origin. Custodian of the customer's key material.
_Avoid_: Connector, cloudflared, daemon, client

**Origin**:
The private service the customer wants to expose. Encryption terminates here.
_Avoid_: Backend, upstream, target, service

**Edge**:
The operator-run, publicly reachable node that coordinates Client↔Agent Rendezvous and relays ciphertext only as a fallback when a direct path fails. Never in the trust path; cannot decrypt.
_Avoid_: Relay, gateway, server, PoP

**Rendezvous**:
The Edge-coordinated NAT-traversal exchange that lets a Client and Agent establish a direct peer-to-peer path. After a successful Rendezvous the operator is out of the data path entirely.
_Avoid_: Signaling, STUN, discovery

**Client**:
The end-user or system that reaches an exposed Origin through a Tunnel. In the Mesh Plane (v1) the Client runs operator software; in the Browser Plane (later) it is any TLS-capable browser or tool.
_Avoid_: Visitor, user (reserve "user" for the customer's account holder)

**Mesh Plane**:
The v1 access model: Clients run operator software and reach Origins over a fully client-authenticated tunnel, routed by opaque token rather than hostname. Supports any protocol (TCP/UDP) and hides the routing hostname from the operator.
_Avoid_: VPN, overlay

**Browser Plane**:
The later access model: anonymous browsers reach an Origin via SNI-routed TLS passthrough. Cannot hide the SNI hostname from the operator.
_Avoid_: Public mode, web mode

**Lawful Floor**:
The only grounds on which the operator will Terminate: a narrow, binding legal order in its jurisdiction, or verified CSAM. Discretionary complaints, political pressure, and third-party abuse feeds are explicitly out of scope.
_Avoid_: Abuse policy, moderation (the AUP documents the Lawful Floor, it is not additional grounds)

**Routing Token**:
The opaque identifier that addresses a Tunnel in the Mesh Plane. It routes a Client to the right Agent without revealing a hostname to the operator.
_Avoid_: Hostname, SNI, subdomain (those are Browser-Plane concepts)

**Origin Identity**:
The Origin's static Noise public key, pinned by Clients to authenticate the Origin end-to-end. Distinct from the Agent Identity used for control-plane/Edge auth.
_Avoid_: Server key, cert, fingerprint

**Capability**:
A self-contained connection grant — Routing Token + Origin Identity + Edge address — that the customer generates and distributes out of band to authorized Clients. Possession is sufficient to reach and authenticate an Origin; revocation is by rotating its Token or key.
_Avoid_: Link, invite, credential, ticket

**Tenant**:
The customer account that owns Agents, hostnames, and Tunnels; the unit of authorization and isolation.
_Avoid_: Account, org, customer (customer is the informal human/company; Tenant is the boundary)

**Join Token**:
A single-use, dashboard-issued secret that bootstraps one Agent's enrollment; exchanged once for a bound Agent Identity, then discarded.
_Avoid_: Authtoken, API key, secret

**Agent Identity**:
The per-Agent keypair, bound to a Tenant at enrollment, from which short-lived mTLS credentials are minted for control-plane and Edge authentication. Distinct from the Origin's TLS certificate.
_Avoid_: Credential, cert (ambiguous with the Origin cert)

**Tunnel Registry**:
The authoritative mapping from a hostname to the Edge node currently holding that hostname's live Agent tunnel; consulted to route each incoming Client connection.
_Avoid_: Routing table, directory, DNS (it is not DNS)

**Control Plane**:
The operator's thin coordination service: Agent enrollment, the Tunnel Registry, the Rendezvous endpoint, and billing. It holds no Agent/CA private keys and never sees payload, and is designed to be self-hostable so customers can survive operator takedown. It is not trust-material-free, though: where configured, it holds the credential-issuer signing key, per-CA ACME EAB credentials, and a DNS-provider token — operator secrets requiring the same protection/rotation as any other (#266).
_Avoid_: Backend, API, server (too generic); the dashboard is one client of it, not the Control Plane itself

**Termination**:
The operator's sole enforcement action: refusing to route a hostname or Tenant. Because the operator is provider-blind there is no content-level remediation — enforcement is all-or-nothing. Applied only at the Lawful Floor; the operator does not terminate on discretionary or third-party pressure.
_Avoid_: Ban, block, filter, takedown (takedown implies content removal we cannot do)
