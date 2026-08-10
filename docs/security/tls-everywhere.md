# TLS everywhere

Encryption posture for every hop, and how the deployment enforces it (M23.4).

## Hops

| Hop | Protection | Enforced by |
|-----|-----------|-------------|
| Client ↔ Origin (payload) | **End-to-end Noise_IK** — the operator never sees plaintext | ct-common noise / M8 |
| Client/Agent ↔ Edge | QUIC (TLS 1.3) with a TLS-over-TCP fallback; edge cert chains to the internal CA | ct-edge transport / M20 |
| External ↔ Control-plane API | **HTTPS terminated at the edge's `:443` front door**, both hosted and self-host; plaintext HTTP is redirected to HTTPS | edge `:443` front door (both deployments) — or the alternate `control-plane-ingress.yaml` (hosted, opt-in, see below) / a reverse proxy of your own (self-host) |
| Edge front door ↔ Control-plane (in-cluster / internal network) | Cluster-internal only (hosted) or the Docker internal network (self-host); optionally mTLS via a service mesh (hosted) | cluster network policy / Docker network isolation |

The only component that speaks plain HTTP is the control-plane API, and it is
never exposed directly: **both** the hosted and self-host bundles terminate TLS
at the edge's own `:443` front door and reverse-proxy plaintext HTTP to the
control plane over the internal network. So no external hop is ever plaintext.

## Hosted (Kubernetes)

**#309**: the hosted (k8s) deployment now uses the SAME mechanism as self-host
— the edge's unified `:443` front door (ADR-0019) — as its default, sole public
TLS-terminating entry point, not a separate `Ingress`. This is a deliberate
architecture choice made on #309: an `Ingress` object can't carry the tunnel
data plane or the Agent-Fabric channel broker (neither is HTTP), and running
an `Ingress` *alongside* the edge's own terminate-mode side by side for the
same public hostname would be two independent TLS terminators racing for one
DNS name — see `docker/deploy/k8s/kustomization.yaml`'s header for the full
reasoning.

- `docker/deploy/k8s/edge-config.yaml`'s `CT_EDGE_PORTAL_HOST`/`CT_CP_PROXY_ADDR`
  configure which SNI hostname the front door terminates and reverse-proxies —
  same env vars, same mechanism as the self-host front door below.
- `docker/deploy/k8s/edge-certificate.yaml` requests the Portal's TLS cert via a
  cert-manager `Certificate` + DNS-01 `ClusterIssuer` (matching ADR-0019's own
  DNS-01 cert-issuance mechanism), writing to the `ct-edge-portal-tls` Secret
  the edge mounts. No cert-manager? Create that Secret yourself, out-of-band —
  see that file's header.
- `docker/deploy/k8s/edge-deployment.yaml` reads the shared
  `CT_EDGE_ADMIN_TOKEN`/`CT_CP_EDGE_ADMIN_TOKEN` from the `ct-edge-admin-token`
  Secret — also supplied out-of-band, never committed. See
  `kustomization.yaml`'s header for the exact `kubectl create secret` command.

**Alternate path**: `docker/deploy/k8s/control-plane-ingress.yaml` (a
conventional `ingress-nginx` + `cert-manager` `Ingress`, `spec.tls[].secretName`
= `ct-control-plane-tls`) is kept in the directory but **not** in
`kustomization.yaml`'s default resource list — an operator who prefers it over
the edge's `:443` mux can opt back in; see that file's header for how, and why
not to run both for the same hostname at once.

Render/validate offline:

```bash
kubectl kustomize docker/deploy/k8s
```

## Self-host

Add the optional `:443` front-door overlay
(`docker/deploy/compose.frontdoor.yml`, #31/#60): the edge itself terminates
HTTPS with a BYO certificate (`CT_EDGE_PORTAL_CERT`/`CT_EDGE_PORTAL_KEY`) and
reverse-proxies the Portal to `control-plane:8090` (`CT_CP_PROXY_ADDR`); see
the [runbook](../ops/runbook.md#deploy). A separate TLS reverse proxy (Caddy,
nginx, Traefik) in front of `control-plane:8090` works too if you'd rather not
use the built-in front door. Either way, do **not** publish port 8090 to the
public internet directly.

## Checklist before exposing a deployment

- [ ] Control-plane API reachable only via HTTPS (ingress / proxy), never :8090 directly.
- [ ] Valid, auto-renewing server certificate (cert-manager or equivalent).
- [ ] HTTP→HTTPS redirect on.
- [ ] Edge reachable on 4433 (QUIC + TLS-TCP); clients hold the edge CA root.
