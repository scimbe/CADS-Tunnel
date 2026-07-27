# DNS-01 via deSEC (alternative to the self-hosted `ct-dns`)

For automatic Let's Encrypt certificates (the `:443` front-door cert #31 FD4, the
wildcard `*.<zone>`, and customer origin certs #23 BP4c) the ACME client needs to
publish `_acme-challenge` **TXT** records. Two interchangeable backends exist and
both stay supported — pick one with `CT_ACME_DNS_PROVIDER`:

- `self-hosted` — run our own authoritative DNS (`ct-dns`, see ADR-0019). Fully
  self-contained, no third party; you run public `:53`.
- `desec` — **deSEC** (<https://desec.io>), a free, EU-based, privacy-friendly
  managed DNS with a clean REST API. No `:53` to run; a third party hosts the zone.

This document sets up the **deSEC** option.

## 1. Create a deSEC account
1. Sign up at **<https://desec.io/signup>** (email + password; free, no payment).
   The account confirmation email contains your initial API token — keep it.
2. Log in to the dashboard.

## 2. Bring your domain under deSEC
You have two choices:

**A. Delegate your own domain (recommended for `bunsenbrenner.org`).**
1. In deSEC: **Domains → Add domain** → `bunsenbrenner.org`. deSEC shows the two
   nameservers to use: `ns1.desec.io` and `ns2.desec.org`.
2. At your registrar (Strato): **change the domain's nameservers** to
   `ns1.desec.io` and `ns2.desec.org`. This moves DNS hosting for the whole zone
   to deSEC (so you now manage A/AAAA/TXT there, via UI or API).
3. In deSEC, recreate your routing records (this replaces the Strato entries):
   - `A  @   → 45.133.9.145`  (the apex)
   - `A  *   → 45.133.9.145`  (wildcard — all customer subdomains hit the plane; #31)
   NS propagation can take a while; verify with `dig +short NS bunsenbrenner.org @1.1.1.1`.

**B. Use a free `dedyn.io` name** (quickest, for testing): claim e.g.
`yourname.dedyn.io` in deSEC and use that as the zone. No registrar changes.

> Delegating to deSEC replaces Strato as your DNS host and removes the need for
> the acme-dns glue/subzone delegation in the self-hosted path (#33). You then no
> longer run `ct-dns` at all.

## 3. Create a scoped API token
1. deSEC dashboard → **Token Management → Create token**.
2. Optionally **restrict it**: limit to the domain `bunsenbrenner.org` and to the
   subname pattern `_acme-challenge*` — least privilege, so a leaked token can only
   touch challenge records.
3. Copy the token value (shown once).

## 4. Configure the `.env` — which file, exactly

The vars must go in the `.env` that the **running service actually loads** — this
differs by deployment mode, so put them in the right place:

- **Self-host Compose** (the usual case): the stack loads **`docker/deploy/.env`**
  (`compose.selfhost.yml` runs with `--env-file docker/deploy/.env`). A root
  `./.env` is **NOT** read by the containers — a token placed there is silently
  ignored. Put the deSEC vars in `docker/deploy/.env`:
  ```bash
  # first-time setup copies the deploy example (then you edit secrets):
  cp docker/deploy/.env.example docker/deploy/.env       # if not already done
  # append the deSEC block from the reference template, then edit the token:
  cat config/desec.env.example >> docker/deploy/.env
  ${EDITOR:-nano} docker/deploy/.env                     # set DESEC_TOKEN=...
  ```

- **Standalone / bare process**: export the vars in the environment of whatever
  launches the ACME client (systemd `EnvironmentFile=`, a shell `export`, etc.).
  `config/desec.env.example` is the reference template for the exact variable names.

Required keys (**never commit the real token**):
```dotenv
CT_ACME_DNS_PROVIDER=desec
DESEC_TOKEN=<your deSEC API token>
DESEC_DOMAIN=bunsenbrenner.org
# DESEC_API_BASE=https://desec.io/api/v1   # default; only override for testing
```

The token is read at startup and never logged. The service that **consumes**
`DESEC_TOKEN` (the ACME client) lands with **#31 FD4**; the authoritative location
above is stable, so you can set the token now. What the client does under the
hood (for reference): a bulk **`PATCH https://desec.io/api/v1/domains/<zone>/rrsets/`**
with `Authorization: Token <token>` and a body like
`[{"subname":"_acme-challenge","type":"TXT","ttl":3600,"records":["\"<value>\""]}]`
to publish, and the same with `"records":[]` to clean up. (This is exactly what
`ct_dns::provider::DesecClient` sends; verified in its tests against a mock.)

## 5. Verify
After a cert run publishes a challenge, from anywhere:
```bash
dig +short TXT _acme-challenge.bunsenbrenner.org @1.1.1.1
```
It should return the current challenge value. Once resolution works, Let's Encrypt
DNS-01 validates and the certificate issues/renews automatically.

## Using `acme.sh` for the front-door Portal cert (BYO)

The `:443` front door's Portal cert (`PORTAL_CERT_DIR`, see the
[runbook](ops/runbook.md)) is BYO — obtained with an external ACME client, not
by the tunnel's own services. `scripts/deploy-selfhost.sh --frontdoor` automates
this with [`acme.sh`](https://github.com/acmesh-official/acme.sh)'s `dns_desec`
hook. **Gotcha**: that hook reads `DEDYN_TOKEN`, not `DESEC_TOKEN` — a holdover
from deSEC's `dedyn.io` dynamic-DNS naming. The deploy script sets both (it
exports `DEDYN_TOKEN` from `DESEC_TOKEN` before calling `acme.sh`); doing this
by hand instead, remember to `export DEDYN_TOKEN=<your deSEC token>`.

## Which to choose
- **deSEC**: least operational effort, robust (deSEC runs anycast NS), no `:53` to
  expose — at the cost of a third party hosting your zone (still zero-knowledge for
  tunnel payload; DNS never sees payload).
- **Self-hosted `ct-dns`**: no third party, fully self-contained — at the cost of
  running/securing public `:53` and ideally ≥2 nameservers.

Related: #31 (universal :443 / FD4), #23 (Browser Plane / BP4c), #30/#33 (domain
+ reachability), ADR-0019.
