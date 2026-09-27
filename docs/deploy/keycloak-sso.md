# Keycloak SSO demo (#42)

Turn the customer portal's `Sign in with SSO` into a real, clickable
Authorization-Code login backed by a Keycloak identity provider. This is the
optional SSO overlay from `docker/deploy/compose.sso.yml`; the base self-host
stack runs unchanged without it.

## What ships in-repo

- `docker/deploy/compose.sso.yml` — the Keycloak service (image pinned in that file's
  `keycloak` service, currently `quay.io/keycloak/keycloak:26.7.3`; `scripts/validate-realm-import.sh`
  derives its default validation image from there so the two never drift apart, `start-dev
  --import-realm`) plus the `CT_OIDC_*` env merged onto the control-plane.
- `docker/deploy/keycloak/ct-demo-realm.json` — a declarative realm `ct-demo` with a
  confidential RS256 client `ct-portal` and self-registration enabled. Its secret is
  **pinned to `${KC_PORTAL_CLIENT_SECRET}`** (#65) — no literal is baked in, but
  Keycloak adopts that exact value on every (re)import, so it stays stable across the
  ephemeral realm's recreates and never drifts from the control-plane.

The control-plane verifies tokens by fetching the realm's RS256 signing key from
its JWKS at startup (`CT_OIDC_ISSUER` alone is enough; no PEM export needed).

## Keycloak is served through the `:443` front door (#48)

Keycloak no longer publishes its own port. It's reached on its **own hostname**
(`auth.<zone>`) through the edge's unified `:443` front door — the edge terminates
TLS for `auth.<zone>` with a BYO cert and reverse-proxies to `keycloak:8080`
internally, exactly like it does for the Portal (FD4-a).

This solves the split-horizon that a published-port setup hit: the realm
**issuer** (`<KEYCLOAK_PUBLIC_URL>/realms/ct-demo`) is baked into every token's
`iss` and is where both the browser (login redirect) and the control-plane
(JWKS + token endpoint) talk to Keycloak — and now both go through the **same**
public URL `https://auth.<zone>`, reachable identically from an external browser
and from the control-plane container.

- ✅ `KEYCLOAK_PUBLIC_URL=https://auth.bunsenbrenner.org` — the front-door hostname.
- ❌ `http://localhost:8091` / an internal `172.x` IP — the browser can't reach it
  (or the control-plane can't), so the login redirect points somewhere unreachable
  and/or the boot-time JWKS fetch fails (`the realm JWKS had no usable RS256 key —
  /me/* disabled` in the control-plane logs).

**Prereq:** the edge must already run the front door for the Portal (FD4-a):
`CT_FRONT_DOOR=0.0.0.0:443` + `CT_EDGE_PORTAL_HOST`/`CT_CP_PROXY_ADDR`/
`CT_EDGE_PORTAL_CERT`|`_KEY`. This overlay adds the Auth route to it. Point
`auth.<zone>`'s DNS at the edge, and get a BYO cert for it the same way as the
Portal's (deSEC DNS-01).

## `.env` keys (add to `docker/deploy/.env`)

```dotenv
# Keycloak's own front-door hostname (its DNS points at the edge :443).
AUTH_PUBLIC_HOST=auth.bunsenbrenner.org
KEYCLOAK_PUBLIC_URL=https://auth.bunsenbrenner.org
# Host dir holding the BYO cert for auth.<zone>: fullchain.pem + privkey.pem.
AUTH_CERT_DIR=/etc/ct/certs/auth
# Portal base URL the browser uses.
PORTAL_PUBLIC_URL=https://bunsenbrenner.org
# The ct-portal client secret (#65). Pick any random hex ONCE (e.g. `openssl rand
# -hex 32`); Keycloak imports this exact value and the control-plane uses the same
# var for the code->token exchange, so they never drift across a Keycloak recreate.
KC_PORTAL_CLIENT_SECRET=<random-hex-you-choose>
# Optional (#43): restrict who may self-register, by email domain.
CT_PORTAL_ALLOWED_EMAIL_DOMAINS=becke.biz
# Keycloak admin console creds (change for anything reachable).
KC_ADMIN_USER=admin
KC_ADMIN_PASSWORD=change-me
```

`CT_OIDC_ISSUER`, `CT_OIDC_CLIENT_ID`, and `CT_OIDC_REDIRECT_URI` are derived from
`KEYCLOAK_PUBLIC_URL` / `PORTAL_PUBLIC_URL` in the compose overlay — you don't set
them directly.

## Bring it up

```bash
docker compose \
  -f docker/deploy/compose.selfhost.yml \
  -f docker/deploy/compose.frontdoor.yml \
  -f docker/deploy/compose.sso.yml \
  --env-file docker/deploy/.env up --build -d
```

1. Wait for Keycloak to become healthy (`docker compose ... ps`); the realm
   imports on first boot.
2. If the control-plane started before Keycloak was ready and logged OIDC as
   disabled, restart it: `docker compose ... restart control-plane` — it re-fetches
   the JWKS. (A boot-time retry is a possible follow-up.)
3. **Client secret (#65)**: you no longer copy a Keycloak-minted secret. Set
   `KC_PORTAL_CLIENT_SECRET=<random hex>` in `.env` **once** — Keycloak imports that
   value for `ct-portal` on every realm (re)import and the control-plane reads the
   same var, so the two stay in sync automatically. After a Keycloak recreate you do
   **not** need to re-sync anything; just make sure any `.env` change is picked up by
   recreating the affected service (`docker compose ... up -d`), not `docker restart`
   (which reuses the container's original baked-in env and does not re-read `.env`).

## Click-through

1. Open `PORTAL_PUBLIC_URL/portal` → **Sign in with SSO**.
2. Keycloak login page → **Register** (self-registration is on) → create an
   account (if `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` is set, use an allowed domain).
3. Back to `/portal/home` — signed in. From there: account, tunnels, installer.
4. **Sign out** clears the session cookie and returns to the shell.

If a non-allowed email is used with `CT_PORTAL_ALLOWED_EMAIL_DOMAINS` set, the
callback returns a clear "not on the access list" page and mints no session (#43).

## Social login / identity brokering (#49)

The `ct-demo` realm ships with **Google, GitHub, GitLab, and HAW GitLab**
identity providers declared (see `keycloak/ct-demo-realm.json`), but not all of
them show up on the public login page. Once you supply real OAuth-app
credentials, **Google and GitHub** grow "Sign in with Google / GitHub" buttons
on Keycloak's normal login page alongside the local account form — **no
control-plane change**, and `#43`'s email-domain allow-list still gates access
using whatever `email` the broker passes through (the providers set
`trustEmail`).

**GitLab** (the generic `gitlab.com`-style provider) is declared but currently
**disabled** (`enabled: false`) on this deployment — flip it on in the admin
console if you want it live.

**HAW GitLab** (`git.haw-hamburg.de`) is deliberately **hidden from the public
login page** (`hideOnLoginPage: true`) — it's an institution-scoped provider,
not a general-audience option. It's only reachable via a direct link carrying
`kc_idp_hint=haw-gitlab` (e.g. a dedicated landing page for that institution),
which sends the browser straight to `/broker/haw-gitlab/login`, skipping
Keycloak's normal provider-picker page entirely. Use this pattern for any
future institution/partner-specific IdP you don't want showing to everyone.

For each provider you want active, register an OAuth app on that platform and set
its **redirect / callback URI** to Keycloak's broker endpoint:

```
https://<AUTH_PUBLIC_HOST>/realms/ct-demo/broker/<alias>/endpoint
```

| Provider | `<alias>` | Register the OAuth app at | `.env` keys |
|----------|-----------|---------------------------|-------------|
| Google | `google` | Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web) | `KC_GOOGLE_CLIENT_ID`, `KC_GOOGLE_CLIENT_SECRET` |
| GitHub | `github` | GitHub → Settings → Developer settings → OAuth Apps → New | `KC_GITHUB_CLIENT_ID`, `KC_GITHUB_CLIENT_SECRET` |
| GitLab | `gitlab` | GitLab → Preferences → Applications (scopes: `openid`, `email`, `profile`) | `KC_GITLAB_CLIENT_ID`, `KC_GITLAB_CLIENT_SECRET` |
| HAW GitLab (`git.haw-hamburg.de`) | `haw-gitlab` | git.haw-hamburg.de → User Settings → Applications, Confidential, scopes `openid`, `profile`, `email` | `KC_HAW_GITLAB_CLIENT_ID`, `KC_HAW_GITLAB_CLIENT_SECRET` |

Put the credentials in `docker/deploy/.env`, then redeploy (or restart Keycloak) —
the realm import substitutes them via `${KC_*}`. A provider left with **empty**
credentials still shows a button that errors on click; disable or delete the ones
you don't use in the Keycloak admin console (Identity Providers → the provider →
toggle *Enabled* off), or remove them from the realm JSON.

**A custom OIDC provider** (any fourth IdP) needs no code or realm-file change —
add it live in the admin console: **Identity Providers → Add provider → OpenID
Connect v1.0**, paste the provider's discovery URL (`.../.well-known/openid-configuration`),
set the client ID/secret, and give the provider the same broker redirect URI above
with your chosen alias.

## How it verifies (no key export)

`CT_OIDC_ISSUER` → the control-plane derives `<issuer>/protocol/openid-connect/certs`,
fetches the JWKS, selects the RS256 signing key, and builds the verifier at
startup. `CT_OIDC_PUBKEY_PATH` (a PEM of the realm public key) remains an explicit
offline override and takes precedence when set.
