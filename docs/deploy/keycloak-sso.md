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

## Login look per client: `ct-mydailyidea`

`docker/deploy/keycloak/themes/ct-mydailyidea` is a second login theme with the look of the
"My Daily Idea" web app (yellow band, cream sheet, ink edges, Anton). Its parent is
`ct-bunsenbrenner`; it only adds `login/resources/css/ct-mydailyidea.css` and the message key
`loginAccountTitle` (EN/DE). No template is overridden, so login, registration, password
reset, error pages and the social buttons (GitHub, Google) work exactly as before.

The realm keeps `loginTheme=ct-bunsenbrenner`. A client opts in with the client attribute
`login_theme=ct-mydailyidea` (admin console: Clients → *client* → Settings → Login settings →
Login theme). Do **not** set it on `ct-portal`: that client serves the portal sign-in **and**
the Browser-Plane login gate (`crates/control-plane/src/gate.rs`, `/gate/start`) for every
gated tunnel, including the whole demo gallery on `demos-34a13a96.bunsenbrenner.org`, so all
of them would change look at once. My Daily Idea therefore has a client of its own,
`mydailyidea` (confidential, PKCE S256 required, only `${PORTAL_PUBLIC_URL}/gate/callback` as
redirect URI, secret pinned to `${KC_MYDAILYIDEA_CLIENT_SECRET}` like `ct-portal`'s).

The gate picks it per login from `CT_GATE_CLIENT_ROUTES` (control-plane): entries
`host[/path]=client-id`, matched against the gated host and the login's return path (the
path and everything below it, longest prefix wins). For My Daily Idea:

```
KC_MYDAILYIDEA_CLIENT_SECRET=<random hex, e.g. openssl rand -hex 32>
CT_GATE_CLIENT_ROUTES=demos-34a13a96.bunsenbrenner.org/duell=mydailyidea
```

Logins returning to `/duell...` on that host use `mydailyidea`; every other path on the same
host (the rest of the demo gallery) and every other host stay on `ct-portal`. The secret is
read from `CT_GATE_CLIENT_SECRET_<CLIENT ID>` (upper case, other characters as `_`); compose
derives it from `KC_MYDAILYIDEA_CLIENT_SECRET`. A route without a secret is skipped.

Every gate login sends PKCE (S256, verifier derived from the state with the gate key) and
`ui_locales`: `en` unless `/gate/start` gets `lang=de` from the app.

## Login look per client: `ct-riisc`

`docker/deploy/keycloak/themes/ct-riisc` gives the sign-in pages the look of
riisc.bunsenbrenner.org (white page, white top bar with olive rule and the navy RIISC mark,
white card, steel "Praktikumszugang"/"Lab access" badge, navy upper-case button, navy footer
band; CaDS reference tokens). Built like `ct-mydailyidea`: parent `ct-bunsenbrenner`, only
`login/resources/css/ct-riisc.css` and `loginAccountTitle` (EN/DE), no template overridden, no
font file and no external request (headings ask for a locally installed Roboto, else Arial).

It is set on the client `praktikum-creator` (`attributes.login_theme=ct-riisc` in the realm
JSON). That client serves every redirect URI listed there: `riisc.bunsenbrenner.org`,
`rn-praktikum.bunsenbrenner.org` and `praktikum.bunsenbrenner.org`. rn-praktikum sends
`kc_idp_hint=haw-gitlab` and skips the Keycloak sign-in form, but Keycloak pages it still shows
(errors, first-login profile, terms) carry the RIISC look too. A different look per host needs
a client per host.

The realm JSON is imported only on first boot, so an existing realm gets the attribute through
the admin API (theme first, attribute second -- a client naming a theme Keycloak cannot find
falls back to the stock `keycloak.v2` look):

```bash
docker compose ... exec -T keycloak sh -c '/opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kcadm.config --server http://localhost:8080 --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"'
ID=$(docker compose ... exec -T keycloak /opt/keycloak/bin/kcadm.sh get clients -r ct-demo \
  --config /tmp/kcadm.config -q clientId=praktikum-creator --fields id --format csv --noquotes)
docker compose ... exec -T keycloak /opt/keycloak/bin/kcadm.sh update "clients/$ID" -r ct-demo \
  --config /tmp/kcadm.config -s 'attributes.login_theme=ct-riisc'
```

`update -s` reads the client, changes this one attribute and writes it back; secret, redirect
URIs and mappers stay as they are. Undo: `-s 'attributes.login_theme='` (Keycloak drops the
empty attribute, the realm default `ct-bunsenbrenner` applies again).

## Theme files on the host

The compose overlay mounts the whole `keycloak/themes` directory read-only at
`/opt/keycloak/themes` (the image keeps only a README there). A new theme directory is
therefore visible to the running container right after `git checkout`, without a new volume
entry or a restart (checked with Keycloak 26.7.3 in production mode). Keycloak caches an
existing theme's `theme.properties` in production mode, so a change there (e.g. a new
`styles=` entry) needs `docker compose ... restart keycloak`. The deploy checkout runs with
umask 077; after every checkout make the files readable for the container user:

```bash
chmod -R a+rX docker/deploy/keycloak/themes docker/deploy/keycloak/ct-demo-realm.json
```

For k8s bake the `themes` directory into the derived image under `/opt/keycloak/themes`.

## How it verifies (no key export)

`CT_OIDC_ISSUER` → the control-plane derives `<issuer>/protocol/openid-connect/certs`,
fetches the JWKS, selects the RS256 signing key, and builds the verifier at
startup. `CT_OIDC_PUBKEY_PATH` (a PEM of the realm public key) remains an explicit
offline override and takes precedence when set.
