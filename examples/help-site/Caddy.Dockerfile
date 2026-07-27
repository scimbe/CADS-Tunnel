# Plain Caddy — no custom build, no ACME DNS plugin. The origin's cert is
# issued CORE-side (scripts/deploy-selfhost.sh's cert tooling / scripts/
# lib-acme.sh, deSEC DNS-01) and mounted in as static files; Caddy here only
# ever reads fullchain.pem/privkey.pem (#219) — it never holds the deSEC
# zone-wide token.
FROM caddy:2
