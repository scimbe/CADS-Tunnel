# Plain Caddy — same posture as examples/help-site/Caddy.Dockerfile: no custom
# build, no ACME DNS plugin. The origin's cert is issued CORE-side (scripts/
# lib-acme.sh, deSEC DNS-01) and mounted in as static files; Caddy here only
# ever reads fullchain.pem/privkey.pem, never a deSEC token.
FROM caddy:2
