# Caddy built with the deSEC DNS provider plugin, so it can solve ACME DNS-01
# against deSEC for cookbook.bunsenbrenner.org (origin-side cert, ADR-0019 / #23 / #31).
# Identical to examples/help-site/Caddy.Dockerfile — the demo origin is a plain static server.
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/caddy-dns/desec

FROM caddy:2
COPY --from=build /usr/bin/caddy /usr/bin/caddy
