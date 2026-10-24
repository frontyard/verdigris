# Caddy + the fastcache handler (http.handlers.fastcache), fetched from
# GitHub at build time — no local checkout needed. Append @<ref> to pin
# a version or commit.
FROM caddy:2-builder-alpine AS build
RUN xcaddy build --with github.com/frontyard/fastcache
FROM caddy:2-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
