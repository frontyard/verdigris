# Caddy + the fastcache handler (http.handlers.fastcache), fetched from
# GitHub at build time — no local checkout needed. Append @<ref> to pin
# a version or commit.
FROM caddy:2-builder-alpine@sha256:ef9b65adf9a224770c6d5f6d1ae1bf99bc3caaa78d8c4bae3ea949ee6984f301 AS build
RUN xcaddy build --with github.com/frontyard/fastcache
FROM caddy:2-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
COPY --from=build /usr/bin/caddy /usr/bin/caddy
