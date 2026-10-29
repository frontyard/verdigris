# Verdigris

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/frontyard/verdigris/badge)](https://scorecard.dev/viewer/?uri=github.com/frontyard/verdigris)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15915/badge)](https://www.bestpractices.dev/projects/15915)
[![codecov](https://codecov.io/gh/frontyard/verdigris/graph/badge.svg)](https://codecov.io/gh/frontyard/verdigris)

Verdigris is a self-hosting web server and reverse proxy in a single
static binary: nginx-class performance with Caddy-like zero-configuration
TLS and a readable TOML configuration.

- HTTP/1.1 and HTTP/2 (plus h2c) on the same listener, downstream and upstream
- Static files with ranges, ETag/Last-Modified, precompressed variants
- Reverse proxy with load balancing, retries, health checks, WebSocket upgrades
- TLS with manual certs, self-signed, or automatic ACME (Let's Encrypt)
- Auth (basic/bearer/API key), IP ACLs, CORS, rate limiting, compression
  (br/zstd/gzip), and a full HTTP response cache (RAM/disk/hybrid)
- Prometheus metrics, structured access logs, admin API, atomic reloads

## Docs

See [REFERENCE.md](docs/book/src/reference.md) for the complete configuration schema
and [QUICKSTART.md](docs/book/src/quickstart.md) for a hands-on tour.

Full [documentation](https://www.frontyard.co/verdigris/) is
automatically generated on every release. Point AI agents to [llms-full.txt](llms-full.txt)
for comprehensive context when setting up or troubleshooting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## Install

Prebuilt static musl binaries (x86_64, aarch64) are attached to every
[release](https://github.com/frontyard/verdigris/releases):

```sh
curl -LO https://github.com/frontyard/verdigris/releases/download/v0.1.0/verd-x86_64-unknown-linux-musl.tar.gz
sha256sum -c checksums.txt --ignore-missing
tar xzf verd-*.tar.gz
sudo install -m755 verd /usr/local/bin/
```

Container image:

```sh
docker run --read-only \
  -v $PWD/verd.toml:/etc/verd/verd.toml:ro \
  -v verd-data:/var/lib/verd \
  -p 8080:8080 -p 127.0.0.1:2019:2019 \
  ghcr.io/frontyard/verdigris:latest
```

## Build from source

Rust 1.88 or newer:

```sh
cargo build --release --locked
./target/release/verd version
```

## Quickstart

Minimal `verd.toml`:

```toml
[server]
listen = ["0.0.0.0:8080"]

[[site]]
default = true
tls = "off"

[[site.route]]
prefix = "/"
static = { root = "/var/www/site" }
```

```sh
verd run                    # finds ./verd.toml, then /etc/verd/
verd validate               # check the config without serving
verd config                 # print the effective config (secrets redacted)
verd schema                 # dump the full JSON Schema of the config
```

The admin listener serves `/health`, `/ready`, `/metrics`, `/version`,
`/config`, `/upstreams`, `/reload`, `/purge` on `127.0.0.1:2019`.

## Demo stack

```sh
docker compose up --build
```

Static site on `:8080`, an `http-echo` upstream behind `/api`, admin API
on `127.0.0.1:2019`.

## Documentation

- [Book](https://frontyard.github.io/verdigris/) — guides and the
  generated config reference (`docs/book/`, built with mdBook)
- `llms.txt` — curated summary + recipes for LLM ingestion;
  `llms-full.txt` is the whole book in one file
- `MISSION.md` — design goals and non-goals
- `PERFORMANCE.md` — benchmark findings vs nginx/caddy+fastcache/ferron
- `RELEASING.md` — how releases and container images are produced

## Development

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test --all-targets && cargo test --doc
./bench/run.sh                # wrk-based benchmark vs nginx/caddy+fastcache/ferron
```

Every TOML snippet in the docs is validated against the real config
parser in CI, and `docs/book/src/reference.md` is regenerated from
`verd schema` — keep them in sync when changing `src/config/`.

## License

MIT OR Apache-2.0
