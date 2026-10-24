# Docker & deployment

The published image is a static musl binary on `distroless/static`,
running as `nonroot` with a read-only root filesystem.

## Writable directories

| Path | Used for |
|---|---|
| `/var/lib/verd` | disk-cache objects, ACME account + certificates |
| `/var/log/verd` | access-log files (or log to stdout) |
| `/etc/verd` | config + manual cert files (mount **read-only**) |

```sh
docker run --read-only \
  -v $PWD/verd.toml:/etc/verd/verd.toml:ro \
  -v verd-data:/var/lib/verd \
  -p 80:8080 -p 127.0.0.1:2019:2019 \
  ghcr.io/frontyard/verdigris:latest
```

## Compose

`docker-compose.yml` at the repo root runs a demo: static site, an
`http-echo` upstream behind `/api`, and the admin API on
`127.0.0.1:2019`.

## systemd

`packaging/verd.service` — `ExecReload` uses SIGHUP for config reload
and SIGUSR1 for access-log reopen, `ProtectSystem=strict` with
`ReadWritePaths` limited to state/log/config dirs, and
`AmbientCapabilities=CAP_NET_BIND_SERVICE` for ports <1024.
