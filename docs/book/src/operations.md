# Operations

## Day-to-day

- **Reload config**: `systemctl reload verd` (SIGHUP), `POST /reload`,
  or `--watch`. All are atomic; a bad file keeps the old generation.
  `${VAR}`/`${file:…}` interpolation runs at load — env-var changes are
  not file events, so `--watch` alone doesn't catch them; send SIGHUP
  or `POST /reload` after editing an env var.
- **Rotate access logs**: move the file, then `kill -USR1` (the systemd
  unit wires this as the second `ExecReload`).
- **Rotate TLS certs**: overwrite the PEM files — the watcher hot-loads
  them for new handshakes.
- **Drain a backend**: `POST /upstreams/<cluster>/<member>/drain` before
  maintenance; `/undrain` to restore.

## Debugging

- `VERD_LOG=debug` (or `--log-level`) for structured tracing on stderr.
- `GET /config` (admin) shows the *effective* merged config with secrets
  redacted — check this before assuming a key applied.
- `GET /upstreams` shows member health/drain/in-flight live.
- Access-log `499` = the client hung up mid-body, not a server error.
- Metrics `verd_upstream_healthy{member=…} = 0` marks members out of
  rotation (active probe failing, passive cooldown, or drained).

## Failure modes

- Reload bind failure → reload aborts, old generation keeps serving.
- Cache disk corruption → entries dropped at boot rebuild; serving
  continues with an empty cache.
- ACME failure → issuance retries with backoff; sites with no cert yet
  serve HTTP until one exists.
