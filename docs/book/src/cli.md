# Command line

`verd` is a single binary with seven subcommands.

| Command | Purpose |
| --- | --- |
| `verd run` | Start the server. |
| `verd validate` | Check a config file for errors and dry-run the full runtime build (read-only); exits non-zero on failure. |
| `verd init` | Write a starter `verd.toml`. |
| `verd config` | Print the effective merged/interpolated config as TOML or JSON (secrets redacted). |
| `verd fmt` | Normalize whitespace in a config file in place, preserving comments. |
| `verd schema` | Print the JSON Schema for the config format to stdout. |
| `verd version` | Print version, build commit, and target triple. |

## Flags

| Flag | Env var | Applies to | Effect |
| --- | --- | --- | --- |
| `-c, --config PATH` | `VERD_CONFIG` | `run`, `validate`, `config`, `fmt` | Config file path. Without it, `verd` searches `./verd.toml` and `/etc/verd/verd.toml`. |
| `--watch` | — | `run` | Reload config when it changes on disk (in addition to `POST /reload`). Observes the parent directories of every loaded source — the config file, `include`d files, `include` dirs/globs, and `${file:…}` secret files — so atomic renames, editor save-swaps, k8s `..data` swaps, and newly dropped-in `*.toml` include fragments all trigger a reload. Events on unrelated files in those directories (e.g. a log file written next to the config) are ignored. The watched set is re-derived after each reload. |
| `--format FMT` | — | `validate` | `text` (default) prints diagnostics on stderr; `json` prints a machine-readable report on stdout — always `{ valid, strict, diagnostics, sources }`, plus `"error"` on load/dry-build failures. |
| `--format FMT` | — | `config` | `toml` (default) prints canonical TOML; `json` prints the same redacted JSON the admin `/config` endpoint serves. |
| `--strict` | — | `validate` | Fail on warnings too, not just errors. |
| `--check` | — | `fmt` | Exit non-zero if unformatted instead of rewriting. |
| `--diff` | — | `fmt` | Print a line-level diff of pending changes (implies `--check`). |
| `--all` | — | `fmt` | Also format every file reachable through `include`. |
| `-o, --output PATH` | — | `schema`, `init` | `schema`: write the schema to a file instead of stdout. `init`: where to write the config (default `./verd.toml`; `-` is stdout). |
| `--force` | — | `init` | Overwrite an existing file. |
| `--log-level LVL` | `VERD_LOG` | `run`, `validate` | Server log level filter (`error` / `warn` / `info` / `debug` / `trace`, or an env-filter spec like `verd=debug,hyper=info`). Overrides `[log] level`; default `info`. |

The server log's format and destination are configured in the file
(`[log] format` / `[log] output`), not on the command line — see
[Observability](./observability.md).

`verd --version` prints just the crate version; `verd version` also
prints the build commit (when built with `VERD_GIT_SHA`) and target.

## Exit codes

`0` success; `1` config/runtime failures (including missing config);
`2` CLI usage errors. `validate` prints one line per error or warning
to stderr (or a JSON report on stdout with `--format json`); `--strict`
turns warnings fatal.
