# Command line

`verd` is a single binary with five subcommands. All options can also be
set via environment variables.

| Command | Purpose |
|---|---|
| `verd run` | Start the server. Default when a config file exists. |
| `verd validate` | Check a config file for errors; exits non-zero on failure. |
| `verd config` | Print the effective merged/interpolated config as TOML (secrets redacted). |
| `verd fmt` | Normalize whitespace in a config file in place, preserving comments. |
| `verd schema` | Print the JSON Schema for the config format to stdout. |
| `verd version` | Print version, build commit, and target triple. |

## Flags

| Flag | Env var | Applies to | Effect |
|---|---|---|---|
| `-c, --config PATH` | `VERD_CONFIG` | `run`, `validate`, `config`, `fmt` | Config file path. Without it, `verd` searches `./verd.toml`, `./config/verd.toml`, `/etc/verd/verd.toml`. |
| `--watch` | — | `run` | Reload config when the file changes on disk (in addition to `POST /reload`). |
| `--check` | — | `fmt` | Exit non-zero if unformatted instead of rewriting. |
| `-o, --output PATH` | — | `schema` | Write the schema to a file instead of stdout. |
| `--log-level LVL` | `VERD_LOG` | all | `error` / `warn` / `info` / `debug` / `trace`; default `info`. JSON logs when stderr is not a TTY. |

`verd --version` prints just the crate version; `verd version` also
prints the build commit (when built with `VERD_GIT_SHA`) and target.

## Exit codes

`0` success; `1` config errors / missing config; `2` CLI usage errors.
`validate` prints one line per error or warning to stderr.
