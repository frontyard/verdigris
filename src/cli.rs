//! Command line interface: `verd run | validate | version | fmt | schema`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};

/// Verdigris — a simple, fast web server and reverse proxy.
#[derive(Parser)]
#[command(name = "verd", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Server log level (error, warn, info, debug, trace).
    #[arg(long, global = true, env = "VERD_LOG")]
    log_level: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server.
    Run {
        /// Path to the configuration file.
        #[arg(short, long, env = "VERD_CONFIG", value_name = "PATH")]
        config: Option<PathBuf>,

        /// Reload the configuration when the file changes on disk.
        #[arg(long)]
        watch: bool,
    },
    /// Check a configuration file for errors without starting the server.
    Validate {
        /// Path to the configuration file.
        #[arg(short, long, env = "VERD_CONFIG", value_name = "PATH")]
        config: Option<PathBuf>,
    },
    /// Print version and build information.
    Version,
    /// Format a configuration file in place, preserving comments.
    Fmt {
        /// Path to the configuration file.
        #[arg(short, long, env = "VERD_CONFIG", value_name = "PATH")]
        config: Option<PathBuf>,

        /// Exit non-zero if the file is not formatted instead of writing it.
        #[arg(long)]
        check: bool,
    },
    /// Print the JSON Schema for the configuration file.
    Schema {
        /// Write the schema to a file instead of stdout.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

/// Entry point for `verd`: parse args and dispatch the subcommand.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.log_level.as_deref());

    match cli.command {
        Command::Run { config, watch } => cmd_run(config, watch),
        Command::Validate { config } => cmd_validate(config),
        Command::Version => {
            println!("verd {}", env!("CARGO_PKG_VERSION"));
            if let Some(sha) = option_env!("VERD_GIT_SHA") {
                println!("commit: {sha}");
            }
            println!(
                "target: {}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            );
            ExitCode::SUCCESS
        }
        Command::Fmt { config, check } => cmd_fmt(config, check),
        Command::Schema { output } => cmd_schema(output),
    }
}

fn init_tracing(level: Option<&str>) {
    let filter = tracing_subscriber::EnvFilter::try_new(level.unwrap_or("info"))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// Candidate config locations, in priority order: explicit flag/env,
/// `./verd.toml`, `/etc/verd/verd.toml`.
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf, Vec<PathBuf>> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let candidates = [
        PathBuf::from("verd.toml"),
        PathBuf::from("/etc/verd/verd.toml"),
    ];
    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    Err(candidates.to_vec())
}

fn missing_config_error(tried: &[PathBuf]) -> ExitCode {
    eprintln!("error: no configuration file found");
    eprintln!();
    eprintln!("looked for:");
    for path in tried {
        eprintln!("  - {}", path.display());
    }
    eprintln!();
    eprintln!("a minimal verd.toml looks like:");
    eprintln!();
    eprintln!("  [[site]]");
    eprintln!("  hosts = [\"localhost\"]");
    eprintln!("  root  = \"./public\"");
    eprintln!();
    eprintln!("or pass a path explicitly: verd run --config /path/to/verd.toml");
    ExitCode::from(2)
}

fn cmd_run(config: Option<PathBuf>, watch: bool) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    let loaded = match crate::config::load(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    print_diagnostics(&loaded);
    if !loaded.is_valid() {
        return ExitCode::from(2);
    }
    let rt = match crate::server::Runtime::build(Arc::new(loaded.config)) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        "verd starting"
    );

    let tokio_rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    tokio_rt.block_on(run_async(rt, path, watch))
}

async fn run_async(rt: Arc<crate::server::Runtime>, config_path: PathBuf, watch: bool) -> ExitCode {
    crate::observe::metrics::install();
    let shared = crate::server::Shared::new(rt);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<crate::server::Reload>(4);

    // First signal initiates graceful drain; a second forces exit.
    // SIGHUP reloads; SIGUSR1 reopens the access log (logrotate).
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    {
        let tx = reload_tx.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("install SIGINT handler");
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("install SIGHUP handler");
            let mut usr =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                    .expect("install SIGUSR1 handler");
            loop {
                tokio::select! {
                    _ = int.recv() => break,
                    _ = term.recv() => break,
                    _ = hup.recv() => {
                        let _ = tx.try_send(crate::server::Reload { cause: "sighup", done: None });
                    }
                    _ = usr.recv() => shared.load().access.reopen(),
                }
            }
            tracing::info!("shutdown signal received; draining");
            let _ = sd_tx.send(true);
            tokio::select! {
                _ = int.recv() => {},
                _ = term.recv() => {},
            }
            std::process::exit(1);
        });
    }

    // --watch: reload when the config file changes on disk (debounced)
    if watch {
        let tx = reload_tx.clone();
        let path = config_path.clone();
        tokio::spawn(async move {
            use notify::Watcher;
            let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel(8);
            let mut watcher = match notify::recommended_watcher(move |r| {
                let _ = ev_tx.try_send(r);
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!(error = %e, "config watch unavailable");
                    return;
                }
            };
            if let Err(e) = watcher.watch(&path, notify::RecursiveMode::NonRecursive) {
                tracing::error!(path = %path.display(), error = %e, "cannot watch config");
                return;
            }
            tracing::info!(path = %path.display(), "watching config for changes");
            while ev_rx.recv().await.is_some() {
                // debounce: drain queued events, then reload once
                while ev_rx.try_recv().is_ok() {}
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                while ev_rx.try_recv().is_ok() {}
                let _ = tx
                    .send(crate::server::Reload {
                        cause: "file watch",
                        done: None,
                    })
                    .await;
            }
        });
    }

    let mut tasks: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    {
        let shared = shared.clone();
        let mut sd = sd_rx.clone();
        tasks.spawn(async move {
            crate::server::serve_shared(shared, reload_rx, Some(config_path), async move {
                let _ = sd.changed().await;
            })
            .await
            .map_err(|e| e.to_string())
        });
    }
    {
        let sd = sd_rx.clone();
        tasks.spawn(async move {
            crate::admin::serve(shared, reload_tx, sd)
                .await
                .map_err(|e| format!("admin listener: {e}"))
        });
    }

    let mut exit = ExitCode::SUCCESS;
    while let Some(res) = tasks.join_next().await {
        match res {
            Err(e) => {
                eprintln!("error: server task panicked: {e}");
                exit = ExitCode::FAILURE;
            }
            Ok(Err(e)) => {
                eprintln!("error: {e}");
                exit = ExitCode::FAILURE;
            }
            Ok(Ok(())) => {}
        }
    }
    tracing::info!("verd stopped");
    exit
}

fn cmd_validate(config: Option<PathBuf>) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    let loaded = match crate::config::load(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    print_diagnostics(&loaded);
    if loaded.is_valid() {
        if loaded.diagnostics.is_empty() {
            println!("{}: configuration is valid", path.display());
        } else {
            println!("{}: configuration is valid (with warnings)", path.display());
        }
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_diagnostics(loaded: &crate::config::Loaded) {
    for diag in &loaded.diagnostics {
        eprintln!("{diag}");
    }
}

fn cmd_fmt(config: Option<PathBuf>, check: bool) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    if check {
        return match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                crate::config::fmt::format_str(&text)
                    .map(|formatted| (text, formatted))
                    .map_err(|e| e.to_string())
            }) {
            Ok((original, formatted)) if original == formatted => ExitCode::SUCCESS,
            Ok(_) => {
                eprintln!("{}: not formatted", path.display());
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("error: {}: {e}", path.display());
                ExitCode::FAILURE
            }
        };
    }
    match crate::config::fmt::format_file(&path) {
        Ok(true) => {
            println!("{}: formatted", path.display());
            ExitCode::SUCCESS
        }
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_schema(output: Option<PathBuf>) -> ExitCode {
    let schema = crate::config::fmt::json_schema();
    let text = match serde_json::to_string_pretty(&schema) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: cannot serialize schema: {e}");
            return ExitCode::FAILURE;
        }
    };
    match output {
        Some(path) => match std::fs::write(&path, format!("{text}\n")) {
            Ok(()) => {
                println!("wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: cannot write {}: {e}", path.display());
                ExitCode::FAILURE
            }
        },
        None => {
            println!("{text}");
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_missing_path_is_reported() {
        let path = resolve_config_path(Some(PathBuf::from("/nonexistent/x.toml")));
        assert_eq!(path.unwrap(), PathBuf::from("/nonexistent/x.toml"));
    }

    #[test]
    fn cwd_candidates_checked_in_order() {
        let tried = resolve_config_path(None).unwrap_err();
        assert_eq!(tried[0], PathBuf::from("verd.toml"));
        assert_eq!(tried[1], PathBuf::from("/etc/verd/verd.toml"));
    }
}
