//! Command line interface: `verd run | validate | config | version | fmt | schema`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};

use crate::config::model as cfg;
use crate::observe::{check_log_path, open_append};

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

        /// Output format: human-readable text or a JSON report.
        #[arg(long, value_enum, default_value_t = ValidateFormat::Text)]
        format: ValidateFormat,

        /// Fail on warnings too, not just errors.
        #[arg(long)]
        strict: bool,
    },
    /// Write a starter verd.toml.
    Init {
        /// Where to write the file ("-" for stdout).
        #[arg(short, long, value_name = "PATH", default_value = "verd.toml")]
        output: PathBuf,

        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Print the effective configuration (merged, interpolated, fully
    /// defaulted). Secret values are redacted.
    Config {
        /// Path to the configuration file.
        #[arg(short, long, env = "VERD_CONFIG", value_name = "PATH")]
        config: Option<PathBuf>,

        /// Output format: TOML or JSON.
        #[arg(long, value_enum, default_value_t = ConfigFormat::Toml)]
        format: ConfigFormat,
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

        /// Print a line-level diff of the pending changes (implies --check).
        #[arg(long)]
        diff: bool,

        /// Also format every file reachable through `include`.
        #[arg(long)]
        all: bool,
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

    match cli.command {
        Command::Run { config, watch } => cmd_run(config, watch, cli.log_level.as_deref()),
        Command::Validate {
            config,
            format,
            strict,
        } => cmd_validate(config, cli.log_level.as_deref(), format, strict),
        Command::Init { output, force } => cmd_init(output, force),
        Command::Config { config, format } => cmd_config(config, format),
        Command::Version => cmd_version(),
        Command::Fmt {
            config,
            check,
            diff,
            all,
        } => cmd_fmt(config, check, diff, all),
        Command::Schema { output } => cmd_schema(output),
    }
}

/// `verd validate --format` output modes.
#[derive(Clone, Copy, clap::ValueEnum)]
enum ValidateFormat {
    /// Human-readable diagnostics on stderr.
    Text,
    /// Machine-readable report on stdout.
    Json,
}

/// `verd config --format` output modes.
#[derive(Clone, Copy, clap::ValueEnum)]
enum ConfigFormat {
    /// TOML — the format config is written in.
    Toml,
    /// JSON — same shape as the admin `/config` endpoint.
    Json,
}

fn cmd_version() -> ExitCode {
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

/// The server-log file sink, shared with tracing: SIGUSR1 swaps the
/// handle under the lock (logrotate). Writes lock per event — the same
/// pattern as the access logger's reopen.
#[derive(Clone)]
pub struct ServerLogFile {
    inner: Arc<Mutex<ServerLogInner>>,
}

struct ServerLogInner {
    file: std::fs::File,
    path: PathBuf,
}

impl ServerLogFile {
    fn open(path: &str) -> Result<Self, String> {
        Ok(Self {
            inner: Arc::new(Mutex::new(ServerLogInner {
                file: open_append(path)?,
                path: PathBuf::from(path),
            })),
        })
    }

    /// Swap the handle for a fresh one on the same path (post-rotate).
    pub fn reopen(&self) {
        if let Ok(mut g) = self.inner.lock()
            && let Ok(f) = open_append(&g.path.to_string_lossy())
        {
            g.file = f;
        }
    }
}

impl Write for ServerLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner
            .lock()
            .map_err(|_| std::io::Error::other("log sink poisoned"))?
            .file
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| std::io::Error::other("log sink poisoned"))?
            .file
            .flush()
    }
}

/// Runtime-selectable tracing writer: `stdout`, `stderr`, or the shared
/// log file.
#[derive(Clone)]
enum LogWriter {
    Stdout,
    Stderr,
    File(ServerLogFile),
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = Box<dyn Write + Send + Sync + 'a>;

    fn make_writer(&'a self) -> Self::Writer {
        match self {
            Self::Stdout => Box::new(std::io::stdout()),
            Self::Stderr => Box::new(std::io::stderr()),
            Self::File(f) => Box::new(f.clone()),
        }
    }
}

/// Initialize tracing per `[log]` with `--log-level`/`VERD_LOG` taking
/// precedence over `log.level`. Returns the file sink when `log.output`
/// is a path so `run_async` can reopen it on SIGUSR1.
fn init_tracing(
    log: &cfg::LogConfig,
    cli_level: Option<&str>,
) -> Result<Option<ServerLogFile>, String> {
    let level = cli_level.unwrap_or(log.level.as_str());
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .map_err(|e| format!("invalid log level {level:?}: {e}"))?;
    let (writer, file) = match log.output.as_str() {
        "stdout" => (LogWriter::Stdout, None),
        "stderr" => (LogWriter::Stderr, None),
        path => {
            let f = ServerLogFile::open(path)?;
            (LogWriter::File(f.clone()), Some(f))
        }
    };
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match log.format {
        cfg::LogFormat::Json => builder.json().with_writer(writer).try_init(),
        cfg::LogFormat::Pretty => builder.with_writer(writer).try_init(),
    }
    // a second init only happens under tests — the first subscriber wins
    .map_err(|_| ())
    .ok();
    Ok(file)
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

/// `verd … -c -` reads the root document from stdin (`VERD_CONFIG=-`
/// works the same). `include` and `${file:}` resolve against the
/// current directory.
fn load_root(path: &Path) -> Result<crate::config::Loaded, crate::config::LoadError> {
    if path.as_os_str() != "-" {
        return crate::config::load(path);
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut text)
        .map_err(|e| crate::config::LoadError::Io(PathBuf::from("<stdin>"), e.to_string()))?;
    crate::config::load_stdin(&text)
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
    eprintln!("  tls   = \"off\"");
    eprintln!("  root  = \"./public\"");
    eprintln!();
    eprintln!("scaffold one with `verd init`, or pass a path explicitly:");
    eprintln!("  verd run --config /path/to/verd.toml");
    ExitCode::FAILURE
}

fn cmd_run(config: Option<PathBuf>, watch: bool, log_level: Option<&str>) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    let loaded = match load_root(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    print_diagnostics(&loaded);
    if !loaded.is_valid() {
        return ExitCode::FAILURE;
    }
    let watch_plan = loaded.watch_plan();
    // tracing is configured only now: [log] lives in the config file, so
    // level/format/output can't apply until it has been loaded
    let log_file = match init_tracing(&loaded.config.log, log_level) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
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
    tokio_rt.block_on(run_async(rt, path, watch, watch_plan, log_file))
}

async fn run_async(
    rt: Arc<crate::server::Runtime>,
    config_path: PathBuf,
    watch: bool,
    watch_plan: crate::config::WatchPlan,
    log_file: Option<ServerLogFile>,
) -> ExitCode {
    crate::observe::metrics::install();
    let admin_enabled = rt.config.admin.enabled;
    let shared = crate::server::Shared::with_watch(rt, watch_plan);
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<crate::server::Reload>(4);

    // First signal initiates graceful drain; a second forces exit.
    // SIGHUP reloads; SIGUSR1 reopens log files (logrotate).
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
                    _ = usr.recv() => {
                        shared.load().access.reopen();
                        if let Some(f) = &log_file {
                            f.reopen();
                        }
                    }
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

    // --watch: reload when any config source changes — parents of the
    // loaded files are observed (atomic renames and editor save-swap
    // patterns report the target path) plus `include` dirs/globs, where
    // any `*.toml` event counts. Reloads re-derive the set so include
    // additions/removals take effect without a restart.
    if watch {
        let tx = reload_tx.clone();
        let mut watch_rx = shared.watch_rx();
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
            let mut plan = watch_rx.borrow_and_update().clone();
            for d in &plan.dirs {
                if let Err(e) = watcher.watch(d, notify::RecursiveMode::NonRecursive) {
                    tracing::error!(dir = %d.display(), error = %e, "cannot watch config dir");
                }
            }
            tracing::info!(
                dirs = plan.dirs.len(),
                "watching config sources for changes"
            );
            loop {
                tokio::select! {
                    changed = watch_rx.changed() => {
                        if changed.is_err() { return }
                        let new = watch_rx.borrow_and_update().clone();
                        for d in plan.dirs.difference(&new.dirs) {
                            let _ = watcher.unwatch(d);
                        }
                        for d in new.dirs.difference(&plan.dirs) {
                            if let Err(e) = watcher.watch(d, notify::RecursiveMode::NonRecursive) {
                                tracing::error!(dir = %d.display(), error = %e, "cannot watch config dir");
                            }
                        }
                        plan = new;
                    }
                    ev = ev_rx.recv() => {
                        let Some(Ok(ev)) = ev else { return };
                        if !plan.hit(&ev) {
                            continue;
                        }
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
                }
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
    if admin_enabled {
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

fn cmd_validate(
    config: Option<PathBuf>,
    log_level: Option<&str>,
    format: ValidateFormat,
    strict: bool,
) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    let json = matches!(format, ValidateFormat::Json);
    let loaded = match load_root(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "strict": strict,
                        "diagnostics": [],
                        "sources": [],
                        "error": e.to_string(),
                    })
                );
            } else {
                eprintln!("error: {e}");
            }
            return ExitCode::FAILURE;
        }
    };

    // diagnostics/sources are cloned so `loaded.config` can move into
    // the runtime check while failures still report what was found
    let diags = loaded.diagnostics.clone();
    let sources = loaded.sources.clone();
    let fatal = |msg: String| -> ExitCode {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "valid": false,
                    "strict": strict,
                    "diagnostics": diags,
                    "sources": sources,
                    "error": msg,
                })
            );
        } else {
            for d in &diags {
                eprintln!("{d}");
            }
            eprintln!("error: {msg}");
        }
        ExitCode::FAILURE
    };

    if !loaded.is_valid() {
        return fatal("configuration has errors".to_string());
    }
    // the server-log sink lives outside the runtime — `verd run` opens
    // it in init_tracing — so check level and output read-only here
    let level = log_level.unwrap_or(loaded.config.log.level.as_str());
    if let Err(e) = tracing_subscriber::EnvFilter::try_new(level) {
        return fatal(format!("invalid log level {level:?}: {e}"));
    }
    match loaded.config.log.output.as_str() {
        "stdout" | "stderr" => {}
        p => {
            if let Err(e) = check_log_path(p) {
                return fatal(e);
            }
        }
    }
    // full dry build: every compile-time check `verd run` performs, but
    // read-only — a green result means the server would actually start
    if let Err(e) = crate::server::Runtime::check(Arc::new(loaded.config)) {
        return fatal(e.to_string());
    }

    let ok = !(strict && !diags.is_empty());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "valid": ok,
                "strict": strict,
                "diagnostics": diags,
                "sources": sources,
            })
        );
    } else {
        for d in &diags {
            eprintln!("{d}");
        }
        if ok {
            if diags.is_empty() {
                println!("{}: configuration is valid", path.display());
            } else {
                println!("{}: configuration is valid (with warnings)", path.display());
            }
        } else {
            eprintln!(
                "error: {}: warnings treated as errors (--strict)",
                path.display()
            );
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_config(config: Option<PathBuf>, format: ConfigFormat) -> ExitCode {
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    let loaded = match load_root(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    print_diagnostics(&loaded);
    if !loaded.is_valid() {
        return ExitCode::FAILURE;
    }
    let rendered = match format {
        ConfigFormat::Toml => crate::config::dump(&loaded.config),
        ConfigFormat::Json => crate::config::dump_json(&loaded.config),
    };
    match rendered {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_diagnostics(loaded: &crate::config::Loaded) {
    for diag in &loaded.diagnostics {
        eprintln!("{diag}");
    }
}

/// Write a starter configuration — one plaintext listener, a loopback
/// admin API, and a hello-world route. Kept deliberately small; the
/// generated `reference.md` covers every field.
const INIT_TEMPLATE: &str = r#"# verd.toml — `verd validate` checks this file, `verd config` prints
# the effective (merged, defaulted) view, `verd fmt` reformats it.

[server]
# "ip:port" strings are plaintext listeners; { addr, tls = true } tables
# terminate TLS. listen = ["0.0.0.0:80", { tls = true }] is the classic
# 80 + 443 pair.
listen = ["0.0.0.0:8080"]

[admin]
# Loopback admin API: /metrics, /healthz, /reload, /config (redacted).
listen = "127.0.0.1:2019"
# token = "${file:/run/secrets/verd-admin-token}"  # required off-loopback

[log]
level = "info"       # error | warn | info | debug | trace, or a filter
# format = "json"    # json | pretty
# output = "stderr"  # stdout | stderr | /path/to/file (SIGUSR1 reopens)

# [acme]
# email = "you@example.com"   # required for tls = "auto" sites

[[site]]
hosts = ["localhost"]
tls = "off"          # "auto" for ACME certificates on a public name

[[site.route]]
prefix = "/"
respond = "hello from verd\n"  # 200 with this body; `404` or a table also work

# …or serve a directory with the `root` shorthand instead of routes:
# root = "./public"
#
# …or reverse-proxy:
# proxy = "http://127.0.0.1:9000"
#
# Split larger configs with `include = ["conf.d"]` — every *.toml file
# inside merges into this one (arrays append, scalars must agree).
# Secret material belongs in ${VAR} or ${file:} references, never inline.
"#;

fn cmd_init(output: PathBuf, force: bool) -> ExitCode {
    if output.as_os_str() == "-" {
        print!("{INIT_TEMPLATE}");
        return ExitCode::SUCCESS;
    }
    if output.exists() && !force {
        eprintln!(
            "error: {} already exists (use --force to overwrite)",
            output.display()
        );
        return ExitCode::FAILURE;
    }
    match std::fs::write(&output, INIT_TEMPLATE) {
        Ok(()) => {
            println!(
                "wrote {} — edit it, then check with `verd validate`",
                output.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot write {}: {e}", output.display());
            ExitCode::FAILURE
        }
    }
}

fn cmd_fmt(config: Option<PathBuf>, check: bool, diff: bool, all: bool) -> ExitCode {
    // --diff implies --check: show the drift, never write
    let check = check || diff;
    let path = match resolve_config_path(config) {
        Ok(path) => path,
        Err(tried) => return missing_config_error(&tried),
    };
    let files = if all {
        // `--all` formats the whole include tree — the loader reports
        // the exact file set, deduplicated
        match load_root(&path) {
            Ok(loaded) => loaded.sources,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        vec![path]
    };
    let mut ok = true;
    for file in &files {
        ok &= fmt_one(file, check, diff);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Format (or check) one file; returns false when `--check` finds drift
/// or the file cannot be parsed.
fn fmt_one(path: &std::path::Path, check: bool, diff: bool) -> bool {
    if path.as_os_str() == "-" {
        return fmt_stdin(check, diff);
    }
    if path.is_dir() {
        eprintln!(
            "error: {} is a directory — point -c at a file, e.g. -c {}/verd.toml",
            path.display(),
            path.display()
        );
        return false;
    }
    if check {
        return match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                crate::config::fmt::format_str(&text)
                    .map(|formatted| (text, formatted))
                    .map_err(|e| e.to_string())
            }) {
            Ok((original, formatted)) if original == formatted => true,
            Ok((original, formatted)) => {
                if diff {
                    print_diff(path, &original, &formatted);
                } else {
                    eprintln!("{}: not formatted", path.display());
                }
                false
            }
            Err(e) => {
                eprintln!("error: {}: {e}", path.display());
                false
            }
        };
    }
    match crate::config::fmt::format_file(path) {
        Ok(true) => {
            println!("{}: formatted", path.display());
            true
        }
        Ok(false) => true,
        Err(e) => {
            eprintln!("error: {e}");
            false
        }
    }
}

/// `verd fmt -` — read stdin, print the formatted document to stdout.
/// `--check`/`--diff` compare instead of printing.
fn fmt_stdin(check: bool, diff: bool) -> bool {
    let stdin_path = std::path::Path::new("<stdin>");
    let mut original = String::new();
    if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut original) {
        eprintln!("error: <stdin>: {e}");
        return false;
    }
    let formatted = match crate::config::fmt::format_str(&original) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: <stdin>: {e}");
            return false;
        }
    };
    if check {
        if original == formatted {
            return true;
        }
        if diff {
            print_diff(stdin_path, &original, &formatted);
        } else {
            eprintln!("<stdin>: not formatted");
        }
        return false;
    }
    print!("{formatted}");
    true
}

/// Minimal line diff for `fmt --diff` — LCS over lines; config files
/// are small enough that O(n·m) memory is fine, so no dependency.
fn print_diff(path: &std::path::Path, old: &str, new: &str) {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    println!("--- {}", path.display());
    println!("+++ {} (formatted)", path.display());
    // backtrack into ops, then emit with 2 lines of unchanged context
    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push((' ', a[i]));
            (i, j) = (i + 1, j + 1);
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
    ops.extend(a[i..].iter().map(|l| ('-', *l)));
    ops.extend(b[j..].iter().map(|l| ('+', *l)));
    let mut elided = false;
    for (k, (mark, line)) in ops.iter().enumerate() {
        if *mark == ' ' {
            let near = ops[k.saturating_sub(2)..k]
                .iter()
                .chain(&ops[k + 1..(k + 3).min(ops.len())])
                .any(|(mk, _)| *mk != ' ');
            if !near {
                if !elided {
                    println!(" ...");
                }
                elided = true;
                continue;
            }
        }
        elided = false;
        println!("{mark}{line}");
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

    fn write_cfg(dir: &tempfile::TempDir, text: &str) -> PathBuf {
        let p = dir.path().join("verd.toml");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn parses_all_subcommands() {
        let cli = Cli::try_parse_from(["verd", "run", "-c", "x.toml", "--watch"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Run {
                config: Some(_),
                watch: true
            }
        ));
        let cli = Cli::try_parse_from(["verd", "validate", "-c", "x.toml"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Validate {
                config: Some(_),
                format: ValidateFormat::Text,
                strict: false
            }
        ));
        let cli =
            Cli::try_parse_from(["verd", "validate", "--format", "json", "--strict"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Validate {
                format: ValidateFormat::Json,
                strict: true,
                ..
            }
        ));
        let cli = Cli::try_parse_from(["verd", "init", "--force"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Init {
                output: _,
                force: true
            }
        ));
        let cli = Cli::try_parse_from(["verd", "version"]).unwrap();
        assert!(matches!(cli.command, Command::Version));
        let cli = Cli::try_parse_from(["verd", "fmt", "--check", "--all"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Fmt {
                config: None,
                check: true,
                diff: false,
                all: true
            }
        ));
        let cli = Cli::try_parse_from(["verd", "config", "-c", "x.toml"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                config: Some(_),
                format: ConfigFormat::Toml
            }
        ));
        let cli = Cli::try_parse_from(["verd", "schema", "-o", "s.json"]).unwrap();
        assert!(matches!(cli.command, Command::Schema { output: Some(_) }));
        let cli = Cli::try_parse_from(["verd", "--log-level", "debug", "version"]).unwrap();
        assert_eq!(cli.log_level.as_deref(), Some("debug"));
        assert!(Cli::try_parse_from(["verd", "bogus"]).is_err());
        assert!(Cli::try_parse_from(["verd"]).is_err());
    }

    #[test]
    fn cmd_version_ok() {
        assert_eq!(cmd_version(), ExitCode::SUCCESS);
    }

    #[test]
    fn cmd_validate_paths() {
        let dir = tempfile::tempdir().unwrap();

        let valid = write_cfg(&dir, "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n");
        assert_eq!(
            cmd_validate(Some(valid), None, ValidateFormat::Text, false),
            ExitCode::SUCCESS
        );

        // valid but with warnings (unusual log level)
        let warned = write_cfg(
            &dir,
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[log]\nlevel = \"banana\"\n",
        );
        assert_eq!(
            cmd_validate(Some(warned), None, ValidateFormat::Text, false),
            ExitCode::SUCCESS
        );

        // an invalid config: non-loopback admin without token
        let invalid = write_cfg(
            &dir,
            "[admin]\nlisten = \"0.0.0.0:2019\"\n[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n",
        );
        assert_eq!(
            cmd_validate(Some(invalid), None, ValidateFormat::Text, false),
            ExitCode::FAILURE
        );

        // unreadable / malformed
        let missing = dir.path().join("ghost.toml");
        assert_eq!(
            cmd_validate(Some(missing), None, ValidateFormat::Text, false),
            ExitCode::FAILURE
        );
        let bad = write_cfg(&dir, "[[[\n");
        assert_eq!(
            cmd_validate(Some(bad), None, ValidateFormat::Text, false),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn cmd_validate_dry_build_catches_runtime_errors() {
        let dir = tempfile::tempdir().unwrap();
        // each of these passes load + semantic validation but used to
        // blow up only in Runtime::build — the dry build must catch them
        let cases = [
            // upstream URL with a path (validator checks scheme+host only)
            r#"
[upstream.api]
servers = ["http://10.0.0.1/has/a/path"]

[[site]]
hosts = ["x"]
proxy = "api"
"#,
            // argon2 prefix but a garbage body
            r#"
[[site]]
hosts = ["x"]

[[site.route]]
prefix = "/"
respond = { status = 200, body = "ok" }
auth = { basic = { users = { u = "$argon2id$garbage" } } }
"#,
            // access-log filter that won't parse
            r#"
[log.access]
filter = "bogus = x"

[[site]]
hosts = ["x"]
root = "/tmp"
"#,
            // server log output blocked by a file where the parent
            // directory would have to be created
            r#"
[log]
output = "/etc/passwd/server.log"

[[site]]
hosts = ["x"]
root = "/tmp"
"#,
        ];
        for (i, text) in cases.iter().enumerate() {
            let p = dir.path().join(format!("case{i}.toml"));
            std::fs::write(&p, text).unwrap();
            assert_eq!(
                cmd_validate(Some(p.clone()), None, ValidateFormat::Text, false),
                ExitCode::FAILURE,
                "case {i} should fail dry build:\n{text}"
            );
        }

        // a malformed --log-level fails the same way `verd run` would
        let ok = write_cfg(&dir, "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n");
        assert_eq!(
            cmd_validate(Some(ok.clone()), Some("!!bad"), ValidateFormat::Text, false),
            ExitCode::FAILURE
        );
        assert_eq!(
            cmd_validate(Some(ok), None, ValidateFormat::Text, false),
            ExitCode::SUCCESS
        );
    }

    #[test]
    fn cmd_fmt_modes() {
        let dir = tempfile::tempdir().unwrap();

        // sloppy spacing fails --check and is normalized in write mode
        let cfg = write_cfg(&dir, "[[site]]\nhosts=[\"x\"]   \n");
        assert_eq!(
            cmd_fmt(Some(cfg.clone()), true, false, false),
            ExitCode::FAILURE
        );
        assert_eq!(
            cmd_fmt(Some(cfg.clone()), false, false, false),
            ExitCode::SUCCESS
        );
        assert_eq!(
            cmd_fmt(Some(cfg.clone()), true, false, false),
            ExitCode::SUCCESS
        );

        // missing file → error; malformed → check-mode error
        let ghost = dir.path().join("ghost.toml");
        assert_eq!(cmd_fmt(Some(ghost), false, false, false), ExitCode::FAILURE);
        let bad = write_cfg(&dir, "[[[\n");
        assert_eq!(cmd_fmt(Some(bad), true, false, false), ExitCode::FAILURE);
    }

    #[test]
    fn cmd_fmt_all_covers_includes() {
        let dir = tempfile::tempdir().unwrap();
        let frag_dir = dir.path().join("conf.d");
        std::fs::create_dir(&frag_dir).unwrap();
        let frag = frag_dir.join("site.toml");
        std::fs::write(&frag, "[[site]]\nhosts=[\"x\"]\nroot=\"/tmp\"\n").unwrap();
        let cfg = write_cfg(&dir, "include = [\"conf.d\"]\n[log]\nlevel=\"info\"\n");

        // --check reports drift in both files
        assert_eq!(
            cmd_fmt(Some(cfg.clone()), true, false, true),
            ExitCode::FAILURE
        );
        // write mode formats every source
        assert_eq!(
            cmd_fmt(Some(cfg.clone()), false, false, true),
            ExitCode::SUCCESS
        );
        assert!(
            std::fs::read_to_string(&frag)
                .unwrap()
                .contains("hosts = [\"x\"]")
        );
        assert_eq!(cmd_fmt(Some(cfg), true, false, true), ExitCode::SUCCESS);
    }

    #[test]
    fn cmd_validate_strict_and_json() {
        let dir = tempfile::tempdir().unwrap();
        // valid but warns (unusual log level) — fails only under --strict
        let warned = write_cfg(
            &dir,
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n[log]\nlevel = \"banana\"\n",
        );
        assert_eq!(
            cmd_validate(Some(warned.clone()), None, ValidateFormat::Text, false),
            ExitCode::SUCCESS
        );
        assert_eq!(
            cmd_validate(Some(warned.clone()), None, ValidateFormat::Text, true),
            ExitCode::FAILURE
        );
        assert_eq!(
            cmd_validate(Some(warned), None, ValidateFormat::Json, false),
            ExitCode::SUCCESS
        );
        let invalid = write_cfg(&dir, "bogus_key = 1\n");
        assert_eq!(
            cmd_validate(Some(invalid), None, ValidateFormat::Json, false),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn cmd_init_writes_template() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("verd.toml");
        assert_eq!(cmd_init(out.clone(), false), ExitCode::SUCCESS);
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(
            text.contains("[server]") && text.contains("[[site]]"),
            "{text}"
        );
        // refuses to overwrite without --force
        assert_eq!(cmd_init(out.clone(), false), ExitCode::FAILURE);
        assert_eq!(cmd_init(out, true), ExitCode::SUCCESS);
        // "-" prints to stdout
        assert_eq!(cmd_init(PathBuf::from("-"), false), ExitCode::SUCCESS);
        // the template itself must validate
        let parsed = crate::config::load(&dir.path().join("verd.toml")).unwrap();
        assert!(parsed.is_valid(), "{:?}", parsed.diagnostics);
    }

    #[test]
    fn cmd_schema_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("schema.json");
        assert_eq!(cmd_schema(Some(out.clone())), ExitCode::SUCCESS);
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("\"Config\"")
        );

        // stdout variant
        assert_eq!(cmd_schema(None), ExitCode::SUCCESS);

        // unwritable target → failure
        assert_eq!(
            cmd_schema(Some(dir.path().join("no/such/dir/s.json"))),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn missing_config_error_is_exit_1() {
        assert_eq!(
            missing_config_error(&[PathBuf::from("a"), PathBuf::from("b")]),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn cmd_run_rejects_bad_config() {
        let dir = tempfile::tempdir().unwrap();
        // load failure → exit 1
        let bad = write_cfg(&dir, "[[[\n");
        assert_eq!(cmd_run(Some(bad), false, None), ExitCode::FAILURE);
        // semantic errors → exit 1 (before runtime build)
        let invalid = write_cfg(&dir, "[[site]]\nroot = \"/tmp\"\n");
        assert_eq!(cmd_run(Some(invalid), false, None), ExitCode::FAILURE);
    }
}
