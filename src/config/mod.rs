//! Configuration loading: TOML file → interpolation → `include` merging →
//! typed [`Config`] → semantic validation.

mod interpolate;
pub mod model;
pub(crate) mod validate;
mod values;

/// `verd fmt` — comment-preserving TOML formatter.
pub mod fmt;

pub use interpolate::InterpolateError;
pub use model::Config;
pub use validate::{Diagnostic, Severity, validate};
pub use values::{ByteSize, RateSpec};

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors while loading a configuration file.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read {0}: {1}")]
    Io(PathBuf, String),
    /// The TOML is malformed.
    #[error("{0}: TOML syntax error: {1}")]
    Syntax(PathBuf, String),
    /// Secret interpolation failed.
    #[error("{0}: {1}")]
    Interpolate(PathBuf, InterpolateError),
    /// The TOML did not match the configuration schema.
    #[error("{0}: invalid configuration: {1}")]
    Schema(PathBuf, String),
    /// An `include` entry is not a file or directory.
    #[error("{0}: include target {1} does not exist or is not readable")]
    IncludeMissing(PathBuf, PathBuf),
    /// Includes exceeded the maximum nesting depth (cycle?).
    #[error("{0}: includes nested deeper than {1} levels (cycle?)")]
    IncludeDepth(PathBuf, usize),
    /// Two fragments set the same scalar to different values.
    #[error(
        "{0}: key {1:?} is set to conflicting values by multiple config sources (arrays append; scalars must agree)"
    )]
    MergeConflict(PathBuf, String),
}

const MAX_INCLUDE_DEPTH: usize = 8;

/// A fully loaded configuration plus its diagnostics.
pub struct Loaded {
    /// The parsed configuration.
    pub config: Config,
    /// Semantic diagnostics (warnings may accompany a valid config).
    pub diagnostics: Vec<Diagnostic>,
}

impl Loaded {
    /// Whether the configuration has no error-severity diagnostics.
    pub fn is_valid(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }

    /// The errors (severity = error) among the diagnostics.
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
    }
}

/// Load a configuration file: read → interpolate → merge includes →
/// deserialize → validate.
pub fn load(path: &Path) -> Result<Loaded, LoadError> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let value = load_document(&path, 0)?;
    let config: Config = value
        .try_into()
        .map_err(|e| LoadError::Schema(path.clone(), e.to_string()))?;
    let mut diagnostics = validate(&config);
    diagnostics.extend(config_file_perm_diag(&path, &config));
    Ok(Loaded {
        config,
        diagnostics,
    })
}

/// Key names that smell secret-bearing — values under them are blanked in
/// config dumps (`verd config`, admin `/config`).
pub(crate) const SECRET_KEYS: [&str; 6] =
    ["password", "token", "secret", "key", "key_file", "api_key"];

/// Header-style key suffixes that carry credentials — matched as
/// *suffixes* so `Authorization`/`Set-Cookie`/`X-Token-Cookie` are caught
/// while `cookies` (a list of cookie *names* for cache bypass) is not.
const SECRET_SUFFIXES: [&str; 2] = ["authorization", "cookie"];

/// Does a config key name suggest the value beneath it is a secret?
/// Shared by `verd config` dumps and the admin `/config` endpoint.
pub(crate) fn key_is_secret(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|s| k.contains(s)) || SECRET_SUFFIXES.iter().any(|s| k.ends_with(s))
}

/// Serialize the effective configuration as TOML with secrets redacted —
/// the merged, interpolated, fully-defaulted view (`verd config`).
pub fn dump(cfg: &Config) -> Result<String, String> {
    let mut v = toml::Value::try_from(cfg).map_err(|e| e.to_string())?;
    redact_toml(&mut v);
    toml::to_string_pretty(&v).map_err(|e| e.to_string())
}

/// Recursively replace values whose key name suggests a secret, and scrub
/// `user:pass@` credentials embedded in URL strings.
fn redact_toml(v: &mut toml::Value) {
    match v {
        toml::Value::Table(m) => {
            for (k, val) in m.iter_mut() {
                if key_is_secret(k) {
                    *val = toml::Value::String("***".into());
                } else {
                    redact_toml(val);
                }
            }
        }
        toml::Value::Array(a) => a.iter_mut().for_each(redact_toml),
        toml::Value::String(s) => {
            if let Some(scheme_end) = s.find("://") {
                let rest = &s[scheme_end + 3..];
                let authority_end = rest.find('/').unwrap_or(rest.len());
                let authority = &rest[..authority_end];
                if let Some(at) = authority.rfind('@')
                    && at > 0
                {
                    *s = format!("{}://***@{}", &s[..scheme_end], &authority[at + 1..]);
                }
            }
        }
        _ => {}
    }
}

/// Warn when the config file itself is unsafe: group/other-writable is
/// always flagged; group/other-*readable* is flagged only when the
/// config embeds literal secrets (tokens/api keys — `${file:}` and
/// `${env}` references don't count).
#[cfg(unix)]
fn config_file_perm_diag(path: &Path, config: &Config) -> Option<Diagnostic> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Some(Diagnostic {
            severity: Severity::Warning,
            path: path.display().to_string(),
            message: format!(
                "config file is group/other-writable (mode {mode:o}) — chmod 640 or 600"
            ),
        });
    }
    let has_inline_secrets = config.admin.token.is_some()
        || config.site.iter().any(|s| {
            s.route.iter().any(|r| {
                r.auth.as_ref().is_some_and(|a| {
                    a.bearer.as_ref().is_some_and(|b| !b.tokens.is_empty())
                        || a.api_key.as_ref().is_some_and(|k| !k.keys.is_empty())
                })
            })
        });
    if has_inline_secrets && mode & 0o044 != 0 {
        return Some(Diagnostic {
            severity: Severity::Warning,
            path: path.display().to_string(),
            message: format!(
                "config file is group/other-readable (mode {mode:o}) and contains inline credentials — chmod 640 or move secrets to ${{file:}} references"
            ),
        });
    }
    None
}

/// Config permission checks only exist on unix.
#[cfg(not(unix))]
fn config_file_perm_diag(_: &Path, _: &Config) -> Option<Diagnostic> {
    None
}

/// Parse one TOML document, interpolate secrets, and recursively merge its
/// `include` targets (which are resolved relative to the document's dir).
fn load_document(path: &Path, depth: usize) -> Result<toml::Value, LoadError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(LoadError::IncludeDepth(
            path.to_path_buf(),
            MAX_INCLUDE_DEPTH,
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| LoadError::Io(path.to_path_buf(), e.to_string()))?;
    let mut value: toml::Value =
        toml::from_str(&text).map_err(|e| LoadError::Syntax(path.to_path_buf(), e.to_string()))?;
    interpolate::interpolate(&mut value)
        .map_err(|e| LoadError::Interpolate(path.to_path_buf(), e))?;

    let base_dir = path.parent().unwrap_or(Path::new("."));
    let includes: Vec<String> = value
        .get("include")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if let Some(table) = value.as_table_mut() {
        table.remove("include");
    }

    for include in includes {
        for fragment in expand_include(base_dir, &include).map_err(|e| match e {
            LoadError::IncludeMissing(_, p) => LoadError::IncludeMissing(path.to_path_buf(), p),
            e => e,
        })? {
            let frag = load_document(&fragment, depth + 1)?;
            merge(&mut value, frag)
                .map_err(|key| LoadError::MergeConflict(fragment.clone(), key))?;
        }
    }
    Ok(value)
}

/// Expand an include entry to a sorted list of files: the file itself,
/// every `*.toml` directly inside the directory, or a glob pattern like
/// `conf.d/*.toml` or `extra-*.toml` (`*` matches any characters).
fn expand_include(base_dir: &Path, include: &str) -> Result<Vec<PathBuf>, LoadError> {
    let target = base_dir.join(include);
    if target.is_file() {
        return Ok(vec![target]);
    }
    if target.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&target)
            .map_err(|e| LoadError::Io(target.clone(), e.to_string()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file())
            .collect();
        files.sort();
        return Ok(files);
    }
    if include.contains('*') {
        // Split at the last '/' before the first '*' into a literal
        // directory part and a filename glob.
        let star = include.find('*').unwrap_or(include.len());
        let dir_len = include[..star].rfind('/').map(|i| i + 1).unwrap_or(0);
        let (dir_part, name_pat) = include.split_at(dir_len);
        let dir = base_dir.join(if dir_part.is_empty() { "." } else { dir_part });
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| LoadError::Io(dir.clone(), e.to_string()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| crate::handler::static_files::glob_match(name_pat, n))
            })
            .collect();
        files.sort();
        // Zero matches is not an error: `conf.d/*.toml` is meant to be
        // populated later. A missing directory still fails via read_dir.
        return Ok(files);
    }
    Err(LoadError::IncludeMissing(target.clone(), target))
}

/// Deep-merge `frag` into `base`: tables merge recursively, arrays append,
/// scalars must not conflict.
fn merge(base: &mut toml::Value, frag: toml::Value) -> Result<(), String> {
    match (base, frag) {
        (toml::Value::Table(b), toml::Value::Table(f)) => {
            for (key, fval) in f {
                match b.get_mut(&key) {
                    Some(bval) => merge(bval, fval).map_err(|sub| {
                        if sub.is_empty() {
                            key.clone()
                        } else {
                            format!("{key}.{sub}")
                        }
                    })?,
                    None => {
                        b.insert(key, fval);
                    }
                }
            }
            Ok(())
        }
        (toml::Value::Array(b), toml::Value::Array(f)) => {
            b.extend(f);
            Ok(())
        }
        (b, f) => {
            if *b == f {
                Ok(())
            } else {
                Err(String::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        p
    }

    #[test]
    fn loads_minimal_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[[site]]
hosts = ["example.com"]
root = "./public"
"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.site.len(), 1);
        assert!(loaded.is_valid(), "{:?}", loaded.diagnostics);
    }

    #[test]
    fn include_directory_merges_fragments() {
        let dir = tempfile::tempdir().unwrap();
        let frag_dir = dir.path().join("conf.d");
        std::fs::create_dir(&frag_dir).unwrap();
        write(
            &frag_dir,
            "01-a.toml",
            r#"[[site]]
hosts = ["a.example.com"]
root = "./a"
"#,
        );
        write(
            &frag_dir,
            "02-b.toml",
            r#"[[site]]
hosts = ["b.example.com"]
proxy = ["http://10.0.0.1:9000"]
"#,
        );
        write(&frag_dir, "ignored.txt", "not toml");
        let path = write(
            dir.path(),
            "verd.toml",
            r#"include = ["conf.d"]

[log]
level = "debug"
"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.site.len(), 2);
        assert_eq!(loaded.config.log.level, "debug");
    }

    #[test]
    fn scalar_conflict_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "frag.toml",
            r#"[log]
level = "warn"
"#,
        );
        let path = write(
            dir.path(),
            "verd.toml",
            r#"include = ["frag.toml"]

[log]
level = "info"
"#,
        );
        assert!(matches!(load(&path), Err(LoadError::MergeConflict(_, _))));
    }

    #[test]
    fn upstream_tables_merge_by_name() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "frag.toml",
            r#"[upstream.api]
servers = ["http://10.0.0.1:1"]
"#,
        );
        let path = write(
            dir.path(),
            "verd.toml",
            r#"include = ["frag.toml"]

[upstream.web]
servers = ["http://10.0.0.2:2"]

[[site]]
hosts = ["x"]
[[site.route]]
path = "/"
proxy = { upstream = "api" }
"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.upstream.len(), 2);
        assert!(loaded.is_valid(), "{:?}", loaded.diagnostics);
    }

    #[test]
    fn include_cycle_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.toml", r#"include = ["b.toml"]"#);
        write(dir.path(), "b.toml", r#"include = ["a.toml"]"#);
        let path = dir.path().join("a.toml");
        assert!(matches!(load(&path), Err(LoadError::IncludeDepth(_, _))));
    }

    #[test]
    fn secrets_interpolated_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("token");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"s3cr3t\n")
            .unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            &format!("[admin]\ntoken = \"${{file:{}}}\"\n", secret.display()),
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.admin.token.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn schema_errors_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", "bogus_key = 1\n");
        assert!(matches!(load(&path), Err(LoadError::Schema(_, _))));
    }

    #[test]
    fn load_error_variants() {
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("nope.toml");
        assert!(matches!(load(&missing), Err(LoadError::Io(_, _))));

        let path = write(dir.path(), "bad.toml", "[[site]\n");
        assert!(matches!(load(&path), Err(LoadError::Syntax(_, _))));

        let path = write(
            dir.path(),
            "interp.toml",
            "[admin]\ntoken = \"${DEFINITELY_MISSING_ENV}\"\n",
        );
        assert!(matches!(load(&path), Err(LoadError::Interpolate(_, _))));

        let path = write(dir.path(), "inc.toml", "include = [\"ghost.toml\"]\n");
        assert!(matches!(load(&path), Err(LoadError::IncludeMissing(_, _))));
    }

    #[test]
    fn errors_iterator_filters() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", "[[site]]\nroot = \"/tmp\"\n");
        let loaded = load(&path).unwrap();
        assert!(loaded.errors().count() > 0);
        assert!(!loaded.is_valid());
        // warnings don't affect validity
        let path = write(
            dir.path(),
            "warn.toml",
            "[admin]\nlisten = \"127.0.0.1:2019\"\n[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n",
        );
        let loaded = load(&path).unwrap();
        assert!(loaded.is_valid());
        assert_eq!(loaded.errors().count(), 0);
    }

    #[test]
    fn merge_equal_scalars_and_arrays() {
        let mut base: toml::Value = toml::from_str("a = 1\nlist = [1]").unwrap();
        let frag: toml::Value = toml::from_str("a = 1\nlist = [2]").unwrap();
        merge(&mut base, frag).unwrap();
        assert_eq!(base["a"].as_integer(), Some(1));
        assert_eq!(base["list"].as_array().unwrap().len(), 2);

        let mut base: toml::Value = toml::from_str("a = 1").unwrap();
        let frag: toml::Value = toml::from_str("a = 2").unwrap();
        assert!(merge(&mut base, frag).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn config_file_permissions_warned() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", "[admin]\ntoken = \"s3cr3t\"\n");

        // group/other-writable is always flagged
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).unwrap();
        let loaded = load(&path).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .any(|d| d.message.contains("group/other-writable")),
            "{:?}",
            loaded.diagnostics
        );

        // group/other-readable flagged only because inline secrets exist
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load(&path).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .any(|d| d.message.contains("group/other-readable")),
            "{:?}",
            loaded.diagnostics
        );

        // same mode, no inline secrets → no warning
        let path2 = write(dir.path(), "plain.toml", "[log]\nlevel = \"info\"\n");
        std::fs::set_permissions(&path2, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load(&path2).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("readable")),
            "{:?}",
            loaded.diagnostics
        );

        // private mode → silent
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = load(&path).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("config file is")),
            "{:?}",
            loaded.diagnostics
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn config_file_permissions_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", "");
        assert!(config_file_perm_diag(&path, &Config::default()).is_none());
    }

    #[test]
    fn include_glob_expands_matches() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "extra-01.toml",
            r#"[[site]]
hosts = ["a.example.com"]
root = "/tmp"
"#,
        );
        write(
            dir.path(),
            "extra-02.toml",
            r#"[[site]]
hosts = ["b.example.com"]
root = "/tmp"
"#,
        );
        write(
            dir.path(),
            "other.toml",
            r#"[log]
level = "warn"
"#,
        );
        let path = write(
            dir.path(),
            "verd.toml",
            r#"include = ["extra-*.toml"]
"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.site.len(), 2);
        // glob only matched extra-*, so log.level keeps the default
        assert_eq!(loaded.config.log.level, "info");
    }

    #[test]
    fn include_glob_in_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let frag_dir = dir.path().join("conf.d");
        std::fs::create_dir(&frag_dir).unwrap();
        write(
            &frag_dir,
            "site-x.toml",
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n",
        );
        write(&frag_dir, "notes.md", "not a match");
        let path = write(
            dir.path(),
            "verd.toml",
            r#"include = ["conf.d/site-*.toml"]"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.site.len(), 1);
    }

    #[test]
    fn include_glob_no_match_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", r#"include = ["ghost-*.toml"]"#);
        assert!(load(&path).is_ok());
    }

    #[test]
    fn include_glob_missing_dir_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", r#"include = ["nope/*.toml"]"#);
        assert!(load(&path).is_err());
    }

    #[test]
    fn merge_conflict_path_has_no_trailing_dot() {
        let mut base: toml::Value = toml::from_str("[log]\nlevel = \"info\"").unwrap();
        let frag: toml::Value = toml::from_str("[log]\nlevel = \"debug\"").unwrap();
        let err = merge(&mut base, frag).unwrap_err();
        assert_eq!(err, "log.level");
    }

    #[test]
    fn dump_redacts_secret_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[admin]
token = "hunter2"
[[site]]
hosts = ["x"]
root = "/tmp"
"#,
        );
        let loaded = load(&path).unwrap();
        let out = dump(&loaded.config).unwrap();
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("***"), "{out}");
    }

    #[test]
    fn key_is_secret_suffix_vs_substring() {
        for key in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "api_key",
        ] {
            assert!(key_is_secret(key), "{key}");
        }
        // a list of cookie *names* is not a secret — suffix match only
        for key in ["cookies", "headers", "x-trace-id"] {
            assert!(!key_is_secret(key), "{key}");
        }
    }

    #[test]
    fn dump_redacts_secret_header_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[[site]]
hosts = ["x"]

[[site.route]]
path = "/"
respond = { status = 200, body = "ok" }
response_headers = { set = { Authorization = "hunter2", X-Plain = "shown" } }
"#,
        );
        let loaded = load(&path).unwrap();
        let out = dump(&loaded.config).unwrap();
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("X-Plain = \"shown\""), "{out}");
    }

    #[test]
    fn dump_redacts_url_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[[site]]
hosts = ["x"]
proxy = "http://user:pass@127.0.0.1:9000"
"#,
        );
        let loaded = load(&path).unwrap();
        let out = dump(&loaded.config).unwrap();
        assert!(!out.contains("user:pass"), "{out}");
        assert!(out.contains("http://***@127.0.0.1:9000"), "{out}");
    }

    #[test]
    fn graceful_timeout_accepts_humantime() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            "[server]\ngraceful_timeout = \"45s\"\n",
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.server.graceful_timeout.as_secs(), 45);
    }

    #[test]
    fn listen_accepts_bare_strings() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[server]
listen = ["0.0.0.0:8080", { addr = "0.0.0.0:8443", tls = true }]
"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.server.listen.len(), 2);
        assert!(!loaded.config.server.listen[0].tls);
        assert!(loaded.config.server.listen[1].tls);
    }

    #[test]
    fn hsts_max_age_accepts_int_and_duration() {
        let dir = tempfile::tempdir().unwrap();
        for (val, want_secs) in [("180", 180u64), ("\"30d\"", 30 * 24 * 3600)] {
            let path = write(
                dir.path(),
                "verd.toml",
                &format!("[server.security]\nhsts_max_age = {val}\n"),
            );
            let loaded = load(&path).unwrap();
            assert_eq!(
                loaded.config.server.security.hsts_max_age.as_secs(),
                want_secs
            );
        }
    }

    #[test]
    fn site_proxy_accepts_name_url_and_list() {
        let toml_src = r#"
[upstream.app]
servers = ["http://10.0.0.1:1"]
[[site]]
hosts = ["x"]
proxy = "app"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "verd.toml", toml_src);
        let loaded = load(&path).unwrap();
        assert!(loaded.is_valid(), "{:?}", loaded.diagnostics);

        for proxy in [
            "\"http://127.0.0.1:9000\"",
            "[\"http://127.0.0.1:9000\", \"http://127.0.0.1:9001\"]",
        ] {
            let path = write(
                dir.path(),
                "v2.toml",
                &format!("[[site]]\nhosts = [\"x\"]\nproxy = {proxy}\n"),
            );
            let loaded = load(&path).unwrap();
            assert!(loaded.is_valid(), "{proxy}: {:?}", loaded.diagnostics);
        }

        // a bare URL string is read as a URL, not a name
        let path = write(
            dir.path(),
            "v3.toml",
            "[[site]]\nhosts = [\"x\"]\nproxy = \"missing\"\n",
        );
        let loaded = load(&path).unwrap();
        assert!(!loaded.is_valid());
        assert!(
            loaded
                .diagnostics
                .iter()
                .any(|d| d.message.contains("unknown upstream \"missing\"")),
            "{:?}",
            loaded.diagnostics
        );
    }

    #[test]
    fn upstream_limits_alias_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[upstream.app]
servers = ["http://10.0.0.1:1"]
[upstream.app.limits]
connect = "1s"
"#,
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.upstream["app"].timeouts.connect.as_secs(), 1);
    }

    #[test]
    fn replace_prefix_accepts_named_and_tuple() {
        let dir = tempfile::tempdir().unwrap();
        for rewrite in [
            r#"replace_prefix = { from = "/a", to = "/b" }"#,
            r#"replace_prefix = ["/a", "/b"]"#,
        ] {
            let path = write(
                dir.path(),
                "verd.toml",
                &format!(
                    "[[site]]\nhosts = [\"x\"]\n[[site.route]]\npath = \"/\"\nproxy = {{ upstream = \"http://127.0.0.1:1\", rewrite = {{ {rewrite} }} }}\n"
                ),
            );
            let loaded = load(&path).unwrap();
            let pp = loaded.config.site[0].route[0]
                .proxy
                .as_ref()
                .unwrap()
                .rewrite
                .as_ref()
                .unwrap()
                .replace_prefix
                .as_ref()
                .unwrap();
            assert_eq!(pp.pair(), ("/a", "/b"), "{rewrite}");
        }
    }

    #[test]
    fn enum_aliases_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            r#"[upstream.app]
servers = ["http://10.0.0.1:1"]
lb = "least-conn"
[[site]]
hosts = ["x"]
tls = "self-signed"
proxy = "app"
"#,
        );
        let loaded = load(&path).unwrap();
        assert!(loaded.is_valid(), "{:?}", loaded.diagnostics);
        assert!(matches!(
            loaded.config.site[0].tls,
            model::SiteTls::Mode(model::TlsMode::SelfSigned)
        ));
    }
}
