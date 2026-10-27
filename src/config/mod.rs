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
    /// An `include` key is present but not a list of path strings.
    #[error("{0}: `include` must be a list of path strings")]
    IncludeType(PathBuf),
    /// An `include` entry is not a file or directory.
    #[error("{0}: include target {1} does not exist or is not readable")]
    IncludeMissing(PathBuf, PathBuf),
    /// The include chain loops back to a file already being merged.
    #[error("{0}: include cycle — {1} is already on the include chain")]
    IncludeCycle(PathBuf, PathBuf),
    /// Includes exceeded the maximum nesting depth (cycle?).
    #[error("{0}: includes nested deeper than {1} levels (cycle?)")]
    IncludeDepth(PathBuf, usize),
    /// Two fragments set the same scalar to different values; the second
    /// path is the file that set it first.
    #[error(
        "{0}: key {1:?} conflicts with a value already set by {2} (arrays append; scalars must agree)"
    )]
    MergeConflict(PathBuf, String, String),
}

const MAX_INCLUDE_DEPTH: usize = 8;

/// A fully loaded configuration plus its diagnostics and the provenance
/// of where it came from (which `--watch` follows).
pub struct Loaded {
    /// The parsed configuration.
    pub config: Config,
    /// Semantic diagnostics (warnings may accompany a valid config).
    pub diagnostics: Vec<Diagnostic>,
    /// Every file read while loading, in load order (main file first).
    pub sources: Vec<PathBuf>,
    /// Directories named by `include` entries that can grow new fragments
    /// (directory and glob targets).
    pub watch_dirs: Vec<PathBuf>,
    /// Config paths that held a `${…}` marker before substitution.
    pub interpolated: std::collections::HashSet<String>,
    /// Files referenced by `${file:…}` markers.
    pub file_refs: Vec<PathBuf>,
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

    /// What `--watch` needs to follow this configuration on disk.
    pub fn watch_plan(&self) -> WatchPlan {
        let mut dirs = std::collections::BTreeSet::new();
        for p in self.sources.iter().chain(self.file_refs.iter()) {
            if let Some(parent) = p.parent()
                && !parent.as_os_str().is_empty()
            {
                dirs.insert(parent.to_path_buf());
            }
        }
        dirs.extend(self.watch_dirs.iter().cloned());
        WatchPlan {
            files: self
                .sources
                .iter()
                .chain(self.file_refs.iter())
                .cloned()
                .collect(),
            include_dirs: self.watch_dirs.iter().cloned().collect(),
            dirs,
        }
    }
}

/// The watch set for one config generation: which loaded paths a file
/// event must touch to be a reload trigger, and which directories a
/// physical watcher should observe.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WatchPlan {
    /// Files whose contents were read — includes and `${file:}`
    /// secrets. An event on any of them is a reload trigger (atomic
    /// renames report the target path, so replacement counts).
    pub files: std::collections::BTreeSet<PathBuf>,
    /// Directories that can grow new `*.toml` fragments (dir and glob
    /// `include` targets). A `*.toml` event inside one is a trigger.
    pub include_dirs: std::collections::BTreeSet<PathBuf>,
    /// Directories to physically observe (non-recursive): parents of
    /// every `files` entry — so atomic renames and k8s `..data` swaps
    /// fire — plus `include_dirs`.
    pub dirs: std::collections::BTreeSet<PathBuf>,
}

impl WatchPlan {
    /// Should a filesystem event trigger a config reload?
    ///
    /// Only real mutations count: a reload reads every file in `files`,
    /// and the resulting access events would retrigger the watcher
    /// forever. Paths must name a loaded file, a `*.toml` fragment in an
    /// include dir, or a k8s `..data` symlink swap — anything else
    /// (server/access logs, cache files next to the config, …) is noise.
    pub fn hit(&self, ev: &notify::Event) -> bool {
        if !matches!(
            ev.kind,
            notify::EventKind::Create(_)
                | notify::EventKind::Modify(_)
                | notify::EventKind::Remove(_)
        ) {
            return false;
        }
        ev.paths.iter().any(|p| {
            self.files.contains(p)
                || p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("..data"))
                || (p.extension().is_some_and(|x| x == "toml")
                    && p.parent().is_some_and(|d| self.include_dirs.contains(d)))
        })
    }
}

/// Load a configuration file: read → interpolate → merge includes →
/// deserialize → validate.
pub fn load(path: &Path) -> Result<Loaded, LoadError> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut report = LoadReport::default();
    let (value, origins) = load_document(&path, 0, &mut report)?;
    let config: Config = serde_path_to_error::deserialize(value).map_err(|e| {
        LoadError::Schema(
            path.clone(),
            format!(
                "{}: {}",
                normalize_serde_path(&e.path().to_string()),
                e.inner()
            ),
        )
    })?;
    let mut diagnostics = validate(&config);
    for d in &mut diagnostics {
        d.source = origin_for(&config, &origins, &d.path);
    }
    diagnostics.extend(config_file_perm_diag(&report));
    Ok(Loaded {
        config,
        diagnostics,
        sources: report.sources,
        watch_dirs: report.watch_dirs,
        interpolated: report.interpolated,
        file_refs: report.file_refs.into_iter().map(|(_, p)| p).collect(),
    })
}

/// Key-name *segments* that smell secret-bearing — the key is split on
/// non-alphanumeric characters and matched as whole words, so `monkey`
/// and `key_id` stay visible while `X-Api-Key`, `api_token`, `tokens`,
/// and `keys` are caught.
const SECRET_SEGMENTS: [&str; 8] = [
    "key", "keys", "token", "tokens", "secret", "password", "passwd", "apikey",
];

/// Header-style key suffixes that carry credentials — matched as
/// *suffixes* so `Authorization`/`Set-Cookie`/`X-Token-Cookie` are caught
/// while `cookies` (a list of cookie *names* for cache bypass) is not.
const SECRET_SUFFIXES: [&str; 2] = ["authorization", "cookie"];

/// Whether `ancestors` (dotted key path) ends with `tail`.
fn tail_is(ancestors: &[String], tail: &[&str]) -> bool {
    ancestors.len() >= tail.len()
        && ancestors[ancestors.len() - tail.len()..]
            .iter()
            .map(String::as_str)
            .eq(tail.iter().copied())
}

/// Does a key at a config path suggest its value is a secret? Shared by
/// `verd config` dumps and the admin `/config` endpoint. `is_table` is
/// true when the value under the key is a table/object — a container
/// still gets its leaves visited, so carving it out lets non-secret
/// siblings show while the secret members inside are blanked.
pub(crate) fn secret_at(ancestors: &[String], key: &str, is_table: bool) -> bool {
    // every value under `auth.basic.users` is a password hash
    if tail_is(ancestors, &["auth", "basic", "users"]) {
        return true;
    }
    let k = key.to_ascii_lowercase();
    // `key`/`key_file` under a `tls` table is a PEM path, not material
    if matches!(k.as_str(), "key" | "key_file")
        && ancestors.last().map(String::as_str) == Some("tls")
    {
        return false;
    }
    // `eab.key_id` is an identifier; the `key` next to it is the secret
    if k == "key_id" {
        return false;
    }
    // `[auth.api_key]` is a table of settings — only `keys` inside is
    // secret; a *scalar* (header value) or *array* (list of keys) named
    // `api_key`/`x-api-key` still counts
    if k == "api_key" && is_table {
        return false;
    }
    k.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|seg| SECRET_SEGMENTS.contains(&seg))
        || SECRET_SUFFIXES.iter().any(|s| k.ends_with(s))
}

/// Serialize the effective configuration as TOML with secrets redacted —
/// the merged, interpolated, fully-defaulted view (`verd config`).
pub fn dump(cfg: &Config) -> Result<String, String> {
    let mut v = toml::Value::try_from(cfg).map_err(|e| e.to_string())?;
    redact_toml(&mut v, &mut Vec::new(), false);
    toml::to_string_pretty(&v).map_err(|e| e.to_string())
}

/// Serialize the effective configuration as JSON with secrets redacted —
/// `verd config --format json` and the admin `/config` endpoint share
/// this so the two redaction policies can't drift.
pub fn dump_json(cfg: &Config) -> Result<String, String> {
    let mut v = serde_json::to_value(cfg).map_err(|e| e.to_string())?;
    redact_json(&mut v, &mut Vec::new(), false);
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

/// Recursively blank leaf values under secret-named keys — the JSON
/// twin of `redact_toml`, shared by `verd config` and admin `/config`.
pub(crate) fn redact_json(v: &mut serde_json::Value, path: &mut Vec<String>, under_secret: bool) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                let secret = under_secret || secret_at(path, k, val.is_object());
                path.push(k.clone());
                redact_json(val, path, secret);
                path.pop();
            }
        }
        serde_json::Value::Array(a) => {
            for val in a.iter_mut() {
                redact_json(val, path, under_secret);
            }
        }
        serde_json::Value::String(s) => {
            if under_secret {
                *s = "***".into();
            } else if let Some(scheme_end) = s.find("://") {
                // credentials embedded in URL userinfo:
                // `scheme://user:pass@host` — the `url` key doesn't smell
                // secret but the value is
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
        _ => {
            if under_secret {
                *v = serde_json::json!("***");
            }
        }
    }
}

/// Recursively blank leaf values under secret-named keys, and scrub
/// `user:pass@` credentials embedded in URL strings.
fn redact_toml(v: &mut toml::Value, path: &mut Vec<String>, under_secret: bool) {
    match v {
        toml::Value::Table(m) => {
            for (k, val) in m.iter_mut() {
                let secret = under_secret || secret_at(path, k, val.is_table());
                path.push(k.clone());
                redact_toml(val, path, secret);
                path.pop();
            }
        }
        toml::Value::Array(a) => {
            for val in a.iter_mut() {
                redact_toml(val, path, under_secret);
            }
        }
        toml::Value::String(s) => {
            if under_secret {
                *s = "***".into();
            } else if let Some(scheme_end) = s.find("://") {
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
        _ => {
            if under_secret {
                *v = toml::Value::String("***".into());
            }
        }
    }
}

/// Config fields holding filesystem paths, as dotted patterns where `*`
/// matches one segment (an array index or map key). Values under these
/// keys are rewritten at load to anchor on their document's directory —
/// the same anchor `include` uses — so a config tree relocates as a
/// unit. `error_pages`/`try_files` are excluded by design: they resolve
/// against `static.root`, not any file-system base. `include` and
/// `${file:}` are already file-anchored. Built-in defaults are not
/// document values and keep their documented CWD-relative meaning.
const PATH_FIELDS: &[&str] = &[
    "site.*.root",
    "site.*.route.*.static.root",
    "site.*.tls.cert",
    "site.*.tls.key",
    "admin.tls.cert",
    "admin.tls.key",
    "site.*.route.*.auth.basic.htpasswd",
    "cache.*.disk_path",
    "acme.storage",
    "acme.ca_roots",
    "upstream.*.tls.ca",
    "log.output",
    "log.access.output",
];

/// `log.*.output` destinations that are not paths.
fn is_output_sentinel(v: &str) -> bool {
    v == "stdout" || v == "stderr"
}

/// Does `path` match `pattern` (`*` = any single segment)?
fn path_pattern_matches(pattern: &str, path: &[String]) -> bool {
    let mut pat = pattern.split('.');
    let mut seg = path.iter();
    loop {
        match (pat.next(), seg.next()) {
            (None, None) => return true,
            (Some(p), Some(s)) if p == "*" || p == s => continue,
            _ => return false,
        }
    }
}

/// Rewrite relative paths under [`PATH_FIELDS`] onto `base_dir` — the
/// anchor `include` already uses — so a fragment's relative paths stay
/// next to the fragment, not the process CWD. Absolute paths and the
/// `log.*.output` sentinels pass through.
fn rebase_paths(v: &mut toml::Value, base_dir: &Path, path: &mut Vec<String>) {
    match v {
        toml::Value::Table(m) => {
            for (k, val) in m.iter_mut() {
                path.push(k.clone());
                rebase_paths(val, base_dir, path);
                path.pop();
            }
        }
        toml::Value::Array(a) => {
            for (i, val) in a.iter_mut().enumerate() {
                path.push(i.to_string());
                rebase_paths(val, base_dir, path);
                path.pop();
            }
        }
        toml::Value::String(s) => {
            if is_output_sentinel(s) {
                return;
            }
            let p = Path::new(s.as_str());
            if p.is_relative()
                && PATH_FIELDS
                    .iter()
                    .any(|pat| path_pattern_matches(pat, path))
            {
                *s = base_dir.join(p).to_string_lossy().into_owned();
            }
        }
        _ => {}
    }
}

/// Whether a dotted config path is secret-bearing — every ancestor key
/// is checked, so `…auth.bearer.tokens.0` counts even though its leaf
/// segment is an array index.
#[cfg(unix)]
fn path_is_secret(at: &str) -> bool {
    let segs: Vec<&str> = at.split('.').collect();
    (0..segs.len()).any(|i| {
        secret_at(
            &segs[..i].iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            segs[i],
            false,
        )
    })
}

/// Does a document contain literal (non-interpolated) secret material?
/// Walks like `redact_toml`: a leaf counts as secret when its key — or
/// any ancestor's — matches `secret_at`, unless the value held a `${…}`
/// marker (tracked in `substituted`).
fn has_inline_secret(v: &toml::Value, substituted: &std::collections::HashSet<String>) -> bool {
    fn walk(
        v: &toml::Value,
        path: &mut Vec<String>,
        under_secret: bool,
        sub: &std::collections::HashSet<String>,
    ) -> bool {
        match v {
            toml::Value::Table(m) => m.iter().any(|(k, val)| {
                let secret = under_secret || secret_at(path, k, val.is_table());
                path.push(k.clone());
                let r = walk(val, path, secret, sub);
                path.pop();
                r
            }),
            toml::Value::Array(a) => a.iter().enumerate().any(|(i, val)| {
                path.push(i.to_string());
                let r = walk(val, path, under_secret, sub);
                path.pop();
                r
            }),
            _ => under_secret && !sub.contains(&path.join(".")),
        }
    }
    walk(v, &mut Vec::new(), false, substituted)
}

/// Warn when config sources are unsafe: group/other-writable is always
/// flagged; group/other-*readable* is flagged only for files that embed
/// literal secrets, detected per document before merging so `include`d
/// fragments are checked with their own index space. `${file:}` targets
/// feeding secret-bearing paths are flagged when group/other-writable
/// (group/other-*readable* is not flagged: mounted secrets in k8s and
/// Docker are platform-managed `0444` by design and would warn on every
/// deployment).
#[cfg(unix)]
fn config_file_perm_diag(report: &LoadReport) -> Vec<Diagnostic> {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| {
        std::fs::metadata(p)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    };
    let mut out = Vec::new();
    for src in &report.sources {
        let Some(m) = mode(src) else { continue };
        if m & 0o022 != 0 {
            out.push(Diagnostic {
                severity: Severity::Warning,
                path: src.display().to_string(),
                message: format!(
                    "config file is group/other-writable (mode {m:o}) — chmod 640 or 600"
                ),
                source: None,
            });
        } else if report.files_with_secrets.contains(src) && m & 0o044 != 0 {
            out.push(Diagnostic {
                severity: Severity::Warning,
                path: src.display().to_string(),
                message: format!(
                    "config file is group/other-readable (mode {m:o}) and contains inline credentials — chmod 640 or move secrets to ${{file:}} references"
                ),
                source: None,
            });
        }
    }
    for (at, f) in &report.file_refs {
        if !path_is_secret(at) {
            continue;
        }
        let Some(m) = mode(f) else { continue };
        if m & 0o022 != 0 {
            out.push(Diagnostic {
                severity: Severity::Warning,
                path: f.display().to_string(),
                message: format!(
                    "secret file for {at} is group/other-writable (mode {m:o}) — chmod 640 or 600"
                ),
                source: None,
            });
        }
    }
    out
}

/// Config permission checks only exist on unix.
#[cfg(not(unix))]
fn config_file_perm_diag(_: &LoadReport) -> Vec<Diagnostic> {
    Vec::new()
}

/// Split a diagnostic display path on dots at bracket depth 0 — host
/// names inside `site["a.b.com"]` contain dots and must not split.
fn split_top(display: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;
    for (i, c) in display.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => {
                out.push(&display[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&display[start..]);
    out
}

/// Map a diagnostic display path (`site["x"].route[0].auth`) back to the
/// merged dotted form used by `origins` (`site.0.route.0.auth`). `site`
/// labels resolve through `name` first, then `hosts[0]` — mirroring
/// `site_label`'s own precedence.
fn display_to_dotted(cfg: &Config, display: &str) -> Option<String> {
    let mut out = Vec::new();
    for seg in split_top(display) {
        if let Some(rest) = seg.strip_prefix("site[") {
            let token = rest.strip_suffix(']')?;
            // last match wins on ambiguous labels — duplicate-host
            // style errors always fire on the later site
            let idx = if token == "default" {
                cfg.site.iter().rposition(|s| s.default)
            } else if let Some(name) = token.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
                cfg.site
                    .iter()
                    .rposition(|s| s.name.as_deref() == Some(name))
                    .or_else(|| {
                        cfg.site
                            .iter()
                            .rposition(|s| s.hosts.first().map(String::as_str) == Some(name))
                    })
            } else {
                token.parse::<usize>().ok()
            }?;
            out.push(format!("site.{idx}"));
        } else if let Some(pos) = seg.rfind('[') {
            let (key, rest) = seg.split_at(pos);
            let idx: usize = rest.strip_prefix('[')?.strip_suffix(']')?.parse().ok()?;
            out.push(format!("{key}.{idx}"));
        } else {
            out.push(seg.to_string());
        }
    }
    Some(out.join("."))
}

/// Which file set the value a diagnostic points at — via merged dotted
/// leaf paths in `origins`. An exact leaf hit wins; otherwise the file
/// owning the most descendant leaves represents "who set this subtree".
fn origin_for(
    cfg: &Config,
    origins: &std::collections::HashMap<String, PathBuf>,
    display: &str,
) -> Option<PathBuf> {
    let dotted = display_to_dotted(cfg, display)?;
    if let Some(p) = origins.get(&dotted) {
        return Some(p.clone());
    }
    let prefix = format!("{dotted}.");
    let mut counts: std::collections::BTreeMap<&PathBuf, usize> = std::collections::BTreeMap::new();
    for (k, file) in origins {
        if k.starts_with(&prefix) {
            *counts.entry(file).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(p, _)| p.clone())
}

/// Paths of every array node in a document → its element count. Used to
/// rebase fragment leaf paths onto merged positions: when an array
/// exists in both documents, concatenation shifts the fragment's
/// indices by the base length.
fn array_lens(v: &toml::Value) -> std::collections::HashMap<String, usize> {
    fn walk(
        v: &toml::Value,
        path: &mut Vec<String>,
        out: &mut std::collections::HashMap<String, usize>,
    ) {
        match v {
            toml::Value::Table(m) => {
                for (k, val) in m {
                    path.push(k.clone());
                    walk(val, path, out);
                    path.pop();
                }
            }
            toml::Value::Array(a) => {
                out.insert(path.join("."), a.len());
                for (i, val) in a.iter().enumerate() {
                    path.push(i.to_string());
                    walk(val, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = std::collections::HashMap::new();
    walk(v, &mut Vec::new(), &mut out);
    out
}

/// Translate a fragment-local leaf path to its merged position: each
/// array-index segment shifts by the base array's length when that
/// array exists in both documents. Array nodes inside a *newly
/// appended* element never exist in base and don't shift — the rebased
/// prefix lookup misses for them by construction.
fn rebased_leaf(
    leaf: &[String],
    base_arrays: &std::collections::HashMap<String, usize>,
    frag_arrays: &std::collections::HashMap<String, usize>,
) -> String {
    let mut segs: Vec<String> = leaf.to_vec();
    for i in 1..segs.len() {
        if !frag_arrays.contains_key(&leaf[..i].join(".")) {
            continue;
        }
        if let (Some(&len), Ok(idx)) = (
            base_arrays.get(&segs[..i].join(".")),
            segs[i].parse::<usize>(),
        ) {
            segs[i] = (len + idx).to_string();
        }
    }
    segs.join(".")
}

/// Load-time bookkeeping accumulated while a document and its `include`
/// fragments are read.
#[derive(Debug, Default)]
struct LoadReport {
    /// Every file read, in load order.
    sources: Vec<PathBuf>,
    /// Directories named by `include` entries that can grow fragments.
    watch_dirs: Vec<PathBuf>,
    /// Config paths that held a `${…}` marker before substitution.
    interpolated: std::collections::HashSet<String>,
    /// `${file:…}` targets paired with the document-local config path
    /// that referenced each.
    file_refs: Vec<(String, PathBuf)>,
    /// Source files containing literal (non-interpolated) secret
    /// values — per-file input to the permission diagnostics.
    files_with_secrets: std::collections::HashSet<PathBuf>,
    /// Canonical paths already fully merged — diamond includes merge once.
    done: std::collections::HashSet<PathBuf>,
    /// The active include chain — revisiting a file on it is a cycle.
    stack: Vec<PathBuf>,
}

/// Parse one TOML document, interpolate secrets, and recursively merge its
/// `include` targets (which are resolved relative to the document's dir).
///
/// Canonicalizes `path` so cycle detection (`stack`) and diamond dedupe
/// (`done`) work across different spellings of the same file.
fn load_document(
    path: &Path,
    depth: usize,
    report: &mut LoadReport,
) -> Result<(toml::Value, std::collections::HashMap<String, PathBuf>), LoadError> {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    report.stack.push(canon.clone());
    let out = load_document_impl(&canon, depth, report);
    report.stack.pop();
    if out.is_ok() {
        report.done.insert(canon);
    }
    out
}

fn load_document_impl(
    path: &Path,
    depth: usize,
    report: &mut LoadReport,
) -> Result<(toml::Value, std::collections::HashMap<String, PathBuf>), LoadError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(LoadError::IncludeDepth(
            path.to_path_buf(),
            MAX_INCLUDE_DEPTH,
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| LoadError::Io(path.to_path_buf(), e.to_string()))?;
    report.sources.push(path.to_path_buf());
    let mut value: toml::Value =
        toml::from_str(&text).map_err(|e| LoadError::Syntax(path.to_path_buf(), e.to_string()))?;
    let base_dir = path.parent().unwrap_or(Path::new("."));
    let interp = interpolate::interpolate(&mut value, base_dir)
        .map_err(|e| LoadError::Interpolate(path.to_path_buf(), e))?;
    if has_inline_secret(&value, &interp.substituted) {
        report.files_with_secrets.insert(path.to_path_buf());
    }
    report.interpolated.extend(interp.substituted);
    report.file_refs.extend(interp.file_refs);
    rebase_paths(&mut value, base_dir, &mut Vec::new());

    let includes: Vec<String> = match value.get("include") {
        None => Vec::new(),
        Some(toml::Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .ok_or_else(|| LoadError::IncludeType(path.to_path_buf()))
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(LoadError::IncludeType(path.to_path_buf())),
    };
    if let Some(table) = value.as_table_mut() {
        table.remove("include");
    }

    // Schema-check this document before it merges: a merged `toml::Value`
    // has lost provenance, so checking per-document names the offending
    // file. Deserializing the interpolated value gives the dotted field
    // path; re-parsing the raw text gives file:line — used only when the
    // failure is not an interpolation artifact (`${…}` inside a typed
    // field never parses raw).
    if let Err(e) = serde_path_to_error::deserialize::<toml::Value, Config>(value.clone()) {
        let msg = match toml::from_str::<Config>(&text) {
            Err(raw)
                if raw
                    .span()
                    .is_none_or(|s| !text.get(s.clone()).is_some_and(|t| t.contains('$'))) =>
            {
                raw.to_string()
            }
            _ => format!(
                "{}: {}",
                normalize_serde_path(&e.path().to_string()),
                e.inner()
            ),
        };
        return Err(LoadError::Schema(path.to_path_buf(), did_you_mean(&msg)));
    }

    // provenance of every leaf already in `value` — lets a merge
    // conflict name the file that set the key first
    let mut origins: std::collections::HashMap<String, PathBuf> = leaf_paths(&value)
        .into_iter()
        .map(|p| (p, path.to_path_buf()))
        .collect();

    for include in includes {
        let expansion = expand_include(base_dir, &include).map_err(|e| match e {
            LoadError::IncludeMissing(_, p) => LoadError::IncludeMissing(path.to_path_buf(), p),
            e => e,
        })?;
        report.watch_dirs.extend(expansion.dirs);
        for fragment in expansion.files {
            let fcanon = fragment.canonicalize().unwrap_or_else(|_| fragment.clone());
            if report.stack.contains(&fcanon) {
                return Err(LoadError::IncludeCycle(path.to_path_buf(), fragment));
            }
            if report.done.contains(&fcanon) {
                continue;
            }
            let (frag, frag_origins) = load_document(&fcanon, depth + 1, report)?;
            // array positions shift on merge — rebase fragment leaf
            // paths onto merged indices so `origins` names the right
            // file for merged-config diagnostics
            let base_arrays = array_lens(&value);
            let frag_arrays = array_lens(&frag);
            merge(&mut value, frag).map_err(|key| {
                let origin = origins
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| path.to_path_buf());
                LoadError::MergeConflict(fragment.clone(), key, origin.display().to_string())
            })?;
            for (leaf, file) in frag_origins {
                let segs: Vec<String> = leaf.split('.').map(String::from).collect();
                origins.insert(rebased_leaf(&segs, &base_arrays, &frag_arrays), file);
            }
        }
    }
    Ok((value, origins))
}

/// Dotted paths of every non-table leaf in a TOML document —
/// `log.level`, `site.0.hosts.0`, …
/// Append `did you mean \`x\`?` to a serde "unknown field/variant" error
/// when a close spelling exists among the expected names — catches typos
/// like `host`→`hosts`, `sttic`→`static`, or `dns_01`→`dns-01` in every
/// `deny_unknown_fields` table and enum uniformly.
fn did_you_mean(msg: &str) -> String {
    let re = regex::Regex::new(
        r"unknown (?:field|variant) `([^`]+)`.*expected (?:one of )?(`[^`]+`(?:(?:, | or )`[^`]+`)*)",
    )
    .expect("static regex");
    let Some(cap) = re.captures(msg) else {
        return msg.to_string();
    };
    let typo = cap[1].to_lowercase();
    let (mut best, mut dist) = ("", usize::MAX);
    for m in regex::Regex::new(r"`([^`]+)`")
        .expect("static regex")
        .captures_iter(&cap[2])
    {
        let d = levenshtein(&typo, &m[1].to_lowercase());
        if d < dist {
            (best, dist) = (m.get(1).unwrap().as_str(), d);
        }
    }
    if dist > 2 {
        return msg.to_string();
    }
    format!("{msg}; did you mean `{best}`?")
}

/// serde paths render as `site.0.route.2`; the human-facing label
/// style is `site[0].route[2]` — rewrite numeric `.N` segments so the
/// two syntaxes never mix.
pub(crate) fn normalize_serde_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len() + 8);
    for seg in p.split('.') {
        if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
            out.push('[');
            out.push_str(seg);
            out.push(']');
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(seg);
        }
    }
    out
}

/// Edit distance between two strings (unbounded — inputs are config
/// keys, tens of bytes at most).
pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.chars().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

fn leaf_paths(v: &toml::Value) -> Vec<String> {
    fn walk(v: &toml::Value, path: &mut Vec<String>, out: &mut Vec<String>) {
        match v {
            toml::Value::Table(m) => {
                for (k, val) in m {
                    path.push(k.clone());
                    walk(val, path, out);
                    path.pop();
                }
            }
            toml::Value::Array(items) => {
                for (i, val) in items.iter().enumerate() {
                    path.push(i.to_string());
                    walk(val, path, out);
                    path.pop();
                }
            }
            _ => out.push(path.join(".")),
        }
    }
    let mut out = Vec::new();
    walk(v, &mut Vec::new(), &mut out);
    out
}

/// A resolved `include` entry.
struct IncludeExpansion {
    /// Files to merge (sorted).
    files: Vec<PathBuf>,
    /// Directories to watch for new fragments (dir/glob includes).
    dirs: Vec<PathBuf>,
}

/// Expand an include entry to a sorted list of files: the file itself,
/// every `*.toml` directly inside the directory, or a glob pattern like
/// `conf.d/*.toml` or `extra-*.toml` (`*` matches any characters).
fn expand_include(base_dir: &Path, include: &str) -> Result<IncludeExpansion, LoadError> {
    let target = base_dir.join(include);
    if target.is_file() {
        return Ok(IncludeExpansion {
            files: vec![target],
            dirs: Vec::new(),
        });
    }
    if target.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&target)
            .map_err(|e| LoadError::Io(target.clone(), e.to_string()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file())
            .collect();
        files.sort();
        return Ok(IncludeExpansion {
            files,
            dirs: vec![target.canonicalize().unwrap_or(target)],
        });
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
        return Ok(IncludeExpansion {
            files,
            dirs: vec![dir.canonicalize().unwrap_or(dir)],
        });
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
        match load(&path) {
            Err(LoadError::MergeConflict(frag, key, origin)) => {
                assert_eq!(key, "log.level");
                assert!(frag.ends_with("frag.toml"));
                assert!(origin.ends_with("verd.toml"), "{origin}");
            }
            Err(e) => panic!("{e}"),
            Ok(_) => panic!("expected merge conflict"),
        }
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
prefix = "/"
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
        match load(&path) {
            Err(LoadError::IncludeCycle(includer, target)) => {
                assert!(includer.ends_with("b.toml"), "{includer:?}");
                assert!(target.ends_with("a.toml"), "{target:?}");
            }
            Err(e) => panic!("expected IncludeCycle, got {e}"),
            Ok(_) => panic!("expected IncludeCycle, load succeeded"),
        }
    }

    #[test]
    fn self_include_is_a_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "a.toml", r#"include = ["a.toml"]"#);
        assert!(matches!(load(&path), Err(LoadError::IncludeCycle(_, _))));
    }

    #[test]
    fn diamond_include_merges_once() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "shared.toml",
            "[[site]]\nhosts = [\"shared\"]\nroot = \"/tmp\"\n",
        );
        write(dir.path(), "a.toml", "include = [\"shared.toml\"]\n");
        write(dir.path(), "b.toml", "include = [\"shared.toml\"]\n");
        let path = write(dir.path(), "verd.toml", r#"include = ["a.toml", "b.toml"]"#);
        let loaded = load(&path).unwrap();
        // shared.toml's site arrives once, not twice
        assert_eq!(loaded.config.site.len(), 1);
        assert_eq!(loaded.sources.len(), 4);
    }

    #[test]
    fn schema_error_names_the_fragment() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "frag.toml", "bogus_key = 1\n");
        let path = write(dir.path(), "verd.toml", "include = [\"frag.toml\"]\n");
        match load(&path) {
            Err(LoadError::Schema(file, msg)) => {
                assert!(file.ends_with("frag.toml"), "{file:?}");
                assert!(msg.contains("bogus_key"), "{msg}");
            }
            Err(e) => panic!("expected Schema, got {e}"),
            Ok(_) => panic!("expected Schema, load succeeded"),
        }
    }

    #[test]
    fn schema_error_reports_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            "[server]\nworkers = 4\nbogus_key = 1\n",
        );
        match load(&path) {
            Err(LoadError::Schema(_, msg)) => {
                assert!(msg.contains("line"), "{msg}");
            }
            Err(e) => panic!("expected Schema, got {e}"),
            Ok(_) => panic!("expected Schema, load succeeded"),
        }
    }

    #[test]
    fn interpolated_typed_fields_do_not_confuse_schema_check() {
        // `${VAR}` in a typed field: the raw text never parses, but the
        // interpolated document does — no spurious schema error.
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("workers");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"4s\n")
            .unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            &format!(
                "[server]\ngraceful_timeout = \"${{file:{}:-45s}}\"\n",
                secret.display()
            ),
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.server.graceful_timeout.as_secs(), 4);
    }

    #[test]
    fn relative_file_ref_resolves_against_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "secret.txt", "hunter2\n");
        let path = write(
            dir.path(),
            "verd.toml",
            "[admin]\ntoken = \"${file:secret.txt}\"\n",
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.config.admin.token.as_deref(), Some("hunter2"));
        let want = dir.path().join("secret.txt").canonicalize().unwrap();
        assert_eq!(loaded.file_refs, vec![want]);
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
        assert!(config_file_perm_diag(&LoadReport::default()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn interpolated_secrets_skip_readable_warning() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("token");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"s3cr3t\n")
            .unwrap();
        // token resolved from ${file:} — the file holds no literal
        // credential, so group/other-readable is not flagged
        let path = write(
            dir.path(),
            "verd.toml",
            &format!("[admin]\ntoken = \"${{file:{}}}\"\n", secret.display()),
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load(&path).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("group/other-readable")),
            "{:?}",
            loaded.diagnostics
        );
    }

    #[cfg(unix)]
    #[test]
    fn fragment_inline_secret_warns_on_fragment() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // the readable file holding a literal secret is the *fragment*,
        // so the warning names frag.toml — not the 0600 main file
        let main = write(
            dir.path(),
            "verd.toml",
            "include = [\"frag.toml\"]\n[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
        );
        let frag = write(
            dir.path(),
            "frag.toml",
            "[[site]]\nhosts = [\"b.com\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = { status = 200, body = \"x\" }\n[site.route.auth]\n[site.route.auth.bearer]\ntokens = [\"s3cr3t\"]\n",
        );
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&frag, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load(&main).unwrap();
        let d = loaded
            .diagnostics
            .iter()
            .find(|d| d.message.contains("group/other-readable"))
            .unwrap_or_else(|| panic!("readable warning missing: {:?}", loaded.diagnostics));
        assert!(d.path.ends_with("frag.toml"), "{d}");
    }

    #[cfg(unix)]
    #[test]
    fn interpolated_fragment_secret_not_flagged_on_main() {
        use std::os::unix::fs::PermissionsExt;
        // regression: secret detection used to run on merged indices
        // while interpolation paths were document-local — a fragment's
        // interpolated token read as a literal secret on the main file
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("tok");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"t\n")
            .unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let main = write(
            dir.path(),
            "verd.toml",
            // main defines a site, so the fragment's site lands at index 1
            "include = [\"frag.toml\"]\n[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
        );
        write(
            dir.path(),
            "frag.toml",
            &format!(
                "[[site]]\nhosts = [\"b.com\"]\nroot = \"/tmp\"\n[[site.route]]\nrespond = {{ status = 200, body = \"x\" }}\n[site.route.auth]\n[site.route.auth.bearer]\ntokens = [\"${{file:{}}}\"]\n",
                secret.display()
            ),
        );
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = load(&main).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("readable")),
            "{:?}",
            loaded.diagnostics
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_writable_warned() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("tok");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"t\n")
            .unwrap();
        let main = write(
            dir.path(),
            "verd.toml",
            &format!(
                "[admin]\ntoken = \"${{file:{}}}\"\n[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
                secret.display()
            ),
        );
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o600)).unwrap();

        // writable file feeding a secret path is flagged
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o666)).unwrap();
        let loaded = load(&main).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .any(|d| d.message.contains("secret file")),
            "{:?}",
            loaded.diagnostics
        );

        // platform-mounted read-only secrets (0444) are not flagged
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o444)).unwrap();
        let loaded = load(&main).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("secret file")),
            "{:?}",
            loaded.diagnostics
        );

        // a ${file:} feeding a non-secret path is not a secret file
        let lvl = write(dir.path(), "lvl", "info\n");
        std::fs::set_permissions(&lvl, std::fs::Permissions::from_mode(0o666)).unwrap();
        let main2 = write(
            dir.path(),
            "v2.toml",
            &format!("[log]\nlevel = \"${{file:{}}}\"\n", lvl.display()),
        );
        std::fs::set_permissions(&main2, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = load(&main2).unwrap();
        assert!(
            loaded
                .diagnostics
                .iter()
                .all(|d| !d.message.contains("secret file")),
            "{:?}",
            loaded.diagnostics
        );
    }

    #[test]
    fn diagnostics_carry_source_file() {
        let dir = tempfile::tempdir().unwrap();
        let main = write(
            dir.path(),
            "verd.toml",
            "include = [\"frag.toml\"]\n[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
        );
        write(
            dir.path(),
            "frag.toml",
            "[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
        );
        let loaded = load(&main).unwrap();
        let d = loaded
            .diagnostics
            .iter()
            .find(|d| d.message.contains("duplicate host"))
            .expect("duplicate host diagnostic");
        let src = d.source.as_ref().expect("source file recorded");
        assert!(src.ends_with("frag.toml"), "{src:?} → {d}");
        assert!(d.to_string().contains("(in "), "{d}");
    }

    #[test]
    fn diagnostic_source_reaches_transitive_includes() {
        let dir = tempfile::tempdir().unwrap();
        let main = write(
            dir.path(),
            "verd.toml",
            "include = [\"mid.toml\"]\n[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
        );
        write(dir.path(), "mid.toml", "include = [\"leaf.toml\"]\n");
        write(
            dir.path(),
            "leaf.toml",
            "[[site]]\nhosts = [\"a.com\"]\nroot = \"/tmp\"\n",
        );
        let loaded = load(&main).unwrap();
        let d = loaded
            .diagnostics
            .iter()
            .find(|d| d.message.contains("duplicate host"))
            .expect("duplicate host diagnostic");
        let src = d.source.as_ref().expect("source file recorded");
        // attributed to the file that set the leaf, not the includer
        assert!(src.ends_with("leaf.toml"), "{src:?} → {d}");
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
    fn secret_at_segments_and_suffixes() {
        let no_path: &[String] = &[];
        for key in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "api_key",
            "x-api-key",
            "api_token",
            "bearer_tokens",
        ] {
            assert!(secret_at(no_path, key, false), "{key}");
        }
        // a list of cookie *names* is not a secret; segment matching
        // leaves `monkey`/`keyboard` alone
        for key in [
            "cookies",
            "headers",
            "x-trace-id",
            "monkey",
            "keyboard",
            "key_id",
        ] {
            assert!(!secret_at(no_path, key, false), "{key}");
        }
        // `[auth.api_key]` is a settings table — only `keys` inside it
        // is secret; a scalar named api_key stays secret
        assert!(!secret_at(no_path, "api_key", true));
        assert!(secret_at(no_path, "api_key", false));
        // every entry under `auth.basic.users` is a password hash
        let users = ["site", "0", "route", "0", "auth", "basic", "users"]
            .map(String::from)
            .to_vec();
        assert!(secret_at(&users, "alice", false));
        // `key` under `tls` is a file path — elsewhere it's secret
        let tls = ["site", "0", "tls"].map(String::from).to_vec();
        assert!(!secret_at(&tls, "key", false));
        assert!(secret_at(no_path, "key", false));
        let eab = ["acme", "eab"].map(String::from).to_vec();
        assert!(secret_at(&eab, "key", false));
        assert!(!secret_at(&eab, "key_id", false));
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
prefix = "/"
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
    fn hsts_max_age_accepts_duration_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            "[server.security]\nhsts_max_age = \"30d\"\n",
        );
        let loaded = load(&path).unwrap();
        assert_eq!(
            loaded.config.server.security.hsts_max_age.as_secs(),
            30 * 24 * 3600
        );
        // bare seconds were retired — strings only
        let path = write(
            dir.path(),
            "int.toml",
            "[server.security]\nhsts_max_age = 180\n",
        );
        assert!(load(&path).is_err());
    }

    #[test]
    fn include_must_be_a_list_of_strings() {
        let dir = tempfile::tempdir().unwrap();
        for doc in [
            "include = \"conf.d\"\n",
            "include = [1]\n",
            "include = {}\n",
        ] {
            let path = write(dir.path(), "verd.toml", doc);
            assert!(
                matches!(load(&path), Err(LoadError::IncludeType(_))),
                "{doc}"
            );
        }
    }

    #[test]
    fn include_dropped_from_dump() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "frag.toml", "[log]\nlevel = \"warn\"\n");
        let path = write(
            dir.path(),
            "verd.toml",
            "include = [\"frag.toml\"]\n[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n",
        );
        let loaded = load(&path).unwrap();
        let out = dump(&loaded.config).unwrap();
        assert!(!out.contains("include"), "{out}");
    }

    #[test]
    fn load_tracks_sources_and_file_refs() {
        let dir = tempfile::tempdir().unwrap();
        let frag_dir = dir.path().join("conf.d");
        std::fs::create_dir(&frag_dir).unwrap();
        let frag = write(
            &frag_dir,
            "site.toml",
            "[[site]]\nhosts = [\"x\"]\nroot = \"/tmp\"\n",
        );
        let secret = dir.path().join("token");
        std::fs::File::create(&secret)
            .unwrap()
            .write_all(b"s3cr3t\n")
            .unwrap();
        let path = write(
            dir.path(),
            "verd.toml",
            &format!(
                "include = [\"conf.d\"]\n[admin]\ntoken = \"${{file:{}}}\"\n",
                secret.display()
            ),
        );
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.sources.len(), 2);
        assert_eq!(loaded.sources[0], path.canonicalize().unwrap());
        assert!(loaded.sources.contains(&frag));
        assert_eq!(loaded.file_refs, vec![secret.clone()]);
        assert!(loaded.interpolated.contains("admin.token"));
        let plan = loaded.watch_plan();
        assert!(plan.dirs.contains(&frag_dir));
        assert!(plan.include_dirs.contains(&frag_dir));
        assert!(plan.files.contains(&frag));
        assert!(plan.files.contains(&secret));
    }

    #[test]
    fn watch_plan_filters_events() {
        let dir = tempfile::tempdir().unwrap();
        let inc = dir.path().join("conf.d");
        std::fs::create_dir(&inc).unwrap();
        let cfg = dir.path().join("verd.toml");
        let log = dir.path().join("server.log");
        let plan = WatchPlan {
            files: [cfg.clone()].into_iter().collect(),
            include_dirs: [inc.clone()].into_iter().collect(),
            dirs: [dir.path().to_path_buf(), inc.clone()]
                .into_iter()
                .collect(),
        };
        let ev = |kind, p: &std::path::Path| notify::Event::new(kind).add_path(p.to_path_buf());
        use notify::EventKind;
        use notify::event::{AccessKind, CreateKind, ModifyKind, RemoveKind};

        // a reload reads every source — access events must not retrigger
        assert!(!plan.hit(&ev(EventKind::Access(AccessKind::Read), &cfg)));
        // real mutations on a loaded file trigger
        assert!(plan.hit(&ev(EventKind::Modify(ModifyKind::Any), &cfg)));
        assert!(plan.hit(&ev(EventKind::Create(CreateKind::File), &cfg)));
        assert!(plan.hit(&ev(EventKind::Remove(RemoveKind::File), &cfg)));
        // unrelated files in a watched dir (server logs, caches) are noise
        assert!(!plan.hit(&ev(EventKind::Modify(ModifyKind::Any), &log)));
        assert!(!plan.hit(&ev(EventKind::Create(CreateKind::Any), &log)));
        // a new *.toml inside an include dir triggers; elsewhere doesn't
        assert!(plan.hit(&ev(
            EventKind::Create(CreateKind::File),
            &inc.join("new.toml")
        )));
        assert!(!plan.hit(&ev(
            EventKind::Create(CreateKind::File),
            &dir.path().join("stray.toml")
        )));
        // k8s ConfigMap/Secret atomic swap
        assert!(plan.hit(&ev(
            EventKind::Create(CreateKind::Any),
            &dir.path().join("..data")
        )));
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
    fn retired_config_spellings_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for (name, doc) in [
            (
                "upstream limits",
                r#"[upstream.app]
servers = ["http://10.0.0.1:1"]
[upstream.app.limits]
connect = "1s"
"#,
            ),
            (
                "route headers",
                r#"[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { body = "ok" }
headers = { set = { x-a = "1" } }
"#,
            ),
            (
                "proxy headers",
                r#"[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
proxy = { upstream = "http://10.0.0.1:1", headers = { set = { x-a = "1" } } }
"#,
            ),
            (
                "route path",
                r#"[[site]]
hosts = ["x"]
[[site.route]]
path = "/"
respond = { body = "ok" }
"#,
            ),
            (
                "route conditions",
                r#"[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { body = "ok" }
conditions = { methods = ["GET"] }
"#,
            ),
            (
                "proxy pass_host",
                r#"[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
proxy = { upstream = "http://10.0.0.1:1", pass_host = false }
"#,
            ),
            (
                "upstream timeouts.max_connections",
                r#"[upstream.app]
servers = ["http://10.0.0.1:1"]
timeouts = { max_connections = 8 }
"#,
            ),
            (
                "tls selfsigned",
                r#"[[site]]
hosts = ["x"]
tls = "selfsigned"
respond = { body = "ok" }
"#,
            ),
            (
                "squashed lb spelling",
                r#"[upstream.app]
servers = ["http://10.0.0.1:1"]
lb = "leastconn"
"#,
            ),
            (
                "squashed challenge spelling",
                r#"[acme]
challenge = "dns01"
"#,
            ),
        ] {
            let path = write(dir.path(), "verd.toml", doc);
            assert!(load(&path).is_err(), "{name} should be rejected");
        }
    }

    #[test]
    fn replace_prefix_named_form() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = |rewrite: &str| {
            write(
                dir.path(),
                "verd.toml",
                &format!(
                    "[[site]]\nhosts = [\"x\"]\n[[site.route]]\nprefix = \"/\"\nproxy = {{ upstream = \"http://127.0.0.1:1\", rewrite = {{ {rewrite} }} }}\n"
                ),
            )
        };
        let loaded = load(&cfg(r#"replace_prefix = { from = "/a", to = "/b" }"#)).unwrap();
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
        assert_eq!(pp.pair(), ("/a", "/b"));
        assert!(load(&cfg(r#"replace_prefix = ["/a", "/b"]"#)).is_err());
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

    /// Behavioral mirror of `docs/config-grammar.md` — each accepted
    /// config shape and its parity/strictness policy has a row. When the
    /// grammar doc gains an invariant, this test gains a case; the
    /// ergonomics audit is the diff between the two.
    mod surface_audit {
        use super::*;

        fn load_str(body: &str) -> Result<Loaded, LoadError> {
            let dir = tempfile::tempdir().unwrap();
            let path = write(dir.path(), "verd.toml", body);
            let r = load(&path);
            drop(dir); // dir must outlive `load` — it does
            r
        }

        #[test]
        fn route_proxy_accepts_site_proxy_shapes() {
            for shorthand in [
                r#"proxy = "http://127.0.0.1:9""#,
                r#"proxy = "cluster""#,
                r#"proxy = ["http://127.0.0.1:9", "http://127.0.0.1:10"]"#,
                r#"proxy = { upstream = "http://127.0.0.1:9" }"#,
            ] {
                let l = load_str(&format!(
                    "[[site]]\n[[site.route]]\nprefix = \"/\"\n{shorthand}\n"
                ))
                .unwrap_or_else(|e| panic!("{shorthand} should parse: {e}"));
                assert!(
                    l.config.site[0].route[0].proxy.is_some(),
                    "{shorthand} produced no proxy"
                );
            }
        }

        #[test]
        fn scalar_sugar_on_approved_lists() {
            // every field in the grammar's scalar-vs-list section parses
            // the bare-value form as a one-element list
            for (field, body) in [
                (
                    "site.hosts",
                    "[[site]]\nhosts = \"a.example.com\"\nroot = \"/tmp\"",
                ),
                (
                    "route.ip_allow",
                    "[[site]]\nroot = \"/tmp\"\n[[site.route]]\nip_allow = \"10.0.0.0/8\"",
                ),
                (
                    "match.methods",
                    "[[site]]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.match]\nmethods = \"GET\"",
                ),
                (
                    "upstream.servers",
                    "[upstream.u]\nservers = \"127.0.0.1:1\"",
                ),
                (
                    "bearer.tokens",
                    "[[site]]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.auth]\n[site.route.auth.bearer]\ntokens = \"t\"",
                ),
                ("server.listen", "[server]\nlisten = \"127.0.0.1:18080\""),
                (
                    "cache.bypass.cookies",
                    "[cache.c]\n[[site]]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.cache]\nstore = \"c\"\n[site.route.cache.bypass]\ncookies = \"sess\"",
                ),
                (
                    "cache.bypass.paths",
                    "[cache.c]\n[[site]]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.cache]\nstore = \"c\"\n[site.route.cache.bypass]\npaths = \"/admin/*\"",
                ),
                (
                    "static.index",
                    "[[site]]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.static]\nroot = \"/tmp\"\nindex = \"idx.html\"",
                ),
                (
                    "static.try_files",
                    "[[site]]\nroot = \"/tmp\"\n[[site.route]]\n[site.route.static]\nroot = \"/tmp\"\ntry_files = \"f.html\"",
                ),
                (
                    "response_headers.remove",
                    "[[site]]\nroot = \"/tmp\"\n[[site.route]]\nrespond = { status = 200, body = \"x\" }\n[site.route.response_headers]\nremove = \"x-powered-by\"",
                ),
                (
                    "proxy.request_headers.remove",
                    "[[site]]\n[[site.route]]\n[site.route.proxy]\nupstream = \"http://x:1\"\n[site.route.proxy.request_headers]\nremove = \"x-a\"",
                ),
            ] {
                load_str(body).unwrap_or_else(|e| panic!("{field} should take a scalar: {e}"));
            }
        }

        #[test]
        fn off_switches_and_scalar_table_shorthands() {
            // retries = false → no retries; retries = true → defaults
            let l = load_str(
                "[[site]]\n[[site.route]]\n[site.route.proxy]\nupstream = \"http://x:1\"\nretries = false",
            )
            .unwrap();
            assert_eq!(
                l.config.site[0].route[0]
                    .proxy
                    .as_ref()
                    .unwrap()
                    .retries
                    .max_per_request,
                0
            );
            let l = load_str(
                "[[site]]\n[[site.route]]\n[site.route.proxy]\nupstream = \"http://x:1\"\nretries = true",
            )
            .unwrap();
            assert_eq!(
                l.config.site[0].route[0]
                    .proxy
                    .as_ref()
                    .unwrap()
                    .retries
                    .max_per_request,
                2
            );

            // log.access = false disables access logging
            let l = load_str("[log]\naccess = false").unwrap();
            assert!(!l.config.log.access.enabled);

            // upstream.dns = "dur" → { grace }; health.active = "path" → { path }
            let l = load_str("[upstream.u]\nservers = \"x:1\"\ndns = \"90s\"").unwrap();
            assert_eq!(
                l.config.upstream["u"].dns.grace,
                std::time::Duration::from_secs(90)
            );
            let l =
                load_str("[upstream.u]\nservers = \"x:1\"\n[upstream.u.health]\nactive = \"/up\"")
                    .unwrap();
            assert_eq!(
                l.config.upstream["u"].health.active.as_ref().unwrap().path,
                "/up"
            );

            // acme.challenge snake spellings are aliases of the kebab canon
            let l = load_str("[acme]\nchallenge = \"dns_01\"").unwrap();
            assert_eq!(l.config.acme.challenge, model::AcmeChallenge::Dns01);
            let l = load_str("[acme]\nchallenge = \"tls_alpn_01\"").unwrap();
            assert_eq!(l.config.acme.challenge, model::AcmeChallenge::TlsAlpn01);

            // upstream.servers entries: bare URL or { url, weight, backup }
            let l = load_str(
                "[upstream.u]\nservers = [\"http://a:1\", { url = \"http://b:2\", weight = 3 }, { url = \"http://c:3\", backup = true }]",
            )
            .unwrap();
            let srv = &l.config.upstream["u"].servers;
            assert_eq!(srv[0].url, "http://a:1");
            assert_eq!((srv[0].weight, srv[0].backup), (1, false));
            assert_eq!((srv[1].weight, srv[1].backup), (3, false));
            assert!((srv[2].backup && srv[2].weight == 1));

            // host_header: keywords still work; anything else is verbatim
            for (v, want) in [
                ("upstream", model::HostHeader::Upstream),
                ("original", model::HostHeader::Original),
                (
                    "api.internal",
                    model::HostHeader::Custom("api.internal".into()),
                ),
            ] {
                let l = load_str(&format!(
                    "[[site]]\n[[site.route]]\n[site.route.proxy]\nupstream = \"http://x:1\"\nhost_header = \"{v}\""
                ))
                .unwrap();
                assert_eq!(
                    l.config.site[0].route[0]
                        .proxy
                        .as_ref()
                        .unwrap()
                        .host_header,
                    want,
                    "{v}"
                );
            }
        }

        #[test]
        fn handler_scalar_shorthands() {
            // each handler's dominant field has a scalar form; the full
            // table form still parses
            let l = load_str("[[site]]\n[[site.route]]\nprefix = \"/\"\nstatic = \"/srv/www\"\n")
                .unwrap();
            assert_eq!(
                l.config.site[0].route[0]
                    .static_files
                    .as_ref()
                    .unwrap()
                    .root,
                std::path::PathBuf::from("/srv/www")
            );

            let l = load_str(
                "[[site]]\n[[site.route]]\nprefix = \"/\"\nredirect = \"https://new.example{path}\"\n",
            )
            .unwrap();
            assert_eq!(
                l.config.site[0].route[0]
                    .redirect
                    .as_ref()
                    .unwrap()
                    .to
                    .as_deref(),
                Some("https://new.example{path}")
            );

            let l =
                load_str("[[site]]\n[[site.route]]\nprefix = \"/\"\nrespond = \"pong\"\n").unwrap();
            let r = l.config.site[0].route[0].respond.as_ref().unwrap();
            assert_eq!((r.status, r.body.as_str()), (200, "pong"));

            let l = load_str("[[site]]\n[[site.route]]\nprefix = \"/\"\nrate_limit = \"100/s\"\n")
                .unwrap();
            let r = l.config.site[0].route[0].rate_limit.as_ref().unwrap();
            assert_eq!(r.key, "ip");

            // bad rate strings are schema errors, not silent passes
            match load_str("[[site]]\n[[site.route]]\nprefix = \"/\"\nrate_limit = \"fast\"") {
                Err(LoadError::Schema(_, _)) => {}
                Err(e) => panic!("expected Schema, got {e}"),
                Ok(_) => panic!("rate_limit = \"fast\" should fail"),
            }
        }

        #[test]
        fn site_level_middleware_defaults() {
            // every site-level middleware block accepts the same forms
            // as its route-level counterpart
            let l = load_str(
                r#"
[cache.c]
[[site]]
hosts = ["x"]
auth = { bearer = { tokens = ["t"] } }
cors = { origins = ["https://a.example"] }
rate_limit = "50/s"
cache = "c"
compress = true
response_headers = { set = { x-a = "1" } }
ip_allow = "10.0.0.0/8"
ip_deny = "10.0.0.9/32"
[site.timeouts]
idle = "5s"
[site.limits]
body_bytes = "1mb"
[site.security]
hsts = true
[[site.route]]
prefix = "/"
respond = { status = 200 }
"#,
            )
            .unwrap();
            let s = &l.config.site[0];
            assert!(s.auth.is_some() && s.cors.is_some());
            assert_eq!(s.rate_limit.as_ref().unwrap().key, "ip");
            assert!(s.cache.is_some() && s.compress.is_some());
            assert!(s.response_headers.is_some());
            assert_eq!(s.ip_allow.len(), 1);
            assert_eq!(s.ip_deny.len(), 1);
            assert!(s.timeouts.is_some() && s.limits.is_some() && s.security.is_some());

            // a route-level `enabled = false` marker parses for every
            // inheritable block
            let l = load_str(
                r#"
[[site]]
hosts = ["x"]
[[site.route]]
prefix = "/"
respond = { status = 200 }
auth = { enabled = false }
cors = { enabled = false }
rate_limit = { enabled = false }
cache = false
compress = false
response_headers = { enabled = false }
"#,
            )
            .unwrap();
            let r = &l.config.site[0].route[0];
            for (name, disabled) in [
                ("auth", !r.auth.as_ref().unwrap().enabled),
                ("cors", !r.cors.as_ref().unwrap().enabled),
                ("rate_limit", !r.rate_limit.as_ref().unwrap().enabled),
                ("cache", !r.cache.as_ref().unwrap().enabled),
                ("compress", !r.compress.as_ref().unwrap().enabled),
                (
                    "response_headers",
                    !r.response_headers.as_ref().unwrap().enabled,
                ),
            ] {
                assert!(disabled, "{name} opt-out did not parse");
            }
        }

        #[test]
        fn relative_paths_anchor_to_their_document() {
            // a fragment's relative paths resolve against the fragment's
            // directory — the same anchor `include` uses — not the CWD
            let dir = tempfile::tempdir().unwrap();
            let sub = dir.path().join("frag.d");
            std::fs::create_dir(&sub).unwrap();
            let main = write(
                dir.path(),
                "verd.toml",
                "include = [\"frag.d/one.toml\"]\n[[site]]\nhosts = [\"a\"]\nroot = \"./pub\"\n",
            );
            write(
                &sub,
                "one.toml",
                "[[site]]\nhosts = [\"b\"]\nroot = \"./pub\"\n",
            );
            let loaded = load(&main).unwrap();
            assert_eq!(
                loaded.config.site[0].root.as_deref(),
                Some(dir.path().join("pub").as_path())
            );
            assert_eq!(
                loaded.config.site[1].root.as_deref(),
                Some(sub.join("pub").as_path())
            );

            // absolute paths and output sentinels pass through untouched
            let main2 = write(
                dir.path(),
                "v2.toml",
                "[log]\noutput = \"stdout\"\n[log.access]\noutput = \"stderr\"\n[[site]]\nhosts = [\"c\"]\nroot = \"/srv/www\"\n",
            );
            let loaded = load(&main2).unwrap();
            assert_eq!(loaded.config.log.output, "stdout");
            assert_eq!(loaded.config.log.access.output, "stderr");
            assert_eq!(
                loaded.config.site[0].root.as_deref(),
                Some(Path::new("/srv/www"))
            );
        }

        #[test]
        fn include_stays_strict() {
            // documented exception — merge order is load-bearing, and
            // the error is the teaching moment
            match load_str("include = \"conf.d\"") {
                Err(e) => {
                    assert!(e.to_string().contains("list of path strings"), "{e}");
                }
                Ok(_) => panic!("include scalar should fail"),
            }
        }

        #[test]
        fn admin_disabled_parses_and_warns_on_dead_config() {
            let l = load_str("[admin]\nenabled = false\n[[site]]\nhosts = \"x\"\nroot = \"/tmp\"")
                .unwrap();
            assert!(!l.config.admin.enabled);
            assert!(l.diagnostics.iter().all(|d| !d.path.starts_with("admin.")));

            // token/tls set under enabled=false → dead-config warnings
            let l = load_str("[admin]\nenabled = false\ntoken = \"t\"\n").unwrap();
            assert!(
                l.diagnostics
                    .iter()
                    .any(|d| d.message.contains("admin.enabled = false")),
                "{:?}",
                l.diagnostics
            );
        }

        #[test]
        fn unknown_fields_suggest_close_spellings() {
            for (body, want) in [
                ("[[site]]\nhost = \"a\"\nroot = \"/tmp\"", "hosts"),
                ("[server]\nlistn = \"127.0.0.1:80\"", "listen"),
                ("[[site]]\n[[site.route]]\nsttic = {}", "static"),
            ] {
                match load_str(body) {
                    Err(LoadError::Schema(_, msg)) => {
                        assert!(
                            msg.contains(&format!("did you mean `{want}`?")),
                            "{body} → {msg}"
                        );
                    }
                    Err(e) => panic!("{body} should be a schema error, got {e}"),
                    Ok(_) => panic!("{body} should be a schema error"),
                }
            }
            // distant names get no suggestion
            match load_str("[server]\nzzz = 1") {
                Err(LoadError::Schema(_, msg)) => {
                    assert!(!msg.contains("did you mean"), "{msg}");
                }
                Err(e) => panic!("expected Schema, got {e}"),
                Ok(_) => panic!("expected Schema, load succeeded"),
            }
        }

        #[test]
        fn new_grammar_forms() {
            // `security = false` → { enabled = false } at site and route
            let l = load_str(
                "[[site]]\nhosts = [\"x\"]\nsecurity = false\n[[site.route]]\nrespond = { status = 200 }\nsecurity = false",
            )
            .unwrap();
            assert_eq!(
                l.config.site[0].security.as_ref().unwrap().enabled,
                Some(false)
            );
            assert_eq!(
                l.config.site[0].route[0].security.as_ref().unwrap().enabled,
                Some(false)
            );

            // bare IPs parse as host routes on every network field
            let l = load_str(
                "[[site]]\nroot = \"/tmp\"\nip_allow = \"10.0.0.1\"\ntrusted_proxies = \"127.0.0.1\"\n[[site.route]]\nip_deny = \"::1\"\nrate_limit = { rate = \"10/s\", exempt = \"10.0.0.2\" }",
            )
            .unwrap();
            assert_eq!(l.config.site[0].ip_allow[0], "10.0.0.1/32".parse().unwrap());
            assert_eq!(
                l.config.site[0].trusted_proxies.as_ref().unwrap()[0],
                "127.0.0.1/32".parse().unwrap()
            );
            assert_eq!(
                l.config.site[0].route[0].ip_deny[0],
                "::1/128".parse().unwrap()
            );
            assert_eq!(
                l.config.site[0].route[0]
                    .rate_limit
                    .as_ref()
                    .unwrap()
                    .exempt[0],
                "10.0.0.2/32".parse().unwrap()
            );
            match load_str("[[site]]\nroot = \"/tmp\"\nip_allow = \"10.0.0.300\"") {
                Err(LoadError::Schema(_, _)) => {}
                Err(e) => panic!("expected Schema, got {e}"),
                Ok(_) => panic!("ip_allow = \"10.0.0.300\" should fail"),
            }

            // `listen = ":8080"` → wildcard; a bare `"8080"` stays an error
            let l = load_str("[server]\nlisten = \":8080\"").unwrap();
            assert_eq!(l.config.server.listen[0].addr.to_string(), "0.0.0.0:8080");
            let l = load_str("[server]\nlisten = [{ addr = \":8080\", tls = true }]").unwrap();
            assert_eq!(l.config.server.listen[0].addr.to_string(), "0.0.0.0:8080");
            match load_str("[server]\nlisten = \"8080\"") {
                Err(LoadError::Schema(_, _)) => {}
                Err(e) => panic!("expected Schema, got {e}"),
                Ok(_) => panic!("listen = \"8080\" should fail"),
            }

            // acme.directory aliases resolve to their URL at load
            let l = load_str("[acme]\ndirectory = \"letsencrypt-staging\"").unwrap();
            assert_eq!(
                l.config.acme.directory,
                "https://acme-staging-v02.api.letsencrypt.org/directory"
            );
            let l = load_str("[acme]\ndirectory = \"letsencrypt\"").unwrap();
            assert_eq!(
                l.config.acme.directory,
                "https://acme-v02.api.letsencrypt.org/directory"
            );

            // site.proxy accepts the full table form, not just a ref
            let l = load_str(
                "[[site]]\nhosts = [\"x\"]\nproxy = { upstream = \"http://127.0.0.1:9\", host_header = \"original\" }",
            )
            .unwrap();
            let p = l.config.site[0].proxy.as_ref().unwrap();
            assert_eq!(p.host_header, model::HostHeader::Original);

            // `passive = 5` → { failures = 5, default cooldown }
            let l = load_str("[upstream.u]\nservers = \"x:1\"\nhealth = { passive = 5 }").unwrap();
            assert_eq!(
                l.config.upstream["u"]
                    .health
                    .passive
                    .as_ref()
                    .unwrap()
                    .failures,
                5
            );

            // rates accept arbitrary periods — "10/30s" is ten per 30s
            let l = load_str("[[site]]\nroot = \"/tmp\"\n[[site.route]]\nrate_limit = \"10/30s\"")
                .unwrap();
            assert_eq!(
                l.config.site[0].route[0]
                    .rate_limit
                    .as_ref()
                    .unwrap()
                    .rate
                    .unwrap()
                    .period,
                std::time::Duration::from_secs(30)
            );
        }

        #[test]
        fn unknown_enum_variants_suggest_close_spellings() {
            for (body, want) in [
                // `dns_01` parses — it is an accepted alias now
                ("[acme]\nchallenge = \"dns-0\"", "dns-01"),
                ("[acme]\nchallenge = \"htt-01\"", "http-01"),
                (
                    "[upstream.u]\nservers = \"127.0.0.1:1\"\nlb = \"least_conn_\"",
                    "least_conn",
                ),
            ] {
                match load_str(body) {
                    Err(LoadError::Schema(_, msg)) => {
                        assert!(
                            msg.contains(&format!("did you mean `{want}`?")),
                            "{body} → {msg}"
                        );
                    }
                    Err(e) => panic!("{body} should be a schema error, got {e}"),
                    Ok(_) => panic!("{body} should be a schema error"),
                }
            }
        }
    }
}
