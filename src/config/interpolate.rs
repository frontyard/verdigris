//! Secret interpolation in configuration strings: `${VAR}` reads an
//! environment variable, `${VAR:-default}` falls back when unset or empty,
//! and `${file:/path}` reads a file (trailing newlines trimmed; a
//! `:-default` fallback applies when the file is unreadable) — suited to
//! Docker and Kubernetes mounted secrets. Relative `${file:}` paths
//! resolve against the directory of the document containing them, like
//! `include`. `$${` renders a literal `${`.
//! Interpolation applies to string values anywhere in the config,
//! including inside arrays and tables.

use std::collections::HashSet;
use std::path::PathBuf;

use thiserror::Error;

/// An interpolation failure. `at` is the dotted config path of the value
/// that contained the reference, e.g. `admin.token` or
/// `site.0.route.1.auth.bearer.tokens.0`.
#[derive(Debug, Error)]
pub enum InterpolateError {
    /// An environment variable was not set and no default was given.
    #[error("{at}: environment variable {name:?} is not set")]
    MissingEnv {
        /// Where the reference appears.
        at: String,
        /// The variable name.
        name: String,
    },
    /// A referenced file could not be read.
    #[error("{at}: cannot read secret file {path:?}: {cause}")]
    UnreadableFile {
        /// Where the reference appears.
        at: String,
        /// The referenced path.
        path: PathBuf,
        /// The OS error.
        cause: String,
    },
    /// The interpolation syntax was malformed.
    #[error("{at}: malformed interpolation {expr:?}")]
    Malformed {
        /// Where the reference appears.
        at: String,
        /// The offending value.
        expr: String,
    },
}

/// What the interpolation pass observed about a document.
#[derive(Debug, Default)]
pub struct Report {
    /// Dotted key paths of values that contained a `${…}` marker —
    /// interpolated secrets are not literals for permission diagnostics.
    pub substituted: HashSet<String>,
    /// Files referenced by `${file:…}` markers (for `--watch`).
    pub file_refs: Vec<PathBuf>,
}

/// Apply interpolation to every string value in a parsed TOML document.
/// `base_dir` resolves relative `${file:…}` paths — the directory of the
/// document being interpolated, matching how `include` paths resolve.
pub fn interpolate(
    value: &mut toml::Value,
    base_dir: &std::path::Path,
) -> Result<Report, InterpolateError> {
    interpolate_with(value, |name| std::env::var(name).ok(), base_dir)
}

/// Like [`interpolate`] but with an injectable environment lookup — kept
/// separate so tests need no process-env mutation (forbidden `unsafe`).
pub fn interpolate_with(
    value: &mut toml::Value,
    env: impl Fn(&str) -> Option<String>,
    base_dir: &std::path::Path,
) -> Result<Report, InterpolateError> {
    let mut report = Report::default();
    let mut path = Vec::new();
    walk(value, &mut path, &mut |s, at| {
        substitute(s, &env, at, base_dir, &mut report)
    })?;
    Ok(report)
}

fn walk(
    value: &mut toml::Value,
    path: &mut Vec<String>,
    f: &mut dyn FnMut(&str, &str) -> Result<String, InterpolateError>,
) -> Result<(), InterpolateError> {
    match value {
        toml::Value::String(s) => {
            *s = f(s, &path.join("."))?;
            Ok(())
        }
        toml::Value::Array(items) => {
            for (i, v) in items.iter_mut().enumerate() {
                path.push(i.to_string());
                walk(v, path, f)?;
                path.pop();
            }
            Ok(())
        }
        toml::Value::Table(map) => {
            for (k, v) in map.iter_mut() {
                path.push(k.clone());
                walk(v, path, f)?;
                path.pop();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn substitute(
    input: &str,
    env: &dyn Fn(&str) -> Option<String>,
    at: &str,
    base_dir: &std::path::Path,
    report: &mut Report,
) -> Result<String, InterpolateError> {
    if !input.contains('$') {
        return Ok(input.to_string());
    }
    let malformed = || InterpolateError::Malformed {
        at: at.to_string(),
        expr: input.to_string(),
    };
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        if let Some(tail) = after.strip_prefix('$') {
            // `$$` renders a literal `$`
            out.push('$');
            rest = tail;
        } else if let Some(tail) = after.strip_prefix('{') {
            let end = tail.find('}').ok_or_else(malformed)?;
            report.substituted.insert(at.to_string());
            out.push_str(&resolve(&tail[..end], input, env, at, base_dir, report)?);
            rest = &tail[end + 1..];
        } else {
            // lone `$` — not a marker
            out.push('$');
            rest = after;
        }
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve(
    expr: &str,
    whole: &str,
    env: &dyn Fn(&str) -> Option<String>,
    at: &str,
    base_dir: &std::path::Path,
    report: &mut Report,
) -> Result<String, InterpolateError> {
    if let Some(expr) = expr.strip_prefix("file:") {
        let (path, default) = match expr.split_once(":-") {
            Some((p, d)) => (p.trim(), Some(d)),
            None => (expr.trim(), None),
        };
        // Relative paths anchor to the document's directory — same rule
        // as `include`, so a config tree stays location-independent.
        let path = PathBuf::from(path);
        let path = if path.is_relative() {
            base_dir.join(path)
        } else {
            path
        };
        let path = path.canonicalize().unwrap_or(path);
        report.file_refs.push(path.clone());
        return match std::fs::read_to_string(&path) {
            Ok(content) => Ok(content.trim_end_matches(['\n', '\r']).to_string()),
            Err(e) => match default {
                Some(d) => Ok(d.to_string()),
                None => Err(InterpolateError::UnreadableFile {
                    at: at.to_string(),
                    path: path.clone(),
                    cause: e.to_string(),
                }),
            },
        };
    }
    // `${VAR}` or `${VAR:-default}`; the variable name must be non-empty.
    let (name, default) = match expr.split_once(":-") {
        Some((name, default)) => (name.trim(), Some(default)),
        None => (expr.trim(), None),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(InterpolateError::Malformed {
            at: at.to_string(),
            expr: whole.to_string(),
        });
    }
    match env(name) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => match default {
            Some(d) => Ok(d.to_string()),
            None => Err(InterpolateError::MissingEnv {
                at: at.to_string(),
                name: name.to_string(),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_env(name: &str) -> Option<String> {
        match name {
            "VERD_TEST_VAR" => Some("sekret".into()),
            _ => None,
        }
    }

    fn interp(v: &mut toml::Value) -> Result<Report, InterpolateError> {
        interpolate_with(v, test_env, std::path::Path::new("."))
    }

    fn val(s: &str) -> toml::Value {
        toml::Value::String(s.to_string())
    }

    #[test]
    fn env_var_substituted() {
        let mut v = val("token=${VERD_TEST_VAR}");
        let r = interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "token=sekret");
        assert!(r.substituted.contains(""));
    }

    #[test]
    fn default_used_when_unset() {
        let mut v = val("${VERD_DEFINITELY_UNSET:-fallback}");
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "fallback");
    }

    #[test]
    fn missing_env_names_var_and_path() {
        let mut v: toml::Value =
            toml::from_str("[admin]\ntoken = \"${VERD_DEFINITELY_UNSET}\"").unwrap();
        match interp(&mut v) {
            Err(InterpolateError::MissingEnv { at, name }) => {
                assert_eq!(at, "admin.token");
                assert_eq!(name, "VERD_DEFINITELY_UNSET");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn file_substituted_and_trimmed() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hunter2\n").unwrap();
        let mut v = val(&format!("${{file:{}}}", f.path().display()));
        let r = interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "hunter2");
        assert_eq!(r.file_refs.len(), 1);
    }

    #[test]
    fn nested_values_reached() {
        let mut v: toml::Value = toml::from_str(
            "a = \"${VERD_TEST_VAR}\"\nb = [\"${VERD_TEST_VAR}\"]\n[t]\nc = \"x ${VERD_TEST_VAR} y\"",
        )
        .unwrap();
        let r = interp(&mut v).unwrap();
        assert_eq!(v["t"]["c"].as_str().unwrap(), "x sekret y");
        assert_eq!(v["b"][0].as_str().unwrap(), "sekret");
        assert!(r.substituted.contains("t.c"));
        assert!(r.substituted.contains("b.0"));
    }

    #[test]
    fn malformed_rejected() {
        for bad in ["${", "${-bad-name}", "${}"] {
            let mut v = val(bad);
            assert!(interp(&mut v).is_err(), "{bad}");
        }
    }

    #[test]
    fn strings_without_markers_untouched() {
        let mut v = val("$HOME literally, no braces");
        let r = interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "$HOME literally, no braces");
        assert!(r.substituted.is_empty());
    }

    #[test]
    fn double_dollar_escapes_marker() {
        let mut v = val("costs $${price} and $${VERD_TEST_VAR}");
        let r = interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "costs ${price} and ${VERD_TEST_VAR}");
        assert!(r.substituted.is_empty());
    }

    #[test]
    fn triple_dollar_is_literal_then_expansion() {
        // `$$${VAR}` = literal `${` followed by... no — `$$` escapes only
        // before `${`; `$` then `${VAR}` expands.
        let mut v = val("$$${VERD_TEST_VAR}");
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "$sekret");
    }

    #[test]
    fn file_default_used_when_unreadable() {
        let mut v = val("${file:/definitely/missing/secret:-fallback}");
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "fallback");
    }

    #[test]
    fn file_default_ignored_when_readable() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"real\n").unwrap();
        let mut v = val(&format!("${{file:{}:-fallback}}", f.path().display()));
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "real");
    }

    #[test]
    fn file_without_default_still_errors() {
        let mut v = val("${file:/definitely/missing/secret}");
        assert!(matches!(
            interp(&mut v),
            Err(InterpolateError::UnreadableFile { .. })
        ));
    }
}
