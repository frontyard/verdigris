//! Secret interpolation in configuration strings: `${VAR}` reads an
//! environment variable, `${VAR:-default}` falls back when unset or empty,
//! and `${file:/path}` reads a file (trailing newlines trimmed; a
//! `:-default` fallback applies when the file is unreadable) — suited to
//! Docker and Kubernetes mounted secrets. `$${` renders a literal `${`.
//! Interpolation applies to string values anywhere in the config,
//! including inside arrays and tables.

use std::path::PathBuf;

use thiserror::Error;

/// An interpolation failure.
#[derive(Debug, Error)]
pub enum InterpolateError {
    /// An environment variable was not set and no default was given.
    #[error("environment variable {0:?} is not set")]
    MissingEnv(String),
    /// A referenced file could not be read.
    #[error("cannot read secret file {0:?}: {1}")]
    UnreadableFile(PathBuf, String),
    /// The interpolation syntax was malformed.
    #[error("malformed interpolation {0:?}")]
    Malformed(String),
}

/// Apply interpolation to every string value in a parsed TOML document.
pub fn interpolate(value: &mut toml::Value) -> Result<(), InterpolateError> {
    interpolate_with(value, |name| std::env::var(name).ok())
}

/// Like [`interpolate`] but with an injectable environment lookup — kept
/// separate so tests need no process-env mutation (forbidden `unsafe`).
pub fn interpolate_with(
    value: &mut toml::Value,
    env: impl Fn(&str) -> Option<String>,
) -> Result<(), InterpolateError> {
    walk(value, &mut |s| substitute(s, &env))
}

fn walk(
    value: &mut toml::Value,
    f: &mut dyn FnMut(&str) -> Result<String, InterpolateError>,
) -> Result<(), InterpolateError> {
    match value {
        toml::Value::String(s) => {
            *s = f(s)?;
            Ok(())
        }
        toml::Value::Array(items) => items.iter_mut().try_for_each(|v| walk(v, f)),
        toml::Value::Table(map) => map.iter_mut().try_for_each(|(_, v)| walk(v, f)),
        _ => Ok(()),
    }
}

fn substitute(
    input: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, InterpolateError> {
    if !input.contains('$') {
        return Ok(input.to_string());
    }
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
            let end = tail
                .find('}')
                .ok_or_else(|| InterpolateError::Malformed(input.to_string()))?;
            out.push_str(&resolve(&tail[..end], input, env)?);
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
) -> Result<String, InterpolateError> {
    if let Some(expr) = expr.strip_prefix("file:") {
        let (path, default) = match expr.split_once(":-") {
            Some((p, d)) => (p.trim(), Some(d)),
            None => (expr.trim(), None),
        };
        let path = PathBuf::from(path);
        return match std::fs::read_to_string(&path) {
            Ok(content) => Ok(content.trim_end_matches(['\n', '\r']).to_string()),
            Err(e) => match default {
                Some(d) => Ok(d.to_string()),
                None => Err(InterpolateError::UnreadableFile(
                    path.clone(),
                    e.to_string(),
                )),
            },
        };
    }
    // `${VAR}` or `${VAR:-default}`; the variable name must be non-empty.
    let (name, default) = match expr.split_once(":-") {
        Some((name, default)) => (name.trim(), Some(default)),
        None => (expr.trim(), None),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(InterpolateError::Malformed(whole.to_string()));
    }
    match env(name) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => match default {
            Some(d) => Ok(d.to_string()),
            None => Err(InterpolateError::MissingEnv(name.to_string())),
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

    fn interp(v: &mut toml::Value) -> Result<(), InterpolateError> {
        interpolate_with(v, test_env)
    }

    fn val(s: &str) -> toml::Value {
        toml::Value::String(s.to_string())
    }

    #[test]
    fn env_var_substituted() {
        let mut v = val("token=${VERD_TEST_VAR}");
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "token=sekret");
    }

    #[test]
    fn default_used_when_unset() {
        let mut v = val("${VERD_DEFINITELY_UNSET:-fallback}");
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "fallback");
    }

    #[test]
    fn missing_env_is_error() {
        let mut v = val("${VERD_DEFINITELY_UNSET}");
        assert!(matches!(
            interp(&mut v),
            Err(InterpolateError::MissingEnv(_))
        ));
    }

    #[test]
    fn file_substituted_and_trimmed() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hunter2\n").unwrap();
        let mut v = val(&format!("${{file:{}}}", f.path().display()));
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "hunter2");
    }

    #[test]
    fn nested_values_reached() {
        let mut v: toml::Value = toml::from_str(
            "a = \"${VERD_TEST_VAR}\"\nb = [\"${VERD_TEST_VAR}\"]\n[t]\nc = \"x ${VERD_TEST_VAR} y\"",
        )
        .unwrap();
        interp(&mut v).unwrap();
        assert_eq!(v["t"]["c"].as_str().unwrap(), "x sekret y");
        assert_eq!(v["b"][0].as_str().unwrap(), "sekret");
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
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "$HOME literally, no braces");
    }

    #[test]
    fn double_dollar_escapes_marker() {
        let mut v = val("costs $${price} and $${VERD_TEST_VAR}");
        interp(&mut v).unwrap();
        assert_eq!(v.as_str().unwrap(), "costs ${price} and ${VERD_TEST_VAR}");
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
            Err(InterpolateError::UnreadableFile(_, _))
        ));
    }
}
