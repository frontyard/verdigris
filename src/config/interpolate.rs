//! Secret interpolation in configuration strings: `${VAR}` reads an
//! environment variable, `${VAR:-default}` falls back when unset or empty,
//! and `${file:/path}` reads a file (trailing newlines trimmed) — suited to
//! Docker and Kubernetes mounted secrets. Interpolation applies to string
//! values anywhere in the config, including inside arrays and tables.

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
    if !input.contains("${") {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let inner_start = start + 2;
        let end = rest[inner_start..]
            .find('}')
            .map(|e| inner_start + e)
            .ok_or_else(|| InterpolateError::Malformed(input.to_string()))?;
        let expr = &rest[inner_start..end];
        out.push_str(&resolve(expr, input, env)?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve(
    expr: &str,
    whole: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, InterpolateError> {
    if let Some(path) = expr.strip_prefix("file:") {
        let path = PathBuf::from(path.trim());
        let content = std::fs::read_to_string(&path)
            .map_err(|e| InterpolateError::UnreadableFile(path.clone(), e.to_string()))?;
        return Ok(content.trim_end_matches(['\n', '\r']).to_string());
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
}
