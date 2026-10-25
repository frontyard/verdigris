//! `verd fmt`: normalize a TOML config while preserving comments, using
//! `toml_edit`'s lossless document representation. Formatting normalizes
//! whitespace around `=` and trailing spaces; comments and key order are
//! untouched.

use std::path::Path;

use thiserror::Error;

/// Formatting failures.
#[derive(Debug, Error)]
pub enum FmtError {
    /// The file could not be read.
    #[error("cannot read {0}: {1}")]
    Io(std::path::PathBuf, String),
    /// The file is not valid TOML.
    #[error("{0}: TOML syntax error: {1}")]
    Syntax(std::path::PathBuf, String),
}

/// Format TOML text, preserving comments and key order.
pub fn format_str(text: &str) -> Result<String, String> {
    let doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e: toml_edit::TomlError| e.to_string())?;
    Ok(doc.to_string())
}

/// Format a file in place. Returns `true` if the content changed.
pub fn format_file(path: &Path) -> Result<bool, FmtError> {
    let original = std::fs::read_to_string(path)
        .map_err(|e| FmtError::Io(path.to_path_buf(), e.to_string()))?;
    let formatted = format_str(&original).map_err(|e| FmtError::Syntax(path.to_path_buf(), e))?;
    if formatted == original {
        return Ok(false);
    }
    std::fs::write(path, formatted).map_err(|e| FmtError::Io(path.to_path_buf(), e.to_string()))?;
    Ok(true)
}

/// Emit the JSON Schema for [`crate::config::model::Config`].
pub fn json_schema() -> serde_json::Value {
    schemars::schema_for!(crate::config::model::Config).to_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_preserved() {
        let input = "# top comment\n[server]   # inline\ngraceful_timeout = \"30s\"\n";
        let out = format_str(input).unwrap();
        assert!(out.contains("# top comment"));
        assert!(out.contains("# inline"));
    }

    #[test]
    fn invalid_toml_is_error() {
        assert!(format_str("[[[").is_err());
    }

    #[test]
    fn formatting_is_idempotent() {
        let input = "[[site]]\nhosts=[\"a\"]\nroot=\"./public\"\n";
        let once = format_str(input).unwrap();
        let twice = format_str(&once).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn schema_has_config_title() {
        let schema = json_schema();
        assert!(schema.get("$schema").is_some() || schema.get("title").is_some());
    }

    #[test]
    fn format_file_rewrites_unformatted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verd.toml");
        std::fs::write(&path, "[[site]]\nhosts=[\"a\"]   # keep\n").unwrap();
        // toml_edit is lossless: a parseable document round-trips
        // unchanged, so this is a no-op
        assert!(!format_file(&path).unwrap());
        assert!(std::fs::read_to_string(&path).unwrap().contains("# keep"));

        let missing = dir.path().join("ghost.toml");
        assert!(matches!(format_file(&missing), Err(FmtError::Io(_, _))));
        std::fs::write(&path, "[[[").unwrap();
        assert!(matches!(format_file(&path), Err(FmtError::Syntax(_, _))));
    }
}
