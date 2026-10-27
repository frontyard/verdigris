//! `verd fmt`: normalize a TOML config while preserving comments, using
//! `toml_edit`'s lossless document representation. Formatting normalizes
//! the gap around `=` to a single space and strips trailing whitespace;
//! comments and key order are untouched.

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
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e: toml_edit::TomlError| e.to_string())?;
    normalize_table(doc.as_table_mut());
    Ok(doc.to_string())
}

/// Recursively normalize one table's entries.
///
/// toml_edit decor layout for `key = value`: the key's *suffix* is the
/// gap before `=`, the value's *prefix* is the gap after `=`, and the
/// value's *suffix* holds everything up to the next key — trailing
/// whitespace and/or an end-of-line comment. The key's *prefix* holds
/// the previous line's newline plus any comment lines and indentation.
fn normalize_table(table: &mut toml_edit::Table) {
    for (mut key, item) in table.iter_mut() {
        match item {
            toml_edit::Item::Value(v) => {
                rstrip_lines(key.leaf_decor_mut());
                gap_to_one_space(key.leaf_decor_mut(), true);
                gap_to_one_space(v.decor_mut(), false);
                clean_trailing(v.decor_mut());
                match v {
                    toml_edit::Value::InlineTable(it) => normalize_inline_table(it),
                    toml_edit::Value::Array(a) => normalize_array(a),
                    _ => {}
                }
            }
            toml_edit::Item::Table(t) => {
                rstrip_lines(t.decor_mut());
                clean_trailing(t.decor_mut());
                normalize_table(t);
            }
            toml_edit::Item::ArrayOfTables(a) => {
                for t in a.iter_mut() {
                    rstrip_lines(t.decor_mut());
                    clean_trailing(t.decor_mut());
                    normalize_table(t);
                }
            }
            toml_edit::Item::None => {}
        }
    }
}

/// Recursively normalize an inline table's `key = value` gaps — only the
/// `=` gaps; `{ a = 1 }` keeps its brace/comma spacing.
fn normalize_inline_table(table: &mut toml_edit::InlineTable) {
    for (mut key, item) in table.iter_mut() {
        gap_to_one_space(key.leaf_decor_mut(), true);
        gap_to_one_space(item.decor_mut(), false);
        match item {
            toml_edit::Value::InlineTable(it) => normalize_inline_table(it),
            toml_edit::Value::Array(a) => normalize_array(a),
            _ => {}
        }
    }
}

/// Recurse into an array's elements — inline tables inside arrays
/// (`listen = [{ addr = "..." }]`) carry `=` gaps like any table.
fn normalize_array(array: &mut toml_edit::Array) {
    for v in array.iter_mut() {
        match v {
            toml_edit::Value::InlineTable(it) => normalize_inline_table(it),
            toml_edit::Value::Array(a) => normalize_array(a),
            _ => {}
        }
    }
}

/// Collapse a mid-line `=` gap (key suffix / value prefix) to `" "`.
/// These gaps are single-line by TOML rules, so no comment can appear.
fn gap_to_one_space(decor: &mut toml_edit::Decor, suffix_side: bool) {
    let gap = if suffix_side {
        decor.suffix()
    } else {
        decor.prefix()
    };
    let needs_fix = gap
        .and_then(|g| g.as_str())
        .is_some_and(|s| s != " " && s.chars().all(char::is_whitespace));
    if needs_fix {
        if suffix_side {
            decor.set_suffix(" ");
        } else {
            decor.set_prefix(" ");
        }
    }
}

/// Normalize a value's (or table header's) suffix: the chunk ends at a
/// line end, so it holds trailing whitespace and/or a `#` comment.
/// Pure whitespace → `""`; whitespace before a comment → `" "`.
fn clean_trailing(decor: &mut toml_edit::Decor) {
    let Some(s) = decor.suffix().and_then(|r| r.as_str().map(str::to_string)) else {
        return;
    };
    let cleaned = match s.find('#') {
        // one space between the value and the comment marker
        Some(i) if s[..i].chars().all(char::is_whitespace) => {
            format!(" {}", s[i..].trim_end())
        }
        Some(_) => s.trim_end().to_string(),
        None if s.chars().all(char::is_whitespace) => String::new(),
        None => s.trim_end().to_string(),
    };
    if cleaned != s {
        decor.set_suffix(cleaned);
    }
}

/// Strip trailing spaces/tabs on every *complete* line in a decor chunk —
/// the final partial line (indentation before a key or `[`) is left alone.
fn rstrip_lines(decor: &mut toml_edit::Decor) {
    let strip = |r: &toml_edit::RawString| -> Option<String> {
        let s = r.as_str()?;
        if !s.contains('\n') {
            return None;
        }
        let mut out = String::with_capacity(s.len());
        for part in s.split_inclusive('\n') {
            let line = part.strip_suffix('\n').unwrap_or(part);
            out.push_str(line.trim_end());
            if part.ends_with('\n') {
                out.push('\n');
            }
        }
        (out != s).then_some(out)
    };
    let pre = decor.prefix().and_then(strip);
    let suf = decor.suffix().and_then(strip);
    if let Some(s) = pre {
        decor.set_prefix(s);
    }
    if let Some(s) = suf {
        decor.set_suffix(s);
    }
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
        // `hosts=[` is unformatted — the file is rewritten and changed
        assert!(format_file(&path).unwrap());
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains("hosts = [\"a\"]"), "{out}");
        assert!(out.contains("# keep"));
        // second run is a no-op
        assert!(!format_file(&path).unwrap());

        let missing = dir.path().join("ghost.toml");
        assert!(matches!(format_file(&missing), Err(FmtError::Io(_, _))));
        std::fs::write(&path, "[[[").unwrap();
        assert!(matches!(format_file(&path), Err(FmtError::Syntax(_, _))));
    }

    #[test]
    fn gaps_and_trailing_ws_normalized() {
        let input = "a   =   1  \nb=  \"x\"\n[t]\nk  =  [\n  1,\n]\n";
        let out = format_str(input).unwrap();
        assert_eq!(out, "a = 1\nb = \"x\"\n[t]\nk = [\n  1,\n]\n");
    }

    #[test]
    fn gap_before_comment_kept() {
        // the value→comment gap normalizes to one space; comment text
        // itself is preserved
        let input = "a=1 # note\nb=2# also a comment\n";
        let out = format_str(input).unwrap();
        assert_eq!(out, "a = 1 # note\nb = 2 # also a comment\n");
    }

    #[test]
    fn inline_tables_inside_arrays_normalized() {
        let input = "[server]\nlisten = [{addr=\"127.0.0.1:8080\", tls=true}, \"0.0.0.0:80\"]\n";
        let out = format_str(input).unwrap();
        assert!(out.contains("listen = ["), "{out}");
        assert!(out.contains("addr = \"127.0.0.1:8080\""), "{out}");
        assert!(out.contains("tls = true"), "{out}");
        // nested arrays inside inline tables too
        let nested = "x = { tags  =  [{a=1}] }\n";
        let out = format_str(nested).unwrap();
        assert!(out.contains("a = 1"), "{out}");
    }

    #[test]
    fn inline_table_gaps_normalized() {
        let input = "[[site]]\nhosts=[\"x\"]\nrespond = { status  =  200 , body=\"hi\" }\n";
        let out = format_str(input).unwrap();
        assert!(out.contains("hosts = [\"x\"]"), "{out}");
        assert!(out.contains("status = 200"), "{out}");
        assert!(out.contains("body = \"hi\""), "{out}");
    }
}
