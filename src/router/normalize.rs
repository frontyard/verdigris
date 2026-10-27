//! Path normalization applied before route matching, filesystem access and
//! upstream forwarding: percent-decoding, dot-segment resolution and
//! duplicate-slash collapsing, per RFC 3986 §5.2.4 semantics with the twist
//! that `%2F` decodes into a real separator (like nginx).
//!
//! The result is always an absolute path starting with exactly one `/`.
//! Traversal above the root is clamped — `/a/../../b` normalizes to `/b`,
//! and percent-encoded dot segments are treated like literal ones.

/// A path that could not be normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    /// Path contains a NUL byte (possibly percent-encoded).
    Nul,
    /// Path contains an ASCII/control character (possibly
    /// percent-encoded) — `%09`-style bytes are legal in a request
    /// target but meaningless in a filesystem path and dangerous in
    /// generated markup.
    Control,
    /// The path bytes were not valid UTF-8 after percent-decoding.
    Utf8,
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nul => write!(f, "path contains NUL"),
            Self::Control => write!(f, "path contains a control character"),
            Self::Utf8 => write!(f, "path is not valid UTF-8"),
        }
    }
}

impl std::error::Error for NormalizeError {}

/// Normalize a request path (the part before `?`).
pub fn normalize_path(raw: &str) -> Result<String, NormalizeError> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| NormalizeError::Utf8)?;
    if decoded.contains('\0') {
        return Err(NormalizeError::Nul);
    }
    if decoded.chars().any(|c| c.is_control()) {
        return Err(NormalizeError::Control);
    }
    let had_trailing_slash = decoded.ends_with('/') && decoded.len() > 1;
    let mut out: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            seg => out.push(seg),
        }
    }
    let mut path = String::with_capacity(decoded.len());
    path.push('/');
    path.push_str(&out.join("/"));
    if had_trailing_slash && !path.ends_with('/') {
        path.push('/');
    }
    Ok(path)
}

/// Shorten a normalized path to its parent prefix: `/a/b/c` → `/a/b`,
/// `/a` → `/`. Used to enumerate progressively less-specific prefix matches.
pub fn parent_prefix(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        match path.rfind('/') {
            Some(0) => "/",
            Some(i) => &path[..i],
            None => "/",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_duplicate_slashes() {
        assert_eq!(normalize_path("//a///b").unwrap(), "/a/b");
    }

    #[test]
    fn resolves_dot_segments() {
        assert_eq!(normalize_path("/a/./b").unwrap(), "/a/b");
        assert_eq!(normalize_path("/a/../b").unwrap(), "/b");
        assert_eq!(normalize_path("/a/b/../../c").unwrap(), "/c");
    }

    #[test]
    fn traversal_clamps_at_root() {
        assert_eq!(normalize_path("/../a").unwrap(), "/a");
        assert_eq!(normalize_path("/../../x").unwrap(), "/x");
        assert_eq!(normalize_path("/a/../../../b").unwrap(), "/b");
    }

    #[test]
    fn decodes_percent_encoding() {
        assert_eq!(normalize_path("/a%20b/c").unwrap(), "/a b/c");
        assert_eq!(normalize_path("/%2e%2e/secret").unwrap(), "/secret");
        assert_eq!(normalize_path("/a%2Fb").unwrap(), "/a/b");
    }

    #[test]
    fn preserves_trailing_slash() {
        assert_eq!(normalize_path("/a/b/").unwrap(), "/a/b/");
        assert_eq!(normalize_path("/a//b/").unwrap(), "/a/b/");
        assert_eq!(normalize_path("/").unwrap(), "/");
    }

    #[test]
    fn rejects_nul_and_bad_utf8() {
        assert_eq!(normalize_path("/a%00b"), Err(NormalizeError::Nul));
        assert_eq!(normalize_path("/%ff"), Err(NormalizeError::Utf8));
    }

    #[test]
    fn rejects_decoded_control_chars() {
        assert_eq!(normalize_path("/a%09b"), Err(NormalizeError::Control));
        assert_eq!(normalize_path("/a%1fb"), Err(NormalizeError::Control));
        assert_eq!(normalize_path("/a%7fb"), Err(NormalizeError::Control));
        // raw space is fine — it is not a control character
        assert_eq!(normalize_path("/a b").unwrap(), "/a b");
    }

    #[test]
    fn parent_prefix_climbs() {
        assert_eq!(parent_prefix("/a/b/c"), "/a/b");
        assert_eq!(parent_prefix("/a"), "/");
        assert_eq!(parent_prefix("/"), "/");
    }
}
