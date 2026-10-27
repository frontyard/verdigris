//! Filesystem permission helpers: dirs that hold secret-adjacent data
//! (ACME account keys, private key PEMs, cached response bodies) must be
//! owner-only on multi-user hosts.

use std::path::Path;

/// Ensure `dir` is owner-only (0700). `create_dir_all` honours umask
/// (typically 022 → 0755), so a freshly created dir is usually too
/// permissive: tighten it unconditionally on unix and warn when an
/// existing dir has group/other access we could not or did not change.
/// No-op on non-unix platforms (default ACLs apply).
#[cfg(unix)]
pub fn private_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(m) = std::fs::metadata(dir) else {
        return;
    };
    if m.permissions().mode() & 0o077 == 0 {
        return; // already owner-only
    }
    match std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
        Ok(()) => {
            tracing::warn!(
                ?dir,
                "directory was group/other-accessible; tightened to 0700"
            );
        }
        Err(e) => {
            tracing::warn!(
                ?dir,
                error = %e,
                "directory is group/other-accessible — its contents may leak to local users; chmod 700"
            );
        }
    }
}

/// No-op on non-unix platforms.
#[cfg(not(unix))]
pub fn private_dir(_: &Path) {}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(unix)]
    fn private_dir_tightens() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        super::private_dir(dir.path());
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // already-private → early return
        super::private_dir(dir.path());
        // missing dir → early return, no panic
        super::private_dir(dir.path().join("nope").as_path());
    }
}
