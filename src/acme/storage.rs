//! On-disk ACME state: account credentials and issued certificates.
//!
//! Layout under `acme.storage`:
//!
//! ```text
//! account.json                 mode 0600 — instant-acme credentials
//! certs/{sanitized-host}/cert.pem   full chain PEM
//! certs/{sanitized-host}/key.pem    private key PEM, mode 0600
//! ```
//!
//! Writes are atomic (tmp file + rename) so a crash mid-renewal never
//! leaves half a certificate behind.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Storage rooted at `acme.storage`.
#[derive(Debug, Clone)]
pub struct Storage {
    root: PathBuf,
}

/// A persisted certificate pair plus the leaf's validity window.
pub struct StoredCert {
    /// Full chain PEM.
    pub cert_pem: String,
    /// Private key PEM.
    pub key_pem: String,
    /// Leaf `notBefore`.
    pub not_before: SystemTime,
    /// Leaf `notAfter`.
    pub not_after: SystemTime,
}

impl Storage {
    /// Root at `root` (created lazily on first write).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn account_path(&self) -> PathBuf {
        self.root.join("account.json")
    }

    fn cert_dir(&self, host: &str) -> PathBuf {
        self.root.join("certs").join(sanitize(host))
    }

    /// Load serialized account credentials, if any.
    pub fn load_account(&self) -> Option<Vec<u8>> {
        fs::read(self.account_path()).ok()
    }

    /// Persist serialized account credentials (0600).
    pub fn save_account(&self, creds: &[u8]) -> Result<(), String> {
        fs::create_dir_all(&self.root).map_err(err)?;
        write_atomic(&self.account_path(), creds, true).map_err(err)
    }

    /// Persist an issued cert+key for `host`.
    pub fn save_cert(&self, host: &str, cert_pem: &str, key_pem: &str) -> Result<(), String> {
        let dir = self.cert_dir(host);
        fs::create_dir_all(&dir).map_err(err)?;
        write_atomic(&dir.join("cert.pem"), cert_pem.as_bytes(), false).map_err(err)?;
        write_atomic(&dir.join("key.pem"), key_pem.as_bytes(), true).map_err(err)
    }

    /// Load a stored cert+key for `host` and parse its leaf `notAfter`.
    /// `None` when absent or unparsable (treated as "issue fresh").
    pub fn load_cert(&self, host: &str) -> Option<StoredCert> {
        let dir = self.cert_dir(host);
        let cert_pem = String::from_utf8(fs::read(dir.join("cert.pem")).ok()?).ok()?;
        let key_pem = String::from_utf8(fs::read(dir.join("key.pem")).ok()?).ok()?;
        let (not_before, not_after) = leaf_validity(&cert_pem)?;
        Some(StoredCert {
            cert_pem,
            key_pem,
            not_before,
            not_after,
        })
    }
}

/// Safe single-label filename: hosts are DNS names but `*.` wildcards and
/// stray separators must not escape the certs dir.
fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// `notBefore`/`notAfter` of the first certificate in a PEM bundle.
fn leaf_validity(pem: &str) -> Option<(SystemTime, SystemTime)> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let der = rustls_pemfile::certs(&mut rd).next()?.ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let v = cert.validity();
    let (nb, na) = (v.not_before.timestamp(), v.not_after.timestamp());
    if nb < 0 || na < 0 {
        return None;
    }
    let epoch = SystemTime::UNIX_EPOCH;
    Some((
        epoch + std::time::Duration::from_secs(nb as u64),
        epoch + std::time::Duration::from_secs(na as u64),
    ))
}

/// Write `data` to a sibling tmp file then rename over `path`; `secret`
/// files get mode 0600.
fn write_atomic(path: &Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &tmp,
            fs::Permissions::from_mode(if secret { 0o600 } else { 0o644 }),
        )?;
    }
    let _ = secret; // windows: default ACLs apply
    fs::rename(&tmp, path)
}

fn err(e: std::io::Error) -> String {
    format!("acme storage: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_separators() {
        assert_eq!(sanitize("*.example.com"), "_.example.com");
        assert_eq!(sanitize("../evil"), ".._evil");
        assert_eq!(sanitize("HOST.COM"), "host.com");
    }

    #[test]
    fn cert_roundtrip_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::new(dir.path().into());
        let (cert_pem, key_pem) = crate::tls::selfsigned::generate_pems(&["t.example".into()]);
        s.save_cert("t.example", &cert_pem, &key_pem).unwrap();
        let got = s.load_cert("t.example").unwrap();
        assert_eq!(got.cert_pem, cert_pem);
        assert_eq!(got.key_pem, key_pem);
        assert!(got.not_after > SystemTime::now());
        assert!(s.load_cert("missing.example").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("certs/t.example/key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
