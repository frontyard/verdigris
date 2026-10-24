//! Manual certificate loading (PEM chain + private key) and hot reload:
//! a `notify` watcher reloads changed pairs and swaps them into the
//! [`CertResolver`] in place — new handshakes pick up the new cert
//! immediately, in-flight connections are untouched.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use crate::config::model::ManualTls;
use crate::tls::resolver::CertResolver;

/// Load a PEM certificate chain + private key into a [`CertifiedKey`].
pub fn load_pair(m: &ManualTls) -> Result<Arc<CertifiedKey>, String> {
    let certs = load_certs(&m.cert)?;
    let key = load_key(&m.key)?;
    Ok(Arc::new(build_key(certs, key)?))
}

/// Parse a PEM file into a certificate chain; must contain ≥1 certificate.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot read certificate {}: {e}", path.display()))?;
    let mut rd = std::io::BufReader::new(data.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cannot parse certificate PEM {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

/// Parse the first private key in a PEM file (PKCS#8, PKCS#1 or SEC1).
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("cannot read private key {}: {e}", path.display()))?;
    let mut rd = std::io::BufReader::new(data.as_slice());
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| format!("cannot parse private key PEM {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key found in {}", path.display()))
}

/// Combine chain + key, verifying they match where the provider can tell.
pub fn build_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey, String> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    CertifiedKey::from_der(certs, key, &provider)
        .map_err(|e| format!("certificate/private key mismatch: {e}"))
}

/// A watched cert/key pair and the hostnames it serves.
#[derive(Debug, Clone)]
pub struct WatchEntry {
    /// PEM certificate chain path.
    pub cert: PathBuf,
    /// PEM private key path.
    pub key: PathBuf,
    /// Hostnames (incl. `*.` wildcards) this pair is registered under.
    pub hosts: Vec<String>,
}

/// Spawn the hot-reload watcher. The task exits when `stop` fires or when
/// `resolver` is dropped (runtime generation swapped out).
pub fn spawn_watcher(
    resolver: std::sync::Weak<CertResolver>,
    entries: Vec<WatchEntry>,
    stop: CancellationToken,
) {
    use notify::{RecursiveMode, Watcher};
    if entries.is_empty() {
        return;
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = match notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "cannot watch certificates; hot reload disabled");
            return;
        }
    };

    // Watch parent directories (atomic-rename safe) and match on path.
    let mut watched = std::collections::BTreeSet::new();
    for e in &entries {
        for p in [&e.cert, &e.key] {
            if let Some(dir) = p.parent()
                && watched.insert(dir.to_path_buf())
                && let Err(err) = watcher.watch(dir, RecursiveMode::NonRecursive)
            {
                tracing::warn!(path = %dir.display(), error = %err, "cert watch failed");
            }
        }
    }
    tracing::debug!(
        dirs = watched.len(),
        pairs = entries.len(),
        "cert hot-reload armed"
    );

    tokio::spawn(async move {
        let _watcher = watcher; // keep alive for the task's life
        loop {
            let event = tokio::select! {
                _ = stop.cancelled() => return,
                e = rx.recv() => match e {
                    Some(e) => e,
                    None => return,
                },
            };
            let mut paths = match event {
                Ok(notify::Event {
                    kind:
                        notify::EventKind::Modify(_)
                        | notify::EventKind::Create(_)
                        | notify::EventKind::Remove(_),
                    paths,
                    ..
                }) => paths,
                Ok(_) => continue,
                Err(e) => {
                    tracing::debug!(error = %e, "cert watcher error");
                    continue;
                }
            };
            // Debounce: a cert deploy produces several events (cert write,
            // key write, renames). Wait, then fold every queued event into
            // this one batch so each pair reloads at most once.
            tokio::time::sleep(Duration::from_millis(200)).await;
            while let Ok(next) = rx.try_recv() {
                if let Ok(notify::Event { paths: p, .. }) = next {
                    paths.extend(p);
                }
            }
            let Some(resolver) = resolver.upgrade() else {
                return;
            };
            for entry in &entries {
                let hit = paths
                    .iter()
                    .any(|p| same_file(p, &entry.cert) || same_file(p, &entry.key));
                if !hit {
                    continue;
                }
                let m = ManualTls {
                    cert: entry.cert.clone(),
                    key: entry.key.clone(),
                };
                match load_pair(&m) {
                    Ok(ck) => {
                        resolver.insert(&entry.hosts, ck);
                        tracing::info!(
                            cert = %entry.cert.display(),
                            "certificate reloaded"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            cert = %entry.cert.display(),
                            error = %e,
                            "certificate reload failed; keeping previous"
                        );
                    }
                }
            }
        }
    });
}

/// Path equality that also treats different spellings of the same file as
/// equal (symlinks, `..`, relative vs absolute).
fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a fresh self-signed pair and load it back.
    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = crate::tls::selfsigned::generate_pems(&["t.local".into()]);
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, cert_pem).unwrap();
        std::fs::write(&key, key_pem).unwrap();
        let ck = load_pair(&ManualTls { cert, key }).unwrap();
        assert_eq!(ck.cert.len(), 1);
    }

    #[test]
    fn missing_cert_errors() {
        let m = ManualTls {
            cert: PathBuf::from("/nonexistent/cert.pem"),
            key: PathBuf::from("/nonexistent/key.pem"),
        };
        assert!(load_pair(&m).is_err());
    }
}
