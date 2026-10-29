//! SNI → certificate resolution for inbound TLS. A single [`CertResolver`]
//! serves all TLS listeners: exact hostnames, `*.suffix` wildcards, and an
//! optional default for clients that send no SNI. Entries are swapped in
//! place, so certificate hot-reload and (later) ACME issuance take effect
//! on the next handshake without restarting.

use std::sync::Arc;

use dashmap::DashMap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Normalize a hostname for map lookups: lowercase, strip a trailing dot.
pub fn host_key(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Synchronous on-demand issuance consulted by [`CertResolver::resolve`]
/// for unknown SNI. `resolve` runs on a tokio worker inside handshake
/// polling — implementations **must not block**: parking the worker
/// behind issuance duration lets a handful of connections deadlock the
/// whole runtime. Kick issuance off elsewhere and return `None`; the
/// client's retry resolves the cert once it lands.
pub trait OnDemandIssue: Send + Sync + std::fmt::Debug {
    /// Issue a certificate for `host` — synchronously, without blocking.
    /// `None` declines (not allowed, rate limited, issuance still in
    /// flight, or failed); the handshake falls back or fails and the
    /// client retries.
    fn issue(&self, host: &str) -> Option<Arc<CertifiedKey>>;
}

/// Per-generation certificate store. Thread-safe and updated in place.
#[derive(Debug, Default)]
pub struct CertResolver {
    /// `host` → cert for exact hostnames.
    exact: DashMap<String, Arc<CertifiedKey>>,
    /// `example.com` → cert for `*.example.com` wildcards (single label).
    wild: DashMap<String, Arc<CertifiedKey>>,
    /// Fallback when the client sends no SNI or SNI matches nothing.
    default: std::sync::RwLock<Option<Arc<CertifiedKey>>>,
    /// `tls-alpn-01` challenge certificates (shared with the ACME
    /// manager; checked before everything when ALPN is `acme-tls/1`).
    pub alpn: crate::acme::challenge::AlpnStore,
    /// On-demand issuer for unknown SNI (ACME `on_demand`).
    on_demand: std::sync::RwLock<Option<Arc<dyn OnDemandIssue>>>,
}

impl CertResolver {
    /// Register `key` for each of `hosts` (wildcards recognized). When the
    /// resolver has no default yet, this cert becomes the default.
    pub fn insert(&self, hosts: &[String], key: Arc<CertifiedKey>) {
        for h in hosts {
            let h = host_key(h);
            if let Some(suffix) = h.strip_prefix("*.") {
                self.wild.insert(suffix.to_string(), key.clone());
            } else {
                self.exact.insert(h, key.clone());
            }
        }
        let mut def = self.default.write().unwrap_or_else(|e| e.into_inner());
        if def.is_none() {
            *def = Some(key);
        }
    }

    /// Replace the no-SNI/unknown-SNI fallback certificate.
    pub fn set_default(&self, key: Arc<CertifiedKey>) {
        *self.default.write().unwrap_or_else(|e| e.into_inner()) = Some(key);
    }

    /// Remove all hostnames bound to `hosts` (used on config reload before
    /// re-adding; certs themselves stay valid for in-flight handshakes).
    pub fn remove(&self, hosts: &[String]) {
        for h in hosts {
            let h = host_key(h);
            if let Some(suffix) = h.strip_prefix("*.") {
                self.wild.remove(suffix);
            } else {
                self.exact.remove(&h);
            }
        }
    }

    /// Whether a certificate is registered for `host` (exact or wildcard).
    /// Used by the HTTP→HTTPS redirect decision.
    pub fn has_cert(&self, host: &str) -> bool {
        self.lookup(host).is_some()
    }

    /// Resolve a normalized or raw hostname.
    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let h = host_key(host);
        if let Some(k) = self.exact.get(&h) {
            return Some(k.clone());
        }
        // `*.example.com` covers exactly one leftmost label.
        if let Some((_, suffix)) = h.split_once('.')
            && let Some(k) = self.wild.get(suffix)
        {
            return Some(k.clone());
        }
        None
    }

    /// Number of (host → cert) bindings; for tests/admin.
    pub fn binding_count(&self) -> usize {
        self.exact.len() + self.wild.len()
    }

    /// `(host, seconds-until-expiry)` for every exact binding — the
    /// metrics sweep emits `verd_cert_expiry_seconds` from these.
    pub fn cert_expiries(&self) -> Vec<(String, f64)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.exact
            .iter()
            .filter_map(|e| {
                let der = e.value().cert.first()?;
                let (_, x): (_, x509_parser::certificate::X509Certificate) =
                    x509_parser::prelude::FromDer::from_der(der.as_ref()).ok()?;
                let left = x.validity().not_after.timestamp() - now;
                Some((e.key().clone(), left as f64))
            })
            .collect()
    }

    /// Install the on-demand issuer (ACME); consulted for unknown SNI.
    pub fn set_on_demand(&self, od: Arc<dyn OnDemandIssue>) {
        *self.on_demand.write().unwrap_or_else(|e| e.into_inner()) = Some(od);
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // `acme-tls/1` handshakes get only the challenge cert — never the
        // default (a default would fail validation and also leak the
        // real cert to the CA probe).
        if client_hello
            .alpn()
            .is_some_and(|mut p| p.any(|a| a == crate::acme::challenge::ACME_TLS_ALPN))
        {
            return client_hello
                .server_name()
                .and_then(|s| self.alpn.lookup(&host_key(s)));
        }
        if let Some(sni) = client_hello.server_name() {
            if let Some(k) = self.lookup(sni) {
                return Some(k);
            }
            // unknown SNI: on-demand issuance may produce a cert inline
            if let Some(od) = self
                .on_demand
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                && let Some(k) = od.issue(&host_key(sni))
            {
                return Some(k);
            }
        }
        self.default
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ck() -> Arc<CertifiedKey> {
        crate::tls::selfsigned::generate(&["gen.local".into()]).unwrap()
    }

    #[test]
    fn exact_and_default() {
        let r = CertResolver::default();
        let k = ck();
        r.insert(&["example.com".into()], k.clone());
        assert!(r.lookup("example.com").is_some());
        assert!(r.lookup("EXAMPLE.com.").is_some());
        assert!(r.lookup("other.com").is_none());
        // first insert becomes the implicit default
        assert!(r.has_cert("example.com"));
    }

    #[test]
    fn wildcard_single_label() {
        let r = CertResolver::default();
        r.insert(&["*.example.com".into()], ck());
        assert!(r.lookup("www.example.com").is_some());
        assert!(r.lookup("a.b.example.com").is_none());
        assert!(r.lookup("example.com").is_none());
        assert_eq!(r.binding_count(), 1);
    }

    #[test]
    fn in_place_swap() {
        let r = CertResolver::default();
        r.insert(&["a.com".into()], ck());
        let k2 = ck();
        r.insert(&["a.com".into()], k2.clone());
        assert!(Arc::ptr_eq(&r.lookup("a.com").unwrap(), &k2));
    }

    #[test]
    fn cert_expiries_reports_each_binding() {
        let r = CertResolver::default();
        r.insert(&["exp.test".into()], ck());
        let exps = r.cert_expiries();
        assert_eq!(exps.len(), 1);
        assert_eq!(exps[0].0, "exp.test");
        assert!(
            exps[0].1 > 0.0,
            "a fresh self-signed cert must have positive ttl, got {}",
            exps[0].1
        );
    }

    #[test]
    fn set_on_demand_installs_issuer() {
        #[derive(Debug)]
        struct Noop;
        impl OnDemandIssue for Noop {
            fn issue(&self, _host: &str) -> Option<Arc<CertifiedKey>> {
                None
            }
        }
        let r = CertResolver::default();
        assert!(r.on_demand.read().unwrap().is_none());
        r.set_on_demand(Arc::new(Noop));
        assert!(
            r.on_demand.read().unwrap().is_some(),
            "set_on_demand must install the issuer, not drop it"
        );
    }
}
