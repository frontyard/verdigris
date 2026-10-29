//! Shared ACME challenge state: HTTP-01 tokens served by the data plane
//! and TLS-ALPN-01 certificates resolved during the handshake.

use std::sync::Arc;

use dashmap::DashMap;
use rustls::sign::CertifiedKey;

/// ALPN protocol the ACME server uses for `tls-alpn-01` (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Pending `http-01` answers: token → key authorization.
///
/// Tokens are unguessable by design, so a global map is safe — the CA is
/// the only party that knows the token it issued.
#[derive(Debug, Default)]
pub struct Http01Store {
    tokens: DashMap<String, String>,
}

impl Http01Store {
    /// Register a token → key authorization for the challenge duration.
    pub fn insert(&self, token: &str, key_auth: String) {
        self.tokens.insert(token.to_string(), key_auth);
    }

    /// Look up a token; `Some(key_authorization)` while the challenge is
    /// active.
    pub fn lookup(&self, token: &str) -> Option<String> {
        self.tokens.get(token).map(|v| v.clone())
    }

    /// Drop the token once the CA has checked it.
    pub fn remove(&self, token: &str) {
        self.tokens.remove(token);
    }
}

/// Pending `tls-alpn-01` challenge certificates keyed by hostname.
#[derive(Debug, Default)]
pub struct AlpnStore {
    certs: DashMap<String, Arc<CertifiedKey>>,
}

impl AlpnStore {
    /// Install the challenge cert for `host` (normalized by the caller).
    pub fn insert(&self, host: &str, key: Arc<CertifiedKey>) {
        self.certs.insert(host.to_string(), key);
    }

    /// Challenge cert for `host`, if any.
    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.certs.get(host).map(|v| v.clone())
    }

    /// Drop the challenge cert once the CA has checked it.
    pub fn remove(&self, host: &str) {
        self.certs.remove(host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http01_token_lifecycle() {
        let s = Http01Store::default();
        assert!(s.lookup("tok").is_none());
        s.insert("tok", "tok.thumbprint".into());
        assert_eq!(s.lookup("tok").as_deref(), Some("tok.thumbprint"));
        s.remove("tok");
        assert!(s.lookup("tok").is_none());
        // independent tokens
        s.insert("a", "ka".into());
        s.insert("b", "kb".into());
        s.remove("a");
        assert!(s.lookup("a").is_none() && s.lookup("b").is_some());
    }

    #[test]
    fn alpn_cert_lifecycle() {
        let s = AlpnStore::default();
        let ck = crate::tls::selfsigned::generate(&["h.test".into()]).unwrap();
        assert!(s.lookup("h.test").is_none());
        s.insert("h.test", ck.clone());
        assert!(Arc::ptr_eq(&s.lookup("h.test").unwrap(), &ck));
        s.remove("h.test");
        assert!(s.lookup("h.test").is_none());
    }
}
