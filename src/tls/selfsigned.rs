//! `tls = "selfsigned"`: generate a per-site self-signed certificate at
//! startup via rcgen — a development convenience, never used for `auto`.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// Generate a self-signed certificate covering `hosts` (SANs incl.
/// wildcards) and return it as a rustls [`CertifiedKey`].
pub fn generate(hosts: &[String]) -> Result<Arc<CertifiedKey>, String> {
    let sans: Vec<String> = if hosts.is_empty() {
        vec!["localhost".to_string()]
    } else {
        hosts.to_vec()
    };
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(sans)
        .map_err(|e| format!("self-signed generation failed: {e}"))?;
    let certs = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let key = crate::tls::manual::build_key(certs, key)?;
    Ok(Arc::new(key))
}

/// Same certificate as PEM strings — used by tests and `verd` tooling.
pub fn generate_pems(hosts: &[String]) -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(hosts.to_vec()).expect("self-signed generation");
    (cert.pem(), signing_key.serialize_pem())
}
