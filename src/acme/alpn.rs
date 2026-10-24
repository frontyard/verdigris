//! `tls-alpn-01` (RFC 8737) challenge certificates: a throwaway
//! self-signed cert bearing the critical `id-pe-acmeIdentifier`
//! extension with the SHA-256 of the key authorization, presented only
//! to handshakes negotiating the `acme-tls/1` ALPN protocol.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// Build the ephemeral challenge certificate for `domain` whose
/// acmeIdentifier carries `sha256(key_authorization)` (`digest` as
/// produced by `instant_acme::KeyAuthorization::digest`).
pub fn challenge_cert(domain: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let keypair = rcgen::KeyPair::generate().map_err(|e| format!("rcgen keypair: {e}"))?;
    let mut params =
        rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(digest));
    let cert = params
        .self_signed(&keypair)
        .map_err(|e| format!("rcgen sign: {e}"))?;
    let certs = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));
    // `CertifiedKey::from_der` validates the leaf and rejects the
    // mandatory critical acmeIdentifier extension — load the signing
    // key directly instead; the cert is a throwaway for the CA only.
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| format!("load challenge key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_has_acme_extension() {
        let digest = [7u8; 32];
        let key = challenge_cert("acme.example", &digest).unwrap();
        let cert = &key.cert[0];
        // DER scan: the OID 1.3.6.1.5.5.7.1.31 encodes as
        // 06 08 2B 06 01 05 05 07 01 1F.
        let oid = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F];
        assert!(
            cert.as_ref().windows(oid.len()).any(|w| w == oid),
            "acmeIdentifier OID present in DER"
        );
        // digest bytes present (inside the OCTET STRING)
        assert!(cert.as_ref().windows(32).any(|w| w == digest));
    }
}
