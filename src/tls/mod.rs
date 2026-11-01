//! Inbound TLS: certificate resolution (SNI → site cert), PEM loading with
//! hot reload, self-signed generation and the acceptor construction.
//! Upstream (client-side) TLS lives in `proxy::cluster`; ACME lands in P8
//! and plugs into the same [`CertResolver`].

pub mod manual;
pub mod resolver;
pub mod selfsigned;

use std::sync::Arc;

use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::model as cfg;
use crate::tls::manual::WatchEntry;
use crate::tls::resolver::CertResolver;

/// TLS state for one config generation: the acceptor handed to connection
/// tasks plus the resolver the cert watcher updates in place.
pub struct TlsRuntime {
    /// Per-connection acceptor (ALPN: h2, http/1.1).
    pub acceptor: TlsAcceptor,
    /// SNI → cert map; shared with the hot-reload watcher.
    pub resolver: Arc<CertResolver>,
    /// Cert files watched for in-place reload.
    pub watch: Vec<WatchEntry>,
}

impl TlsRuntime {
    /// Build certificates for every site that needs them:
    /// `manual` → load PEMs (+watch), `selfsigned` → generate, `auto` →
    /// deferred to the ACME phase (nothing is inserted yet). Returns `None`
    /// when no TLS listeners exist.
    pub fn build(config: &cfg::Config) -> Result<Option<Self>, String> {
        if !config.server.listen.iter().any(|l| l.tls) {
            return Ok(None);
        }
        let resolver = Arc::new(CertResolver::default());
        let mut watch = Vec::new();
        let mut default_hosts: Option<Vec<String>> = None;

        for site in &config.site {
            let hosts = &site.hosts;
            match &site.tls {
                cfg::SiteTls::Manual(m) => {
                    let key = manual::load_pair(m).map_err(|e| {
                        format!("site {:?}: {e}", site.name.as_deref().unwrap_or("?"))
                    })?;
                    resolver.insert(hosts, key);
                    watch.push(WatchEntry {
                        cert: m.cert.clone(),
                        key: m.key.clone(),
                        hosts: hosts.clone(),
                    });
                    if site.default {
                        default_hosts = Some(hosts.clone());
                    }
                }
                cfg::SiteTls::Mode(cfg::TlsMode::SelfSigned) => {
                    let key = selfsigned::generate(hosts).map_err(|e| {
                        format!("site {:?}: {e}", site.name.as_deref().unwrap_or("?"))
                    })?;
                    resolver.insert(hosts, key);
                    if site.default {
                        default_hosts = Some(hosts.clone());
                    }
                }
                cfg::SiteTls::Mode(cfg::TlsMode::Auto) => {
                    // P8: the ACME issuer will insert certs dynamically;
                    // handshakes for these hosts fail until then.
                    tracing::debug!(
                        site = site.name.as_deref().unwrap_or("?"),
                        "tls = \"auto\": certificate pending ACME issuance"
                    );
                }
                cfg::SiteTls::Mode(cfg::TlsMode::Off) => {}
            }
        }

        // The default site's cert answers no-SNI clients when present.
        if let Some(hosts) = default_hosts
            && let Some(first) = hosts.first()
            && let Some(k) = resolver.lookup(first)
        {
            resolver.set_default(k);
        }

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        // `acme-tls/1` so TLS-ALPN-01 challenge handshakes negotiate ALPN
        // and reach the resolver's challenge-cert branch; without a
        // pending challenge there's nothing to resolve and the handshake
        // still aborts.
        server_config.alpn_protocols = vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
            crate::acme::challenge::ACME_TLS_ALPN.to_vec(),
        ];

        Ok(Some(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            resolver,
            watch,
        }))
    }

    /// Arm the certificate hot-reload watcher; stops with the runtime.
    pub fn spawn_watcher(self: &Arc<Self>, stop: CancellationToken) {
        manual::spawn_watcher(Arc::downgrade(&self.resolver), self.watch.clone(), stop);
    }
}
