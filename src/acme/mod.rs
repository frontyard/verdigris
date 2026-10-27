//! ACME certificate management (`tls = "auto"` + on-demand issuance).
//!
//! [`AcmeManager`] owns the ACME account (persisted under
//! `acme.storage`), the `http-01` token store the data plane serves, the
//! `tls-alpn-01` challenge certs the [`CertResolver`] resolves for
//! `acme-tls/1` handshakes, the `dns-01` provider client that publishes
//! `_acme-challenge` TXT records, and the renewal sweep that keeps
//! managed certificates fresh. Issued certs are written to disk
//! atomically and installed into the resolver in place — no restart, no
//! dropped connections.

mod alpn;
pub mod challenge;
pub mod dns;
mod storage;

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use crate::acme::challenge::Http01Store;
use crate::acme::storage::Storage;
use crate::config::model as cfg;
use crate::tls::resolver::{CertResolver, OnDemandIssue, host_key};

/// RetryPolicy for ACME polling — ACME validation is usually <10s.
const ISSUE_POLL: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_millis(500))
    .backoff(2.0)
    .timeout(Duration::from_secs(120));
/// Renewal sweep cadence — cheap, checks stored `notAfter`s.
const SWEEP: Duration = Duration::from_secs(3600);
/// Failed issuance backoff before the next attempt.
const RETRY_BACKOFF: Duration = Duration::from_secs(300);
/// Don't reinstall a stored cert this close to expiry — issue instead.
const MIN_STORED_VALIDITY: Duration = Duration::from_secs(60);

/// The ACME manager for one runtime generation.
pub struct AcmeManager {
    cfg: cfg::AcmeConfig,
    resolver: Arc<CertResolver>,
    storage: Storage,
    /// Pending `http-01` tokens — the data plane serves these.
    pub http01: Arc<Http01Store>,
    challenge: ChallengeType,
    /// DNS provider client when `challenge` is `dns-01`.
    dns: Option<Arc<dns::Solver>>,
    /// Host lists of `tls = "auto"` sites — one cert per site.
    site_hosts: Vec<Vec<String>>,
    account: tokio::sync::OnceCell<Account>,
    /// Managed cert bookkeeping: last-known `notAfter` + retry gating.
    managed: Arc<dashmap::DashMap<String, Managed>>,
}

/// Bookkeeping for one managed hostname set.
#[derive(Debug, Default)]
struct Managed {
    not_after: Mutex<Option<SystemTime>>,
    next_attempt: Mutex<Option<Instant>>,
}

/// Build the manager when the config calls for ACME: a TLS listener plus
/// at least one `tls = "auto"` site or `on_demand` enabled. `None`
/// otherwise.
pub fn build(
    config: &cfg::Config,
    resolver: &Arc<CertResolver>,
) -> Result<Option<Arc<AcmeManager>>, String> {
    if !config.server.listen.iter().any(|l| l.tls) {
        return Ok(None);
    }
    let dns01 = matches!(config.acme.challenge, cfg::AcmeChallenge::Dns01);
    let site_hosts: Vec<Vec<String>> = config
        .site
        .iter()
        .filter(|s| matches!(s.tls, cfg::SiteTls::Mode(cfg::TlsMode::Auto)))
        .map(|s| {
            // wildcards need DNS-01 — without it they're excluded; the
            // cert covers the site's concrete hostnames (validation warns)
            s.hosts
                .iter()
                .filter(|h| dns01 || !h.starts_with("*."))
                .cloned()
                .collect::<Vec<_>>()
        })
        .filter(|h| !h.is_empty())
        .collect();
    if site_hosts.is_empty() && !config.acme.on_demand.enabled {
        return Ok(None);
    }

    let has_plain = config.server.listen.iter().any(|l| !l.tls);
    let (challenge, dns) = match config.acme.challenge {
        cfg::AcmeChallenge::Http01 => (ChallengeType::Http01, None),
        cfg::AcmeChallenge::TlsAlpn01 => (ChallengeType::TlsAlpn01, None),
        cfg::AcmeChallenge::Auto => (
            if has_plain {
                ChallengeType::Http01
            } else {
                ChallengeType::TlsAlpn01
            },
            None,
        ),
        cfg::AcmeChallenge::Dns01 => {
            let d = config.acme.dns.as_ref().ok_or(
                "acme.challenge = \"dns-01\" requires an [acme.dns] provider configuration",
            )?;
            (ChallengeType::Dns01, Some(Arc::new(dns::Solver::build(d)?)))
        }
    };

    let mgr = Arc::new(AcmeManager {
        cfg: config.acme.clone(),
        resolver: resolver.clone(),
        storage: Storage::new(config.acme.storage.clone()),
        http01: Arc::new(Http01Store::default()),
        challenge,
        dns,
        site_hosts,
        account: tokio::sync::OnceCell::new(),
        managed: Arc::new(dashmap::DashMap::new()),
    });

    if config.acme.on_demand.enabled {
        let rate = config.acme.on_demand.rate.or_else(|| {
            // No configured rate would make every allowed SNI a fresh CA
            // order — a self-serve abuse channel. Floor it conservatively.
            tracing::warn!("acme.on_demand has no `rate`; applying the safety floor of 5/hour");
            Some(crate::config::RateSpec {
                permits: 5,
                period: Duration::from_secs(3600),
            })
        });
        let od = Arc::new(OnDemand {
            mgr: Arc::downgrade(&mgr),
            allowed: config.acme.on_demand.allowed_hosts.clone(),
            rate,
            window: Mutex::new(VecDeque::new()),
            inflight: dashmap::DashMap::new(),
        });
        resolver.set_on_demand(od);
    }
    Ok(Some(mgr))
}

impl AcmeManager {
    /// Load-or-issue all site certs, then sweep renewals forever. Stops
    /// when `stop` fires (generation shutdown).
    pub async fn run(self: Arc<Self>, stop: CancellationToken) {
        if let Err(e) = self.account().await {
            tracing::error!(error = %e, "ACME account init failed; issuance disabled");
        }
        for hosts in &self.site_hosts {
            self.ensure(hosts).await;
        }
        let mut tick = tokio::time::interval(SWEEP);
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tick.tick() => {
                    for hosts in &self.site_hosts {
                        if self.renew_due(hosts) {
                            tracing::debug!(hosts = ?hosts, "acme renewal due");
                            self.ensure(hosts).await;
                        }
                    }
                }
            }
        }
    }

    /// Stored cert valid beyond `renew_before` → install and remember;
    /// otherwise issue a fresh one.
    async fn ensure(self: &Arc<Self>, hosts: &[String]) {
        let store_key = &hosts[0];
        // gate retries after failures
        {
            let entry = self.managed.entry(store_key.clone()).or_default();
            let next = entry.next_attempt.lock().unwrap_or_else(|e| e.into_inner());
            if next.is_some_and(|t| t > Instant::now()) {
                return;
            }
        }
        if let Some(stored) = self.storage.load_cert(store_key)
            && stored.not_after > SystemTime::now() + MIN_STORED_VALIDITY
            && let Ok(ck) = key_from_pems(&stored.cert_pem, &stored.key_pem)
        {
            self.resolver.insert(hosts, Arc::new(ck));
            self.set_not_after(store_key, stored.not_after);
            return;
        }
        match self.issue(hosts).await {
            Ok(ck) => {
                crate::observe::metrics::acme_issuance(true);
                self.resolver.insert(hosts, ck);
            }
            Err(e) => {
                crate::observe::metrics::acme_issuance(false);
                tracing::error!(hosts = ?hosts, error = %e, "ACME issuance failed");
                let entry = self.managed.entry(store_key.clone()).or_default();
                *entry.next_attempt.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now() + RETRY_BACKOFF);
            }
        }
    }

    /// True when the stored cert for `hosts[0]` should be renewed: the
    /// lead time is `renew_before` capped at a third of the cert's total
    /// lifetime so short-lived certs aren't "due" the instant they're
    /// issued (jittered per host so fleets don't stampede).
    fn renew_due(&self, hosts: &[String]) -> bool {
        let Some(stored) = self.storage.load_cert(&hosts[0]) else {
            return true; // nothing persisted — ensure() restores it
        };
        let lifetime = stored
            .not_after
            .duration_since(stored.not_before)
            .unwrap_or_default();
        let threshold = self.cfg.renew_before.min(lifetime / 3);
        let jitter = Duration::from_secs(hosts[0].len() as u64 % 3600);
        stored.not_after < SystemTime::now() + threshold.saturating_sub(jitter)
    }

    fn set_not_after(&self, key: &str, t: SystemTime) {
        let entry = self.managed.entry(key.to_string()).or_default();
        *entry.not_after.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
    }

    /// AccountBuilder for our HTTP client + trust roots (consumable).
    fn builder(&self) -> Result<instant_acme::AccountBuilder, String> {
        match &self.cfg.ca_roots {
            Some(p) => {
                Account::builder_with_root(p).map_err(|e| format!("acme ca_roots {p:?}: {e}"))
            }
            None => Account::builder().map_err(|e| e.to_string()),
        }
    }

    /// The ACME account: restored from storage when possible, otherwise
    /// created and persisted.
    async fn account(&self) -> Result<&Account, String> {
        self.account
            .get_or_try_init(|| async {
                if let Some(raw) = self.storage.load_account()
                    && let Ok(creds) = serde_json::from_slice::<AccountCredentials>(&raw)
                    && let Ok(acc) = self.builder()?.from_credentials(creds).await
                {
                    return Ok(acc);
                }
                let email = self.cfg.email.as_deref().unwrap_or("admin@localhost");
                let contact = format!("mailto:{email}");
                let new = NewAccount {
                    contact: &[contact.as_str()],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                };
                let eab = self
                    .cfg
                    .eab
                    .as_ref()
                    .map(|e| {
                        let key = B64_URL
                            .decode(e.key.trim())
                            .or_else(|_| B64_STD.decode(e.key.trim()))
                            .map_err(|err| format!("acme.eab.key base64: {err}"))?;
                        Ok::<_, String>(ExternalAccountKey::new(e.key_id.clone(), &key))
                    })
                    .transpose()?;
                let (account, creds) = self
                    .builder()?
                    .create(&new, self.cfg.directory.clone(), eab.as_ref())
                    .await
                    .map_err(|e| format!("create ACME account: {e}"))?;
                let raw = serde_json::to_vec(&creds).map_err(|e| e.to_string())?;
                self.storage.save_account(&raw)?;
                Ok(account)
            })
            .await
    }

    /// Issue a certificate covering `hosts` — full order → authorize →
    /// finalize → poll → persist → return installable key.
    async fn issue(self: &Arc<Self>, hosts: &[String]) -> Result<Arc<CertifiedKey>, String> {
        let account = self.account().await.map_err(|e| format!("account: {e}"))?;
        let ids: Vec<Identifier> = hosts.iter().map(|h| Identifier::Dns(h.clone())).collect();
        let mut order = account
            .new_order(&NewOrder::new(&ids))
            .await
            .map_err(|e| format!("new order: {e}"))?;

        // Provision state the retract pass below must undo — everything
        // lives in one result block so retraction runs on every path,
        // including mid-provision failures (an orphaned public TXT
        // record never cleans itself up).
        let mut tokens = Vec::new();
        let mut alpn_hosts = Vec::new();
        // (record name, expected TXT value) + provider handles to retract
        let mut dns_want: Vec<(String, String)> = Vec::new();
        let mut dns_records: Vec<dns::Record> = Vec::new();
        let result = async {
            // provision every authorization's challenge, then mark ready
            let mut auths = order.authorizations();
            while let Some(res) = auths.next().await {
                let mut authz = res.map_err(|e| format!("authorization: {e}"))?;
                // RFC 8555 lets the CA attach an already-valid
                // authorization to a new order — nothing to provision
                // or mark ready.
                if authz.status == instant_acme::AuthorizationStatus::Valid {
                    continue;
                }
                match &self.challenge {
                    ChallengeType::Http01 => {
                        let mut ch = authz
                            .challenge(ChallengeType::Http01)
                            .ok_or("CA offered no http-01 challenge")?;
                        self.http01
                            .insert(&ch.token, ch.key_authorization().as_str().to_string());
                        tokens.push(ch.token.clone());
                        ch.set_ready()
                            .await
                            .map_err(|e| format!("challenge ready: {e}"))?;
                    }
                    ChallengeType::TlsAlpn01 => {
                        let mut ch = authz
                            .challenge(ChallengeType::TlsAlpn01)
                            .ok_or("CA offered no tls-alpn-01 challenge")?;
                        // AuthorizedIdentifier renders wildcards as "*.dom"
                        let ident = ch.identifier().to_string();
                        let host = ident.strip_prefix("*.").unwrap_or(&ident);
                        let cert =
                            alpn::challenge_cert(host, ch.key_authorization().digest().as_ref())?;
                        self.resolver.alpn.insert(&host_key(host), cert);
                        alpn_hosts.push(host_key(host));
                        ch.set_ready()
                            .await
                            .map_err(|e| format!("challenge ready: {e}"))?;
                    }
                    ChallengeType::Dns01 => {
                        let (name, value) = {
                            let ch = authz
                                .challenge(ChallengeType::Dns01)
                                .ok_or("CA offered no dns-01 challenge")?;
                            // AuthorizedIdentifier renders wildcards as
                            // "*.dom"; the record lives at the base name.
                            let ident = ch.identifier().to_string();
                            let host = ident.strip_prefix("*.").unwrap_or(&ident);
                            (
                                format!("_acme-challenge.{host}"),
                                ch.key_authorization().dns_value(),
                            )
                        };
                        let solver = self.dns.as_ref().ok_or("dns-01 without provider")?;
                        let record = solver
                            .present(&name, &value)
                            .await
                            .map_err(|e| format!("publish {name}: {e}"))?;
                        dns_records.push(record);
                        dns_want.push((name, value));
                    }
                    other => return Err(format!("unsupported challenge {other:?}")),
                }
            }

            // dns-01: all records published — wait for public
            // propagation, then mark every challenge ready in a second
            // pass (handles can't outlive the authorizations stream
            // they borrow).
            if !dns_want.is_empty() {
                let solver = self.dns.as_ref().ok_or("dns-01 without provider")?;
                solver.await_propagation(&dns_want).await;
                let mut auths = order.authorizations();
                while let Some(res) = auths.next().await {
                    let mut authz = res.map_err(|e| format!("authorization: {e}"))?;
                    if authz.status == instant_acme::AuthorizationStatus::Valid {
                        continue;
                    }
                    authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or("CA offered no dns-01 challenge")?
                        .set_ready()
                        .await
                        .map_err(|e| format!("challenge ready: {e}"))?;
                }
            }

            let status = order
                .poll_ready(&ISSUE_POLL)
                .await
                .map_err(|e| format!("order poll: {e}"))?;
            if !matches!(status, OrderStatus::Ready) {
                return Err(format!("order not ready: {status:?}"));
            }
            let key_pem = order
                .finalize()
                .await
                .map_err(|e| format!("finalize: {e}"))?;
            let chain = order
                .poll_certificate(&ISSUE_POLL)
                .await
                .map_err(|e| format!("certificate poll: {e}"))?;
            Ok((key_pem, chain))
        }
        .await;

        // challenges are single-use — always retract
        for t in &tokens {
            self.http01.remove(t);
        }
        for h in &alpn_hosts {
            self.resolver.alpn.remove(h);
        }
        if let Some(solver) = &self.dns {
            for r in &dns_records {
                solver.retract(r).await;
            }
        }

        let (key_pem, chain) = result?;
        let ck = Arc::new(key_from_pems(&chain, &key_pem)?);
        self.storage.save_cert(&hosts[0], &chain, &key_pem)?;
        if let Some(na) = storage_not_after(&chain) {
            self.set_not_after(&hosts[0], na);
        }
        tracing::info!(hosts = ?hosts, "ACME certificate issued");
        Ok(ck)
    }
}

/// Parse PEM chain + key into a rustls [`CertifiedKey`].
fn key_from_pems(chain_pem: &str, key_pem: &str) -> Result<CertifiedKey, String> {
    let mut rd = std::io::BufReader::new(chain_pem.as_bytes());
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_reader_iter(&mut rd)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("cert PEM: {e}"))?;
    if certs.is_empty() {
        return Err("cert PEM contains no certificates".into());
    }
    let mut rd = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls::pki_types::PrivateKeyDer::from_pem_reader(&mut rd)
        .map_err(|e| format!("key PEM: {e}"))?;
    crate::tls::manual::build_key(certs, key)
}

/// Leaf `notAfter` of a PEM chain — re-parse via storage's helper.
fn storage_not_after(chain_pem: &str) -> Option<SystemTime> {
    let mut rd = std::io::BufReader::new(chain_pem.as_bytes());
    let der = rustls::pki_types::CertificateDer::pem_reader_iter(&mut rd)
        .next()?
        .ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let ts = cert.validity().not_after.timestamp();
    (ts > 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(ts as u64))
}

/// On-demand issuance: allowlist + rate gate + deduped synchronous
/// issuance invoked from `ResolvesServerCert::resolve` on handshake.
#[derive(Debug)]
pub struct OnDemand {
    mgr: Weak<AcmeManager>,
    /// Exact hosts or `*.suffix` patterns.
    allowed: Vec<String>,
    rate: Option<crate::config::RateSpec>,
    /// Sliding-window issuance counter for the rate gate.
    window: Mutex<VecDeque<Instant>>,
    /// host → in-flight or completed issuance wait point.
    inflight: dashmap::DashMap<String, Arc<IssueWait>>,
}

#[derive(Debug, Default)]
struct IssueWait {
    result: Mutex<Option<Result<(), ()>>>,
    done: Condvar,
}

impl IssueWait {
    fn complete(&self, ok: bool) {
        *self.result.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(if ok { Ok(()) } else { Err(()) });
        self.done.notify_all();
    }

    /// Non-blocking peek: `Some(ok)` once issuance resolved, `None`
    /// while still in flight. The resolver path must never block.
    fn peek(&self) -> Option<bool> {
        self.result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|r| r.is_ok())
    }

    #[cfg(test)]
    fn wait(&self, timeout: Duration) -> Result<(), ()> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(r) = &*guard {
                return *r;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(());
            }
            let (g, res) = self
                .done
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|e| e.into_inner());
            guard = g;
            if res.timed_out() {
                return Err(());
            }
        }
    }
}

impl OnDemand {
    /// Hostname allowlist: exact or `*.suffix` (one label).
    fn allowed(&self, host: &str) -> bool {
        self.allowed.iter().any(|p| {
            if let Some(suffix) = p.strip_prefix("*.") {
                host.split_once('.').is_some_and(|(_, rest)| rest == suffix)
            } else {
                host == p
            }
        })
    }

    /// Sliding-window rate gate.
    fn rate_ok(&self) -> bool {
        let Some(rate) = self.rate else { return true };
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while w.front().is_some_and(|t| now - *t > rate.period) {
            w.pop_front();
        }
        if w.len() as u64 >= rate.permits {
            return false;
        }
        w.push_back(now);
        true
    }
}

impl OnDemandIssue for OnDemand {
    /// Never blocks: `resolve` runs on a tokio worker inside the TLS
    /// handshake — parking it on a `Condvar` for the issuance duration
    /// lets N ≥ worker-count handshakes deadlock the whole runtime
    /// (the spawned issuance task and the http-01 handler both need a
    /// worker). Instead, kick off background issuance and decline; the
    /// client's next handshake resolves the cert once it lands in the
    /// resolver.
    fn issue(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host_key(host);
        if !self.allowed(&host) {
            tracing::warn!(host, "on-demand TLS: host not in allowed_hosts");
            return None;
        }
        if !self.rate_ok() {
            tracing::warn!(host, "on-demand TLS: rate limit reached");
            return None;
        }
        use dashmap::mapref::entry::Entry;
        let wait = match self.inflight.entry(host.clone()) {
            Entry::Vacant(v) => {
                let w = Arc::new(IssueWait::default());
                if let Some(mgr) = self.mgr.upgrade() {
                    let w2 = w.clone();
                    let hosts = vec![host.clone()];
                    tokio::spawn(async move {
                        let r = mgr.issue(&hosts).await;
                        if let Ok(ck) = r {
                            mgr.resolver.insert(&hosts, ck);
                            w2.complete(true);
                        } else {
                            w2.complete(false);
                        }
                    });
                } else {
                    w.complete(false);
                }
                v.insert(w.clone());
                w
            }
            Entry::Occupied(e) => e.get().clone(),
        };
        // A result already landed? Serve it (or free a failed slot so
        // the next handshake retries). Still-in-flight: decline.
        match wait.peek() {
            Some(true) => {
                self.inflight.remove_if(&host, |_, w| Arc::ptr_eq(w, &wait));
                self.mgr.upgrade()?.resolver.lookup(&host)
            }
            Some(false) => {
                self.inflight.remove_if(&host, |_, w| Arc::ptr_eq(w, &wait));
                None
            }
            None => None,
        }
    }
}

impl fmt::Debug for AcmeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeManager")
            .field("directory", &self.cfg.directory)
            .field("challenge", &self.challenge)
            .field("site_hosts", &self.site_hosts)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_demand_allowlist() {
        let od = OnDemand {
            mgr: Weak::new(),
            allowed: vec!["exact.example".into(), "*.wild.example".into()],
            rate: None,
            window: Mutex::new(VecDeque::new()),
            inflight: dashmap::DashMap::new(),
        };
        assert!(od.allowed("exact.example"));
        assert!(od.allowed("a.wild.example"));
        assert!(!od.allowed("wild.example"));
        assert!(!od.allowed("a.b.wild.example"));
        assert!(!od.allowed("other.example"));
    }

    #[test]
    fn on_demand_rate_gate() {
        let od = OnDemand {
            mgr: Weak::new(),
            allowed: vec![],
            rate: Some(crate::config::RateSpec::parse("2/s").unwrap()),
            window: Mutex::new(VecDeque::new()),
            inflight: dashmap::DashMap::new(),
        };
        assert!(od.rate_ok());
        assert!(od.rate_ok());
        assert!(!od.rate_ok());
    }

    #[tokio::test]
    async fn issue_wait_roundtrip() {
        let w = IssueWait::default();
        assert!(w.wait(Duration::from_millis(10)).is_err());
        let w = Arc::new(IssueWait::default());
        let w2 = w.clone();
        std::thread::spawn(move || w2.complete(true));
        assert!(w.wait(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn key_from_pems_roundtrip() {
        let (cert, key) = crate::tls::selfsigned::generate_pems(&["k.example".into()]);
        key_from_pems(&cert, &key).unwrap();
    }
}
