//! DNS-01 solvers: publish `_acme-challenge` TXT records through a DNS
//! provider API, wait for public propagation, then retract them.
//!
//! [`Solver`] is built from `[acme.dns]` once per runtime generation.
//! `present`/`retract` wrap the provider API; `await_propagation` polls
//! public DNS (system resolver, or `resolver` when configured) until
//! every expected value is visible — the CA sees the same records we
//! publish, so validating before propagation is the common failure.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use crate::config::model as cfg;

/// Default Cloudflare API base.
const CF_API: &str = "https://api.cloudflare.com/client/v4";
/// Per-request timeout for provider API calls.
const API_TIMEOUT: Duration = Duration::from_secs(15);
/// Poll cadence while waiting for TXT propagation.
const PROPAGATION_POLL: Duration = Duration::from_secs(2);

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What `Provider::present` created — enough to retract it later.
#[derive(Debug)]
pub struct Record {
    /// Provider-specific container the record lives in (Cloudflare zone).
    zone: String,
    /// Provider-assigned record id.
    id: String,
}

/// DNS provider backend: create + delete TXT records. One impl per
/// provider; adding providers is a matter of a new `Provider` and a
/// variant in [`cfg::AcmeDns`].
trait Provider: fmt::Debug + Send + Sync {
    /// Create TXT `fqdn = value`; returns the retract handle.
    fn present<'a>(&'a self, fqdn: &'a str, value: &'a str) -> BoxFut<'a, Result<Record, String>>;
    /// Delete a record `present` returned.
    fn retract<'a>(&'a self, record: &'a Record) -> BoxFut<'a, Result<(), String>>;
}

/// The configured dns-01 solver: provider client plus the propagation
/// check gating `set_ready`.
#[derive(Debug)]
pub struct Solver {
    provider: Box<dyn Provider>,
    /// Propagation-check nameserver; `None` → the system resolver.
    resolver: Option<SocketAddr>,
    timeout: Duration,
}

impl Solver {
    /// Build the solver for `[acme.dns]`.
    pub fn build(dns: &cfg::AcmeDns) -> Result<Self, String> {
        match dns {
            cfg::AcmeDns::Cloudflare(c) => Self::cloudflare(c),
        }
    }

    fn cloudflare(c: &cfg::CloudflareDns) -> Result<Self, String> {
        let token = c.api_token.trim();
        if token.is_empty() {
            return Err("acme.dns.cloudflare.api_token is empty".into());
        }
        Ok(Self {
            provider: Box::new(Cloudflare {
                client: https_client(),
                base: c
                    .api_base
                    .clone()
                    .unwrap_or_else(|| CF_API.to_string())
                    .trim_end_matches('/')
                    .to_string(),
                token: token.to_string(),
                zone: c.zone_id.clone(),
                zones: DashMap::new(),
            }),
            resolver: c
                .resolver
                .as_deref()
                .map(|s| {
                    parse_nameserver(s).map_err(|e| format!("acme.dns.cloudflare.resolver: {e}"))
                })
                .transpose()?,
            timeout: c.propagation_timeout,
        })
    }

    /// Publish one TXT value at `fqdn`.
    pub async fn present(&self, fqdn: &str, value: &str) -> Result<Record, String> {
        self.provider.present(fqdn, value).await
    }

    /// Retract a record; best-effort — orphaned TXTs are harmless and a
    /// hard failure here would mask the issuance result.
    pub async fn retract(&self, record: &Record) {
        if let Err(e) = self.provider.retract(record).await {
            tracing::warn!(error = %e, "dns-01: failed to delete TXT record");
        }
    }

    /// Wait until every `_acme-challenge` name serves all its expected
    /// values, bounded by `propagation_timeout`. Timeout only logs —
    /// the CA polls authorizations itself and may see the records even
    /// when our resolver can't yet.
    pub async fn await_propagation(&self, want: &[(String, String)]) {
        if self.timeout.is_zero() {
            return;
        }
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.all_visible(want).await {
                Ok(true) => {
                    tracing::debug!("dns-01: TXT records visible in DNS");
                    return;
                }
                Ok(false) => {}
                Err(e) => tracing::debug!(error = %e, "dns-01: propagation check failed"),
            }
            let now = Instant::now();
            if now >= deadline {
                tracing::warn!(
                    timeout = ?self.timeout,
                    "dns-01: TXT records not visible in DNS yet; validating anyway"
                );
                return;
            }
            tokio::time::sleep(PROPAGATION_POLL.min(deadline - now)).await;
        }
    }

    /// One propagation round: `true` when every name serves all values.
    async fn all_visible(&self, want: &[(String, String)]) -> Result<bool, String> {
        // A fresh resolver per round — a cached negative answer would
        // otherwise poison the whole wait.
        let resolver = self.resolver()?;
        for (name, values) in group_by_name(want) {
            let Ok(lookup) = resolver.txt_lookup(name).await else {
                return Ok(false);
            };
            let have: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(t) => Some(t),
                    _ => None,
                })
                .flat_map(|t| t.txt_data.iter())
                .map(|s| String::from_utf8_lossy(s.as_ref()).into_owned())
                .collect();
            if !values.iter().all(|v| have.iter().any(|h| h == v)) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn resolver(&self) -> Result<TokioResolver, String> {
        match self.resolver {
            None => TokioResolver::builder_tokio()
                .and_then(|b| b.build())
                .map_err(|e| format!("system resolver: {e}")),
            Some(addr) => {
                let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
                tcp.port = addr.port();
                let ns = NameServerConfig::new(addr.ip(), true, vec![udp, tcp]);
                let config = ResolverConfig::from_parts(None, vec![], vec![ns]);
                Resolver::builder_with_config(config, TokioRuntimeProvider::new())
                    .build()
                    .map_err(|e| format!("resolver {addr}: {e}"))
            }
        }
    }
}

/// Group expected values per record name — an order covering
/// `example.com` plus `*.example.com` yields two authorizations whose
/// digests both live at `_acme-challenge.example.com`.
fn group_by_name(want: &[(String, String)]) -> BTreeMap<&str, Vec<&str>> {
    let mut m: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, value) in want {
        m.entry(name.as_str()).or_default().push(value.as_str());
    }
    m
}

/// `ip` or `ip:port` → nameserver address (port defaults to 53).
fn parse_nameserver(raw: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }
    raw.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|_| format!("{raw:?} is not `ip` or `ip:port`"))
}

/// Zone candidates for an `_acme-challenge.<host>` name, longest first,
/// stopping before a bare TLD.
fn zone_candidates(record_name: &str) -> Vec<String> {
    let host = record_name
        .strip_prefix("_acme-challenge.")
        .unwrap_or(record_name);
    let host = host.strip_prefix("*.").unwrap_or(host);
    let mut labels: Vec<&str> = host.split('.').collect();
    let mut out = Vec::new();
    while labels.len() >= 2 {
        out.push(labels.join("."));
        labels.remove(0);
    }
    out
}

/// HTTPS client for provider APIs (webpki roots). `https_or_http` so
/// tests can point `api_base` at a plain-HTTP mock — nothing else can
/// produce an `http://` base.
fn https_client() -> Client<HttpsConnector<HttpConnector>, Full<Bytes>> {
    let conn = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(conn)
}

/// Cloudflare API v4 — token auth, zone discovery by name, TXT create
/// and delete.
#[derive(Debug)]
struct Cloudflare {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    base: String,
    token: String,
    /// Pinned zone id — skips discovery when set.
    zone: Option<String>,
    /// zone name → id; discovery is cached for the generation.
    zones: DashMap<String, String>,
}

/// Cloudflare API v4 response envelope.
#[derive(Deserialize)]
struct CfEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default)]
    result: serde_json::Value,
}

#[derive(Deserialize)]
struct CfError {
    message: Option<String>,
}

impl Cloudflare {
    /// One API call; returns the `result` payload, or an error built
    /// from the envelope's `errors` list.
    async fn call(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let payload = match &body {
            Some(v) => serde_json::to_vec(v).map_err(|e| e.to_string())?,
            None => Vec::new(),
        };
        let req = Request::builder()
            .method(&method)
            .uri(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| format!("{method} {path}: {e}"))?;
        let rsp = tokio::time::timeout(API_TIMEOUT, self.client.request(req))
            .await
            .map_err(|_| format!("{method} {path}: timed out"))?
            .map_err(|e| format!("{method} {path}: {e}"))?;
        let status = rsp.status();
        let raw = rsp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("{method} {path}: {e}"))?
            .to_bytes();
        let env: CfEnvelope = serde_json::from_slice(&raw)
            .map_err(|e| format!("{method} {path}: bad response ({status}): {e}"))?;
        if !env.success {
            let details = env
                .errors
                .iter()
                .filter_map(|e| e.message.as_deref())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "{method} {path}: Cloudflare error ({status}): {details}"
            ));
        }
        Ok(env.result)
    }

    /// Zone id covering `fqdn` — pinned config, else discovery by
    /// walking the name's labels up via `GET /zones?name=`.
    async fn zone_id(&self, fqdn: &str) -> Result<String, String> {
        if let Some(z) = &self.zone {
            return Ok(z.clone());
        }
        for cand in zone_candidates(fqdn) {
            if let Some(id) = self.zones.get(&cand) {
                return Ok(id.clone());
            }
            let q = form_urlencoded::Serializer::new(String::new())
                .append_pair("name", &cand)
                .finish();
            let out = self
                .call(hyper::Method::GET, &format!("/zones?{q}"), None)
                .await?;
            if let Some(id) = out
                .as_array()
                .and_then(|a| a.first())
                .and_then(|z| z.get("id"))
                .and_then(|v| v.as_str())
            {
                self.zones.insert(cand, id.to_string());
                return Ok(id.to_string());
            }
        }
        Err(format!("no Cloudflare zone contains {fqdn}"))
    }
}

impl Provider for Cloudflare {
    fn present<'a>(&'a self, fqdn: &'a str, value: &'a str) -> BoxFut<'a, Result<Record, String>> {
        Box::pin(async move {
            let zone = self.zone_id(fqdn).await?;
            let out = self
                .call(
                    hyper::Method::POST,
                    &format!("/zones/{zone}/dns_records"),
                    Some(serde_json::json!({
                        "type": "TXT",
                        "name": fqdn,
                        "content": value,
                        "ttl": 60,
                        "comment": "verd ACME dns-01",
                    })),
                )
                .await?;
            let id = out
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("create dns_record: response carries no id")?;
            tracing::debug!(zone, name = fqdn, id, "dns-01: TXT record created");
            Ok(Record {
                zone,
                id: id.to_string(),
            })
        })
    }

    fn retract<'a>(&'a self, record: &'a Record) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            self.call(
                hyper::Method::DELETE,
                &format!("/zones/{}/dns_records/{}", record.zone, record.id),
                None,
            )
            .await?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_candidates_walk_up() {
        assert_eq!(
            zone_candidates("_acme-challenge.foo.bar.example.com"),
            vec!["foo.bar.example.com", "bar.example.com", "example.com"]
        );
        assert_eq!(
            zone_candidates("_acme-challenge.example.com"),
            vec!["example.com"]
        );
        assert!(zone_candidates("_acme-challenge.localhost").is_empty());
        assert_eq!(
            zone_candidates("_acme-challenge.*.example.com"),
            vec!["example.com"]
        );
    }

    #[test]
    fn nameserver_parse() {
        assert_eq!(
            parse_nameserver("1.1.1.1").unwrap(),
            SocketAddr::from(([1, 1, 1, 1], 53))
        );
        assert_eq!(
            parse_nameserver("1.1.1.1:5353").unwrap(),
            SocketAddr::from(([1, 1, 1, 1], 5353))
        );
        assert_eq!(
            parse_nameserver("[::1]:5353").unwrap(),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 5353))
        );
        assert!(parse_nameserver("not-an-ip").is_err());
    }

    #[test]
    fn group_by_name_merges() {
        let want = vec![
            ("_acme-challenge.example.com".to_string(), "aaa".to_string()),
            ("_acme-challenge.example.com".to_string(), "bbb".to_string()),
            ("_acme-challenge.x.com".to_string(), "ccc".to_string()),
        ];
        let g = group_by_name(&want);
        assert_eq!(g["_acme-challenge.example.com"], vec!["aaa", "bbb"]);
        assert_eq!(g["_acme-challenge.x.com"], vec!["ccc"]);
    }
}
