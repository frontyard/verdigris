//! Member selection for the configured load-balancing algorithm and the
//! retry budget shared across the cluster.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use ahash::AHasher;

use crate::config::model as cfg;
use crate::proxy::cluster::{Cluster, Member, RetryGuard};

/// Choose the next healthy member for a request. `tried` excludes members
/// already attempted for this request so retries land on a different
/// upstream where possible; if every healthy member was tried, the
/// exclusion is ignored (better a retried member than no member).
pub fn pick(cluster: &Cluster, client_ip: IpAddr, tried: &[usize]) -> Option<Arc<Member>> {
    let now = std::time::Instant::now();
    let mut healthy: Vec<&Arc<Member>> = cluster
        .members
        .iter()
        .filter(|m| m.healthy_at(now) && !tried.contains(&m.id))
        .collect();
    if healthy.is_empty() {
        healthy = cluster
            .members
            .iter()
            .filter(|m| m.healthy_at(now))
            .collect();
    }
    if healthy.is_empty() {
        return None;
    }
    let m = match cluster.lb {
        cfg::LoadBalancing::RoundRobin => {
            let i = cluster.rr.fetch_add(1, Ordering::Relaxed) % healthy.len();
            healthy[i]
        }
        cfg::LoadBalancing::LeastConn => healthy
            .iter()
            .min_by_key(|m| m.inflight.load(Ordering::Relaxed))
            .unwrap(),
        cfg::LoadBalancing::IpHash => {
            let mut h = AHasher::default();
            std::hash::Hash::hash(&client_ip, &mut h);
            let i = (std::hash::Hasher::finish(&h) as usize) % healthy.len();
            healthy[i]
        }
    };
    Some(m.clone())
}

/// Admit a retry if the cluster's in-flight retries stay within
/// `budget_fraction` of total requests seen. Returns a guard that frees
/// the slot when the retry attempt resolves.
pub fn take_retry(cluster: &Arc<Cluster>, budget_fraction: f64) -> Option<RetryGuard> {
    let n = cluster.retries_inflight.fetch_add(1, Ordering::Relaxed) + 1;
    let requests = cluster.requests.load(Ordering::Relaxed) as f64;
    let allowed = (requests * budget_fraction).floor().max(1.0);
    if n as f64 > allowed {
        cluster.retries_inflight.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    Some(RetryGuard {
        cluster: cluster.clone(),
    })
}

/// Whether the method is idempotent (RFC 9110 §9.2.2) — only those may be
/// retried on connection failure. TRACE is technically safe but excluded:
/// retrying an echo diagnostic just re-discloses the request headers.
pub fn idempotent(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::PUT
            | http::Method::DELETE
            | http::Method::OPTIONS
    )
}

/// Whether a `send_request` error looks like a connection-level failure
/// (safe to retry for idempotent methods) rather than an upstream response
/// error.
pub fn conn_failure(err: &hyper::Error) -> bool {
    err.is_closed() || err.is_canceled() || err.is_incomplete_message()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn cluster(n: usize, lb: cfg::LoadBalancing) -> Arc<Cluster> {
        let c = cfg::UpstreamConfig {
            servers: (0..n).map(|i| format!("http://10.0.0.{i}:80")).collect(),
            lb,
            ..Default::default()
        };
        Arc::new(Cluster::build("t", &c).unwrap())
    }

    #[test]
    fn round_robin_cycles() {
        let c = cluster(3, cfg::LoadBalancing::RoundRobin);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let picks: Vec<usize> = (0..6).map(|_| pick(&c, ip, &[]).unwrap().id).collect();
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn least_conn_picks_least_busy() {
        let c = cluster(3, cfg::LoadBalancing::LeastConn);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        c.members[0].inflight.store(5, Ordering::Relaxed);
        c.members[1].inflight.store(2, Ordering::Relaxed);
        c.members[2].inflight.store(1, Ordering::Relaxed);
        let m = pick(&c, ip, &[]).unwrap();
        assert_eq!(m.id, 2);
        c.members[2].inflight.store(9, Ordering::Relaxed);
        let m = pick(&c, ip, &[]).unwrap();
        assert_eq!(m.id, 1);
    }

    #[test]
    fn ip_hash_is_sticky() {
        let c = cluster(4, cfg::LoadBalancing::IpHash);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let first = pick(&c, ip, &[]).unwrap().id;
        for _ in 0..8 {
            assert_eq!(pick(&c, ip, &[]).unwrap().id, first);
        }
    }

    #[test]
    fn sick_members_skipped_and_retries_avoid_tried() {
        let c = cluster(3, cfg::LoadBalancing::RoundRobin);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        c.members[0].mark_sick(std::time::Duration::from_secs(60));
        let picks: Vec<usize> = (0..4).map(|_| pick(&c, ip, &[]).unwrap().id).collect();
        assert!(!picks.contains(&0));

        // member 2 is the only healthy, untried member left
        let m = pick(&c, ip, &[0, 1]).unwrap();
        assert_eq!(m.id, 2);

        // when all healthy members were tried, `tried` is ignored rather
        // than starving the request
        let m = pick(&c, ip, &[1, 2]).unwrap();
        assert!(m.id == 1 || m.id == 2);

        // all sick → no pick
        for m in &c.members {
            m.mark_sick(std::time::Duration::from_secs(60));
        }
        assert!(pick(&c, ip, &[]).is_none());
    }

    #[test]
    fn retry_budget_caps_inflight() {
        let c = cluster(1, cfg::LoadBalancing::RoundRobin);
        c.requests.store(10, Ordering::Relaxed);
        // budget_fraction 0.2 → at most 2 in-flight retries
        let g1 = take_retry(&c, 0.2).expect("first retry allowed");
        let g2 = take_retry(&c, 0.2).expect("second retry allowed");
        assert!(take_retry(&c, 0.2).is_none(), "third exceeds budget");
        drop(g1);
        drop(g2);
        assert!(take_retry(&c, 0.2).is_some());
    }
}
