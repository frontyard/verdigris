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
/// `backup = true` members are considered only when no primary is
/// healthy at all.
pub fn pick(cluster: &Cluster, client_ip: IpAddr, tried: &[usize]) -> Option<Arc<Member>> {
    let now = std::time::Instant::now();
    let candidates = |backup: bool, respect_tried: bool| -> Vec<&Arc<Member>> {
        cluster
            .members
            .iter()
            .filter(|m| {
                m.backup == backup
                    && m.healthy_at(now)
                    && (!respect_tried || !tried.contains(&m.id))
            })
            .collect()
    };
    let mut healthy = candidates(false, true);
    if healthy.is_empty() {
        healthy = candidates(false, false);
    }
    if healthy.is_empty() {
        healthy = candidates(true, true);
    }
    if healthy.is_empty() {
        healthy = candidates(true, false);
    }
    if healthy.is_empty() {
        return None;
    }
    let m = match cluster.lb {
        cfg::LoadBalancing::RoundRobin => smooth_wrr(&healthy),
        cfg::LoadBalancing::LeastConn => healthy
            .iter()
            .min_by(|a, b| {
                // weight-normalized: inflight/weight compared without floats
                let lhs = a.inflight.load(Ordering::Relaxed) as u128 * b.weight as u128;
                let rhs = b.inflight.load(Ordering::Relaxed) as u128 * a.weight as u128;
                lhs.cmp(&rhs)
            })
            .unwrap(),
        cfg::LoadBalancing::IpHash => {
            let mut h = AHasher::default();
            std::hash::Hash::hash(&client_ip, &mut h);
            let total: u64 = healthy.iter().map(|m| m.weight as u64).sum();
            let mut point = std::hash::Hasher::finish(&h) % total;
            healthy
                .iter()
                .find(|m| {
                    let w = m.weight as u64;
                    if point < w {
                        true
                    } else {
                        point -= w;
                        false
                    }
                })
                .unwrap()
        }
    };
    Some(m.clone())
}

/// Smooth weighted round-robin: every pick adds each member's weight to
/// its running counter, serves the largest, then subtracts the total.
/// Produces the weight ratio without the long runs a plain modulo gives.
fn smooth_wrr<'a>(members: &[&'a Arc<Member>]) -> &'a Arc<Member> {
    let mut total = 0i64;
    let mut best: Option<&Arc<Member>> = None;
    let mut best_ew = i64::MIN;
    for m in members {
        total += m.weight as i64;
        let ew = m.ew.fetch_add(m.weight as i64, Ordering::Relaxed) + m.weight as i64;
        if ew > best_ew {
            best_ew = ew;
            best = Some(m);
        }
    }
    let b = best.unwrap();
    b.ew.fetch_sub(total, Ordering::Relaxed);
    b
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
            servers: (0..n)
                .map(|i| format!("http://10.0.0.{i}:80").into())
                .collect(),
            lb,
            ..Default::default()
        };
        Arc::new(Cluster::build("t", &c).unwrap())
    }

    fn cluster_of(servers: &[cfg::UpstreamServer], lb: cfg::LoadBalancing) -> Arc<Cluster> {
        let c = cfg::UpstreamConfig {
            servers: servers.to_vec(),
            lb,
            ..Default::default()
        };
        Arc::new(Cluster::build("t", &c).unwrap())
    }

    fn entry(url: &str, weight: u32, backup: bool) -> cfg::UpstreamServer {
        cfg::UpstreamServer {
            url: url.into(),
            weight,
            backup,
        }
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
    fn weighted_round_robin_hits_ratio() {
        let c = cluster_of(
            &[
                entry("http://a:80", 3, false),
                entry("http://b:80", 1, false),
            ],
            cfg::LoadBalancing::RoundRobin,
        );
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let picks: Vec<usize> = (0..8).map(|_| pick(&c, ip, &[]).unwrap().id).collect();
        let a = picks.iter().filter(|&&i| i == 0).count();
        assert_eq!((a, picks.len() - a), (6, 2), "3:1 over 8 picks: {picks:?}");
    }

    #[test]
    fn weighted_least_conn_normalizes_by_weight() {
        let c = cluster_of(
            &[
                entry("http://a:80", 4, false),
                entry("http://b:80", 1, false),
            ],
            cfg::LoadBalancing::LeastConn,
        );
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // 4/4=1 vs 0/1=0 → b wins despite a's heavier weight
        c.members[0].inflight.store(4, Ordering::Relaxed);
        assert_eq!(pick(&c, ip, &[]).unwrap().id, 1);
        // 4/4=1 vs 2/1=2 → a wins: the big member absorbs more load
        c.members[1].inflight.store(2, Ordering::Relaxed);
        assert_eq!(pick(&c, ip, &[]).unwrap().id, 0);
    }

    #[test]
    fn ip_hash_weights_distribution_and_stays_sticky() {
        let c = cluster_of(
            &[
                entry("http://a:80", 3, false),
                entry("http://b:80", 1, false),
            ],
            cfg::LoadBalancing::IpHash,
        );
        let mut a = 0usize;
        for i in 0..200u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
            let first = pick(&c, ip, &[]).unwrap().id;
            // sticky: same client always lands on the same member
            for _ in 0..4 {
                assert_eq!(pick(&c, ip, &[]).unwrap().id, first);
            }
            a += usize::from(first == 0);
        }
        assert!(
            a > 100 && a < 190,
            "expected roughly 3:1 split, got {a}/200 for the weight-3 member"
        );
    }

    #[test]
    fn backups_serve_only_when_no_primary_is_healthy() {
        let c = cluster_of(
            &[
                entry("http://a:80", 1, false),
                entry("http://b:80", 1, true),
            ],
            cfg::LoadBalancing::RoundRobin,
        );
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..6 {
            assert_eq!(pick(&c, ip, &[]).unwrap().id, 0, "backup sits idle");
        }
        // primary sick → backup takes over; tried is honored there too
        c.members[0].mark_sick(std::time::Duration::from_secs(60));
        assert_eq!(pick(&c, ip, &[]).unwrap().id, 1);
        assert!(
            pick(&c, ip, &[1]).unwrap().id == 1,
            "tried backup still picked"
        );
        // primary back → backup sits out again
        c.members[0].report_success();
        assert_eq!(pick(&c, ip, &[]).unwrap().id, 0);
        // all sick → nothing
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
