//! Eviction ordering shared by the RAM and disk tiers: one B-tree keyed
//! by a policy-dependent rank tuple, so the next victim is always the
//! first key.
//!
//! - LRU: rank = `(last_access_seq, 0)` — touch bumps the seq.
//! - FIFO: rank = `(insert_seq, 0)` — touch is a no-op.
//! - LFU: rank = `(hits, insert_seq)` — touch bumps hits.

use std::collections::{BTreeMap, HashMap};

use crate::config::model::EvictionPolicy;

/// Ordered index of entry hashes by eviction preference.
#[derive(Debug)]
pub struct Order {
    /// hash → its current rank tuple `(rank, seq)`.
    pos: HashMap<u64, (u64, u64)>,
    /// rank tuple + hash → unit; first entry is the next victim.
    set: BTreeMap<(u64, u64, u64), ()>,
    /// Monotonic sequence counter for insertion/access ordering.
    seq: u64,
    /// Whether hits reorder entries (false for FIFO).
    touch_on_hit: bool,
    /// Whether rank counts hits (LFU) or access order (LRU/FIFO).
    lfu: bool,
}

impl Order {
    /// New index for `policy`.
    pub fn new(policy: EvictionPolicy) -> Self {
        Self {
            pos: HashMap::new(),
            set: BTreeMap::new(),
            seq: 0,
            touch_on_hit: policy != EvictionPolicy::Fifo,
            lfu: policy == EvictionPolicy::Lfu,
        }
    }

    /// Register a newly inserted entry. `hits` seeds LFU (entries
    /// promoted from disk start warm).
    pub fn insert(&mut self, key: u64, hits: u64) {
        self.remove(key);
        self.seq += 1;
        let rank = if self.lfu { hits } else { self.seq };
        self.pos.insert(key, (rank, self.seq));
        self.set.insert((rank, self.seq, key), ());
    }

    /// Record an access per the policy (no-op for FIFO).
    pub fn touch(&mut self, key: u64) {
        if !self.touch_on_hit {
            return;
        }
        let Some((rank, seq)) = self.pos.get(&key).copied() else {
            return;
        };
        self.set.remove(&(rank, seq, key));
        if self.lfu {
            self.pos.insert(key, (rank + 1, seq));
            self.set.insert((rank + 1, seq, key), ());
        } else {
            self.seq += 1;
            self.pos.insert(key, (self.seq, 0));
            self.set.insert((self.seq, 0, key), ());
        }
    }

    /// The next eviction candidate.
    pub fn victim(&self) -> Option<u64> {
        self.set.keys().next().map(|t| t.2)
    }

    /// Drop an entry from the index.
    pub fn remove(&mut self, key: u64) {
        if let Some((rank, seq)) = self.pos.remove(&key) {
            self.set.remove(&(rank, seq, key));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_least_recent() {
        let mut o = Order::new(EvictionPolicy::Lru);
        o.insert(1, 0);
        o.insert(2, 0);
        o.insert(3, 0);
        o.touch(1);
        assert_eq!(o.victim(), Some(2));
        o.touch(2);
        assert_eq!(o.victim(), Some(3));
    }

    #[test]
    fn fifo_ignores_hits() {
        let mut o = Order::new(EvictionPolicy::Fifo);
        o.insert(1, 0);
        o.insert(2, 0);
        o.touch(1);
        o.touch(1);
        assert_eq!(o.victim(), Some(1));
    }

    #[test]
    fn lfu_evicts_least_frequent() {
        let mut o = Order::new(EvictionPolicy::Lfu);
        o.insert(1, 0);
        o.insert(2, 0);
        o.insert(3, 0);
        o.touch(2);
        o.touch(3);
        o.touch(3);
        assert_eq!(o.victim(), Some(1));
        o.touch(1);
        o.touch(1);
        assert_eq!(o.victim(), Some(2));
    }

    #[test]
    fn remove_drops() {
        let mut o = Order::new(EvictionPolicy::Lru);
        o.insert(1, 0);
        o.insert(2, 0);
        o.remove(1);
        assert_eq!(o.victim(), Some(2));
        assert_eq!(o.set.len(), 1);
    }
}
