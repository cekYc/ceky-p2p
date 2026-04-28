//! SuperNode promotion and management.
//!
//! SuperNodes are high-performance peers that provide additional services:
//! - Relay traffic for peers behind symmetric NATs
//! - Cache popular DHT entries
//! - Serve as bootstrap entry points
//!
//! Promotion is automatic and score-based — no central authority.
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │           SuperNode Promotion Ladder          │
//! │                                               │
//! │  Regular ──► Candidate ──► SuperNode ──► Elite │
//! │                                               │
//! │  Criteria:                                    │
//! │   • Uptime > 4 hours                          │
//! │   • Success rate > 95%                        │
//! │   • Low latency (< 100ms avg)                 │
//! │   • Sufficient bandwidth                      │
//! └──────────────────────────────────────────────┘
//! ```

use ceky_crypto::PeerId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// SuperNode tier (higher = more trusted/capable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SuperNodeTier {
    /// Standard peer — not a SuperNode.
    Regular,
    /// Meets minimum criteria, under observation.
    Candidate,
    /// Confirmed SuperNode — eligible for relay duty.
    SuperNode,
    /// Top-tier node — highest reliability, used as bootstrap seed.
    Elite,
}

impl SuperNodeTier {
    /// Can this tier act as a relay?
    pub fn can_relay(&self) -> bool {
        matches!(self, Self::SuperNode | Self::Elite)
    }

    /// Can this tier serve as a bootstrap seed?
    pub fn can_bootstrap(&self) -> bool {
        matches!(self, Self::Elite)
    }
}

impl std::fmt::Display for SuperNodeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Regular => write!(f, "Regular"),
            Self::Candidate => write!(f, "Candidate"),
            Self::SuperNode => write!(f, "SuperNode"),
            Self::Elite => write!(f, "Elite"),
        }
    }
}

/// Promotion criteria thresholds.
#[derive(Debug, Clone)]
pub struct PromotionCriteria {
    /// Minimum uptime for Candidate status.
    pub candidate_uptime: Duration,
    /// Minimum uptime for SuperNode status.
    pub supernode_uptime: Duration,
    /// Minimum uptime for Elite status.
    pub elite_uptime: Duration,
    /// Minimum success rate (0.0 - 1.0) for Candidate.
    pub min_success_rate: f64,
    /// Maximum average latency (ms) for promotion.
    pub max_avg_latency_ms: f64,
    /// Minimum successful queries for SuperNode.
    pub min_successes: u64,
    /// Minimum successful queries for Elite.
    pub elite_min_successes: u64,
    /// Observation period before promotion.
    pub observation_period: Duration,
}

impl Default for PromotionCriteria {
    fn default() -> Self {
        Self {
            candidate_uptime: Duration::from_secs(3600),        // 1 hour
            supernode_uptime: Duration::from_secs(4 * 3600),    // 4 hours
            elite_uptime: Duration::from_secs(24 * 3600),       // 24 hours
            min_success_rate: 0.95,
            max_avg_latency_ms: 100.0,
            min_successes: 100,
            elite_min_successes: 1000,
            observation_period: Duration::from_secs(1800),       // 30 min
        }
    }
}

/// Tracked SuperNode state.
#[derive(Debug, Clone)]
pub struct SuperNodeInfo {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub tier: SuperNodeTier,
    /// When this node was first promoted from Regular.
    pub promoted_at: Option<Instant>,
    /// When the current tier was assigned.
    pub tier_since: Instant,
    /// Accumulated performance stats.
    pub total_successes: u64,
    pub total_failures: u64,
    pub avg_latency_ms: f64,
    pub bytes_relayed: u64,
    /// When we first started tracking this node.
    pub tracked_since: Instant,
}

impl SuperNodeInfo {
    fn new(peer_id: PeerId, addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            addr,
            tier: SuperNodeTier::Regular,
            promoted_at: None,
            tier_since: now,
            total_successes: 0,
            total_failures: 0,
            avg_latency_ms: 0.0,
            bytes_relayed: 0,
            tracked_since: now,
        }
    }

    /// Uptime since we started tracking this node.
    pub fn uptime(&self) -> Duration {
        self.tracked_since.elapsed()
    }

    /// Success rate (0.0 - 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.total_successes + self.total_failures;
        if total == 0 {
            return 0.0;
        }
        self.total_successes as f64 / total as f64
    }
}

/// SuperNode manager — handles promotion, demotion, and discovery.
pub struct SuperNodeManager {
    criteria: PromotionCriteria,
    /// All tracked nodes (potential and actual SuperNodes).
    nodes: HashMap<PeerId, SuperNodeInfo>,
    /// Maximum number of tracked SuperNode candidates.
    max_tracked: usize,
}

impl SuperNodeManager {
    /// Create a new SuperNode manager.
    pub fn new(criteria: PromotionCriteria, max_tracked: usize) -> Self {
        Self {
            criteria,
            nodes: HashMap::new(),
            max_tracked,
        }
    }

    /// Create with default criteria.
    pub fn with_defaults() -> Self {
        Self::new(PromotionCriteria::default(), 500)
    }

    /// Track or update a peer's performance metrics.
    pub fn record_performance(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        success: bool,
        latency_ms: Option<f64>,
    ) {
        let info = self
            .nodes
            .entry(peer_id)
            .or_insert_with(|| SuperNodeInfo::new(peer_id, addr));

        info.addr = addr;
        if success {
            info.total_successes += 1;
            if let Some(lat) = latency_ms {
                let n = info.total_successes as f64;
                info.avg_latency_ms = info.avg_latency_ms * ((n - 1.0) / n) + lat / n;
            }
        } else {
            info.total_failures += 1;
        }
    }

    /// Record relay bytes for a node.
    pub fn record_relay(&mut self, peer_id: &PeerId, bytes: u64) {
        if let Some(info) = self.nodes.get_mut(peer_id) {
            info.bytes_relayed += bytes;
        }
    }

    /// Evaluate all tracked nodes and promote/demote as needed.
    pub fn evaluate_all(&mut self) -> Vec<(PeerId, SuperNodeTier, SuperNodeTier)> {
        let criteria = self.criteria.clone();
        let mut changes = Vec::new();

        for info in self.nodes.values_mut() {
            let old_tier = info.tier;
            let new_tier = Self::evaluate_tier(info, &criteria);

            if new_tier != old_tier {
                info.tier = new_tier;
                info.tier_since = Instant::now();
                if old_tier == SuperNodeTier::Regular && new_tier != SuperNodeTier::Regular {
                    info.promoted_at = Some(Instant::now());
                }
                changes.push((info.peer_id, old_tier, new_tier));

                if new_tier > old_tier {
                    info!(
                        peer = %info.peer_id,
                        from = %old_tier,
                        to = %new_tier,
                        "peer promoted"
                    );
                } else {
                    warn!(
                        peer = %info.peer_id,
                        from = %old_tier,
                        to = %new_tier,
                        "peer demoted"
                    );
                }
            }
        }

        changes
    }

    /// Evaluate a single node's tier.
    fn evaluate_tier(info: &SuperNodeInfo, criteria: &PromotionCriteria) -> SuperNodeTier {
        let uptime = info.uptime();
        let success_rate = info.success_rate();

        // Demotion check: if success rate drops below threshold, demote
        if success_rate < criteria.min_success_rate && info.total_successes + info.total_failures > 10 {
            return SuperNodeTier::Regular;
        }

        // Latency check
        if info.avg_latency_ms > criteria.max_avg_latency_ms && info.total_successes > 10 {
            return SuperNodeTier::Regular;
        }

        // Elite
        if uptime >= criteria.elite_uptime
            && success_rate >= criteria.min_success_rate
            && info.total_successes >= criteria.elite_min_successes
            && info.avg_latency_ms <= criteria.max_avg_latency_ms
        {
            return SuperNodeTier::Elite;
        }

        // SuperNode
        if uptime >= criteria.supernode_uptime
            && success_rate >= criteria.min_success_rate
            && info.total_successes >= criteria.min_successes
            && info.avg_latency_ms <= criteria.max_avg_latency_ms
        {
            return SuperNodeTier::SuperNode;
        }

        // Candidate
        if uptime >= criteria.candidate_uptime
            && success_rate >= criteria.min_success_rate
        {
            return SuperNodeTier::Candidate;
        }

        SuperNodeTier::Regular
    }

    /// Get all nodes of a specific tier.
    pub fn nodes_by_tier(&self, tier: SuperNodeTier) -> Vec<&SuperNodeInfo> {
        self.nodes
            .values()
            .filter(|n| n.tier == tier)
            .collect()
    }

    /// Get all relay-capable nodes (SuperNode + Elite).
    pub fn relay_capable(&self) -> Vec<&SuperNodeInfo> {
        self.nodes
            .values()
            .filter(|n| n.tier.can_relay())
            .collect()
    }

    /// Get the best relay node (highest success rate among relay-capable).
    pub fn best_relay(&self) -> Option<&SuperNodeInfo> {
        self.relay_capable()
            .into_iter()
            .max_by(|a, b| {
                a.success_rate()
                    .partial_cmp(&b.success_rate())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Get node info by PeerId.
    pub fn get(&self, peer_id: &PeerId) -> Option<&SuperNodeInfo> {
        self.nodes.get(peer_id)
    }

    /// Remove a node from tracking.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<SuperNodeInfo> {
        self.nodes.remove(peer_id)
    }

    /// Prune lowest-scoring Regular nodes if over capacity.
    pub fn prune(&mut self) -> usize {
        if self.nodes.len() <= self.max_tracked {
            return 0;
        }

        let excess = self.nodes.len() - self.max_tracked;

        // Collect Regular-tier nodes sorted by success count (worst first)
        let mut regulars: Vec<(PeerId, u64)> = self
            .nodes
            .iter()
            .filter(|(_, info)| info.tier == SuperNodeTier::Regular)
            .map(|(id, info)| (*id, info.total_successes))
            .collect();

        // Sort by successes ascending (prune worst first)
        regulars.sort_by_key(|(_, successes)| *successes);

        let pruned = regulars.len().min(excess);
        for (id, _) in regulars.into_iter().take(pruned) {
            self.nodes.remove(&id);
        }

        if pruned > 0 {
            debug!(count = pruned, "pruned low-value tracked nodes");
        }

        pruned
    }

    /// Summary statistics.
    pub fn stats(&self) -> SuperNodeStats {
        let mut regular = 0;
        let mut candidate = 0;
        let mut supernode = 0;
        let mut elite = 0;

        for info in self.nodes.values() {
            match info.tier {
                SuperNodeTier::Regular => regular += 1,
                SuperNodeTier::Candidate => candidate += 1,
                SuperNodeTier::SuperNode => supernode += 1,
                SuperNodeTier::Elite => elite += 1,
            }
        }

        SuperNodeStats {
            total_tracked: self.nodes.len(),
            regular,
            candidate,
            supernode,
            elite,
        }
    }
}

/// SuperNode manager statistics.
#[derive(Debug, Clone)]
pub struct SuperNodeStats {
    pub total_tracked: usize,
    pub regular: usize,
    pub candidate: usize,
    pub supernode: usize,
    pub elite: usize,
}

impl std::fmt::Display for SuperNodeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SuperNodes[{} tracked: {} regular, {} candidate, {} super, {} elite]",
            self.total_tracked,
            self.regular,
            self.candidate,
            self.supernode,
            self.elite,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn regular_by_default() {
        let mut mgr = SuperNodeManager::with_defaults();
        mgr.record_performance(peer(1), addr(9001), true, Some(50.0));

        let info = mgr.get(&peer(1)).unwrap();
        assert_eq!(info.tier, SuperNodeTier::Regular);
    }

    #[test]
    fn promotion_with_fast_criteria() {
        let criteria = PromotionCriteria {
            candidate_uptime: Duration::from_millis(0),
            supernode_uptime: Duration::from_millis(0),
            elite_uptime: Duration::from_millis(0),
            min_success_rate: 0.90,
            max_avg_latency_ms: 200.0,
            min_successes: 5,
            elite_min_successes: 20,
            observation_period: Duration::from_millis(0),
        };

        let mut mgr = SuperNodeManager::new(criteria, 100);

        // Record enough successes for SuperNode
        for _ in 0..10 {
            mgr.record_performance(peer(1), addr(9001), true, Some(50.0));
        }

        let changes = mgr.evaluate_all();
        assert!(!changes.is_empty());

        let info = mgr.get(&peer(1)).unwrap();
        assert!(info.tier >= SuperNodeTier::SuperNode);
    }

    #[test]
    fn demotion_on_failures() {
        let criteria = PromotionCriteria {
            candidate_uptime: Duration::from_millis(0),
            supernode_uptime: Duration::from_millis(0),
            elite_uptime: Duration::from_millis(0),
            min_success_rate: 0.90,
            max_avg_latency_ms: 200.0,
            min_successes: 5,
            elite_min_successes: 20,
            observation_period: Duration::from_millis(0),
        };

        let mut mgr = SuperNodeManager::new(criteria, 100);

        // First, promote
        for _ in 0..10 {
            mgr.record_performance(peer(1), addr(9001), true, Some(50.0));
        }
        mgr.evaluate_all();
        assert!(mgr.get(&peer(1)).unwrap().tier >= SuperNodeTier::SuperNode);

        // Now add many failures to drop success rate below threshold
        for _ in 0..100 {
            mgr.record_performance(peer(1), addr(9001), false, None);
        }
        mgr.evaluate_all();
        assert_eq!(mgr.get(&peer(1)).unwrap().tier, SuperNodeTier::Regular);
    }

    #[test]
    fn relay_capable_filter() {
        let criteria = PromotionCriteria {
            candidate_uptime: Duration::from_millis(0),
            supernode_uptime: Duration::from_millis(0),
            elite_uptime: Duration::from_millis(0),
            min_success_rate: 0.80,
            max_avg_latency_ms: 200.0,
            min_successes: 3,
            elite_min_successes: 100,
            observation_period: Duration::from_millis(0),
        };

        let mut mgr = SuperNodeManager::new(criteria, 100);

        // Make peer 1 a SuperNode
        for _ in 0..5 {
            mgr.record_performance(peer(1), addr(9001), true, Some(30.0));
        }
        // Keep peer 2 as Regular (only 1 success)
        mgr.record_performance(peer(2), addr(9002), true, Some(30.0));

        mgr.evaluate_all();

        let relays = mgr.relay_capable();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].peer_id, peer(1));
    }

    #[test]
    fn tier_ordering() {
        assert!(SuperNodeTier::Elite > SuperNodeTier::SuperNode);
        assert!(SuperNodeTier::SuperNode > SuperNodeTier::Candidate);
        assert!(SuperNodeTier::Candidate > SuperNodeTier::Regular);
    }

    #[test]
    fn stats() {
        let mut mgr = SuperNodeManager::with_defaults();
        mgr.record_performance(peer(1), addr(9001), true, Some(10.0));
        mgr.record_performance(peer(2), addr(9002), true, Some(20.0));

        let stats = mgr.stats();
        assert_eq!(stats.total_tracked, 2);
        assert_eq!(stats.regular, 2);
    }
}
