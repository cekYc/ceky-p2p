//! DHT bootstrap process.
//!
//! Initializes the routing table by contacting hardcoded seed nodes
//! and performing iterative find_node lookups to progressively fill
//! k-buckets across all distance ranges.
//!
//! ```text
//! Bootstrap Flow:
//!
//! 1. Contact seed nodes → add to routing table
//! 2. FIND_NODE(self) → discover nearby peers
//! 3. FIND_NODE(random_id per bucket) → fill distant buckets
//! 4. Periodic refresh → keep buckets fresh
//! ```

use crate::operations::{IterativeLookup, PeerEntry};
use crate::routing::{RoutingTable, NUM_BUCKETS};
use ceky_crypto::PeerId;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Bootstrap configuration.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Hardcoded seed node addresses.
    pub seed_nodes: Vec<SocketAddr>,
    /// Timeout for each bootstrap probe.
    pub probe_timeout: Duration,
    /// Number of random lookups to fill distant buckets.
    pub random_lookups: usize,
    /// Interval between periodic bucket refreshes.
    pub refresh_interval: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            seed_nodes: Vec::new(),
            probe_timeout: Duration::from_secs(5),
            random_lookups: 3,
            refresh_interval: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Bootstrap state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapState {
    /// Not yet started.
    Idle,
    /// Contacting seed nodes.
    ContactingSeeds,
    /// Running self-lookup to find nearby peers.
    SelfLookup,
    /// Filling distant buckets with random lookups.
    BucketFill,
    /// Bootstrap complete.
    Complete,
    /// Bootstrap failed.
    Failed,
}

/// Result of the bootstrap process.
#[derive(Debug)]
pub struct BootstrapResult {
    /// Final state.
    pub state: BootstrapState,
    /// Number of peers discovered during bootstrap.
    pub peers_discovered: usize,
    /// Number of seed nodes that responded.
    pub seeds_responded: usize,
    /// Total seeds attempted.
    pub seeds_attempted: usize,
}

/// Bootstrap manager for initializing the DHT routing table.
pub struct BootstrapManager {
    config: BootstrapConfig,
    state: BootstrapState,
}

impl BootstrapManager {
    /// Create a new bootstrap manager.
    pub fn new(config: BootstrapConfig) -> Self {
        Self {
            config,
            state: BootstrapState::Idle,
        }
    }

    /// Create with default config and provided seed nodes.
    pub fn with_seeds(seeds: Vec<SocketAddr>) -> Self {
        Self::new(BootstrapConfig {
            seed_nodes: seeds,
            ..Default::default()
        })
    }

    /// Get the current bootstrap state.
    pub fn state(&self) -> BootstrapState {
        self.state
    }

    /// Get seed node addresses from config.
    pub fn seed_addrs(&self) -> &[SocketAddr] {
        &self.config.seed_nodes
    }

    /// Prepare the self-lookup for finding nearby peers.
    ///
    /// Returns the seed entries for the iterative lookup targeting our own PeerId.
    /// The caller is responsible for driving the actual network I/O.
    pub fn prepare_self_lookup(
        &mut self,
        local_id: &PeerId,
        known_peers: Vec<PeerEntry>,
    ) -> IterativeLookup {
        self.state = BootstrapState::SelfLookup;
        debug!(
            local_id = %local_id,
            known_peers = known_peers.len(),
            "starting self-lookup"
        );
        IterativeLookup::new(*local_id, known_peers)
    }

    /// Generate random PeerIds for bucket fill lookups.
    ///
    /// Creates random targets at various distances to ensure
    /// we discover peers across all k-bucket ranges.
    pub fn generate_bucket_fill_targets(&self, local_id: &PeerId) -> Vec<PeerId> {
        let mut targets = Vec::with_capacity(self.config.random_lookups);
        let local_bytes = local_id.as_bytes();

        for i in 0..self.config.random_lookups {
            // Generate a target that's roughly at bucket distance (i * 256 / random_lookups)
            let target_bucket = (i * NUM_BUCKETS) / self.config.random_lookups.max(1);
            let mut target_bytes = *local_bytes;

            // Flip a bit at the target distance to create a PeerId in that bucket range
            let byte_idx = target_bucket / 8;
            let bit_idx = target_bucket % 8;
            if byte_idx < 32 {
                target_bytes[byte_idx] ^= 1 << bit_idx;
            }

            // Add some randomness to lower bytes
            let seed = (i as u8).wrapping_mul(0x9E).wrapping_add(0x37);
            for b in target_bytes.iter_mut().skip(byte_idx + 1) {
                *b ^= seed;
            }

            targets.push(PeerId::from_bytes(target_bytes));
        }

        debug!(
            count = targets.len(),
            "generated bucket fill targets"
        );
        targets
    }

    /// Mark seed contact phase as complete, report how many responded.
    pub fn seeds_contacted(&mut self, responded: usize, total: usize) {
        if responded == 0 {
            warn!(
                attempted = total,
                "no seed nodes responded — bootstrap may fail"
            );
        } else {
            info!(
                responded = responded,
                total = total,
                "seed nodes contacted"
            );
        }
        self.state = BootstrapState::ContactingSeeds;
    }

    /// Transition to bucket fill phase.
    pub fn begin_bucket_fill(&mut self) {
        self.state = BootstrapState::BucketFill;
        debug!("beginning bucket fill phase");
    }

    /// Mark bootstrap as complete.
    pub fn complete(&mut self, routing_table: &RoutingTable) -> BootstrapResult {
        let peers_discovered = routing_table.total_peers();
        self.state = if peers_discovered > 0 {
            BootstrapState::Complete
        } else {
            BootstrapState::Failed
        };

        let result = BootstrapResult {
            state: self.state,
            peers_discovered,
            seeds_responded: 0, // filled by caller
            seeds_attempted: self.config.seed_nodes.len(),
        };

        info!(
            state = ?self.state,
            peers = peers_discovered,
            "bootstrap finished"
        );

        result
    }

    /// Check which buckets need a refresh and return their target PeerIds.
    pub fn stale_bucket_targets(
        &self,
        local_id: &PeerId,
        routing_table: &RoutingTable,
    ) -> Vec<PeerId> {
        let stale = routing_table.stale_buckets(self.config.refresh_interval);
        let local_bytes = local_id.as_bytes();

        stale
            .into_iter()
            .map(|bucket_idx| {
                let mut target = *local_bytes;
                let byte_idx = bucket_idx / 8;
                let bit_idx = bucket_idx % 8;
                if byte_idx < 32 {
                    target[byte_idx] ^= 1 << bit_idx;
                }
                PeerId::from_bytes(target)
            })
            .collect()
    }

    /// Get the refresh interval.
    pub fn refresh_interval(&self) -> Duration {
        self.config.refresh_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn bootstrap_lifecycle() {
        let seeds = vec![addr(9001), addr(9002)];
        let mut bm = BootstrapManager::with_seeds(seeds);

        assert_eq!(bm.state(), BootstrapState::Idle);
        assert_eq!(bm.seed_addrs().len(), 2);

        bm.seeds_contacted(1, 2);
        // After contacting seeds, state is ContactingSeeds (then we'd do self-lookup)
    }

    #[test]
    fn generate_fill_targets() {
        let local = PeerId::from_bytes([0x00; 32]);
        let bm = BootstrapManager::new(BootstrapConfig {
            random_lookups: 5,
            ..Default::default()
        });

        let targets = bm.generate_bucket_fill_targets(&local);
        assert_eq!(targets.len(), 5);

        // All targets should be different from local
        for t in &targets {
            assert_ne!(*t, local);
        }
    }

    #[test]
    fn stale_bucket_refresh() {
        let local = PeerId::from_bytes([0x00; 32]);
        let rt = RoutingTable::new(local);
        let bm = BootstrapManager::new(BootstrapConfig {
            refresh_interval: Duration::from_secs(0), // Everything is stale
            ..Default::default()
        });

        // Empty routing table has no stale buckets (empty buckets aren't stale)
        let targets = bm.stale_bucket_targets(&local, &rt);
        assert!(targets.is_empty());
    }

    #[test]
    fn complete_with_peers() {
        let local = PeerId::from_bytes([0x00; 32]);
        let mut rt = RoutingTable::new(local);
        let peer = PeerId::from_bytes([0x01; 32]);
        rt.insert(peer, addr(9001)).unwrap();

        let mut bm = BootstrapManager::new(Default::default());
        let result = bm.complete(&rt);

        assert_eq!(result.state, BootstrapState::Complete);
        assert_eq!(result.peers_discovered, 1);
    }

    #[test]
    fn complete_without_peers() {
        let local = PeerId::from_bytes([0x00; 32]);
        let rt = RoutingTable::new(local);

        let mut bm = BootstrapManager::new(Default::default());
        let result = bm.complete(&rt);

        assert_eq!(result.state, BootstrapState::Failed);
        assert_eq!(result.peers_discovered, 0);
    }
}
