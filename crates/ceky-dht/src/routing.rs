//! Kademlia routing table with k-buckets.
//!
//! The routing table organizes peers by XOR distance from our own PeerId.
//! Each bucket holds up to `K` peers at a specific distance range.
//!
//! ```text
//! Our PeerId: 0xABCD...
//!
//! Bucket[0]:   Distance 2^0   (1 bit diff)   — closest peers
//! Bucket[1]:   Distance 2^1   (2 bit diff)
//! ...
//! Bucket[255]: Distance 2^255 (all bits diff) — furthest peers
//!
//! Each bucket: [PeerInfo; K] where K=20 (standard Kademlia)
//! ```

use crate::peer_info::{PeerInfo, PeerState};
use crate::DhtError;
use ceky_crypto::PeerId;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Standard Kademlia K parameter (peers per bucket).
pub const K: usize = 20;

/// Number of buckets (256 for 256-bit PeerIds).
pub const NUM_BUCKETS: usize = 256;

/// Alpha parameter — parallel lookups during iterative find.
pub const ALPHA: usize = 3;

/// Result of a bucket insert operation.
enum InsertOutcome {
    /// New peer added (bucket had space).
    NewPeer,
    /// Existing peer updated in-place.
    Updated,
    /// A dead/suspect peer was evicted to make room.
    Evicted,
}

/// A single k-bucket holding up to K peers.
#[derive(Debug)]
struct KBucket {
    /// Peers in this bucket, ordered by last-seen (most recent at the end).
    peers: Vec<PeerInfo>,
    /// Last time this bucket was refreshed.
    last_refresh: Instant,
}

impl KBucket {
    fn new() -> Self {
        Self {
            peers: Vec::with_capacity(K),
            last_refresh: Instant::now(),
        }
    }

    /// Number of peers in this bucket.
    fn len(&self) -> usize {
        self.peers.len()
    }

    /// Is this bucket full?
    fn is_full(&self) -> bool {
        self.peers.len() >= K
    }

    /// Is this bucket empty?
    fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Find a peer by PeerId.
    fn find(&self, peer_id: &PeerId) -> Option<usize> {
        self.peers.iter().position(|p| p.peer_id == *peer_id)
    }

    /// Get a peer by PeerId.
    fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.iter().find(|p| p.peer_id == *peer_id)
    }

    /// Get a mutable reference to a peer.
    fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.iter_mut().find(|p| p.peer_id == *peer_id)
    }

    /// Insert or update a peer.
    ///
    /// Returns:
    /// - Ok(InsertOutcome::NewPeer) if newly added
    /// - Ok(InsertOutcome::Updated) if existing peer was updated
    /// - Ok(InsertOutcome::Evicted) if a dead/suspect peer was evicted to make room
    /// - Err(()) if the bucket is full with good peers
    fn insert_or_update(&mut self, peer: PeerInfo) -> Result<InsertOutcome, ()> {
        // If peer already exists, update it
        if let Some(idx) = self.find(&peer.peer_id) {
            self.peers[idx].addr = peer.addr;
            self.peers[idx].touch();
            // Move to end (most recently seen)
            let p = self.peers.remove(idx);
            self.peers.push(p);
            return Ok(InsertOutcome::Updated);
        }

        // Try to insert
        if !self.is_full() {
            self.peers.push(peer);
            return Ok(InsertOutcome::NewPeer);
        }

        // Bucket full — try to evict worst peer
        if let Some(evict_idx) = self.find_eviction_candidate() {
            self.peers.remove(evict_idx);
            self.peers.push(peer);
            return Ok(InsertOutcome::Evicted);
        }

        // No eviction candidate — bucket genuinely full with good peers
        Err(())
    }

    /// Find the best candidate for eviction (dead/suspect with lowest score).
    fn find_eviction_candidate(&self) -> Option<usize> {
        let mut best_idx = None;
        let mut best_score = f64::MAX;

        for (i, peer) in self.peers.iter().enumerate() {
            match peer.state {
                PeerState::Dead => {
                    // Dead peers are always evictable
                    let score = peer.score.composite_score();
                    if score < best_score {
                        best_score = score;
                        best_idx = Some(i);
                    }
                }
                PeerState::Suspect => {
                    let score = peer.score.composite_score();
                    if score < best_score {
                        best_score = score;
                        best_idx = Some(i);
                    }
                }
                _ => {}
            }
        }

        best_idx
    }

    /// Remove a peer by PeerId.
    fn remove(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        if let Some(idx) = self.find(peer_id) {
            Some(self.peers.remove(idx))
        } else {
            None
        }
    }

    /// Get the N closest peers to a target, sorted by score (best first).
    #[allow(dead_code)]
    fn closest_peers(&self) -> Vec<&PeerInfo> {
        let mut peers: Vec<&PeerInfo> = self
            .peers
            .iter()
            .filter(|p| p.is_usable())
            .collect();
        peers.sort_by(|a, b| {
            b.score
                .composite_score()
                .partial_cmp(&a.score.composite_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        peers
    }

    /// Mark this bucket as refreshed.
    #[allow(dead_code)]
    fn mark_refreshed(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// How long since this bucket was last refreshed.
    fn time_since_refresh(&self) -> Duration {
        self.last_refresh.elapsed()
    }
}

/// Kademlia routing table.
///
/// 256 k-buckets indexed by XOR distance from our own PeerId.
/// Each bucket holds up to K (20) peers.
pub struct RoutingTable {
    /// Our own PeerId.
    local_id: PeerId,
    /// The 256 k-buckets.
    buckets: Vec<KBucket>,
    /// Total number of peers across all buckets.
    total_peers: usize,
}

impl RoutingTable {
    /// Create a new routing table for the given local peer ID.
    pub fn new(local_id: PeerId) -> Self {
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(KBucket::new());
        }
        Self {
            local_id,
            buckets,
            total_peers: 0,
        }
    }

    /// Get our own PeerId.
    pub fn local_id(&self) -> &PeerId {
        &self.local_id
    }

    /// Total number of peers in the routing table.
    pub fn total_peers(&self) -> usize {
        self.total_peers
    }

    /// Determine which bucket a peer belongs to based on XOR distance.
    fn bucket_index(&self, peer_id: &PeerId) -> Option<usize> {
        self.local_id.bucket_index(peer_id)
    }

    /// Insert or update a peer in the routing table.
    pub fn insert(&mut self, peer_id: PeerId, addr: SocketAddr) -> Result<bool, DhtError> {
        // Don't insert ourselves
        if peer_id == self.local_id {
            return Ok(false);
        }

        let bucket_idx = self.bucket_index(&peer_id).ok_or(DhtError::InvalidKey {
            reason: "same as local ID".into(),
        })?;

        let peer = PeerInfo::new(peer_id, addr);
        match self.buckets[bucket_idx].insert_or_update(peer) {
            Ok(InsertOutcome::NewPeer) => {
                self.total_peers += 1;
                trace!(
                    peer_id = %peer_id,
                    bucket = bucket_idx,
                    total = self.total_peers,
                    "peer added to routing table"
                );
                Ok(true)
            }
            Ok(InsertOutcome::Evicted) => {
                // Net change: 0 (removed one, added one)
                trace!(
                    peer_id = %peer_id,
                    bucket = bucket_idx,
                    "peer added (evicted dead/suspect peer)"
                );
                Ok(true)
            }
            Ok(InsertOutcome::Updated) => {
                trace!(peer_id = %peer_id, "peer updated in routing table");
                Ok(false)
            }
            Err(()) => {
                Err(DhtError::BucketFull {
                    bucket: bucket_idx,
                })
            }
        }
    }

    /// Remove a peer from the routing table.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        if let Some(bucket_idx) = self.bucket_index(peer_id) {
            if let Some(peer) = self.buckets[bucket_idx].remove(peer_id) {
                self.total_peers -= 1;
                debug!(peer_id = %peer_id, "peer removed from routing table");
                Some(peer)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Find a peer by PeerId.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        if let Some(bucket_idx) = self.bucket_index(peer_id) {
            self.buckets[bucket_idx].get(peer_id)
        } else {
            None
        }
    }

    /// Get a mutable reference to a peer.
    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        if let Some(bucket_idx) = self.bucket_index(peer_id) {
            self.buckets[bucket_idx].get_mut(peer_id)
        } else {
            None
        }
    }

    /// Find the K closest peers to a target PeerId.
    ///
    /// This is the core Kademlia operation. Searches all buckets
    /// and returns up to K peers sorted by XOR distance to the target.
    pub fn find_closest(&self, target: &PeerId, count: usize) -> Vec<&PeerInfo> {
        let mut all_peers: Vec<(&PeerInfo, [u8; 32])> = Vec::new();

        for bucket in &self.buckets {
            for peer in &bucket.peers {
                if peer.is_usable() {
                    let distance = peer.peer_id.xor_distance(target);
                    all_peers.push((peer, distance));
                }
            }
        }

        // Sort by XOR distance (ascending — closest first)
        all_peers.sort_by(|a, b| a.1.cmp(&b.1));

        all_peers
            .into_iter()
            .take(count)
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Get all peers in the routing table.
    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.peers.iter())
            .collect()
    }

    /// Get all active peers (usable for queries).
    pub fn active_peers(&self) -> Vec<&PeerInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.peers.iter())
            .filter(|p| p.is_usable())
            .collect()
    }

    /// Find buckets that need refreshing (haven't been queried recently).
    pub fn stale_buckets(&self, max_age: Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.is_empty() && b.time_since_refresh() > max_age)
            .map(|(i, _)| i)
            .collect()
    }

    /// Mark a peer as active (responded to a query).
    pub fn mark_active(&mut self, peer_id: &PeerId, latency: Duration) {
        if let Some(peer) = self.get_mut(peer_id) {
            peer.mark_active(latency);
        }
    }

    /// Mark a peer as suspect (failed to respond).
    pub fn mark_suspect(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.get_mut(peer_id) {
            peer.mark_suspect();
        }
    }

    /// Evict all dead peers from the routing table.
    pub fn evict_dead(&mut self) -> usize {
        let mut evicted = 0;
        for bucket in &mut self.buckets {
            let before = bucket.len();
            bucket.peers.retain(|p| p.state != PeerState::Dead);
            let removed = before - bucket.len();
            evicted += removed;
            self.total_peers -= removed;
        }
        if evicted > 0 {
            debug!(count = evicted, "evicted dead peers from routing table");
        }
        evicted
    }

    /// Routing table statistics.
    pub fn stats(&self) -> RoutingStats {
        let mut non_empty_buckets = 0;
        let mut active = 0;
        let mut suspect = 0;
        let mut discovered = 0;

        for bucket in &self.buckets {
            if !bucket.is_empty() {
                non_empty_buckets += 1;
            }
            for peer in &bucket.peers {
                match peer.state {
                    PeerState::Active => active += 1,
                    PeerState::Suspect => suspect += 1,
                    PeerState::Discovered => discovered += 1,
                    PeerState::Dead => {} // should be evicted
                }
            }
        }

        RoutingStats {
            total_peers: self.total_peers,
            non_empty_buckets,
            active,
            suspect,
            discovered,
        }
    }
}

/// Routing table statistics snapshot.
#[derive(Debug, Clone)]
pub struct RoutingStats {
    pub total_peers: usize,
    pub non_empty_buckets: usize,
    pub active: usize,
    pub suspect: usize,
    pub discovered: usize,
}

impl std::fmt::Display for RoutingStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RT[{} peers in {} buckets: {} active, {} suspect, {} discovered]",
            self.total_peers,
            self.non_empty_buckets,
            self.active,
            self.suspect,
            self.discovered,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_peer_id(byte: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        PeerId::from_bytes(bytes)
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn insert_and_find() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        let peer1 = make_peer_id(0x01);
        let peer2 = make_peer_id(0x02);

        rt.insert(peer1, addr(9001)).unwrap();
        rt.insert(peer2, addr(9002)).unwrap();

        assert_eq!(rt.total_peers(), 2);
        assert!(rt.get(&peer1).is_some());
        assert!(rt.get(&peer2).is_some());
    }

    #[test]
    fn dont_insert_self() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        let result = rt.insert(local, addr(9000));
        assert!(matches!(result, Ok(false)));
        assert_eq!(rt.total_peers(), 0);
    }

    #[test]
    fn find_closest_returns_sorted() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        // Insert peers at various distances
        for i in 1..=10u8 {
            let peer_id = make_peer_id(i);
            rt.insert(peer_id, addr(9000 + i as u16)).unwrap();
        }

        // Find closest to 0x00 (our local ID)
        let target = make_peer_id(0x01);
        let closest = rt.find_closest(&target, 5);
        assert_eq!(closest.len(), 5);

        // Verify sorted by XOR distance
        for window in closest.windows(2) {
            let d0 = window[0].peer_id.xor_distance(&target);
            let d1 = window[1].peer_id.xor_distance(&target);
            assert!(d0 <= d1, "results should be sorted by distance");
        }
    }

    #[test]
    fn update_existing_peer() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        let peer = make_peer_id(0x01);
        rt.insert(peer, addr(9001)).unwrap();
        assert_eq!(rt.total_peers(), 1);

        // Insert again (should update, not duplicate)
        let inserted = rt.insert(peer, addr(9002)).unwrap();
        assert!(!inserted); // Updated, not newly inserted
        assert_eq!(rt.total_peers(), 1);

        // Address should be updated
        assert_eq!(rt.get(&peer).unwrap().addr, addr(9002));
    }

    #[test]
    fn remove_peer() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        let peer = make_peer_id(0x01);
        rt.insert(peer, addr(9001)).unwrap();

        let removed = rt.remove(&peer);
        assert!(removed.is_some());
        assert_eq!(rt.total_peers(), 0);
        assert!(rt.get(&peer).is_none());
    }

    #[test]
    fn mark_active_and_suspect() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        let peer = make_peer_id(0x01);
        rt.insert(peer, addr(9001)).unwrap();

        rt.mark_active(&peer, Duration::from_millis(50));
        assert_eq!(rt.get(&peer).unwrap().state, PeerState::Active);

        rt.mark_suspect(&peer);
        assert_eq!(rt.get(&peer).unwrap().state, PeerState::Suspect);
    }

    #[test]
    fn evict_dead_peers() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        let peer1 = make_peer_id(0x01);
        let peer2 = make_peer_id(0x02);
        let peer3 = make_peer_id(0x03);
        rt.insert(peer1, addr(9001)).unwrap();
        rt.insert(peer2, addr(9002)).unwrap();
        rt.insert(peer3, addr(9003)).unwrap();

        // Mark peer2 as dead
        if let Some(p) = rt.get_mut(&peer2) {
            p.mark_dead();
        }

        let evicted = rt.evict_dead();
        assert_eq!(evicted, 1);
        assert_eq!(rt.total_peers(), 2);
        assert!(rt.get(&peer2).is_none());
    }

    #[test]
    fn bucket_overflow_evicts_worst() {
        let local = PeerId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local);

        // We need K+1 peers that all land in the SAME bucket.
        // bucket_index = (byte_idx * 8) + (7 - leading_zeros)
        // If we XOR with local=[0;32], distance = peer_id itself.
        // For all peers to land in same bucket, they need the same
        // highest set bit position in the XOR distance.
        //
        // Let's use byte[0] = 0x01, and vary lower bytes.
        // XOR distance = peer_id (since local is all zeros).
        // Highest set bit: byte[0]=0x01 → byte_idx=0, bit=0 → bucket 0.
        // As long as byte[0] stays 0x01 and no higher byte changes, same bucket.

        for i in 0..K {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x01; // Same highest bit
            bytes[31] = i as u8; // Vary low bytes for uniqueness
            let peer = PeerId::from_bytes(bytes);
            rt.insert(peer, addr(9000 + i as u16)).unwrap();
        }
        assert_eq!(rt.total_peers(), K);

        // Next insert should fail (bucket full, no dead/suspect peers)
        let mut overflow_bytes = [0u8; 32];
        overflow_bytes[0] = 0x01;
        overflow_bytes[31] = K as u8;
        let overflow_peer = PeerId::from_bytes(overflow_bytes);
        let result = rt.insert(overflow_peer, addr(9999));
        assert!(matches!(result, Err(DhtError::BucketFull { .. })));

        // Mark one peer as dead → should allow insert
        let mut dead_bytes = [0u8; 32];
        dead_bytes[0] = 0x01;
        dead_bytes[31] = 0;
        let dead_peer = PeerId::from_bytes(dead_bytes);
        if let Some(p) = rt.get_mut(&dead_peer) {
            p.mark_dead();
        }

        let result = rt.insert(overflow_peer, addr(9999));
        assert!(result.is_ok());
        assert_eq!(rt.total_peers(), K);
    }

    #[test]
    fn stats() {
        let local = make_peer_id(0x00);
        let mut rt = RoutingTable::new(local);

        rt.insert(make_peer_id(0x01), addr(9001)).unwrap();
        rt.insert(make_peer_id(0x02), addr(9002)).unwrap();
        rt.insert(make_peer_id(0x80), addr(9003)).unwrap(); // Different bucket

        rt.mark_active(&make_peer_id(0x01), Duration::from_millis(10));

        let stats = rt.stats();
        assert_eq!(stats.total_peers, 3);
        assert!(stats.non_empty_buckets >= 2);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.discovered, 2);
    }

    #[test]
    fn large_scale_routing() {
        let local = PeerId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local);

        // Insert peers with different highest-bit positions to spread
        // across many buckets, avoiding K overflow per bucket.
        let mut inserted = 0u16;
        for byte_idx in 0..32u8 {
            for bit in 0..8u8 {
                let mut bytes = [0u8; 32];
                bytes[byte_idx as usize] = 1 << bit;
                let peer = PeerId::from_bytes(bytes);
                if rt.insert(peer, addr(9000 + inserted)).is_ok() {
                    inserted += 1;
                }
            }
        }

        // 256 unique peers, each in a different bucket
        assert!(inserted > 200, "should insert most of the 256 peers, got {inserted}");

        // find_closest should return at most K peers
        let target = make_peer_id(0x42);
        let closest = rt.find_closest(&target, K);
        assert!(closest.len() <= K);
        assert!(!closest.is_empty());
    }
}
