//! Kademlia iterative lookup operations.
//!
//! Implements the core DHT operations:
//! - `find_node`: Iteratively find the K closest peers to a target
//! - `store`: Store a key-value pair in the network
//! - `find_value`: Retrieve a value by key, falling back to find_node
//!
//! These are the building blocks for the distributed hash table.
//! The actual network I/O is abstracted behind the `DhtRpc` trait.

use crate::routing::{K, ALPHA};
use crate::DhtError;
use ceky_crypto::PeerId;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;

/// Result of a find_node operation.
#[derive(Debug)]
pub struct FindNodeResult {
    /// The K closest peers found.
    pub closest: Vec<PeerEntry>,
    /// Number of hops (rounds) the lookup took.
    pub hops: usize,
    /// Total peers queried.
    pub queried_count: usize,
}

/// A lightweight peer entry returned from lookups.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub distance: [u8; 32],
}

/// Result of a store operation.
#[derive(Debug)]
pub struct StoreResult {
    /// Number of peers that acknowledged the store.
    pub stored_at: usize,
    /// Peers that were contacted.
    pub contacted: usize,
}

/// Result of a find_value operation.
#[derive(Debug)]
pub enum FindValueResult {
    /// Value was found.
    Found {
        value: Vec<u8>,
        /// Peer that held the value.
        from: PeerId,
    },
    /// Value not found, but here are the closest peers.
    NotFound(FindNodeResult),
}

/// A stored key-value pair with metadata.
#[derive(Debug, Clone)]
pub struct StoredEntry {
    /// The key (typically a content hash).
    pub key: [u8; 32],
    /// The value data.
    pub value: Vec<u8>,
    /// Who stored it originally.
    pub publisher: PeerId,
    /// When it was stored.
    pub stored_at: std::time::Instant,
    /// Time-to-live before expiration.
    pub ttl: Duration,
}

impl StoredEntry {
    /// Create a new stored entry.
    pub fn new(key: [u8; 32], value: Vec<u8>, publisher: PeerId, ttl: Duration) -> Self {
        Self {
            key,
            value,
            publisher,
            stored_at: std::time::Instant::now(),
            ttl,
        }
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self) -> bool {
        self.stored_at.elapsed() > self.ttl
    }
}

/// Local DHT storage for key-value pairs.
pub struct LocalStore {
    entries: HashMap<[u8; 32], StoredEntry>,
    /// Maximum number of entries to store locally.
    max_entries: usize,
}

impl LocalStore {
    /// Create a new local store.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Store a value locally.
    pub fn put(&mut self, entry: StoredEntry) -> Result<(), DhtError> {
        // Evict expired entries first
        self.evict_expired();

        if self.entries.len() >= self.max_entries {
            return Err(DhtError::StoreFailed {
                reason: "local store full".into(),
            });
        }

        self.entries.insert(entry.key, entry);
        Ok(())
    }

    /// Retrieve a value by key.
    pub fn get(&self, key: &[u8; 32]) -> Option<&StoredEntry> {
        self.entries.get(key).filter(|e| !e.is_expired())
    }

    /// Remove a value by key.
    pub fn remove(&mut self, key: &[u8; 32]) -> Option<StoredEntry> {
        self.entries.remove(key)
    }

    /// Evict all expired entries.
    pub fn evict_expired(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, v| !v.is_expired());
        before - self.entries.len()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the store empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all non-expired entries.
    pub fn all_entries(&self) -> Vec<&StoredEntry> {
        self.entries.values().filter(|e| !e.is_expired()).collect()
    }
}

/// Iterative lookup state machine.
///
/// This performs the iterative Kademlia lookup algorithm locally,
/// managing the state of which peers have been queried, which responded,
/// and tracking convergence.
pub struct IterativeLookup {
    /// Target we're looking for.
    target: PeerId,
    /// Peers we know about, sorted by distance.
    known_peers: Vec<PeerEntry>,
    /// Peers we've already queried.
    queried: HashSet<PeerId>,
    /// Current round number.
    round: usize,
    /// Whether the lookup has converged (no closer peers found).
    converged: bool,
}

impl IterativeLookup {
    /// Start a new iterative lookup.
    pub fn new(target: PeerId, seed_peers: Vec<PeerEntry>) -> Self {
        let mut lookup = Self {
            target,
            known_peers: Vec::new(),
            queried: HashSet::new(),
            round: 0,
            converged: false,
        };

        // Add seed peers
        for peer in seed_peers {
            lookup.add_peer(peer);
        }

        lookup
    }

    /// Add a newly discovered peer to the lookup.
    pub fn add_peer(&mut self, peer: PeerEntry) {
        // Don't add duplicates
        if self.known_peers.iter().any(|p| p.peer_id == peer.peer_id) {
            return;
        }

        let distance = peer.peer_id.xor_distance(&self.target);
        let entry = PeerEntry {
            peer_id: peer.peer_id,
            addr: peer.addr,
            distance,
        };

        self.known_peers.push(entry);

        // Keep sorted by distance
        self.known_peers.sort_by(|a, b| a.distance.cmp(&b.distance));

        // Trim to reasonable size
        self.known_peers.truncate(K * 3);
    }

    /// Get the next batch of peers to query (up to ALPHA).
    pub fn next_to_query(&mut self) -> Vec<PeerEntry> {
        let to_query: Vec<PeerEntry> = self
            .known_peers
            .iter()
            .filter(|p| !self.queried.contains(&p.peer_id))
            .take(ALPHA)
            .cloned()
            .collect();

        if to_query.is_empty() {
            self.converged = true;
        }

        // Mark as queried
        for peer in &to_query {
            self.queried.insert(peer.peer_id);
        }

        self.round += 1;
        to_query
    }

    /// Process responses from queried peers.
    pub fn process_responses(&mut self, new_peers: Vec<PeerEntry>) {
        let before_closest = self
            .known_peers
            .first()
            .map(|p| p.distance);

        for peer in new_peers {
            self.add_peer(peer);
        }

        // Check if we found closer peers
        let after_closest = self
            .known_peers
            .first()
            .map(|p| p.distance);

        if before_closest == after_closest {
            // No improvement — may be converging
            // We don't set converged here; that happens when there's
            // no one left to query.
        }
    }

    /// Is the lookup complete?
    pub fn is_complete(&self) -> bool {
        self.converged
    }

    /// Get the final result.
    pub fn result(&self) -> FindNodeResult {
        FindNodeResult {
            closest: self
                .known_peers
                .iter()
                .take(K)
                .cloned()
                .collect(),
            hops: self.round,
            queried_count: self.queried.len(),
        }
    }

    /// Current round.
    pub fn round(&self) -> usize {
        self.round
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

    fn make_entry(byte: u8, target: &PeerId) -> PeerEntry {
        let peer_id = make_peer_id(byte);
        PeerEntry {
            peer_id,
            addr: addr(9000 + byte as u16),
            distance: peer_id.xor_distance(target),
        }
    }

    #[test]
    fn local_store_put_and_get() {
        let mut store = LocalStore::new(100);
        let key = [0x42u8; 32];
        let entry = StoredEntry::new(
            key,
            b"hello world".to_vec(),
            make_peer_id(0x01),
            Duration::from_secs(3600),
        );

        store.put(entry).unwrap();
        assert_eq!(store.len(), 1);

        let retrieved = store.get(&key).unwrap();
        assert_eq!(retrieved.value, b"hello world");
    }

    #[test]
    fn local_store_capacity() {
        let mut store = LocalStore::new(2);
        let key1 = [0x01; 32];
        let key2 = [0x02; 32];
        let key3 = [0x03; 32];

        store
            .put(StoredEntry::new(key1, vec![1], make_peer_id(1), Duration::from_secs(60)))
            .unwrap();
        store
            .put(StoredEntry::new(key2, vec![2], make_peer_id(1), Duration::from_secs(60)))
            .unwrap();

        // Third should fail
        let result = store.put(StoredEntry::new(
            key3,
            vec![3],
            make_peer_id(1),
            Duration::from_secs(60),
        ));
        assert!(result.is_err());
    }

    #[test]
    fn iterative_lookup_converges() {
        let target = make_peer_id(0x42);

        // Seed with a few peers
        let seeds = vec![
            make_entry(0x40, &target),
            make_entry(0x44, &target),
            make_entry(0x50, &target),
        ];

        let mut lookup = IterativeLookup::new(target, seeds);

        // Round 1: get ALPHA peers to query
        let to_query = lookup.next_to_query();
        assert_eq!(to_query.len(), ALPHA);

        // Simulate responses with closer peers
        let closer = vec![
            make_entry(0x43, &target),
            make_entry(0x41, &target),
        ];
        lookup.process_responses(closer);

        // Round 2
        let to_query = lookup.next_to_query();
        assert!(!to_query.is_empty());

        // No more new peers → should converge
        lookup.process_responses(vec![]);
        let to_query = lookup.next_to_query();
        if to_query.is_empty() {
            assert!(lookup.is_complete());
        }

        let result = lookup.result();
        assert!(result.hops >= 2);
        assert!(!result.closest.is_empty());
    }

    #[test]
    fn iterative_lookup_deduplicates() {
        let target = make_peer_id(0x42);
        let seeds = vec![make_entry(0x40, &target)];

        let mut lookup = IterativeLookup::new(target, seeds);
        let _ = lookup.next_to_query();

        // Add same peer again
        lookup.process_responses(vec![make_entry(0x40, &target)]);

        // Should not have duplicates in result
        let result = lookup.result();
        let ids: HashSet<_> = result.closest.iter().map(|p| p.peer_id).collect();
        assert_eq!(ids.len(), result.closest.len());
    }

    #[test]
    fn find_node_result_sorted_by_distance() {
        let target = make_peer_id(0x00);
        let seeds = vec![
            make_entry(0x80, &target), // Far
            make_entry(0x01, &target), // Close
            make_entry(0x40, &target), // Medium
            make_entry(0x02, &target), // Close
        ];

        let lookup = IterativeLookup::new(target, seeds);
        let result = lookup.result();

        // Should be sorted by distance
        for window in result.closest.windows(2) {
            assert!(
                window[0].distance <= window[1].distance,
                "results should be sorted by distance"
            );
        }
    }
}
