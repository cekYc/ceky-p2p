//! Peer metadata and performance scoring.
//!
//! Every peer in the routing table has associated info and a score
//! that influences routing decisions. Good peers get promoted,
//! bad peers get evicted.

use ceky_crypto::PeerId;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Peer lifecycle state within the DHT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Peer was discovered but not yet verified.
    Discovered,
    /// Peer responded to a PING/FIND_NODE — confirmed alive.
    Active,
    /// Peer failed to respond to recent queries.
    Suspect,
    /// Peer has been unreachable for too long.
    Dead,
}

/// Performance-based peer score.
///
/// Higher score = more reliable peer. Influences:
/// - Routing preference (high-score peers queried first)
/// - Eviction order (low-score peers evicted first)
/// - SuperNode promotion candidates
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// Average round-trip latency in milliseconds.
    pub avg_latency_ms: f64,
    /// Total successful responses.
    pub successes: u64,
    /// Total failed queries (timeout or error).
    pub failures: u64,
    /// Total bytes relayed through this peer.
    pub bytes_relayed: u64,
    /// How long this peer has been in our routing table.
    pub uptime: Duration,
    /// Timestamp of first contact.
    first_seen: Instant,
    /// Running latency sum for incremental average.
    latency_sum_ms: f64,
}

impl PeerScore {
    /// Create a new score for a freshly discovered peer.
    pub fn new() -> Self {
        Self {
            avg_latency_ms: 0.0,
            successes: 0,
            failures: 0,
            bytes_relayed: 0,
            uptime: Duration::ZERO,
            first_seen: Instant::now(),
            latency_sum_ms: 0.0,
        }
    }

    /// Record a successful response with measured latency.
    pub fn record_success(&mut self, latency: Duration) {
        self.successes += 1;
        let latency_ms = latency.as_secs_f64() * 1000.0;
        self.latency_sum_ms += latency_ms;
        self.avg_latency_ms = self.latency_sum_ms / self.successes as f64;
        self.uptime = self.first_seen.elapsed();
    }

    /// Record a failed query.
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.uptime = self.first_seen.elapsed();
    }

    /// Record bytes relayed through this peer.
    pub fn record_relay(&mut self, bytes: u64) {
        self.bytes_relayed += bytes;
    }

    /// Compute a composite score (higher = better).
    ///
    /// Formula: `score = (successes * 10) / (failures + 1) - avg_latency/100 + uptime_bonus`
    pub fn composite_score(&self) -> f64 {
        let reliability = (self.successes as f64 * 10.0) / (self.failures as f64 + 1.0);
        let latency_penalty = self.avg_latency_ms / 100.0;
        let uptime_bonus = (self.uptime.as_secs() as f64).min(3600.0) / 360.0; // max 10 points for 1hr
        let relay_bonus = (self.bytes_relayed as f64).log2().max(0.0) / 10.0;

        reliability - latency_penalty + uptime_bonus + relay_bonus
    }

    /// Success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.0;
        }
        (self.successes as f64 / total as f64) * 100.0
    }
}

impl Default for PeerScore {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete info about a known peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's unique identifier (SHA-256 of Ed25519 PK).
    pub peer_id: PeerId,
    /// Network address.
    pub addr: SocketAddr,
    /// Current lifecycle state.
    pub state: PeerState,
    /// Performance score.
    pub score: PeerScore,
    /// When we last heard from this peer.
    pub last_seen: Instant,
    /// When this peer was added to our routing table.
    pub added_at: Instant,
}

impl PeerInfo {
    /// Create a new peer info entry.
    pub fn new(peer_id: PeerId, addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            addr,
            state: PeerState::Discovered,
            score: PeerScore::new(),
            last_seen: now,
            added_at: now,
        }
    }

    /// Mark this peer as active (responded to a query).
    pub fn mark_active(&mut self, latency: Duration) {
        self.state = PeerState::Active;
        self.last_seen = Instant::now();
        self.score.record_success(latency);
    }

    /// Mark this peer as suspect (failed to respond).
    pub fn mark_suspect(&mut self) {
        self.state = PeerState::Suspect;
        self.score.record_failure();
    }

    /// Mark this peer as dead.
    pub fn mark_dead(&mut self) {
        self.state = PeerState::Dead;
    }

    /// Update the last-seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// How long since we last heard from this peer.
    pub fn idle_time(&self) -> Duration {
        self.last_seen.elapsed()
    }

    /// Is this peer in a usable state?
    pub fn is_usable(&self) -> bool {
        matches!(self.state, PeerState::Discovered | PeerState::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_peer() -> PeerInfo {
        let peer_id = PeerId::from_bytes([0x42; 32]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
        PeerInfo::new(peer_id, addr)
    }

    #[test]
    fn peer_lifecycle() {
        let mut peer = test_peer();
        assert_eq!(peer.state, PeerState::Discovered);
        assert!(peer.is_usable());

        peer.mark_active(Duration::from_millis(50));
        assert_eq!(peer.state, PeerState::Active);
        assert!(peer.is_usable());

        peer.mark_suspect();
        assert_eq!(peer.state, PeerState::Suspect);
        assert!(!peer.is_usable());

        peer.mark_dead();
        assert_eq!(peer.state, PeerState::Dead);
        assert!(!peer.is_usable());
    }

    #[test]
    fn score_tracking() {
        let mut score = PeerScore::new();
        score.record_success(Duration::from_millis(50));
        score.record_success(Duration::from_millis(30));
        assert_eq!(score.successes, 2);
        assert!((score.avg_latency_ms - 40.0).abs() < 0.1);

        score.record_failure();
        assert_eq!(score.failures, 1);
        assert!((score.success_rate() - 66.666).abs() < 1.0);
    }

    #[test]
    fn composite_score_rewards_reliability() {
        let mut good = PeerScore::new();
        for _ in 0..100 {
            good.record_success(Duration::from_millis(20));
        }

        let mut bad = PeerScore::new();
        for _ in 0..10 {
            bad.record_success(Duration::from_millis(200));
        }
        for _ in 0..90 {
            bad.record_failure();
        }

        assert!(good.composite_score() > bad.composite_score());
    }
}
