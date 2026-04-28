//! Relay service for symmetric NAT fallback.
//!
//! When direct hole punching fails (symmetric NAT), traffic is
//! forwarded through a relay node (SuperNode). The relay enforces
//! bandwidth limits and session timeouts to prevent abuse.
//!
//! ```text
//! Peer A ──────► Relay (SuperNode) ──────► Peer B
//!        encrypted          forwarded           encrypted
//! ```

use crate::NatError;
use ceky_crypto::PeerId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Relay session configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Maximum bandwidth per session (bytes/sec).
    pub max_bandwidth_bps: u64,
    /// Session timeout (no traffic).
    pub idle_timeout: Duration,
    /// Maximum session duration.
    pub max_duration: Duration,
    /// Maximum concurrent relay sessions.
    pub max_sessions: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_bandwidth_bps: 512 * 1024, // 512 KB/s per session
            idle_timeout: Duration::from_secs(60),
            max_duration: Duration::from_secs(3600), // 1 hour max
            max_sessions: 100,
        }
    }
}

/// A single relay session between two peers.
#[derive(Debug, Clone)]
pub struct RelaySession {
    /// Unique session ID.
    pub session_id: u64,
    /// Peer A.
    pub peer_a: RelayPeer,
    /// Peer B.
    pub peer_b: RelayPeer,
    /// When this session was created.
    pub created_at: Instant,
    /// Last time traffic passed through.
    pub last_activity: Instant,
    /// Total bytes relayed (A→B + B→A).
    pub bytes_relayed: u64,
    /// Session state.
    pub state: RelaySessionState,
}

/// State of a relay session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySessionState {
    /// Waiting for peer B to accept.
    Pending,
    /// Both peers connected, relaying traffic.
    Active,
    /// Session closed.
    Closed,
}

/// A peer in a relay session.
#[derive(Debug, Clone)]
pub struct RelayPeer {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl RelayPeer {
    pub fn new(peer_id: PeerId, addr: SocketAddr) -> Self {
        Self {
            peer_id,
            addr,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Relay service managing multiple relay sessions.
pub struct RelayService {
    config: RelayConfig,
    sessions: HashMap<u64, RelaySession>,
    next_session_id: u64,
}

impl RelayService {
    /// Create a new relay service.
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            next_session_id: 1,
        }
    }

    /// Create with default config.
    pub fn with_defaults() -> Self {
        Self::new(RelayConfig::default())
    }

    /// Request a new relay session between two peers.
    pub fn create_session(
        &mut self,
        peer_a_id: PeerId,
        peer_a_addr: SocketAddr,
        peer_b_id: PeerId,
        peer_b_addr: SocketAddr,
    ) -> Result<u64, NatError> {
        // Check capacity
        if self.sessions.len() >= self.config.max_sessions {
            // Try to clean up expired sessions first
            self.cleanup_expired();

            if self.sessions.len() >= self.config.max_sessions {
                return Err(NatError::RelayRefused {
                    reason: "relay at capacity".into(),
                });
            }
        }

        let session_id = self.next_session_id;
        self.next_session_id += 1;

        let now = Instant::now();
        let session = RelaySession {
            session_id,
            peer_a: RelayPeer::new(peer_a_id, peer_a_addr),
            peer_b: RelayPeer::new(peer_b_id, peer_b_addr),
            created_at: now,
            last_activity: now,
            bytes_relayed: 0,
            state: RelaySessionState::Pending,
        };

        self.sessions.insert(session_id, session);
        debug!(session_id = session_id, "relay session created");

        Ok(session_id)
    }

    /// Activate a pending session (peer B accepted).
    pub fn activate_session(&mut self, session_id: u64) -> Result<(), NatError> {
        let session = self.sessions.get_mut(&session_id).ok_or(NatError::RelayRefused {
            reason: format!("session {session_id} not found"),
        })?;

        if session.state != RelaySessionState::Pending {
            return Err(NatError::RelayRefused {
                reason: format!("session {session_id} not in pending state"),
            });
        }

        session.state = RelaySessionState::Active;
        session.last_activity = Instant::now();
        info!(session_id = session_id, "relay session activated");
        Ok(())
    }

    /// Record bytes relayed through a session.
    pub fn record_relay(
        &mut self,
        session_id: u64,
        bytes: u64,
        from_a: bool,
    ) -> Result<(), NatError> {
        let session = self.sessions.get_mut(&session_id).ok_or(NatError::RelayRefused {
            reason: format!("session {session_id} not found"),
        })?;

        if session.state != RelaySessionState::Active {
            return Err(NatError::RelayRefused {
                reason: "session not active".into(),
            });
        }

        // Check bandwidth limit (only after warmup period to avoid
        // false positives from sub-millisecond elapsed times)
        let elapsed = session.created_at.elapsed();
        if elapsed.as_secs() >= 1 {
            let bps = session.bytes_relayed as f64 / elapsed.as_secs_f64();
            if bps > self.config.max_bandwidth_bps as f64 {
                return Err(NatError::RelayRefused {
                    reason: "bandwidth limit exceeded".into(),
                });
            }
        }

        session.bytes_relayed += bytes;
        session.last_activity = Instant::now();

        if from_a {
            session.peer_a.bytes_sent += bytes;
            session.peer_b.bytes_received += bytes;
        } else {
            session.peer_b.bytes_sent += bytes;
            session.peer_a.bytes_received += bytes;
        }

        Ok(())
    }

    /// Close a relay session.
    pub fn close_session(&mut self, session_id: u64) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.state = RelaySessionState::Closed;
            debug!(
                session_id = session_id,
                bytes_relayed = session.bytes_relayed,
                "relay session closed"
            );
        }
    }

    /// Get session info.
    pub fn get_session(&self, session_id: u64) -> Option<&RelaySession> {
        self.sessions.get(&session_id)
    }

    /// Get the forwarding address for a packet from a specific peer.
    pub fn get_forward_addr(
        &self,
        session_id: u64,
        from_peer: &PeerId,
    ) -> Option<SocketAddr> {
        let session = self.sessions.get(&session_id)?;
        if session.state != RelaySessionState::Active {
            return None;
        }

        if session.peer_a.peer_id == *from_peer {
            Some(session.peer_b.addr)
        } else if session.peer_b.peer_id == *from_peer {
            Some(session.peer_a.addr)
        } else {
            None
        }
    }

    /// Clean up expired and closed sessions.
    pub fn cleanup_expired(&mut self) -> usize {
        let idle_timeout = self.config.idle_timeout;
        let max_duration = self.config.max_duration;

        let expired: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.state == RelaySessionState::Closed
                    || s.last_activity.elapsed() > idle_timeout
                    || s.created_at.elapsed() > max_duration
            })
            .map(|(id, _)| *id)
            .collect();

        let count = expired.len();
        for id in expired {
            self.sessions.remove(&id);
        }

        if count > 0 {
            debug!(count = count, "cleaned up expired relay sessions");
        }
        count
    }

    /// Number of active sessions.
    pub fn active_sessions(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state == RelaySessionState::Active)
            .count()
    }

    /// Total sessions (all states).
    pub fn total_sessions(&self) -> usize {
        self.sessions.len()
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
    fn create_and_activate_session() {
        let mut relay = RelayService::with_defaults();

        let session_id = relay
            .create_session(peer(1), addr(9001), peer(2), addr(9002))
            .unwrap();

        assert_eq!(relay.total_sessions(), 1);
        let session = relay.get_session(session_id).unwrap();
        assert_eq!(session.state, RelaySessionState::Pending);

        relay.activate_session(session_id).unwrap();
        let session = relay.get_session(session_id).unwrap();
        assert_eq!(session.state, RelaySessionState::Active);
    }

    #[test]
    fn relay_forwarding() {
        let mut relay = RelayService::with_defaults();

        let id = relay
            .create_session(peer(1), addr(9001), peer(2), addr(9002))
            .unwrap();
        relay.activate_session(id).unwrap();

        // Peer A sends → should forward to Peer B's address
        let fwd = relay.get_forward_addr(id, &peer(1));
        assert_eq!(fwd, Some(addr(9002)));

        // Peer B sends → should forward to Peer A's address
        let fwd = relay.get_forward_addr(id, &peer(2));
        assert_eq!(fwd, Some(addr(9001)));

        // Unknown peer → None
        let fwd = relay.get_forward_addr(id, &peer(3));
        assert_eq!(fwd, None);
    }

    #[test]
    fn record_relay_bytes() {
        let mut relay = RelayService::with_defaults();

        let id = relay
            .create_session(peer(1), addr(9001), peer(2), addr(9002))
            .unwrap();
        relay.activate_session(id).unwrap();

        relay.record_relay(id, 1024, true).unwrap();
        relay.record_relay(id, 512, false).unwrap();

        let session = relay.get_session(id).unwrap();
        assert_eq!(session.bytes_relayed, 1536);
        assert_eq!(session.peer_a.bytes_sent, 1024);
        assert_eq!(session.peer_b.bytes_sent, 512);
    }

    #[test]
    fn capacity_limit() {
        let config = RelayConfig {
            max_sessions: 2,
            ..Default::default()
        };
        let mut relay = RelayService::new(config);

        relay.create_session(peer(1), addr(9001), peer(2), addr(9002)).unwrap();
        relay.create_session(peer(3), addr(9003), peer(4), addr(9004)).unwrap();

        // Third should fail
        let result = relay.create_session(peer(5), addr(9005), peer(6), addr(9006));
        assert!(result.is_err());
    }

    #[test]
    fn close_and_cleanup() {
        let mut relay = RelayService::with_defaults();

        let id1 = relay
            .create_session(peer(1), addr(9001), peer(2), addr(9002))
            .unwrap();
        let _id2 = relay
            .create_session(peer(3), addr(9003), peer(4), addr(9004))
            .unwrap();

        relay.close_session(id1);
        assert_eq!(relay.total_sessions(), 2);

        let cleaned = relay.cleanup_expired();
        assert_eq!(cleaned, 1); // Only the closed one
        assert_eq!(relay.total_sessions(), 1);
    }
}
