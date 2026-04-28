//! Connection state machine with heartbeat (PING/PONG).
//!
//! Each connection tracks its lifecycle state and manages automatic
//! keepalive probing to detect dead peers.
//!
//! ```text
//! ┌───────────┐     ┌──────────────┐     ┌─────────────┐     ┌─────────┐
//! │ Connecting │────▶│ Established  │────▶│   Closing    │────▶│ Closed  │
//! └───────────┘     └──────────────┘     └─────────────┘     └─────────┘
//!                          │  ▲
//!                          │  │
//!                     PING/PONG heartbeat
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// Connection lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// TCP connection established, waiting for handshake.
    Connecting,
    /// Handshake complete, ready for data exchange.
    Established,
    /// Graceful shutdown initiated.
    Closing,
    /// Connection fully closed.
    Closed,
}

/// Configuration for connection behavior.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Interval between PING probes.
    pub heartbeat_interval: Duration,
    /// Max time to wait for a PONG before declaring peer dead.
    pub heartbeat_timeout: Duration,
    /// Max number of missed heartbeats before disconnecting.
    pub max_missed_heartbeats: u32,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(15),
            heartbeat_timeout: Duration::from_secs(5),
            max_missed_heartbeats: 3,
        }
    }
}

/// Tracks the state of a single peer connection.
///
/// This is metadata only — the actual I/O handle (TcpStream, etc.)
/// is managed by the transport layer. This struct tracks lifecycle,
/// timing, and health information.
#[derive(Debug)]
pub struct ConnectionInfo {
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Current connection state.
    pub state: ConnectionState,
    /// When this connection was established.
    pub connected_at: Instant,
    /// Last time we received any data from this peer.
    pub last_recv: Instant,
    /// Last time we sent any data to this peer.
    pub last_send: Instant,
    /// Last time we sent a PING.
    pub last_ping_sent: Option<Instant>,
    /// Number of consecutive missed heartbeats.
    pub missed_heartbeats: u32,
    /// Total bytes received from this peer.
    pub bytes_recv: u64,
    /// Total bytes sent to this peer.
    pub bytes_sent: u64,
    /// Total frames received.
    pub frames_recv: u64,
    /// Total frames sent.
    pub frames_sent: u64,
    /// Connection configuration.
    config: ConnectionConfig,
}

impl ConnectionInfo {
    /// Create a new connection info for the given peer.
    pub fn new(peer_addr: SocketAddr, config: ConnectionConfig) -> Self {
        let now = Instant::now();
        Self {
            peer_addr,
            state: ConnectionState::Connecting,
            connected_at: now,
            last_recv: now,
            last_send: now,
            last_ping_sent: None,
            missed_heartbeats: 0,
            bytes_recv: 0,
            bytes_sent: 0,
            frames_recv: 0,
            frames_sent: 0,
            config,
        }
    }

    /// Transition to Established state.
    pub fn set_established(&mut self) {
        self.state = ConnectionState::Established;
        debug!(peer = %self.peer_addr, "connection established");
    }

    /// Transition to Closing state.
    pub fn set_closing(&mut self) {
        self.state = ConnectionState::Closing;
        debug!(peer = %self.peer_addr, "connection closing");
    }

    /// Transition to Closed state.
    pub fn set_closed(&mut self) {
        self.state = ConnectionState::Closed;
        debug!(peer = %self.peer_addr, "connection closed");
    }

    /// Record that we received data from this peer.
    pub fn record_recv(&mut self, bytes: u64) {
        self.last_recv = Instant::now();
        self.bytes_recv += bytes;
        self.frames_recv += 1;
    }

    /// Record that we sent data to this peer.
    pub fn record_send(&mut self, bytes: u64) {
        self.last_send = Instant::now();
        self.bytes_sent += bytes;
        self.frames_sent += 1;
    }

    /// Record that a PING was sent.
    pub fn record_ping_sent(&mut self) {
        self.last_ping_sent = Some(Instant::now());
        trace!(peer = %self.peer_addr, "heartbeat PING sent");
    }

    /// Record that a PONG was received — reset missed heartbeat counter.
    pub fn record_pong_received(&mut self) {
        self.missed_heartbeats = 0;
        self.last_ping_sent = None;
        self.last_recv = Instant::now();
        trace!(peer = %self.peer_addr, "heartbeat PONG received");
    }

    /// Check if a heartbeat PING should be sent now.
    pub fn should_send_ping(&self) -> bool {
        if self.state != ConnectionState::Established {
            return false;
        }
        // Don't send if we're already waiting for a PONG
        if self.last_ping_sent.is_some() {
            return false;
        }
        self.last_recv.elapsed() >= self.config.heartbeat_interval
    }

    /// Check if the peer is considered dead (too many missed heartbeats).
    pub fn is_dead(&self) -> bool {
        if let Some(ping_time) = self.last_ping_sent {
            if ping_time.elapsed() >= self.config.heartbeat_timeout {
                // PONG timeout — count as missed
                return self.missed_heartbeats + 1 >= self.config.max_missed_heartbeats;
            }
        }
        self.missed_heartbeats >= self.config.max_missed_heartbeats
    }

    /// Record a missed heartbeat (PONG timeout).
    pub fn record_missed_heartbeat(&mut self) {
        self.missed_heartbeats += 1;
        self.last_ping_sent = None;
        warn!(
            peer = %self.peer_addr,
            missed = self.missed_heartbeats,
            max = self.config.max_missed_heartbeats,
            "heartbeat missed"
        );
    }

    /// Connection uptime.
    pub fn uptime(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Idle time since last received data.
    pub fn idle_time(&self) -> Duration {
        self.last_recv.elapsed()
    }

    /// Is this connection in an active (usable) state?
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Established
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)
    }

    #[test]
    fn connection_lifecycle() {
        let mut conn = ConnectionInfo::new(test_addr(), ConnectionConfig::default());
        assert_eq!(conn.state, ConnectionState::Connecting);
        assert!(conn.is_active());

        conn.set_established();
        assert_eq!(conn.state, ConnectionState::Established);
        assert!(conn.is_active());

        conn.set_closing();
        assert_eq!(conn.state, ConnectionState::Closing);
        assert!(!conn.is_active());

        conn.set_closed();
        assert_eq!(conn.state, ConnectionState::Closed);
        assert!(!conn.is_active());
    }

    #[test]
    fn heartbeat_tracking() {
        let config = ConnectionConfig {
            heartbeat_interval: Duration::from_millis(10),
            heartbeat_timeout: Duration::from_millis(50),
            max_missed_heartbeats: 2,
        };
        let mut conn = ConnectionInfo::new(test_addr(), config);
        conn.set_established();

        // Initially shouldn't need ping (just connected)
        assert!(!conn.should_send_ping());

        // After receiving PONG, missed counter resets
        conn.record_ping_sent();
        assert!(!conn.should_send_ping()); // waiting for PONG
        conn.record_pong_received();
        assert_eq!(conn.missed_heartbeats, 0);
    }

    #[test]
    fn dead_peer_detection() {
        let config = ConnectionConfig {
            heartbeat_interval: Duration::from_millis(1),
            heartbeat_timeout: Duration::from_millis(1),
            max_missed_heartbeats: 2,
        };
        let mut conn = ConnectionInfo::new(test_addr(), config);
        conn.set_established();

        assert!(!conn.is_dead());
        conn.record_missed_heartbeat();
        assert!(!conn.is_dead()); // 1 miss, need 2
        conn.record_missed_heartbeat();
        assert!(conn.is_dead()); // 2 misses, dead
    }

    #[test]
    fn byte_accounting() {
        let mut conn = ConnectionInfo::new(test_addr(), ConnectionConfig::default());
        conn.record_recv(100);
        conn.record_recv(200);
        conn.record_send(50);

        assert_eq!(conn.bytes_recv, 300);
        assert_eq!(conn.bytes_sent, 50);
        assert_eq!(conn.frames_recv, 2);
        assert_eq!(conn.frames_sent, 1);
    }
}
