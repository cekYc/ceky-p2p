//! # ceky-transport
//!
//! TCP/UDP transport layer with connection pooling for cekyP2P.
//! Non-blocking, lock-free, zero-copy.
//!
//! ## Architecture
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌────────────────┐
//! │ TcpTransport │────▶│  Connection   │────▶│ ConnectionPool │
//! │ UdpTransport │     │ (state machine)│     │ (DashMap)      │
//! └─────────────┘     └──────────────┘     └────────────────┘
//!        │                    │                      │
//!        └──── FrameCodec ────┘                      │
//!              (zero-copy)            TransportEvent ─┘
//! ```

pub mod connection;
pub mod pool;
pub mod tcp;
pub mod udp;

use ceky_protocol::Frame;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::mpsc;

/// Events emitted by the transport layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// New peer connected.
    Connected { peer_addr: SocketAddr },
    /// Peer disconnected.
    Disconnected {
        peer_addr: SocketAddr,
        reason: String,
    },
    /// Received a complete frame from a peer.
    FrameReceived {
        peer_addr: SocketAddr,
        frame: Frame,
    },
    /// Transport-level error.
    Error {
        peer_addr: Option<SocketAddr>,
        error: String,
    },
}

/// Transport layer errors.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(#[from] ceky_protocol::ProtocolError),

    #[error("connection closed by peer: {addr}")]
    ConnectionClosed { addr: SocketAddr },

    #[error("connection pool full: max {max} connections")]
    PoolFull { max: usize },

    #[error("peer not found: {addr}")]
    PeerNotFound { addr: SocketAddr },

    #[error("send failed: channel closed")]
    SendFailed,

    #[error("connection timed out: {addr}")]
    Timeout { addr: SocketAddr },
}

/// Shared type for event sender channels.
pub type EventSender = mpsc::UnboundedSender<TransportEvent>;
/// Shared type for event receiver channels.
pub type EventReceiver = mpsc::UnboundedReceiver<TransportEvent>;

/// Create an event channel pair.
pub fn event_channel() -> (EventSender, EventReceiver) {
    mpsc::unbounded_channel()
}
