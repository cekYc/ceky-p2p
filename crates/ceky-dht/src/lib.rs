//! # ceky-dht
//!
//! Kademlia-based distributed hash table with performance-based peer scoring.
//!
//! ## Architecture
//! ```text
//! ┌──────────────────────────────────────────┐
//! │              RoutingTable                 │
//! │  ┌─────────────────────────────────────┐ │
//! │  │ K-Bucket[0]  (distance 2^0)         │ │
//! │  │ K-Bucket[1]  (distance 2^1)         │ │
//! │  │ ...                                  │ │
//! │  │ K-Bucket[255] (distance 2^255)      │ │
//! │  └─────────────────────────────────────┘ │
//! │         │                                 │
//! │  ┌──────▼──────┐   ┌──────────────────┐ │
//! │  │  PeerInfo    │   │  PeerScore       │ │
//! │  │  (addr, id)  │   │  (latency, etc.) │ │
//! │  └─────────────┘   └──────────────────┘ │
//! └──────────────────────────────────────────┘
//! ```

pub mod peer_info;
pub mod routing;
pub mod operations;

pub use peer_info::{PeerInfo, PeerScore, PeerState};
pub use routing::RoutingTable;

use thiserror::Error;

/// DHT errors.
#[derive(Debug, Error)]
pub enum DhtError {
    #[error("routing table full for bucket {bucket}")]
    BucketFull { bucket: usize },

    #[error("peer not found: {peer_id}")]
    PeerNotFound { peer_id: String },

    #[error("lookup failed: {reason}")]
    LookupFailed { reason: String },

    #[error("store failed: {reason}")]
    StoreFailed { reason: String },

    #[error("invalid key: {reason}")]
    InvalidKey { reason: String },
}
