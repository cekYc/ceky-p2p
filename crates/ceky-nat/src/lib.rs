//! # ceky-nat
//!
//! NAT traversal subsystem for cekyP2P.
//!
//! ## Architecture
//! ```text
//! ┌────────────────────────────────────────────┐
//! │            NAT Traversal Pipeline           │
//! │                                             │
//! │  1. STUN Probe  → Discover external IP:port │
//! │  2. NAT Detect  → Classify NAT type         │
//! │  3. Hole Punch  → Direct P2P via UDP        │
//! │  4. Relay       → Fallback via SuperNode    │
//! │                                             │
//! │  NatType::None ──────► Direct connection     │
//! │  NatType::FullCone ──► Hole punch (easy)     │
//! │  NatType::Restricted ► Hole punch (medium)   │
//! │  NatType::Symmetric ─► Relay only            │
//! └────────────────────────────────────────────┘
//! ```

pub mod stun;
pub mod detection;
pub mod hole_punch;
pub mod relay;

pub use detection::{NatDetector, NatType, NatInfo};
pub use hole_punch::HolePuncher;
pub use relay::RelayService;
pub use stun::StunClient;

use thiserror::Error;

/// NAT traversal errors.
#[derive(Debug, Error)]
pub enum NatError {
    #[error("STUN request failed: {reason}")]
    StunFailed { reason: String },

    #[error("STUN response timeout after {timeout_ms}ms")]
    StunTimeout { timeout_ms: u64 },

    #[error("hole punch failed: {reason}")]
    HolePunchFailed { reason: String },

    #[error("relay refused: {reason}")]
    RelayRefused { reason: String },

    #[error("NAT type is symmetric — direct connection impossible")]
    SymmetricNat,

    #[error("no STUN servers configured")]
    NoStunServers,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
