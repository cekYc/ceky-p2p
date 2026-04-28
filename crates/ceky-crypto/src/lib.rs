//! # ceky-crypto
//!
//! Zero-trust identity system and Noise protocol handshake for cekyP2P.
//!
//! ## Architecture
//! ```text
//! ┌─────────────────────────────────┐
//! │         Node Identity           │
//! ├─────────────────────────────────┤
//! │  Ed25519 Keypair (long-term)    │  ← Permanent identity
//! │  X25519 Static Key (Noise)      │  ← Noise handshake key
//! │  PeerId = SHA-256(Ed25519 PK)   │  ← 32-byte unique ID
//! │  Ed25519 Sig over X25519 PK     │  ← Identity binding proof
//! └─────────────────────────────────┘
//!          │
//!          ▼
//! ┌─────────────────────────────────┐
//! │     Noise XX Handshake          │
//! │  → Encrypted Tunnel             │
//! │  → ChaChaPoly1305 session keys  │
//! │  → Forward secrecy              │
//! └─────────────────────────────────┘
//! ```

pub mod error;
pub mod identity;
pub mod noise;
pub mod session;

pub use error::CryptoError;
pub use identity::{Identity, PeerId};
pub use noise::NoiseHandshake;
pub use session::SecureSession;
