//! Crypto error types.

use thiserror::Error;

/// Errors from the cryptographic subsystem.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("handshake failed: {reason}")]
    HandshakeFailed { reason: String },

    #[error("handshake in unexpected state: expected {expected}, got {got}")]
    InvalidHandshakeState { expected: String, got: String },

    #[error("decryption failed: ciphertext is invalid or tampered")]
    DecryptionFailed,

    #[error("invalid signature: peer identity verification failed")]
    InvalidSignature,

    #[error("invalid peer ID: {reason}")]
    InvalidPeerId { reason: String },

    #[error("nonce overflow: session must be rekeyed")]
    NonceOverflow,

    #[error("replay attack detected: nonce {nonce} already seen")]
    ReplayDetected { nonce: u64 },

    #[error("key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
