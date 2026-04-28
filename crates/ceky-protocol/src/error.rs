//! Protocol error types.

use thiserror::Error;

/// Errors that can occur during protocol encoding/decoding.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid magic bytes: expected 0x{:04X}, got 0x{got:04X}", crate::MAGIC)]
    InvalidMagic { got: u16 },

    #[error("unsupported protocol version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("unknown message type: 0x{code:02X}")]
    UnknownMessageType { code: u8 },

    #[error("payload too large: {size} bytes (max {})", crate::MAX_PAYLOAD_SIZE)]
    PayloadTooLarge { size: u32 },

    #[error("checksum mismatch: expected 0x{expected:08X}, got 0x{got:08X}")]
    ChecksumMismatch { expected: u32, got: u32 },

    #[error("incomplete frame: need {needed} more bytes")]
    Incomplete { needed: usize },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
