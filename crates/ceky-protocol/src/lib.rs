//! # ceky-protocol
//!
//! Binary wire protocol for cekyP2P network.
//!
//! Zero-copy frame encoding/decoding with CRC32C integrity checks.
//! Every byte is accounted for — no JSON, no HTTP, no waste.
//!
//! ## Wire Format
//! ```text
//! ┌──────────┬──────┬──────┬───────┬────────────────┬────────────┬──────────┬─────────┐
//! │ Magic 2B │ V 1B │ T 1B │ F 1B  │ PayloadLen 4B  │ ReqId 8B   │ CRC32 4B │ Payload │
//! └──────────┴──────┴──────┴───────┴────────────────┴────────────┴──────────┴─────────┘
//! Header: 20 bytes fixed
//! ```

pub mod codec;
pub mod error;
pub mod types;

pub use codec::FrameCodec;
pub use error::ProtocolError;
pub use types::{Flags, Frame, FrameHeader, MessageType};

/// Protocol magic bytes: 0xCE4B ("CEKY" tribute)
pub const MAGIC: u16 = 0xCE4B;

/// Current protocol version
pub const VERSION: u8 = 1;

/// Fixed header size in bytes
/// magic(2) + version(1) + type(1) + flags(1) + payload_len(4) + request_id(8) + checksum(4) = 21
pub const HEADER_SIZE: usize = 21;

/// Maximum payload size (16 MB)
pub const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;
