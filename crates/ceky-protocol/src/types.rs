//! Core protocol types: message types, flags, headers, and frames.

use bytes::Bytes;
use std::fmt;

/// All message types in the cekyP2P protocol.
///
/// Each variant maps to a unique byte on the wire. Grouped by function:
/// - 0x01-0x0F: Connection lifecycle
/// - 0x10-0x1F: DHT operations
/// - 0x20-0x2F: Data transfer
/// - 0x30-0x3F: NAT traversal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    // -- Connection lifecycle --
    Handshake     = 0x01,
    Ping          = 0x02,
    Pong          = 0x03,
    Disconnect    = 0x04,

    // -- DHT operations --
    FindNode      = 0x10,
    FindNodeResp  = 0x11,
    Store         = 0x12,
    StoreResp     = 0x13,
    FindValue     = 0x14,
    FindValueResp = 0x15,

    // -- Data transfer --
    Data          = 0x20,
    DataAck       = 0x21,
    CreditUpdate  = 0x22, // Backpressure: window/credit flow control
    FileOffer     = 0x23,
    FileAccept    = 0x24,
    FileReject    = 0x25,
    FileChunk     = 0x26,
    FileChunkAck  = 0x27,
    FileComplete  = 0x28,
    FileCancel    = 0x29,

    // -- NAT traversal --
    NatProbe      = 0x30,
    NatProbeResp  = 0x31,
    HolePunch     = 0x32,
    HolePunchResp = 0x33,
    RelayRequest  = 0x34,
    RelayData     = 0x35,
}

impl MessageType {
    /// Decode a byte into a MessageType.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::Ping),
            0x03 => Some(Self::Pong),
            0x04 => Some(Self::Disconnect),
            0x10 => Some(Self::FindNode),
            0x11 => Some(Self::FindNodeResp),
            0x12 => Some(Self::Store),
            0x13 => Some(Self::StoreResp),
            0x14 => Some(Self::FindValue),
            0x15 => Some(Self::FindValueResp),
            0x20 => Some(Self::Data),
            0x21 => Some(Self::DataAck),
            0x22 => Some(Self::CreditUpdate),
            0x23 => Some(Self::FileOffer),
            0x24 => Some(Self::FileAccept),
            0x25 => Some(Self::FileReject),
            0x26 => Some(Self::FileChunk),
            0x27 => Some(Self::FileChunkAck),
            0x28 => Some(Self::FileComplete),
            0x29 => Some(Self::FileCancel),
            0x30 => Some(Self::NatProbe),
            0x31 => Some(Self::NatProbeResp),
            0x32 => Some(Self::HolePunch),
            0x33 => Some(Self::HolePunchResp),
            0x34 => Some(Self::RelayRequest),
            0x35 => Some(Self::RelayData),
            _ => None,
        }
    }

    /// Encode as wire byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake     => write!(f, "HANDSHAKE"),
            Self::Ping          => write!(f, "PING"),
            Self::Pong          => write!(f, "PONG"),
            Self::Disconnect    => write!(f, "DISCONNECT"),
            Self::FindNode      => write!(f, "FIND_NODE"),
            Self::FindNodeResp  => write!(f, "FIND_NODE_RESP"),
            Self::Store         => write!(f, "STORE"),
            Self::StoreResp     => write!(f, "STORE_RESP"),
            Self::FindValue     => write!(f, "FIND_VALUE"),
            Self::FindValueResp => write!(f, "FIND_VALUE_RESP"),
            Self::Data          => write!(f, "DATA"),
            Self::DataAck       => write!(f, "DATA_ACK"),
            Self::CreditUpdate  => write!(f, "CREDIT_UPDATE"),
            Self::FileOffer     => write!(f, "FILE_OFFER"),
            Self::FileAccept    => write!(f, "FILE_ACCEPT"),
            Self::FileReject    => write!(f, "FILE_REJECT"),
            Self::FileChunk     => write!(f, "FILE_CHUNK"),
            Self::FileChunkAck  => write!(f, "FILE_CHUNK_ACK"),
            Self::FileComplete  => write!(f, "FILE_COMPLETE"),
            Self::FileCancel    => write!(f, "FILE_CANCEL"),
            Self::NatProbe      => write!(f, "NAT_PROBE"),
            Self::NatProbeResp  => write!(f, "NAT_PROBE_RESP"),
            Self::HolePunch     => write!(f, "HOLE_PUNCH"),
            Self::HolePunchResp => write!(f, "HOLE_PUNCH_RESP"),
            Self::RelayRequest  => write!(f, "RELAY_REQUEST"),
            Self::RelayData     => write!(f, "RELAY_DATA"),
        }
    }
}

/// Frame flags bitfield.
///
/// ```text
/// Bit 0: Encrypted (payload is AEAD encrypted)
/// Bit 1: Compressed (payload is compressed)
/// Bit 2: Fragmented (part of a multi-frame message)
/// Bit 3: Priority (high-priority message, skip queue)
/// Bit 4-7: Reserved
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(u8);

impl Flags {
    pub const ENCRYPTED: u8   = 0b0000_0001;
    pub const COMPRESSED: u8  = 0b0000_0010;
    pub const FRAGMENTED: u8  = 0b0000_0100;
    pub const PRIORITY: u8    = 0b0000_1000;

    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_encrypted(self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }

    pub const fn is_compressed(self) -> bool {
        self.0 & Self::COMPRESSED != 0
    }

    pub const fn is_fragmented(self) -> bool {
        self.0 & Self::FRAGMENTED != 0
    }

    pub const fn is_priority(self) -> bool {
        self.0 & Self::PRIORITY != 0
    }

    pub const fn with_encrypted(self) -> Self {
        Self(self.0 | Self::ENCRYPTED)
    }

    pub const fn with_compressed(self) -> Self {
        Self(self.0 | Self::COMPRESSED)
    }

    pub const fn with_fragmented(self) -> Self {
        Self(self.0 | Self::FRAGMENTED)
    }

    pub const fn with_priority(self) -> Self {
        Self(self.0 | Self::PRIORITY)
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.is_encrypted()  { parts.push("ENC"); }
        if self.is_compressed() { parts.push("CMP"); }
        if self.is_fragmented() { parts.push("FRG"); }
        if self.is_priority()   { parts.push("PRI"); }
        if parts.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", parts.join("|"))
        }
    }
}

/// Decoded frame header (20 bytes on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub magic: u16,
    pub version: u8,
    pub msg_type: MessageType,
    pub flags: Flags,
    pub payload_len: u32,
    pub request_id: u64,
    pub checksum: u32,
}

/// Complete protocol frame: header + zero-copy payload.
///
/// The payload is stored as `bytes::Bytes` — reference-counted,
/// zero-copy sliceable. No memcpy when passing between tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Bytes,
}

impl Frame {
    /// Create a new frame with the given message type and payload.
    pub fn new(msg_type: MessageType, flags: Flags, request_id: u64, payload: Bytes) -> Self {
        let header = FrameHeader {
            magic: crate::MAGIC,
            version: crate::VERSION,
            msg_type,
            flags,
            payload_len: payload.len() as u32,
            request_id,
            checksum: 0, // Computed during encoding
        };
        Self { header, payload }
    }

    /// Create a simple frame with no flags and empty payload.
    pub fn simple(msg_type: MessageType, request_id: u64) -> Self {
        Self::new(msg_type, Flags::empty(), request_id, Bytes::new())
    }

    /// Total wire size of this frame.
    pub fn wire_size(&self) -> usize {
        crate::HEADER_SIZE + self.payload.len()
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Frame[{} flags={} req={:#x} payload={}B]",
            self.header.msg_type,
            self.header.flags,
            self.header.request_id,
            self.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_roundtrip() {
        for code in 0u8..=255 {
            if let Some(mt) = MessageType::from_byte(code) {
                assert_eq!(mt.as_byte(), code);
            }
        }
    }

    #[test]
    fn flags_composition() {
        let f = Flags::empty().with_encrypted().with_priority();
        assert!(f.is_encrypted());
        assert!(!f.is_compressed());
        assert!(!f.is_fragmented());
        assert!(f.is_priority());
        assert_eq!(f.bits(), 0b0000_1001);
    }

    #[test]
    fn frame_display() {
        let frame = Frame::simple(MessageType::Ping, 42);
        let s = format!("{frame}");
        assert!(s.contains("PING"));
    }
}
