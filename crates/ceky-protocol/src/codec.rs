//! Zero-copy frame codec for tokio's Framed adapter.
//!
//! # Design Principles
//! - **Zero-copy decode**: `BytesMut::split_to().freeze()` → `Bytes` (no memcpy)
//! - **CRC32C checksum**: Hardware-accelerated on x86_64 (SSE4.2)
//! - **Streaming**: Handles partial reads naturally via tokio-util's Framed

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::trace;

use crate::error::ProtocolError;
use crate::types::{Flags, Frame, FrameHeader, MessageType};
use crate::{HEADER_SIZE, MAGIC, MAX_PAYLOAD_SIZE, VERSION};

/// Zero-copy frame codec.
///
/// Implements `Decoder` and `Encoder` for use with `tokio_util::codec::Framed`.
/// The decoder never copies payload data — it slices directly from the receive buffer.
#[derive(Debug, Default)]
pub struct FrameCodec {
    /// Current decode state — either waiting for header or waiting for payload.
    state: DecodeState,
}

#[derive(Debug, Default)]
enum DecodeState {
    #[default]
    Header,
    Payload(FrameHeader),
}

impl FrameCodec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute CRC32C over header fields (excluding the checksum field itself)
    /// and the payload.
    fn compute_checksum(header: &FrameHeader, payload: &[u8]) -> u32 {
        // Hash header fields in wire order (excluding checksum)
        // magic(2) + ver(1) + type(1) + flags(1) + len(4) + reqid(8) = 17 bytes
        let mut buf = [0u8; 17];
        buf[0..2].copy_from_slice(&header.magic.to_be_bytes());
        buf[2] = header.version;
        buf[3] = header.msg_type.as_byte();
        buf[4] = header.flags.bits();
        buf[5..9].copy_from_slice(&header.payload_len.to_be_bytes());
        buf[9..17].copy_from_slice(&header.request_id.to_be_bytes());

        let header_crc = crc32c::crc32c(&buf);
        // Continue CRC over payload
        crc32c::crc32c_append(header_crc, payload)
    }

    /// Decode header from exactly HEADER_SIZE bytes.
    fn decode_header(src: &[u8]) -> Result<FrameHeader, ProtocolError> {
        debug_assert!(src.len() >= HEADER_SIZE);

        let magic = u16::from_be_bytes([src[0], src[1]]);
        if magic != MAGIC {
            return Err(ProtocolError::InvalidMagic { got: magic });
        }

        let version = src[2];
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion { version });
        }

        let msg_type = MessageType::from_byte(src[3])
            .ok_or(ProtocolError::UnknownMessageType { code: src[3] })?;

        let flags = Flags::new(src[4]);

        let payload_len = u32::from_be_bytes([src[5], src[6], src[7], src[8]]);
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge { size: payload_len });
        }

        let request_id = u64::from_be_bytes([
            src[9], src[10], src[11], src[12],
            src[13], src[14], src[15], src[16],
        ]);

        let checksum = u32::from_be_bytes([src[17], src[18], src[19], src[20]]);

        Ok(FrameHeader {
            magic,
            version,
            msg_type,
            flags,
            payload_len,
            request_id,
            checksum,
        })
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &self.state {
                DecodeState::Header => {
                    if src.len() < HEADER_SIZE {
                        src.reserve(HEADER_SIZE - src.len());
                        return Ok(None);
                    }

                    let header = Self::decode_header(&src[..HEADER_SIZE])?;

                    trace!(
                        msg_type = %header.msg_type,
                        payload_len = header.payload_len,
                        request_id = header.request_id,
                        "decoded frame header"
                    );

                    if header.payload_len == 0 {
                        // No payload — verify checksum and emit frame immediately
                        let computed = Self::compute_checksum(&header, &[]);
                        if computed != header.checksum {
                            return Err(ProtocolError::ChecksumMismatch {
                                expected: header.checksum,
                                got: computed,
                            });
                        }
                        src.advance(HEADER_SIZE);
                        let frame = Frame {
                            header,
                            payload: Bytes::new(),
                        };
                        // State stays Header for next frame
                        return Ok(Some(frame));
                    }

                    // Transition to payload state
                    self.state = DecodeState::Payload(header);
                }
                DecodeState::Payload(header) => {
                    let total = HEADER_SIZE + header.payload_len as usize;

                    if src.len() < total {
                        src.reserve(total - src.len());
                        return Ok(None);
                    }

                    let header = *header;

                    // Verify checksum over payload
                    let payload_start = HEADER_SIZE;
                    let payload_end = payload_start + header.payload_len as usize;
                    let computed = Self::compute_checksum(&header, &src[payload_start..payload_end]);

                    if computed != header.checksum {
                        return Err(ProtocolError::ChecksumMismatch {
                            expected: header.checksum,
                            got: computed,
                        });
                    }

                    // Zero-copy: split the buffer and freeze into Bytes
                    let mut frame_buf = src.split_to(total);
                    frame_buf.advance(HEADER_SIZE);
                    let payload = frame_buf.freeze(); // Zero-copy! Just increments refcount.

                    let frame = Frame { header, payload };

                    trace!(frame = %frame, "decoded complete frame");

                    self.state = DecodeState::Header;
                    return Ok(Some(frame));
                }
            }
        }
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = ProtocolError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = frame.payload.len() as u32;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge { size: payload_len });
        }

        // Compute checksum before writing
        let header_for_crc = FrameHeader {
            checksum: 0, // placeholder, not included in CRC input
            ..frame.header
        };
        let checksum = Self::compute_checksum(&header_for_crc, &frame.payload);

        // Reserve exact space — no waste
        dst.reserve(HEADER_SIZE + frame.payload.len());

        // Write header in network byte order (big endian)
        dst.put_u16(MAGIC);
        dst.put_u8(VERSION);
        dst.put_u8(frame.header.msg_type.as_byte());
        dst.put_u8(frame.header.flags.bits());
        dst.put_u32(payload_len);
        dst.put_u64(frame.header.request_id);
        dst.put_u32(checksum);

        // Write payload (Bytes::clone is O(1) — just refcount increment)
        dst.extend_from_slice(&frame.payload);

        trace!(frame = %frame, wire_size = HEADER_SIZE + frame.payload.len(), "encoded frame");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: encode → decode must produce identical frame.
    #[test]
    fn roundtrip_empty_payload() {
        let mut codec = FrameCodec::new();
        let original = Frame::simple(MessageType::Ping, 0xDEADBEEF);

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(decoded.header.msg_type, MessageType::Ping);
        assert_eq!(decoded.header.request_id, 0xDEADBEEF);
        assert!(decoded.payload.is_empty());
    }

    /// Round-trip with payload data.
    #[test]
    fn roundtrip_with_payload() {
        let mut codec = FrameCodec::new();
        let data = Bytes::from_static(b"cekyP2P raw binary data - no JSON allowed!");
        let original = Frame::new(
            MessageType::Data,
            Flags::empty().with_encrypted(),
            42,
            data.clone(),
        );

        let mut buf = BytesMut::new();
        codec.encode(original, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("should decode");
        assert_eq!(decoded.header.msg_type, MessageType::Data);
        assert!(decoded.header.flags.is_encrypted());
        assert_eq!(decoded.header.request_id, 42);
        assert_eq!(decoded.payload, data);
    }

    /// Partial data should return Ok(None) and not consume the buffer.
    #[test]
    fn partial_header() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::from(&[0xCE, 0x4B][..]); // Only magic, not enough
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 2); // Nothing consumed
    }

    /// Invalid magic should error immediately.
    #[test]
    fn invalid_magic() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::from(&[0xFF, 0xFF, 0x01, 0x02, 0x00,
            0, 0, 0, 0,  // payload len
            0, 0, 0, 0, 0, 0, 0, 0,  // request id
            0, 0, 0, 0,  // checksum
        ][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMagic { .. }));
    }

    /// Payload exceeding MAX_PAYLOAD_SIZE should error.
    #[test]
    fn payload_too_large() {
        let mut codec = FrameCodec::new();
        let huge_len: u32 = MAX_PAYLOAD_SIZE + 1;
        let mut buf = BytesMut::new();
        buf.put_u16(MAGIC);
        buf.put_u8(VERSION);
        buf.put_u8(MessageType::Data.as_byte());
        buf.put_u8(0);
        buf.put_u32(huge_len);
        buf.put_u64(0);
        buf.put_u32(0);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::PayloadTooLarge { .. }));
    }

    /// Corrupted payload should trigger checksum mismatch.
    #[test]
    fn checksum_corruption() {
        let mut codec = FrameCodec::new();
        let data = Bytes::from_static(b"important data");
        let frame = Frame::new(MessageType::Data, Flags::empty(), 1, data);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Corrupt one byte in the payload
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;

        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::ChecksumMismatch { .. }));
    }

    /// Multiple frames in one buffer should decode sequentially.
    #[test]
    fn multiple_frames_in_buffer() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        let f1 = Frame::simple(MessageType::Ping, 1);
        let f2 = Frame::simple(MessageType::Pong, 2);
        let f3 = Frame::new(MessageType::Data, Flags::empty(), 3, Bytes::from_static(b"hello"));

        codec.encode(f1, &mut buf).unwrap();
        codec.encode(f2, &mut buf).unwrap();
        codec.encode(f3, &mut buf).unwrap();

        let d1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(d1.header.msg_type, MessageType::Ping);
        assert_eq!(d1.header.request_id, 1);

        let d2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(d2.header.msg_type, MessageType::Pong);
        assert_eq!(d2.header.request_id, 2);

        let d3 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(d3.header.msg_type, MessageType::Data);
        assert_eq!(d3.payload, &b"hello"[..]);

        // Buffer should be empty now
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    /// All message types should roundtrip correctly.
    #[test]
    fn all_message_types_roundtrip() {
        let types = [
            MessageType::Handshake, MessageType::Ping, MessageType::Pong,
            MessageType::Disconnect, MessageType::FindNode, MessageType::FindNodeResp,
            MessageType::Store, MessageType::StoreResp, MessageType::FindValue,
            MessageType::FindValueResp, MessageType::Data, MessageType::DataAck,
            MessageType::CreditUpdate, MessageType::NatProbe, MessageType::NatProbeResp,
            MessageType::HolePunch, MessageType::HolePunchResp,
            MessageType::RelayRequest, MessageType::RelayData,
        ];

        for (i, &mt) in types.iter().enumerate() {
            let mut codec = FrameCodec::new();
            let frame = Frame::simple(mt, i as u64);
            let mut buf = BytesMut::new();
            codec.encode(frame, &mut buf).unwrap();
            let decoded = codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.header.msg_type, mt, "failed for {mt}");
        }
    }
}
