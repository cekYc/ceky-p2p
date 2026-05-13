//! File transfer message formats and helpers.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

pub const TRANSFER_VERSION: u8 = 1;
pub const TRANSFER_ID_LEN: usize = 16;
pub const FILE_HASH_LEN: usize = 32;
pub const MAX_FILE_NAME_LEN: u16 = 255;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("unsupported transfer version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("buffer too short: need {needed} bytes, got {got}")]
    BufferTooShort { needed: usize, got: usize },

    #[error("invalid field: {field}")]
    InvalidField { field: &'static str },

    #[error("invalid utf-8 in file name")]
    InvalidFileName,

    #[error("unknown enum value for {field}: 0x{value:02X}")]
    UnknownEnum { field: &'static str, value: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId([u8; TRANSFER_ID_LEN]);

impl TransferId {
    pub fn from_bytes(bytes: [u8; TRANSFER_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    pub fn to_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; TRANSFER_ID_LEN] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOffer {
    pub transfer_id: TransferId,
    pub file_name: String,
    pub file_size: u64,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub file_hash: [u8; FILE_HASH_LEN],
}

impl FileOffer {
    pub fn new(
        transfer_id: TransferId,
        file_name: String,
        file_size: u64,
        chunk_size: u32,
        file_hash: [u8; FILE_HASH_LEN],
    ) -> Result<Self, TransferError> {
        if chunk_size == 0 {
            return Err(TransferError::InvalidField { field: "chunk_size" });
        }
        let expected_chunks = compute_total_chunks(file_size, chunk_size);
        if total_chunks != expected_chunks {
            return Err(TransferError::InvalidField { field: "total_chunks" });
        }
        if file_name.len() > MAX_FILE_NAME_LEN as usize {
            return Err(TransferError::InvalidField { field: "file_name" });
        }
        let total_chunks = compute_total_chunks(file_size, chunk_size);
        Ok(Self {
            transfer_id,
            file_name,
            file_size,
            chunk_size,
            total_chunks,
            file_hash,
        })
    }

    pub fn encode(&self) -> Bytes {
        let name_bytes = self.file_name.as_bytes();
        let mut buf = BytesMut::with_capacity(
            1 + TRANSFER_ID_LEN + 8 + 4 + 4 + FILE_HASH_LEN + 2 + name_bytes.len(),
        );
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.put_u64(self.file_size);
        buf.put_u32(self.chunk_size);
        buf.put_u32(self.total_chunks);
        buf.extend_from_slice(&self.file_hash);
        buf.put_u16(name_bytes.len() as u16);
        buf.extend_from_slice(name_bytes);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, TransferError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + 8 + 4 + 4 + FILE_HASH_LEN + 2)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let file_size = buf.get_u64();
        let chunk_size = buf.get_u32();
        let total_chunks = buf.get_u32();
        let file_hash = read_fixed::<FILE_HASH_LEN>(&mut buf)?;
        let name_len = buf.get_u16() as usize;

        if name_len > MAX_FILE_NAME_LEN as usize {
            return Err(TransferError::InvalidField { field: "file_name" });
        }

        ensure_remaining(&buf, name_len)?;
        let name_bytes = buf.copy_to_bytes(name_len);
        let file_name = std::str::from_utf8(&name_bytes)
            .map_err(|_| TransferError::InvalidFileName)?
            .to_string();

        if chunk_size == 0 {
            return Err(TransferError::InvalidField { field: "chunk_size" });
        }

        Ok(Self {
            transfer_id,
            file_name,
            file_size,
            chunk_size,
            total_chunks,
            file_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccept {
    pub transfer_id: TransferId,
    pub resume: bool,
    pub missing_bitmap: Vec<u8>,
}

impl FileAccept {
    pub fn new(transfer_id: TransferId, missing_bitmap: Vec<u8>) -> Self {
        let resume = !missing_bitmap.is_empty();
        Self {
            transfer_id,
            resume,
            missing_bitmap,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + TRANSFER_ID_LEN + 1 + 4 + self.missing_bitmap.len());
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.put_u8(self.resume as u8);
        buf.put_u32(self.missing_bitmap.len() as u32);
        buf.extend_from_slice(&self.missing_bitmap);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, TransferError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + 1 + 4)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let resume = buf.get_u8() != 0;
        let bitmap_len = buf.get_u32() as usize;

        if !resume && bitmap_len != 0 {
            return Err(TransferError::InvalidField { field: "missing_bitmap" });
        }

        ensure_remaining(&buf, bitmap_len)?;
        let missing_bitmap = buf.copy_to_bytes(bitmap_len).to_vec();

        Ok(Self {
            transfer_id,
            resume,
            missing_bitmap,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileRejectReason {
    Declined = 1,
    Busy = 2,
    NotFound = 3,
    Protocol = 4,
    Internal = 5,
}

impl FileRejectReason {
    pub fn from_byte(value: u8) -> Result<Self, TransferError> {
        match value {
            1 => Ok(Self::Declined),
            2 => Ok(Self::Busy),
            3 => Ok(Self::NotFound),
            4 => Ok(Self::Protocol),
            5 => Ok(Self::Internal),
            other => Err(TransferError::UnknownEnum {
                field: "FileRejectReason",
                value: other,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReject {
    pub transfer_id: TransferId,
    pub reason: FileRejectReason,
}

impl FileReject {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + TRANSFER_ID_LEN + 1);
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.put_u8(self.reason as u8);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, TransferError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + 1)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let reason = FileRejectReason::from_byte(buf.get_u8())?;

        Ok(Self { transfer_id, reason })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunk {
    pub transfer_id: TransferId,
    pub chunk_index: u32,
    pub chunk_hash: [u8; FILE_HASH_LEN],
    pub data: Bytes,
}

impl FileChunk {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            1 + TRANSFER_ID_LEN + 4 + FILE_HASH_LEN + self.data.len(),
        );
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.put_u32(self.chunk_index);
        buf.extend_from_slice(&self.chunk_hash);
        buf.extend_from_slice(&self.data);
        buf.freeze()
    }

    pub fn decode(payload: Bytes) -> Result<Self, TransferError> {
        let mut buf = payload;
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + 4 + FILE_HASH_LEN)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let chunk_index = buf.get_u32();
        let chunk_hash = read_fixed::<FILE_HASH_LEN>(&mut buf)?;
        let data = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            transfer_id,
            chunk_index,
            chunk_hash,
            data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkAckStatus {
    Ok = 0,
    BadHash = 1,
    Cancelled = 2,
}

impl ChunkAckStatus {
    pub fn from_byte(value: u8) -> Result<Self, TransferError> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::BadHash),
            2 => Ok(Self::Cancelled),
            other => Err(TransferError::UnknownEnum {
                field: "ChunkAckStatus",
                value: other,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunkAck {
    pub transfer_id: TransferId,
    pub chunk_index: u32,
    pub status: ChunkAckStatus,
}

impl FileChunkAck {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + TRANSFER_ID_LEN + 4 + 1);
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.put_u32(self.chunk_index);
        buf.put_u8(self.status as u8);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, TransferError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + 4 + 1)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let chunk_index = buf.get_u32();
        let status = ChunkAckStatus::from_byte(buf.get_u8())?;

        Ok(Self {
            transfer_id,
            chunk_index,
            status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileComplete {
    pub transfer_id: TransferId,
    pub file_hash: [u8; FILE_HASH_LEN],
}

impl FileComplete {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + TRANSFER_ID_LEN + FILE_HASH_LEN);
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.extend_from_slice(&self.file_hash);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, TransferError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + FILE_HASH_LEN)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let file_hash = read_fixed::<FILE_HASH_LEN>(&mut buf)?;

        Ok(Self {
            transfer_id,
            file_hash,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileCancelReason {
    User = 1,
    Error = 2,
    Timeout = 3,
}

impl FileCancelReason {
    pub fn from_byte(value: u8) -> Result<Self, TransferError> {
        match value {
            1 => Ok(Self::User),
            2 => Ok(Self::Error),
            3 => Ok(Self::Timeout),
            other => Err(TransferError::UnknownEnum {
                field: "FileCancelReason",
                value: other,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCancel {
    pub transfer_id: TransferId,
    pub reason: FileCancelReason,
}

impl FileCancel {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + TRANSFER_ID_LEN + 1);
        buf.put_u8(TRANSFER_VERSION);
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.put_u8(self.reason as u8);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, TransferError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + TRANSFER_ID_LEN + 1)?;

        let version = buf.get_u8();
        if version != TRANSFER_VERSION {
            return Err(TransferError::UnsupportedVersion { version });
        }

        let transfer_id = read_transfer_id(&mut buf)?;
        let reason = FileCancelReason::from_byte(buf.get_u8())?;

        Ok(Self { transfer_id, reason })
    }
}

pub fn bitmap_len(chunk_count: u32) -> usize {
    ((chunk_count as usize) + 7) / 8
}

pub fn bitmap_is_missing(bitmap: &[u8], chunk_index: u32) -> bool {
    let byte_index = (chunk_index / 8) as usize;
    let bit_index = (chunk_index % 8) as u8;
    if byte_index >= bitmap.len() {
        return false;
    }
    (bitmap[byte_index] & (1 << bit_index)) != 0
}

pub fn bitmap_set_missing(bitmap: &mut [u8], chunk_index: u32, missing: bool) {
    let byte_index = (chunk_index / 8) as usize;
    let bit_index = (chunk_index % 8) as u8;
    if byte_index >= bitmap.len() {
        return;
    }
    let mask = 1u8 << bit_index;
    if missing {
        bitmap[byte_index] |= mask;
    } else {
        bitmap[byte_index] &= !mask;
    }
}

pub fn compute_total_chunks(file_size: u64, chunk_size: u32) -> u32 {
    if file_size == 0 || chunk_size == 0 {
        return 0;
    }
    let size = chunk_size as u64;
    ((file_size - 1) / size + 1) as u32
}

fn ensure_remaining(buf: &impl Buf, needed: usize) -> Result<(), TransferError> {
    let got = buf.remaining();
    if got < needed {
        return Err(TransferError::BufferTooShort { needed, got });
    }
    Ok(())
}

fn read_transfer_id(buf: &mut Bytes) -> Result<TransferId, TransferError> {
    ensure_remaining(buf, TRANSFER_ID_LEN)?;
    let mut id = [0u8; TRANSFER_ID_LEN];
    buf.copy_to_slice(&mut id);
    Ok(TransferId::from_bytes(id))
}

fn read_fixed<const N: usize>(buf: &mut Bytes) -> Result<[u8; N], TransferError> {
    ensure_remaining(buf, N)?;
    let mut data = [0u8; N];
    buf.copy_to_slice(&mut data);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_offer_roundtrip() {
        let transfer_id = TransferId::from_u128(0xAABBCCDDEEFF00112233445566778899);
        let file_hash = [0xAB; FILE_HASH_LEN];
        let offer = FileOffer::new(
            transfer_id,
            "test.bin".to_string(),
            10_000,
            1024,
            file_hash,
        )
        .expect("valid offer");

        let encoded = offer.encode();
        let decoded = FileOffer::decode(&encoded).expect("decode offer");
        assert_eq!(decoded, offer);
    }

    #[test]
    fn file_accept_roundtrip() {
        let transfer_id = TransferId::from_u128(0x0102030405060708090A0B0C0D0E0F10);
        let mut bitmap = vec![0u8; 2];
        bitmap_set_missing(&mut bitmap, 3, true);
        bitmap_set_missing(&mut bitmap, 9, true);

        let accept = FileAccept::new(transfer_id, bitmap.clone());
        let encoded = accept.encode();
        let decoded = FileAccept::decode(&encoded).expect("decode accept");

        assert_eq!(decoded.transfer_id.to_u128(), accept.transfer_id.to_u128());
        assert_eq!(decoded.resume, true);
        assert_eq!(decoded.missing_bitmap, bitmap);
    }

    #[test]
    fn file_chunk_roundtrip() {
        let transfer_id = TransferId::from_u128(0x0F0E0D0C0B0A09080706050403020100);
        let chunk_hash = [0x11; FILE_HASH_LEN];
        let data = Bytes::from_static(b"chunk-data");

        let chunk = FileChunk {
            transfer_id,
            chunk_index: 7,
            chunk_hash,
            data: data.clone(),
        };

        let encoded = chunk.encode();
        let decoded = FileChunk::decode(encoded).expect("decode chunk");

        assert_eq!(decoded.transfer_id.to_u128(), chunk.transfer_id.to_u128());
        assert_eq!(decoded.chunk_index, 7);
        assert_eq!(decoded.chunk_hash, chunk_hash);
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn bitmap_helpers() {
        let mut bitmap = vec![0u8; 1];
        assert!(!bitmap_is_missing(&bitmap, 0));
        bitmap_set_missing(&mut bitmap, 0, true);
        assert!(bitmap_is_missing(&bitmap, 0));
        bitmap_set_missing(&mut bitmap, 0, false);
        assert!(!bitmap_is_missing(&bitmap, 0));
    }
}
