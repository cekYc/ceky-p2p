//! State definitions for active transfers.

use ceky_protocol::transfer::FILE_HASH_LEN;
use memmap2::{Mmap, MmapMut};
use std::net::SocketAddr;
use std::path::PathBuf;

/// State for a transfer where we are sending a file.
pub struct SendingState {
    pub peer: SocketAddr,
    pub file_map: Mmap,
    pub bitfield: Vec<u8>,
    pub credits: u32,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub current_chunk_idx: u32,
}

/// State for a transfer where we are receiving a file.
pub struct ReceivingState {
    pub peer: SocketAddr,
    pub file_map: MmapMut,
    pub expected_root: [u8; FILE_HASH_LEN],
    pub bitfield: Vec<u8>,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub received_chunks: u32,
    pub file_path: PathBuf,
}

/// The state of an active transfer.
pub enum TransferState {
    Sending(SendingState),
    Receiving(ReceivingState),
}
