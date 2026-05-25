//! TransferManager implementation.

use crate::merkle::{calculate_file_hash, hash_chunk};
use crate::state::{ReceivingState, SendingState, TransferState};
use ceky_crypto::PeerId;
use ceky_protocol::transfer::{
    bitmap_is_missing, bitmap_len, bitmap_set_missing, compute_total_chunks, ChunkAckStatus,
    FileAccept, FileChunk, FileChunkAck, FileOffer, TransferId, FILE_HASH_LEN,
};
use ceky_protocol::{Flags, Frame, MessageType};
use dashmap::DashMap;
use memmap2::MmapOptions;
use std::fs::{File, OpenOptions};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Transfer not found")]
    NotFound,
    #[error("Invalid state for operation")]
    InvalidState,
    #[error("Hash mismatch")]
    BadHash,
}

/// Manages active file transfers (sending and receiving).
pub struct TransferManager {
    active_transfers: Arc<DashMap<TransferId, TransferState>>,
    frame_tx: mpsc::UnboundedSender<(SocketAddr, Frame)>,
    download_dir: PathBuf,
}

impl TransferManager {
    /// Create a new TransferManager.
    pub fn new(download_dir: PathBuf, frame_tx: mpsc::UnboundedSender<(SocketAddr, Frame)>) -> Self {
        std::fs::create_dir_all(&download_dir).unwrap_or_default();
        Self {
            active_transfers: Arc::new(DashMap::new()),
            frame_tx,
            download_dir,
        }
    }

    /// Snapshot of all active transfers for telemetry/UI.
    pub fn snapshot_transfers(&self) -> Vec<(TransferId, String, u32, u32, bool)> {
        let mut snapshot = Vec::new();
        for entry in self.active_transfers.iter() {
            let id = *entry.key();
            let state = entry.value();
            match state {
                TransferState::Sending(s) => {
                    snapshot.push((id, "sending".to_string(), s.total_chunks, s.current_chunk_idx, true));
                }
                TransferState::Receiving(r) => {
                    snapshot.push((id, r.file_path.file_name().unwrap_or_default().to_string_lossy().to_string(), r.total_chunks, r.received_chunks, false));
                }
            }
        }
        snapshot
    }

    /// Initiate a file send offer to a peer.
    /// This is a blocking operation due to initial Merkle hash calculation.
    pub fn offer_file(
        &self,
        peer: SocketAddr,
        file_path: &Path,
        chunk_size: u32,
    ) -> Result<TransferId, TransferError> {
        let file = File::open(file_path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        info!("Calculating Merkle Root for {}...", file_path.display());
        let file_hash = calculate_file_hash(file_path, chunk_size)?;
        let total_chunks = compute_total_chunks(file_size, chunk_size);

        let mmap = unsafe { MmapOptions::new().map(&file)? };

        // Generate random transfer ID
        let mut id_bytes = [0u8; 16];
        getrandom::fill(&mut id_bytes).unwrap_or_default();
        let transfer_id = TransferId::from_bytes(id_bytes);

        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let offer = FileOffer::new(transfer_id, file_name, file_size, chunk_size, file_hash)
            .map_err(|_| TransferError::InvalidState)?;

        let state = SendingState {
            file_map: mmap,
            bitfield: vec![0xff; bitmap_len(total_chunks)], // Assume all missing initially
            credits: 0,
            chunk_size,
            total_chunks,
            current_chunk_idx: 0,
            peer,
        };

        self.active_transfers
            .insert(transfer_id, TransferState::Sending(state));

        // Send FileOffer frame
        let frame = Frame::new(
            MessageType::FileOffer,
            Flags::empty(),
            0,
            bytes::Bytes::from(offer.encode()),
        );
        let _ = self.frame_tx.send((peer, frame));

        info!(
            "Offered file {} to peer {}. Transfer ID: {:?}",
            file_path.display(),
            peer,
            transfer_id
        );

        Ok(transfer_id)
    }

    /// Process an incoming FileOffer.
    pub fn handle_offer(&self, peer: SocketAddr, offer: FileOffer) -> Result<(), TransferError> {
        info!(
            "Received file offer: {} ({} bytes) from {}",
            offer.file_name, offer.file_size, peer
        );

        let path = self.download_dir.join(&offer.file_name);

        // Pre-allocate the file on disk
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        file.set_len(offer.file_size)?;

        let mmap = unsafe { MmapOptions::new().map_mut(&file)? };

        let state = ReceivingState {
            file_map: mmap,
            expected_root: offer.file_hash,
            bitfield: vec![0xff; bitmap_len(offer.total_chunks)], // 1s mean missing
            chunk_size: offer.chunk_size,
            total_chunks: offer.total_chunks,
            received_chunks: 0,
            file_path: path,
            peer,
        };

        self.active_transfers
            .insert(offer.transfer_id, TransferState::Receiving(state));

        // Send FileAccept
        let accept = ceky_protocol::transfer::FileAccept::new(
            offer.transfer_id,
            vec![0xff; bitmap_len(offer.total_chunks)],
        );
        let frame = Frame::new(
            MessageType::FileAccept,
            Flags::empty(),
            0,
            bytes::Bytes::from(accept.encode()),
        );
        let _ = self.frame_tx.send((peer, frame));

        // Send initial CreditUpdate (e.g. 50 chunks window)
        // For simplicity, we encode the credits in payload as little-endian u32
        let credits: u32 = 50;
        let frame = Frame::new(
            MessageType::CreditUpdate,
            Flags::empty(),
            0, // Request ID doesn't matter here, or we could use it for transfer_id but we don't have enough space.
               // We will use payload for transfer_id + credits.
            bytes::Bytes::from({
                let mut buf = Vec::new();
                buf.extend_from_slice(offer.transfer_id.as_bytes());
                buf.extend_from_slice(&credits.to_le_bytes());
                buf
            }),
        );
        let _ = self.frame_tx.send((peer, frame));

        Ok(())
    }

    /// Process an incoming FileAccept.
    pub fn handle_accept(&self, accept: FileAccept) -> Result<(), TransferError> {
        if let Some(mut transfer) = self.active_transfers.get_mut(&accept.transfer_id) {
            if let TransferState::Sending(ref mut state) = *transfer {
                info!("Transfer {} accepted by peer", accept.transfer_id.to_u128());
                state.bitfield = accept.missing_bitmap;
                // We don't start pumping here. We wait for CreditUpdate to grant us credits.
                return Ok(());
            }
        }
        Err(TransferError::NotFound)
    }

    /// Process incoming CreditUpdate.
    pub fn handle_credit_update(
        &self,
        transfer_id: TransferId,
        credits: u32,
    ) -> Result<(), TransferError> {
        if let Some(mut transfer) = self.active_transfers.get_mut(&transfer_id) {
            if let TransferState::Sending(ref mut state) = *transfer {
                state.credits += credits;
                debug!(
                    "Received {} credits for transfer {}. Total: {}",
                    credits,
                    transfer_id.to_u128(),
                    state.credits
                );
            }
        }
        
        // Pump send loop
        self.pump_send(transfer_id);
        
        Ok(())
    }

    /// Process an incoming FileChunk.
    pub fn handle_chunk(&self, chunk: FileChunk) -> Result<(), TransferError> {
        let mut completed = false;
        let mut peer = None;

        if let Some(mut transfer) = self.active_transfers.get_mut(&chunk.transfer_id) {
            if let TransferState::Receiving(ref mut state) = *transfer {
                peer = Some(state.peer);
                // Verify hash
                let calculated_hash = hash_chunk(&chunk.data);
                if calculated_hash != chunk.chunk_hash {
                    warn!("Chunk hash mismatch for index {}", chunk.chunk_index);
                    // Send NACK
                    let ack = FileChunkAck {
                        transfer_id: chunk.transfer_id,
                        chunk_index: chunk.chunk_index,
                        status: ChunkAckStatus::BadHash,
                    };
                    let frame = Frame::new(
                        MessageType::FileChunkAck,
                        Flags::empty(),
                        0,
                        bytes::Bytes::from(ack.encode()),
                    );
                    let _ = self.frame_tx.send((state.peer, frame));
                    return Err(TransferError::BadHash);
                }

                // Write data to mmap via pointer arithmetic (zero-copy from network buffer into disk cache)
                let start = (chunk.chunk_index * state.chunk_size) as usize;
                let end = start + chunk.data.len();
                if end <= state.file_map.len() {
                    state.file_map[start..end].copy_from_slice(&chunk.data);
                    
                    // Mark as received in bitfield
                    bitmap_set_missing(&mut state.bitfield, chunk.chunk_index, false);
                    state.received_chunks += 1;

                    // Send ACK
                    let ack = FileChunkAck {
                        transfer_id: chunk.transfer_id,
                        chunk_index: chunk.chunk_index,
                        status: ChunkAckStatus::Ok,
                    };
                    let frame = Frame::new(
                        MessageType::FileChunkAck,
                        Flags::empty(),
                        0,
                        bytes::Bytes::from(ack.encode()),
                    );
                    let _ = self.frame_tx.send((state.peer, frame));

                    // Send credit update every chunk or batch to keep sliding window moving
                    let credit_msg = {
                        let mut buf = Vec::new();
                        buf.extend_from_slice(chunk.transfer_id.as_bytes());
                        buf.extend_from_slice(&1u32.to_le_bytes()); // Give 1 credit back
                        buf
                    };
                    let frame = Frame::new(
                        MessageType::CreditUpdate,
                        Flags::empty(),
                        0,
                        bytes::Bytes::from(credit_msg),
                    );
                    let _ = self.frame_tx.send((state.peer, frame));

                    if state.received_chunks == state.total_chunks {
                        completed = true;
                    }
                }
            }
        } else {
            return Err(TransferError::NotFound);
        }

        if completed {
            info!("Transfer {} completed successfully!", chunk.transfer_id.to_u128());
            // Sync mmap to disk
            if let Some(mut transfer) = self.active_transfers.get_mut(&chunk.transfer_id) {
                if let TransferState::Receiving(ref mut state) = *transfer {
                    let _ = state.file_map.flush();
                }
            }
            self.active_transfers.remove(&chunk.transfer_id);
            // Optionally send FileComplete message
            if let Some(p) = peer {
                let complete = ceky_protocol::transfer::FileComplete {
                    transfer_id: chunk.transfer_id,
                    file_hash: [0u8; FILE_HASH_LEN], // We could re-hash the file, but chunk hashes were validated
                };
                let frame = Frame::new(
                    MessageType::FileComplete,
                    Flags::empty(),
                    0,
                    bytes::Bytes::from(complete.encode()),
                );
                let _ = self.frame_tx.send((p, frame));
            }
        }

        Ok(())
    }

    /// Process incoming FileChunkAck.
    pub fn handle_chunk_ack(&self, ack: FileChunkAck) -> Result<(), TransferError> {
        if let Some(mut transfer) = self.active_transfers.get_mut(&ack.transfer_id) {
            if let TransferState::Sending(ref mut state) = *transfer {
                if ack.status == ChunkAckStatus::BadHash {
                    // Mark as missing to retransmit
                    bitmap_set_missing(&mut state.bitfield, ack.chunk_index, true);
                    
                    // Rewind if necessary to retransmit sooner, or just let the loop find it later
                    if ack.chunk_index < state.current_chunk_idx {
                        state.current_chunk_idx = ack.chunk_index;
                    }
                }
                
                // Keep pumping
                self.pump_send(ack.transfer_id);
            }
        }
        Ok(())
    }

    /// Pump sending chunks based on available credits and missing bitfield.
    pub fn pump_send(&self, transfer_id: TransferId) {
        if let Some(mut transfer) = self.active_transfers.get_mut(&transfer_id) {
            if let TransferState::Sending(ref mut state) = *transfer {
                while state.credits > 0 && state.current_chunk_idx < state.total_chunks {
                    if bitmap_is_missing(&state.bitfield, state.current_chunk_idx) {
                        let start = (state.current_chunk_idx * state.chunk_size) as usize;
                        let end = std::cmp::min(
                            start + state.chunk_size as usize,
                            state.file_map.len(),
                        );
                        let data_slice = &state.file_map[start..end];

                        let chunk_hash = hash_chunk(data_slice);
                        let chunk = FileChunk {
                            transfer_id,
                            chunk_index: state.current_chunk_idx,
                            chunk_hash,
                            data: bytes::Bytes::copy_from_slice(data_slice),
                        };

                        let frame = Frame::new(
                            MessageType::FileChunk,
                            Flags::empty(),
                            0,
                            bytes::Bytes::from(chunk.encode()),
                        );
                        
                        let _ = self.frame_tx.send((state.peer, frame));
                        state.credits -= 1;
                        
                        debug!(
                            "Sent chunk {} for transfer {}. Credits remaining: {}",
                            state.current_chunk_idx,
                            transfer_id.to_u128(),
                            state.credits
                        );
                    }
                    state.current_chunk_idx += 1;
                }
                
                // If we finished all chunks and have no missing bits to check, we might be done.
                // The receiver will send FileComplete when they get everything.
            }
        }
    }
}
