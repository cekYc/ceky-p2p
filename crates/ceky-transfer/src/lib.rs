//! # ceky-transfer
//! 
//! Zero-copy, Merkle-tree verified file transfer protocol over cekyP2P.
//! 
//! This module utilizes `memmap2` for zero-copy file mapping and implements
//! a sliding window credit-based flow control to prevent OOM.

pub mod manager;
pub mod merkle;
pub mod state;

pub use manager::{TransferManager, TransferError};
pub use state::{TransferState, SendingState, ReceivingState};
