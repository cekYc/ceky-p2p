//! Lock-free telemetry metrics.

use std::sync::atomic::AtomicUsize;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub file_name: String,
    pub total_chunks: u32,
    pub completed_chunks: u32,
    pub is_sending: bool,
}

pub struct GlobalMetrics {
    pub tx_bytes: AtomicUsize,
    pub rx_bytes: AtomicUsize,
    pub tx_rate: AtomicUsize,
    pub rx_rate: AtomicUsize,
    pub active_tcp_connections: AtomicUsize,
    pub dht_active_peers: AtomicUsize,
    pub dht_total_peers: AtomicUsize,
    pub transfers: RwLock<Vec<TransferProgress>>,
}

impl GlobalMetrics {
    pub fn new() -> Self {
        Self {
            tx_bytes: AtomicUsize::new(0),
            rx_bytes: AtomicUsize::new(0),
            tx_rate: AtomicUsize::new(0),
            rx_rate: AtomicUsize::new(0),
            active_tcp_connections: AtomicUsize::new(0),
            dht_active_peers: AtomicUsize::new(0),
            dht_total_peers: AtomicUsize::new(0),
            transfers: RwLock::new(Vec::new()),
        }
    }
}

impl Default for GlobalMetrics {
    fn default() -> Self {
        Self::new()
    }
}
