//! Lock-free connection pool using DashMap.
//!
//! Manages all active peer connections with O(1) lookup by address.
//! Thread-safe without mutexes — DashMap uses sharded locking internally.

use crate::connection::{ConnectionConfig, ConnectionInfo, ConnectionState};
use crate::TransportError;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Lock-free pool of active connections.
///
/// Uses `DashMap` (sharded concurrent hashmap) for zero-contention
/// lookups and inserts across multiple tokio tasks.
pub struct ConnectionPool {
    /// Active connections indexed by peer address.
    connections: DashMap<SocketAddr, ConnectionInfo>,
    /// Maximum number of simultaneous connections.
    max_connections: usize,
    /// Default config for new connections.
    default_config: ConnectionConfig,
    /// Total connections ever created (monotonic counter).
    total_created: AtomicU64,
    /// Total connections ever removed.
    total_removed: AtomicU64,
}

impl ConnectionPool {
    /// Create a new pool with the given capacity limit.
    pub fn new(max_connections: usize, default_config: ConnectionConfig) -> Self {
        Self {
            connections: DashMap::with_capacity(max_connections),
            max_connections,
            default_config,
            total_created: AtomicU64::new(0),
            total_removed: AtomicU64::new(0),
        }
    }

    /// Create a pool with default settings (max 1024 connections).
    pub fn with_defaults() -> Self {
        Self::new(1024, ConnectionConfig::default())
    }

    /// Insert a new connection. Returns error if pool is full or peer already exists.
    pub fn insert(&self, peer_addr: SocketAddr) -> Result<(), TransportError> {
        if self.connections.len() >= self.max_connections {
            return Err(TransportError::PoolFull {
                max: self.max_connections,
            });
        }

        let conn = ConnectionInfo::new(peer_addr, self.default_config.clone());
        // Use entry API for atomic check-and-insert
        match self.connections.entry(peer_addr) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                warn!(peer = %peer_addr, "duplicate connection attempt — already in pool");
                // Silently succeed — peer already connected
                Ok(())
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(conn);
                self.total_created.fetch_add(1, Ordering::Relaxed);
                debug!(peer = %peer_addr, pool_size = self.connections.len(), "peer added to pool");
                Ok(())
            }
        }
    }

    /// Remove a connection from the pool.
    pub fn remove(&self, peer_addr: &SocketAddr) -> Option<ConnectionInfo> {
        let removed = self.connections.remove(peer_addr).map(|(_, info)| info);
        if removed.is_some() {
            self.total_removed.fetch_add(1, Ordering::Relaxed);
            debug!(peer = %peer_addr, pool_size = self.connections.len(), "peer removed from pool");
        }
        removed
    }

    /// Check if a peer is in the pool.
    pub fn contains(&self, peer_addr: &SocketAddr) -> bool {
        self.connections.contains_key(peer_addr)
    }

    /// Get the number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Execute a closure with mutable access to a connection's info.
    /// Returns None if the peer is not in the pool.
    pub fn with_connection<F, R>(&self, peer_addr: &SocketAddr, f: F) -> Option<R>
    where
        F: FnOnce(&mut ConnectionInfo) -> R,
    {
        self.connections.get_mut(peer_addr).map(|mut entry| f(&mut entry))
    }

    /// Execute a closure with read-only access to a connection's info.
    pub fn with_connection_ref<F, R>(&self, peer_addr: &SocketAddr, f: F) -> Option<R>
    where
        F: FnOnce(&ConnectionInfo) -> R,
    {
        self.connections.get(peer_addr).map(|entry| f(&entry))
    }

    /// Get all peer addresses currently in the pool.
    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.connections.iter().map(|entry| *entry.key()).collect()
    }

    /// Get all established (active and ready) connections' addresses.
    pub fn established_peers(&self) -> Vec<SocketAddr> {
        self.connections
            .iter()
            .filter(|entry| entry.state == ConnectionState::Established)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Find peers that need a heartbeat PING sent.
    pub fn peers_needing_ping(&self) -> Vec<SocketAddr> {
        self.connections
            .iter()
            .filter(|entry| entry.should_send_ping())
            .map(|entry| *entry.key())
            .collect()
    }

    /// Find peers that appear dead (too many missed heartbeats).
    pub fn dead_peers(&self) -> Vec<SocketAddr> {
        self.connections
            .iter()
            .filter(|entry| entry.is_dead())
            .map(|entry| *entry.key())
            .collect()
    }

    /// Evict peers that have been idle for longer than the given duration.
    pub fn evict_idle(&self, max_idle: Duration) -> Vec<SocketAddr> {
        let idle_peers: Vec<SocketAddr> = self
            .connections
            .iter()
            .filter(|entry| entry.idle_time() > max_idle)
            .map(|entry| *entry.key())
            .collect();

        for addr in &idle_peers {
            self.remove(addr);
        }

        if !idle_peers.is_empty() {
            info!(count = idle_peers.len(), "evicted idle peers");
        }

        idle_peers
    }

    /// Evict dead peers (too many missed heartbeats).
    pub fn evict_dead(&self) -> Vec<SocketAddr> {
        let dead = self.dead_peers();
        for addr in &dead {
            self.remove(addr);
        }
        if !dead.is_empty() {
            info!(count = dead.len(), "evicted dead peers");
        }
        dead
    }

    /// Pool statistics.
    pub fn stats(&self) -> PoolStats {
        let mut established = 0;
        let mut connecting = 0;
        let mut closing = 0;
        let mut total_bytes_recv = 0u64;
        let mut total_bytes_sent = 0u64;

        for entry in self.connections.iter() {
            match entry.state {
                ConnectionState::Established => established += 1,
                ConnectionState::Connecting => connecting += 1,
                ConnectionState::Closing => closing += 1,
                ConnectionState::Closed => {} // shouldn't be in pool
            }
            total_bytes_recv += entry.bytes_recv;
            total_bytes_sent += entry.bytes_sent;
        }

        PoolStats {
            active: self.connections.len(),
            established,
            connecting,
            closing,
            max: self.max_connections,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_removed: self.total_removed.load(Ordering::Relaxed),
            total_bytes_recv,
            total_bytes_sent,
        }
    }
}

/// Snapshot of pool statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub active: usize,
    pub established: usize,
    pub connecting: usize,
    pub closing: usize,
    pub max: usize,
    pub total_created: u64,
    pub total_removed: u64,
    pub total_bytes_recv: u64,
    pub total_bytes_sent: u64,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Pool[{}/{} active, {} established, {} connecting, recv={}B sent={}B]",
            self.active,
            self.max,
            self.established,
            self.connecting,
            self.total_bytes_recv,
            self.total_bytes_sent,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn insert_and_lookup() {
        let pool = ConnectionPool::with_defaults();
        assert!(pool.is_empty());

        pool.insert(addr(9001)).unwrap();
        pool.insert(addr(9002)).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&addr(9001)));
        assert!(pool.contains(&addr(9002)));
        assert!(!pool.contains(&addr(9999)));
    }

    #[test]
    fn remove() {
        let pool = ConnectionPool::with_defaults();
        pool.insert(addr(9001)).unwrap();
        assert_eq!(pool.len(), 1);

        let removed = pool.remove(&addr(9001));
        assert!(removed.is_some());
        assert!(pool.is_empty());

        // Removing non-existent should return None
        assert!(pool.remove(&addr(9001)).is_none());
    }

    #[test]
    fn pool_full() {
        let pool = ConnectionPool::new(2, ConnectionConfig::default());
        pool.insert(addr(9001)).unwrap();
        pool.insert(addr(9002)).unwrap();

        let result = pool.insert(addr(9003));
        assert!(matches!(result, Err(TransportError::PoolFull { max: 2 })));
    }

    #[test]
    fn duplicate_insert_is_idempotent() {
        let pool = ConnectionPool::with_defaults();
        pool.insert(addr(9001)).unwrap();
        pool.insert(addr(9001)).unwrap(); // should not error
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn with_connection_mutation() {
        let pool = ConnectionPool::with_defaults();
        pool.insert(addr(9001)).unwrap();

        pool.with_connection(&addr(9001), |conn| {
            conn.set_established();
            conn.record_recv(1024);
        });

        let state = pool.with_connection_ref(&addr(9001), |conn| conn.state);
        assert_eq!(state, Some(ConnectionState::Established));

        let bytes = pool.with_connection_ref(&addr(9001), |conn| conn.bytes_recv);
        assert_eq!(bytes, Some(1024));
    }

    #[test]
    fn established_peers() {
        let pool = ConnectionPool::with_defaults();
        pool.insert(addr(9001)).unwrap();
        pool.insert(addr(9002)).unwrap();
        pool.insert(addr(9003)).unwrap();

        pool.with_connection(&addr(9001), |c| c.set_established());
        pool.with_connection(&addr(9003), |c| c.set_established());

        let established = pool.established_peers();
        assert_eq!(established.len(), 2);
        assert!(established.contains(&addr(9001)));
        assert!(established.contains(&addr(9003)));
    }

    #[test]
    fn stats() {
        let pool = ConnectionPool::new(100, ConnectionConfig::default());
        pool.insert(addr(9001)).unwrap();
        pool.insert(addr(9002)).unwrap();
        pool.with_connection(&addr(9001), |c| {
            c.set_established();
            c.record_recv(500);
            c.record_send(300);
        });

        let stats = pool.stats();
        assert_eq!(stats.active, 2);
        assert_eq!(stats.established, 1);
        assert_eq!(stats.connecting, 1);
        assert_eq!(stats.total_created, 2);
        assert_eq!(stats.total_bytes_recv, 500);
        assert_eq!(stats.total_bytes_sent, 300);
    }
}
