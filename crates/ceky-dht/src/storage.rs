//! Persistent DHT Storage using redb and dashmap.
//!
//! Provides a two-tier (Hot Cache + Cold DB) storage architecture
//! with asynchronous write-behind for lock-free performance.

use crate::DhtError;
use ceky_crypto::PeerId;
use dashmap::DashMap;
use redb::{MultimapTableDefinition, TableDefinition, ReadableMultimapTable};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error};

/// A stored key-value pair with metadata, adapted for persistence.
#[derive(Debug, Clone)]
pub struct StoredEntry {
    /// The key (typically a content hash).
    pub key: [u8; 32],
    /// The value data.
    pub value: Vec<u8>,
    /// Who stored it originally.
    pub publisher: PeerId,
    /// Absolute expiration time (UNIX epoch seconds).
    pub expires_at: u64,
}

impl StoredEntry {
    /// Create a new stored entry with a given TTL in seconds.
    pub fn new(key: [u8; 32], value: Vec<u8>, publisher: PeerId, ttl_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            key,
            value,
            publisher,
            expires_at: now + ttl_secs,
        }
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at <= now
    }

    /// Custom binary encoding for `redb` storage.
    /// Format: Key(32) | Publisher(32) | ExpiresAt(8) | ValueLen(4) | Value(N)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 4 + self.value.len());
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(self.publisher.as_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&(self.value.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf
    }

    /// Custom binary decoding.
    pub fn decode(payload: &[u8]) -> Result<Self, DhtError> {
        if payload.len() < 76 {
            return Err(DhtError::InvalidKey {
                reason: "payload too short for stored entry".into(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&payload[0..32]);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&payload[32..64]);
        let publisher = PeerId::from_bytes(pub_bytes);

        let expires_at = u64::from_be_bytes(payload[64..72].try_into().unwrap());
        let val_len = u32::from_be_bytes(payload[72..76].try_into().unwrap()) as usize;

        if payload.len() < 76 + val_len {
            return Err(DhtError::InvalidKey {
                reason: "payload too short for value".into(),
            });
        }

        let value = payload[76..76 + val_len].to_vec();
        Ok(Self {
            key,
            value,
            publisher,
            expires_at,
        })
    }
}

// --- redb Table Definitions ---
const DHT_DATA: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("dht_data");
const EXPIRE_INDEX: MultimapTableDefinition<u64, [u8; 32]> =
    MultimapTableDefinition::new("expire_index");

/// Persistent DHT storage for key-value pairs.
/// 
/// Uses `redb` for disk storage and `DashMap` for hot cache.
/// Writes are batched and executed asynchronously in the background.
pub struct PersistentStore {
    hot_cache: Arc<DashMap<[u8; 32], StoredEntry>>,
    db: Arc<redb::Database>,
    write_tx: mpsc::UnboundedSender<StoredEntry>,
}

impl PersistentStore {
    /// Create a new persistent store at the given path.
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Self, DhtError> {
        let db = redb::Database::create(path).map_err(|e| DhtError::StoreFailed {
            reason: format!("failed to create db: {}", e),
        })?;

        // Initialize tables
        {
            let write_txn = db.begin_write().map_err(|e| DhtError::StoreFailed {
                reason: format!("failed to begin write txn: {}", e),
            })?;
            let _ = write_txn.open_table(DHT_DATA).map_err(|e| DhtError::StoreFailed {
                reason: format!("failed to open DHT_DATA table: {}", e),
            })?;
            let _ = write_txn
                .open_multimap_table(EXPIRE_INDEX)
                .map_err(|e| DhtError::StoreFailed {
                    reason: format!("failed to open EXPIRE_INDEX table: {}", e),
                })?;
            write_txn.commit().map_err(|e| DhtError::StoreFailed {
                reason: format!("failed to commit table creation: {}", e),
            })?;
        }

        let db = Arc::new(db);
        let hot_cache = Arc::new(DashMap::new());
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<StoredEntry>();

        // Background Batch Writer Task
        let db_clone = Arc::clone(&db);
        tokio::spawn(async move {
            let mut batch = Vec::new();
            loop {
                // Block until at least one item arrives
                if let Some(entry) = write_rx.recv().await {
                    batch.push(entry);
                } else {
                    break; // Channel closed
                }

                // Gather more items for up to 500ms or until batch size 100
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    while batch.len() < 100 {
                        if let Some(entry) = write_rx.recv().await {
                            batch.push(entry);
                        } else {
                            break;
                        }
                    }
                })
                .await;

                // Perform the batch write in a blocking thread
                let db_task = Arc::clone(&db_clone);
                let entries = std::mem::take(&mut batch);
                
                let _ = tokio::task::spawn_blocking(move || {
                    if let Ok(write_txn) = db_task.begin_write() {
                        if let (Ok(mut data_table), Ok(mut expire_table)) = (
                            write_txn.open_table(DHT_DATA),
                            write_txn.open_multimap_table(EXPIRE_INDEX),
                        ) {
                            for entry in entries {
                                let encoded = entry.encode();
                                // Store payload
                                let _ = data_table.insert(entry.key, encoded.as_slice());
                                // Index by expiration time
                                let _ = expire_table.insert(entry.expires_at, entry.key);
                            }
                        }
                        if let Err(e) = write_txn.commit() {
                            error!("Failed to commit batch write to redb: {}", e);
                        } else {
                            debug!("Committed batch write to disk");
                        }
                    }
                })
                .await;
            }
        });

        // Background GC Eviction Task (Runs every 5 minutes)
        let db_gc = Arc::clone(&db);
        let cache_gc = Arc::clone(&hot_cache);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let db_handle = Arc::clone(&db_gc);
                let cache = Arc::clone(&cache_gc);

                let _ = tokio::task::spawn_blocking(move || {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Ok(write_txn) = db_handle.begin_write() {
                        let mut keys_to_remove = Vec::new();

                        if let (Ok(_data_table), Ok(expire_table)) = (
                            write_txn.open_table(DHT_DATA),
                            write_txn.open_multimap_table(EXPIRE_INDEX),
                        ) {
                            // Find all expired keys
                            if let Ok(range) = expire_table.range(0..=now) {
                                for item in range {
                                    if let Ok((time, keys)) = item {
                                        for key in keys {
                                            if let Ok(k) = key {
                                                keys_to_remove.push((time.value(), k.value()));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !keys_to_remove.is_empty() {
                            if let (Ok(mut data_table), Ok(mut expire_table)) = (
                                write_txn.open_table(DHT_DATA),
                                write_txn.open_multimap_table(EXPIRE_INDEX),
                            ) {
                                for (time, key) in keys_to_remove {
                                    let _ = data_table.remove(key);
                                    let _ = expire_table.remove(time, key);
                                    cache.remove(&key);
                                }
                            }
                            if let Err(e) = write_txn.commit() {
                                error!("Failed to commit GC eviction to redb: {}", e);
                            } else {
                                debug!("GC eviction removed expired entries");
                            }
                        }
                    }
                })
                .await;
            }
        });

        Ok(Self {
            hot_cache,
            db,
            write_tx,
        })
    }

    /// Store a value persistently (write-behind).
    pub fn put(&self, entry: StoredEntry) -> Result<(), DhtError> {
        self.hot_cache.insert(entry.key, entry.clone());
        let _ = self.write_tx.send(entry);
        Ok(())
    }

    /// Retrieve a value by key.
    pub fn get(&self, key: &[u8; 32]) -> Option<StoredEntry> {
        // 1. Hot Cache Lookup
        if let Some(entry_ref) = self.hot_cache.get(key) {
            if !entry_ref.is_expired() {
                return Some(entry_ref.clone());
            } else {
                return None; // Expired, will be cleaned up by GC
            }
        }

        // 2. Cold DB Lookup
        if let Ok(read_txn) = self.db.begin_read() {
            if let Ok(table) = read_txn.open_table(DHT_DATA) {
                if let Ok(Some(value)) = table.get(key) {
                    if let Ok(entry) = StoredEntry::decode(value.value()) {
                        if !entry.is_expired() {
                            // Populate hot cache for future reads
                            self.hot_cache.insert(*key, entry.clone());
                            return Some(entry);
                        }
                    }
                }
            }
        }

        None
    }

    /// Remove a value by key manually.
    pub fn remove(&self, key: &[u8; 32]) -> Option<StoredEntry> {
        let removed = self.hot_cache.remove(key).map(|(_, v)| v);

        let db = Arc::clone(&self.db);
        let key_val = *key;
        
        // Asynchronously remove from disk
        tokio::task::spawn_blocking(move || {
            if let Ok(write_txn) = db.begin_write() {
                if let Ok(mut table) = write_txn.open_table(DHT_DATA) {
                    let _ = table.remove(key_val);
                }
                let _ = write_txn.commit();
            }
        });

        removed
    }

    /// Number of hot-cached entries.
    pub fn len(&self) -> usize {
        self.hot_cache.len()
    }

    /// Is the hot cache empty?
    pub fn is_empty(&self) -> bool {
        self.hot_cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_peer_id(byte: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        PeerId::from_bytes(bytes)
    }

    #[test]
    fn serialization_roundtrip() {
        let key = [0x42; 32];
        let publisher = make_peer_id(0x01);
        let value = b"hello distributed world".to_vec();
        
        let entry = StoredEntry::new(key, value.clone(), publisher, 3600);
        let encoded = entry.encode();
        
        let decoded = StoredEntry::decode(&encoded).expect("should decode");
        assert_eq!(decoded.key, key);
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.publisher.as_bytes(), publisher.as_bytes());
        assert_eq!(decoded.expires_at, entry.expires_at);
    }

    #[tokio::test]
    async fn persistent_store_put_get() {
        let temp_file = NamedTempFile::new().unwrap();
        let store = PersistentStore::new(temp_file.path()).unwrap();
        
        let key = [0x99; 32];
        let entry = StoredEntry::new(key, b"persistent data".to_vec(), make_peer_id(2), 3600);
        
        store.put(entry.clone()).unwrap();
        
        // Should be in hot cache immediately
        let retrieved = store.get(&key).expect("should find in cache");
        assert_eq!(retrieved.value, b"persistent data");
        
        // Wait for batch writer to write to DB
        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
        
        // Clear hot cache to force disk read
        store.hot_cache.clear();
        assert!(store.is_empty());
        
        // Retrieve again, this time from DB
        let retrieved_db = store.get(&key).expect("should find in db");
        assert_eq!(retrieved_db.value, b"persistent data");
        
        // Cache should be populated again
        assert!(!store.is_empty());
    }
}
