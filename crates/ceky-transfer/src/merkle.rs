//! Merkle Tree and Chunk Hashing utilities.

use ceky_protocol::transfer::FILE_HASH_LEN;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Calculate SHA-256 for a single chunk of data.
pub fn hash_chunk(data: &[u8]) -> [u8; FILE_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; FILE_HASH_LEN];
    hash.copy_from_slice(&result[..FILE_HASH_LEN]);
    hash
}

/// Calculate the Merkle Root (file_hash) by hashing all chunk hashes.
/// For this protocol, it's a simple flat hash of concatenated chunk hashes.
/// Warning: This is a blocking I/O operation.
pub fn calculate_file_hash(path: &Path, chunk_size: u32) -> io::Result<[u8; FILE_HASH_LEN]> {
    let mut file = File::open(path)?;
    let mut root_hasher = Sha256::new();
    let mut buffer = vec![0u8; chunk_size as usize];

    loop {
        let mut read_bytes = 0;
        while read_bytes < chunk_size as usize {
            match file.read(&mut buffer[read_bytes..]) {
                Ok(0) => break,
                Ok(n) => read_bytes += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if read_bytes == 0 {
            break;
        }

        let chunk_hash = hash_chunk(&buffer[..read_bytes]);
        root_hasher.update(&chunk_hash);
    }

    let result = root_hasher.finalize();
    let mut hash = [0u8; FILE_HASH_LEN];
    hash.copy_from_slice(&result[..FILE_HASH_LEN]);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_chunk() {
        let data = b"hello zero-copy world";
        let hash = hash_chunk(data);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_calculate_file_hash() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&vec![0x42; 1024 * 5]).unwrap(); // 5 KB
        let path = file.path();

        let hash_1kb = calculate_file_hash(path, 1024).unwrap();
        let hash_2kb = calculate_file_hash(path, 2048).unwrap();
        
        // Hashes should differ based on chunk size since Merkle structure changes
        assert_ne!(hash_1kb, hash_2kb);
    }
}
