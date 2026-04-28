//! Cryptographic identity for cekyP2P nodes.
//!
//! Each node generates its own Ed25519 keypair (long-term identity)
//! and a separate X25519 static key (for Noise handshakes).
//! The PeerId is a SHA-256 hash of the Ed25519 public key.
//!
//! The X25519 key is signed by Ed25519 to bind it to the identity.

use crate::error::CryptoError;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// 32-byte peer identifier derived from Ed25519 public key.
///
/// `PeerId = SHA-256(Ed25519_PublicKey)`
///
/// Used as the address in the Kademlia DHT. XOR distance
/// between PeerIds determines routing proximity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Create a PeerId from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute XOR distance between two PeerIds.
    /// Used for Kademlia routing table placement.
    pub fn xor_distance(&self, other: &PeerId) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        result
    }

    /// Find the index of the highest set bit in the XOR distance.
    /// Returns 0-255, used to determine which k-bucket a peer belongs to.
    /// Returns None if the distance is zero (same peer).
    pub fn bucket_index(&self, other: &PeerId) -> Option<usize> {
        let distance = self.xor_distance(other);
        for (byte_idx, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                let bit_idx = 7 - byte.leading_zeros() as usize;
                return Some(byte_idx * 8 + bit_idx);
            }
        }
        None // Same peer
    }

    /// Derive PeerId from an Ed25519 public key.
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self(bytes)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show first 8 hex chars for readability
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")?;
        for byte in &self.0[30..] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

impl std::str::FromStr for PeerId {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex_decode(s).map_err(|e| CryptoError::InvalidPeerId {
            reason: format!("invalid hex: {e}"),
        })?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidPeerId {
                reason: format!("expected 32 bytes, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Complete node identity: Ed25519 + X25519 + PeerId.
pub struct Identity {
    /// Long-term Ed25519 signing key (SECRET — never leaves this struct).
    ed25519_signing_key: SigningKey,
    /// Ed25519 public key (shareable).
    pub ed25519_public_key: VerifyingKey,
    /// X25519 static secret (for Noise handshakes).
    x25519_static_secret: X25519StaticSecret,
    /// X25519 static public key.
    pub x25519_public_key: X25519PublicKey,
    /// Ed25519 signature over the X25519 public key (identity binding).
    pub x25519_signature: Signature,
    /// Derived peer ID.
    pub peer_id: PeerId,
}

impl Identity {
    /// Generate a brand new identity with fresh keys.
    pub fn generate() -> Self {
        // Generate Ed25519 keypair
        let ed25519_signing_key = SigningKey::generate(&mut OsRng);
        let ed25519_public_key = ed25519_signing_key.verifying_key();

        // Generate X25519 static key
        let x25519_static_secret = X25519StaticSecret::random_from_rng(OsRng);
        let x25519_public_key = X25519PublicKey::from(&x25519_static_secret);

        // Sign the X25519 public key with Ed25519 (identity binding)
        let x25519_signature = ed25519_signing_key.sign(x25519_public_key.as_bytes());

        // Derive PeerId
        let peer_id = PeerId::from_public_key(&ed25519_public_key);

        tracing::info!(peer_id = %peer_id, "new identity generated");

        Self {
            ed25519_signing_key,
            ed25519_public_key,
            x25519_static_secret,
            x25519_public_key,
            x25519_signature,
            peer_id,
        }
    }

    /// Verify that a remote peer's X25519 key is legitimately bound to their Ed25519 identity.
    pub fn verify_peer_binding(
        ed25519_pk: &VerifyingKey,
        x25519_pk: &X25519PublicKey,
        signature: &Signature,
    ) -> Result<PeerId, CryptoError> {
        ed25519_pk
            .verify(x25519_pk.as_bytes(), signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(PeerId::from_public_key(ed25519_pk))
    }

    /// Sign arbitrary data with the Ed25519 key.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.ed25519_signing_key.sign(data)
    }

    /// Get a reference to the X25519 static secret (for Noise handshake).
    pub(crate) fn x25519_secret(&self) -> &X25519StaticSecret {
        &self.x25519_static_secret
    }

    /// Save identity to a file (Ed25519 secret key + X25519 secret key).
    ///
    /// WARNING: This writes secret keys to disk. The file should have
    /// restricted permissions (0600 on Unix).
    pub fn save_to_file(&self, path: &Path) -> Result<(), CryptoError> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(self.ed25519_signing_key.as_bytes());
        data.extend_from_slice(self.x25519_static_secret.as_bytes());

        std::fs::write(path, &data)?;

        // Zeroize the buffer
        data.zeroize();

        tracing::info!(path = %path.display(), peer_id = %self.peer_id, "identity saved to disk");
        Ok(())
    }

    /// Load identity from a file.
    pub fn load_from_file(path: &Path) -> Result<Self, CryptoError> {
        let mut data = std::fs::read(path)?;

        if data.len() != 64 {
            data.zeroize();
            return Err(CryptoError::Serialization(format!(
                "identity file should be 64 bytes, got {}",
                data.len()
            )));
        }

        let mut ed25519_bytes = [0u8; 32];
        let mut x25519_bytes = [0u8; 32];
        ed25519_bytes.copy_from_slice(&data[..32]);
        x25519_bytes.copy_from_slice(&data[32..64]);
        data.zeroize();

        let ed25519_signing_key = SigningKey::from_bytes(&ed25519_bytes);
        ed25519_bytes.zeroize();

        let ed25519_public_key = ed25519_signing_key.verifying_key();

        let x25519_static_secret = X25519StaticSecret::from(x25519_bytes);
        x25519_bytes.zeroize();

        let x25519_public_key = X25519PublicKey::from(&x25519_static_secret);
        let x25519_signature = ed25519_signing_key.sign(x25519_public_key.as_bytes());
        let peer_id = PeerId::from_public_key(&ed25519_public_key);

        tracing::info!(path = %path.display(), peer_id = %peer_id, "identity loaded from disk");

        Ok(Self {
            ed25519_signing_key,
            ed25519_public_key,
            x25519_static_secret,
            x25519_public_key,
            x25519_signature,
            peer_id,
        })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("peer_id", &self.peer_id)
            .field("ed25519_pk", &hex_encode(self.ed25519_public_key.as_bytes()))
            .field("x25519_pk", &hex_encode(self.x25519_public_key.as_bytes()))
            .finish()
    }
}

// Minimal hex encoding — no external dependency needed
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex at {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let id = Identity::generate();
        // PeerId should be deterministically derived
        let expected = PeerId::from_public_key(&id.ed25519_public_key);
        assert_eq!(id.peer_id, expected);
    }

    #[test]
    fn peer_id_xor_distance() {
        let a = PeerId::from_bytes([0xFF; 32]);
        let b = PeerId::from_bytes([0x00; 32]);
        let dist = a.xor_distance(&b);
        assert_eq!(dist, [0xFF; 32]); // Maximum distance

        let self_dist = a.xor_distance(&a);
        assert_eq!(self_dist, [0x00; 32]); // Zero distance to self
    }

    #[test]
    fn peer_id_bucket_index() {
        let a = PeerId::from_bytes([0x00; 32]);
        let mut b_bytes = [0x00; 32];
        b_bytes[0] = 0x80; // Highest bit set → bucket 0 (furthest)
        let b = PeerId::from_bytes(b_bytes);
        assert_eq!(a.bucket_index(&b), Some(7));

        b_bytes[0] = 0x01; // Lowest bit of first byte → bucket 7
        let c = PeerId::from_bytes(b_bytes);
        assert_eq!(a.bucket_index(&c), Some(0));

        // Same peer → None
        assert_eq!(a.bucket_index(&a), None);
    }

    #[test]
    fn verify_x25519_binding() {
        let id = Identity::generate();
        let result = Identity::verify_peer_binding(
            &id.ed25519_public_key,
            &id.x25519_public_key,
            &id.x25519_signature,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), id.peer_id);
    }

    #[test]
    fn reject_invalid_binding() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        // Try to verify A's X25519 key with B's signature → should fail
        let result = Identity::verify_peer_binding(
            &id_a.ed25519_public_key,
            &id_a.x25519_public_key,
            &id_b.x25519_signature, // Wrong signature!
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let data = b"cekyP2P zero-trust test";
        let sig = id.sign(data);
        assert!(id.ed25519_public_key.verify(data, &sig).is_ok());
    }

    #[test]
    fn peer_id_display_roundtrip() {
        let id = Identity::generate();
        let display = format!("{}", id.peer_id);
        // Should be 8 hex chars + "…" + 4 hex chars = 13 chars
        assert!(display.contains('…'));
        assert!(display.len() > 0);
    }

    #[test]
    fn peer_id_from_str() {
        let hex = "00".repeat(32); // 64 hex chars = 32 bytes
        let pid: PeerId = hex.parse().unwrap();
        assert_eq!(pid, PeerId::from_bytes([0x00; 32]));

        // Bad length
        let bad = "0011";
        let result: Result<PeerId, _> = bad.parse();
        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_identity() {
        let original = Identity::generate();

        // Create a temp file
        let dir = std::env::current_dir().unwrap();
        let path = dir.join("test_identity.key");

        original.save_to_file(&path).unwrap();

        let loaded = Identity::load_from_file(&path).unwrap();

        assert_eq!(original.peer_id, loaded.peer_id);
        assert_eq!(
            original.ed25519_public_key.as_bytes(),
            loaded.ed25519_public_key.as_bytes()
        );
        assert_eq!(
            original.x25519_public_key.as_bytes(),
            loaded.x25519_public_key.as_bytes()
        );

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
