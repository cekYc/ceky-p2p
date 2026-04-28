//! Secure session for encrypting/decrypting frames after handshake.
//!
//! Uses ChaChaPoly1305 with incrementing nonces for each direction.
//! Provides replay protection via a nonce window.

use crate::error::CryptoError;
use crate::noise::SessionKeys;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::trace;

/// Authentication tag size (Poly1305).
pub const TAG_SIZE: usize = 16;

/// Maximum nonce value before rekey is required.
/// At 2^48, with 1M frames/sec, this lasts ~8.9 years.
const MAX_NONCE: u64 = (1u64 << 48) - 1;

/// Size of the replay window (tracks last N nonces).
const REPLAY_WINDOW_SIZE: usize = 256;

/// Encrypted session after a successful Noise handshake.
///
/// Thread-safe: uses atomic nonce counters.
pub struct SecureSession {
    /// Cipher for encrypting outgoing data.
    send_cipher: ChaCha20Poly1305,
    /// Cipher for decrypting incoming data.
    recv_cipher: ChaCha20Poly1305,
    /// Outgoing nonce counter (monotonically increasing).
    send_nonce: AtomicU64,
    /// Highest received nonce (for replay protection).
    recv_nonce_max: AtomicU64,
    /// Replay window bitmask.
    replay_window: std::sync::Mutex<ReplayWindow>,
    /// Remote peer's static public key.
    pub remote_static: [u8; 32],
}

/// Sliding window for replay protection.
struct ReplayWindow {
    /// Highest nonce seen.
    max_nonce: u64,
    /// Bitmask of seen nonces relative to max_nonce.
    /// Bit i represents nonce (max_nonce - i).
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            max_nonce: 0,
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// Check if a nonce has been seen before. Returns true if it's a new nonce.
    fn check_and_mark(&mut self, nonce: u64) -> bool {
        if nonce > self.max_nonce {
            // New highest nonce — shift the window
            let shift = (nonce - self.max_nonce) as usize;
            if shift >= REPLAY_WINDOW_SIZE {
                // Reset entire window
                self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                // Shift bitmap
                self.shift_left(shift);
            }
            self.max_nonce = nonce;
            // Mark bit 0 (current nonce)
            self.bitmap[0] |= 1;
            true
        } else {
            let diff = (self.max_nonce - nonce) as usize;
            if diff >= REPLAY_WINDOW_SIZE {
                // Too old — reject
                return false;
            }
            let word_idx = diff / 64;
            let bit_idx = diff % 64;
            if self.bitmap[word_idx] & (1u64 << bit_idx) != 0 {
                // Already seen — replay!
                return false;
            }
            self.bitmap[word_idx] |= 1u64 << bit_idx;
            true
        }
    }

    fn shift_left(&mut self, amount: usize) {
        if amount >= 64 {
            let word_shift = amount / 64;
            let bit_shift = amount % 64;

            // Shift words
            for i in (0..self.bitmap.len()).rev() {
                if i >= word_shift {
                    self.bitmap[i] = self.bitmap[i - word_shift];
                } else {
                    self.bitmap[i] = 0;
                }
            }

            // Shift remaining bits
            if bit_shift > 0 {
                for i in (0..self.bitmap.len()).rev() {
                    self.bitmap[i] <<= bit_shift;
                    if i > 0 {
                        self.bitmap[i] |= self.bitmap[i - 1] >> (64 - bit_shift);
                    }
                }
            }
        } else if amount > 0 {
            for i in (0..self.bitmap.len()).rev() {
                self.bitmap[i] <<= amount;
                if i > 0 {
                    self.bitmap[i] |= self.bitmap[i - 1] >> (64 - amount);
                }
            }
        }
    }
}

impl SecureSession {
    /// Create a session from handshake-derived keys.
    pub fn from_keys(keys: SessionKeys) -> Result<Self, CryptoError> {
        let send_cipher = ChaCha20Poly1305::new_from_slice(&keys.send_key)
            .map_err(|e| CryptoError::KeyGenerationFailed {
                reason: format!("send cipher: {e}"),
            })?;

        let recv_cipher = ChaCha20Poly1305::new_from_slice(&keys.recv_key)
            .map_err(|e| CryptoError::KeyGenerationFailed {
                reason: format!("recv cipher: {e}"),
            })?;

        Ok(Self {
            send_cipher,
            recv_cipher,
            send_nonce: AtomicU64::new(0),
            recv_nonce_max: AtomicU64::new(0),
            replay_window: std::sync::Mutex::new(ReplayWindow::new()),
            remote_static: keys.remote_static,
        })
    }

    /// Encrypt a plaintext payload.
    ///
    /// Returns `(nonce_counter, ciphertext)`.
    /// The nonce counter must be sent alongside the ciphertext
    /// so the receiver can decrypt.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), CryptoError> {
        let nonce_val = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        if nonce_val > MAX_NONCE {
            return Err(CryptoError::NonceOverflow);
        }

        let nonce = Self::build_nonce(nonce_val);

        let ciphertext = self
            .send_cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::HandshakeFailed {
                reason: "AEAD encrypt failed".into(),
            })?;

        trace!(nonce = nonce_val, plaintext_len = plaintext.len(), ciphertext_len = ciphertext.len(), "encrypted");
        Ok((nonce_val, ciphertext))
    }

    /// Encrypt with associated data (authenticated but not encrypted).
    pub fn encrypt_with_ad(
        &self,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(u64, Vec<u8>), CryptoError> {
        let nonce_val = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        if nonce_val > MAX_NONCE {
            return Err(CryptoError::NonceOverflow);
        }

        let nonce = Self::build_nonce(nonce_val);
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };

        let ciphertext = self
            .send_cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::HandshakeFailed {
                reason: "AEAD encrypt failed".into(),
            })?;

        Ok((nonce_val, ciphertext))
    }

    /// Decrypt a ciphertext payload with replay protection.
    pub fn decrypt(
        &self,
        nonce_val: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Replay protection
        {
            let mut window = self.replay_window.lock().unwrap();
            if !window.check_and_mark(nonce_val) {
                return Err(CryptoError::ReplayDetected { nonce: nonce_val });
            }
        }

        let nonce = Self::build_nonce(nonce_val);

        let plaintext = self
            .recv_cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        self.recv_nonce_max
            .fetch_max(nonce_val, Ordering::Relaxed);

        trace!(nonce = nonce_val, ciphertext_len = ciphertext.len(), plaintext_len = plaintext.len(), "decrypted");
        Ok(plaintext)
    }

    /// Decrypt with associated data.
    pub fn decrypt_with_ad(
        &self,
        nonce_val: u64,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        {
            let mut window = self.replay_window.lock().unwrap();
            if !window.check_and_mark(nonce_val) {
                return Err(CryptoError::ReplayDetected { nonce: nonce_val });
            }
        }

        let nonce = Self::build_nonce(nonce_val);
        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };

        let plaintext = self
            .recv_cipher
            .decrypt(&nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        self.recv_nonce_max
            .fetch_max(nonce_val, Ordering::Relaxed);

        Ok(plaintext)
    }

    /// Build a 12-byte nonce from a u64 counter.
    /// Format: [0, 0, 0, 0, counter_le_bytes(8)]
    fn build_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Get the current send nonce counter.
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce.load(Ordering::Relaxed)
    }

    /// Get the highest received nonce.
    pub fn recv_nonce_max(&self) -> u64 {
        self.recv_nonce_max.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::SessionKeys;

    fn make_session_pair() -> (SecureSession, SecureSession) {
        // Create complementary key pairs (A's send = B's recv)
        let key_a = [0x42u8; 32];
        let key_b = [0x84u8; 32];
        let remote = [0xFFu8; 32];

        let session_a = SecureSession::from_keys(SessionKeys {
            send_key: key_a,
            recv_key: key_b,
            remote_static: remote,
        })
        .unwrap();

        let session_b = SecureSession::from_keys(SessionKeys {
            send_key: key_b,
            recv_key: key_a,
            remote_static: remote,
        })
        .unwrap();

        (session_a, session_b)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (session_a, session_b) = make_session_pair();

        let plaintext = b"cekyP2P encrypted payload - zero-trust!";
        let (nonce, ciphertext) = session_a.encrypt(plaintext).unwrap();

        // Ciphertext should be larger than plaintext (16-byte tag)
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = session_b.decrypt(nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (session_a, session_b) = make_session_pair();

        let (nonce, mut ciphertext) = session_a.encrypt(b"sensitive data").unwrap();

        // Corrupt one byte
        ciphertext[0] ^= 0xFF;

        let result = session_b.decrypt(nonce, &ciphertext);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn replay_protection() {
        let (session_a, session_b) = make_session_pair();

        let (nonce, ciphertext) = session_a.encrypt(b"first message").unwrap();

        // First decryption should succeed
        session_b.decrypt(nonce, &ciphertext).unwrap();

        // Same nonce again → replay detected
        let result = session_b.decrypt(nonce, &ciphertext);
        assert!(matches!(result, Err(CryptoError::ReplayDetected { .. })));
    }

    #[test]
    fn out_of_order_decryption() {
        let (session_a, session_b) = make_session_pair();

        // Encrypt 3 messages
        let (n1, c1) = session_a.encrypt(b"message 1").unwrap();
        let (n2, c2) = session_a.encrypt(b"message 2").unwrap();
        let (n3, c3) = session_a.encrypt(b"message 3").unwrap();

        // Decrypt in reverse order (simulates network reordering)
        assert!(session_b.decrypt(n3, &c3).is_ok());
        assert!(session_b.decrypt(n1, &c1).is_ok());
        assert!(session_b.decrypt(n2, &c2).is_ok());

        // But not again
        assert!(session_b.decrypt(n2, &c2).is_err());
    }

    #[test]
    fn encrypt_with_ad_roundtrip() {
        let (session_a, session_b) = make_session_pair();

        let ad = b"frame header bytes";
        let plaintext = b"payload";

        let (nonce, ciphertext) = session_a.encrypt_with_ad(plaintext, ad).unwrap();

        // Correct AD succeeds
        let decrypted = session_b.decrypt_with_ad(nonce, &ciphertext, ad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_ad_fails() {
        let (session_a, session_b) = make_session_pair();

        let ad = b"correct header";
        let (nonce, ciphertext) = session_a.encrypt_with_ad(b"data", ad).unwrap();

        // Wrong AD should fail
        let result = session_b.decrypt_with_ad(nonce, &ciphertext, b"wrong header");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn nonce_counter_increments() {
        let (session_a, _) = make_session_pair();

        assert_eq!(session_a.send_nonce(), 0);
        session_a.encrypt(b"a").unwrap();
        assert_eq!(session_a.send_nonce(), 1);
        session_a.encrypt(b"b").unwrap();
        assert_eq!(session_a.send_nonce(), 2);
    }

    #[test]
    fn replay_window_basic() {
        let mut window = ReplayWindow::new();

        // First nonce should be accepted
        assert!(window.check_and_mark(0));
        // Replay should be rejected
        assert!(!window.check_and_mark(0));

        // Sequential nonces
        assert!(window.check_and_mark(1));
        assert!(window.check_and_mark(2));
        assert!(window.check_and_mark(5));

        // Gap-filled nonces
        assert!(window.check_and_mark(3));
        assert!(window.check_and_mark(4));

        // All should be marked now
        assert!(!window.check_and_mark(3));
        assert!(!window.check_and_mark(5));
    }
}
