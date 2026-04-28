//! UDP hole punching for NAT traversal.
//!
//! Enables direct peer-to-peer UDP connections through NATs by
//! having both peers simultaneously send packets to each other's
//! external address, creating NAT mapping entries.
//!
//! ```text
//! Peer A (behind NAT-A)          Rendezvous Server          Peer B (behind NAT-B)
//!    │                               │                            │
//!    │── "I want to talk to B" ────►│                            │
//!    │                               │◄── "I want to talk to A" ─│
//!    │                               │                            │
//!    │◄── "B is at ext_B" ──────────│                            │
//!    │                               │──── "A is at ext_A" ─────►│
//!    │                               │                            │
//!    │═══════ UDP to ext_B ═══════════════════════════════════►│
//!    │◄══════ UDP to ext_A ═══════════════════════════════════│
//!    │                                                            │
//!    │◄═══════════ Direct P2P ═══════════════════════════════►│
//! ```

use crate::NatError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Hole punch configuration.
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Number of punch packets to send per round.
    pub packets_per_round: usize,
    /// Delay between punch packets.
    pub packet_interval: Duration,
    /// Total number of rounds to attempt.
    pub max_rounds: usize,
    /// Timeout for waiting for a response.
    pub round_timeout: Duration,
    /// Magic bytes prepended to punch packets for identification.
    pub magic: [u8; 4],
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            packets_per_round: 3,
            packet_interval: Duration::from_millis(50),
            max_rounds: 10,
            round_timeout: Duration::from_millis(500),
            magic: *b"CEKY",
        }
    }
}

/// Result of a successful hole punch.
#[derive(Debug, Clone)]
pub struct HolePunchResult {
    /// The confirmed external address of the remote peer.
    pub peer_addr: SocketAddr,
    /// How long the hole punch took.
    pub duration: Duration,
    /// Number of rounds it took.
    pub rounds: usize,
}

/// UDP hole puncher.
pub struct HolePuncher {
    config: HolePunchConfig,
}

impl HolePuncher {
    /// Create a new hole puncher with default config.
    pub fn new() -> Self {
        Self {
            config: HolePunchConfig::default(),
        }
    }

    /// Create with custom config.
    pub fn with_config(config: HolePunchConfig) -> Self {
        Self { config }
    }

    /// Attempt to punch a hole to the remote peer's external address.
    ///
    /// Both peers should call this simultaneously with each other's
    /// external address (obtained from STUN or rendezvous server).
    pub async fn punch(
        &self,
        socket: &UdpSocket,
        remote_external: SocketAddr,
    ) -> Result<HolePunchResult, NatError> {
        let start = Instant::now();
        debug!(
            remote = %remote_external,
            "starting UDP hole punch"
        );

        for round in 0..self.config.max_rounds {
            trace!(round = round, "hole punch round");

            // Send punch packets
            for i in 0..self.config.packets_per_round {
                let packet = self.build_punch_packet(round as u32, i as u32);
                match socket.send_to(&packet, remote_external).await {
                    Ok(_) => trace!(round = round, packet = i, "punch packet sent"),
                    Err(e) => warn!(error = %e, "punch send failed"),
                }

                if i < self.config.packets_per_round - 1 {
                    tokio::time::sleep(self.config.packet_interval).await;
                }
            }

            // Wait for a response
            let mut buf = [0u8; 64];
            match timeout(self.config.round_timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    if len >= 4 && buf[..4] == self.config.magic {
                        let duration = start.elapsed();
                        info!(
                            remote = %from,
                            rounds = round + 1,
                            duration_ms = duration.as_millis(),
                            "hole punch succeeded!"
                        );

                        return Ok(HolePunchResult {
                            peer_addr: from,
                            duration,
                            rounds: round + 1,
                        });
                    }
                    trace!(from = %from, len = len, "non-punch packet received");
                }
                Ok(Err(e)) => {
                    trace!(error = %e, "recv error during hole punch");
                }
                Err(_) => {
                    trace!(round = round, "round timed out, retrying");
                }
            }
        }

        Err(NatError::HolePunchFailed {
            reason: format!(
                "no response after {} rounds to {}",
                self.config.max_rounds, remote_external
            ),
        })
    }

    /// Build a punch packet with identifying magic and sequence info.
    fn build_punch_packet(&self, round: u32, seq: u32) -> Vec<u8> {
        let mut packet = Vec::with_capacity(12);
        packet.extend_from_slice(&self.config.magic);
        packet.extend_from_slice(&round.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet
    }

    /// Check if a received packet is a hole punch packet.
    pub fn is_punch_packet(&self, data: &[u8]) -> bool {
        data.len() >= 4 && data[..4] == self.config.magic
    }
}

impl Default for HolePuncher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punch_packet_format() {
        let puncher = HolePuncher::new();
        let packet = puncher.build_punch_packet(5, 2);

        assert_eq!(packet.len(), 12);
        assert_eq!(&packet[..4], b"CEKY");
        assert_eq!(u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]), 5);
        assert_eq!(u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]), 2);
    }

    #[test]
    fn detect_punch_packet() {
        let puncher = HolePuncher::new();
        let packet = puncher.build_punch_packet(0, 0);
        assert!(puncher.is_punch_packet(&packet));
        assert!(!puncher.is_punch_packet(b"NOPE"));
        assert!(!puncher.is_punch_packet(&[]));
    }

    #[tokio::test]
    async fn hole_punch_between_localhost() {
        let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let socket_a = UdpSocket::bind(addr_a).await.unwrap();
        let socket_b = UdpSocket::bind(addr_b).await.unwrap();

        let actual_a = socket_a.local_addr().unwrap();
        let actual_b = socket_b.local_addr().unwrap();

        let config = HolePunchConfig {
            packets_per_round: 1,
            packet_interval: Duration::from_millis(10),
            max_rounds: 3,
            round_timeout: Duration::from_millis(200),
            ..Default::default()
        };

        let puncher_a = HolePuncher::with_config(config.clone());
        let puncher_b = HolePuncher::with_config(config);

        // Run both sides concurrently
        let (result_a, result_b) = tokio::join!(
            puncher_a.punch(&socket_a, actual_b),
            puncher_b.punch(&socket_b, actual_a),
        );

        // At least one should succeed on localhost
        assert!(
            result_a.is_ok() || result_b.is_ok(),
            "at least one side should succeed: a={result_a:?}, b={result_b:?}"
        );
    }
}
