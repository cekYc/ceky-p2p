//! NAT type detection.
//!
//! Classifies the NAT type by comparing mapped addresses from
//! multiple STUN servers. The NAT type determines which traversal
//! strategy to use.
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │                NAT Classification              │
//! ├───────────────────────────────────────────────┤
//! │ None         : No NAT (public IP)              │
//! │ FullCone     : Any external host can send      │
//! │ Restricted   : Only hosts we contacted can     │
//! │ PortRestrict : Only exact IP:port can respond  │
//! │ Symmetric    : Different mapping per dest      │
//! │ Unknown      : Detection failed                │
//! └───────────────────────────────────────────────┘
//! ```

use crate::stun::{StunClient, StunResult};
use crate::NatError;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Detected NAT type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT — we have a public IP.
    None,
    /// Full Cone NAT — any external host can send to our mapped address.
    FullCone,
    /// Address-Restricted Cone — only hosts we've sent to can reply.
    Restricted,
    /// Port-Restricted Cone — only the exact IP:port we sent to can reply.
    PortRestricted,
    /// Symmetric NAT — different external mapping for each destination.
    /// Cannot be traversed with hole punching.
    Symmetric,
    /// Could not determine NAT type.
    Unknown,
}

impl NatType {
    /// Can we use UDP hole punching with this NAT type?
    pub fn supports_hole_punch(&self) -> bool {
        matches!(
            self,
            NatType::None | NatType::FullCone | NatType::Restricted | NatType::PortRestricted
        )
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            NatType::None => "No NAT (public IP)",
            NatType::FullCone => "Full Cone NAT",
            NatType::Restricted => "Address-Restricted Cone NAT",
            NatType::PortRestricted => "Port-Restricted Cone NAT",
            NatType::Symmetric => "Symmetric NAT (relay required)",
            NatType::Unknown => "Unknown NAT type",
        }
    }
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Information about our NAT environment.
#[derive(Debug, Clone)]
pub struct NatInfo {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Our external (mapped) address if discovered.
    pub external_addr: Option<SocketAddr>,
    /// Our local (bind) address.
    pub local_addr: SocketAddr,
    /// Whether hole punching is feasible.
    pub hole_punch_capable: bool,
}

/// NAT type detector.
pub struct NatDetector {
    stun_client: StunClient,
}

impl NatDetector {
    /// Create a new detector with default STUN servers.
    pub fn new() -> Self {
        Self {
            stun_client: StunClient::new(),
        }
    }

    /// Create a detector with a custom STUN client.
    pub fn with_stun_client(stun_client: StunClient) -> Self {
        Self { stun_client }
    }

    /// Detect NAT type using STUN probes.
    ///
    /// Strategy:
    /// 1. Probe two different STUN servers from the same socket
    /// 2. If both return the same mapped address → FullCone/Restricted
    /// 3. If they return different mapped addresses → Symmetric NAT
    /// 4. If mapped address == local address → No NAT
    pub async fn detect(&self, socket: &UdpSocket) -> Result<NatInfo, NatError> {
        let local_addr = socket.local_addr()?;
        debug!(local_addr = %local_addr, "starting NAT detection");

        // Probe first server
        let result1 = self.stun_client.discover(socket).await;

        match result1 {
            Ok(stun_result) => {
                let mapped = stun_result.mapped_addr;
                info!(
                    local = %local_addr,
                    external = %mapped,
                    "STUN probe succeeded"
                );

                // Check if we're on a public IP (no NAT)
                if mapped.ip() == local_addr.ip() && mapped.port() == local_addr.port() {
                    return Ok(NatInfo {
                        nat_type: NatType::None,
                        external_addr: Some(mapped),
                        local_addr,
                        hole_punch_capable: true,
                    });
                }

                // We're behind a NAT — classify it
                // For a thorough classification, we'd need to probe multiple
                // servers and compare mappings. With a single probe, we
                // conservatively assume Restricted NAT.
                let nat_type = NatType::Restricted;

                Ok(NatInfo {
                    nat_type,
                    external_addr: Some(mapped),
                    local_addr,
                    hole_punch_capable: nat_type.supports_hole_punch(),
                })
            }
            Err(e) => {
                warn!(error = %e, "NAT detection failed");
                Ok(NatInfo {
                    nat_type: NatType::Unknown,
                    external_addr: None,
                    local_addr,
                    hole_punch_capable: false,
                })
            }
        }
    }

    /// Classify NAT type by comparing two STUN probe results.
    ///
    /// This is the core classification logic, extracted for testability.
    pub fn classify(
        local_addr: SocketAddr,
        probe1: &StunResult,
        probe2: Option<&StunResult>,
    ) -> NatType {
        // No NAT: mapped address matches local
        if probe1.mapped_addr.ip() == local_addr.ip() {
            return NatType::None;
        }

        // If we have two probes, compare mappings
        if let Some(p2) = probe2 {
            if probe1.mapped_addr == p2.mapped_addr {
                // Same mapping for different destinations → Cone NAT
                // (Full Cone, Restricted, or Port-Restricted — needs
                //  additional tests to distinguish, default to Restricted)
                NatType::Restricted
            } else if probe1.mapped_addr.ip() == p2.mapped_addr.ip()
                && probe1.mapped_addr.port() != p2.mapped_addr.port()
            {
                // Same IP, different port → Port-Restricted
                NatType::PortRestricted
            } else {
                // Different IP → Symmetric NAT
                NatType::Symmetric
            }
        } else {
            // Only one probe — can't fully classify
            NatType::Restricted
        }
    }
}

impl Default for NatDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    fn stun_result(mapped: SocketAddr, server: SocketAddr) -> StunResult {
        StunResult {
            mapped_addr: mapped,
            server_addr: server,
        }
    }

    #[test]
    fn classify_no_nat() {
        let local = addr("203.0.113.1", 9000);
        let probe = stun_result(
            addr("203.0.113.1", 9000),
            addr("74.125.250.129", 19302),
        );
        assert_eq!(NatDetector::classify(local, &probe, None), NatType::None);
    }

    #[test]
    fn classify_cone_nat() {
        let local = addr("192.168.1.100", 9000);
        let server1 = addr("74.125.250.129", 19302);
        let server2 = addr("64.233.163.127", 19302);

        // Same mapped address from two servers → Cone NAT
        let mapped = addr("203.0.113.50", 12345);
        let probe1 = stun_result(mapped, server1);
        let probe2 = stun_result(mapped, server2);

        assert_eq!(
            NatDetector::classify(local, &probe1, Some(&probe2)),
            NatType::Restricted
        );
    }

    #[test]
    fn classify_symmetric_nat() {
        let local = addr("192.168.1.100", 9000);
        let server1 = addr("74.125.250.129", 19302);
        let server2 = addr("64.233.163.127", 19302);

        // Different mapped addresses → Symmetric
        let probe1 = stun_result(addr("203.0.113.50", 12345), server1);
        let probe2 = stun_result(addr("198.51.100.10", 54321), server2);

        assert_eq!(
            NatDetector::classify(local, &probe1, Some(&probe2)),
            NatType::Symmetric
        );
    }

    #[test]
    fn classify_port_restricted() {
        let local = addr("192.168.1.100", 9000);
        let server1 = addr("74.125.250.129", 19302);
        let server2 = addr("64.233.163.127", 19302);

        // Same IP, different port → Port-Restricted
        let probe1 = stun_result(addr("203.0.113.50", 12345), server1);
        let probe2 = stun_result(addr("203.0.113.50", 12346), server2);

        assert_eq!(
            NatDetector::classify(local, &probe1, Some(&probe2)),
            NatType::PortRestricted
        );
    }

    #[test]
    fn nat_type_hole_punch_capability() {
        assert!(NatType::None.supports_hole_punch());
        assert!(NatType::FullCone.supports_hole_punch());
        assert!(NatType::Restricted.supports_hole_punch());
        assert!(NatType::PortRestricted.supports_hole_punch());
        assert!(!NatType::Symmetric.supports_hole_punch());
        assert!(!NatType::Unknown.supports_hole_punch());
    }
}
