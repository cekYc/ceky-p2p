//! Minimal STUN client (RFC 5389 subset).
//!
//! Implements just enough of the STUN protocol to discover
//! the external (mapped) IP and port behind a NAT.
//!
//! Wire format:
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     STUN Message Type     |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Transaction ID (96 bits)                    |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::NatError;
use std::net::{SocketAddr, Ipv4Addr, IpAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, trace, warn};

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message type: Binding Request.
const BINDING_REQUEST: u16 = 0x0001;

/// STUN message type: Binding Response (success).
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute: MAPPED-ADDRESS (0x0001).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN attribute: XOR-MAPPED-ADDRESS (0x0020).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN header size (20 bytes).
const STUN_HEADER_SIZE: usize = 20;

/// Default STUN timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum STUN response size.
const MAX_RESPONSE_SIZE: usize = 576;

/// Result of a STUN probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResult {
    /// Our external (mapped) address as seen by the STUN server.
    pub mapped_addr: SocketAddr,
    /// The STUN server that responded.
    pub server_addr: SocketAddr,
}

/// Minimal STUN client for NAT discovery.
pub struct StunClient {
    /// STUN server addresses to try.
    servers: Vec<SocketAddr>,
    /// Request timeout.
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client with default public servers.
    pub fn new() -> Self {
        Self {
            servers: default_stun_servers(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a client with custom servers.
    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform a STUN binding request to discover our external address.
    ///
    /// Tries each configured server until one responds.
    pub async fn discover(&self, socket: &UdpSocket) -> Result<StunResult, NatError> {
        if self.servers.is_empty() {
            return Err(NatError::NoStunServers);
        }

        for server in &self.servers {
            match self.probe(socket, *server).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!(server = %server, error = %e, "STUN probe failed, trying next");
                }
            }
        }

        Err(NatError::StunFailed {
            reason: "all STUN servers failed".into(),
        })
    }

    /// Probe a single STUN server.
    pub async fn probe(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
    ) -> Result<StunResult, NatError> {
        // Build binding request
        let txn_id = generate_transaction_id();
        let request = build_binding_request(&txn_id);

        // Send request
        socket.send_to(&request, server).await?;
        debug!(server = %server, "STUN binding request sent");

        // Wait for response
        let mut buf = [0u8; MAX_RESPONSE_SIZE];
        let (len, from) = timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| NatError::StunTimeout {
                timeout_ms: self.timeout.as_millis() as u64,
            })??;

        trace!(server = %from, bytes = len, "STUN response received");

        // Parse response
        let mapped_addr = parse_binding_response(&buf[..len], &txn_id)?;

        Ok(StunResult {
            mapped_addr,
            server_addr: from,
        })
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random 12-byte transaction ID.
fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    // Use simple random from current time + thread ID as entropy
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = ((seed >> (i * 8)) & 0xFF) as u8;
    }
    id
}

/// Build a STUN Binding Request message.
fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(STUN_HEADER_SIZE);

    // Message type: Binding Request (0x0001)
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());

    // Message length: 0 (no attributes)
    msg.extend_from_slice(&0u16.to_be_bytes());

    // Magic cookie
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

    // Transaction ID (12 bytes)
    msg.extend_from_slice(txn_id);

    msg
}

/// Parse a STUN Binding Response to extract the mapped address.
fn parse_binding_response(
    data: &[u8],
    expected_txn_id: &[u8; 12],
) -> Result<SocketAddr, NatError> {
    if data.len() < STUN_HEADER_SIZE {
        return Err(NatError::StunFailed {
            reason: format!("response too short: {} bytes", data.len()),
        });
    }

    // Verify message type
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(NatError::StunFailed {
            reason: format!("unexpected message type: 0x{msg_type:04x}"),
        });
    }

    // Verify magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(NatError::StunFailed {
            reason: format!("invalid magic cookie: 0x{cookie:08x}"),
        });
    }

    // Verify transaction ID
    if &data[8..20] != expected_txn_id {
        return Err(NatError::StunFailed {
            reason: "transaction ID mismatch".into(),
        });
    }

    // Message length
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < STUN_HEADER_SIZE + msg_len {
        return Err(NatError::StunFailed {
            reason: "truncated response".into(),
        });
    }

    // Parse attributes
    let mut offset = STUN_HEADER_SIZE;
    let end = STUN_HEADER_SIZE + msg_len;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > end {
            break;
        }

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(&data[offset..offset + attr_len]);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(&data[offset..offset + attr_len]);
            }
            _ => {
                // Skip unknown attributes
                trace!(attr_type = attr_type, "skipping unknown STUN attribute");
            }
        }

        // Attributes are padded to 4-byte boundaries
        offset += (attr_len + 3) & !3;
    }

    Err(NatError::StunFailed {
        reason: "no mapped address in response".into(),
    })
}

/// Parse a MAPPED-ADDRESS attribute.
fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr, NatError> {
    if data.len() < 8 {
        return Err(NatError::StunFailed {
            reason: "MAPPED-ADDRESS too short".into(),
        });
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            // IPv4
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        _ => Err(NatError::StunFailed {
            reason: format!("unsupported address family: 0x{family:02x}"),
        }),
    }
}

/// Parse an XOR-MAPPED-ADDRESS attribute.
fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr, NatError> {
    if data.len() < 8 {
        return Err(NatError::StunFailed {
            reason: "XOR-MAPPED-ADDRESS too short".into(),
        });
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4: XOR with magic cookie
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                data[4] ^ cookie_bytes[0],
                data[5] ^ cookie_bytes[1],
                data[6] ^ cookie_bytes[2],
                data[7] ^ cookie_bytes[3],
            );
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        _ => Err(NatError::StunFailed {
            reason: format!("unsupported address family: 0x{family:02x}"),
        }),
    }
}

/// Default public STUN servers.
fn default_stun_servers() -> Vec<SocketAddr> {
    // Well-known public STUN servers (Google, Cloudflare)
    vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(74, 125, 250, 129)), 19302),  // stun.l.google.com
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(64, 233, 163, 127)), 19302),  // stun1.l.google.com
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_valid() {
        let txn_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let request = build_binding_request(&txn_id);

        assert_eq!(request.len(), STUN_HEADER_SIZE);
        // Message type = Binding Request
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);
        // Length = 0
        assert_eq!(request[2], 0x00);
        assert_eq!(request[3], 0x00);
        // Magic cookie
        assert_eq!(request[4], 0x21);
        assert_eq!(request[5], 0x12);
        assert_eq!(request[6], 0xA4);
        assert_eq!(request[7], 0x42);
        // Transaction ID
        assert_eq!(&request[8..20], &txn_id);
    }

    #[test]
    fn parse_xor_mapped_address_ipv4() {
        // Build a fake XOR-MAPPED-ADDRESS for 203.0.113.1:8080
        let ip = Ipv4Addr::new(203, 0, 113, 1);
        let port: u16 = 8080;
        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();

        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = [
            ip.octets()[0] ^ cookie_bytes[0],
            ip.octets()[1] ^ cookie_bytes[1],
            ip.octets()[2] ^ cookie_bytes[2],
            ip.octets()[3] ^ cookie_bytes[3],
        ];

        let data = [
            0x00, 0x01, // reserved + family (IPv4)
            (xor_port >> 8) as u8, (xor_port & 0xFF) as u8,
            xor_ip[0], xor_ip[1], xor_ip[2], xor_ip[3],
        ];

        let result = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(result.ip(), IpAddr::V4(ip));
        assert_eq!(result.port(), port);
    }

    #[test]
    fn parse_mapped_address_ipv4() {
        let data = [
            0x00, 0x01, // reserved + family (IPv4)
            0x1F, 0x90, // port = 8080
            192, 168, 1, 100, // IP
        ];

        let result = parse_mapped_address(&data).unwrap();
        assert_eq!(result, "192.168.1.100:8080".parse().unwrap());
    }

    #[test]
    fn parse_full_binding_response() {
        let txn_id = [0xAA; 12];
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let port: u16 = 12345;

        // Build MAPPED-ADDRESS attribute
        let attr_data = [
            0x00, 0x01, // family IPv4
            (port >> 8) as u8, (port & 0xFF) as u8,
            ip.octets()[0], ip.octets()[1], ip.octets()[2], ip.octets()[3],
        ];

        // Build full response
        let attr_len = attr_data.len() as u16;
        let msg_len = 4 + attr_len; // attr header (4) + attr data

        let mut response = Vec::new();
        // Header
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&msg_len.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);
        // Attribute header
        response.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&attr_len.to_be_bytes());
        // Attribute data
        response.extend_from_slice(&attr_data);

        let result = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(result.ip(), IpAddr::V4(ip));
        assert_eq!(result.port(), port);
    }

    #[test]
    fn reject_wrong_txn_id() {
        let txn_id = [0xAA; 12];
        let wrong_txn = [0xBB; 12];

        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&wrong_txn);

        let result = parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
    }

    #[test]
    fn reject_wrong_message_type() {
        let txn_id = [0xAA; 12];
        let mut response = Vec::new();
        response.extend_from_slice(&0x0111u16.to_be_bytes()); // Wrong type
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);

        let result = parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
    }
}
