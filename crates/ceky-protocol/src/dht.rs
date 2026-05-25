//! DHT message formats and helpers.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

pub const DHT_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum DhtError {
    #[error("unsupported dht version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("buffer too short: need {needed} bytes, got {got}")]
    BufferTooShort { needed: usize, got: usize },

    #[error("invalid address family: {family}")]
    InvalidAddressFamily { family: u8 },
}

fn ensure_remaining(buf: &impl Buf, needed: usize) -> Result<(), DhtError> {
    let got = buf.remaining();
    if got < needed {
        return Err(DhtError::BufferTooShort { needed, got });
    }
    Ok(())
}

fn read_peer_id(buf: &mut Bytes) -> Result<[u8; 32], DhtError> {
    ensure_remaining(buf, 32)?;
    let mut id = [0u8; 32];
    buf.copy_to_slice(&mut id);
    Ok(id)
}

fn write_socket_addr(buf: &mut BytesMut, addr: &SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        SocketAddr::V6(v6) => {
            buf.put_u8(6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
    }
}

fn read_socket_addr(buf: &mut Bytes) -> Result<SocketAddr, DhtError> {
    ensure_remaining(buf, 1)?;
    let family = buf.get_u8();
    match family {
        4 => {
            ensure_remaining(buf, 4 + 2)?;
            let mut ip = [0u8; 4];
            buf.copy_to_slice(&mut ip);
            let port = buf.get_u16();
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        6 => {
            ensure_remaining(buf, 16 + 2)?;
            let mut ip = [0u8; 16];
            buf.copy_to_slice(&mut ip);
            let port = buf.get_u16();
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => Err(DhtError::InvalidAddressFamily { family }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNode {
    pub target: [u8; 32],
}

impl FindNode {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + 32);
        buf.put_u8(DHT_VERSION);
        buf.extend_from_slice(&self.target);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, DhtError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 1 + 32)?;

        let version = buf.get_u8();
        if version != DHT_VERSION {
            return Err(DhtError::UnsupportedVersion { version });
        }

        let target = read_peer_id(&mut buf)?;
        Ok(Self { target })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNodeResp {
    pub peers: Vec<([u8; 32], SocketAddr)>,
}

impl FindNodeResp {
    pub fn encode(&self) -> Bytes {
        // approximate size: 1 (version) + 1 (count) + N * (32 + 7)
        let mut buf = BytesMut::with_capacity(2 + self.peers.len() * 40);
        buf.put_u8(DHT_VERSION);
        // max 255 peers
        let count = std::cmp::min(self.peers.len(), 255) as u8;
        buf.put_u8(count);
        for (id, addr) in self.peers.iter().take(count as usize) {
            buf.extend_from_slice(id);
            write_socket_addr(&mut buf, addr);
        }
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, DhtError> {
        let mut buf = Bytes::copy_from_slice(payload);
        ensure_remaining(&buf, 2)?;

        let version = buf.get_u8();
        if version != DHT_VERSION {
            return Err(DhtError::UnsupportedVersion { version });
        }

        let count = buf.get_u8();
        let mut peers = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let id = read_peer_id(&mut buf)?;
            let addr = read_socket_addr(&mut buf)?;
            peers.push((id, addr));
        }

        Ok(Self { peers })
    }
}
