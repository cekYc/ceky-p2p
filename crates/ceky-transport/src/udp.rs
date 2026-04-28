//! UDP transport for datagram-based communication.
//!
//! Used primarily for:
//! - NAT traversal (hole punching)
//! - DHT queries (lightweight, no connection overhead)
//! - STUN probes
//!
//! Unlike TCP, UDP is connectionless — we encode/decode frames
//! per-datagram. Each datagram must contain a complete frame.

use crate::{EventSender, TransportError, TransportEvent};
use ceky_protocol::{Frame, FrameCodec};
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error, trace, warn};

/// Maximum UDP datagram size we'll handle.
/// Standard MTU is 1500, minus IP(20) and UDP(8) headers = 1472.
/// We use a larger buffer for non-fragmented local traffic.
const MAX_DATAGRAM_SIZE: usize = 65535;

/// UDP transport — stateless, frame-per-datagram communication.
pub struct UdpTransport {
    /// The underlying UDP socket (shared via Arc for send/recv split).
    socket: Arc<UdpSocket>,
    /// Event sender for notifying the upper layer.
    event_tx: EventSender,
}

impl UdpTransport {
    /// Create a new UDP transport bound to the given address.
    pub async fn bind(
        listen_addr: SocketAddr,
        event_tx: EventSender,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(listen_addr).await?;
        let actual_addr = socket.local_addr()?;
        debug!(addr = %actual_addr, "UDP transport bound");

        Ok(Self {
            socket: Arc::new(socket),
            event_tx,
        })
    }

    /// Get the actual bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }

    /// Start receiving datagrams in a background task.
    pub fn start_receiving(&self) {
        let socket = Arc::clone(&self.socket);
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer_addr)) => {
                        trace!(peer = %peer_addr, bytes = len, "UDP datagram received");

                        // Decode the frame from the datagram
                        let mut data = BytesMut::from(&buf[..len]);
                        let mut codec = FrameCodec::new();

                        match codec.decode(&mut data) {
                            Ok(Some(frame)) => {
                                let _ = event_tx.send(TransportEvent::FrameReceived {
                                    peer_addr,
                                    frame,
                                });
                            }
                            Ok(None) => {
                                warn!(
                                    peer = %peer_addr,
                                    bytes = len,
                                    "incomplete UDP frame (truncated datagram)"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    peer = %peer_addr,
                                    error = %e,
                                    "invalid UDP frame"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "UDP recv error");
                        // Non-fatal for UDP — keep listening
                    }
                }
            }
        });
    }

    /// Send a frame to a specific address via UDP.
    pub async fn send_to(
        &self,
        peer_addr: SocketAddr,
        frame: Frame,
    ) -> Result<usize, TransportError> {
        let mut buf = BytesMut::with_capacity(frame.wire_size());
        let mut codec = FrameCodec::new();

        codec
            .encode(frame, &mut buf)
            .map_err(TransportError::Protocol)?;

        let bytes_sent = self.socket.send_to(&buf, peer_addr).await?;
        trace!(peer = %peer_addr, bytes = bytes_sent, "UDP datagram sent");
        Ok(bytes_sent)
    }

    /// Send raw bytes to a specific address (for STUN/NAT probes).
    pub async fn send_raw(
        &self,
        peer_addr: SocketAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        let bytes_sent = self.socket.send_to(data, peer_addr).await?;
        Ok(bytes_sent)
    }

    /// Get a reference to the underlying socket (for NAT traversal).
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ceky_protocol::{Flags, MessageType};
    use std::time::Duration;

    #[tokio::test]
    async fn udp_roundtrip() {
        let (event_tx_a, _) = crate::event_channel();
        let (event_tx_b, mut event_rx_b) = crate::event_channel();

        // Bind two UDP transports on random ports
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport_a = UdpTransport::bind(addr, event_tx_a).await.unwrap();
        let transport_b = UdpTransport::bind(addr, event_tx_b).await.unwrap();

        let addr_a = transport_a.local_addr().unwrap();
        let addr_b = transport_b.local_addr().unwrap();

        // Start B receiving
        transport_b.start_receiving();

        // A sends a frame to B
        let payload = Bytes::from_static(b"UDP zero-copy test");
        let frame = Frame::new(MessageType::FindNode, Flags::empty(), 0xCAFE, payload.clone());
        let sent = transport_a.send_to(addr_b, frame).await.unwrap();
        assert!(sent > 0);

        // B should receive the frame
        let evt = tokio::time::timeout(Duration::from_secs(2), event_rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match evt {
            TransportEvent::FrameReceived { peer_addr, frame } => {
                assert_eq!(peer_addr, addr_a);
                assert_eq!(frame.header.msg_type, MessageType::FindNode);
                assert_eq!(frame.header.request_id, 0xCAFE);
                assert_eq!(frame.payload, payload);
            }
            other => panic!("expected FrameReceived, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_multiple_frames() {
        let (event_tx, mut event_rx) = crate::event_channel();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let sender = UdpTransport::bind(addr, {
            let (tx, _) = crate::event_channel();
            tx
        })
        .await
        .unwrap();
        let receiver = UdpTransport::bind(addr, event_tx).await.unwrap();
        let recv_addr = receiver.local_addr().unwrap();
        receiver.start_receiving();

        // Send 5 frames rapidly
        for i in 0..5u64 {
            let frame = Frame::simple(MessageType::Ping, i);
            sender.send_to(recv_addr, frame).await.unwrap();
        }

        // Receive all 5
        for _i in 0..5u64 {
            let evt = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");

            if let TransportEvent::FrameReceived { frame, .. } = evt {
                assert_eq!(frame.header.msg_type, MessageType::Ping);
                // Note: UDP doesn't guarantee order, so we just check count
            }
        }
    }
}
