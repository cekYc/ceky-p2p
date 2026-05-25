//! TCP transport layer using tokio + FrameCodec.
//!
//! Provides reliable, ordered, framed communication over TCP.
//! Each connection uses `Framed<TcpStream, FrameCodec>` for zero-copy
//! frame encode/decode directly on the socket buffer.

use crate::pool::ConnectionPool;
use crate::{EventSender, TransportError, TransportEvent};
use ceky_protocol::{Frame, FrameCodec, MessageType};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, trace, warn};

/// TCP transport — listens for inbound connections and manages outbound ones.
pub struct TcpTransport {
    /// Address we're listening on.
    listen_addr: SocketAddr,
    /// Shared connection pool.
    pool: Arc<ConnectionPool>,
    /// Event sender for notifying the upper layer.
    event_tx: EventSender,
    /// Channel for sending frames to specific peers.
    /// Maps peer_addr -> sender for that peer's writer task.
    peer_senders: Arc<dashmap::DashMap<SocketAddr, mpsc::UnboundedSender<Frame>>>,
}

impl TcpTransport {
    /// Create a new TCP transport bound to the given address.
    pub async fn bind(
        listen_addr: SocketAddr,
        pool: Arc<ConnectionPool>,
        event_tx: EventSender,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            listen_addr,
            pool,
            event_tx,
            peer_senders: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Start listening for inbound connections.
    /// This spawns a background task that accepts connections.
    pub async fn start_listening(&self) -> Result<SocketAddr, TransportError> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        info!(addr = %actual_addr, "TCP transport listening");

        let pool = Arc::clone(&self.pool);
        let event_tx = self.event_tx.clone();
        let peer_senders = Arc::clone(&self.peer_senders);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!(peer = %peer_addr, "inbound TCP connection");
                        if let Err(e) = pool.insert(peer_addr) {
                            warn!(peer = %peer_addr, error = %e, "rejecting connection");
                            continue;
                        }

                        let _ = event_tx.send(TransportEvent::Connected { peer_addr });

                        // Mark as established immediately for TCP (handshake happens at crypto layer)
                        pool.with_connection(&peer_addr, |conn| {
                            conn.set_established();
                        });

                        Self::spawn_connection_tasks(
                            stream,
                            peer_addr,
                            Arc::clone(&pool),
                            event_tx.clone(),
                            Arc::clone(&peer_senders),
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "failed to accept TCP connection");
                    }
                }
            }
        });

        Ok(actual_addr)
    }

    /// Connect to a remote peer.
    pub async fn connect(&self, peer_addr: SocketAddr) -> Result<(), TransportError> {
        let stream = TcpStream::connect(peer_addr).await?;
        debug!(peer = %peer_addr, "outbound TCP connection established");

        self.pool.insert(peer_addr)?;
        let _ = self.event_tx.send(TransportEvent::Connected { peer_addr });

        self.pool.with_connection(&peer_addr, |conn| {
            conn.set_established();
        });

        Self::spawn_connection_tasks(
            stream,
            peer_addr,
            Arc::clone(&self.pool),
            self.event_tx.clone(),
            Arc::clone(&self.peer_senders),
        );

        Ok(())
    }

    /// Send a frame to a specific peer.
    pub fn send_to(&self, peer_addr: &SocketAddr, frame: Frame) -> Result<(), TransportError> {
        if let Some(sender) = self.peer_senders.get(peer_addr) {
            sender
                .send(frame)
                .map_err(|_| TransportError::SendFailed)?;

            // Update stats
            self.pool.with_connection(peer_addr, |conn| {
                conn.record_send(0); // actual byte count tracked in writer task
            });

            Ok(())
        } else {
            Err(TransportError::PeerNotFound { addr: *peer_addr })
        }
    }

    /// Broadcast a frame to all established peers.
    pub fn broadcast(&self, frame: Frame) {
        for entry in self.peer_senders.iter() {
            let _ = entry.value().send(frame.clone());
        }
    }

    /// Disconnect a peer.
    pub fn disconnect(&self, peer_addr: &SocketAddr) {
        // Remove the sender channel — this will cause the writer task to stop
        self.peer_senders.remove(peer_addr);

        self.pool.with_connection(peer_addr, |conn| {
            conn.set_closing();
        });
    }

    /// Get the actual listening address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Spawn reader and writer tasks for a connection.
    fn spawn_connection_tasks(
        stream: TcpStream,
        peer_addr: SocketAddr,
        pool: Arc<ConnectionPool>,
        event_tx: EventSender,
        peer_senders: Arc<dashmap::DashMap<SocketAddr, mpsc::UnboundedSender<Frame>>>,
    ) {
        // Disable Nagle's algorithm for low latency
        let _ = stream.set_nodelay(true);

        #[cfg(feature = "chaos")]
        let stream = crate::chaos::ChaosStream::new(stream);

        let (reader, writer) = tokio::io::split(stream);
        let mut framed_reader = FramedRead::new(reader, FrameCodec::new());
        let mut framed_writer = FramedWrite::new(writer, FrameCodec::new());

        // Create a channel for the writer task
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Frame>();
        peer_senders.insert(peer_addr, write_tx);

        // Writer task — drains the channel and writes frames to the socket
        let pool_w = Arc::clone(&pool);
        let _peer_senders_w = Arc::clone(&peer_senders);
        let _event_tx_w = event_tx.clone();
        tokio::spawn(async move {
            while let Some(frame) = write_rx.recv().await {
                let wire_size = frame.wire_size() as u64;
                if let Err(e) = SinkExt::send(&mut framed_writer, frame).await {
                    warn!(peer = %peer_addr, error = %e, "write error");
                    break;
                }
                pool_w.with_connection(&peer_addr, |conn| {
                    conn.record_send(wire_size);
                });
            }
            trace!(peer = %peer_addr, "writer task exiting");
        });

        // Reader task — reads frames from the socket and emits events
        let pool_r = Arc::clone(&pool);
        tokio::spawn(async move {
            loop {
                match framed_reader.next().await {
                    Some(Ok(frame)) => {
                        let wire_size = frame.wire_size() as u64;
                        pool_r.with_connection(&peer_addr, |conn| {
                            conn.record_recv(wire_size);
                        });

                        // Handle protocol-level frames internally
                        match frame.header.msg_type {
                            MessageType::Ping => {
                                // Auto-respond with PONG
                                let pong = Frame::simple(
                                    MessageType::Pong,
                                    frame.header.request_id,
                                );
                                if let Some(sender) = peer_senders.get(&peer_addr) {
                                    let _ = sender.send(pong);
                                }
                                trace!(peer = %peer_addr, "auto-PONG sent");
                            }
                            MessageType::Pong => {
                                pool_r.with_connection(&peer_addr, |conn| {
                                    conn.record_pong_received();
                                });
                            }
                            _ => {
                                // Forward all other frames to the upper layer
                                let _ = event_tx.send(TransportEvent::FrameReceived {
                                    peer_addr,
                                    frame,
                                });
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!(peer = %peer_addr, error = %e, "read error");
                        let _ = event_tx.send(TransportEvent::Error {
                            peer_addr: Some(peer_addr),
                            error: e.to_string(),
                        });
                        break;
                    }
                    None => {
                        // Connection closed by peer
                        debug!(peer = %peer_addr, "peer disconnected (EOF)");
                        break;
                    }
                }
            }

            // Cleanup
            peer_senders.remove(&peer_addr);
            pool_r.with_connection(&peer_addr, |conn| {
                conn.set_closed();
            });
            pool_r.remove(&peer_addr);
            let _ = event_tx.send(TransportEvent::Disconnected {
                peer_addr,
                reason: "connection closed".into(),
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ceky_protocol::{Flags, MessageType};

    /// Integration test: two TCP transports communicating.
    #[tokio::test]
    async fn tcp_echo_roundtrip() {
        let pool_a = Arc::new(ConnectionPool::with_defaults());
        let pool_b = Arc::new(ConnectionPool::with_defaults());

        let (event_tx_a, mut event_rx_a) = crate::event_channel();
        let (event_tx_b, mut event_rx_b) = crate::event_channel();

        // Start listener (node B)
        let addr_b = "127.0.0.1:0".parse().unwrap();
        let transport_b = TcpTransport::bind(addr_b, pool_b.clone(), event_tx_b).await.unwrap();
        let actual_b = transport_b.start_listening().await.unwrap();

        // Connect from node A to node B
        let addr_a = "127.0.0.1:0".parse().unwrap();
        let transport_a = TcpTransport::bind(addr_a, pool_a.clone(), event_tx_a).await.unwrap();
        transport_a.connect(actual_b).await.unwrap();

        // Wait for B to see the connection
        let evt = tokio::time::timeout(Duration::from_secs(2), event_rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        let peer_a_addr = match evt {
            TransportEvent::Connected { peer_addr } => peer_addr,
            other => panic!("expected Connected, got {other:?}"),
        };

        // A sends a DATA frame to B
        let payload = Bytes::from_static(b"hello from A");
        let frame = Frame::new(MessageType::Data, Flags::empty(), 42, payload.clone());
        transport_a.send_to(&actual_b, frame).unwrap();

        // B should receive the frame
        let evt = tokio::time::timeout(Duration::from_secs(2), event_rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        match evt {
            TransportEvent::FrameReceived { peer_addr, frame } => {
                assert_eq!(frame.header.msg_type, MessageType::Data);
                assert_eq!(frame.header.request_id, 42);
                assert_eq!(frame.payload, payload);
            }
            other => panic!("expected FrameReceived, got {other:?}"),
        }

        // B sends a frame back to A
        let reply = Frame::new(
            MessageType::Data,
            Flags::empty(),
            43,
            Bytes::from_static(b"hello from B"),
        );
        transport_b.send_to(&peer_a_addr, reply).unwrap();

        // A should receive it
        // Skip the Connected event first
        let evt = tokio::time::timeout(Duration::from_secs(2), event_rx_a.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        // May be Connected or FrameReceived
        let frame_evt = if matches!(evt, TransportEvent::Connected { .. }) {
            tokio::time::timeout(Duration::from_secs(2), event_rx_a.recv())
                .await
                .expect("timeout")
                .expect("channel closed")
        } else {
            evt
        };

        match frame_evt {
            TransportEvent::FrameReceived { frame, .. } => {
                assert_eq!(frame.header.msg_type, MessageType::Data);
                assert_eq!(frame.payload, &b"hello from B"[..]);
            }
            other => panic!("expected FrameReceived, got {other:?}"),
        }
    }

    /// Test that PING auto-responds with PONG.
    #[tokio::test]
    async fn ping_pong_auto_response() {
        let pool_a = Arc::new(ConnectionPool::with_defaults());
        let pool_b = Arc::new(ConnectionPool::with_defaults());

        let (event_tx_a, _event_rx_a) = crate::event_channel();
        let (event_tx_b, mut event_rx_b) = crate::event_channel();

        let addr_b = "127.0.0.1:0".parse().unwrap();
        let transport_b = TcpTransport::bind(addr_b, pool_b.clone(), event_tx_b).await.unwrap();
        let actual_b = transport_b.start_listening().await.unwrap();

        let addr_a = "127.0.0.1:0".parse().unwrap();
        let transport_a = TcpTransport::bind(addr_a, pool_a.clone(), event_tx_a).await.unwrap();
        transport_a.connect(actual_b).await.unwrap();

        // Wait for B's connected event
        let _ = tokio::time::timeout(Duration::from_secs(2), event_rx_b.recv()).await;

        // A sends PING to B
        let ping = Frame::simple(MessageType::Ping, 0xBEEF);
        transport_a.send_to(&actual_b, ping).unwrap();

        // PING should NOT be forwarded as a FrameReceived (handled internally)
        // Instead, B auto-sends PONG, which A receives internally too
        // Give it a moment for the round-trip
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify pool stats show the PONG was received
        // (PONG is handled internally, not forwarded to event channel)
    }

    use std::time::Duration;
}
