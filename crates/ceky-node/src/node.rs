use anyhow::Result;
use bytes::Bytes;
use ceky_crypto::{Identity, NoiseHandshake, SecureSession};
use ceky_dht::RoutingTable;
use ceky_nat::NatDetector;
use ceky_protocol::{Flags, Frame, MessageType};
use ceky_protocol::transfer::{FileOffer, FileAccept, FileChunk, FileChunkAck};
use ceky_transfer::TransferManager;
use ceky_transport::{event_channel, pool::ConnectionPool, tcp::TcpTransport, udp::UdpTransport};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use tracing::{debug, error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::config::ResolvedConfig;
use crate::api::{self, ApiCommand};

/// Handle to interact with the running node.
pub struct NodeHandle {
    pub command_tx: mpsc::UnboundedSender<ApiCommand>,
    pub event_rx: broadcast::Receiver<serde_json::Value>,
    pub shutdown_token: CancellationToken,
}

enum PeerState {
    InitiatorWaitMsg2 { handshake: NoiseHandshake },
    ResponderWaitMsg1 { handshake: NoiseHandshake },
    ResponderWaitMsg3 { handshake: NoiseHandshake },
    Secure { session: SecureSession },
}

pub async fn start_node(
    config: ResolvedConfig,
    metrics: Arc<ceky_telemetry::GlobalMetrics>,
    log_rx: crossbeam::channel::Receiver<ceky_telemetry::LogMessage>,
) -> Result<NodeHandle> {
    // --- Identity ---
    let identity = if config.key_file.exists() {
        info!(path = %config.key_file.display(), "loading existing identity");
        Identity::load_from_file(&config.key_file)?
    } else {
        info!("generating new identity");
        let id = Identity::generate();
        id.save_to_file(&config.key_file)?;
        info!(path = %config.key_file.display(), "identity saved");
        id
    };

    let identity = Arc::new(identity);
    info!(peer_id = %identity.peer_id, "node identity ready");

    // --- Connection Pool ---
    let pool = Arc::new(ConnectionPool::new(
        config.max_connections,
        ceky_transport::connection::ConnectionConfig::default(),
    ));

    // --- Transport Layer ---
    let (tcp_event_tx, mut tcp_event_rx) = event_channel();
    let (udp_event_tx, mut _udp_event_rx) = event_channel();

    let tcp_transport = TcpTransport::bind(config.tcp_addr, pool.clone(), tcp_event_tx).await?;
    let tcp_addr = tcp_transport.start_listening().await?;
    info!(addr = %tcp_addr, "TCP transport ready");

    let udp_transport = UdpTransport::bind(config.udp_addr, udp_event_tx).await?;
    let udp_addr = udp_transport.local_addr()?;
    udp_transport.start_receiving();
    info!(addr = %udp_addr, "UDP transport ready");

    // --- NAT Detection ---
    if !config.skip_nat {
        info!("detecting NAT type...");
        let nat_detector = NatDetector::new();
        match nat_detector.detect(udp_transport.inner_socket()).await {
            Ok(nat_info) => {
                info!(
                    nat_type = %nat_info.nat_type,
                    external = ?nat_info.external_addr,
                    hole_punch = nat_info.hole_punch_capable,
                    "NAT detection complete"
                );
            }
            Err(e) => {
                warn!(error = %e, "NAT detection failed (continuing without external address)");
            }
        }
    }

    // --- DHT Routing Table ---
    let routing_table = RoutingTable::new(identity.peer_id.clone());
    info!("DHT routing table initialized");

    // --- Transfer Manager ---
    let (transfer_frame_tx, mut transfer_frame_rx) = mpsc::unbounded_channel::<(SocketAddr, Frame)>();
    let transfer_manager = Arc::new(TransferManager::new(
        PathBuf::from("downloads"),
        transfer_frame_tx,
    ));
    info!("Transfer manager initialized");

    // --- Telemetry Updater Task ---
    let shutdown_token = CancellationToken::new();
    let ui_shutdown = shutdown_token.clone();
    
    let metrics_updater = metrics.clone();
    let update_pool = pool.clone();
    let update_tm = transfer_manager.clone();
    let update_token = shutdown_token.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let p_stats = update_pool.stats();
                    metrics_updater.active_tcp_connections.store(p_stats.active, std::sync::atomic::Ordering::Relaxed);
                    
                    let prev_tx = metrics_updater.tx_bytes.swap(p_stats.total_bytes_sent as usize, std::sync::atomic::Ordering::Relaxed);
                    let prev_rx = metrics_updater.rx_bytes.swap(p_stats.total_bytes_recv as usize, std::sync::atomic::Ordering::Relaxed);
                    
                    metrics_updater.tx_rate.store((p_stats.total_bytes_sent as usize).saturating_sub(prev_tx), std::sync::atomic::Ordering::Relaxed);
                    metrics_updater.rx_rate.store((p_stats.total_bytes_recv as usize).saturating_sub(prev_rx), std::sync::atomic::Ordering::Relaxed);
                    
                    let t_stats = update_tm.snapshot_transfers();
                    let mut transfers = Vec::new();
                    for (id, name, total, completed, is_sending) in t_stats {
                        transfers.push(ceky_telemetry::TransferProgress {
                            transfer_id: hex::encode(id.as_bytes()),
                            file_name: name,
                            total_chunks: total,
                            completed_chunks: completed,
                            is_sending,
                        });
                    }
                    if let Ok(mut lock) = metrics_updater.transfers.write() {
                        *lock = transfers;
                    }
                }
                _ = update_token.cancelled() => break,
            }
        }
    });

    let tui_metrics = Arc::clone(&metrics);
    if !config.daemon {
        tokio::task::spawn_blocking(move || {
            let _ = ceky_telemetry::run_tui(tui_metrics, log_rx, ui_shutdown);
        });
    } else {
        info!("Running in daemon mode. TUI is disabled.");
        tokio::spawn(async move {
            // Drain the unused log channel
            while let Ok(_) = log_rx.recv() {}
        });
    }

    // --- API Task (Sidecar) ---
    let (api_command_tx, mut api_command_rx) = mpsc::unbounded_channel::<api::ApiCommand>();
    let (api_event_tx, api_event_rx) = tokio::sync::broadcast::channel(100);

    let api_state = Arc::new(api::ApiState {
        metrics: Arc::clone(&metrics),
        identity: Arc::clone(&identity),
        tcp_addr: config.tcp_addr,
        udp_addr: config.udp_addr,
        api_key: config.api_key.clone(),
        command_tx: api_command_tx.clone(),
        event_tx: api_event_tx.clone(),
    });

    let api_port = config.api_port;
    let api_shutdown = shutdown_token.clone();
    tokio::spawn(async move {
        tokio::select! {
            res = api::start_api_server(api_port, api_state) => {
                if let Err(e) = res {
                    tracing::error!("API server failed: {}", e);
                }
            }
            _ = api_shutdown.cancelled() => {}
        }
    });

    // --- Control Plane Task ---
    let mut peer_states: HashMap<SocketAddr, PeerState> = HashMap::new();

    // --- Bootstrap ---
    if !config.seeds.is_empty() {
        info!(seeds = config.seeds.len(), "connecting to seed nodes...");
        for seed_addr in &config.seeds {
            match tcp_transport.connect(*seed_addr).await {
                Ok(()) => {
                    info!(seed = %seed_addr, "connected to seed (TCP), starting handshake");
                    let mut handshake = NoiseHandshake::new_initiator(Arc::clone(&identity));
                    match handshake.create_message1() {
                        Ok(msg1) => {
                            let frame = Frame::new(MessageType::Handshake, Flags::empty(), 0, Bytes::from(msg1));
                            if let Err(e) = tcp_transport.send_to(seed_addr, frame) {
                                warn!("Failed to send MSG1 to {}: {}", seed_addr, e);
                            } else {
                                peer_states.insert(*seed_addr, PeerState::InitiatorWaitMsg2 { handshake });
                            }
                        }
                        Err(e) => warn!("Failed to create MSG1: {}", e),
                    }
                }
                Err(e) => warn!(seed = %seed_addr, error = %e, "failed to connect to seed"),
            }
        }
    } else {
        info!("no seed nodes configured — running in standalone mode");
    }

    // --- Event Loop ---
    let event_loop_shutdown = shutdown_token.clone();
    let event_loop_api_tx = api_event_tx.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = event_loop_shutdown.cancelled() => {
                    info!("shutdown signal received — stopping node event loop...");
                    break;
                }

                cmd = api_command_rx.recv() => {
                    if let Some(command) = cmd {
                        match command {
                            api::ApiCommand::Connect(addr) => {
                                info!(target = %addr, "API requested connection");
                                if let Err(e) = tcp_transport.connect(addr).await {
                                    warn!("API connection request to {} failed: {}", addr, e);
                                } else {
                                    let mut handshake = NoiseHandshake::new_initiator(Arc::clone(&identity));
                                    if let Ok(msg1) = handshake.create_message1() {
                                        let frame = Frame::new(MessageType::Handshake, Flags::empty(), 0, bytes::Bytes::from(msg1));
                                        if let Err(e) = tcp_transport.send_to(&addr, frame) {
                                            warn!("API failed to send MSG1 to {}: {}", addr, e);
                                        } else {
                                            peer_states.insert(addr, PeerState::InitiatorWaitMsg2 { handshake });
                                        }
                                    }
                                }
                            }
                            api::ApiCommand::SendFile { target, file_path } => {
                                info!(target = %target, file = ?file_path, "API requested file transfer");
                                if peer_states.contains_key(&target) {
                                    let _ = transfer_manager.offer_file(target, &file_path, 1000);
                                } else {
                                    warn!("Cannot send file, not connected to peer: {}", target);
                                }
                            }
                            api::ApiCommand::SendMessage { target, message } => {
                                info!(target = %target, "API requested message send");
                                if let Some(PeerState::Secure { session }) = peer_states.get_mut(&target) {
                                    if let Ok((enc_nonce, ciphertext)) = session.encrypt(message.as_bytes()) {
                                        let frame = Frame::new(MessageType::Data, Flags::empty().with_encrypted(), enc_nonce, bytes::Bytes::from(ciphertext));
                                        if let Err(e) = tcp_transport.send_to(&target, frame) {
                                            warn!("Failed to send message to {}: {}", target, e);
                                        }
                                    }
                                } else {
                                    warn!("Cannot send message, secure session not ready for {}", target);
                                }
                            }
                        }
                    }
                }

                event = tcp_event_rx.recv() => {
                    match event {
                        Some(ceky_transport::TransportEvent::Connected { peer_addr }) => {
                            let _ = event_loop_api_tx.send(serde_json::json!({
                                "event": "peer_connected",
                                "peer": peer_addr.to_string()
                            }));
                            if !peer_states.contains_key(&peer_addr) {
                                debug!(peer = %peer_addr, "inbound connection accepted, waiting for handshake MSG1");
                                let handshake = NoiseHandshake::new_responder(Arc::clone(&identity));
                                peer_states.insert(peer_addr, PeerState::ResponderWaitMsg1 { handshake });
                            }
                        }
                        Some(ceky_transport::TransportEvent::Disconnected { peer_addr, reason }) => {
                            let _ = event_loop_api_tx.send(serde_json::json!({
                                "event": "peer_disconnected",
                                "peer": peer_addr.to_string(),
                                "reason": reason.to_string()
                            }));
                            peer_states.remove(&peer_addr);
                            info!(peer = %peer_addr, reason = %reason, "peer disconnected");
                        }
                        Some(ceky_transport::TransportEvent::FrameReceived { peer_addr, frame }) => {
                            if frame.header.msg_type == MessageType::Handshake {
                                if let Some(state) = peer_states.remove(&peer_addr) {
                                    match state {
                                        PeerState::InitiatorWaitMsg2 { mut handshake } => {
                                            match handshake.process_message2_create_message3(&frame.payload) {
                                                Ok(msg3) => {
                                                    let f = Frame::new(MessageType::Handshake, Flags::empty(), 0, Bytes::from(msg3));
                                                    let _ = tcp_transport.send_to(&peer_addr, f);
                                                    if let Ok(keys) = handshake.into_session_keys() {
                                                        if let Ok(session) = SecureSession::from_keys(keys) {
                                                            peer_states.insert(peer_addr, PeerState::Secure { session });
                                                            info!(peer = %peer_addr, "handshake complete (initiator) - session secure");
                                                        }
                                                    }
                                                }
                                                Err(e) => warn!("MSG2 process failed for {}: {}", peer_addr, e),
                                            }
                                        }
                                        PeerState::ResponderWaitMsg1 { mut handshake } => {
                                            match handshake.process_message1_create_message2(&frame.payload) {
                                                Ok(msg2) => {
                                                    let f = Frame::new(MessageType::Handshake, Flags::empty(), 0, Bytes::from(msg2));
                                                    let _ = tcp_transport.send_to(&peer_addr, f);
                                                    peer_states.insert(peer_addr, PeerState::ResponderWaitMsg3 { handshake });
                                                }
                                                Err(e) => warn!("MSG1 process failed for {}: {}", peer_addr, e),
                                            }
                                        }
                                        PeerState::ResponderWaitMsg3 { mut handshake } => {
                                            match handshake.process_message3(&frame.payload) {
                                                Ok(()) => {
                                                    if let Ok(keys) = handshake.into_session_keys() {
                                                        if let Ok(session) = SecureSession::from_keys(keys) {
                                                            peer_states.insert(peer_addr, PeerState::Secure { session });
                                                            info!(peer = %peer_addr, "handshake complete (responder) - session secure");
                                                        }
                                                    }
                                                }
                                                Err(e) => warn!("MSG3 process failed for {}: {}", peer_addr, e),
                                            }
                                        }
                                        PeerState::Secure { session } => {
                                            warn!(peer = %peer_addr, "received handshake frame on already secure session");
                                            peer_states.insert(peer_addr, PeerState::Secure { session });
                                        }
                                    }
                                } else {
                                    warn!(peer = %peer_addr, "received handshake frame from unknown state");
                                }
                            } else {
                                if let Some(PeerState::Secure { session }) = peer_states.get(&peer_addr) {
                                    if frame.header.flags.is_encrypted() {
                                        match session.decrypt(frame.header.request_id, &frame.payload) {
                                            Ok(data) => {
                                                debug!(
                                                    peer = %peer_addr,
                                                    msg_type = %frame.header.msg_type,
                                                    "secure frame received and decrypted"
                                                );
                                                match frame.header.msg_type {
                                                    MessageType::FileOffer => {
                                                        if let Ok(offer) = FileOffer::decode(&data) {
                                                            let _ = event_loop_api_tx.send(serde_json::json!({
                                                                "event": "file_offer_received",
                                                                "peer": peer_addr.to_string(),
                                                                "file_name": offer.file_name.clone(),
                                                                "total_size": offer.file_size
                                                            }));
                                                            let _ = transfer_manager.handle_offer(peer_addr, offer);
                                                        }
                                                    }
                                                    MessageType::FileAccept => {
                                                        if let Ok(accept) = FileAccept::decode(&data) {
                                                            let _ = transfer_manager.handle_accept(accept);
                                                        }
                                                    }
                                                    MessageType::FileChunk => {
                                                        if let Ok(chunk) = FileChunk::decode(bytes::Bytes::copy_from_slice(&data)) {
                                                            let _ = transfer_manager.handle_chunk(chunk);
                                                        }
                                                    }
                                                    MessageType::FileChunkAck => {
                                                        if let Ok(ack) = FileChunkAck::decode(&data) {
                                                            let _ = transfer_manager.handle_chunk_ack(ack);
                                                        }
                                                    }
                                                    MessageType::CreditUpdate => {
                                                        if data.len() >= 20 {
                                                            let mut id = [0u8; 16];
                                                            id.copy_from_slice(&data[0..16]);
                                                            let tid = ceky_protocol::transfer::TransferId::from_bytes(id);
                                                            let mut cred = [0u8; 4];
                                                            cred.copy_from_slice(&data[16..20]);
                                                            let credits = u32::from_le_bytes(cred);
                                                            let _ = transfer_manager.handle_credit_update(tid, credits);
                                                        }
                                                    }
                                                    MessageType::Data => {
                                                        if let Ok(msg_str) = String::from_utf8(data.to_vec()) {
                                                            let _ = event_loop_api_tx.send(serde_json::json!({
                                                                "event": "message_received",
                                                                "peer": peer_addr.to_string(),
                                                                "message": msg_str
                                                            }));
                                                        }
                                                    }
                                                    _ => {
                                                        debug!("Application data: {} bytes", data.len());
                                                    }
                                                }
                                            }
                                            Err(e) => warn!(peer = %peer_addr, error = %e, "decryption failed"),
                                        }
                                    } else {
                                        warn!(peer = %peer_addr, "unencrypted frame on secure session rejected");
                                    }
                                } else {
                                    warn!(peer = %peer_addr, "received normal frame on non-secure connection");
                                }
                            }
                        }
                        Some(ceky_transport::TransportEvent::Error { peer_addr, error }) => {
                            warn!(peer = ?peer_addr, error = %error, "transport error");
                            if let Some(addr) = peer_addr {
                                peer_states.remove(&addr);
                            }
                        }
                        None => {
                            error!("event channel closed unexpectedly");
                            break;
                        }
                    }
                }

                transfer_opt = transfer_frame_rx.recv() => {
                    if let Some((peer_addr, frame)) = transfer_opt {
                        if let Some(PeerState::Secure { session }) = peer_states.get_mut(&peer_addr) {
                            if let Ok((enc_nonce, ciphertext)) = session.encrypt(&frame.payload) {
                                let enc_frame = Frame::new(frame.header.msg_type, Flags::empty().with_encrypted(), enc_nonce, Bytes::from(ciphertext));
                                if let Err(e) = tcp_transport.send_to(&peer_addr, enc_frame) {
                                    warn!("Failed to send transfer frame to {}: {}", peer_addr, e);
                                }
                            }
                        } else {
                            warn!("Cannot send transfer frame: session not secure for {}", peer_addr);
                        }
                    }
                }
            }
        }

        let stats = pool.stats();
        info!(
            active = stats.active,
            total_created = stats.total_created,
            bytes_recv = stats.total_bytes_recv,
            bytes_sent = stats.total_bytes_sent,
            "final pool stats"
        );
        let rt_stats = routing_table.stats();
        info!(peers = rt_stats.total_peers, active = rt_stats.active, "final routing table stats");
        info!("ceky-node shutdown complete");
    });

    Ok(NodeHandle {
        command_tx: api_command_tx,
        event_rx: api_event_rx,
        shutdown_token,
    })
}
