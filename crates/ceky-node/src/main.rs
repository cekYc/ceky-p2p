//! # ceky-node
//!
//! Main P2P node binary — orchestrates all cekyP2P subsystems.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                     ceky-node                        │
//! │                                                      │
//! │  ┌──────────┐  ┌───────────┐  ┌─────────────────┐  │
//! │  │ Protocol │  │ Transport │  │     Crypto       │  │
//! │  │  Codec   │──│ TCP / UDP │──│ Noise + Session  │  │
//! │  └──────────┘  └───────────┘  └─────────────────┘  │
//! │        │              │               │              │
//! │  ┌─────▼──────────────▼───────────────▼─────────┐   │
//! │  │              Node Event Loop                  │   │
//! │  │  ┌─────┐  ┌───────────┐  ┌──────────────┐   │   │
//! │  │  │ DHT │  │ Bootstrap │  │ NAT Traversal │   │   │
//! │  │  └─────┘  └───────────┘  └──────────────┘   │   │
//! │  └──────────────────────────────────────────────┘   │
//! └──────────────────────────────────────────────────────┘
//! ```

#[cfg(feature = "custom-allocator")]
use mimalloc::MiMalloc;

#[cfg(feature = "custom-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod config;

use anyhow::Result;
use bytes::Bytes;
use ceky_crypto::{Identity, NoiseHandshake, SecureSession};
use ceky_dht::RoutingTable;
use ceky_nat::NatDetector;
use ceky_protocol::{Flags, Frame, MessageType, MAGIC};
use ceky_protocol::transfer::{FileOffer, FileAccept, FileChunk, FileChunkAck};
use ceky_transfer::TransferManager;
use ceky_transport::{event_channel, pool::ConnectionPool, tcp::TcpTransport, udp::UdpTransport};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use config::{ConfigFile, ResolvedConfig};

/// cekyP2P node — zero-dependency P2P network.
#[derive(Parser, Debug)]
#[command(name = "ceky-node", version, about = "Decentralized P2P network node")]
pub struct Cli {
    /// Path to config file.
    #[arg(short = 'c', long, default_value = "ceky.toml")]
    config: PathBuf,

    /// TCP listen address.
    #[arg(short = 't', long)]
    tcp_addr: Option<SocketAddr>,

    /// UDP listen address.
    #[arg(short = 'u', long)]
    udp_addr: Option<SocketAddr>,

    /// Path to identity key file. Generated on first run.
    #[arg(short = 'k', long)]
    key_file: Option<PathBuf>,

    /// Seed node addresses to bootstrap from (comma-separated).
    #[arg(short = 's', long, value_delimiter = ',')]
    seeds: Option<Vec<SocketAddr>>,

    /// Maximum concurrent connections.
    #[arg(long)]
    max_connections: Option<usize>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short = 'l', long)]
    log_level: Option<String>,

    /// Skip NAT detection at startup.
    #[arg(long, default_value = "false")]
    skip_nat: bool,
}



/// State of a peer connection (Noise handshake and secure session).
enum PeerState {
    InitiatorWaitMsg2 { handshake: NoiseHandshake },
    ResponderWaitMsg1 { handshake: NoiseHandshake },
    ResponderWaitMsg3 { handshake: NoiseHandshake },
    Secure { session: SecureSession },
}



fn main() -> Result<()> {
    let cli = Cli::parse();

    // Parse config file if exists
    let config_file = ConfigFile::load_from_file(&cli.config).unwrap_or_else(|e| {
        println!("Warning: Failed to parse config file {}: {}", cli.config.display(), e);
        ConfigFile::default()
    });

    let resolved_config = ResolvedConfig::merge(
        cli.tcp_addr, cli.udp_addr, cli.key_file, cli.seeds,
        cli.max_connections, cli.log_level, cli.skip_nat, config_file
    );

    let (log_tx, log_rx) = crossbeam::channel::unbounded();
    let metrics = Arc::new(ceky_telemetry::GlobalMetrics::new());

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&resolved_config.log_level)),
        )
        .with(ceky_telemetry::TuiLoggerLayer::new(log_tx))
        .init();

    info!("ceky-node v{}", env!("CARGO_PKG_VERSION"));
    info!("protocol magic: 0x{:04X}", MAGIC);

    #[cfg(feature = "custom-allocator")]
    info!("allocator: mimalloc");
    #[cfg(not(feature = "custom-allocator"))]
    info!("allocator: system default");

    // Build and run the async runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ceky-worker")
        .build()?;

    let tui_metrics = Arc::clone(&metrics);
    rt.block_on(async move { run_node(resolved_config, tui_metrics, log_rx).await })
}

async fn run_node(config: ResolvedConfig, metrics: Arc<ceky_telemetry::GlobalMetrics>, log_rx: crossbeam::channel::Receiver<ceky_telemetry::LogMessage>) -> Result<()> {
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
    let shutdown_token = tokio_util::sync::CancellationToken::new();
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
    tokio::task::spawn_blocking(move || {
        let _ = ceky_telemetry::run_tui(tui_metrics, log_rx, ui_shutdown);
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
    info!("node is running — TUI active");

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!("shutdown signal received — stopping node...");
                break;
            }

            // Handle transport events
            event = tcp_event_rx.recv() => {
                match event {
                    Some(ceky_transport::TransportEvent::Connected { peer_addr }) => {
                        // Check if it's already in peer_states (meaning we initiated it)
                        if !peer_states.contains_key(&peer_addr) {
                            debug!(peer = %peer_addr, "inbound connection accepted, waiting for handshake MSG1");
                            let handshake = NoiseHandshake::new_responder(Arc::clone(&identity));
                            peer_states.insert(peer_addr, PeerState::ResponderWaitMsg1 { handshake });
                        }
                    }
                    Some(ceky_transport::TransportEvent::Disconnected { peer_addr, reason }) => {
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
                            // Normal frame processing — decrypt and dispatch
                            if let Some(PeerState::Secure { session }) = peer_states.get(&peer_addr) {
                                if frame.header.flags.is_encrypted() {
                                    match session.decrypt(frame.header.request_id, &frame.payload) {
                                        Ok(data) => {
                                            debug!(
                                                peer = %peer_addr,
                                                msg_type = %frame.header.msg_type,
                                                "secure frame received and decrypted"
                                            );
                                            // Dispatch to sub-systems based on msg_type
                                            match frame.header.msg_type {
                                                MessageType::FindNode | MessageType::FindNodeResp |
                                                MessageType::Store | MessageType::StoreResp |
                                                MessageType::FindValue | MessageType::FindValueResp => {
                                                    debug!("Routing to DHT: {:?}", frame.header.msg_type);
                                                    // TODO: dht_tx.send(...)
                                                }
                                                MessageType::FileOffer => {
                                                    if let Ok(offer) = FileOffer::decode(&data) {
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
                                                MessageType::NatProbe | MessageType::NatProbeResp |
                                                MessageType::HolePunch | MessageType::HolePunchResp => {
                                                    debug!("Routing to NAT: {:?}", frame.header.msg_type);
                                                    // TODO: nat_tx.send(...)
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

            // Handle outgoing transfer frames
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

    // Cleanup
    let stats = pool.stats();
    info!(
        active = stats.active,
        total_created = stats.total_created,
        bytes_recv = stats.total_bytes_recv,
        bytes_sent = stats.total_bytes_sent,
        "final pool stats"
    );

    let rt_stats = routing_table.stats();
    info!(
        peers = rt_stats.total_peers,
        active = rt_stats.active,
        "final routing table stats"
    );

    info!("ceky-node shutdown complete");
    Ok(())
}
