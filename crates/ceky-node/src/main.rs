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

use anyhow::Result;
use ceky_crypto::Identity;
use ceky_dht::RoutingTable;
use ceky_nat::NatDetector;
use ceky_protocol::MAGIC;
use ceky_transport::{event_channel, pool::ConnectionPool, tcp::TcpTransport, udp::UdpTransport};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, error};

/// cekyP2P node — zero-dependency P2P network.
#[derive(Parser, Debug)]
#[command(name = "ceky-node", version, about = "Decentralized P2P network node")]
struct Cli {
    /// TCP listen address.
    #[arg(short = 't', long, default_value = "0.0.0.0:9741")]
    tcp_addr: SocketAddr,

    /// UDP listen address.
    #[arg(short = 'u', long, default_value = "0.0.0.0:9742")]
    udp_addr: SocketAddr,

    /// Path to identity key file. Generated on first run.
    #[arg(short = 'k', long, default_value = "identity.key")]
    key_file: PathBuf,

    /// Seed node addresses to bootstrap from (comma-separated).
    #[arg(short = 's', long, value_delimiter = ',')]
    seeds: Vec<SocketAddr>,

    /// Maximum concurrent connections.
    #[arg(long, default_value = "1024")]
    max_connections: usize,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short = 'l', long, default_value = "info")]
    log_level: String,

    /// Skip NAT detection at startup.
    #[arg(long, default_value = "false")]
    skip_nat: bool,
}

/// Print the startup banner.
fn print_banner() {
    println!(r#"
     ██████╗███████╗██╗  ██╗██╗   ██╗██████╗ ██████╗ ██████╗
    ██╔════╝██╔════╝██║ ██╔╝╚██╗ ██╔╝██╔══██╗╚════██╗██╔══██╗
    ██║     █████╗  █████╔╝  ╚████╔╝ ██████╔╝ █████╔╝██████╔╝
    ██║     ██╔══╝  ██╔═██╗   ╚██╔╝  ██╔═══╝ ██╔═══╝ ██╔═══╝
    ╚██████╗███████╗██║  ██╗   ██║   ██║     ███████╗██║
     ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝
    "#);
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    print_banner();

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

    rt.block_on(async move { run_node(cli).await })
}

async fn run_node(cli: Cli) -> Result<()> {
    // --- Identity ---
    let identity = if cli.key_file.exists() {
        info!(path = %cli.key_file.display(), "loading existing identity");
        Identity::load_from_file(&cli.key_file)?
    } else {
        info!("generating new identity");
        let id = Identity::generate();
        id.save_to_file(&cli.key_file)?;
        info!(path = %cli.key_file.display(), "identity saved");
        id
    };

    let identity = Arc::new(identity);
    info!(peer_id = %identity.peer_id, "node identity ready");

    // --- Connection Pool ---
    let pool = Arc::new(ConnectionPool::new(
        cli.max_connections,
        ceky_transport::connection::ConnectionConfig::default(),
    ));

    // --- Transport Layer ---
    let (tcp_event_tx, mut tcp_event_rx) = event_channel();
    let (udp_event_tx, mut _udp_event_rx) = event_channel();

    let tcp_transport = TcpTransport::bind(cli.tcp_addr, pool.clone(), tcp_event_tx).await?;
    let tcp_addr = tcp_transport.start_listening().await?;
    info!(addr = %tcp_addr, "TCP transport ready");

    let udp_transport = UdpTransport::bind(cli.udp_addr, udp_event_tx).await?;
    let udp_addr = udp_transport.local_addr()?;
    udp_transport.start_receiving();
    info!(addr = %udp_addr, "UDP transport ready");

    // --- NAT Detection ---
    if !cli.skip_nat {
        info!("detecting NAT type...");
        let nat_detector = NatDetector::new();
        match nat_detector.detect(udp_transport.socket()).await {
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
    let routing_table = RoutingTable::new(identity.peer_id);
    info!("DHT routing table initialized");

    // --- Bootstrap ---
    if !cli.seeds.is_empty() {
        info!(seeds = cli.seeds.len(), "connecting to seed nodes...");
        for seed_addr in &cli.seeds {
            match tcp_transport.connect(*seed_addr).await {
                Ok(()) => info!(seed = %seed_addr, "connected to seed"),
                Err(e) => warn!(seed = %seed_addr, error = %e, "failed to connect to seed"),
            }
        }
    } else {
        info!("no seed nodes configured — running in standalone mode");
    }

    // --- Event Loop ---
    info!("node is running — press Ctrl+C to stop");

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            // Handle transport events
            event = tcp_event_rx.recv() => {
                match event {
                    Some(ceky_transport::TransportEvent::Connected { peer_addr }) => {
                        info!(peer = %peer_addr, "peer connected");
                    }
                    Some(ceky_transport::TransportEvent::Disconnected { peer_addr, reason }) => {
                        info!(peer = %peer_addr, reason = %reason, "peer disconnected");
                    }
                    Some(ceky_transport::TransportEvent::FrameReceived { peer_addr, frame }) => {
                        info!(
                            peer = %peer_addr,
                            msg_type = %frame.header.msg_type,
                            payload_bytes = frame.payload.len(),
                            "frame received"
                        );
                    }
                    Some(ceky_transport::TransportEvent::Error { peer_addr, error }) => {
                        warn!(peer = ?peer_addr, error = %error, "transport error");
                    }
                    None => {
                        error!("event channel closed unexpectedly");
                        break;
                    }
                }
            }

            // Graceful shutdown
            _ = &mut shutdown => {
                info!("shutdown signal received — stopping node...");
                break;
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
