use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use ceky_node::config::{ConfigFile, ResolvedConfig};
use ceky_protocol::MAGIC;

#[cfg(feature = "custom-allocator")]
use mimalloc::MiMalloc;

#[cfg(feature = "custom-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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

    /// API server port (Sidecar mode).
    #[arg(long)]
    api_port: Option<u16>,

    /// API token for authentication.
    #[arg(long)]
    api_key: Option<String>,

    /// Run as a background daemon without TUI.
    #[arg(long, default_value = "false")]
    daemon: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Parse config file if exists
    let config_file = ConfigFile::load_from_file(&cli.config).unwrap_or_else(|e| {
        println!("Warning: Failed to parse config file {}: {}", cli.config.display(), e);
        ConfigFile::default()
    });

    let config = ResolvedConfig::merge(
        cli.tcp_addr,
        cli.udp_addr,
        cli.key_file,
        cli.seeds,
        cli.max_connections,
        cli.log_level,
        cli.skip_nat,
        cli.api_port,
        cli.api_key,
        cli.daemon,
        config_file,
    );

    let (log_tx, log_rx) = crossbeam::channel::unbounded();
    let metrics = Arc::new(ceky_telemetry::GlobalMetrics::new());

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));

    if config.daemon {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(ceky_telemetry::TuiLoggerLayer::new(log_tx))
            .init();
    }

    info!("ceky-node v{}", env!("CARGO_PKG_VERSION"));
    info!("protocol magic: 0x{:04X}", MAGIC);

    // Build and run the async runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ceky-worker")
        .build()?;

    let tui_metrics = Arc::clone(&metrics);
    rt.block_on(async move {
        let handle = ceky_node::node::start_node(config, tui_metrics, log_rx).await?;
        
        tokio::signal::ctrl_c().await?;
        info!("Received Ctrl-C, shutting down...");
        handle.shutdown_token.cancel();
        
        Ok(())
    })
}
