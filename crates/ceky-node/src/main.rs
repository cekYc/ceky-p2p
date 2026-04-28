//! # ceky-node
//!
//! Main P2P node binary — orchestrates all cekyP2P subsystems.
//! On Linux production builds, use `--features custom-allocator` for mimalloc.

#[cfg(feature = "custom-allocator")]
use mimalloc::MiMalloc;

#[cfg(feature = "custom-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("ceky-node v{}", env!("CARGO_PKG_VERSION"));

    #[cfg(feature = "custom-allocator")]
    tracing::info!("allocator: mimalloc");
    #[cfg(not(feature = "custom-allocator"))]
    tracing::info!("allocator: system default");

    tracing::info!("protocol magic: 0x{:04X}", ceky_protocol::MAGIC);
    tracing::info!("header size: {} bytes", ceky_protocol::HEADER_SIZE);

    // TODO: Faz 5 — CLI, Node struct, event loop
    tracing::info!("node skeleton ready — awaiting implementation");
}
