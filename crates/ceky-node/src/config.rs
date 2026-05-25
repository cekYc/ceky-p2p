use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::fs;

#[derive(Deserialize, Debug, Default)]
pub struct NetworkConfig {
    pub tcp_addr: Option<SocketAddr>,
    pub udp_addr: Option<SocketAddr>,
    pub max_connections: Option<usize>,
    pub skip_nat: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
pub struct BootstrapConfig {
    pub seeds: Option<Vec<SocketAddr>>,
}

#[derive(Deserialize, Debug, Default)]
pub struct NodeInfoConfig {
    pub key_file: Option<PathBuf>,
    pub log_level: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct ConfigFile {
    pub network: Option<NetworkConfig>,
    pub bootstrap: Option<BootstrapConfig>,
    pub node: Option<NodeInfoConfig>,
}

impl ConfigFile {
    pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let config: ConfigFile = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }
}

/// The final resolved configuration for the node.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub key_file: PathBuf,
    pub seeds: Vec<SocketAddr>,
    pub max_connections: usize,
    pub log_level: String,
    pub skip_nat: bool,
}

impl ResolvedConfig {
    /// Merges CLI arguments over the TOML config file, falling back to defaults.
    pub fn merge(cli_tcp: Option<SocketAddr>, cli_udp: Option<SocketAddr>, cli_key: Option<PathBuf>, cli_seeds: Option<Vec<SocketAddr>>, cli_max_conn: Option<usize>, cli_log: Option<String>, cli_skip_nat: bool, file: ConfigFile) -> Self {
        
        let network = file.network.unwrap_or_default();
        let bootstrap = file.bootstrap.unwrap_or_default();
        let node = file.node.unwrap_or_default();

        let tcp_addr = cli_tcp
            .or(network.tcp_addr)
            .unwrap_or_else(|| "0.0.0.0:9741".parse().unwrap());
            
        let udp_addr = cli_udp
            .or(network.udp_addr)
            .unwrap_or_else(|| "0.0.0.0:9742".parse().unwrap());
            
        let key_file = cli_key
            .or(node.key_file)
            .unwrap_or_else(|| PathBuf::from("identity.key"));
            
        let seeds = cli_seeds
            .or(bootstrap.seeds)
            .unwrap_or_default();
            
        let max_connections = cli_max_conn
            .or(network.max_connections)
            .unwrap_or(1024);
            
        let log_level = cli_log
            .or(node.log_level)
            .unwrap_or_else(|| "info".to_string());
            
        // For flags, if CLI explicitly sets it (e.g. action ArgAction::SetTrue), it's true. 
        // If false, we check config.
        let skip_nat = if cli_skip_nat {
            true
        } else {
            network.skip_nat.unwrap_or(false)
        };

        Self {
            tcp_addr,
            udp_addr,
            key_file,
            seeds,
            max_connections,
            log_level,
            skip_nat,
        }
    }
}
