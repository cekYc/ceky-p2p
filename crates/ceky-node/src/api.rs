use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
    middleware::{self, Next},
    http::Request,
    body::Body,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::info;

use ceky_telemetry::GlobalMetrics;
use ceky_crypto::Identity;

/// Commands sent from the API to the main event loop.
#[derive(Debug)]
pub enum ApiCommand {
    Connect(SocketAddr),
    SendFile {
        target: SocketAddr,
        file_path: PathBuf,
    },
}

/// Shared state for all API endpoints.
pub struct ApiState {
    pub metrics: Arc<GlobalMetrics>,
    pub identity: Arc<Identity>,
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub api_key: Option<String>,
    pub command_tx: mpsc::UnboundedSender<ApiCommand>,
    pub event_tx: broadcast::Sender<serde_json::Value>,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub peer_id: String,
    pub tcp_addr: String,
    pub udp_addr: String,
    pub active_connections: usize,
    pub dht_active_peers: usize,
    pub dht_total_peers: usize,
}

#[derive(Serialize)]
pub struct MetricsResponse {
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub tx_rate: usize,
    pub rx_rate: usize,
    pub transfers: Vec<ceky_telemetry::TransferProgress>,
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    pub peer_addr: String,
}

#[derive(Deserialize)]
pub struct TransferRequest {
    pub target_peer: String,
    pub file_path: String,
}

/// Start the Axum API server.
pub async fn start_api_server(
    port: u16,
    state: Arc<ApiState>,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/metrics", get(get_metrics))
        .route("/api/peers/connect", post(connect_peer))
        .route("/api/transfers/send", post(send_file))
        .route("/ws/events", get(ws_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("Starting API server on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Middleware to check API key (Bearer token).
async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(expected_key) = &state.api_key {
        let auth_header = req.headers().get("Authorization");
        let is_valid = match auth_header {
            Some(value) => {
                let s = value.to_str().unwrap_or("");
                s == format!("Bearer {}", expected_key)
            }
            None => false,
        };

        if !is_valid {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(req).await)
}

async fn get_status(State(state): State<Arc<ApiState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        peer_id: state.identity.peer_id.to_string(),
        tcp_addr: state.tcp_addr.to_string(),
        udp_addr: state.udp_addr.to_string(),
        active_connections: state.metrics.active_tcp_connections.load(std::sync::atomic::Ordering::Relaxed),
        dht_active_peers: state.metrics.dht_active_peers.load(std::sync::atomic::Ordering::Relaxed),
        dht_total_peers: state.metrics.dht_total_peers.load(std::sync::atomic::Ordering::Relaxed),
    })
}

async fn get_metrics(State(state): State<Arc<ApiState>>) -> Json<MetricsResponse> {
    let transfers = if let Ok(lock) = state.metrics.transfers.read() {
        lock.clone()
    } else {
        Vec::new()
    };

    Json(MetricsResponse {
        tx_bytes: state.metrics.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
        rx_bytes: state.metrics.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
        tx_rate: state.metrics.tx_rate.load(std::sync::atomic::Ordering::Relaxed),
        rx_rate: state.metrics.rx_rate.load(std::sync::atomic::Ordering::Relaxed),
        transfers,
    })
}

async fn connect_peer(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<ConnectRequest>,
) -> Result<StatusCode, StatusCode> {
    match req.peer_addr.parse::<SocketAddr>() {
        Ok(addr) => {
            let _ = state.command_tx.send(ApiCommand::Connect(addr));
            Ok(StatusCode::ACCEPTED)
        }
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

async fn send_file(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<TransferRequest>,
) -> Result<StatusCode, StatusCode> {
    match req.target_peer.parse::<SocketAddr>() {
        Ok(addr) => {
            let _ = state.command_tx.send(ApiCommand::SendFile {
                target: addr,
                file_path: PathBuf::from(req.file_path),
            });
            Ok(StatusCode::ACCEPTED)
        }
        Err(_) => Err(StatusCode::BAD_REQUEST),
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<ApiState>) {
    let mut rx = state.event_tx.subscribe();
    
    // Welcome message
    let welcome = serde_json::json!({ "event": "connected", "peer_id": state.identity.peer_id.to_string() });
    if socket.send(Message::Text(welcome.to_string())).await.is_err() {
        return;
    }

    // Forward events
    while let Ok(event) = rx.recv().await {
        if socket.send(Message::Text(event.to_string())).await.is_err() {
            break;
        }
    }
}
