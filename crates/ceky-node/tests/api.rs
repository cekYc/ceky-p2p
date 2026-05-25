use std::process::{Command, Child};
use std::time::Duration;
use reqwest::Client;
use serde_json::Value;
use std::path::PathBuf;

struct NodeProcess {
    child: Child,
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_api_node(api_port: u16, api_key: &str) -> NodeProcess {
    let bin_path = env!("CARGO_BIN_EXE_ceky-node");

    let child = Command::new(bin_path)
        .arg("--daemon")
        .arg("--api-port")
        .arg(api_port.to_string())
        .arg("--api-key")
        .arg(api_key)
        .arg("--tcp-addr")
        .arg(format!("127.0.0.1:{}", api_port + 100))
        .arg("--udp-addr")
        .arg(format!("127.0.0.1:{}", api_port + 101))
        .spawn()
        .expect("Failed to start ceky-node");

    std::thread::sleep(Duration::from_secs(1)); // wait for startup

    NodeProcess { child }
}

#[tokio::test]
async fn test_api_status_and_auth() {
    let _node = start_api_node(18080, "secret123");
    let client = Client::new();

    // 1. Request without token should fail (401)
    let resp = client.get("http://127.0.0.1:18080/api/status").send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // 2. Request with wrong token should fail (401)
    let resp = client.get("http://127.0.0.1:18080/api/status")
        .header("Authorization", "Bearer wrong")
        .send().await.unwrap();
    assert_eq!(resp.status(), 401);

    // 3. Request with correct token should succeed (200)
    let resp = client.get("http://127.0.0.1:18080/api/status")
        .header("Authorization", "Bearer secret123")
        .send().await.unwrap();
    
    assert_eq!(resp.status(), 200);
    
    let json: Value = resp.json().await.unwrap();
    assert!(json.get("peer_id").is_some());
    assert!(json.get("tcp_addr").is_some());
    assert!(json.get("active_connections").is_some());
}

#[tokio::test]
async fn test_api_metrics() {
    let _node = start_api_node(18081, "secret456");
    let client = Client::new();

    let resp = client.get("http://127.0.0.1:18081/api/metrics")
        .header("Authorization", "Bearer secret456")
        .send().await.unwrap();
    
    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert!(json.get("tx_bytes").is_some());
    assert!(json.get("rx_bytes").is_some());
    assert!(json.get("transfers").unwrap().is_array());
}

#[tokio::test]
async fn test_api_connect() {
    let _node = start_api_node(18082, "test_token");
    let client = Client::new();

    let resp = client.post("http://127.0.0.1:18082/api/peers/connect")
        .header("Authorization", "Bearer test_token")
        .json(&serde_json::json!({
            "peer_addr": "127.0.0.1:9999"
        }))
        .send().await.unwrap();
    
    assert_eq!(resp.status(), 202); // 202 Accepted
}
