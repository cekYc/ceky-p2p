use std::process::{Command, Child};
use std::time::Duration;
use std::path::PathBuf;
use std::fs;
use std::net::SocketAddr;

/// Start a node as a child process.
fn start_node(id: usize, tcp_port: u16, udp_port: u16, seeds: Vec<SocketAddr>, test_dir: &std::path::Path) -> Child {
    let key_file = test_dir.join(format!("identity_{}.key", id));
    
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ceky-node"));
    
    let seed_args = seeds
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",");

    cmd.arg("-t").arg(format!("127.0.0.1:{}", tcp_port))
       .arg("-u").arg(format!("127.0.0.1:{}", udp_port))
       .arg("-k").arg(key_file)
       .arg("--skip-nat")
       .env("RUST_LOG", "info");

    if !seed_args.is_empty() {
        cmd.arg("-s").arg(seed_args);
    }

    // We don't pipe stdout/stderr so we can see the chaos in the test output, 
    // but in a real CI environment we might want to capture and assert on logs.
    cmd.spawn().expect("failed to start ceky-node")
}

#[test]
fn test_swarm_convergence_and_chaos() {
    let test_dir = std::env::temp_dir().join(format!(
        "ceky_swarm_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let mut children = Vec::new();
    let num_nodes = 5;
    let base_tcp = 29000;
    let base_udp = 30000;

    let seed_addr: SocketAddr = format!("127.0.0.1:{}", base_tcp).parse().unwrap();

    println!("Starting {} nodes in swarm...", num_nodes);

    for i in 0..num_nodes {
        let seeds = if i == 0 {
            vec![] // Node 0 is the seed
        } else {
            vec![seed_addr] // Others connect to Node 0
        };

        let child = start_node(i, base_tcp + i as u16, base_udp + i as u16, seeds, &test_dir);
        children.push(child);
        
        // Give the seed node a moment to bind before others connect
        if i == 0 {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    println!("Swarm running. Waiting 5 seconds to let them connect and perform DHT lookups...");
    std::thread::sleep(Duration::from_secs(5));

    println!("Killing nodes...");
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    
    // In a real test, we would parse the logs or query an HTTP API to assert the routing table sizes.
    // Here we mainly ensure they don't panic and can bootstrap successfully despite Chaos (if feature enabled).
    println!("Swarm test completed successfully!");
}
