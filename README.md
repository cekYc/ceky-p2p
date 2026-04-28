<div align="center">

# 🌐 cekyP2P

**Zero-dependency peer-to-peer network stack built from scratch in Rust.**

No libp2p. No QUIC wrappers. Every byte on the wire is accounted for.

[![Rust](https://img.shields.io/badge/Rust-1.95+-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-95%20passing-brightgreen?style=flat-square)](#testing)

</div>

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          ceky-node                               │
│                     (Binary + Event Loop)                        │
├──────────────┬───────────────┬──────────────┬───────────────────┤
│  ceky-dht    │  ceky-crypto  │  ceky-nat    │  ceky-transport   │
│  Kademlia    │  Noise XX     │  STUN/Punch  │  TCP/UDP          │
│  Routing     │  Ed25519      │  Relay       │  Connection Pool  │
│  Bootstrap   │  ChaChaPoly   │  Detection   │  Zero-copy I/O    │
│  SuperNode   │  Sessions     │              │  Heartbeat        │
├──────────────┴───────────────┴──────────────┴───────────────────┤
│                        ceky-protocol                             │
│              Binary Wire Protocol · 21B Header · CRC32C         │
└──────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### 🔧 Custom Binary Protocol (`ceky-protocol`)
- **21-byte fixed header** — magic, version, type, flags, payload length, request ID, CRC32C
- **Zero-copy codec** — `BytesMut::split_to().freeze()` → no memcpy on decode
- **Hardware CRC32C** — SSE4.2 accelerated on x86_64
- **19 message types** — connection lifecycle, DHT ops, data transfer, NAT traversal
- **Bitfield flags** — encrypted, compressed, fragmented, priority

### 🛡️ Zero-Trust Security (`ceky-crypto`)
- **Ed25519** long-term identity keypairs with PeerId derivation (`SHA-256(PK)`)
- **Noise XX handshake** (`Noise_XX_25519_ChaChaPoly_SHA256`) — mutual authentication, forward secrecy
- **ChaChaPoly1305** AEAD session encryption with atomic nonce counters
- **Replay protection** — sliding window bitmap (256-nonce window)
- **Identity binding** — Ed25519 signature over X25519 static key prevents key substitution
- **Zeroize** — secret key material is wiped from memory on drop

### 🌍 Kademlia DHT (`ceky-dht`)
- **256 k-buckets** with K=20 peers each, XOR distance routing
- **Performance scoring** — composite score from latency, success rate, uptime, relay contribution
- **Iterative lookups** — α=3 parallel queries, convergence detection, deduplication
- **Local store** — key-value storage with TTL expiration and capacity limits
- **Bootstrap manager** — seed node contact, self-lookup, random bucket fill, periodic refresh
- **SuperNode promotion** — automatic tier system (Regular → Candidate → SuperNode → Elite)

### 🕳️ NAT Traversal (`ceky-nat`)
- **STUN client** — RFC 5389 Binding Request/Response with XOR-MAPPED-ADDRESS
- **NAT type detection** — classifies None/FullCone/Restricted/PortRestricted/Symmetric
- **UDP hole punching** — configurable rounds, packet intervals, magic-byte identification
- **Relay service** — bandwidth-limited session forwarding for symmetric NAT fallback
- **Automatic strategy** — selects direct/punch/relay based on detected NAT type

### 🚀 Transport Layer (`ceky-transport`)
- **TCP transport** — `Framed<TcpStream, FrameCodec>` with Nagle disabled
- **UDP transport** — stateless datagram-per-frame with send/receive split
- **Connection pool** — `DashMap`-based lock-free O(1) peer management
- **Heartbeat system** — PING/PONG with configurable intervals, auto-response, dead peer eviction
- **Connection state machine** — Connecting → Established → Closing → Closed
- **Full byte accounting** — per-connection send/recv counters

### ⚡ Performance
- **mimalloc** allocator support (opt-in via `--features custom-allocator`)
- **Lock-free concurrency** — DashMap, atomic counters, crossbeam
- **Zero-copy buffers** — `bytes::Bytes` reference-counted slicing
- **Fat LTO** + single codegen unit + panic=abort in release profile

## 📦 Workspace Structure

```
cekyP2P/
├── Cargo.toml                 # Workspace root
├── crates/
│   ├── ceky-protocol/         # Wire protocol, codec, frame types
│   │   └── src/
│   │       ├── lib.rs          # Constants: MAGIC=0xCE4B, HEADER_SIZE=21
│   │       ├── types.rs        # MessageType, Flags, Frame, FrameHeader
│   │       ├── codec.rs        # FrameCodec: Encoder + Decoder
│   │       └── error.rs        # ProtocolError variants
│   │
│   ├── ceky-crypto/           # Identity, handshake, encryption
│   │   └── src/
│   │       ├── lib.rs          # Module exports
│   │       ├── identity.rs     # Ed25519 + X25519 + PeerId + persistence
│   │       ├── noise.rs        # Noise XX 3-message handshake
│   │       ├── session.rs      # SecureSession: AEAD encrypt/decrypt
│   │       └── error.rs        # CryptoError variants
│   │
│   ├── ceky-transport/        # Network I/O layer
│   │   └── src/
│   │       ├── lib.rs          # TransportEvent, TransportError
│   │       ├── tcp.rs          # TcpTransport: listen, connect, send
│   │       ├── udp.rs          # UdpTransport: bind, send_to, send_raw
│   │       ├── connection.rs   # ConnectionInfo state machine
│   │       └── pool.rs         # ConnectionPool with stats
│   │
│   ├── ceky-dht/              # Distributed hash table
│   │   └── src/
│   │       ├── lib.rs          # DhtError, module exports
│   │       ├── routing.rs      # RoutingTable with 256 k-buckets
│   │       ├── operations.rs   # IterativeLookup, LocalStore
│   │       ├── peer_info.rs    # PeerInfo, PeerScore, PeerState
│   │       ├── bootstrap.rs    # BootstrapManager, seed contact
│   │       └── supernode.rs    # SuperNodeManager, tier promotion
│   │
│   ├── ceky-nat/              # NAT traversal
│   │   └── src/
│   │       ├── lib.rs          # NatError, module exports
│   │       ├── stun.rs         # StunClient, RFC 5389 parsing
│   │       ├── detection.rs    # NatDetector, NatType classification
│   │       ├── hole_punch.rs   # HolePuncher, UDP punch protocol
│   │       └── relay.rs        # RelayService, session management
│   │
│   └── ceky-node/             # Main binary
│       └── src/
│           └── main.rs         # CLI, node orchestration, event loop
│
└── .cargo/
    └── config.toml            # Build optimizations
```

## 🚀 Quick Start

### Prerequisites

- **Rust 1.95+** (edition 2024)
- **Git**

### Build

```bash
git clone https://github.com/cekyc/ceky-p2p.git
cd ceky-p2p
cargo build --workspace
```

### Run

```bash
# Start a node with default settings
cargo run --bin ceky-node

# Start with custom ports and seed nodes
cargo run --bin ceky-node -- \
  --tcp-addr 0.0.0.0:9741 \
  --udp-addr 0.0.0.0:9742 \
  --seeds 192.168.1.10:9741,192.168.1.11:9741

# Enable debug logging
cargo run --bin ceky-node -- --log-level debug

# Skip NAT detection (for local testing)
cargo run --bin ceky-node -- --skip-nat
```

### Release Build (Optimized)

```bash
# Standard release
cargo build --release --bin ceky-node

# With mimalloc allocator (Linux recommended)
cargo build --release --bin ceky-node --features custom-allocator
```

## 🧪 Testing

```bash
# Run all 95 tests
cargo test --workspace

# Run specific crate tests
cargo test -p ceky-protocol
cargo test -p ceky-crypto
cargo test -p ceky-transport
cargo test -p ceky-dht
cargo test -p ceky-nat

# With output
cargo test --workspace -- --nocapture
```

### Test Coverage

| Crate | Tests | Coverage |
|-------|------:|----------|
| `ceky-protocol` | 11 | Codec roundtrip, corruption, partial reads, all message types |
| `ceky-crypto` | 21 | Key generation, handshake, AEAD, replay window, persistence |
| `ceky-transport` | 15 | TCP echo, UDP roundtrip, ping/pong, connection pool, heartbeat |
| `ceky-dht` | 29 | Routing table, lookups, scoring, bootstrap, SuperNode promotion |
| `ceky-nat` | 19 | STUN parsing, NAT classification, hole punch, relay sessions |
| **Total** | **95** | |

## 🔌 Wire Protocol

Every frame on the wire follows this format:

```
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0
┌─────────┬───┬───┬───┬───────────┬─────────────────┬───────────┬─────────┐
│ Magic   │ V │ T │ F │PayloadLen │   Request ID    │  CRC32C   │ Payload │
│ 0xCE4B  │   │   │   │  (4 B)    │    (8 B)        │  (4 B)    │  (N B)  │
└─────────┴───┴───┴───┴───────────┴─────────────────┴───────────┴─────────┘
  2 bytes  1B  1B  1B    4 bytes      8 bytes          4 bytes     0-16MB
                     └──────────────── 21 bytes header ───────────────┘
```

| Field | Size | Description |
|-------|------|-------------|
| Magic | 2B | `0xCE4B` — protocol identifier |
| Version | 1B | Protocol version (currently `1`) |
| Type | 1B | Message type (`0x01`-`0x35`) |
| Flags | 1B | Bitfield: encrypted, compressed, fragmented, priority |
| PayloadLen | 4B | Payload size in bytes (max 16 MB) |
| RequestID | 8B | Correlation ID for request/response matching |
| CRC32C | 4B | Checksum over header fields + payload |

## 🔐 Security Model

```
Node Identity
┌──────────────────────────────────────┐
│  Ed25519 Keypair  → Long-term ID    │
│  X25519 Static    → Noise handshake │
│  PeerId           → SHA-256(Ed25519) │
│  Signature        → Ed25519(X25519)  │
└──────────────────────────────────────┘
         │
         ▼
Noise XX Handshake (3 messages)
┌──────────────────────────────────────┐
│  msg1: → e                           │
│  msg2: ← e, ee, s, es               │
│  msg3: → s, se                       │
│                                      │
│  Result: 2× ChaChaPoly1305 keys     │
│  (one per direction, forward secrecy)│
└──────────────────────────────────────┘
         │
         ▼
Encrypted Session
┌──────────────────────────────────────┐
│  ChaChaPoly1305 AEAD                 │
│  Atomic nonce counters               │
│  256-nonce replay window             │
│  Max 2^48 frames before rekey        │
└──────────────────────────────────────┘
```

## 🌐 NAT Traversal Pipeline

```
1. STUN Probe    → Discover external IP:port
2. NAT Detect    → Classify NAT type
3. Strategy      → Select traversal method
                    ├─ None/FullCone → Direct connection
                    ├─ Restricted    → UDP hole punching
                    └─ Symmetric     → Relay via SuperNode
```

## ⚙️ CLI Options

```
ceky-node — Decentralized P2P network node

Usage: ceky-node [OPTIONS]

Options:
  -t, --tcp-addr <ADDR>         TCP listen address [default: 0.0.0.0:9741]
  -u, --udp-addr <ADDR>         UDP listen address [default: 0.0.0.0:9742]
  -k, --key-file <PATH>         Identity key file [default: identity.key]
  -s, --seeds <ADDR,ADDR,...>   Seed node addresses
      --max-connections <N>     Max connections [default: 1024]
  -l, --log-level <LEVEL>       Log level [default: info]
      --skip-nat                Skip NAT detection
  -h, --help                    Print help
  -V, --version                 Print version
```

## 📊 Performance Profile

| Metric | Value |
|--------|-------|
| Header overhead | 21 bytes per frame |
| Max payload | 16 MB |
| CRC32C | Hardware-accelerated (SSE4.2) |
| Connection pool lookup | O(1) via DashMap |
| K-bucket capacity | 20 peers × 256 buckets |
| Heartbeat interval | 15 seconds |
| Replay window | 256 nonces |
| Max session frames | 2^48 (~8.9 years at 1M fps) |
| Release LTO | Fat LTO, 1 codegen unit |

## 🗺️ Roadmap

- [x] **Faz 1** — Binary wire protocol with zero-copy codec
- [x] **Faz 2** — TCP/UDP transport, connection pool, heartbeat
- [x] **Faz 3** — Kademlia DHT, routing table, iterative lookup
- [x] **Faz 4** — NAT traversal (STUN, hole punch, relay)
- [x] **Faz 5** — Noise XX handshake, encrypted sessions
- [x] **Faz 6** — Bootstrap, SuperNode promotion, node binary
- [ ] **Faz 7** — File transfer protocol (chunked + merkle)
- [ ] **Faz 8** — Persistent storage (redb) + config system
- [ ] **Faz 9** — Metrics dashboard + TUI monitoring

## 📜 License

[MIT](LICENSE) — ceky © 2026
