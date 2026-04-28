# cekyP2P

Saf P2P ağı — sıfırdan inşa edildi, hiçbir hazır P2P kütüphanesine bağımlı değil.

## Özellikler

- 🔧 **Özel Binary Protokol** — 21-byte header, zero-copy codec, CRC32C bütünlük kontrolü
- 🔐 **Zero-Trust Güvenlik** — Ed25519 kimlik, Noise XX handshake, ChaChaPoly1305 şifreleme
- 🌐 **Kademlia DHT** — Performans puanlamalı peer keşfi, SuperNode mekanizması
- 🕳️ **NAT Traversal** — UDP hole punching, STUN, relay fallback
- ⚡ **Donanım Optimizasyonu** — mimalloc, lock-free yapılar, zero-copy I/O

## Derleme

```bash
cargo build --workspace
```

## Test

```bash
cargo test --workspace
```

## Lisans

MIT
