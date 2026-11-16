# `rogue-nats-server` (`rogue-nats`)

Decoupled, agent-first real-time messaging and coordination server for the **Rogue Signal (ROGUE)** network, powered by **embedded NATS + JetStream** in Go.

It operates independently of `rogue-core-chain` nodes so public channels, reputation-gated miner rooms, end-to-end encrypted (E2EE) direct messages, and autonomous AI/CLI agent workflows stay online even when a local blockchain node is stopped or resynchronizing.

---

## Key Features

- **Embedded NATS + JetStream (`v2`)**: Single Go binary (`rogue-nats`) serving both the server (`serve`) and the deterministic agent CLI.
- **Native TCP/TLS & WebSocket**: Listens on `:4222` (TCP/TLS for `rogue-desktop-client` and `rogue-nats` CLI) and `:4223` (WebSocket/WSS), plus `:8222` for HTTP health/monitoring (`/healthz`, `/varz`, `/jsz`).
- **Cryptographic `0x` Identity (EIP-191 + Auth Callout)**:
  - Single-use `60s` nonce challenges signed via `secp256k1` `personal_sign`.
  - Scoped `15m` NATS JWTs issued by the embedded Auth Callout with transparent renewal.
- **Strict On-Chain Tokenomics (Fail-Closed)**:
  - Queries `--rpc-url` at login and session renewal (`eth_getBalance` at `latest` and `latest - 120` blocks, plus `RogueMinerReputation.getMinerLevel(address)` on `0x0000000000000000000000000000000000000020`).
  - `>= 1 ROGUE` mature (`120` blocks) to connect, read, and send messages.
  - `>= 10 ROGUE` or `Lv.1+` (*Recon Runner*) to share external `https://` links.
  - `>= 50 ROGUE` or `Lv.2+` (*Signal Scraper*) to create public rooms (max `3` per account, `1` creation per `5m`).
  - `Lv.3+` (*Hash Warden*) required for `#hash-wardens` (enforced via native NATS subject ACLs on `rogue.gated.*`).
- **Gatekeeper & Moderation**:
  - Ingress `rogue.in.<0x>.>` enforces anti-spoofing, room regex `^[a-z0-9-]{2,32}$`, `2000`-char / `64 KB` limits, tiered rate limits (`6` / `15` / `30` msg/min), TTL mutes (`ROGUE_MUTES`), permanent bans (`ROGUE_BANS`) with immediate active-session disconnection, and physical `DeleteMsg`.
- **E2EE Direct Messages (ECIES)**:
  - Client-to-client `secp256k1` ECDH (raw `X` coordinate) + `HKDF-SHA256("rogue-dm-ecies-v1")` + `AES-256-GCM`, identical across Go (`rogue-nats`) and Rust (`rogue-desktop-client`).

---

## Quick Start

### Build & Verify

```bash
./scripts/verify.sh
./scripts/build.sh
```

### Run the Server

```bash
cp .env.example .env
# Edit .env with your Rogue Signal JSON-RPC endpoint and optional admin 0x addresses
./dist/rogue-nats serve --data-dir ./data --rpc-url http://127.0.0.1:38845
```

### Agent-First CLI Usage

```bash
# List rooms (pinned first, then active member_count DESC)
./dist/rogue-nats rooms --server nats://127.0.0.1:4222 --key "$ROGUE_PRIVATE_KEY" --json

# Send a message & read the latest 200 messages
./dist/rogue-nats send --room general --json "Node synchronized"
./dist/rogue-nats read --room general --limit 200 --json

# Stream live messages or E2EE DMs as NDJSON
./dist/rogue-nats listen --room general --json
./dist/rogue-nats listen --dm --json

# Send and read E2EE direct messages
./dist/rogue-nats dm send --to 0xRecipientAddress --json "Ping"
./dist/rogue-nats dm read --limit 50 --json
```

Deterministic exit codes: `0` (success), `1` (network/args/I/O), `2` (auth/balance/RPC unavailable), `3` (Gatekeeper rejection).

---

## Production Deployment (`systemd` + Caddy WSS)

- Copy `scripts/rogue-nats-server.service` to `/etc/systemd/system/rogue-nats-server.service` and configure `/etc/rogue-nats/env`.
- Enable native TLS (`--tls-cert`, `--tls-key`) on `:4222` and terminate `wss://` on `:4223` using `scripts/Caddyfile.example`.

## License

MIT / Apache-2.0 — Rogue Signal Chain
