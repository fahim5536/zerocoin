# ZeroCoin (ZRO)

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](#prerequisites)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Status: experimental](https://img.shields.io/badge/status-experimental-red.svg)](#project-status)

ZeroCoin (ticker **ZRO**) is an experimental, from-scratch **UTXO blockchain written in
Rust**. It is a *fair-launch* chain: there is **no premine and no owner**, and the only way
value enters the system is the block subsidy earned by proof of work.

The project ships three binaries:

| Binary | Role |
|--------|------|
| `zerocoind` | The full node — chain state, authenticated P2P fabric, loopback JSON-RPC. |
| `zerocoin-cli` | A thin client — one subcommand maps to one RPC call (like `bitcoin-cli`). |
| `zerocoin-gui` | A self-contained desktop wallet (Slint). Starts its own embedded node on demand. |

> **This is experimental software.** It has **not** been independently audited. Do **not**
> use it with real money or any funds you cannot afford to lose. See
> [Security](#security) and [Disclaimer](#disclaimer).

---

## Table of contents

- [Project status](#project-status)
- [Overview](#overview)
- [Verified features](#verified-features)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Consensus rules](#consensus-rules)
- [Networks](#networks)
- [Cryptography](#cryptography)
- [Prerequisites](#prerequisites)
- [Installation (Windows)](#installation-windows)
- [Build](#build)
- [Run the node and CLI](#run-the-node-and-cli)
- [Devnet setup](#devnet-setup)
- [Multi-node testing](#multi-node-testing)
- [Wallet usage](#wallet-usage)
- [Mining and the in-built pool](#mining-and-the-in-built-pool)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Contributing](#contributing)
- [Security](#security)
- [Roadmap](#roadmap)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Project status

ZeroCoin is **alpha / experimental** software under active development. The repository is a
single Rust crate (`zerocoin/`, `version 0.1.0`). Everything documented below is taken from
the code in this repository; anything that could not be verified from the source is marked
*unverified* or omitted.

There is **no published roadmap file, no security policy file, and no contribution guide file**
in the repository at the time of writing (see [Roadmap](#roadmap) and [Contributing](#contributing)).
This README describes what the code does today — not what it may become.

---

## Overview

ZeroCoin follows the Bitcoin UTXO model closely, with three deliberate design changes:

1. **60-second blocks** with a **1,440-block (24-hour)** difficulty-retarget window.
2. **CPU-friendly, memory-hard proof of work** (a scratchpad engine) instead of SHA-256d,
   intended to reduce the advantage of purpose-built ASICs. Devnet and regtest can also run a
   trivial SHA-256d engine for fast local testing.
3. **A built-in mining pool** built around *shares* and *micro-rewards*, so that low-end
   devices (for example a 4 GB phone) can earn a proportional slice of a block it did not
   itself find — **without** changing what the chain agrees on.

Honest framing:

- ZeroCoin is **not** a Bitcoin fork; it is a clean-room implementation written in Rust.
- It is **not** production-ready, **not** audited, and **not** listed on any exchange.
- It makes **no** claims about decentralization in the field, monetary value, or guaranteed
  double-spend protection. It implements the *mechanisms* (proof of work, UTXO validation,
  coinbase maturity) that a network of independent nodes would rely on; whether such a
  network exists in practice is a separate, deployment question.

---

## Verified features

The following are implemented and verifiable in the source tree.

**Consensus and chain**

- Zero-premine genesis: block 0 has **no outputs** (`src/genesis.rs`).
- 60-second target spacing; 1,440-block retarget (mainnet/devnet); regtest retarget disabled.
- Memory-hard proof of work behind a `PowEngine` trait, plus a trivial SHA-256d engine for
  regtest/devnet (`src/consensus/pow.rs`).
- Block subsidy of 50 ZRO, halving every 210,000 blocks, capped at 21,000,000 ZRO
  (`src/consensus/reward.rs`).
- Coinbase maturity of **100 blocks** (`COINBASE_MATURITY`), enforced by the UTXO set.
- BIP-34 height commitment in the coinbase; `validate_coinbase` re-checks reward and the
  running supply against the cap on every connect.
- A `Uint256` nBits-style difficulty type implemented with no external big-number dependency
  (`src/consensus/uint256.rs`).

**Ledger**

- Bitcoin-legacy (pre-SegWit) transaction serialization; `txid = SHA-256d(serialize())`
  (`src/ledger/transaction.rs`).
- A UTXO set (`BTreeMap<Outpoint, UtxoEntry>`) with all-or-nothing block application and a
  double-SHA-256 state root (`src/ledger/utxo.rs`).
- A small Forth-like script interpreter supporting **P2PKH only**; disabled and flow-control
  opcodes are rejected (`src/ledger/script.rs`).
- `SIGHASH_ALL` transaction signing, chain-id-bound to prevent cross-chain replay
  (`src/ledger/sighash.rs`).

**Wallet**

- Single-address P2PKH wallet; the private key is **never stored in the clear**.
- Keystore sealed with **argon2id → AES-256-GCM** (`src/crypto/keystore.rs`,
  `src/wallet.rs`). AEAD associated data binds the sealed secret to the wallet's identity.
- Atomic save (write-to-sibling then rename) and a password-gated `unlock`.
- Coin selection spends **mature** coins only; an immature coinbase spend fails with
  `ImmatureCoinbase` instead of producing an invalid transaction.

**Networking**

- Authenticated handshake: ephemeral-ephemeral secp256k1 ECDH (forward secrecy) plus
  long-term-key signatures (mutual authentication) (`src/network/handshake.rs`).
- Encrypted, authenticated transport frames: **AES-256-GCM + HMAC-SHA256** (encrypt-then-MAC)
  with a monotonic sequence number for replay/reorder protection (`src/network/frame.rs`).
- JSON-encoded protocol messages with `Version`/`Verack`, `Ping`/`Pong`, `GetAddr`/`Addr`,
  `Inv`/`GetData`/`Tx`, `GetHeaders`/`Headers`, `Block`, and `Share` (`src/network/message.rs`).

**Interfaces**

- Loopback-only JSON-RPC (4-byte little-endian length prefix + JSON, 8 MiB max frame)
  (`src/node.rs`).
- A CLI that mirrors `bitcoin-cli` subcommands (`src/bin/zerocoin_cli.rs`).
- A Slint desktop wallet that is *self-contained* (spawns its own node) and holds **no keys**
  itself (`src/bin/zerocoin_gui.rs`, `ui/wallet.slint`).
- A built-in pool layer with share accounting that **redistributes** the existing subsidy and
  never mints new coins (`src/pool.rs`).

---

## Architecture

Modules are layered in `src/lib.rs` as `crypto → ledger → consensus → network`, then
`params / address / genesis`, then `storage / chain / mempool`, then `node`, then `pool`,
with `datadir` alongside.

```
crypto/          SHA-256, SHA-256d, RIPEMD-160, hash160, secp256k1 (k256), argon2id keystore
ledger/          transaction, utxo set, P2PKH script, sighash
consensus/       block, difficulty, pow engines, reward/subsidy, immutability anchors, uint256
network/         frame, handshake, message, mod
params.rs        ChainParams: mainnet | devnet | regtest
address.rs       Base58Check P2PKH
genesis.rs       hard-coded zero-premine genesis
storage.rs       ChainData persistence (chain.json)
chain.rs         block connection, mempool integration, balances, mining
mempool.rs       fee-rate-ordered transaction pool
wallet.rs        single-address wallet (sealed secret)
pool.rs          share ledger + micro-reward split
node.rs          node loop, P2P sessions, JSON-RPC server, embedded-node config
datadir.rs       per-user, per-network data directory resolver
```

The three binaries are thin front-ends over the library:

- `zerocoind` → `src/bin/zerocoind.rs`
- `zerocoin-cli` → `src/bin/zerocoin_cli.rs`
- `zerocoin-gui` → `src/bin/zerocoin_gui.rs` (UI in `ui/wallet.slint`, compiled at build time)

---

## Technology stack

| Area | Choice |
|------|--------|
| Language | Rust, edition 2021, MSRV **1.75** |
| Async runtime | `tokio` 1.53 |
| GUI | `slint` 1.18 (+ `slint-build` in `build.rs`) |
| Serialization | `serde` / `serde_json` |
| Hashing | `sha2`, `ripemd`, `hmac`, `hkdf` |
| Signatures / curves | `k256` (secp256k1, RustCrypto) |
| Encryption | `aes-gcm` (AES-256-GCM), `argon2` (argon2id) |
| Encoding | `bs58` (Base58Check), `hex` |
| Hygiene | `zeroize`, `subtle`, `rand`, `getrandom` |
| Clipboard / dialogs | `arboard`, `rfd` |
| Dev / test | `proptest`, `tempfile` |

Release profile (`Cargo.toml`): `opt-level = 3`, `lto = true`, `codegen-units = 1`.

---

## Consensus rules

All values below are read directly from the source.

| Parameter | Value | Source |
|-----------|-------|--------|
| Block interval (target spacing) | 60 seconds | `src/consensus/difficulty.rs` |
| Retarget interval | 1,440 blocks (24 h) | `src/consensus/difficulty.rs` |
| Retarget adjustment clamp | 4× per retarget | `src/consensus/difficulty.rs` |
| Initial block subsidy | 50 ZRO | `src/consensus/reward.rs` |
| Halving interval | 210,000 blocks | `src/consensus/reward.rs` |
| Maximum halvings | 64 | `src/consensus/reward.rs` |
| Maximum supply | 21,000,000 ZRO | `src/consensus/reward.rs` |
| Coinbase maturity | 100 blocks | `src/consensus/reward.rs` |
| Genesis (block 0) subsidy | **0** (mints nothing) | `src/genesis.rs` |
| Smallest unit | 1 ZRO = 100,000,000 Fah | `src/lib.rs` |
| Default transaction fee | 1,000 Fah | `src/bin/zerocoin_cli.rs` |
| Max transactions per block | 2,000 | `src/consensus/block.rs` |
| Max transaction size | 1,000,000 bytes | `src/ledger/transaction.rs` |
| Max inputs / outputs | 10,000 / 10,000 | `src/ledger/transaction.rs` |

**A coinbase mined at height `H` becomes spendable once the chain tip reaches `H + 100`.**
At tip 101 from genesis, only the coinbases at heights 1 and 2 are unlocked (100 ZRO of the
5,050 ZRO mined). See the [Devnet setup](#devnet-setup) walkthrough.

---

## Networks

Three networks are defined by `ChainParams` (`src/params.rs`).

| Network | Chain ID | PoW engine | Retarget | Default P2P | Default RPC | Address prefix |
|---------|----------|-----------|----------|:-----------:|:-----------:|:--------------:|
| `mainnet` | `0x5A524F01` | scratchpad, 2 MiB / 4096 rounds | on | 8233 | 8232 | `0x00` (leading `1`) |
| `devnet` | `0x5A524F02` | scratchpad, 64 KiB / 1024 rounds | on | 18233 | 18232 | `0x6f` (leading `m`/`n`) |
| `regtest` | `0x5A524F00` | trivial SHA-256d | off | 18444 | 18443 | `0x6f` (leading `m`/`n`) |

- The **genesis timestamp** is fixed at `1_735_689_600` (2025-01-01T00:00:00Z).
- **regtest** disables retargeting and uses an easy target so a single process can mine
  instantly — it is the network used for the local walkthroughs below.
- The **scratchpad size is a per-network consensus constant**, not a per-device choice: the
  memory-hard hash folds the whole scratchpad into the digest, so two nodes with different
  scratchpad sizes would compute different hashes and fork. A device that cannot allocate the
  network's scratchpad should act as a *share-miner*, not a full validator.

---

## Cryptography

| Purpose | Algorithm | Where |
|---------|-----------|-------|
| Hashing | SHA-256; SHA-256d (double SHA-256) | `src/crypto/hash.rs` |
| Key hashing | RIPEMD-160(SHA-256(pubkey)) (= `hash160`) | `src/crypto/hash.rs` |
| Signatures | secp256k1 ECDSA, deterministic (RFC 6979), DER-encoded | `src/crypto/secp256k1.rs` |
| Public keys | Compressed SEC1 (33 bytes) | `src/crypto/secp256k1.rs` |
| Keystore KDF | argon2id (m=19,456 KiB, t=2, p=1) | `src/crypto/keystore.rs` |
| Keystore cipher | AES-256-GCM (AAD = wallet public identity) | `src/crypto/keystore.rs` |
| Transport key agreement | ephemeral-ephemeral secp256k1 ECDH + HKDF-SHA256 | `src/network/handshake.rs` |
| Transport cipher | AES-256-GCM + HMAC-SHA256 (encrypt-then-MAC) | `src/network/frame.rs` |
| Address | Base58Check P2PKH | `src/address.rs` |

Private keys are wrapped in a `PrivateKey` type that is **zeroized on drop** and whose
`Debug` output is redacted. The argon2id parameters are the OWASP interactive-login profile,
and the keystore decoder clamps attacker-supplied parameters to safe upper bounds.

---

## Prerequisites

- **Rust 1.75 or newer** (the crate's MSRV is `rust-version = "1.75"`). Install with
  [rustup](https://rustup.rs/).
- **A C linker / build tools.** On Windows this is the MSVC toolchain (Visual Studio Build
  Tools with the Windows SDK), which the default `x86_64-pc-windows-msvc` target uses at link
  time. The GUI is built by Slint, which is compiled into the binary via `build.rs`.

Verify the toolchain:

```powershell
rustc --version   # rustc 1.75 or newer
cargo --version
```

There is no external service, database, or network configuration required to build and run a
local (regtest) node.

---

## Installation (Windows)

1. Install Rust via rustup:

   ```powershell
   winget install --id Rustlang.Rustup
   ```

   (Alternatively, download the installer from <https://rustup.rs/>.) rustup installs the
   `stable-x86_64-pc-windows-msvc` toolchain by default.

2. Ensure the **MSVC build tools / Windows SDK** are present. If `cargo build` fails at link
   time, install "Desktop development with C++" from the Visual Studio Build Tools.

3. Verify:

   ```powershell
   rustc --version
   cargo --version
   ```

4. Clone the repository and enter the crate directory (all build/run commands in this README
   assume the current directory is the **crate root**, `zerocoin/`):

   ```powershell
   git clone https://github.com/fahim5536/zerocoin.git
   cd zerocoin\zerocoin
   ```

> The macOS and Linux data-directory locations are defined in `src/datadir.rs` but have not
> been executed on this machine; only the Windows path is asserted as verified here.

---

## Build

From the crate root (`zerocoin/`):

```powershell
# Debug build (fast to compile; instant regtest mining)
cargo build --bins

# Release build (realistic PoW performance; slower to compile)
cargo build --release --bins
```

This produces the executables under `target\debug\` (or `target\release\`):

- `zerocoind.exe`
- `zerocoin-cli.exe`
- `zerocoin-gui.exe`

---

## Run the node and CLI

### Start the node

```powershell
# Set the wallet password (the daemon never stores a key in the clear), then start
$env:ZRO_WALLET_PASSWORD = "change-me-local-only"
.\target\debug\zerocoind.exe --network regtest `
    --datadir .\target\zro-regtest `
    --rpc 127.0.0.1:18443 --p2p 127.0.0.1:18444
```

`zerocoind` accepts:

```
zerocoind [--network devnet|regtest|mainnet] [--datadir DIR]
          [--p2p HOST:PORT] [--rpc HOST:PORT] [--connect HOST:PORT]... [--password PW]
```

- `--network` defaults to **devnet**.
- `--p2p` defaults to `0.0.0.0:<default p2p port>` (all interfaces).
- `--rpc` defaults to `127.0.0.1:<default rpc port>` and is **loopback only**.
- `--connect` may be repeated to dial peers.
- The wallet password is read from `--password` or the `ZRO_WALLET_PASSWORD` environment
  variable. Without either, the node starts **walletless** (no key in the clear).

### Drive it with the CLI

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getinfo
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getnewaddress
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 101
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getbalance
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 stop
```

`zerocoin-cli` usage and subcommands:

```
zerocoin-cli [--network devnet|regtest|mainnet] [--rpc HOST:PORT] <command> [options]

getinfo                                    chain/network summary
getnewaddress                              the wallet's receiving address
getbalance                                 confirmed and spendable balances (Fah)
getpeercount                               number of connected peers
getpoolinfo                                in-built pool: contributors, weight, share target
mine --blocks N                            mine N blocks (alias: generate)
sendtoaddress --address A --amount FAH [--fee FAH] --password PW   (alias: send)
stop                                       ask the node to shut down
help                                       show help
```

Amounts are in **Fah** (1 ZRO = 100,000,000 Fah); the default fee is **1000 Fah**. The
`--network` default is **devnet**.

---

## Devnet setup

This walkthrough (regtest) demonstrates the two properties the design insists on: the
**zero-premine genesis** and the **100-block coinbase-maturity rule**. It mirrors
`zerocoin/demos/regtest-maturity.ps1`.

**1. Start the daemon** (terminal 1):

```powershell
$env:ZRO_WALLET_PASSWORD = "zro-regtest-demo"
.\target\debug\zerocoind.exe --network regtest `
    --datadir .\target\zro-regtest `
    --rpc 127.0.0.1:18443 --p2p 127.0.0.1:18444
```

The startup banner prints the network, chain id, PoW engine, data dir, the P2P endpoint, the
loopback RPC endpoint, and the wallet address.

**2. Inspect the fresh chain** (terminal 2), then mine:

```powershell
$cli = ".\target\debug\zerocoin-cli.exe"
& $cli --network regtest --rpc 127.0.0.1:18443 getinfo      # height 0, subsidy_issued 0, utxo_count 0
& $cli --network regtest --rpc 127.0.0.1:18443 getnewaddress
& $cli --network regtest --rpc 127.0.0.1:18443 mine --blocks 99
& $cli --network regtest --rpc 127.0.0.1:18443 getbalance   # 4950 ZRO confirmed, 0 spendable
& $cli --network regtest --rpc 127.0.0.1:18443 mine --blocks 2
& $cli --network regtest --rpc 127.0.0.1:18443 getbalance   # 5050 ZRO confirmed, 100 ZRO spendable
& $cli --network regtest --rpc 127.0.0.1:18443 getinfo       # height 101, subsidy_issued 5050 ZRO
& $cli --network regtest --rpc 127.0.0.1:18443 stop
```

After 101 blocks: **5,050 ZRO confirmed**, but only **100 ZRO spendable** — exactly the two
coinbases at heights 1 and 2 that have reached 100 confirmations.

**Or run the whole thing as one script** (from the crate root):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-maturity.ps1
```

The script starts a throwaway daemon on the regtest defaults, runs the steps above, prints the
real balances, and always stops the node and deletes its temp data dir — even if a step throws.
(The scripts use `#requires -Version 5.1`, so Windows PowerShell works.)

---

## Multi-node testing

Prove the authenticated P2P fabric gossips blocks between two independent nodes.

**Terminal 1 — node A:**

```powershell
$env:ZRO_WALLET_PASSWORD = "node-a"
.\target\debug\zerocoind.exe --network regtest --datadir .\target\zro-a `
    --rpc 127.0.0.1:18443 --p2p 127.0.0.1:18444
```

**Terminal 2 — node B, dialing A via `--connect`:**

```powershell
$env:ZRO_WALLET_PASSWORD = "node-b"
.\target\debug\zerocoind.exe --network regtest --datadir .\target\zro-b `
    --rpc 127.0.0.1:18543 --p2p 127.0.0.1:18544 --connect 127.0.0.1:18444
```

The two nodes complete the mutual-authentication handshake (ephemeral ECDH + static-key
signatures) and then exchange messages inside AES-256-GCM + HMAC-SHA256 frames with replay
protection. Confirm the link and propagate a block:

```powershell
# Both nodes should report one peer
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getpeercount   # { "peers": 1 }
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18543 getpeercount   # { "peers": 1 }

# Mine on A; B picks the block up via inv -> getdata -> block gossip
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 5
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18543 getinfo        # height now 5 as well
```

`--datadir` isolates each node's chain and wallet, so the two nodes keep separate state.

---

## Wallet usage

### Desktop wallet (`zerocoin-gui`)

```powershell
.\target\debug\zerocoin-gui.exe            # devnet by default; starts its own node
```

```
zerocoin-gui [--network mainnet|devnet|regtest] [--rpc HOST:PORT] [--no-spawn]
```

- By default the wallet probes the network's default loopback RPC port; if nothing is
  listening, it **spawns its own detached `zerocoind`**, pointed at the same per-user data
  directory. The spawned daemon receives **no password** — the wallet creates or imports the
  wallet over RPC, so the password never appears on a command line.
- `--rpc` points the wallet at a node you run yourself; it then never spawns one.
- `--no-spawn` never starts an embedded node.
- The wallet **holds no keys**: keystore unlock, signing, and broadcast all happen inside the
  node. The UI never keeps a submitted password.

First run shows a **welcome** screen (create a new wallet, or import an existing seed/keystore).
After a successful **create**, a mandatory "download your backup" step freezes the window until
the fresh `wallet.json` keystore has been saved once via the native file dialog; only then does
the dashboard unlock. The dashboard shows the spendable balance, a network/connectivity pill,
and Send / Receive / History actions.

### Command-line wallet

```powershell
# Create a fresh wallet (or import); then it is persisted under the data dir
$pw = "change-me-local-only"

# Pay 25 ZRO (2,500,000,000 Fah), fee 1000 Fah
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 `
    sendtoaddress --address <RECIPIENT> --amount 2500000000 --fee 1000 --password $pw

# Mine one block to confirm it
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 1
```

Only **spendable (matured)** coins are eligible for selection, so spending an immature
coinbase fails with `ImmatureCoinbase` rather than producing an invalid transaction.

### Where the wallet is stored

Chain and wallet state live under a per-user, **per-network** data directory
(`src/datadir.rs`):

| OS | Base directory | Per-network path |
|----|----------------|------------------|
| Windows | `%APPDATA%\ZeroCoin` | `%APPDATA%\ZeroCoin\<network>` |
| macOS | `~/Library/Application Support/ZeroCoin` | `.../ZeroCoin/<network>` |
| Linux | `$XDG_DATA_HOME/zerocoin` or `~/.local/share/zerocoin` | `<base>/<network>` |

The environment variable `ZRO_HOME` overrides the base directory. The encrypted wallet file is
`wallet.json` under the network directory; the chain state is `chain.json` in the same place.
Because the wallet and any embedded daemon resolve the *same* path, the balance and identity
survive moving, deleting, or updating the binaries.

---

## Mining and the in-built pool

- **Mining** is driven by the RPC `mine`/`generate` command (`--blocks N`). A node mines with
  the engine its network defines. On regtest the trivial engine makes blocks instant.
- **Device profiles** (`HardwareProfile`) and eco-mining exist to make ordinary hardware viable
  without changing consensus: a mobile/low-spec profile pins mining to a single thread and
  sleeps between attempts. The throttle sleeps *between* hashes, never inside `hash()`, so an
  eco-mined block validates identically everywhere.
- **The in-built pool** lets a low-end device submit **shares** — valid proofs against an
  easier target — to a full node, which credits share weight and pays a proportional slice of
  the next block it finds. Shares are **off-chain pool state**: they never enter a block, so
  issuance is unchanged — the chain only ever sees the split coinbase, bounded exactly like a
  solo one.

Inspect a running node's pool:

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getpoolinfo
```

There is also a pool smoke-test script (from the crate root):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-pool.ps1
```

It starts a throwaway daemon, calls `getpoolinfo`, mines solo blocks, and confirms
`subsidy_issued` advances by exactly the subsidies mined — then always stops and cleans up.

---

## Configuration

### Environment variables

| Variable | Meaning |
|----------|---------|
| `ZRO_WALLET_PASSWORD` | Wallet password used by `zerocoind` at boot when `--password` is not given. |
| `ZRO_HOME` | Overrides the base data directory. |

Treat the wallet password as sensitive. Do not put it in shell history, scripts you commit, or
your environment on a shared machine.

### Command-line summary

| Binary | Options |
|--------|---------|
| `zerocoind` | `--network`, `--datadir`, `--p2p`, `--rpc`, `--connect`, `--password`, `--help` |
| `zerocoin-cli` | `--network`, `--rpc`, then a command (`getinfo`, `getnewaddress`, `getbalance`, `getpeercount`, `getpoolinfo`, `mine`/`generate`, `sendtoaddress`/`send`, `stop`, `help`) |
| `zerocoin-gui` | `--network`, `--rpc`, `--no-spawn`, `--help` |

### Ports

- **P2P:** mainnet 8233, devnet 18233, regtest 18444.
- **RPC:** mainnet 8232, devnet 18232, regtest 18443 — **loopback only**.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `no wallet password: pass --password PW or set ZRO_WALLET_PASSWORD` | The daemon will not store a key in the clear; supply a password (or run walletless with the GUI). |
| `daemon did not open RPC port ... in time` | A previous node still holds the port; change `--rpc`/`--p2p` or stop it. |
| `stored chain data is corrupt: key must be a string` | A data dir from an older format; delete `--datadir` and start fresh. |
| `GenesisMismatch` | The data dir belongs to a different network; use a per-network `--datadir`. |
| Mining feels slow on `devnet` | Expected — devnet uses the real memory-hard scratchpad engine; use `regtest` for instant blocks. |
| A phone cannot validate / the OS kills it | Do not run a full node on it; run it as a **share-miner** for a pool. |
| `getpoolinfo` shows `active: false` | No shares have been submitted since the last block; the ledger drains on every `mine`. |

---

## Testing

The full test suite is run with:

```powershell
cargo test
```

As executed on this repository (Windows, debug profile):

```
unittests src/lib.rs      ... 207 passed; 0 failed
unittests src/bin/zerocoin_cli.rs ... 0 passed
unittests src/bin/zerocoin_gui.rs ... 13 passed; 0 failed
unittests src/bin/zerocoind.rs    ... 0 passed
Doc-tests zerocoin        ... 0 passed
```

**Total: 220 tests, 0 failed.** This includes unit tests (`proptest` property tests and
`tempfile`-backed tests) and in-process integration tests that exercise the node RPC,
the wallet lifecycle, and the pool share → micro-reward split.

> Note: `zerocoin/DEVNET_GUIDE.md` states "196 unit tests". That number is **out of date** —
> the suite currently reports 220 passing tests.

---

## Contributing

There is currently **no `CONTRIBUTING.md`** in the repository. If you would like to
contribute, the conventions the project follows are:

- Use **conventional commit** messages (`feat`, `fix`, `chore`, `docs`, `refactor`, `test`).
- Keep changes **small and focused**; one purpose per pull request.
- Reference the relevant issue with `#<issue-number>` in commit messages and pull-request
  descriptions.
- Update documentation when behavior changes.

Because this is experimental software, please open an issue to discuss larger changes before
implementing them, and include tests for behavioral changes. **Do not commit secrets, wallet
files, or chain data** — see the note on `.gitignore` in [Security](#security).

---

## Security

ZeroCoin is **unaudited experimental software**. Before using it for anything of value, it
should receive an independent security review. Key points:

- **Do not use real funds.** There is no guarantee of safety, liveness, or value.
- **Back up your wallet.** The desktop wallet deliberately forces a one-time backup of
  `wallet.json` after creation; keep that file (and your password) somewhere safe. Losing
  either means losing access to the funds.
- **The wallet password is sensitive.** It unlocks the argon2id-derived AES-256-GCM keystore.
  Never share it, and never commit it.
- **RPC is loopback-only.** The JSON-RPC endpoint is a separate trust boundary from the
  authenticated P2P fabric and binds to `127.0.0.1`. Do not expose it to a network.
- **No wallet/chain files belong in Git.** The repository's `.gitignore` is written to exclude
  `wallet.json`, `chain.json` (and their temporary siblings), `.env*` files, per-user data
  directories, and build output — precisely so state and secrets are not accidentally
  committed. `Cargo.lock` **is** intentionally tracked (this is a binary crate; a lockfile
  makes builds reproducible and contains no secrets).

**Reporting a vulnerability.** No security policy or private contact is published in the
repository at this time. Until one exists, report privately — for example by opening a private
security advisory on the GitHub repository's **Security** tab — and **do not** disclose issues
publicly before they can be triaged. There is no bug-bounty program.

### Repository secret audit

As part of this documentation pass, `.gitignore` and the Git-tracked files were reviewed for
accidentally committed secrets. Findings:

- The tracked files contain **no** private keys, API keys, tokens, or credentials.
- The only authentication-like strings present are **obvious demo placeholders** in
  `zerocoin/DEVNET_GUIDE.md` (`"node-a"`, `"node-b"`, `"zro-regtest-demo"`), used as example
  passwords in copy-paste commands. They are not real secrets, but any operator must still use
  their own strong, unique password.
- `zerocoin/src/node.rs` contains a `"test-password"` literal and an import path for a
  64-hex-character secret — both are **test/example code**, not stored credentials.

No action was taken beyond this report (no files were deleted and no history was rewritten).

---

## Roadmap

The repository does **not** contain a roadmap document, milestone list, or issue templates at
the time of writing, so no future-release commitments are documented here. What exists today is
the implementation described in [Verified features](#verified-features). Anything beyond that
(e.g. a public network, mobile clients, exchange integration, light clients) is **not yet
implemented in this repository** and should be treated as unverified.

---

## License

This project is licensed under the **MIT License**. See the [`LICENSE`](LICENSE) file for the
full text. The `Cargo.toml` also declares `license = "MIT"`.

---

## Disclaimer

ZeroCoin is **experimental, unaudited software** provided **"as is", without warranty of any
kind**. It is provided for research and educational purposes. The authors and contributors:

- make **no** claim that it is secure, correct, or production-ready;
- make **no** guarantee of availability, consensus stability, or value;
- are **not** responsible for any loss of funds, data, or time.

**Do not use this software to store or transact anything of value.** If you run it, do so on a
throwaway network such as `regtest`, with disposable keys, and never expose private keys or
wallet files. Use at your own risk.