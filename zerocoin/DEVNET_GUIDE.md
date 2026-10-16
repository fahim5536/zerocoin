# ZeroCoin (ZRO) — Devnet Setup Guide

This guide walks a brand-new machine from source to a running, mining ZeroCoin node,
and demonstrates the two things the specification insists on:

1. the **zero-premine genesis** — block 0 creates *nothing* (`VALUE = 0`, no allocations); and
2. the **100-block coinbase-maturity** rule — mined coins cannot be spent until they have
   100 confirmations, verified with the canonical `mine --blocks 101` flow.

It also covers mining on **low-end hardware**: device profiles, eco-mining, and the in-built
pool that lets a 4 GB phone earn micro-rewards (§7) — without changing what the chain agrees on.

Everything below was run and captured on Windows (PowerShell); the same commands work on
Linux/macOS with the obvious shell substitutions.

---

## 0. Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Rust toolchain | `rustc` ≥ 1.75 | the crate's MSRV (`Cargo.toml → rust-version`) |
| Cargo | ships with Rust | build + test |

There is **no C/C++ dependency** and no external service: the ASIC-resistant PoW is pure
Rust behind the `PowEngine` trait, and secp256k1 comes from RustCrypto's `k256`. It builds
cleanly on Windows, Linux, and macOS.

```powershell
rustc --version   # rustc 1.75 or newer
cargo --version
```

---

## 1. Build

From the crate root (`zerocoin/`):

```powershell
cargo build --bins          # debug: fast to compile, instant regtest mining
# or, for a realistic PoW feel on devnet/mainnet:
cargo build --release --bins
```

This produces two executables under `target/debug/` (or `target/release/`):

- **`zerocoind`** — the full node: chain state, authenticated P2P fabric, loopback JSON-RPC.
- **`zerocoin-cli`** — the thin client: one subcommand = one RPC call (like `bitcoin-cli`).

Run the full test suite (196 unit tests) at any time:

```powershell
cargo test                  # => test result: ok. 196 passed; 0 failed
```

---

## 2. The hard-coded, zero-premine genesis

The genesis block is **compiled into the software**, not handed to the first node by an
operator. Nobody is rich at launch because block 0 has **no outputs at all**.

`src/genesis.rs`:

```rust
pub fn genesis_coinbase() -> Transaction {
    let mut script_sig = Vec::new();
    push_data(&[], &mut script_sig);              // BIP-34 height commitment: height 0
    push_data(GENESIS_MESSAGE, &mut script_sig);  // "No premine, no owner: ..."

    Transaction {
        version: 1,
        inputs: vec![TxIn { previous_output: Outpoint::null(), script_sig, sequence: u32::MAX }],
        outputs: Vec::new(),   // <-- NO OUTPUTS: the genesis block mints nothing (VALUE = 0)
        lock_time: 0,
    }
}
```

Every header field except the nonce is a fixed constant derived from the network's
`ChainParams`; the nonce is found by a *deterministic* search from zero, so every node on a
given network derives the **identical genesis hash**. `Chain::open` refuses to run if the
stored block 0 does not match that hash (`ChainError::GenesisMismatch`), so a node can never
be tricked onto a pre-funded private chain.

The result is visible in `getinfo` on a fresh chain: `height 0`, `subsidy_issued 0`,
`utxo_count 0`. The **only** way value ever enters ZeroCoin is the block subsidy earned by
proof of work — mine it, or be paid by someone who did.

> **Mainnet note.** At the mainnet difficulty floor the memory-hard engine would search for a
> long time, so a real launch mines block 0 **once, offline**, and pins the resulting nonce
> with `genesis_block_with_nonce(...)`. The constant belongs to the software, not to whoever
> boots first — exactly as Bitcoin's block 0 is baked into the client.

---

## 3. Choose a network

`ChainParams` defines three networks (`src/params.rs`):

| Network | PoW engine | Retarget | Default RPC / P2P | Use |
|---------|-----------|----------|-------------------|-----|
| `mainnet` | scratchpad, 2 MiB / 4096 rounds | every 1440 blocks | 8232 / 8233 | the real network |
| `devnet` | scratchpad, 64 KiB / 1024 rounds | every 1440 blocks | 18232 / 18233 | public testing, real ASIC-resistant hash |
| `regtest` | trivial SHA-256d | **off** (pinned) | 18443 / 18444 | local, instant mining, this guide |

All three target **60-second** blocks with a **1,440-block (24 h)** retarget window; regtest
simply disables retargeting and uses an easy target so a single process can mine on demand.

The wallet is encrypted with **AES-256-GCM over an argon2id key**, so `zerocoind` **requires**
a password and refuses to start without one — there is no insecure default. Supply it with
`--password` or the `ZRO_WALLET_PASSWORD` environment variable.

---

## 4. Single-node regtest: mine and prove coinbase maturity

### 4.1 Start the daemon

```powershell
$env:ZRO_WALLET_PASSWORD = "zro-regtest-demo"
.\target\debug\zerocoind.exe --network regtest `
    --datadir .\target\zro-regtest `
    --rpc 127.0.0.1:18443 --p2p 127.0.0.1:18444
```

Startup banner (abridged):

```text
ZeroCoin node starting
  network   : regtest
  chain id  : 0x5a524f00
  pow engine: sha256d-trivial
  data dir  : .\target\zro-regtest
  p2p       : 127.0.0.1:18444 (listening)
  rpc       : 127.0.0.1:18443 (loopback only)
  wallet    : mxSS9TCPRZh8nGypqqhcxsTaXtuA3MGsLo
Drive this node with zerocoin-cli, e.g.:
  zerocoin-cli --network regtest mine --blocks 101
```

The RPC binds to **loopback only** — a separate trust boundary from the authenticated P2P
fabric, never exposed to the network.

### 4.2 Inspect the fresh chain (in a second terminal)

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getinfo
```

```json
{
  "network": "regtest",
  "chain_id": 1515343616,
  "height": 0,
  "engine": "sha256d-trivial",
  "subsidy_issued": 0,
  "utxo_count": 0,
  "peers": 0
}
```

`subsidy_issued: 0` and `utxo_count: 0` — **the genesis created nothing.**

### 4.3 Mine 99 blocks — every coinbase is still locked

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 99
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getbalance
```

```json
{ "address": "mxSS9TCPRZh8nGypqqhcxsTaXtuA3MGsLo", "confirmed": 495000000000, "spendable": 0 }
```

99 blocks × 50 ZRO = **4950 ZRO confirmed**, but **0 spendable** — the height-1 coinbase has
only 99 confirmations, one short of the 100 required. The maturity rule is enforced by the
UTXO set (`is_mature`), not just reported.

### 4.4 Mine 2 more blocks (101 total) — the first coinbases unlock

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 2
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getbalance
```

```json
{ "address": "mxSS9TCPRZh8nGypqqhcxsTaXtuA3MGsLo", "confirmed": 505000000000, "spendable": 10000000000 }
```

At tip 101: **5050 ZRO confirmed** but only **100 ZRO spendable** — precisely the two
coinbases at heights 1 and 2 that have reached 100 confirmations. The other 4950 ZRO remain
locked. This is the maturity rule demonstrated end to end.

> A coinbase mined at height `H` becomes spendable once the tip reaches `H + 100`
> (`COINBASE_MATURITY = 100`). `mine --blocks 101` from genesis is the canonical check.

### 4.5 Shut down

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 stop
```

State and the encrypted wallet persist in `--datadir`; restarting resumes from the same tip.

### 4.6 …or run the whole thing as one script

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-maturity.ps1
```

`demos/regtest-maturity.ps1` starts a throwaway daemon, runs steps 4.2–4.5, prints the real
balances, and always stops the node and deletes the temp data dir — even if a step throws.

---

## 5. Two-node regtest devnet: peer discovery + block propagation

Prove the authenticated P2P fabric gossips blocks between independent nodes.

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

The two nodes run the mutual-authentication handshake (ephemeral ECDH + static-key
signatures) and then exchange messages inside AES-256-GCM + HMAC-SHA256 frames with
replay protection. Confirm the link:

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getpeercount   # { "peers": 1 }
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18543 getpeercount   # { "peers": 1 }
```

Mine on A; B picks the block up via `inv` → `getdata` → `block` gossip:

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 5
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18543 getinfo        # height now 5 too
```

---

## 6. Sending a payment

`sendtoaddress` unlocks the wallet (argon2id → AES-256-GCM), selects **mature** coins, builds
and signs a P2PKH transaction, admits it to the mempool, and broadcasts it. Amounts are in
**Fah** (1 ZRO = 100,000,000 Fah); the default fee is 1000 Fah.

```powershell
# pay 25 ZRO (2500000000 Fah) to a recipient address, fee 1000 Fah
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 `
    sendtoaddress --address <RECIPIENT> --amount 2500000000 --fee 1000 --password "node-a"

# mine one block to confirm it
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 mine --blocks 1
```

Only spendable (matured) coins are eligible for selection, so an attempt to spend an
immature coinbase fails with `ImmatureCoinbase` rather than producing an invalid transaction.

---

## 7. Mobile, eco-mining, and the in-built pool

ZeroCoin is built to be mined on ordinary hardware — including a 4 GB Android phone — not
only on rigs. Three cooperating pieces make that real, in `src/consensus/pow.rs`,
`src/consensus/reward.rs`, and `src/pool.rs`.

> ### Consensus-safety first (read this)
>
> Two rules are non-negotiable, and the design below respects both:
>
> 1. **The scratchpad size is a *per-network consensus constant*, never a per-device
>    choice.** The memory-hard hash folds in the whole scratchpad, so its *length is an input
>    to the hash*. Two nodes that allocate different amounts compute different hashes and
>    **fork the chain**. "Mobile Mode" therefore does *not* silently shrink memory at runtime;
>    instead a network that wants to be phone-mineable adopts `ScratchPadEngine::mobile()`
>    (256 MiB) as its single engine, and *every* node — phone or rig — uses exactly that size.
>    A device that cannot allocate it must run as a **share-miner** (§7.3), not a full validator.
> 2. **Micro-rewards *redistribute* the existing subsidy; they never mint new coins.** A pool
>    block pays many contributors from one multi-output coinbase whose total is exactly
>    `subsidy + fees`. `validate_coinbase` re-checks that total and the running supply against
>    the **21,000,000 ZRO** cap on every connect, so the pool cannot inflate issuance by one Fah.

### 7.1 Device profiles and phone-safe memory

`HardwareProfile` classifies a device from its usable RAM and core count
(`HardwareProfile::detect()`), and answers three *ergonomics* questions — never a consensus
question:

| Profile | Detected as | Mining threads | Eco throttle | Local memory budget |
|---------|-------------|:--------------:|:------------:|:-------------------:|
| `Mobile`  | ≤ 4 GB RAM (or ≤ 2 cores) | **1** | **30 ms** | 256 MiB |
| `LowSpec` | ≤ 8 GB RAM (or ≤ 4 cores) | **1** | **20 ms** | 512 MiB |
| `Desktop` | ≤ 16 GB RAM               | cores / 2 | — | 512 MiB |
| `Server`  | more                      | all cores | — | unbounded |

Two ready-made engines bound the memory a low-end device commits:

```rust
ScratchPadEngine::mobile()   // 256 MiB scratchpad, 1024 rounds — fits a 4 GB phone
ScratchPadEngine::low_spec() // 512 MiB scratchpad, 2048 rounds
```

`engine.fits_in_available_ram(bytes)` lets a device check it can run *full validation* while
leaving the OS its 1 GiB reserve; if not, it should mine shares instead. `engine.capped_to(profile)`
clamps a locally-chosen engine to the profile's budget — a *local* decision that never redefines
the network's engine.

### 7.2 Eco-mining and the single-core limiter

`MiningConfig` is how a miner drives the nonce search: how many threads, and whether to cool
between attempts. A mobile/low-spec profile pins mining to **exactly one CPU thread** and
inserts an aggressive cooling interval — **20–30 ms slept between hash attempts** — to keep a
phone from overheating and to protect its battery:

```rust
let cfg = MiningConfig::for_profile(HardwareProfile::Mobile); // 1 thread, 30 ms cool
// or the canonical eco preset:
let cfg = MiningConfig::mobile_eco();

let (nonce, hash) = mine_with_config(
    &engine, &header.preimage(), &target, 0, &cfg, Some(&stop_flag),
)?;
```

The throttle sleeps **between** attempts, never inside `hash()`, so:

- the hash a nonce produces is **byte-identical** to full-speed mining — an eco-mined block or
  share validates on every node (tested by `eco_throttle_never_changes_the_hash`); and
- **validation is never slowed** — a validator only ever calls `verify_pow`, one hash.

Multi-core rigs still get a parallel search (`mine_parallel`, a strided nonce partition) when no
throttle is set; `mine_with_config` picks the path automatically. The optional `stop: &AtomicBool`
lets a mobile app cancel mining instantly (e.g. on a thermal warning).

### 7.3 The in-built pool: shares and micro-rewards

A phone will essentially never win a full-block race, so on its own it earns nothing. The pool
lets it submit **shares** — valid proofs against an *easier* target — to a full node, which credits
share weight and pays a proportional slice of the next block it finds.

- **Share target** = the block target scaled by `DEFAULT_SHARE_EASINESS` (`2^20`, ~1,000,000×
  easier), capped at the network `pow_limit` so a share is never cheaper than the easiest legal
  block. `share_target_for(&params, &block_target)` computes it; `validate_share` checks one (a
  single hash, no state touched).
- **Submission** rides the P2P fabric as `Message::Share` (protocol v2). A coordinator validates it
  with `pool::validate_share_submission` — it must be for *this* network and the height being mined
  *next* (stale or foreign shares are refused) — then credits `PoolLedger::record_share(payout_key_hash)`.
- **Finder weight.** Whoever finds the real block is credited `FINDER_SHARE_WEIGHT` (`= 2^20`), the
  share-equivalent of a whole block, so the finder keeps the bulk while mobiles earn a fair, stable
  micro-income proportional to the shares they produced.
- **Payout.** When the node mines it drains the ledger, and `reward::split_reward` divides the exact
  reward by weight — rounding **down** and giving the remainder to the first contributor, so the parts
  sum to *exactly* the reward. `pool_coinbase_transaction` packs them into one multi-output coinbase
  (tagged `ZeroCoin/pool`) that `mine_block_with_coinbase` solves and connects.

Inspect a running node's pool:

```powershell
.\target\debug\zerocoin-cli.exe --network regtest --rpc 127.0.0.1:18443 getpoolinfo
```

```json
{
  "active": false,
  "contributors": 0,
  "finder_weight": 1048576,
  "mining_height": 1,
  "share_easiness": 1048576,
  "share_target": "0x7fffff0000000000000000000000000000000000000000000000000000000000",
  "total_weight": 0
}
```

(Keys come back sorted; on regtest `share_target` is the `0x207fffff` floor — `0x7fffff`
then 29 zero bytes. Once mobiles submit shares, `active` flips to `true` and
`contributors`/`total_weight` rise; after the next `mine` the ledger drains back to zero.)

> Run the whole pool RPC flow as one script — it starts a throwaway daemon, calls
> `getpoolinfo`, mines solo blocks (`pooled_blocks: 0`), and confirms `subsidy_issued`
> advances by exactly the subsidies mined (the cap intact), then always stops and cleans up:
>
> ```powershell
> powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-pool.ps1
> ```

Because a share is pure pool-layer state — it never enters a block — however many shares circulate,
issuance is unchanged: the chain sees only the split coinbase, bounded exactly like a solo one. This
is verified end to end by the `node.rs` integration test `a_submitted_share_earns_a_mobile_micro_reward`
(the mobile balance is > 0 while `subsidy_issued` advances by exactly one subsidy) and by the cap tests
in `reward.rs`.

---

## 8. CLI reference

```text
zerocoind  [--network regtest|devnet|mainnet] [--datadir DIR]
           [--p2p HOST:PORT] [--rpc HOST:PORT] [--connect HOST:PORT]... [--password PW]

zerocoin-cli [--network NAME] [--rpc HOST:PORT] <command>
    getinfo                                   chain/network summary
    getnewaddress                             the wallet's receiving address
    getbalance                                confirmed and spendable balances (Fah)
    getpeercount                              number of connected peers
    getpoolinfo                               in-built pool: contributors, weight, share target
    mine --blocks N                           mine N blocks; splits the reward with pool
                                              share-miners when any contributed (alias: generate)
    sendtoaddress --address A --amount FAH [--fee FAH] --password PW
    stop                                      ask the node to shut down
```

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `no wallet password: pass --password PW or set ZRO_WALLET_PASSWORD` | the daemon never stores a key in the clear; supply a password |
| `daemon did not open RPC port ... in time` | a previous node still holds the port; change `--rpc`/`--p2p` or `stop` it |
| `stored chain data is corrupt: key must be a string` | a pre-fix data dir; delete `--datadir` and start fresh (the UTXO set now serializes as a Vec of pairs) |
| `GenesisMismatch` | the data dir belongs to a different network; use a per-network `--datadir` |
| mining feels slow on `devnet` | expected — devnet uses the real memory-hard scratchpad engine; use `regtest` for instant blocks |
| a phone can't validate / the OS kills it | don't run a full node on it — run it as a **share-miner** for a pool (§7.3); check `ScratchPadEngine::fits_in_available_ram` first |
| `getpoolinfo` shows `active: false` | no shares have been submitted since the last block; the ledger drains on every `mine` |
