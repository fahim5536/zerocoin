# 01 — Architecture audit of the Rust reference implementation

Audited commit: `5248b10` (`main`). Crate root: `zerocoin/`. All paths below are
relative to that crate root unless stated otherwise.

Labels: `[VERIFIED]` read from source or produced by a command quoted here;
`[PROPOSED]` recommendation; `[UNVERIFIED]` assumption.

---

## 1. Scope and method

The audit covers every file in `zerocoin/src/` (36 files, 14,986 physical lines,
13,649 of them non-blank), the Slint UI (`ui/wallet.slint`, 1,314 physical lines,
1,157 non-blank), the manifest and build script, the two demo scripts, and the two
Markdown guides. Method:

1. **Read** each module end to end, in dependency order (crypto → ledger →
   consensus → network → state → node), recording the exact byte layouts, numeric
   constants, and validation order.
2. **Grep** for negative evidence: features that are *absent* (reorg handling,
   mempool eviction, lock-time enforcement) are established by the absence of any
   code path, and that absence is stated as such.
3. **Execute** the existing test suite and the existing end-to-end demo, quoting
   the output verbatim in §12.
4. **Diff** the documentation against the code and record drift instead of
   repeating the documentation.

No file was modified during the audit.

---

## 2. Repository and build inventory

### 2.1 Layout `[VERIFIED]`

```
zerocoin/
├── Cargo.toml            # single crate, three binaries, one optional UI feature
├── Cargo.lock            # tracked on purpose (binary crate, reproducible builds)
├── build.rs              # compiles ui/wallet.slint into the crate
├── ui/wallet.slint       # 1,314 lines of Slint markup (1,157 non-blank)
├── demos/
│   ├── regtest-maturity.ps1   # end-to-end zero-premine + maturity proof
│   └── regtest-pool.ps1       # share-pool demo
├── DEVNET_GUIDE.md
├── MOBILE_BUILD.md
└── src/                  # 36 files, 14,986 lines (13,649 non-blank)
```

At the repository root there is a hand-written `.gitignore` that blocks ledger
state (`chain.json`, `wallet.json`), build output (`target/`), environment files,
and OS noise, while deliberately **not** ignoring `Cargo.lock`. It also documents
why a bare `ZeroCoin/` rule is unsafe on case-insensitive filesystems: it would
ignore the crate directory itself. `[VERIFIED]`

### 2.2 Crate configuration `[VERIFIED]`

| Item | Value |
|---|---|
| Package | `zerocoin` 0.1.0, edition 2021, `rust-version = "1.75"`, MIT |
| Library | `crate-type = ["rlib", "cdylib"]` — the `cdylib` is the Android native library |
| Binaries | `zerocoind`, `zerocoin-cli`, `zerocoin-gui` (the last `required-features = ["gui"]`) |
| Default feature | `gui = ["dep:slint", "dep:arboard", "dep:rfd"]` |
| Build script | `slint_build::compile("ui/wallet.slint")` — no other code generation |
| Release profile | `opt-level = 3`, `lto = true`, `codegen-units = 1` |
| Android metadata | package `org.zerocoin.wallet`, `minSdk 26`, `targetSdk 35`, `aarch64-linux-android` |

Dependencies, by role:

| Role | Crates |
|---|---|
| Serialisation | `serde`, `serde_json`, `hex`, `bs58` (with `check`) |
| Errors | `thiserror` |
| Hashing / MAC | `sha2`, `ripemd`, `hmac`, `hkdf` |
| Elliptic curve | `k256` (`ecdsa`, `arithmetic`, `ecdh`, `sha256`, `pkcs8`, `pem`) |
| Wallet at rest | `aes-gcm`, `argon2`, `zeroize` |
| Randomness | `rand`, `getrandom` |
| Constant-time compare | `subtle` |
| Networking / runtime | `tokio` (`rt-multi-thread`, `net`, `io-util`, `time`, `process`) |
| UI (desktop) | `slint`, `arboard`, `rfd` |
| UI (Android) | `slint` android-activity backend, `jni`, `ndk-context` |
| Dev | `proptest`, `tempfile` |

There is **no** `tests/` directory, **no** `benches/`, **no** `fuzz/`, and **no**
`.github/` workflow: the entire test surface is `#[test]` functions inside the
`src/` modules. `[VERIFIED]`

### 2.3 Source size by file `[VERIFIED]`

Counts are **non-blank** lines, the `Measure-Object -Line` convention used for the
whole audit; the physical total including blank lines is 14,986. The two numbers
are both true, they just measure different things.

| File | Non-blank lines | Class |
|---|---:|---|
| `src/lib.rs` | 40 | — |
| `src/params.rs` | 227 | C |
| `src/address.rs` | 187 | N |
| `src/genesis.rs` | 180 | C |
| `src/chain.rs` | 684 | C |
| `src/storage.rs` | 183 | N |
| `src/mempool.rs` | 366 | N |
| `src/wallet.rs` | 515 | N |
| `src/pool.rs` | 286 | N |
| `src/node.rs` | 1779 | N |
| `src/session.rs` | 583 | N |
| `src/datadir.rs` | 163 | N |
| `src/gui.rs` | 2033 | U |
| `src/bin/zerocoind.rs` | 175 | U |
| `src/bin/zerocoin_cli.rs` | 175 | U |
| `src/bin/zerocoin_gui.rs` | 15 | U |
| `src/consensus/mod.rs` | 25 | — |
| `src/consensus/block.rs` | 331 | C |
| `src/consensus/difficulty.rs` | 207 | C |
| `src/consensus/immutability.rs` | 588 | C |
| `src/consensus/pow.rs` | 801 | C |
| `src/consensus/reward.rs` | 537 | C |
| `src/consensus/uint256.rs` | 316 | C |
| `src/crypto/mod.rs` | 11 | — |
| `src/crypto/hash.rs` | 156 | C |
| `src/crypto/keystore.rs` | 307 | N |
| `src/crypto/secp256k1.rs` | 258 | C |
| `src/ledger/mod.rs` | 16 | — |
| `src/ledger/script.rs` | 322 | C |
| `src/ledger/sighash.rs` | 210 | C |
| `src/ledger/transaction.rs` | 330 | C |
| `src/ledger/utxo.rs` | 456 | C |
| `src/network/mod.rs` | 30 | N |
| `src/network/frame.rs` | 514 | N |
| `src/network/handshake.rs` | 380 | N |
| `src/network/message.rs` | 263 | N |
| **Total** | **13,649** | |

Class key: **C** = consensus-critical (a behavioural difference forks the chain),
**N** = node/policy (affects propagation, storage, or usability but not validity),
**U** = user interface or tooling.

---

## 3. Layered module map `[VERIFIED]`

`src/lib.rs` documents the design intent, and the dependency graph matches it:

```
crypto  →  ledger  →  consensus  →  network
                ↘         ↓
                 params / address / genesis
                          ↓
              storage / chain / mempool
                          ↓
                        node  →  session → gui
                          ↓
                        pool (off-chain)
```

| Layer | Modules | Responsibility |
|---|---|---|
| Primitives | `crypto::hash`, `crypto::secp256k1`, `crypto::keystore` | SHA-256/SHA-256d/HASH160, secp256k1 keys and ECDSA, AES-256-GCM + argon2id wallet sealing |
| Ledger | `ledger::transaction`, `ledger::script`, `ledger::sighash`, `ledger::utxo` | Canonical transaction bytes, script subset, chain-bound signature preimage, unspent-output state machine |
| Consensus | `consensus::block`, `difficulty`, `pow`, `reward`, `uint256`, `immutability` | Header, Merkle, PoW engines, retarget, subsidy/maturity, 256-bit target maths, frozen anchors |
| Binding | `params`, `genesis`, `address` | Per-network constants, the deterministic genesis block, Base58Check addresses |
| State | `storage`, `chain`, `mempool` | Persistence, block connection, transaction pool |
| Node | `node`, `session` | P2P service, wallet, JSON-RPC over loopback, in-process API |
| Aux | `pool`, `datadir` | Off-chain share accounting, platform data directories |
| Front-end | `gui` | Slint desktop wallet and the Android entry point |

Two structural observations matter for a port:

- **`chain.rs` is the only place where consensus is applied.** `Block::validate_structure`
  checks structure and PoW; `Chain::connect_block` replays transactions against a
  cloned UTXO set and commits only on success. Everything else is plumbing.
- **`immutability.rs` is not documentation, it is executable policy.** It contains
  compile-time `assert!`s over every frozen constant plus boot-time comparisons
  against pinned hashes; `Chain::open` refuses to start if any anchor drifted.

---

## 4. Consensus rules (normative)

### 4.1 Networks `[VERIFIED]` (`src/params.rs`)

| | mainnet | devnet | regtest |
|---|---|---|---|
| Chain id | `0x5A524F01` (1515343617) | `0x5A524F02` (1515343618) | `0x5A524F00` (1515343616) |
| PoW engine | scratchpad, 2 MiB, 4,096 rounds | scratchpad, 64 KiB, 1,024 rounds | trivial SHA-256d |
| Engine id | 1 | 1 | 0 |
| Target spacing | 60 s | 60 s | 60 s |
| Retarget interval | 1,440 blocks | 1,440 blocks | 1,440 blocks |
| Max adjustment | ×4 up / ÷4 down | same | same |
| PoW limit (compact) | `0x1e00ffff` | `0x207fffff` | `0x207fffff` |
| Genesis bits | `0x1e00ffff` | `0x207fffff` | `0x207fffff` |
| Retarget enabled | yes | yes | **no** |
| P2PKH prefix | `0x00` | `0x6f` | `0x6f` |
| P2P / RPC port | 8233 / 8232 | 18233 / 18232 | 18444 / 18443 |

`ChainParams::by_name` accepts `mainnet`, `devnet`, `regtest`, and `test` as an
alias for `regtest`. `ChainParams` is a `const fn` so the immutability layer can
assert every field at compile time.

Note that **devnet mines the real scratchpad algorithm at a lighter profile**;
only regtest substitutes SHA-256d. A port that treats "test network" as "trivial
PoW" would be wrong for devnet.

### 4.2 Genesis `[VERIFIED]` (`src/genesis.rs`)

- `GENESIS_TIMESTAMP = 1_735_689_600` (2025-01-01T00:00:00Z).
- Coinbase message: `No premine, no owner: ZeroCoin is issued only by proof of work`.
- The genesis coinbase has **`outputs: Vec::new()`** — it mints nothing, by design.
  Its scriptSig is the message push with an empty height push in front.
- Header: `version = BLOCK_VERSION = 1`, `chain = params.chain_id`, `height = 0`,
  `previous_hash = 0`, `merkle_root = coinbase txid` (a single-leaf Merkle tree is
  the leaf itself), `timestamp` as above, `difficulty_bits = params.genesis_bits`,
  `engine_id = params.engine.id()`, `nonce` searched from zero.
- `genesis_block()` solves the nonce deterministically and is intended for devnet
  and regtest; mainnet uses `genesis_block_with_nonce()` with a launch nonce that
  belongs to the software, not to whoever starts the node first.

Because the coinbase has no outputs, the genesis Merkle root equals the coinbase
txid; both are pinned separately in `immutability.rs`.

### 4.3 Block header and PoW preimage `[VERIFIED]` (`src/consensus/block.rs`)

```
preimage = HEADER_TAG                        15 bytes  "ZRO/header/v1\0"
         || version           u32 LE          4
         || chain             u32 LE          4
         || height            u64 LE          8
         || previous_hash     32 bytes       32
         || merkle_root       32 bytes       32
         || timestamp         u64 LE          8
         || difficulty_bits   u32 LE          4
         || engine_id         u8              1
                                               = 108 bytes
```

The engine appends the nonce itself. `TrivialEngine` appends `nonce` as `u64 LE`
and returns `sha256d(preimage || nonce)`, i.e. 116 bytes hashed. Neither the tag
nor the field order may change: one byte changes every block hash on every network.

`Block::compute_merkle_root` duplicates a trailing odd leaf, and
`merkle_root(&[])` is `sha256d("ZRO/merkle:empty\0")`. A single-leaf tree returns
that leaf unchanged — it is **not** hashed again.

### 4.4 Structural validation order `[VERIFIED]`

`Block::validate_structure(engine, expected_chain, expected_height,
expected_previous, expected_bits, median_time_past, now)` checks, in this order:

1. `chain` equals the node's chain id;
2. `height` equals tip height + 1;
3. `previous_hash` equals the tip hash;
4. `engine_id` equals the network's engine id;
5. `difficulty_bits` equals the value this node computed for this height;
6. at least one transaction;
7. at most `MAX_BLOCK_TRANSACTIONS = 2_000` transactions;
8. transaction 0 is a coinbase;
9. no further coinbase appears;
10. `timestamp > median_time_past` (median of the previous 11 blocks);
11. `timestamp <= now + MAX_FUTURE_SECONDS` (`7_200` s);
12. Merkle root matches the transactions present;
13. the header's own hash meets the header's own target.

Steps 4 and 5 mean an attacker cannot downgrade the algorithm or the difficulty;
the target is recomputed by the receiver, not trusted from the header.

### 4.5 Proof-of-work engines `[VERIFIED]` (`src/consensus/pow.rs`)

`trait PowEngine { fn id(&self) -> u8; fn name(&self) -> &'static str;
fn hash(&self, preimage: &[u8], nonce: u64) -> Hash256; }`

- **Trivial (id 0)** — `sha256d(preimage || nonce_le)`.
- **Scratchpad (id 1)** — memory-hard construction with a 32-byte cell:
  1. `seed = SHA256(preimage || nonce_le)`;
  2. fill the pad of `memory_bytes / 32` cells from the seed by a hash chain;
  3. perform `rounds` data-dependent read-modify-write operations, where the index
     is taken from the first 8 bytes (little-endian) of the running state, masked
     when the cell count is a power of two and reduced modulo otherwise;
  4. final digest = `SHA256(state || every cell)`.

  Mainnet uses 2 MiB and 4,096 rounds; devnet 64 KiB and 1,024 rounds.

Hardware profiles (`Mobile`, `LowSpec`, `Desktop`, `Server`) only choose mining
threads and ergonomics — `MOBILE_SCRATCHPAD_BYTES = 256 MiB`,
`LOW_SPEC = 512 MiB`, `OS_MEMORY_RESERVE = 1 GiB`, thread caps 1 / 2 / 64. They are
**not** consensus: two nodes with different profiles agree on validity.

### 4.6 Difficulty `[VERIFIED]` (`src/consensus/difficulty.rs`)

`DIFFICULTY_PARAMS` = 60 s spacing, 1,440-block window, ×4 clamp, limit
`0x1e00ffff`. `next_difficulty()`:

- clamps the observed timespan to `[expected / 4, expected × 4]`;
- uses divide-first arithmetic when the target has at least 20 leading zero bits,
  so easy (regtest/devnet) targets do not overflow;
- caps the result at the network's PoW limit;
- is skipped entirely when `allow_pow_retarget == false` (regtest pins
  `genesis_bits` forever).

`required_work = (~target) / (target + 1) + 1`. `validate_bits` rejects zero and
any compact value above the network limit.

### 4.7 Supply, subsidy, maturity `[VERIFIED]` (`src/consensus/reward.rs`)

| Constant | Value |
|---|---|
| `FAH_PER_ZRO` | 100,000,000 |
| `INITIAL_SUBSIDY` | 50 ZRO = 5,000,000,000 Fah |
| `HALVING_INTERVAL` | 210,000 blocks |
| `MAX_HALVINGS` | 64 |
| `MAX_SUPPLY` | 21,000,000 ZRO |
| `COINBASE_MATURITY` | 100 blocks |

- `block_subsidy(0) == 0`; thereafter `INITIAL_SUBSIDY >> (height / 210_000)`,
  zero after 64 halvings, saturating.
- `block_reward = subsidy + fees` with checked addition.
- `maturity_height = height + 100`; an output from a coinbase at height *H* is
  spendable in a block at height *H + 100* (i.e. after 100 confirmations).
- `total_supply_ceiling()` saturates at `MAX_SUPPLY`; `subsidy_issued` is tracked
  across the chain and starts at zero.

`split_reward(reward, weights)` allocates with `u128` intermediate arithmetic,
drops zero-weight shares, and gives the remainder to the first recipient — exact,
no rounding loss.

### 4.8 Coinbase validation `[VERIFIED]`

`validate_coinbase(tx, height, fees, subsidy_issued)`:

1. the transaction must be a coinbase;
2. its scriptSig must begin with a minimal push of `height` encoded as
   little-endian bytes of at most 8 bytes — the height commitment;
3. at genesis the claimed value must be zero;
4. claimed value `<= block_subsidy(height) + fees`;
5. claimed value `>= fees` (the miner may not burn fee value into thin air);
6. `subsidy_issued + (claimed - fees) <= MAX_SUPPLY`.

It returns the subsidy actually claimed, which the chain accumulates.

---

## 5. Transactions, signatures, script, and UTXO state

### 5.1 Canonical transaction encoding `[VERIFIED]` (`src/ledger/transaction.rs`)

There is one serialisation, and `txid = sha256d(serialize())`. All integers are
little-endian; all lengths are minimal varints.

```
version      i32 LE
varint       number of inputs
  per input: txid 32 | vout u32 LE | varint script_len | script | sequence u32 LE
varint       number of outputs
  per output: value u64 LE | varint script_len | script
lock_time    u32 LE
```

Limits: `MAX_TX_BYTES = 1_000_000`, `MAX_TX_INPUTS = 10_000`,
`MAX_TX_OUTPUTS = 10_000`. A coinbase is exactly one input whose outpoint is the
null outpoint (`txid = 0`, `vout = u32::MAX`). Non-minimal varints are rejected on
decode. The encoding is legacy-Bitcoin-shaped but **not** Bitcoin: there is no
witness marker, no segwit serialisation, and `lock_time` is carried but unused.

### 5.2 Sighash `[VERIFIED]` (`src/ledger/sighash.rs`)

```
SIGHASH_TAG "ZRO/sighash/v1\0"
|| chain_id u32 LE            ← binds the signature to one network
|| tx.version i32 LE
|| varint n_in
   per input: txid 32 | vout u32 | varint len | script   ← every scriptSig blanked,
                                                             except the input being
                                                             signed, which carries
                                                             the referenced
                                                             script_code
              | sequence u32
|| varint n_out | per output: value u64 | varint len | script
|| lock_time u32
|| sighash_type u32
```

Only `SIGHASH_ALL = 0x01` exists. `TxSigChecker` is bound to
`(transaction, input index, script_code, chain id)` and verifies a DER ECDSA
signature over the SHA-256d of this preimage. Because the chain id is inside the
preimage, a regtest signature can never validate on mainnet.

### 5.3 Script `[VERIFIED]` (`src/ledger/script.rs`)

Supported opcodes: `OP_0`, direct pushes `0x01`–`0x4b`, `OP_PUSHDATA1`,
`OP_PUSHDATA2`, `OP_VERIFY`, `OP_DROP`, `OP_DUP`, `OP_EQUAL`, `OP_EQUALVERIFY`,
`OP_HASH160`, `OP_CHECKSIG`.

Limits: 1,000 stack items, 520-byte elements, 201 opcodes, 10,000-byte script.

`p2pkh_script_pubkey` = `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`.
That is the only standard output type in the codebase. There is **no** P2SH,
multisig, timelock, `OP_RETURN`, or data-carrier convention: a port must not
assume Bitcoin script semantics anywhere.

### 5.4 UTXO set and state root `[VERIFIED]` (`src/ledger/utxo.rs`)

`UtxoSet` is a `BTreeMap<Outpoint, UtxoEntry>`, where `UtxoEntry` is
`{ output: TxOut, height: u64, is_coinbase: bool }`. Ordering is deterministic, so
iteration order is identical on every node.

`apply_transaction` runs three phases:

1. **Reject duplicate inputs** within the transaction;
2. **Non-mutating validation** — every input exists, coinbase inputs are mature at
   the spend height (`height + 100`), each unlocking script satisfies the
   referenced locking script under the chain-bound sighash, input and output sums
   do not overflow, and `inputs >= outputs`;
3. **Commit** — remove spent outputs, insert new ones at the block height, and
   return the fee.

`state_root()` is a **single `sha256d` over the concatenation** of
`txid | vout | value | script_len (u64) | script | height | is_coinbase` for every
entry in key order. The doc comment calls it a Merkle root; the implementation is a
flat hash. `EMPTY_STATE_ROOT` and `STATE_ROOT_LAYOUT_PROBE` are pinned constants,
so the layout is frozen even though it is not a tree.

---

## 6. Networking

### 6.1 Handshake `[VERIFIED]` (`src/network/handshake.rs`)

Domain tags: `ZRO/handshake/init/v1\0`, `ZRO/handshake/resp/v1\0`,
`ZRO/session/v1`.

1. Both sides generate an **ephemeral** secp256k1 key pair per connection and
   exchange `Hello` / `HelloBack` messages carrying chain id, the ephemeral public
   key, a **static** node identity key, and a signature over the transcript.
2. The transcript is signed with the static key, so the ephemeral exchange cannot
   be swapped by a man in the middle.
3. ECDH on the ephemeral keys produces a shared secret; HKDF-SHA256 expands it
   into the directional session keys.

The node identity key is **separate from wallet keys** and never touches funds.

### 6.2 Frame format `[VERIFIED]` (`src/network/frame.rs`)

```
MAGIC 4 || seq u64 LE 8 || len u32 LE 4 || nonce 12 || ciphertext || GCM tag 16 || HMAC 32
```

`FRAME_OVERHEAD = 4 + 8 + 4 + 12 + 16 + 32 = 76` bytes.
`MAX_PLAINTEXT_BYTES = 4 MiB`. AES-256-GCM encrypts; the GCM nonce is derived from
the sequence number (`00000000 || seq`); HMAC-SHA256 covers
`MAGIC || seq || len || nonce || ciphertext`; the AAD is `MAGIC || seq || len`.

Consequences: replay and reordering are rejected by the sequence number, a wrong
key fails the tag, and a tampered length fails the HMAC. The frame is the security
boundary; the payload inside is plain JSON.

### 6.3 Messages `[VERIFIED]` (`src/network/message.rs`)

`PROTOCOL_VERSION = 2`. Thirteen variants: `Version`, `Verack`, `Ping`, `Pong`,
`GetAddr`, `Addr`, `Inv`, `GetData`, `Tx`, `GetHeaders`, `Headers`, `Block`,
`Share`. Bounds: 500 inventory entries, 1,000 addresses, 2,000 headers, 101 locator
hashes. The codec is `serde_json`, so field order and integer formatting follow
serde, not a hand-written wire format.

**Wire compatibility is therefore JSON-shaped, not byte-shaped.** Any reimplementation
must produce JSON that the Rust peer accepts; it does not have to produce identical
bytes.

### 6.4 Sync behaviour `[VERIFIED]` (`src/node.rs`)

- Per-peer reader and writer threads; outbound payloads are sealed per peer, so the
  same announcement is encrypted separately for each connection.
- `POLL_INTERVAL = 50 ms`; seed reconnection backoff grows from 1 s to 30 s.
- `SYNC_BATCH = 500` blocks per request; the length-prefixed frame limit is 8 MiB.
- A block that does not extend the tip is **not** buffered: the node asks for the
  headers above its tip and waits for the ordinary path to deliver them. See
  finding F1.

---

## 7. Node, RPC, and the in-process API

### 7.1 Process model `[VERIFIED]`

`NodeConfig { params, data_dir, p2p_listen, rpc_listen, seeds, wallet_password }`;
`Node::open` loads or creates the chain, `Node::spawn` starts the P2P listener, the
RPC listener, and the mining/wallet plumbing. The wallet password may come from
the `ZRO_WALLET_PASSWORD` environment variable; without one the daemon runs
**walletless** rather than blocking on a prompt.

### 7.2 JSON-RPC surface `[VERIFIED]` — 12 methods

| Method | Purpose |
|---|---|
| `getinfo` | chain id, height, tip, difficulty bits, engine, UTXO count, subsidy issued, state root, peers, mempool depth |
| `getnewaddress` | the node wallet's address |
| `getbalance` | `{ confirmed, spendable }` in Fah |
| `generate` | mine *n* blocks to the node wallet |
| `sendtoaddress` | build, sign, and broadcast a payment |
| `getpoolinfo` | share-pool state |
| `walletstatus` | wallet presence, lock state, address |
| `createwallet` | create the sealed keystore |
| `importwallet` | replace the key from an exported secret |
| `wallethistory` | per-output history with confirmations |
| `getpeercount` | connected peer count |
| `stop` | request a clean shutdown |

The RPC listener is bound to loopback and is **unauthenticated** — see F10.

### 7.3 In-process facade `[VERIFIED]` (`src/session.rs`)

`Session` exposes the same operations without sockets or threads, dispatching
through the same `handle_rpc`. It returns typed views (`WalletStatus`, `Balance`,
`HistoryEntry`, `ChainInfo`). This exists so Android (which cannot spawn a daemon
from the UI process conveniently) uses identical semantics to desktop.

---

## 8. Wallet and keystore

### 8.1 Wallet file `[VERIFIED]` (`src/wallet.rs`)

```
WalletFile { version: 1, chain_id, public_key, address, sealed }
```

- **One key per wallet.** No HD derivation, no address gap, no change addresses.
- The sealed blob is AES-256-GCM; the AAD is
  `"zerocoin-wallet/v1\0" || chain_id u32 LE || SEC1 compressed pubkey`, so a
  wallet file cannot be replayed onto another network or another key.
- `send` decodes and network-checks the destination address, unlocks the keystore,
  selects mature coins largest-first, builds a two-output P2PKH transaction
  (payment + change), and signs every input with `SIGHASH_ALL`.

### 8.2 Keystore `[VERIFIED]` (`src/crypto/keystore.rs`)

argon2id with `m = 19,456 KiB`, `t = 2`, `p = 1`, 16-byte salt, 12-byte GCM nonce,
`KEYSTORE_VERSION = 1`. Derived secrets are zeroized. Keys are compressed SEC1
(33 bytes); signatures are DER; `key_hash()` is HASH160 of the compressed key.

Addresses use Base58Check with a one-byte version prefix (`0x00` mainnet,
`0x6f` test) over the 20-byte HASH160, with a 4-byte checksum `[VERIFIED]`
(`src/address.rs`).

---

## 9. Storage

`ChainData { blocks, utxo, subsidy_issued }` is the whole state `[VERIFIED]`
(`src/storage.rs`). `FileStore` writes `chain.json` by writing a temporary sibling
and renaming it into place; `MemoryStore` holds the same structure for tests. The
`Store` trait is the seam.

Two properties follow, both recorded as findings: the entire ledger is held in
memory, and every block connection rewrites the entire file (F7). On regtest this
is invisible; it bounds mainnet growth.

Note also that the persisted JSON uses the **plain** hex encoding of `Hash256`
(`hex::encode(self.0)`, digest order), because `Serialize`/`Deserialize` are
implemented explicitly. That is a *different* convention from the user-facing RPC
hex (F3).

---

## 10. The share pool

`[VERIFIED]` (`src/pool.rs`)

- `SHARE_WEIGHT = 1`; `FINDER_SHARE_WEIGHT = DEFAULT_SHARE_EASINESS = 1 << 20`, so
  finding the block counts as 2²⁰ ordinary shares.
- `PoolLedger` is a `BTreeMap<Hash160, u64>` of weights, kept **off-chain**. Shares
  never appear in a block and never affect validity.
- `validate_share_submission` checks the share against a target derived from the
  block difficulty, not the full block target.
- `split_reward(reward, weights)` distributes the block reward proportionally when
  a pool coinbase is built (`pool_coinbase_transaction`, tag `ZeroCoin/pool`).

The pool is a coordination feature, not a consensus feature. A C++ port can defer
it entirely without endangering consensus.

---

## 11. GUI

`[VERIFIED]` (`src/gui.rs`, `ui/wallet.slint`)

A Slint `WalletWindow` composed of `StyledField`, `CircleAction`, and `StatusBanner`
components. The desktop binary starts a windowless `zerocoind` on demand and talks
JSON-RPC to it over loopback with a two-worker Tokio runtime; UI updates go through
`upgrade_in_event_loop`. The Android build uses `Session` in-process instead and
exports `android_main` from the `cdylib`. The GUI carries 16 of the 235 tests, all
of them headless logic.

---

## 12. Test and runtime evidence

### 12.1 Test suite `[VERIFIED]`

`cargo +stable-x86_64-pc-windows-gnu test --all-targets` produced:

```
running 235 tests
...
test result: ok. 235 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 49.21s
```

The three binary targets report `0 tests` each. `cargo test --doc` reports no
doctests.

Distribution of `#[test]` functions (sums to 235):

| Module | Tests | Module | Tests |
|---|---:|---|---:|
| `consensus/reward.rs` | 22 | `consensus/block.rs` | 5 |
| `consensus/pow.rs` | 16 | `ledger/sighash.rs` | 5 |
| `network/frame.rs` | 16 | `crypto/hash.rs` | 4 |
| `gui.rs` | 16 | `network/handshake.rs` | 4 |
| `chain.rs` | 11 | `storage.rs` | 4 |
| `node.rs` | 10 | `datadir.rs` | 3 |
| `consensus/difficulty.rs` | 9 | `address.rs` | 7 |
| `wallet.rs` | 9 | `genesis.rs` | 7 |
| `pool.rs` | 9 | `mempool.rs` | 7 |
| `consensus/uint256.rs` | 8 | `ledger/transaction.rs` | 7 |
| `crypto/keystore.rs` | 8 | `consensus/immutability.rs` | 6 |
| `session.rs` | 8 | `params.rs` | 6 |
| `ledger/utxo.rs` | 8 | `crypto/secp256k1.rs` | 6 |
| `network/message.rs` | 8 | `ledger/script.rs` | 6 |

Some of these are heavier than unit tests: the `node.rs` tests bind real loopback
ports and run two or three nodes against each other, and `pow.rs` tests mine. That
is useful, but it also means the suite is not hermetically parallel and has no CI
runner.

### 12.2 End-to-end demo `[VERIFIED]`

`demos/regtest-maturity.ps1` starts `zerocoind --network regtest` on ports
18443/18444 in a temporary data directory and drives it through the CLI. Verbatim
excerpt of the run performed for this audit:

```
==> getinfo  (fresh chain: height 0, subsidy_issued 0 -> the genesis mints nothing)
{
  "chain_id": 1515343616,
  "difficulty_bits": 545259519,
  "engine": "sha256d-trivial",
  "height": 0,
  "mempool": 0,
  "network": "regtest",
  "peers": 0,
  "state_root": "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
  "subsidy_issued": 0,
  "tip": "48910e1ffe15070a403bb2d89e0d7fc96c69a63c8b06e21da9fd404440df0a3f",
  "utxo_count": 0
}

==> mine --blocks 99  (tip 99: the height-1 coinbase has 99 confirmations, still immature)
{ "address": "miimRvmnb41CdbBT3HTAenbmK2yAYZWFbx",
  "confirmed": 495000000000, "spendable": 0 }

==> mine --blocks 2  (tip 101: heights 1 and 2 cross the 100-confirmation threshold)
{ "address": "miimRvmnb41CdbBT3HTAenbmK2yAYZWFbx",
  "confirmed": 505000000000, "spendable": 10000000000 }

==> getinfo  (final state: height 101, subsidy_issued = 101 * 50 ZRO = 5050 ZRO)
{ "height": 101,
  "state_root": "b4eac7e1ab1f0d17d6a1dcbdbc0307c24f5f63e7e4e02154ba5ec2a2bd2753b1",
  "subsidy_issued": 505000000000,
  "tip": "d88ee7eaf626844b97123eccd2f8c31b6037457730c650560715a0bcbe2eae00",
  "utxo_count": 101 }
```

This single run is worth three separate proofs:

1. **Zero premine.** At height 0 the chain has `subsidy_issued = 0` and
   `utxo_count = 0`. The genesis block creates nothing.
2. **The maturity boundary is exactly 100.** At tip 99 nothing is spendable; after
   two more blocks exactly two coinbases are, for exactly 100 ZRO.
3. **The genesis hash is stable.** The user-facing tip at height 0 is
   `48910e1f…df0a3f`; that string is the byte-reversed form of the pinned
   `GENESIS_HASH_REGTEST` constant, whose storage order is `3f0adf40…9148` (see
   F3 for the two hex conventions). A port that prints the storage order where the
   Rust node prints the display order looks "wrong" to every existing tool.

`difficulty_bits = 545259519` is `0x207fffff`, matching the regtest table, and the
engine name reported is `sha256d-trivial`.

### 12.3 Documentation drift `[VERIFIED]`

`DEVNET_GUIDE.md` states the suite contains **196 tests**. The suite contains 235.
The number is not load-bearing, but it is the kind of claim a migration plan will
copy if nobody checks it — hence F11.

---

## 13. Findings register

Severity: **H** = will cause a fork, a loss of funds, or a security failure if
carried forward unexamined; **M** = causes operational or correctness problems
under load or across implementations; **L** = documentation hygiene.

| ID | Sev | Finding | Evidence | Consequence for a C++ port |
|---|---|---|---|---|
| F1 | H | **No reorganisation, no fork choice, no orphan pool.** A block must be exactly `tip.height + 1` with `previous_hash == tip`. Any other block is not stored; the node instead asks for headers above its tip. | `Block::validate_structure` steps 2–3; `connect_block`; the non-tip branch in `node.rs` | Reproduce the linear rule exactly. Do **not** import Bitcoin's best-chain selection "because it is better": that is a consensus change. Record the liveness risk (two miners finding a block at the same height) separately. |
| F2 | M | `UtxoSet::state_root()` is a **flat `sha256d`** over concatenated entries, although its doc comment calls it a Merkle root. | `ledger/utxo.rs`; `STATE_ROOT_LAYOUT_PROBE` | Implement the flat hash. Fixing the comment (not the code) is safe; changing to a tree would change the anchor. |
| F3 | H | **Three hex conventions coexist.** `Display`, `Debug`, `Serialize`, `Deserialize`, and the P2P wire all use digest-order hex; user-facing RPC fields use `Hash256::to_display_hex()`, which **reverses** the bytes (Bitcoin-explorer convention). | `crypto/hash.rs`; `node.rs` uses `to_display_hex()` for `tip` and mined hashes | Highest-risk silent incompatibility in the whole port. Fixed fixtures must cover both directions, and the C++ API should make the distinction explicit in the type system. |
| F4 | M | `lock_time` is serialised and signed but **never enforced**; `sequence` is ignored. There is no `IsFinalTx` equivalent anywhere. | No comparison against tip height or time in `chain.rs`, `utxo.rs`, `mempool.rs`; `sequence` only appears as `u32::MAX` in constructors | Carry the field, do not implement lock-time semantics. A C++ node that *does* enforce it rejects valid Rust blocks. |
| F5 | H | The script system is a **10-opcode subset** with no P2SH, multisig, timelock, or `OP_RETURN`. | `ledger/script.rs` | Any assumption imported from Bitcoin script is invalid, in either direction. |
| F6 | M | The mempool has **no size cap, no eviction, and no fee floor**; the only policy is `take_for_block(limit)` ordered by fee rate. | `mempool.rs` | Reproduce as-is for parity, then fix in both implementations as a policy change. Until then, a port must not "helpfully" add eviction, or the two nodes disagree on which transactions propagate. |
| F7 | M | Persistence rewrites the **entire `chain.json`** on every connected block and holds the entire chain in RAM. | `storage.rs` (`FileStore`), `chain_data()` | Not a consensus issue, but a C++ port must not copy it. Any replacement storage must round-trip the same logical state and produce the same `state_root`. |
| F8 | M | The P2P payload is **JSON**, encrypted inside a binary frame. | `network/message.rs` uses `serde_json` | Interoperability is defined by "Rust accepts it", not by byte equality. The acceptance test is a live Rust↔C++ handshake, not a diff of frames. |
| F9 | H | The scratchpad PoW is **custom and unaudited**, and its parameters (2 MiB / 4,096 rounds on mainnet) are consensus. | `consensus/pow.rs`, `params.rs` | Must be reimplemented bit-exactly and differentially tested; no SHA-256d shortcut, no "simplification". |
| F10 | M | The JSON-RPC listener is **unauthenticated** and trusts any local process. `stop`, `createwallet`, `importwallet`, and `sendtoaddress` are all reachable. | `node.rs` RPC dispatch; loopback bind | Preserve semantics for parity, but treat hardening as a separate, explicitly-scoped change. |
| F11 | L | Documentation drift: `DEVNET_GUIDE.md` claims 196 tests; the suite has 235. | This audit, §12.1 | Do not copy numbers from prose into the port's test plan; regenerate them. |
| F12 | M | **No CI, no integration-test crate, no fuzz targets.** All tests are in-module, some bind fixed ports. | Absence of `.github/`, `tests/`, `fuzz/` | The migration must add the CI the Rust tree never had, or the parity gates in `05` cannot be enforced. |
| F13 | H | The genesis coinbase has **zero outputs** on purpose. | `genesis.rs` (`outputs: Vec::new()`); demo `utxo_count = 0` | Never "fix" this. Changing it changes the genesis hash and forks every existing node. |
| F14 | L | `TxOut::null()` appears to have no call site. | Grep across `src/` | Do not port dead code; confirm with the Rust maintainers before removing it there. |
| F15 | M | The wallet holds **one key**; there is no HD derivation, no address gap, and `importwallet` replaces the key outright. | `wallet.rs`, `crypto/keystore.rs` | Do not substitute an HD wallet in the C++ port and expect address parity. Address derivation must match HASH160 of the compressed key. |
| F16 | H | Consensus state is guarded by **pinned anchors**: genesis txid, genesis Merkle root, regtest/devnet genesis hashes, the mainnet preimage digest, the empty state root, and a state-root layout probe. `Chain::open` refuses to boot on drift. | `consensus/immutability.rs` | The C++ port must reproduce every anchor value *and* the refusal-to-boot behaviour. A port that boots with drifted state is worse than one that fails. |
| F17 | M | An immature-coinbase spend causes the **whole block to be dropped and the serving peer to be isolated**, not just the transaction to be rejected. | `consensus/immutability::isolates_peer`; `utxo.rs` `ImmatureCoinbase` | Reproduce the policy, including peer isolation, or the two implementations will diverge in peer scoring. |

---

## 14. What a reimplementation must reproduce exactly

This is the equivalence surface, extracted from the rules above. It is the input to
`05-test-strategy.md` §2.

**Constants and anchors**
- chain ids, ports, prefixes, difficulty parameters, engine ids and parameters;
- `BLOCK_VERSION`, `MAX_BLOCK_TRANSACTIONS`, `MAX_FUTURE_SECONDS`,
  `MAX_TX_BYTES`, `MAX_TX_INPUTS`, `MAX_TX_OUTPUTS`;
- all script limits; all frame and message limits;
- `FAH_PER_ZRO`, `INITIAL_SUBSIDY`, `HALVING_INTERVAL`, `MAX_HALVINGS`,
  `MAX_SUPPLY`, `COINBASE_MATURITY`;
- `HEADER_TAG`, `EMPTY_MERKLE_TAG`, `SIGHASH_TAG`, the handshake tags, and the
  wallet AAD prefix;
- the six pinned anchors and the state-root probe.

**Byte layouts**
- 108-byte header preimage and the engine-specific nonce append;
- the 116-byte trivial-engine hash input;
- transaction serialisation and minimal-varint rules;
- the sighash preimage, including the chain id;
- the state-root concatenation;
- the 76-byte frame overhead and its nonce/AAD/MAC derivation.

**Algorithms**
- scratchpad fill, round indexing, and finalisation;
- `next_difficulty` clamping and divide-first branch;
- `required_work`;
- subsidy and `split_reward` remainder allocation;
- Merkle duplicate-last rule, including the single-leaf case;
- Base58Check encoding.

**Policies**
- linear chain extension and the absence of reorg handling;
- peer isolation on immature-coinbase spend;
- refuse to boot on anchor drift;
- RPC presentation hex is byte-reversed, storage/wire hex is not.
