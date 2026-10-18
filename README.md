# ZeroCoin (ZRO)

**ZeroCoin is an independent, fair-launch, proof-of-work cryptocurrency with its own consensus rules, its own ledger, and a from-scratch implementation in Rust.**

It is not a fork, it embeds no third-party consensus engine, and it shares no code with Bitcoin Core. Its supply schedule, proof-of-work, transaction format, network identifiers and genesis block are defined by this repository alone.

| | |
|---|---|
| **Ticker** | ZRO |
| **Base unit** | Fah — 1 ZRO = 100,000,000 Fah |
| **Maximum supply** | 21,000,000 ZRO |
| **Issuance** | Proof of work only; no premine, no allocation, no owner |
| **Reference implementation** | Rust, edition 2021, MSRV 1.75 — crate `zerocoin` v0.1.0 |
| **Networks** | `mainnet`, `devnet`, `regtest` |
| **Licence** | MIT — see [LICENSE](LICENSE) |
| **Repository** | https://github.com/fahim5536/zerocoin |

---

## Contents

1. [Project vision and long-term mission](#1-project-vision-and-long-term-mission)
2. [Development status](#2-development-status)
3. [Core architecture and technical features](#3-core-architecture-and-technical-features)
4. [Consensus and blockchain design](#4-consensus-and-blockchain-design)
5. [Wallet security and key protection](#5-wallet-security-and-key-protection)
6. [Network and node operation](#6-network-and-node-operation)
7. [Installation, build, and usage](#7-installation-build-and-usage)
8. [Testing and verification](#8-testing-and-verification)
9. [Security reporting and responsible disclosure](#9-security-reporting-and-responsible-disclosure)
10. [Roadmap, including the planned C++ migration](#10-roadmap-including-the-planned-c-migration)
11. [Contributing](#11-contributing)
12. [Project maintenance](#12-project-maintenance)
13. [Licence](#13-licence)
14. [Honest limitations](#14-honest-limitations)

---

## 1. Project vision and long-term mission

ZeroCoin exists to be a **self-contained monetary network that can be developed, maintained and operated over decades by a community rather than a company**.

The design follows from that intent:

- **Issuance that can be verified before the software is run.** The genesis block creates nothing, the subsidy is a pure function of block height, and the total supply is bounded by a compile-time assertion. Anyone can read `src/consensus/reward.rs` and `src/consensus/immutability.rs` and confirm the schedule without trusting an operator, a foundation or a launch process.
- **Rules that cannot be quietly changed.** Consensus constants are frozen in code — some at compile time, others by pinned digest at boot. A node that detects drift refuses to start rather than follow a forked specification. Changing the money supply requires a visible, reviewable source change, not an administrative action.
- **A ledger with a single issuance path.** There is no administrative minting method, no privileged RPC call that creates value, and no key whose holder can spend coins they do not own. The only way value has ever entered this chain is the subsidy earned by proof of work.
- **Verifiable engineering over claims.** Every number in this document is meant to be reproducible from the source tree and the committed test corpus. Where something is planned rather than implemented, it is labelled as such.
- **Hardware accessibility.** The proof-of-work is memory-hard rather than hash-bound, so mining is designed around ordinary CPUs instead of specialised hardware, and an in-built pool lets low-power devices contribute shares instead of competing for whole blocks.

These are **commitments of engineering practice, not guarantees of outcome**. Long-term reliability, decentralisation and security are properties a network earns through years of adversarial operation; no project can promise them at the outset, and this one does not.

### 1.1 What ZeroCoin is not

- Not a token issued on another chain, and not a wrapper around an existing network.
- Not a Bitcoin fork, and not consensus-compatible with Bitcoin. A ZeroCoin block cannot be validated by Bitcoin Core, and a Bitcoin block cannot be validated by ZeroCoin.
- Not funded by a premine, an ICO, a foundation allocation or a developer reward. Block 0 has no outputs.
- Not a hosted service. Nodes and wallets are software you run yourself; there is no server in the architecture.

### 1.2 Relationship to Bitcoin and Bitcoin Core

ZeroCoin borrows **ideas** that the Bitcoin ecosystem has established over many years: the UTXO accounting model, a Base58Check address format, double-SHA-256 object identifiers, a capped supply with periodic halvings, coinbase maturity, median-time-past timestamp bounds, and an inspectable, minimal script interpreter.

What ZeroCoin does **not** do is inherit Bitcoin Core. This repository contains no Bitcoin Core source, links no Bitcoin library, and implements none of Bitcoin's network magic, ports, genesis block, address prefixes or consensus parameters. ZeroCoin's block spacing is 60 seconds rather than 600, its proof of work is a memory-hard construction rather than SHA-256d, its signatures are bound to a ZeroCoin chain identifier, and its genesis block is its own.

Where ZeroCoin deliberately tries to resemble Bitcoin Core is in **engineering discipline**: a consensus core separated from I/O, frozen consensus constants, an explicit and enumerable rejection taxonomy, committed golden vectors, byte-exact reimplementation gates, and a preference for removing capability over adding it. Section 10 describes how that discipline is being applied to a planned second implementation.

It bears saying plainly: Bitcoin Core has had more than a decade of adversarial review, multiple independent audits and continuous production operation. ZeroCoin has had none of that yet. Sharing engineering intentions is not the same as sharing assurance, and this README nowhere claims Bitcoin-equivalent security.

---

## 2. Development status

ZeroCoin is **pre-release software**. It is actively developed, it is internally consistent, and its consensus rules are enforced and tested — but it has **not been independently audited**, has **no public mainnet**, and should not be used to custody value.

The table below separates what is implemented and verified from what is planned or outstanding. It is the authoritative status summary for this repository.

### Implemented and verified

| Area | State | Where |
|---|---|---|
| Supply schedule, halvings, subsidy cap, coinbase maturity | Implemented, compile-time locked | `src/consensus/reward.rs`, `src/consensus/immutability.rs` |
| Block structure, Merkle commitment, structural validation | Implemented | `src/consensus/block.rs` |
| Pluggable proof of work (memory-hard and trivial engines) | Implemented | `src/consensus/pow.rs` |
| Difficulty retarget with clamping | Implemented | `src/consensus/difficulty.rs` |
| Transactions, P2PKH script subset, chain-bound sighash | Implemented | `src/ledger/` |
| UTXO set with deterministic state root | Implemented | `src/ledger/utxo.rs` |
| Chain validation, mining, persistence | Implemented | `src/chain.rs`, `src/storage.rs` |
| Memory pool with conflict rejection and fee-rate selection | Implemented | `src/mempool.rs` |
| Encrypted wallet and keystore | Implemented | `src/wallet.rs`, `src/crypto/keystore.rs` |
| Authenticated, encrypted P2P transport and gossip | Implemented | `src/network/` |
| Loopback JSON-RPC (12 methods) and in-process session API | Implemented | `src/node.rs`, `src/session.rs` |
| Desktop wallet GUI (Slint) | Implemented | `src/gui.rs`, `ui/wallet.slint` |
| In-built mining pool (shares and proportional payout) | Implemented | `src/pool.rs` |
| Baseline-vector corpus and independent verifier | Implemented, 117 cases | `test/vectors/`, `test/harness/` |
| Android: shared core, daemon and CLI compile for `aarch64-linux-android` | Verified in `MOBILE_BUILD.md` | `zerocoin/MOBILE_BUILD.md` |

### Implemented but not yet hardened

| Item | Current behaviour |
|---|---|
| Chain reorganisation | The chain accepts **linear extensions only**; there is no fork-choice rule and no reorg handling. |
| Mempool policy | Admission, conflict rejection and fee-rate ordering exist; there is **no size cap, no eviction and no fee floor**. |
| Chain persistence | A single JSON document rewritten atomically per block. Correct, but `O(state)` per block; a database backend is planned. |
| Transaction time locks | `lock_time` is carried in serialisation and committed by the sighash, but is **not enforced** as a spending condition. |
| Wallet | Single-key, single-address, largest-first coin selection, P2PKH only. No HD derivation, no mnemonic, no multisig. |
| Peer discovery | Peers are supplied with `--connect`. There are no hardcoded seed nodes and no DNS seeds. |
| Continuous integration | The suite is currently run manually; the repository contains no CI configuration. |

### Planned

| Item | Notes |
|---|---|
| Independent security audit | Not commissioned, not performed. See section 9. |
| Public mainnet launch | Mainnet parameters exist and are tested, but no public network has been bootstrapped and the mainnet genesis nonce has not yet been pinned (section 4.6). |
| Second implementation in C++ | Planned and gated; **no C++ source exists in this repository**. See section 10. |
| SPV / light client | Not implemented. |
| Hardware wallet and multisig support | Not implemented. |
| iOS | Not attempted; requires a macOS host (`MOBILE_BUILD.md` §4). |
| Android GUI packaging | Requires an Android SDK/NDK; the shared core itself compiles. |

---

## 3. Core architecture and technical features

One Rust crate builds four artefacts from a single core:

| Artefact | Source | Role |
|---|---|---|
| `zerocoind` | `src/bin/zerocoind.rs` | Full node: chain state, P2P, loopback JSON-RPC |
| `zerocoin-cli` | `src/bin/zerocoin_cli.rs` | Thin client: one subcommand = one RPC call |
| `zerocoin-gui` | `src/bin/zerocoin_gui.rs` | Slint desktop wallet (feature `gui`, on by default) |
| `zerocoin` library | `src/lib.rs` | The consensus, ledger, wallet and networking core, plus `session` and `gui` modules |

### 3.1 Repository layout

```text
zerocoin/                  Rust crate — the reference implementation
├── src/
│   ├── crypto/            hash primitives, secp256k1 keys, argon2id + AES-GCM keystore
│   ├── ledger/            transactions, script interpreter, sighash, UTXO set
│   ├── consensus/         blocks, difficulty, proof of work, rewards, uint256,
│   │                      and the consensus immutability layer
│   ├── network/           handshake, encrypted framing, P2P message set
│   ├── chain.rs           authoritative ledger view; all consensus rules meet here
│   ├── storage.rs         atomic JSON persistence behind a Store trait
│   ├── mempool.rs         unconfirmed transactions
│   ├── wallet.rs          encrypted single-key wallet and payment path
│   ├── pool.rs            in-built mining pool (shares and payout weights)
│   ├── node.rs            node service, peer management and the RPC dispatcher
│   ├── session.rs         in-process wallet API for front-ends that cannot spawn a daemon
│   ├── gui.rs             Slint wallet shared by desktop and Android
│   ├── params.rs          the three network definitions
│   ├── genesis.rs         the zero-premine genesis block
│   ├── address.rs         Base58Check P2PKH addresses
│   └── datadir.rs         per-user, per-network data directories
├── ui/wallet.slint        the wallet UI definition
├── tests/                 integration test target that exports baseline vectors
├── demos/                 end-to-end PowerShell walkthroughs
├── DEVNET_GUIDE.md        operator walkthrough (regtest, multi-node, pool)
├── MOBILE_BUILD.md        Android/iOS build status, stated as verified or blocked
└── Cargo.toml             metadata, features, release profile, Android target metadata

docs/migration/            architecture audit and the planned C++ programme
test/vectors/              117 committed baseline vectors (JSON)
test/harness/              independent Python verifier, standard library only
```

### 3.2 Module responsibilities

| Module | Responsibility | Notable invariant |
|---|---|---|
| `crypto::hash` | `sha256`, `sha256d`, `hash160`, digest types | Display order vs. storage order are distinct, explicit conversions |
| `crypto::secp256k1` | Keys, ECDSA, DER encoding, compressed SEC1 | Backed by the `k256` crate; no hand-written curve arithmetic |
| `crypto::keystore` | Password-based secret sealing | argon2id + AES-256-GCM, wallet-identity AAD |
| `ledger::transaction` | Canonical serialisation, identifiers | Bounded decoding: 1 MB, 10,000 inputs, 10,000 outputs |
| `ledger::script` | P2PKH interpreter | Ten opcodes only; four execution limits |
| `ledger::sighash` | Signature preimages | `SIGHASH_ALL` only, chain-id bound, domain-tagged |
| `ledger::utxo` | Coin set, maturity, state root | Maturity at `height + 100`; deterministic state commitment |
| `consensus::block` | Header, Merkle root, structural checks | Engine id is committed in the header |
| `consensus::pow` | Pluggable engines | Deterministic: same `(preimage, nonce)` yields the same hash everywhere |
| `consensus::difficulty` | Retarget schedule | Clamped, floored, disabled on regtest |
| `consensus::reward` | Subsidy, maturity, coinbase validation | One function defines issuance; totals are re-checked on every connect |
| `consensus::immutability` | Frozen constants and anchors | Compile-time assertions plus boot-time digest verification |
| `chain` | Applies blocks and transactions | Block application is all-or-nothing |
| `storage` | Persistence behind a trait | Atomic write-then-rename |
| `mempool` | Pending transactions | No conflicting spends can coexist |
| `network::handshake` | Session establishment | Forward secrecy plus mutual authentication |
| `network::frame` | Authenticated record layer | Replay- and reorder-proof by sequence number |
| `network::message` | Application messages | Consensus identity never derives from the wire encoding |
| `node` | Service, peers, RPC | One dispatcher serves both RPC and the in-process session |
| `session` | In-process wallet core | No sockets, no threads, same handlers as RPC |

### 3.3 Design principles visible in the code

- **All-or-nothing state transitions.** `Chain::connect_block` validates the header, replays every transaction against a clone of the UTXO set, and validates the coinbase against exactly `subsidy + fees`. The clone is committed only if every step succeeds, so a partially applied block cannot corrupt state.
- **One implementation per operation.** The loopback RPC server and the in-process `session` API dispatch through the same `handle_rpc` function. Two transports cannot drift because there is only one handler per operation.
- **No custom cryptography.** Hashing, signatures, key agreement, key derivation and AEAD sealing all come from vetted crates (`sha2`, `ripemd`, `k256`, `argon2`, `aes-gcm`, `hmac`, `hkdf`). The project implements protocols and consensus rules, not primitives.
- **Domain separation everywhere.** Header hashes, sighashes, keystores, handshake transcripts and session keys are all tagged with distinct `ZRO/...` labels, so a hash computed for one purpose can never be reused for another.
- **Frozen consensus constants.** Supply, halving interval, maturity and profile budgets are asserted at compile time; genesis and state-root commitments are pinned by digest and verified before a node will serve a chain.
- **Explicit error taxonomies.** Rejections are enumerated (`BlockError`, `UtxoError`, `DifficultyError`, `ScriptError`, `PowError`, `ChainError`, …) rather than collapsed into strings, which is what makes a future second implementation testable against the first.

Provenance note: several module headers describe the shortcomings of an earlier internal prototype (`payd`) that this codebase replaces — a plaintext seed file, plaintext length-prefixed JSON transport and a ChaCha20-Poly1305 envelope. `Cargo.toml`'s description field still carries that lineage phrase. The implementation in this repository is original to ZeroCoin and is the only thing that produces blocks.

---

## 4. Consensus and blockchain design

All values below were read from `src/params.rs`, `src/consensus/reward.rs`, `src/consensus/difficulty.rs`, `src/consensus/block.rs` and `src/genesis.rs`.

### 4.1 Supply and issuance

| Parameter | Value | Source |
|---|---|---|
| Base unit | 1 ZRO = 100,000,000 Fah | `FAH_PER_ZRO` |
| Initial block subsidy | 50 ZRO | `INITIAL_SUBSIDY` |
| Halving interval | 210,000 blocks | `HALVING_INTERVAL` |
| Maximum halvings | 64 | `MAX_HALVINGS` |
| Maximum supply | 21,000,000 ZRO = 2,100,000,000,000,000 Fah | `MAX_SUPPLY` |
| Genesis subsidy (height 0) | 0 | `block_subsidy(0)` |
| Coinbase maturity | 100 blocks | `COINBASE_MATURITY` |

The subsidy is a pure function of height: `50 ZRO` for heights 1–209,999, halving every 210,000 blocks, and exactly zero after the 64th epoch. `total_supply_ceiling()` is asserted at compile time to be **less than or equal to** `MAX_SUPPLY`, so the schedule cannot overshoot the cap even in principle.

The running total of issued subsidy is tracked in persisted chain state and re-checked on every block. A coinbase may never claim more than `subsidy + fees`.

### 4.2 Block production

| Parameter | Value |
|---|---|
| Target block spacing | 60 seconds |
| Difficulty retarget window | 1,440 blocks (24 hours) |
| Retarget clamp | 4× per adjustment |
| Regtest retargeting | Disabled (difficulty pinned) |
| Maximum transactions per block | 2,000 |
| Timestamp lower bound | Median of the previous 11 blocks |
| Timestamp upper bound | 2 hours ahead of the local clock |
| Mainnet difficulty floor | `0x1e00ffff` |
| Trivial (regtest) floor | `0x207fffff` |
| Genesis timestamp | `1735689600` (2025-01-01T00:00:00Z) |

A block's identity **is** its proof-of-work hash. The header commits to the chain id, height, previous hash, Merkle root, timestamp, difficulty bits and the proof-of-work engine id, so a block cannot silently switch algorithms. Header hashing is domain-tagged, so a header hash can never collide with a transaction hash.

### 4.3 Proof of work

The proof-of-work function is pluggable behind a `PowEngine` trait with two implementations:

| Engine | Id | Used by | Construction |
|---|---|---|---|
| ScratchPad | 1 | mainnet, devnet | Memory-hard, CryptoNight-style: derive a seed from the header and nonce, fill a scratchpad, then perform data-dependent read-modify-write rounds |
| Trivial | 0 | regtest only | Plain double SHA-256 over `preimage ‖ nonce` |

| Network | Scratchpad size | Rounds |
|---|---|---|
| mainnet | 2 MiB | 4,096 |
| devnet | 64 KiB | 1,024 |

The scratchpad **length is an input to the hash**, which is why it is a per-network consensus constant and never a per-device runtime choice: two nodes that allocate different amounts would compute different hashes and fork. Device profiles in `pow.rs` affect only local mining ergonomics — thread count and the cooling interval between hash attempts — never the hash a nonce produces, so an eco-mined block validates identically everywhere.

**Honest caveat:** the scratchpad construction is ZeroCoin's own design, inspired by memory-hard proof-of-work generally. Its ASIC-resistance has not been independently cryptanalysed. Treat "ASIC-resistant" as a design intent supported by the construction, not as an audited property.

### 4.4 Transactions, script and signatures

| Property | Value |
|---|---|
| Output model | P2PKH only (pay to public-key hash) |
| Script opcodes | 10: `OP_0`, `OP_PUSHDATA1`, `OP_PUSHDATA2`, `OP_VERIFY`, `OP_DROP`, `OP_DUP`, `OP_EQUAL`, `OP_EQUALVERIFY`, `OP_HASH160`, `OP_CHECKSIG` |
| Script limits | 1,000 stack items, 520-byte elements, 201 operations, 10,000 bytes |
| Sighash type | `SIGHASH_ALL` only — commits to every input and every output |
| Chain binding | The chain id is mixed into every signature preimage |
| Transaction size limit | 1,000,000 bytes |
| Input / output limits | 10,000 inputs, 10,000 outputs |

Restricting the interpreter to the opcodes a standard P2PKH spend needs keeps it small and free of the disabled and flow-control opcodes that have historically produced consensus bugs. Anything outside the subset is rejected.

Because the digest commits to the chain id, a signature that is valid on one ZeroCoin network can never be replayed on another, even if the transaction bytes are identical.

`lock_time` is serialised and committed by the sighash, but **no time-lock rule is enforced**; it is currently a carried field, not a spending condition. This is recorded in section 2 and in the plan.

### 4.5 UTXO state and commitment

The UTXO set supports a deterministic `state_root()` — a commitment over every entry keyed by outpoint. Two nodes with identical state compute an identical root, which lets a peer or a future light client check state agreement without transferring the set. The root is computed from explicit canonical serialisers, never from the JSON persistence encoding.

### 4.6 Genesis and the fair launch

`src/genesis.rs` builds block 0 from a fixed constant set:

- the coinbase has **no outputs at all** — the genesis block mints nothing, and `genesis_coinbase_creates_nothing` asserts it;
- its input commits to height 0 and carries the message `No premine, no owner: ZeroCoin is issued only by proof of work`;
- every header field except the nonce is derived from the network parameters;
- the nonce is found by a **deterministic search from zero**, so every node on a given network derives the identical genesis hash.

A node refuses to run if the stored block 0 does not match the expected hash (`ChainError::GenesisMismatch`), so it cannot be tricked onto a privately funded chain.

**Regtest and devnet** genesis hashes are pinned as constants (`GENESIS_HASH_REGTEST`, `GENESIS_HASH_DEVNET`) and verified at boot.

**Mainnet is not launched.** At the mainnet difficulty floor the memory-hard engine would search for a long time, so a real launch must mine block 0 once, offline, and pin the resulting nonce through `genesis_block_with_nonce`. That nonce has not been pinned, and `immutability.rs` currently pins the nonce-independent mainnet *preimage digest* (`GENESIS_PREIMAGE_DIGEST_MAINNET`) instead. Booting mainnet today would attempt to mine genesis from nonce zero. This is launch work, tracked in section 10.

### 4.7 The consensus immutability layer

`src/consensus/immutability.rs` is the strongest expression of the project's "rules cannot drift" intent. It contains:

- **57 compile-time assertions** (`const _: () = assert!(...)`) covering the base unit, the supply cap in two independent forms, the initial subsidy, the halving interval, the halving cap, the total supply ceiling, the subsidy at heights 0, 1, 209,999, 210,000, 420,000 and after the final halving, the maturity guard at heights 0 and 1, and the hardware-profile memory and thread budgets.
- **Seven pinned digests**: `GENESIS_COINBASE_TXID`, `GENESIS_MERKLE_ROOT`, `GENESIS_HASH_REGTEST`, `GENESIS_HASH_DEVNET`, `GENESIS_PREIMAGE_DIGEST_MAINNET`, `EMPTY_STATE_ROOT` and `STATE_ROOT_LAYOUT_PROBE`.
- **`verify_boot_invariants()`**, called by `Chain::open` before any chain is served. If a genesis checksum or the state-root layout has drifted by one bit, the node refuses to boot rather than follow a divergent specification. The test `one_flipped_genesis_bit_breaks_every_commitment` demonstrates that property.
- **`isolates_peer()`**, a narrow predicate that names the one transaction error class (`ImmatureCoinbase`) for which a serving peer is disconnected rather than merely rejected.

### 4.8 The in-built mining pool

The pool lets a device that would rarely win a whole block submit **shares** — valid proofs of work against a deliberately easier target — to a coordinating full node. The node credits share weight and, when it next finds a block, splits that block's reward across contributors by weight in a single multi-output coinbase.

Two properties keep this consensus-safe and are enforced in code rather than by convention:

1. **A share never enters a block.** Share accounting is plain in-memory pool state. The only thing that reaches the chain is the split coinbase.
2. **The split cannot enlarge issuance.** The coinbase total is bounded by `subsidy + fees` and re-checked by `validate_coinbase` at connect time exactly as a solo coinbase is. Pool payout redistributes one subsidy; it cannot mint a second one.

The finder of the actual block is credited the share-equivalent of a full block's work, so the finder keeps the bulk of the reward while share-miners earn a slice proportional to the shares they actually produced.

---

## 5. Wallet security and key protection

A ZeroCoin wallet is a **single secp256k1 key**. The 32-byte scalar is the wallet, so the entire keystore design exists to ensure that scalar is never stored in the clear.

### 5.1 At rest

| Layer | Construction |
|---|---|
| Key derivation | argon2id, defaults `m = 19,456 KiB`, `t = 2`, `p = 1` |
| Sealing | AES-256-GCM with a per-wallet random salt and nonce |
| Binding | The wallet's chain id and compressed public key are the AEAD associated data |
| Container | `wallet.json`, versioned (`KEYSTORE_VERSION = 1`), inside the per-network data directory |

Three consequences of that design are worth stating explicitly:

- **A wrong password is indistinguishable from a modified file**, because a wrong password derives a key that cannot open the ciphertext — the GCM tag covers both cases.
- **Keystore splicing is rejected.** A sealed secret lifted out of one wallet file and pasted into another will not open, because the associated data binds the ciphertext to that wallet's identity.
- **Hostile files cannot become denial-of-service bombs.** The KDF parameters are read from the file, so the decoder clamps them (`m ≤ 2 GiB`, `t ≤ 64`, `p ≤ 16`) before allocating anything.

No cryptography here is hand-written: derivation is `argon2`, sealing is `aes-gcm`, salt and nonce come from the operating system CSPRNG, and secrets are zeroised on drop.

### 5.2 In use

- **The password never appears on a command line when the GUI starts a node.** `zerocoin-gui` spawns a walletless daemon and creates or imports the wallet over the loopback RPC.
- **A mandatory backup step precedes first use.** After a wallet is created, the desktop wallet will not unlock its dashboard until the `wallet.json` keystore has been saved once through the native file dialog; Android writes the same byte copy into the app's private external files directory, which is visible over USB.
- **Only mature coins are spendable.** Coin selection considers only coins that have reached the 100-block maturity boundary, so an attempt to spend an immature coinbase fails with an explicit error instead of producing an invalid transaction.
- **The wallet holds no independent ledger.** Balance and history are derived from the chain on demand, so the UI cannot show a balance the chain does not support.

### 5.3 What the wallet deliberately does not do

It is a single-key, single-address wallet. There is no hierarchical deterministic derivation, no mnemonic phrase, no multisig, no hardware-wallet integration and no watch-only mode. Coin selection is greedy largest-first, which minimises input count but is not privacy-aware. These are honest scope limits, not oversights; section 10 lists them as future work.

---

## 6. Network and node operation

### 6.1 Transport

ZeroCoin does not send plaintext on the wire. Before any application message flows, two nodes perform a handshake that establishes a pair of directional session keys:

- **Forward-secret key agreement** — an ephemeral-ephemeral secp256k1 ECDH whose secret is discarded at the end of the session, so recording traffic and later stealing a node's long-term key does not decrypt past sessions.
- **Mutual authentication** — each side signs the handshake transcript with its long-term `NodeIdentity` key, and the responder's signature covers the initiator's ephemeral and static keys, binding the response to that specific session. A man-in-the-middle can neither impersonate a node nor split the session.
- **Transcript-bound key expansion** — the transcript hash salts the HKDF that expands the shared secret, so session keys are bound to both identities and the chain id.

A node's `NodeIdentity` is explicitly **not** a wallet key. It signs handshake transcripts and nothing else; the test `node_identity_is_not_a_wallet_key` pins that separation.

### 6.2 Framing

```text
MAGIC(4) || seq(8, LE) || len(4, LE) || nonce(12) || ciphertext||tag(len) || mac(32)
```

Every record is sealed with AES-256-GCM **and** carries an HMAC-SHA256 over the whole framed record, header included. The two integrity checks are independent. The sequence number is baked into the header, the GCM associated data, the HMAC and the AES nonce; a peer accepts a frame only if its sequence number is exactly the next one expected.

Because the nonce is derived from the sequence number (`0x00000000 ‖ seq`) rather than drawn at random, and each direction has its own key with a sequence that only increments, a `(key, nonce)` pair can never repeat. That removes the failure mode that breaks AES-GCM catastrophically. The maximum plaintext payload is 4 MiB, and the frame overhead is 76 bytes.

### 6.3 Messages

Protocol version 2 defines thirteen message types, grouped by job:

| Group | Messages |
|---|---|
| Handshake and liveness | `version`, `verack`, `ping`, `pong` |
| Peer discovery | `getaddr`, `addr` |
| Mempool and block propagation | `inv`, `getdata`, `tx`, `block` |
| Header sync | `getheaders`, `headers` |
| Pool shares | `share` |

List-carrying messages are bounded (`inv` 500 entries, `addr` 1,000, `headers` 2,000, locator 101) so one peer cannot bury another in work.

Payloads are JSON. That is a deliberate trade: the frame layer already provides confidentiality, integrity and freshness, so the codec only has to be unambiguous and evolvable. Consensus identity is never taken from this encoding — a transaction id and a block's proof-of-work hash are computed from their own canonical serialisers in the `ledger` and `consensus` layers — so a wire-format change can never alter what the network agrees on.

### 6.4 RPC and the in-process session

The JSON-RPC endpoint binds to **loopback by default** and is a separate trust boundary from the authenticated P2P fabric. It is framed with a 4-byte little-endian length prefix and an 8 MiB maximum. (`--rpc` can move it, so binding it to an untrusted interface is an operator decision, not a default.)

Exactly twelve methods are dispatched from one function (`handle_rpc`):

| Method | Purpose |
|---|---|
| `getinfo` | Network, chain id, height, tip, difficulty, engine, UTXO count, subsidy issued, state root, mempool size, peers |
| `walletstatus` | Whether a wallet identity is loaded |
| `getnewaddress` | The wallet's receiving address |
| `getbalance` | Confirmed and spendable balances |
| `wallethistory` | The wallet's ledger, re-derived from the chain |
| `sendtoaddress` | Unlock, select mature coins, sign, admit to the mempool and broadcast |
| `generate` | Mine N blocks (exposed as `mine` in the CLI) |
| `getpeercount` | Connected peer count |
| `getpoolinfo` | Pool contributors, weights and share target |
| `createwallet` | Create a wallet after boot |
| `importwallet` | Import an existing secret or keystore |
| `stop` | Ask the node to shut down |

`src/session.rs` exposes the same operations **in process**, for front-ends that cannot spawn a helper executable — notably Android, where a sandboxed application has no daemon to attach to. A session opens the same chain store and the same encrypted wallet file and dispatches through the same `handle_rpc`, so a wallet created by the desktop wallet opens in a session and vice versa. The session binds no sockets and starts no threads.

### 6.5 Networks, ports and data directories

| Network | PoW engine | Retarget | Chain id | Address prefix | RPC | P2P |
|---|---|---|---|---|---|---|
| `mainnet` | ScratchPad 2 MiB / 4,096 rounds | On | `0x5A524F01` | `0x00` | 8232 | 8233 |
| `devnet` | ScratchPad 64 KiB / 1,024 rounds | On | `0x5A524F02` | `0x6f` | 18232 | 18233 |
| `regtest` | Trivial (SHA-256d) | Off | `0x5A524F00` | `0x6f` | 18443 | 18444 |

Chain state and the encrypted wallet live in a per-user, **per-network** directory, so two networks can never share a chain file and a wallet can never be opened against the wrong network:

| OS | Base directory |
|---|---|
| Windows | `%APPDATA%\ZeroCoin\<network>` |
| macOS | `~/Library/Application Support/ZeroCoin/<network>` |
| Linux | `$XDG_DATA_HOME/zerocoin/<network>` or `~/.local/share/zerocoin/<network>` |

`ZRO_HOME` overrides the base directory. Mobile bindings call `datadir::set_base_dir()` once with the sandbox path the platform hands them, which takes precedence over both.

### 6.6 Peers

A node listens on the P2P port and dials any `--connect` seed it is given. Peers are re-dialled if they appear later, and a node that falls behind pulls the missing blocks in one batch — behaviours covered by the node integration tests (`a_seed_that_appears_later_is_still_dialled`, `a_lagging_node_catches_up_across_several_blocks`, `a_batch_mined_after_connecting_is_pulled_in_full`).

There is **no hardcoded seed list and no DNS seeding**, and there is no peer-ban score: a peer that serves a block violating the frozen invariants is disconnected, but persistent-misbehaviour scoring is not implemented.

---

## 7. Installation, build, and usage

### 7.1 Prerequisites

- A Rust toolchain at or above the crate's MSRV, **1.75** (`cargo` ships with it).
- No external service and no database. The consensus code and the proof of work are pure Rust, and secp256k1 comes from RustCrypto's `k256` — no C or C++ dependency is vendored for the ledger.
- A working linker for your host triple.

Windows is the only platform whose build is recorded as verified in this repository (see [zerocoin/MOBILE_BUILD.md](zerocoin/MOBILE_BUILD.md)); Linux and macOS builds have not been captured. On Windows, if the default MSVC toolchain has no linker available, address a GNU toolchain explicitly:

```powershell
cargo +stable-x86_64-pc-windows-gnu build --bins
```

### 7.2 Build

From the crate root (`zerocoin/`):

```powershell
cargo build --bins            # debug; regtest mining is instant
cargo build --release --bins  # optimised (LTO, single codegen unit)
```

This produces `zerocoind`, `zerocoin-cli` and `zerocoin-gui`. The `gui` feature is enabled by default; to build only the daemon, CLI and library — the subset that cross-compiles without a GUI SDK — use:

```powershell
cargo build --bins --no-default-features
```

The library exposes `rlib` and `cdylib` crate types. `Cargo.toml` carries `[package.metadata.android]` (package `org.zerocoin.wallet`, label `ZeroCoin`, `aarch64-linux-android`, min SDK 26, target SDK 35). Packaging an Android app additionally requires the Android SDK and NDK; see [zerocoin/MOBILE_BUILD.md](zerocoin/MOBILE_BUILD.md), which records exactly which commands have been verified and which are blocked on tooling.

### 7.3 Run a node

```powershell
$env:ZRO_WALLET_PASSWORD = "<your-password>"
.\target\debug\zerocoind.exe --network regtest `
    --datadir .\target\zro-regtest `
    --rpc 127.0.0.1:18443 --p2p 127.0.0.1:18444
```

Options:

```text
zerocoind [--network mainnet|devnet|regtest] [--datadir DIR]
          [--p2p HOST:PORT] [--rpc HOST:PORT] [--connect HOST:PORT]...
          [--password PW]
```

By default the node listens for P2P on all interfaces on the network's port and binds RPC to `127.0.0.1`. Without a password the node starts **walletless** rather than falling back to a shared default; the wallet is then created or imported over RPC — which is exactly the flow the desktop wallet uses. The node runs until `zerocoin-cli stop` raises the stop flag.

### 7.4 Use the CLI

```powershell
.\target\debug\zerocoin-cli.exe --network regtest getinfo
.\target\debug\zerocoin-cli.exe --network regtest getnewaddress
.\target\debug\zerocoin-cli.exe --network regtest mine --blocks 101
.\target\debug\zerocoin-cli.exe --network regtest getbalance
.\target\debug\zerocoin-cli.exe --network regtest stop
```

Commands: `getinfo`, `walletstatus`, `getnewaddress`, `getbalance`, `wallethistory`, `getpeercount`, `getpoolinfo`, `mine --blocks N` (alias `generate`), `sendtoaddress --address A --amount FAH [--fee FAH] --password PW` (alias `send`), `stop`, `help`. Amounts are always in Fah; the default fee is 1,000 Fah.

To send a payment of 25 ZRO:

```powershell
.\target\debug\zerocoin-cli.exe --network regtest `
    sendtoaddress --address <RECIPIENT> --amount 2500000000 --fee 1000 `
    --password "<your-password>"

# Confirm it
.\target\debug\zerocoin-cli.exe --network regtest mine --blocks 1
```

### 7.5 Use the desktop wallet

```powershell
.\target\debug\zerocoin-gui.exe            # devnet by default; starts its own node

# zerocoin-gui [--network mainnet|devnet|regtest] [--rpc HOST:PORT]
#              [--seed HOST:PORT]... [--no-spawn]
```

On launch the wallet probes the network's default loopback endpoint and, when nothing is listening, spawns a detached, windowless daemon pointed at the same per-user data directory — with no password on its command line. `--rpc` points the wallet at a node you run yourself (it then never spawns one); `--seed` gives a spawned node a peer to catch up from; `--no-spawn` disables spawning entirely.

First run shows a welcome screen offering to create a wallet or import an existing secret or keystore backup. A successful create is followed by the mandatory backup step described in section 5. The dashboard then shows spendable balance, a network/connectivity indicator, and send, receive and history actions.

### 7.6 Prove the fair launch and the maturity rule

`demos/regtest-maturity.ps1` runs the whole demonstration against a throwaway node and always cleans up:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-maturity.ps1
```

The expected sequence, which the script asserts: a fresh chain reports `height 0`, `subsidy_issued 0`, `utxo_count 0`; after 99 mined blocks the wallet shows 4,950 ZRO confirmed and **0 spendable**; at tip 101 exactly 100 ZRO — the coinbases of heights 1 and 2 — becomes spendable while the rest stays locked.

### 7.7 Run two nodes

```powershell
# Node A
$env:ZRO_WALLET_PASSWORD = "<password-a>"
.\target\debug\zerocoind.exe --network regtest --datadir .\target\zro-a `
    --rpc 127.0.0.1:18443 --p2p 127.0.0.1:18444

# Node B, dialling A
$env:ZRO_WALLET_PASSWORD = "<password-b>"
.\target\debug\zerocoind.exe --network regtest --datadir .\target\zro-b `
    --rpc 127.0.0.1:18543 --p2p 127.0.0.1:18544 --connect 127.0.0.1:18444
```

Both nodes complete the authenticated handshake and report one peer each. Mining on A causes B to fetch the block through `inv` → `getdata` → `block` gossip, so B's height follows A's.

### 7.8 Mining and the pool

`mine --blocks N` mines with the engine the network defines. On regtest the trivial engine makes blocks instantaneous; on devnet and mainnet the memory-hard engine is real work.

`getpoolinfo` shows the coordinator's current share ledger:

```powershell
.\target\debug\zerocoin-cli.exe --network regtest getpoolinfo
```

`demos/regtest-pool.ps1` exercises that flow end to end — it starts a throwaway daemon, inspects the pool, mines solo blocks, and confirms that `subsidy_issued` advances by exactly the subsidies mined, then always stops and cleans up:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-pool.ps1
```

### 7.9 Configuration

| Variable | Meaning |
|---|---|
| `ZRO_WALLET_PASSWORD` | Wallet password used by `zerocoind` at boot when `--password` is absent |
| `ZRO_HOME` | Overrides the base data directory |

The wallet password unlocks the keystore; treat it as secret material. It does not belong in shell history, in committed scripts, or in the environment of a shared machine.

### 7.10 Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| `no wallet loaded` from `getbalance`, `getnewaddress` or `sendtoaddress` | The node is running walletless. Create or import a wallet from the desktop wallet, or restart the node with `--password` / `ZRO_WALLET_PASSWORD`. |
| `The embedded node did not come up within 30 s — start zerocoind manually to see why.` | The desktop wallet could not reach or start a node. Run `zerocoind` yourself to see the underlying error, or point the wallet at a running node with `--rpc`. |
| `stored genesis … does not match this network's …` (`ChainError::GenesisMismatch`) | The data directory belongs to a different network. Use one directory per network. |
| `stored chain data is corrupt: …` | The persisted chain document could not be decoded. Keep a copy of `wallet.json`, then start from a fresh data directory. |
| The CLI reports a connection error while the node is running | `zerocoin-cli` defaults to `devnet` and that network's RPC port. Pass the same `--network` and `--rpc` the node was started with. |
| Mining is slow on `devnet` | Expected — devnet uses the real memory-hard engine. Use `regtest` for instant blocks. |
| `getpoolinfo` reports `active: false` | No shares have been submitted since the last block; the ledger is drained by every `mine`. |

---

## 8. Testing and verification

### 8.1 Test suite

From the crate root (`zerocoin/`):

```powershell
cargo test --all-targets
```

Measured on this repository immediately before this README was committed (Windows, debug profile, GNU toolchain):

```text
unittests src/lib.rs                   235 passed; 0 failed
unittests src/bin/zerocoin_cli.rs        0 passed; 0 failed
unittests src/bin/zerocoin_gui.rs        0 passed; 0 failed
unittests src/bin/zerocoind.rs           0 passed; 0 failed
integration tests tests/export_baseline_vectors.rs
                                         2 passed; 0 failed
```

**Total: 237 tests, 0 failed.**

The suite covers consensus arithmetic and limits, script acceptance and rejection, sighash construction, UTXO maturity and state-root determinism, difficulty retargeting, keystore round-trips and hostile-parameter clamping, transport framing, handshake separation, wallet persistence across restarts, and in-process node scenarios: block propagation to a peer, catch-up across several blocks, dialling a seed that appears later, pulling a batch mined after connecting, and a submitted pool share earning a micro-reward. Property tests (`proptest`) and file-backed tests (`tempfile`) are used where randomised or on-disk behaviour matters.

There are no documentation tests, and the repository contains **no CI configuration**; the suite is run manually. Adding CI is listed in section 10.

### 8.2 Independent baseline vectors

`test/vectors/` holds a committed corpus of **117 cases across 13 files**, generated by the integration test target `tests/export_baseline_vectors.rs` and described by `test/vectors/manifest.json` (schema `zro-baseline-vectors/1`).

The corpus is deliberately deterministic: no wall clock, no RNG, no wallet, no data directory and no network is involved. Keys are published test scalars, block timestamps are literals, ECDSA signatures are RFC 6979 deterministic, and JSON keys are emitted in sorted order.

A **separate, standard-library-only Python implementation** re-derives the expected values from their inputs, so the vectors are not merely a snapshot of Rust output. From the repository root:

```powershell
python test\harness\run_vectors.py --quiet
```

Current result:

```text
phase P0  corpus 117 cases  schema zro-baseline-vectors/1
PASS 112  ANCHOR 5  SKIP 0  FAIL 0
```

`ANCHOR` denotes the five cases that cannot be recomputed from an input — the pinned constants and parameter tables — and are therefore checked rather than derived. Coverage spans hashing primitives, varint and transaction encoding, the script accept/reject matrix, sighash digests, the UTXO state root, header hashing, the pinned anchors, both proof-of-work engines, the difficulty schedule, subsidy and coinbase construction, and address derivation.

### 8.3 End-to-end demonstrations

The two PowerShell scripts in `zerocoin/demos/` are behavioural tests rather than documentation: both start a real daemon, drive it through the CLI, assert on the reported balances and counters, and clean up unconditionally.

- `demos/regtest-maturity.ps1` — zero-premine genesis and the exact 100-block maturity boundary.
- `demos/regtest-pool.ps1` — pool accounting and the supply cap holding across mined blocks.

### 8.4 What these results do and do not prove

They prove that the implementation is internally consistent and that its consensus arithmetic reproduces committed expectations byte for byte.

They do **not** prove that the design is free of security defects, that the economics are sound under adversarial load, or that validators agree under network partition — none of which has been tested at scale. Those gaps are the subject of section 9 and the roadmap.

---

## 9. Security reporting and responsible disclosure

### 9.1 Reporting a vulnerability

The repository has **no `SECURITY.md`** and **no bug-bounty programme**. This section is the project's disclosure policy until a dedicated file is added.

- **Report privately.** Use the repository's **Security** tab to open a private security advisory: <https://github.com/fahim5536/zerocoin/security/advisories/new>. Do not open a public issue for anything that could endanger a running node or a wallet.
- **Include** the affected version or commit, the component, reproduction steps, and the impact you believe it has. A minimal reproduction is far more useful than a description.
- **Allow time to triage.** The project aims to acknowledge a report promptly and to agree a disclosure timeline with the reporter before publication. It cannot currently offer payment, a formal SLA, or a guaranteed response window.
- **Do not test against other people's nodes or wallets**, and do not publish exploit details before a fix or a coordinated disclosure date exists.

### 9.2 Existing hardening measures

These are implemented and visible in the source:

- No custom cryptography; vetted crates for hashing, signatures, key agreement, KDF and AEAD.
- Encrypted keystore with identity-bound associated data and clamped KDF parameters.
- Explicit, enumerated error taxonomies rather than string concatenation.
- Authenticated, encrypted, replay-resistant transport with forward secrecy.
- Bounded decoding at every boundary: transaction size and counts, script limits, message list limits, 4 MiB frames, 8 MiB RPC frames.
- All-or-nothing block application against a cloned UTXO set.
- Compile-time and boot-time freezing of consensus constants, with refusal to boot on drift.
- Domain separation between headers, sighashes, keystores, handshake transcripts and session keys.
- Node identity keys kept separate from wallet keys.

### 9.3 Outstanding security work

Stated plainly, because the absence of these is more informative than the presence of the list above:

- **No independent security audit has been performed**, on the code or on the protocol.
- **No fuzzing campaign** exists for the message decoder, script interpreter or transaction deserialiser.
- **No formal verification** of any consensus rule.
- **No peer-scoring or ban policy**, so persistent misbehaviour is only handled by disconnecting a peer.
- **No production operational history.** The software has not run on a public network under adversarial conditions.
- **The memory-hard proof of work has not been independently analysed.**
- **No CI**, so a regression can only be caught by running the suite locally.

Until those gaps are closed, assume the software may contain exploitable defects, and do not custody meaningful value with it.

---

## 10. Roadmap, including the planned C++ migration

Everything in this section is **planned work**. None of it exists in the repository except where explicitly marked as complete. No dates are promised.

### 10.1 Hardening the reference implementation

Near-term work, in rough dependency order:

1. **Continuous integration.** Build and run the full suite plus the vector harness on Windows, Linux and macOS for every change.
2. **Mempool policy.** A size cap, eviction, a fee floor and replacement rules — currently absent by design, and a prerequisite for anything resembling public operation.
3. **Fork choice and reorganisation.** The chain accepts linear extensions only. A production node needs a best-chain rule, reorg handling and an undo path.
4. **Incremental persistence.** Replace the whole-state JSON rewrite with a database backend behind the existing `Store` trait, leaving the layers above it unchanged.
5. **Enforced time locks** for `lock_time`, or its explicit removal from the serialised format.
6. **Peer management.** Seed infrastructure, address relay, misbehaviour scoring.
7. **Independent review and audit** of consensus, the keystore and the transport, followed by remediation.
8. **Mainnet launch prerequisites.** Mine and pin the mainnet genesis nonce, publish seed infrastructure and operator documentation, and run a public devnet soak first.
9. **Wallet scope**, when justified: HD derivation, multisig, hardware-wallet support, privacy-aware coin selection.
10. **Light clients** and an address index, if the network's usage warrants them.

### 10.2 The planned C++ implementation

`docs/migration/` records a complete, evidence-labelled programme to build an **independent C++ implementation beside the Rust one**. It is a plan, not a product: **no C++ source file exists in this repository**, and no build system currently understands C++.

The programme's governing rules, taken from `docs/migration/03-module-mapping-and-phased-plan.md`:

- **The Rust node remains the reference and the release** until the final gate. Every published binary is the Rust one; the C++ tree is built by developers and CI, never shipped, until proven.
- **No consensus change.** Chain ids, proof of work, difficulty, subsidy, maturity, transaction format, sighash, script, genesis and anchors are frozen exactly as the architecture audit recorded them. If the Rust code looks wrong, the C++ code reproduces the behaviour and the defect is recorded for a separate, explicit consensus-change milestone.
- **No deletion.** No Rust file is removed, moved or rewritten to make a port easier. The implementations coexist.
- **Byte equality where bytes are consensus**; protocol acceptance where they are not.
- **Every phase ends with a gate that can fail** — a command with an exit code, not a judgement call.

| Phase | Scope | Status |
|---|---|---|
| **P0** | Baseline capture: vector corpus and independent verifier | **Complete** — 117 cases, harness green |
| P1 | Kernel primitives: hashes, varint, `uint256`, transaction encoding | Planned |
| P2 | Ledger semantics: script, sighash, signature verification | Planned |
| P3 | Consensus: header, Merkle, difficulty, reward, proof of work, params, genesis, anchors | Planned |
| P4 | State machine: UTXO apply, `connect_block`, storage read, replay | Planned |
| P5 | Node, RPC, wallet, wire protocol, CLI | Planned |
| P6 | Differential soak: both nodes under scripted and randomised load | Planned |
| P7 | Hardening: fuzzing, sanitizers, logging, benchmarks, CI, packaging | Planned |
| P8 | Cutover decision, recorded in writing by the maintainers | Planned |

P0 is the phase this repository can already demonstrate: the corpus is committed, and an independent Python verifier recomputes 112 of the 117 cases and checks the remaining 5 as anchors.

The full documents — architecture audit, Bitcoin Core reference study, module mapping, risk register, test strategy and the P0 record — are in [docs/migration/](docs/migration/README.md).

**Why a second implementation at all?** Because a consensus specification that only one codebase implements is a description of that codebase. An independent implementation, held to byte-exact vectors, is how a protocol becomes something larger than the program that happened to define it — and it is the strongest available check on the reference implementation's own assumptions.

---

## 11. Contributing

There is **no `CONTRIBUTING.md`** in the repository. Until one exists, these are the project's contribution conventions.

### 11.1 Ground rules

- **Consensus changes require explicit approval before implementation.** Open an issue describing the rule, the motivation, the compatibility impact and the migration path. A consensus change is never merged as a side effect of another change.
- **Never change consensus behaviour silently.** Any change to supply, subsidy, maturity, difficulty, proof of work, serialisation, sighash, script, genesis or the pinned anchors must come with updated vectors and a documented rationale.
- **Every behavioural change needs a test.** If the change is consensus-critical, it also needs a vector, so a future second implementation can be held to it.
- **No secrets, wallet files or chain data.** `wallet.json`, `chain.json`, their atomic-write siblings, `.env*` files and build output are excluded by `.gitignore`. `Cargo.lock` **is** intentionally tracked: this is a binary crate, and the lockfile pins dependency versions for reproducible builds without containing any secret.

### 11.2 Conventions

- **Conventional commit messages**: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`. Plans reference a phase, e.g. `feat(kernel): add byte-exact transaction serialisation (P1)`.
- **Small, focused pull requests**, one purpose each.
- **Reference the issue** with `#<issue-number>` in commit messages and pull-request descriptions.
- **Update the documentation** when behaviour changes, including this README, `DEVNET_GUIDE.md` and `MOBILE_BUILD.md` when the change touches them.
- **Match the surrounding code**: module-level documentation explaining *why*, explicit error enums, and no hand-rolled cryptography.

### 11.3 Where help is most useful

- Adversarial review of consensus code and the error taxonomy.
- Fuzzing the transaction decoder, script interpreter and message parser.
- Test infrastructure: CI, a functional test framework, and more vectors.
- Wallet and mobile work, particularly Android packaging and iOS.
- Documentation of operational practice: deployment, monitoring and recovery.

---

## 12. Project maintenance

ZeroCoin is maintained by its contributors. The repository declares no foundation, no company, no paid development team and no token allocation, and consequently offers no service-level agreement, support contract or guaranteed release cadence.

What that means in practice:

- **The source is the project.** Consensus rules, network parameters and the licence live in this repository, not in a policy document that could drift from the code.
- **Changes are reviewed in the open.** Consensus-affecting work needs a written rationale, updated vectors and explicit sign-off; the barrier is deliberately higher than for ordinary fixes.
- **No single party can change the money supply.** Doing so requires a source change that every operator can read, review and refuse.
- **Releases are made when they are ready**, not on a calendar; the crate version is declared in `Cargo.toml`.
- **Continuity is an intention, not a guarantee.** The project is structured — MIT licensed, dependency-light, fully buildable from source, with a documented architecture — so that it can outlive any particular maintainer. It cannot promise that people will keep showing up.

The strongest form of support is independent review and use: run a node, run the vector harness, and report what breaks.

---

## 13. Licence

ZeroCoin is released under the **MIT License**.

```text
Copyright (c) 2026 TAMZID ABDUR RAHMAN
```

See [LICENSE](LICENSE) for the full text. `Cargo.toml` declares the same licence (`license = "MIT"`).

---

## 14. Honest limitations

This README has tried to describe the software as it is. For clarity, the limits it does **not** claim to have overcome:

- **ZeroCoin is pre-release.** It has not been audited, has no public mainnet, and has no production operational history.
- **No security guarantee is offered.** Not by this document, not by the licence, and not by the test suite.
- **Bitcoin-inspired engineering is not Bitcoin-equivalent assurance.** The project aims at Bitcoin Core's discipline; it shares none of Bitcoin Core's years of adversarial review.
- **Decentralisation is a goal, not a current property.** With no seed infrastructure and no public network, there is nothing yet to decentralise.
- **Permanence cannot be promised.** The code is structured to be maintainable and rebuildable, which is the only honest foundation for longevity.
- **There are no tokens for sale, no exchange listings, and no financial returns.** Nothing here should be read as an investment claim.
- **Numbers in this document are reproducible, not authoritative.** If a count here disagrees with the source or the harness, the source and the harness are right — please open an issue.

If you run ZeroCoin today, run it on `regtest` or `devnet`, with keys you are willing to lose, and read the source first.
