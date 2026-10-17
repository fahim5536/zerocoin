# 02 — Bitcoin Core as an educational reference

Reference repository: `https://github.com/bitcoin/bitcoin.git`, inspected through
the GitHub contents API during this audit (not vendored, not cloned into the
project, not built).

This document answers one question: **what about Bitcoin Core's *shape* is worth
copying into ZeroCoin, and what must never be assumed from it?**

Labels as in `README.md`. A fourth label is used here:

- `[VERIFIED — upstream listing]` — an observation about the *file and directory
  layout* of the Bitcoin Core repository, read from the API listing. It says
  nothing about the behaviour of those files, which was not audited line by line.

---

## 1. What was observed

`src/` currently lists 191 entries: 27 directories and 164 files
`[VERIFIED — upstream listing]`.

Directories:

```
bench  common  compat  consensus  crc32c  crypto  index  init  interfaces  ipc
kernel  leveldb  logging  minisketch  node  policy  primitives  qt  rpc  script
secp256k1  support  test  univalue  util  wallet  zmq
```

Top-level files that matter for this study `[VERIFIED — upstream listing]`:
`CMakeLists.txt`, `validation.cpp` / `validation.h`, `net.cpp`,
`net_processing.cpp`, `txmempool.cpp` / `.h`, `txdb.cpp`, `coins.cpp`,
`init.cpp`, `chainparams.cpp`, `arith_uint256.h`, `base58.cpp`,
`bitcoin-chainstate.cpp`, `bip324.cpp`.

`test/functional/` currently lists 295 entries, 288 of which are `.py`, plus the
directories `data/`, `mocks/`, `test_framework/` and the runners
`test_runner.py`, `create_cache.py`, `example_test.py`
`[VERIFIED — upstream listing]`.

The roles attributed to these directories below are inferred from their names and
from the layout as a whole, not from reading their contents. They are labelled
`[UNVERIFIED]` where the inference is doing real work.

---

## 2. The seven ideas worth adopting

These are architectural patterns, not code. Each is followed by why it matters
*specifically* for ZeroCoin.

### 2.1 A consensus-only kernel library

Bitcoin Core exposes a `kernel/` directory whose name and placement — alongside
`bitcoin-chainstate.cpp` at the top level — indicate a build target that contains
chain validation without networking, RPC, wallet, or UI
`[VERIFIED — upstream listing; intent UNVERIFIED]`.

**Why it matters here.** ZeroCoin's `chain.rs` and `utxo.rs` are already free of
I/O, but they are compiled into the same crate as the GUI. A C++ project can make
the boundary a *linker* boundary: one static library that pulls in nothing but
hashing, secp256k1, and the ledger, and that the functional tests can drive
directly. If the GUI or the P2P layer can reach into consensus internals, drift
becomes possible; if it cannot link, it cannot drift.

**Proposal:** `libzerocoin_kernel` — consensus and ledger only, no sockets, no
threads, no JSON, no filesystem.

### 2.2 Separate validation, script, and policy

The upstream layout separates `validation.cpp` (block and transaction
acceptance), `script/` (the interpreter), `policy/` (relay and mempool rules), and
`consensus/` (parameters and consensus constants)
`[VERIFIED — upstream listing; split semantics UNVERIFIED]`.

**Why it matters here.** ZeroCoin currently mixes three different kinds of rule in
two files: consensus (`utxo.rs`), relay policy (`mempool.rs`), and wallet policy
(`wallet.rs` coin selection). The distinction matters because only the first kind
may fork the chain. A port that puts "reject dust" and "reject double spend" in the
same function cannot later change one without auditing the other.

**Proposal:** three directories — `consensus/` (may fork the chain),
`policy/` (relay only), `node/` (everything else) — with a CI check that
`consensus/` never includes a `policy/` header.

### 2.3 A mempool object with explicit limits

Upstream has `txmempool.cpp` as a standalone unit with its own header and its own
policy inputs `[VERIFIED — upstream listing]`.

**Why it matters here.** ZeroCoin's mempool has no capacity, no eviction, and no
fee floor (finding F6). It works, but it has no place to *put* a limit when one is
added. A C++ `Mempool` class with an explicit `MempoolLimits` value object makes
the eventual policy decision a configuration change rather than a refactor.

**Proposal:** `policy/mempool.{h,cpp}` with `MempoolLimits { max_bytes,
max_count, min_fee_rate, expiry }`, all set to "unlimited" in the parity phase so
behaviour matches Rust exactly.

### 2.4 A narrow node-facing interface

Upstream has `interfaces/` and `ipc/` alongside the node implementation
`[VERIFIED — upstream listing; contents UNVERIFIED]`.

**Why it matters here.** ZeroCoin already has the right instinct: `session.rs` is
an in-process facade that dispatches through the same handlers as the RPC, and
Android uses it instead of spawning a daemon. That is exactly the "GUI must not
link the node internals" discipline.

**Proposal:** an abstract `Node` interface in `node/interface.h`; the GUI, RPC, and
`session` equivalent consume only that. No `#include` of `validation.h` from a
front-end target.

### 2.5 Functional tests as a first-class Python suite

Upstream ships close to 300 Python functional tests plus a shared
`test_framework/` and a `test_runner.py` `[VERIFIED — upstream listing]`.

**Why it matters here.** The Rust tree has **no** integration-test crate and **no**
CI (F12); its heaviest tests live inside `node.rs` and bind fixed loopback ports.
The Bitcoin Core model — one Python file per scenario, a framework that owns node
lifecycle, temporary datadirs and port allocation — is precisely what requirement
5 asks for ("Python for automated tests and tooling"), and it is the only
practical way to run the differential tests in `05`.

**Proposal:** `test/functional/` with `test_framework/` providing
`ZroNode` (wraps `zerocoind` or the C++ `zerocoind`), `ZroCLI`, and a port
allocator. Both implementations must be drivable by the same harness.

### 2.6 CMake with real targets

Upstream builds with CMake (`CMakeLists.txt` in `src/` and at the repository root)
`[VERIFIED — upstream listing]`.

**Why it matters here.** Cargo gives ZeroCoin one crate and three binaries; there
is no notion of "this target may not link that library". CMake targets can encode
the layering of 2.1–2.4 as `target_link_libraries` edges, and `ctest` can run both
the C++ unit tests and the Python functional suite from one entry point.

**Proposal:** top-level `CMakeLists.txt` with targets `zerocoin_kernel`,
`zerocoin_consensus`, `zerocoin_node`, `zerocoin_rpc`, `zerocoin_wallet`,
`zerocoin_cli`, `zerocoind`, plus `ctest` hooks for `test/functional`.

### 2.7 Logging and benchmarks as subsystems, not afterthoughts

Upstream has `logging/` and `bench/` `[VERIFIED — upstream listing]`.

**Why it matters here.** ZeroCoin has no benchmark harness at all, and its
diagnostics are ad-hoc. A port that cannot reproduce the Rust node's *performance
profile* cannot answer the only question that justifies the port (does the
scratchpad PoW actually get faster?), and a port with no category-based logging is
undebuggable in a two-node differential test.

**Proposal:** `util/log.{h,cpp}` with categories (`net`, `mempool`, `validation`,
`rpc`, `wallet`) and a `bench/` target that measures scratchpad throughput at the
devnet and mainnet profiles.

---

## 3. What must not be assumed from Bitcoin Core

The task explicitly forbids assuming Bitcoin's consensus rules are suitable.
The table lists every place where a "reasonable default" imported from Bitcoin
would be wrong.

| Area | Bitcoin Core assumption | ZeroCoin reality | Consequence of importing it |
|---|---|---|---|
| Block interval | 10 minutes | **60 seconds** | Difficulty and emission calendar are wrong |
| Retarget | 2,016-block window, ×4 clamp | **1,440-block window, ×4 clamp** | Different difficulty at every height |
| Emission | 210,000 blocks per halving at 10 min ≈ 4 years | 210,000 blocks per halving at 60 s ≈ **146 days** | Same 21 M cap, **4× faster** in wall-clock time. Never quote Bitcoin's emission calendar |
| PoW | SHA-256d | **scratchpad, memory-hard** (2 MiB / 4,096 rounds on mainnet) | Entirely different hash; no shared test vectors |
| Target encoding | compact `0x1d00ffff` style | compact, but limits are `0x1e00ffff` (mainnet) and `0x207fffff` (devnet/regtest) | A hard-coded Bitcoin limit rejects every ZeroCoin block |
| Header | 80 bytes, version/prev/merkle/time/bits/nonce | **108-byte preimage** with chain id, height, engine id, `u64` height and timestamp | No header-level compatibility at all |
| Merkle | Bitcoin's CVE-2012-2459 duplicate rule | duplicate-last, and a **single-leaf tree is the leaf itself** | Subtle root mismatches on 1-transaction blocks |
| Transaction | version/inputs/outputs/locktime, witness optional | legacy shape, **no witness**, minimal varints enforced, 1 MB / 10k / 10k limits | Segwit parsing would mis-read every transaction |
| Signature hash | BIP-143 and legacy variants | **one** variant, `SIGHASH_ALL`, with the chain id inside the preimage | A Bitcoin-style signature never validates |
| Script | full interpreter, P2SH, timelocks, segwit | **10 opcodes**, P2PKH only | Any script-level assumption is invalid |
| Addresses | Base58Check + bech32/bech32m | Base58Check P2PKH only, prefix `0x00` / `0x6f` | Bech32 addresses cannot be paid |
| Chain selection | most-work chain, reorgs, orphan pool | **linear extension only**, no reorg path (F1) | A port with best-chain selection forks away from Rust on the first competing block |
| Mempool | size cap, eviction, fee floor, RBF | **none of these** (F6) | Different relay set, different blocks |
| Wire | magic + binary messages, BIP324 v2 transport | **AES-GCM frames with JSON inside** | Zero interoperability |
| Peers | address manager, banman, feeler connections | seeds, backoff, `Addr` gossip, peer isolation only on immature-coinbase spend | Different peer behaviour under attack |
| Deployment | BIP9/softfork activation | none | No activation machinery exists to reuse |
| Genesis | Bitcoin's specific block | **zero-premine genesis with no outputs** (F13) | Any "helpful" genesis change forks the chain |

The general rule: **a Bitcoin Core default is evidence of what Bitcoin chose, not
evidence of what ZeroCoin does.** ZeroCoin's answers are in
`zerocoin/src/params.rs`, `consensus/`, and `ledger/`, and they win.

---

## 4. Copying policy

Bitcoin Core is MIT-licensed, and so is ZeroCoin, so code reuse would be legally
possible with attribution. This programme nevertheless adopts a stricter rule:

> **No Bitcoin Core source is copied into ZeroCoin.** The reference is consulted
> for structure, naming, and test design. Every line of C++ in ZeroCoin is written
> against ZeroCoin's own Rust specification and its golden vectors.

Reasons, in order of importance:

1. **Consensus contamination.** Bitcoin's validation code encodes assumptions
   (subsidy, maturity, script flags, lock-time, witness) that are *wrong* here. A
   copied function brings its assumptions with it, and they are invisible in
   review because the code "looks familiar".
2. **Audit surface.** A reviewer of a ZeroCoin consensus change must be able to
   hold the whole function in their head. Code that arrived from elsewhere is code
   nobody on this project has reasoned about.
3. **Test independence.** The differential tests compare Rust against C++. If the
   C++ side were derived from Bitcoin, a shared Bitcoin-shaped bug could hide
   behind a Bitcoin-shaped test.
4. **Licence hygiene.** Attribution obligations are easy to state and easy to
   forget; not copying makes the question moot.

What *is* copied, deliberately: **vocabulary**. Names like `kernel`, `policy`,
`validation`, `mempool`, `coins`, `chainparams` are descriptive and widely used;
adopting them makes the layout legible to anyone who knows Bitcoin Core.

---

## 5. Concept mapping

Reading guide for document `03`. "Borrow" means *the structural idea*, never the
implementation.

| ZeroCoin (Rust) | Bitcoin Core analogue | Borrow |
|---|---|---|
| `crypto/hash.rs`, `crypto/secp256k1.rs` | `crypto/`, `secp256k1/` | kept as dependencies/vendored subtrees, not reimplemented |
| `ledger/transaction.rs` | `primitives/transaction.*` | split serialisation from validation |
| `ledger/script.rs` | `script/` | interpreter/limits split; **not** opcode set |
| `ledger/sighash.rs` | `script/interpreter` sighash code | keep ZeroCoin's single variant |
| `ledger/utxo.rs` | `coins.cpp`, `kernel/coinstats` | a `CCoinsView`-style cache is a reasonable *future* shape, not a parity requirement |
| `consensus/block.rs`, `chain.rs::connect_block` | `validation.cpp`, `consensus/` | separate structural from contextual checks |
| `consensus/difficulty.rs`, `consensus/uint256.rs` | `arith_uint256`, `pow.cpp` | dedicated 256-bit type with explicit overflow semantics |
| `consensus/pow.rs` | `pow.cpp` | an engine interface; **algorithm is ZeroCoin's own** |
| `consensus/reward.rs` | (no single analogue — subsidy lives in validation) | ZeroCoin's separation is better; keep it |
| `consensus/immutability.rs` | `kernel/checks`, chainparams assumptions | keep; it is ZeroCoin's strongest safety property |
| `params.rs` | `chainparams.cpp` | one constexpr table per network |
| `genesis.rs` | `chainparams.cpp` genesis construction | keep deterministic construction |
| `mempool.rs` | `txmempool.cpp`, `policy/` | limits object, fee-rate ordering |
| `storage.rs` | `node/blockstorage`, `txdb.cpp`, `leveldb/` | separate block store from UTXO store (a change, not parity) |
| `node.rs` | `net.cpp` + `net_processing.cpp` + `rpc/` | **split** messaging from processing from RPC |
| `session.rs` | `interfaces/`, `ipc/` | narrow node interface |
| `wallet.rs`, `crypto/keystore.rs` | `wallet/` | keep separate from kernel |
| `address.rs` | `base58.cpp`, `key_io` | keep |
| `datadir.rs` | `util/` filesystem helpers | keep |
| `gui.rs`, `ui/wallet.slint` | `qt/` | out of scope for the first C++ milestone |
| `demos/*.ps1` | `test/functional/*.py` | **replace** with Python |
| (absent) | `logging/`, `bench/`, `index/` | adopt logging and bench; defer indexes |

Two deliberate divergences from Bitcoin Core's shape, recorded so they are not
"fixed" later:

- **`consensus/reward.rs` exists as its own module.** Bitcoin keeps subsidy inside
  validation. ZeroCoin's split is easier to test and should survive the port.
- **`consensus/immutability.rs` exists at all.** Bitcoin relies on chainparams and
  review; ZeroCoin executes its invariants at compile time and at boot. The port
  must keep that, and the C++ version can be stronger (`static_assert` plus a
  runtime anchor check that aborts).

---

## 6. Risks this study creates, and how they are contained

| Risk | Containment |
|---|---|
| "Bitcoin does it this way" arguments during review | The findings register in `01` §13 is the authority; a proposal that cites Bitcoin must also cite a ZeroCoin test that would still pass |
| Structural copying drifting into code copying | `04` risk R3; review checklist in `05` §7 |
| Feature envy: adding reorgs, RBF, segwit "while we are here" | Change freeze in `README.md` §5; each of those is a separate consensus-change proposal |
| Adopting upstream build complexity wholesale | `03` specifies a minimal CMake surface; no `leveldb`, `zmq`, `qt`, or `minisketch` in the first milestone |

---

## 7. Summary

Bitcoin Core's contribution to this migration is **shape**: a consensus-only
kernel, a hard split between consensus / policy / node, a real mempool object, a
narrow interface for front-ends, a Python functional-test framework, and CMake
targets that encode the layering.

Its contribution to ZeroCoin's *rules* is **zero**. Every consensus constant,
every byte layout, and every policy in the port comes from the Rust tree and the
golden vectors captured from it.
