# 05 — Test strategy and acceptance gates

This document defines how the C++ implementation earns the right to be trusted.
It assumes `03`'s phases and gates; it does not renumber them.

Status: **proposal**. The harness, the corpus, and the CI described here do not
exist yet. What exists today is the Rust suite (235 tests) and one PowerShell demo.

---

## 1. What "equivalent" means

There are four different claims, and they need different evidence. Conflating them
is how ports ship with confidence they have not earned.

| Claim | Meaning | Evidence |
|---|---|---|
| **Byte equivalence** | The same inputs produce the same bytes | Golden vectors, exact comparison |
| **Validity equivalence** | The same block is accepted or rejected | Replay, differential fuzz |
| **Protocol equivalence** | The two nodes can be each other's peer | Live interop, mixed-network soak |
| **Operational equivalence** | The same data directory, wallet, and RPC surface | Cross-open, RPC parity tests |

A node can pass the first two and fail the third. The gates in §7 require all four
in order.

---

## 2. Layer 0 — The golden vector corpus

Everything else is built on this, so it is the first thing P0 produces.

### 2.1 Properties a vector must have

1. **Provenance.** It names the exact command that produced it, including the commit.
2. **Determinism.** Regenerating it twice produces identical bytes.
3. **Independence.** Small cases have a second derivation that does not use the
   Rust code (hand computation, published test vector, or a second tool).
4. **Intent label.** It says whether it captures a *rule* or a *known oddity*
   (for example F2's flat state root, F3's reversed display hex). Oddities must not
   be silently "corrected" later.

### 2.2 Proposed layout `[PROPOSED]`

```
test/vectors/
├── manifest.json                 # commit, toolchain, generation command, counts
├── hash/
│   ├── sha256.json               # NIST vectors + zero-length + 1 MB
│   ├── sha256d.json
│   └── hash160.json
├── encoding/
│   ├── varint.json               # 0, 1, 252, 253, 65535, 65536, 2^32-1
│   ├── transaction.json          # txid + full hex for each fixture
│   └── header_preimage.json      # 107-byte preimage per network
├── pow/
│   ├── trivial.json              # preimage+nonce -> hash
│   └── scratchpad_devnet.json    # small profile, many nonces
│   └── scratchpad_mainnet.json   # 2 MiB / 4096, a few nonces
├── difficulty/
│   ├── required_work.json
│   ├── compact.json              # compact<->target at boundaries
│   └── sequence.json             # synthetic 3000-block retarget history
├── reward/
│   ├── subsidy.json              # heights around every halving
│   ├── split_reward.json         # remainder cases
│   └── coinbase_scripts.json     # height encodings incl. varint boundaries
├── ledger/
│   ├── script.json               # accept/reject matrix with error class
│   ├── sighash.json
│   └── state_root.json           # incl. the two-entry layout probe
├── chain/
│   ├── genesis.json              # txid, merkle, per-network hash
│   └── regtest_101.blocks.json   # the demo chain, block by block
├── crypto/
│   ├── addresses.json            # hash160 -> Base58Check per network
│   └── signatures.json           # DER + low-S + cross-verify cases
└── network/
    ├── frame.json                # key+seq+plaintext -> exact frame bytes
    └── handshake.json            # fixed keys -> transcript hash and session keys
```

### 2.3 Vector format `[PROPOSED]`

```json
{
  "id": "reward.subsidy.210000",
  "source": "cargo test --release --lib reward::tests::halving -- --nocapture",
  "commit": "5248b10d69c12f4d0af332afb5e67c43605c220c",
  "intent": "rule",
  "input": { "height": 210000 },
  "expected": { "subsidy_fah": 2500000000 },
  "independent_check": "INITIAL_SUBSIDY >> 1"
}
```

`intent` is `rule` for behaviour the port must preserve and `oddity` for behaviour
that is preserved *for now* and tracked by a finding id (`"finding": "F3"`).

### 2.4 Corpus coverage requirement

The corpus is complete when **every variant of every consensus error enum** has at
least one vector that produces it. The audit counted, for example, 13 `BlockError`
variants and 8 `UtxoError` variants; `ScriptError`, transaction and sighash errors
must be enumerated from the source the same way. A new error variant without a
vector fails CI.

That rule replaces a coverage percentage, which measures the wrong thing here: a
line executed is not a rule tested.

---

## 3. Layer 1 — C++ unit tests mirroring the Rust tests

The Rust suite has 235 tests in 28 modules (`01` §12.1). Each becomes a C++ test in
the matching target:

| Rust module | C++ test target | Notes |
|---|---|---|
| `consensus/reward.rs` (22) | `test/unit/reward_test.cpp` | subsidy table, split remainder, coinbase script parsing |
| `consensus/pow.rs` (16) | `test/unit/pow_test.cpp` | both engines, share target, profile independence |
| `network/frame.rs` (16) | `test/unit/frame_test.cpp` | seq nonce, AAD, tamper, replay, reorder |
| `consensus/difficulty.rs` (9) | `test/unit/difficulty_test.cpp` | clamp, divide-first, regtest pinning |
| `wallet.rs` (9) | `test/unit/wallet_test.cpp` | AAD binding, selection, insufficient funds |
| `pool.rs` (9) | `test/unit/pool_test.cpp` | weights, share validation |
| `consensus/uint256.rs` (8) | `test/unit/uint256_test.cpp` | boundaries, overflow, compact |
| `crypto/keystore.rs` (8) | `test/unit/keystore_test.cpp` | argon2 params, wrong password |
| `ledger/utxo.rs` (8) | `test/unit/utxo_test.cpp` | three phases, maturity, state root |
| `network/message.rs` (8) | `test/unit/message_test.cpp` | 13 variants, limits |
| `address.rs` (7) | `test/unit/address_test.cpp` | Base58Check vectors |
| `genesis.rs` (7) | `test/unit/genesis_test.cpp` | deterministic solve, zero outputs |
| `mempool.rs` (7) | `test/unit/mempool_test.cpp` | admission, conflicts, ordering |
| `ledger/transaction.rs` (7) | `test/unit/transaction_test.cpp` | round-trip, minimal varint |
| `consensus/immutability.rs` (6) | `test/unit/anchors_test.cpp` | static asserts compile; boot refusal |
| `params.rs` (6) | `test/unit/params_test.cpp` | three networks, `by_name` |
| `crypto/secp256k1.rs` (6) | `test/unit/keys_test.cpp` | sign/verify, DER, compressed keys |
| `ledger/script.rs` (6) | `test/unit/script_test.cpp` | opcode matrix, four limits |
| `consensus/block.rs` (5) | `test/unit/block_test.cpp` | validation order, Merkle cases |
| `ledger/sighash.rs` (5) | `test/unit/sighash_test.cpp` | chain binding, single type |
| `crypto/hash.rs` (4) | `test/unit/hash_test.cpp` | published vectors |
| `network/handshake.rs` (4) | `test/unit/handshake_test.cpp` | transcript, session keys |
| `storage.rs` (4) | `test/unit/storage_test.cpp` | atomic write, round-trip |
| `datadir.rs` (3) | `test/unit/datadir_test.cpp` | platform paths, `ZRO_HOME` |
| `chain.rs` (11) | `test/unit/validation_test.cpp` | connect, failure atomicity |
| `node.rs` (10) | moved to functional | process-level, not unit |
| `session.rs` (8) | moved to functional | facade over the node |
| `gui.rs` (16) | not ported | GUI stays in Rust |

Twenty-five of the 28 modules map one-to-one; the three that do not are exactly the
three that are better tested at process level. This is a feature, not a gap: it
means the C++ unit suite is smaller than 235 and the functional suite is larger.

---

## 4. Layer 2 — Differential and randomized testing

### 4.1 Differential fuzz (mode D)

A generator produces three families of input:

1. **Valid by construction** — sign real transactions against a real UTXO set.
2. **Near-miss** — mutate one field (a sequence number, an output value, a script
   opcode, a timestamp) from a valid case.
3. **Adversarial** — truncated encodings, non-minimal varints, over-limit counts,
   duplicate inputs, negative fees, wrong chain ids.

Both implementations classify each input: accept, or reject with an error class.
The test fails when the classifications differ. Because the Rust error enums are
the taxonomy, this also forces the C++ side to have the same *kinds* of failure, not
just the same boolean.

### 4.2 Property tests

Properties worth stating independently of any implementation:

- `parse(serialize(tx)) == tx` for every generated transaction, and serialisation is
  canonical (minimal varints).
- `txid` changes when any byte of the transaction changes.
- `state_root` is independent of insertion order (it is key-ordered).
- `sum(inputs) == sum(outputs) + fee` for every accepted transaction.
- `subsidy_issued` is monotone and never exceeds `MAX_SUPPLY`.
- A block at height *H* whose coinbase is spent at *H + 100* is accepted, and at
  *H + 99* is rejected with `ImmatureCoinbase`.

### 4.3 Replay

The captured `regtest_101` chain is replayed block by block. After **each** block,
compare: tip hash, `state_root`, `subsidy_issued`, UTXO count. Any divergence is
reported with the height, which is the single most useful debugging datum in the
whole programme.

The corpus ships the block bytes, not a mining script. `01` §12.2 shows why: the
demo generates a fresh payout key each run, so re-mining produces different hashes
even when every balance is identical.

---

## 5. Layer 3 — Wire interoperability

1. Start a Rust node and a C++ node on one regtest network.
2. Assert that both report one peer.
3. Mine on each in turn; assert that the other connects the block within a bounded
   time and that both report the same tip hash.
4. Submit a transaction to one; assert it appears in the other's mempool and in the
   next block.
5. Kill the C++ node mid-sync and restart it; assert it converges.

A frame-level byte comparison is **not** part of this layer: the payload is JSON
(F8), and equality of ciphertext is impossible by design (fresh nonces). The test is
"the peer accepts it", not "the bytes match".

---

## 6. Layer 4 — Functional scenarios (Python)

The harness owns node lifecycle, temporary data directories, and port allocation,
so tests never collide. Each scenario runs against a binary selected by an
environment variable, which is how the same suite covers Rust-only (P0) and both
implementations (P5+).

| Scenario | Asserts |
|---|---|
| `zero_premine_genesis` | Height 0 has `subsidy_issued = 0` and `utxo_count = 0`; the genesis hash equals the pinned anchor |
| `maturity_boundary` | Nothing spendable at tip 99; exactly two coinbases (100 ZRO) spendable at 101 — the demo, ported |
| `coinbase_height_commitment` | A coinbase whose scriptSig commits to the wrong height is rejected |
| `coinbase_overclaim` | A coinbase above subsidy+fees is rejected; exactly at the bound is accepted |
| `supply_cap` | Accumulated subsidy never exceeds `MAX_SUPPLY` |
| `double_spend_rejected` | Same outpoint twice in one block is rejected |
| `immature_coinbase_isolated` | Rejection class is `ImmatureCoinbase` **and** the serving peer is disconnected (F17) |
| `wrong_chain_signature` | A mainnet-signed transaction is rejected on regtest (sighash chain binding) |
| `script_limits` | Each of the four limits rejects at the boundary and accepts one below |
| `difficulty_retarget` | Synthetic timestamps produce the expected bits sequence |
| `regtest_no_retarget` | Bits stay pinned across 3,000 blocks |
| `mempool_ordering` | `take_for_block` fills by fee rate and honours conflicts |
| `wallet_roundtrip` | Create, fund, send, confirm; balance and history agree |
| `wallet_cross_open` | A Rust-written wallet opens in C++ and vice versa |
| `restart_persistence` | Stop, restart, same tip, same state root, same UTXO count |
| `p2p_sync` | Two nodes converge after mining on one |
| `p2p_non_tip_block` | A block that does not extend the tip triggers header sync, not a fork (F1) |
| `rpc_surface_parity` | All 12 methods return the same fields and units for the same chain |
| `pool_share_accounting` | Shares validate against the share target and never enter a block |

Rust-only tests that exist today (`node.rs`, `session.rs`, `gui.rs`) are the seed for
this suite; the rest are new.

---

## 7. Gates, mapped

| Gate | Passes when |
|---|---|
| **G0** | Corpus regenerates byte-identically twice; Rust suite still 235/235; every vector has provenance |
| **G1** | All hash, varint, transaction, and `uint256` vectors pass; hex types are compile-time distinct |
| **G2** | Script accept/reject matrix passes with matching error classes; sighash digests match; signatures cross-verify both ways |
| **G3** | All seven pinned values match (six anchors plus the state-root probe); header/PoW grid matches on three networks; difficulty sequence matches; subsidy table matches; scratchpad benchmark within ±20 % |
| **G4** | 101-block replay matches at every height; every rejection vector matches; peer isolation reproduced |
| **G5** | Handshake and 1-hour connection; bidirectional block/tx propagation; 12 RPC methods equivalent; wallet cross-open; restart persistence |
| **G6** | 14 days, 100,000 regtest blocks, 10,000 transactions, zero divergence |
| **G7** | 24-hour fuzz with no crash; ASan/UBSan clean; CI green on the full matrix; logging categories in use |
| **G8** | Written decision record; Rust untouched in the same change |

No gate may be waived by a code review comment. A waived gate needs a decision
record and a new date.

---

## 8. CI design `[PROPOSED]`

There is no CI today (F12). This is the minimum that makes the gates meaningful.

```yaml
# .github/workflows/ci.yml  (sketch)
jobs:
  rust-baseline:      # always
    runs-on: ubuntu-latest
    steps: [checkout, cargo test --all-targets, cargo test --doc]
  vectors:            # always, from P0
    runs-on: ubuntu-latest
    steps: [capture_vectors.sh, git diff --exit-code test/vectors]
  cpp-build:          # from P1
    strategy: { matrix: { os: [ubuntu, windows, macos], build: [debug, release] } }
    steps: [cmake -B build, cmake --build build, ctest]
  sanitizers:         # from P2, Linux only
    steps: [cmake -DZRO_SANITIZE=address,undefined, ctest]
  functional-rust:    # from P0
    steps: [build rust, test/functional/test_runner.py --node rust]
  parity:             # from P4
    steps: [build both, scripts/parity.sh --gate G4]
  fuzz:               # from P7, nightly
    steps: [run corpus + 1h libFuzzer]
```

Two rules keep this honest:

- **The vector job fails on any diff.** If Rust behaviour changes, the corpus must
  change in the same commit, deliberately.
- **The functional job never binds a fixed port.** A port allocator or a hard
  failure keeps the suite parallel-safe, which is what the Rust in-module node tests
  cannot do today.

---

## 9. What each layer does *not* prove

| Layer | Blind spot |
|---|---|
| Vectors | Only the inputs you thought of; a rule with no vector is untested |
| Unit parity | Both implementations can agree on a unit and disagree on composition |
| Differential fuzz | The generator's bias; adversarial inputs outside its grammar |
| Replay | Deterministic history only; no concurrency, no peers |
| Wire interop | Does not prove behaviour under attack or under partition |
| Functional | Scenario-shaped; misses interaction effects between scenarios |
| Soak | Long, not necessarily broad; a quiet bug can hide for 14 days |
| Fuzzing | Finds crashes and some divergences, never proves absence |

The strategy is sound because the layers fail in *different* directions. A claim of
equivalence is only made when all of them pass — and it is always a claim about the
tested surface, never a proof.

---

## 10. Review checklist

For every C++ pull request in this programme:

1. Which Rust file does this implement? Is the provenance header present?
2. Which vector proves it? If none exists, why not, and where was it added?
3. Does any constant appear that does not come from `params.rs` or the audit?
4. Could this change a hash? If yes, is there a byte-level test?
5. Does it add a rule that Rust does not have — a reorg, an eviction, a lock-time
   check, a fee floor? If yes, it is a consensus change and is out of scope (R3).
6. Is every failure mode mapped to a Rust error variant?
7. Does it compile with warnings-as-errors on all three compilers?
8. Does the kernel target still have zero dependencies on `node/` or `policy/`?
