# ZeroCoin (ZRO) — Consensus Rules Specification

Status: **P1 audit deliverable — describes the rules the Rust implementation enforces today.**
Audited commit: `260d44c4da07cbeb33efccda7e4fbe3e139091ca` (branch `main`).
Crate root for all `src/...` references below: `zerocoin/`.
Vector corpus: `test/vectors/` (repository root), 13 files / 117 cases, phase P0.

> This document is a **behavioral specification derived from source code**, not a security
> audit, not a claim of Bitcoin equivalence, and not a statement that the rules below are
> final. Where the implementation is silent, permissive, or contains a hazard, that is
> recorded in §14 (Findings) and §15 (Unsupported / planned / unverified) instead of being
> described as a rule. Every normative rule below carries a source reference; nothing in
> this document was inferred from Bitcoin Core behavior.

Conventions used in this document:

- **MUST / REJECT** means the Rust code returns an error or aborts the operation; there is
  no alternative path.
- **OBSERVED** marks behavior that is real but that the code neither documents nor enforces
  deliberately (usually a permission the code does not check).
- "Consensus" means: it can change whether two honest nodes accept the same block. Mempool
  and relay policy are explicitly separated (§13) because they do not change acceptance.
- Line numbers refer to the audited commit and are exact for that commit.

---

## 1. Networks and parameters

`ChainParams` is the only place a network's identity and constants are defined
(`src/params.rs:87`). `Chain::open` refuses to start if the loaded chain's genesis hash does
not equal `genesis_hash(params, engine)` (`src/chain.rs:137`, refusal path at
`src/chain.rs:161`).

| Parameter | mainnet | devnet | regtest | Source |
|---|---|---|---|---|
| `chain_id` (header + sighash) | `0x5A524F01` | `0x5A524F02` | `0x5A524F00` | `src/params.rs:30,32,34` |
| PoW engine | ScratchPad 2 MiB / 4096 rounds (`engine_id = 1`) | ScratchPad 64 KiB / 1024 rounds (`engine_id = 1`) | Trivial SHA-256d (`engine_id = 0`) | `src/params.rs:112,137,161`; ids at `src/consensus/pow.rs:57,58` |
| Difficulty: spacing / retarget / max factor / pow limit | 60 s / 1440 / 4 / `0x1e00ffff` | 60 s / 1440 / 4 / `0x207fffff` | 60 s / 1440 / 4 / `0x207fffff` | `src/params.rs:116,141,162`; defaults `src/consensus/difficulty.rs:47` |
| `genesis_bits` | `0x1e00ffff` | `0x207fffff` | `0x207fffff` | `src/params.rs:122,147,168` |
| `allow_pow_retarget` | `true` | `true` | **`false`** | `src/params.rs:123,148,169` |
| Base58 pubkey prefix | `0x00` | `0x6f` | `0x6f` | `src/params.rs:124,149,170` |
| P2P / RPC ports | 8233 / 8232 | 18233 / 18232 | 18444 / 18443 | `src/params.rs:125,126,150,151,171,172` |

Fixed protocol constants (not per-network):

| Constant | Value | Source |
|---|---|---|
| Genesis timestamp | `1_735_689_600` (2025-01-01T00:00:00Z) | `src/params.rs:39` |
| Median-time-past window | 11 blocks | `src/chain.rs:58` |
| Max future timestamp | 7200 s | `src/consensus/block.rs:33` |
| Max transactions per block | 2000 | `src/consensus/block.rs:31` |
| Initial subsidy | 50 ZRO = `5_000_000_000` Fah | `src/consensus/reward.rs:31` |
| Halving interval | 210 000 blocks | `src/consensus/reward.rs:33` |
| Max halvings | 64 | `src/consensus/reward.rs:35` |
| Supply cap | 21 000 000 ZRO = `2_100_000_000_000_000` Fah | `src/consensus/reward.rs:37` |
| Coinbase maturity | 100 blocks | `src/consensus/reward.rs:39` |
| Block version written | `BLOCK_VERSION` (1) | `src/consensus/block.rs:30` |
| Fah per ZRO | `100_000_000` | `src/lib.rs:42` |
| Network magic (transport) | `b"ZRO\0"` | `src/lib.rs:44` |

Rule **N-1** — A block's `chain` field MUST equal the network's `chain_id`
(`src/consensus/block.rs:147`). A block's `engine_id` MUST equal the running engine's id
(`src/consensus/block.rs:162`).

Rule **N-2** — `Chain::open` MUST reject a persisted chain whose tip history does not start
at the pinned genesis (`ChainError::GenesisMismatch`, `src/chain.rs:161`). `Chain::open` also
runs `verify_boot_invariants()` first and refuses to start if any compile-time/boot anchor
drifted (`src/chain.rs:142`, anchors in `src/consensus/immutability.rs:396`).

---

## 2. Canonical encodings (what the C++ port must byte-match)

ZeroCoin has **five** consensus-critical byte encodings. The P2P wire format is JSON and is
**not** one of them (`src/network/message.rs:16`); two nodes may re-serialize a message
differently without changing consensus, but every encoding in this section must match
exactly.

### 2.1 Varint

`write_varint` (`src/ledger/transaction.rs:195`) and the reader used by
`Transaction::deserialize` implement Bitcoin's CompactSize: `<0xfd` single byte; `0xfd` +
`u16` LE; `0xfe` + `u32` LE; `0xff` + `u64` LE. Decoding MUST reject a value encoded with
more bytes than necessary (`TxDecodeError::NonMinimalVarInt`,
`src/ledger/transaction.rs:91`). P0 cases: `encoding.varint` (9 cases).

### 2.2 Transaction and txid

`Transaction::serialize` (`src/ledger/transaction.rs:109`):

```
version      : i32 little-endian (4 bytes)
input count  : varint
  per input  : prev txid (32 raw bytes, internal order) | vout u32 LE | varint script_len | script_sig | sequence u32 LE
output count : varint
  per output : value u64 LE | varint script_len | script_pubkey
lock_time    : u32 little-endian (4 bytes)
```

`Transaction::txid` is `sha256d(serialize())` over this canonical re-serialization
(`src/ledger/transaction.rs:183`), **not** over the bytes that arrived on the wire. P0
cases: `encoding.transaction` (5 cases).

The id is also the Merkle leaf: `Block::compute_merkle_root` puts `tx.txid()` into the tree
with no further transformation (§2.4), so a port that hashes the wire bytes, the canonical
bytes a second time, or the id's display form produces a root that matches nothing. Since
P3.3B the C++ kernel composes the two rules in `zk::merkle_root_from_transactions`, and
`test/p33-vectors/chain/merkle_root_from_txs.json` publishes each case's per-transaction
`serialized_hex`, `serialized_len` and `txid` alongside the root, so the replay checks the
id-to-leaf mapping and not only the digest at the top of the tree.


Rule **T-1** — Decoding MUST reject: truncated input (`Truncated`), non-minimal varints,
more than `MAX_TX_INPUTS = 10_000` inputs, more than `MAX_TX_OUTPUTS = 10_000` outputs, and
any single script longer than `MAX_TX_BYTES = 1_000_000`
(`src/ledger/transaction.rs:20,22,23,131`).

OBSERVED — `Transaction::deserialize` **ignores bytes trailing a complete transaction**
(`src/ledger/transaction.rs:131`): the cursor is not required to be exhausted. Consequence:
two different byte strings decode to the same transaction, and the txid covers only the
canonical re-serialization. This is documented, tested
(`trailing_bytes_after_a_transaction_are_ignored`), and not changed in P1 — see finding F-5.

### 2.3 Block-header preimage

`BlockHeader::preimage` (`src/consensus/block.rs:84`), exactly 107 bytes:

```
"ZRO/header/v1\0"  (14 bytes, HEADER_TAG at block.rs:25)
version            u32 LE
chain              u32 LE
height             u64 LE
previous_hash      32 raw bytes
merkle_root        32 raw bytes
timestamp          u64 LE
difficulty_bits    u32 LE
engine_id          u8
```

Total: 14 + 4 + 4 + 8 + 32 + 32 + 8 + 4 + 1 = **107 bytes**. Corroborated by
`test/vectors/chain/header.json` (`preimage_len: 107`, 214 hex characters, tag
prefix `5a524f2f6865616465722f763100`) and by the frozen assertion
`assert_eq!(preimage.len(), 107)` in `zerocoin/tests/consensus_rules.rs`. The
engine appends the `u64` nonce, so **115 bytes** are hashed. P2.11 verified this
definition against all of those artifacts; `INTERFACE_CONTRACTS.md` §11
previously said 108 bytes and was corrected there.

Rule **H-1** — The header preimage MUST exclude the nonce; each PoW engine appends the
`u64` nonce itself in its own byte order (`src/consensus/block.rs:84`,
`src/consensus/pow.rs:79,200`). P0 cases: `chain.header` (8 cases), including the pinned
regtest genesis preimage in `chain.anchors.regtest_genesis`.

### 2.4 Merkle root

`merkle_root` (`src/consensus/block.rs:237`–`257`) hashes leaves with `sha256d` in raw internal
byte order:

- empty list → `sha256d("ZRO/merkle:empty\0")` (tag at `src/consensus/block.rs:28`);
- a single leaf is returned **unchanged** (not hashed again);
- odd trailing element is duplicated (`level[i]` used as its own right sibling), at **every**
  level, not only the first;
- each pair is `sha256d(left || right)` with left/right in raw internal order.

Cases: the five historical `chain.merkle.*` cases (`test/vectors/chain/header.json`) verify
this rule inside the P0 harness; the 20-case `chain.merkle_root.*` group in
`test/p32-vectors/chain/merkle_root.json` is the set the C++ kernel is replayed against, via
`kernel_p32_conformance`. Neither set changed in P3.2B, and the P0 harness did not gain or lose
a case.

`merkle_root` itself imposes **no** limit on the number of leaves; the 2000-transaction bound
is B-9, enforced in `validate_structure` (`src/consensus/block.rs:194`). A port that folds a
count limit into the root function would be inventing a rule.

`Block::compute_merkle_root` (`src/consensus/block.rs:120`) builds the leaves as
`tx.txid()` for each transaction in order. It is the same `merkle_root` above with no
additional rule: no limit on the transaction count, no sorting, no deduplication, and no
re-encoding of an id into a different byte order. Since P3.3B the C++ kernel carries this
composition as `zk::merkle_root_from_transactions`, and the 22-case
`chain.merkle_root_from_txs.*` group in
`test/p33-vectors/chain/merkle_root_from_txs.json` is the set it is replayed against, via
`kernel_p33_conformance`. Every expected root in that group is the return value of a direct
call to this Rust function. Two of its properties are easy to lose in a port and are therefore
named in case ids: `.order_abc` against `.order_cba` (the root is positional, so a reordered
list is a different block) and `.two_identical_transactions` /
`.three_copies_of_one_transaction` (a repeated transaction is a repeated leaf, never a
collapsed one). `.empty` fixes the zero-transaction behaviour of the public function, which is
the empty-tag branch, not an error. This is the root **computation** only: comparing a block's
committed root against a header remains B-1/B-14 and is not implemented in C++.


Rule **B-1** — A block's committed `merkle_root` MUST equal
`Block::compute_merkle_root(transactions)` (`src/consensus/block.rs:217`–`219`). P0 cases:
`chain.anchors.genesis_coinbase` and `chain.anchors.pinned_constants`
(`genesis_merkle_root` is the txid of the single genesis coinbase, i.e. the single-leaf rule
observed in the corpus).

### 2.5 UTXO state root

`UtxoSet::state_root` (`src/ledger/utxo.rs:272`) is a **single `sha256d` over the flat
concatenation** of one record per UTXO, in `BTreeMap<Outpoint, UtxoEntry>` iteration order
(lexicographic by `txid` bytes, then `vout`):

```
txid (32) | vout u32 LE | value u64 LE | script_len u64 LE | script | height u64 LE | is_coinbase u8 (0 or 1)
```

The empty set hashes to `sha256d("")`, pinned as `EMPTY_STATE_ROOT`
(`src/consensus/immutability.rs:356`); the layout is pinned by
`STATE_ROOT_LAYOUT_PROBE` (`src/consensus/immutability.rs:362`) and enforced at boot by
`verify_state_root_layout` (`src/consensus/immutability.rs:461`). P0 cases:
`ledger.state_root` (13 cases).

OBSERVED — The doc comment calls this a "Merkle root", but it is not a tree: there is no
per-entry hashing and no inclusion proof. See finding F-4. It is nonetheless a consensus
commitment and MUST be reproduced byte-for-byte.

### 2.6 Sighash v1

`signature_hash` (`src/ledger/sighash.rs:45`) with `SIGHASH_TAG = b"ZRO/sighash/v1\0"`
(`src/ledger/sighash.rs:20`–`24`) and `ChainId`:

```
tag | chain_id u32 LE | version i32 LE | varint input count
    | per input: txid (32) | vout u32 LE | varint script_len | script_sig
      (the input being signed carries `script_code`; all others carry an empty script)
      | sequence u32 LE
    | varint output count | per output: value u64 LE | varint script_len | script_pubkey
    | lock_time u32 LE | sighash_type u32 LE         → sha256d
```

Rule **S-1** — Only `SIGHASH_ALL = 0x01` exists (`src/ledger/sighash.rs:20`). Any other
sighash byte makes `TxSigChecker::check_signature` return `false`
(`src/ledger/sighash.rs:118`), which surfaces as `UtxoError::ScriptInvalid`. An out-of-range
input index returns `None` (`src/ledger/sighash.rs:45`) and therefore `false`. P0 cases:
`ledger.sighash` (8 cases).

---

## 3. Block structure and validation order

`Block` = `header` + `transactions` (`src/consensus/block.rs:112`). `connect_block`
(`src/chain.rs:274`) is the only path that mutates chain state, and it performs these steps
**in this order**:

1. `expected_bits = self.required_bits(block.header.height)` — **before** validation
   (`src/chain.rs:277`).
2. `block.validate_structure(...)` (`src/chain.rs:280`).
3. `difficulty::validate_bits(block.header.difficulty_bits, &params.difficulty)`
   (`src/chain.rs:289`).
4. Replay `transactions[1..]` on a **clone** of the UTXO set, summing fees with
   `saturating_add` (`src/chain.rs:292`–`297`).
5. `reward::validate_coinbase(coinbase, height, fees, subsidy_issued)`
   (`src/chain.rs:301`).
6. `candidate.apply_coinbase(coinbase, height)`, then swap in the candidate
   (`src/chain.rs:304`–`305`).
7. `subsidy_issued += claimed - fees` (`src/chain.rs:310`–`311`).
8. Push block + hash, persist (`src/chain.rs:313`–`316`).

Rule **B-2** — On any error in steps 1–5, **no state changes**: the UTXO candidate is
dropped, the block vector is untouched, and nothing is persisted.

`validate_structure` (`src/consensus/block.rs:135`) evaluates these conditions in exactly
this order; the first failure is the error returned:

| # | Condition | Error | Source |
|---|---|---|---|
| B-3 | `header.chain != expected_chain` | `WrongChain` | `block.rs:147` |
| B-4 | `header.height != expected_height` (= `chain.next_height()`) | `BadHeight` | `block.rs:153` |
| B-5 | `header.previous_hash != tip_hash` | `BadPreviousHash` | `block.rs:159` |
| B-6 | `header.engine_id != engine.id()` | `WrongEngine` | `block.rs:162` |
| B-7 | `header.difficulty_bits != expected_bits` (schedule) | `BadDifficulty` | `block.rs:168` |
| B-8 | `transactions.is_empty()` | `NoTransactions` | `block.rs:174` |
| B-9 | `transactions.len() > 2000` | `TooManyTransactions(len)` | `block.rs:177` |
| B-10 | `!transactions[0].is_coinbase()` | `FirstNotCoinbase` | `block.rs:181` |
| B-11 | any of `transactions[1..]` is a coinbase | `DuplicateCoinbase` | `block.rs:184` |
| B-12 | `header.timestamp <= median_time_past` | `TimestampTooOld` | `block.rs:187` |
| B-13 | `header.timestamp > now + 7200` | `TimestampTooFarFuture` | `block.rs:193` |
| B-14 | `header.merkle_root != compute_merkle_root(txs)` | `RootMismatch` | `block.rs:218` |
| B-15 | header hash does not meet its own compact target | `InsufficientProofOfWork` | `block.rs:205` |

Line-reference provenance: the Merkle rows of §2.4 and this table (B-1, B-14) were rechecked
on 2026-10-24 against `zerocoin/src/consensus/block.rs` and corrected to the current
statements. The **other** rows of this table were not rechecked in that pass and their
citations are not guaranteed current; the visible pattern is a single uniform shift down the
`validate_structure` body, consistent with `validate_header_identity` having been extracted
into its own function above it. Correcting those rows is a separate documentation change and
is deliberately **not** part of the P3.2B milestone, which touched no validation order and no
rule text.

Boundary notes, observed and tested:

- B-9 is `> 2000`: exactly 2000 transactions is structurally allowed; 2001 is
  `TooManyTransactions`. A 2000-entry list whose entries are all coinbases fails B-11
  instead, because `[1..]` still contains a coinbase.
- B-12 is `<=`: a timestamp **equal** to the median is rejected. The minimum admissible
  timestamp is `median_time_past + 1` (`src/chain.rs:377` uses exactly that when mining).
- B-13 is `>`: `timestamp == now + 7200` is accepted, `now + 7201` is rejected. The
  addition saturates at `u64::MAX` (`saturating_add`).
- B-14 runs before B-15, so a tampered transaction or root reports `RootMismatch` even if
  the nonce would also fail.
- **No rule validates `header.version`.** `BLOCK_VERSION` is written when headers are built
  (`src/chain.rs:380`, `src/genesis.rs:70`) and is never read by validation. See F-2.
- **No block byte-size or weight rule exists.** The only block-level limits are 2000
  transactions (B-9), 10 000 inputs / outputs and 1 000 000-byte scripts per transaction
  (T-1), and the 4 MiB transport frame (`src/network/frame.rs`, `MAX_PLAINTEXT_BYTES`). See
  F-3.

OBSERVED — `validate_structure` is a public method; calling it directly does not run
`difficulty::validate_bits`, the UTXO replay, or the coinbase reward check. Consensus
acceptance is only `Chain::connect_block`.

---

## 4. Timestamps and median-time-past

`median_time_past` (`src/chain.rs:241`) takes the last `min(height+1, 11)` block timestamps,
sorts them ascending with `sort_unstable`, and returns the element at index `len / 2`.

- With an even count (e.g. 10 blocks) this is the **upper** median, not the average of the
  two middle values.
- At height 0 the window is the genesis timestamp alone.
- Timestamps are not required to be monotonically increasing; only B-12 and B-13 constrain
  them, so a block may carry a timestamp lower than its immediate parent (but above the
  median).
- MTP is recomputed from the local validated chain, never from a peer-supplied header chain.

Rule **TS-1** — `timestamp` MUST be strictly greater than `median_time_past` of the previous
(up to) 11 blocks (B-12) and at most `node_clock + 7200` (B-13). The node clock is
`now_timestamp()` from the system clock (`src/chain.rs:112`), passed into `connect_block`.

Determinism consequence: block acceptance for a *new* block is a function of the validating
node's wall clock. Two nodes whose clocks differ by more than 7200 s relative to a block's
timestamp can disagree on B-13. This is inherent to the rule and is not a bug; it must be
preserved in the port (see §12 and `CPP_PORT_REQUIREMENTS.md`).

---

## 5. Difficulty

### 5.1 Compact target encoding

`compact_to_target` / `compact_from_target` (`src/consensus/difficulty.rs:65,70`) use the
Bitcoin-style 32-bit compact form: top byte = exponent `e`, low 24 bits = mantissa `m`;
target = `m << 8*(e-3)` for `e > 3`, `m >> 8*(3-e)` for `e <= 3`. `compact_from_target`
(`src/consensus/uint256.rs:77`) rounds the mantissa **down**, so the re-encoded target never
exceeds the true target.

### 5.2 Target comparison

`hash_meets_target` (`src/consensus/difficulty.rs:81`) parses the 32 hash bytes as a
**big-endian** integer (`Uint256::from_be_bytes(hash.0)`) and accepts when
`hash <= target` (inclusive). This is **not** Bitcoin's little-endian display order; the
comparison is over the raw byte order produced by the PoW engine. P0 cases:
`difficulty.hash_meets_target`.

### 5.3 Bits validity

`validate_bits` (`src/consensus/difficulty.rs:134`): a zero target →
`DifficultyError::ZeroTarget`; a target greater than `params.pow_limit()` →
`TargetAbovePowLimit`; otherwise `Ok`. It runs **after** B-7 and before any UTXO work
(`src/chain.rs:289`). P0 cases: `difficulty.validate_bits` (`0x2100ffff` rejected,
`0x1e00ffff` and `0x1d00ffff` accepted, `0` rejected as `ZeroTarget`).

### 5.4 Difficulty schedule

`Chain::required_bits(height)` (`src/chain.rs:255`):

- `height == 0` or `!params.allow_pow_retarget` → `params.genesis_bits` for every height
  (regtest is permanently at `0x207fffff`; the existing unit test
  `difficulty_is_pinned_on_regtest` asserts this for heights 0, 1, 1440, 1441, 100000).
- Otherwise let `prev = blocks[height-1]`. If `height % 1440 != 0` → `prev.difficulty_bits`.
- At `height % 1440 == 0`, let `first = blocks[height-1440]` and
  `actual = prev.timestamp.saturating_sub(first.timestamp)`, then
  `next_difficulty(prev.difficulty_bits, actual, &params.difficulty)`.

`next_difficulty` (`src/consensus/difficulty.rs:102`), exactly:

```
expected     = target_window_seconds().max(1)            // 60 * 1440 = 86400
factor       = max_adjustment_factor.max(2)              // 4
min_timespan = expected / factor                         // 21600
max_timespan = expected * factor                         // 345600
actual'      = clamp(actual, min_timespan.max(1), max_timespan)
new_target   = if prev_target.leading_zeros() >= 20 {
                   prev_target * actual' / expected      // multiply first
               } else {
                   prev_target / expected * actual'      // divide first
               }
capped       = if new_target > pow_limit || new_target == 0 { pow_limit } else { new_target }
result       = compact_from_target(capped)               // mantissa rounded down
```

Rule **D-1** — The retarget clamps to a 4× range in both directions: a window shorter than
21 600 s is treated as 21 600 s (harder), a window longer than 345 600 s as 345 600 s
(easier). `actual == 0` therefore means "25 % of expected", not "maximum difficulty".
P0 cases: `difficulty.retarget` reports `max_adjustment_factor = 4`,
`pow_limit_bits = 503382015` (`0x1e00ffff`), `retarget_interval = 1440`,
`target_spacing_seconds = 60`, `target_window_seconds = 86400`.

Rule **D-2** — The arithmetic is **magnitude-dependent** (`leading_zeros() >= 20`): small
targets are multiplied before dividing, larger targets are divided before multiplying.
These two orders give different integer results. A port MUST reproduce the branch, the
threshold, and the operation order exactly. See F-6.

Rule **D-3** — A computed target is clamped **up** to the pow limit: difficulty can never
go below the network's `pow_limit_bits`.

Boundary notes:

- `next_difficulty` never divides by zero: `expected` is forced to at least 1. `div_u64` and
  `divmod` panic on a zero divisor (`src/consensus/uint256.rs:138,152`), so this guard is
  load-bearing.
- `required_work` (`src/consensus/difficulty.rs:87`, `(~target)/(target+1)+1`) is **not on
  the validation path**. It panics for a target of `Uint256::MAX` (`target+1` wraps to
  zero) but no consensus path calls it. P0 cases exist for it; the port can treat it as a
  reporting helper only.
- `DifficultyError::UnexpectedBits` is declared but never constructed (F-10).

---

## 6. Proof of work

`PowEngine` implementations are selected per network by `EngineSpec` (`src/params.rs:49`);
`engine.id()` is committed in the header, the engine parameters are not.

### 6.1 Trivial engine (`engine_id = 0`)

`TrivialEngine::hash` (`src/consensus/pow.rs:79`): `sha256d(preimage || nonce_u64_LE)`.
Used by regtest only; its pow limit is `0x207fffff`.

### 6.2 Scratchpad engine (`engine_id = 1`)

`ScratchPadEngine::hash` (`src/consensus/pow.rs:200`), byte-exact description:

1. `cell_count = max(memory_bytes / 32, 1)`.
2. `state = sha256(preimage || nonce_u64_LE)`.
3. Fill: for every cell in order, `state = sha256(state)`, `cell = state`.
4. For `rounds` iterations: read `index_word = u64 LE` from `state[0..8]`; `index =
   index_word & (cell_count-1)` when `cell_count` is a power of two, otherwise
   `index_word % cell_count`; `state = sha256(state || scratchpad[index])`;
   `scratchpad[index] = state`.
5. `digest = sha256(state || scratchpad[0] || ... || scratchpad[cell_count-1])`.

Rule **P-1** — A block's PoW hash MUST be `engine.hash(header.preimage(), header.nonce)` and
MUST satisfy `hash_meets_target(hash, compact_to_target(header.difficulty_bits))` (B-15).

Rule **P-2** — Mining (`src/consensus/pow.rs:268`) searches nonce `start, start+1, ...` and
stops at the first accepted hash. Mining therefore has a deterministic result for a given
`(preimage, target, start)` — `Chain::mine_block_with_coinbase` always starts at 0
(`src/chain.rs:391`).

Determinism hazards (see also §12):

- `memory_bytes` and `rounds` are **not** covered by `engine_id`. Two nodes with the same
  `engine_id` but different scratchpad parameters compute different hashes and reject each
  other's blocks. Only the per-network `EngineSpec` pins the parameters (`src/params.rs:112`–`115`,
  `137`–`140`, `161`). This is F-8.
- `cells()` uses `usize` (platform width), and `hash` allocates the whole scratchpad with
  `vec!`; a 32-bit host and a 64-bit host agree only while `memory_bytes` fits in 32 bits,
  and an allocation failure aborts the process rather than returning an error. The
  power-of-two mask vs. modulo branch yields different indices for any non-power-of-two
  `cell_count`, which `capped_to` (`src/consensus/pow.rs:139`) can produce locally.
- The mainnet engine hashes 2 MiB per attempt; the mobile profile 256 MiB per attempt. Both
  are far too slow for unit tests, which is why regtest is used for chain tests.

### 6.3 Engine ids

`ENGINE_ID_TRIVIAL = 0`, `ENGINE_ID_SCRATCHPAD = 1` (`src/consensus/pow.rs:57,58`). P0
cases: `pow.engines` (11 cases) pin engine ids and hashing results.

---

## 7. Rewards, subsidy, and the coinbase

### 7.1 Subsidy schedule

`block_subsidy(height)` (`src/consensus/reward.rs:47`):

- `height == 0` → `0` (zero-premine genesis);
- `halvings = height / 210_000`; `halvings >= 64` → `0`;
- otherwise `INITIAL_SUBSIDY >> halvings`.

`block_reward(height, fees)` (`src/consensus/reward.rs:60`) = `subsidy + fees` with
`checked_add` (`RewardError::RewardOverflow` on overflow). `total_supply_ceiling`
(`src/consensus/reward.rs:73`) sums the schedule and is used only for reporting.

Rule **R-1** — At height 0 the subsidy is zero, so the only admissible coinbase claim is
zero. This is enforced before any fee arithmetic: `height == 0 && claimed != 0` →
`GenesisPremine` (`src/consensus/reward.rs:321`). P0 cases: `reward.subsidy` (6 cases),
`reward.constants` (`reward.constants` anchors the six reward constants).

### 7.2 Coinbase transaction shape

`coinbase_transaction(height, payout, reward)` (`src/consensus/reward.rs:128`):

- `version = 1`, `lock_time = 0`;
- exactly one input: `previous_output = Outpoint::null()` (`txid = ZERO`, `vout =
  u32::MAX`, `src/ledger/transaction.rs:34`), `sequence = u32::MAX`;
- `script_sig = push_data(script_num(height)) || push_data(b"ZeroCoin")`;
- exactly one P2PKH output paying `reward` (`p2pkh_script_pubkey(payout.key_hash())`).

`script_num` (`src/consensus/reward.rs:88`) is a minimal little-endian integer with a `0x00`
pad byte when the top byte's high bit is set; height 0 encodes as the empty vector, pushed
as `OP_0` (single byte `0x00`). `pool_coinbase_transaction`
(`src/consensus/reward.rs:210`) has the same shape but the tag `b"ZeroCoin/pool"` and one
output per payout.

`is_coinbase` (`src/ledger/transaction.rs:103`) is purely structural: **exactly one input
and that input spends the null outpoint**. It does not look at outputs or scripts.

### 7.3 Height commitment

`coinbase_height` (`src/consensus/reward.rs:244`) requires a coinbase, a non-empty
`script_sig`, reads `len = script_sig[0]`, rejects `len > 8` or a truncated push
(`script.len() < 1 + len`), and decodes `script_sig[1..1+len]` with `parse_script_num`
(`src/consensus/reward.rs:106`): empty → `0`; more than 8 bytes → `None`; last byte with
the high bit set (negative) → `None`; otherwise little-endian accumulation.

OBSERVED — Only the **first push** is inspected. The rest of the scriptSig is unconstrained:
the `"ZeroCoin"` tag is not required, and arbitrary trailing bytes are accepted. A miner may
therefore put any data after the height commitment.

Rule **R-2** — The committed height MUST equal the block height
(`RewardError::BadCoinbaseHeight`, `src/consensus/reward.rs:306`), and a missing/unparseable
commitment is `MissingHeightCommitment` (`src/consensus/reward.rs:305`).

### 7.4 Coinbase acceptance order

`validate_coinbase(tx, height, fees, subsidy_issued)` (`src/consensus/reward.rs:295`)
evaluates in this exact order:

| # | Condition | Error | Source |
|---|---|---|---|
| R-3 | not a coinbase | `NotCoinbase` | `reward.rs:301` |
| R-4 | no parseable height commitment | `MissingHeightCommitment` | `reward.rs:305` |
| R-5 | committed height ≠ block height | `BadCoinbaseHeight` | `reward.rs:306` |
| R-6 | sum of outputs overflows `u64` | `RewardOverflow` | `reward.rs:313`–`317` |
| R-7 | `height == 0` and `claimed != 0` | `GenesisPremine` | `reward.rs:321` |
| R-8 | `claimed > subsidy + fees` | `TooMuchReward` | `reward.rs:326` |
| R-9 | `claimed < fees` | `BelowFees` | `reward.rs:334` |
| R-10 | `subsidy_issued + subsidy > MAX_SUPPLY` | `SupplyCapExceeded` | `reward.rs:343` |

Returns `claimed` (the total output value) on success.

Rule **R-11** — **Under-claiming the subsidy is allowed** (`claimed` may be anywhere in
`[fees, subsidy + fees]`); the unclaimed value is never minted. **Under-claiming fees is
not**: the coinbase must carry every fee in the block (`BelowFees`). This differs from
Bitcoin, where a coinbase may claim less than the fees available. It is ZeroCoin behavior
and must be preserved.

Rule **R-12** — The supply cap is checked against the **subsidy** for the height, not against
`claimed`. Under-claiming therefore does not create cap headroom for later blocks.

Rule **R-13** — `Chain::connect_block` credits `subsidy_issued += claimed - fees`
(`src/chain.rs:310`), i.e. only the newly minted value, with `saturating_sub`.

### 7.5 Pool split (reward arithmetic, on the mining path)

`split_reward(reward, weights)` (`src/consensus/reward.rs:171`) computes each share as
`reward * weight / total_weight` in `u128`, rounds **down**, credits the entire remainder to
the **first** contributor, drops zero weights, and finally drops zero-value outputs. The
result sums to exactly `reward` unless all weights are zero or `reward == 0`, in which case
it is empty. `pool_coinbase_transaction` asserts (debug builds only) that payouts do not
exceed the reward (`src/consensus/reward.rs:211`); release builds rely on the subsequent
`validate_coinbase`.

---

## 8. Transaction validity and UTXO transitions

### 8.1 UTXO entry

`UtxoEntry { output: TxOut, height: u64, is_coinbase: bool }` (`src/ledger/utxo.rs:38`).

Rule **U-1** — Maturity (`src/ledger/utxo.rs:56,70`):

```
spendable_at()        = height + 100 (saturating) if is_coinbase else height
is_mature(spend_height) = spendable_at() <= spend_height
```

A coinbase created in block `h` is spendable in block `h + 100` and later. With the first
non-genesis block at height 1, that coin matures for the block at height 101 (existing test
`coinbase_is_immature_then_matures_at_one_hundred`; new test
`maturity_boundary_is_exactly_one_hundred_blocks`). Non-coinbase outputs are spendable in
the block after they confirm (`spendable_at == height`), so a same-block spend is impossible
only because the output does not exist yet.

### 8.2 `apply_transaction`

`UtxoSet::apply_transaction(tx, chain_id, height, spend_height)`
(`src/ledger/utxo.rs:191`) validates against the current set and only then mutates it:

1. `tx.inputs.is_empty()` → `UtxoError::NoInputs`.
2. A `BTreeSet` of input outpoints: a repeated outpoint within the transaction →
   `DoubleSpend`.
3. For each input, in order, **read-only**:
   - unknown outpoint → `MissingInput`;
   - coinbase entry not mature at `spend_height` → `ImmatureCoinbase { outpoint, matures,
     spent }`;
   - `script::verify(script_sig, script_pubkey, &TxSigChecker::new(tx, i, script_code,
     chain_id))` false → `ScriptInvalid { index, source }` (the `source` string is the
     `ScriptError`'s display text).
4. Sum input values with `checked_add` → `InputOverflow`.
5. Sum output values with `checked_add` → `OutputOverflow`.
6. `output_total > input_total` → `NegativeFee { inputs, outputs }`.
7. Commit: remove every spent outpoint, insert every output at `(tx.txid(), vout)` with
   `height` and `is_coinbase = false`.

Returns `input_total - output_total` (the fee). Because validation is complete before the
first mutation, a failure leaves the set untouched.

Rule **U-2** — The transaction's `lock_time` is **not** validated, `version` is not
validated, and `sequence` is not interpreted. Only `is_coinbase`, inputs, outputs, and the
scripts matter.

Rule **U-3** — Duplicate-input detection is per transaction; a transaction that spends an
outpoint already spent by an earlier transaction in the same block fails at step 3 with
`MissingInput` (the earlier transaction removed it).

### 8.3 Coinbase application

`apply_coinbase(tx, height)` (`src/ledger/utxo.rs:261`) inserts every output as
`is_coinbase = true` at `height`, with no signature or maturity checks, and returns the
txid. It is called only after `validate_coinbase` succeeds (`src/chain.rs:304`).

### 8.4 Script execution

`script::verify` (`src/ledger/script.rs:69`) runs `script_sig` then `script_pubkey` on one
shared stack and requires the top of the final stack to be true (`is_true`, negative-zero
handling included). Limits (`src/ledger/script.rs:30`–`33`):

| Limit | Value |
|---|---|
| `MAX_STACK_ITEMS` | 1000 |
| `MAX_SCRIPT_ELEMENT` | 520 bytes |
| `MAX_OPS_PER_SCRIPT` | 201 (counted only for opcodes `> OP_PUSHDATA2`) |
| `MAX_SCRIPT_SIZE` | 10 000 bytes |

Supported opcodes only: `OP_0 (0x00)`, `OP_PUSHDATA1 (0x4c)`, `OP_PUSHDATA2 (0x4d)`,
`OP_VERIFY (0x69)`, `OP_DROP (0x75)`, `OP_DUP (0x76)`, `OP_EQUAL (0x87)`,
`OP_EQUALVERIFY (0x88)`, `OP_HASH160 (0xa9)`, `OP_CHECKSIG (0xac)`
(`src/ledger/script.rs:18`–`27`). Any other byte → `UnsupportedOpcode`. `push_data`
(`src/ledger/script.rs:245`) always emits the minimal push encoding. P2PKH templates:
`p2pkh_script_pubkey` (`src/ledger/script.rs:226`, 25 bytes: `DUP HASH160 <20> EQUALVERIFY
CHECKSIG`) and `p2pkh_script_sig` (`src/ledger/script.rs:237`). P0 cases: `ledger.script`
(15 cases).

Rule **U-4** — A script that pushes a false value and a script that fails the final
`is_true` both surface as `ScriptInvalid`, not as a distinct error.

### 8.4.1 Public-key encoding — rule **P-1**

A public key accepted by `OP_CHECKSIG` is exactly 33 bytes, tagged `0x02` or `0x03`, and
names a point on secp256k1:

| Input | Verdict |
|---|---|
| 33 bytes, tag `0x02`, `x` on the curve | **accept** |
| 33 bytes, tag `0x03`, `x` on the curve | **accept** |
| 33 bytes, tag `0x05` (SEC1 *compact*) | reject |
| 33 bytes, any other tag (`0x00`, `0x01`, `0x04`, `0x06`, `0x07`, …) | reject |
| any other length (0, 32, 64, 65, …) | reject |
| `x >= p`, or `x` with no curve point | reject |

The gate is `PublicKey::from_sec1` (`src/crypto/secp256k1.rs:117`), the single funnel for
script, storage and wire keys. It tests the length, then the tag, then the curve, and
returns `InvalidPublicKey` at the first failure. A rejected key pushes nothing, so
`OP_CHECKSIG` leaves an empty value and the final `is_true` of §8.4 yields `EvalFalse`,
reported as `UtxoError::ScriptInvalid`.

Rule **P-1** — A public key is its *encoding*, not merely the curve point it names.
`0x05 || x` denotes the same point as `0x02 || x` but is **not** an accepted spelling:
`key_hash` is `hash160` over the 33 bytes, so admitting both would give one key two P2PKH
commitments. No code path may re-encode, normalise or alias a non-canonical spelling into
a canonical one.

The decision record — including why `0x05` is excluded on the plain meaning of
*compressed* in B1, and why the contract does not rest on libsecp256k1 — is
[`PUBLIC_KEY_ENCODING_CONTRACT.md`](PUBLIC_KEY_ENCODING_CONTRACT.md). Regression coverage:
`p2_7_pubkey_encoding` (`zerocoin/tests/p2_7_pubkey_encoding.rs`) and the `V4` group of
the P2.6 differential fixture.

### 8.5 `Chain::validate_transaction`

`Chain::validate_transaction` (`src/chain.rs:406`) clones the UTXO set and applies the
transaction at `(next_height, next_height)`, returning the fee. It is the mempool admission
check and **is not** part of block acceptance; `connect_block` repeats the work against its
own clone.

---

## 9. Genesis and the zero-premine invariant

`genesis_coinbase()` (`src/genesis.rs:45`):

- one input spending the null outpoint;
- `script_sig = push_data(&[]) || push_data(GENESIS_MESSAGE)`, where
  `GENESIS_MESSAGE = b"No premine, no owner: ZeroCoin is issued only by proof of work"`
  (`src/genesis.rs:39`) — the first push is an **empty** script number, i.e. height 0;
- **zero outputs** (`outputs: Vec::new()`).

`genesis_block(params, engine)` (`src/genesis.rs:87`) builds the pinned header
(`previous_hash = ZERO`, `timestamp = GENESIS_TIMESTAMP`, `difficulty_bits =
params.genesis_bits`, `engine_id = params.engine.id()`, `version = BLOCK_VERSION`,
`merkle_root = coinbase.txid()`) and mines the first valid nonce starting at 0.

Rule **G-1** — `Chain::open` connects this genesis as block 0 through the same
`connect_block` path, so `validate_coinbase`'s `GenesisPremine` rule applies. The genesis
mints nothing and the UTXO set starts empty (`utxo().is_empty()`; `EMPTY_STATE_ROOT`).

Pinned anchors (`src/consensus/immutability.rs:330`–`362`, mirrored in
`test/vectors/chain/anchors.json` and enforced by `verify_boot_invariants`):

| Anchor | Value |
|---|---|
| `GENESIS_COINBASE_TXID` | `e94d9c36f8d96364c3404380d0d5dd132a4b0eea7c33af144ef51c163d5a4189` |
| `GENESIS_MERKLE_ROOT` | same as the coinbase txid (single-leaf rule) |
| `GENESIS_HASH_REGTEST` | `3f0adf404440fda91de2068b3ca6696cc97f0d9ed8b23b400a0715fe1f0e9148` |
| `GENESIS_HASH_DEVNET` | `7f2ee49364dc841f818660ece86b0bcee831f8c910acdf58118ef92505314b76` |
| `GENESIS_PREIMAGE_DIGEST_MAINNET` | `a3f7f6e355c3a490a3da0d9a2c482af67820073129f6f93f24b116002eaba263` |
| `EMPTY_STATE_ROOT` | `5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456` |
| `STATE_ROOT_LAYOUT_PROBE` | `ca218434f88cad2a18451a9869388de94e92bba798f3b56c682deb69ca3439e2` |

P0 cases: `chain.anchors` (6 cases), including the full regtest genesis preimage and hash.

---

## 10. Chain state, reorganisation, and persistence

- There is **no reorganisation logic**: `connect_block` accepts only a block whose
  `previous_hash` equals the current tip and whose height equals `next_height` (B-4, B-5).
  A competing fork is not evaluated; conflicting blocks are simply invalid. The chain is
  append-only.
- `headers_above` (`src/chain.rs:469`) serves at most `limit` stored headers; `locator`
  (`src/chain.rs:449`) builds a Bitcoin-style exponential-back-off locator ending at genesis.
  Both read only locally validated blocks.
- Persistence is `Store::save(chain_data)` after every connected block (`src/chain.rs:316`).
  `ChainData` serializes the full block list plus `subsidy_issued`; the UTXO set is rebuilt
  by replaying blocks on open. Storage format is **not** consensus; a C++ node may use any
  local store as long as acceptance outcomes and the pinned anchors match.
- `subsidy_issued` is persisted state and is an input to R-10, so a corrupted local store
  can change acceptance. It is not committed to any anchor.

---

## 11. Peer block acceptance (relay behavior that gates consensus)

`node.rs` does not call `connect_block` for arbitrary blocks (`src/node.rs:628`–`708`):

- A block whose hash is already held is ignored.
- A block whose `height != next_height` or whose `previous_hash != tip` never reaches
  `connect_block`; the node instead requests headers (throttled by
  `sync_requested_height`). In particular, an attacker-chosen future height cannot reach
  `required_bits` through the P2P path.
- A block that passes those checks is passed to `connect_block(block, now_timestamp())`.
- `Err(ChainError::Utxo(e))` with `immutability::isolates_peer(e)` (true only for
  `ImmatureCoinbase`, `src/consensus/immutability.rs:513`) is escalated as
  `FrozenInvariantViolation` and the peer connection is dropped. Every other error is
  `Rejected`, and the peer is **not** banned or disconnected.
- A successful connect prunes confirmed transactions from the mempool, relays inventory,
  and resumes sync.

This is relay policy, not consensus: a block rejected here is still rejected by
`connect_block`, but a block that triggers a dropped connection is not thereby invalid.

---

## 12. Determinism register

Consensus-critical calculations reviewed for platform, clock, randomness, floating-point,
and ordering dependence.

| ID | Calculation | Determinism property | Evidence |
|---|---|---|---|
| DET-1 | SHA-256 / SHA-256d / RIPEMD-160 | Pure, no platform dependence; RustCrypto implementations are portable | `src/crypto/hash.rs` |
| DET-2 | Header preimage, tx serialization, txid, merkle, sighash, state root | Fixed byte layouts; no native-endian or padding exposure | §2 above |
| DET-3 | Compact target / `next_difficulty` | Integer only; magnitude-dependent branch must be reproduced exactly; `div_u64` panics on zero, guarded by `expected.max(1)` | `src/consensus/difficulty.rs:102`; F-6, F-7 |
| DET-4 | Trivial PoW | Pure function of `(preimage, nonce)` | `src/consensus/pow.rs:79` |
| DET-5 | Scratchpad PoW | Portable per `u64`/`u8` semantics, but depends on `usize` cell count, allocation success, and the mask-vs-modulo branch | `src/consensus/pow.rs:200`; F-8 |
| DET-6 | MTP | Deterministic given the block timestamps; uses `sort_unstable`, which is irrelevant for integers because equal values are indistinguishable | `src/chain.rs:241` |
| DET-7 | Future-timestamp bound | **Depends on the validating node's wall clock** by design | B-13 |
| DET-8 | UTXO iteration | `BTreeMap` ordering, i.e. total order on `(txid bytes, vout)`; independent of insertion order | `src/ledger/utxo.rs:105,272` |
| DET-9 | Block/tx ordering inside a block | Transaction order is committed by the merkle root; UTXO commit order is the block order | `src/consensus/block.rs:120`; `src/chain.rs:294` |
| DET-10 | Mining nonce search | Deterministic for a fixed `(preimage, target, start)`; starts at 0 | `src/consensus/pow.rs:268`; `src/chain.rs:391` |
| DET-11 | Pool split | `u128` integer arithmetic; remainder credited to the first contributor; input order is significant | `src/consensus/reward.rs:171` |
| DET-12 | ECDSA signing | Non-deterministic unless RFC 6979 is used; **signatures are not consensus values** — verification is deterministic, signing is not. The P0 corpus pins RFC 6979 output for reproducibility | `src/crypto/secp256k1.rs:81`; `test/vectors/manifest.json` |
| DET-13 | Mempool ordering | `fee_rate = fee as f64 / size as f64`, then descending, tie-break by txid ascending. Floating point, but **non-consensus** | `src/mempool.rs:105,132`; F-9 |
| DET-14 | JSON wire format | Serialization order of struct fields and map keys is deterministic for these fixed structs, but JSON is not consensus; a re-encoded message changes no hash | `src/network/message.rs:155` |

Practical rules for the C++ port:

- Never use floating point in any path that decides acceptance or selects a block.
- Never use `HashMap`/unordered iteration for anything that feeds a hash or a state root.
- Never let the native integer width decide a branch (`usize` must be replaced by a fixed
  width, with a documented 64-bit range).
- Treat the wall clock as an input parameter (`now`), not as ambient state, exactly like
  `connect_block(block, now)`.

---

## 13. Non-consensus policy (documented for completeness)

Mempool (`src/mempool.rs`):

- `admit` rejects coinbases (`CoinbaseNotAllowed`), duplicate txids (`Duplicate`), any input
  already spent by a pooled transaction (`ConflictsWithPooled`), then runs
  `Chain::validate_transaction` (`Invalid(ChainError)`).
- `take_for_block(limit)` sorts by `fee_rate` descending then `txid` ascending, skipping
  conflicting spends; the resulting order is deterministic for a given pool.
- `fee_rate` uses `f64`; it affects only mining preference, never validity.

Relay/transport:

- Frames are AES-GCM-sealed with a 4 MiB plaintext cap (`src/network/frame.rs`). Messages
  are JSON (`src/network/message.rs:155`). Neither affects block validity.
- An invalid transaction received from a peer is dropped silently (`src/node.rs`, `Tx`
  branch); it is not relayed.

Wallet, GUI, session, datadir, and pool share accounting are outside consensus and out of
scope for this specification, except where `pool_coinbase_transaction` / `split_reward`
produce a coinbase that consensus validates (§7.5).

---

## 14. Findings — evidence and impact (behavior unchanged in P1)

These are recorded, not fixed. None of them changes acceptance on the current P2P path.
Each has a regression test that pins the *current* behavior where practical.

**F-1 — `connect_block` computes the difficulty schedule from an untrusted height before
validating it (panic hazard).**
`Chain::connect_block` calls `self.required_bits(block.header.height)` at `src/chain.rs:277`,
before `validate_structure` checks the height (B-4). On a retarget-enabled network,
`required_bits` indexes `self.blocks[(height - 1) as usize]` (`src/chain.rs:260`). For any
`height > block_count`, that index is out of bounds and the process panics.
Evidence: the index is unguarded; `height == 0` and `!allow_pow_retarget` are the only early
returns. Impact: a remote peer cannot reach it today, because `node.rs` only forwards blocks
with `height == next_height` and `previous_hash == tip`, and regtest (the only network tests
use) disables retargeting. But `Chain::connect_block` is public API (RPC/GUI/session call
paths, future C++ callers). A C++ port MUST validate the height before any schedule lookup,
or reproduce the panic — the specification requires the former, and that difference must be
recorded. No behavior changed in P1.

**F-2 — Block `version` is never validated.**
`BLOCK_VERSION` is written when headers are constructed (`src/chain.rs:380`,
`src/genesis.rs:70`) and appears in the preimage, but no validation path reads
`header.version`. A block with `version = 0` or `u32::MAX` is accepted if everything else is
valid. Impact: version cannot be used for future soft-fork signalling without a new rule.
Regression test: `block_version_is_not_validated`.

**F-3 — There is no consensus block-size or weight limit.**
The only limits are 2000 transactions (B-9), per-transaction input/output/script limits
(T-1), and the 4 MiB transport frame. A miner can build a block far larger than the
transport frame; peers then cannot relay it, but a node that receives it by other means
(e.g. RPC) will accept it. Impact: a port that adds a block-size rule would change
acceptance; a port that omits one reproduces current behavior. Do not add a rule in P1.

**F-4 — `state_root` is documented as a Merkle root but is a single flat hash.**
`UtxoSet::state_root` (`src/ledger/utxo.rs:272`) hashes the concatenation of all records;
there is no tree and no inclusion proof. The value is pinned by
`STATE_ROOT_LAYOUT_PROBE`. Impact: documentation/naming only; the bytes are consensus.

**F-5 — `Transaction::deserialize` accepts trailing bytes.**
`deserialize` (`src/ledger/transaction.rs:131`) stops after a complete transaction and does
not require the cursor to be exhausted. A decoder that rejects trailing bytes would reject
inputs the Rust node accepts, while `txid` is over the canonical re-serialization, so an
attacker can mutate the bytes without changing txid. Impact: parsers must agree on
"prefix-decoding is accepted". Regression test: `trailing_bytes_after_a_transaction_are_ignored`.

**F-6 — `next_difficulty` is magnitude-dependent.**
The `leading_zeros() >= 20` branch (`src/consensus/difficulty.rs:117`) changes the order of
integer multiply and divide, which changes the result. Impact: a port that always uses
`t*d/e` or `t/d*e` will diverge from the Rust chain. Regression test:
`next_difficulty_is_deterministic_and_branch_stable` covers both branches.

**F-7 — `Uint256::div_u64`/`divmod` panic on a zero divisor; `required_work` can overflow.**
`src/consensus/uint256.rs:138,152`. `next_difficulty` guards with `expected.max(1)`.
`required_work` (`src/consensus/difficulty.rs:87`) computes `target + 1`, which wraps to zero
for `Uint256::MAX` and then divides by zero. It is not on the validation path. Impact: keep
it off the acceptance path in the port, or add an explicit guard when porting.

**F-8 — The scratchpad engine's parameters are not committed by `engine_id`.**
All scratchpad configurations report `ENGINE_ID_SCRATCHPAD = 1` (`src/consensus/pow.rs:192`).
The digest depends on `memory_bytes` and `rounds`. Only `ChainParams` pins the parameters
(`src/params.rs:112,137,161`). Additionally the implementation uses `usize` (`cells()`,
`src/consensus/pow.rs:157`), allocates with `vec!` (abort on OOM), and switches between
mask and modulo indexing for non-power-of-two cell counts (`src/consensus/pow.rs:221`–`229`),
which `capped_to` can produce locally. Impact: any port must hard-code the exact per-network
parameters, must not accept a peer-supplied scratchpad size, and must use 64-bit arithmetic.
No behavior changed in P1.

**F-9 — Mempool ordering uses `f64`.**
`src/mempool.rs:105` computes `fee as f64 / size as f64` for ordering. This never affects
validity but does affect block selection and therefore fee revenue. A port may use exact
rational comparison only if it accepts that the resulting block template differs; it must
not use floats in consensus code.

**F-10 — `DifficultyError::UnexpectedBits` is never constructed.**
Declared at `src/consensus/difficulty.rs:55`; no code returns it. Impact: cosmetic.

**F-11 — `hash_meets_target` interprets the hash big-endian.**
`src/consensus/difficulty.rs:81` uses `Uint256::from_be_bytes(hash.0)`, i.e. the first byte
of the digest is the most significant. Bitcoin compares the reversed (display) order. A
port that copies Bitcoin's comparison will reject every valid ZeroCoin block. Note also that
the comparison is inclusive (`<=`).

---

## 15. Unsupported, planned, and unverified behavior

Explicitly **not** implemented (do not document these as rules):

| Area | Status |
|---|---|
| Chain reorganisation / fork choice / most-work rule | **Not implemented.** Only tip-extension is accepted (`src/chain.rs:274`). |
| Block size / weight limit | **Not implemented** (F-3). |
| `header.version` semantics or soft-fork signalling | **Not implemented** (F-2). |
| `lock_time` / `sequence` semantics (CLTV/CSV, RBF) | **Not implemented**: parsed, ignored (`src/ledger/transaction.rs`, §8.2). |
| Script opcodes beyond the ten listed | **Unsupported** → `UnsupportedOpcode` (`src/ledger/script.rs:18`–`27`). |
| Sighash modes other than `SIGHASH_ALL` | **Unsupported** (`src/ledger/sighash.rs:20`). |
| SegWit / witness data / taproot | **Not implemented.** |
| Multi-signature, P2SH, time locks | **Not implemented.** |
| Difficulty averaging over multiple retarget windows | **Not implemented**: a single 1440-block window, clamped 4×. |
| Chainwork accumulation for fork choice | **Not implemented**; `required_work` exists only as a helper (F-7). |
| Checkpoints signed by a trusted party | **Not implemented**; only the genesis/config anchors exist. |
| Proof-of-work verification for historical headers on open | Headers are re-hashed and their stored hashes recomputed, but PoW is not re-verified on load (`src/chain.rs:137`–`183`). **Unverified** as a defence against a corrupted local store. |

Unverified by this milestone (open questions, not claims):

- Whether the scratchpad engine's cost profile actually achieves its stated ASIC resistance.
  No benchmarking was performed in P1.
- Whether `MAX_BLOCK_TRANSACTIONS = 2000` is reachable within the 4 MiB transport frame for
  realistic transactions. It is not for large transactions; small ones can exceed the frame
  (F-3).
- Long-run supply arithmetic: `total_supply_ceiling` is not compared against `MAX_SUPPLY` by
  any test. It is a reporting function only.
- The interaction of `subsidy_issued` (persisted, unanchored) with R-10 across a corrupted
  store.
- Whether any wallet/RPC path calls `Chain::connect_block` with untrusted heights (F-1);
  P1 audited the P2P path only.

---

## 16. Regression coverage map

| Rule area | Test |
|---|---|
| Genesis anchors, empty state root | `regtest_genesis_matches_the_pinned_anchors` |
| B-3 … B-15 matrix, check order | `structural_rejections_follow_the_documented_order` |
| B-9 / B-11 boundary (2000 vs 2001) | `transaction_count_boundary_is_two_thousand` |
| B-12 / B-13 boundaries | `timestamp_boundaries_are_strictly_above_median_and_at_most_two_hours_ahead` |
| B-14 before B-15 | `merkle_mismatch_is_reported_before_proof_of_work` |
| F-2 (version ignored) | `block_version_is_not_validated` |
| R-1 / R-2 constants and subsidy table | `reward_constants_match_the_p0_vectors` |
| R-3 … R-10, R-12 check order | `coinbase_checks_run_in_the_documented_order` |
| R-8 / R-9 exact edges | `coinbase_claim_must_cover_fees_and_may_not_exceed_reward` |
| U-1 maturity boundary (h+99 vs h+100) | `maturity_boundary_is_exactly_one_hundred_blocks` |
| U-2 / T-1 malformed input | `malformed_transactions_are_rejected` |
| U-3 invalid transactions (missing, double spend, fee, overflow, script) | `invalid_transactions_are_rejected_with_specific_errors` |
| F-5 trailing bytes | `trailing_bytes_after_a_transaction_are_ignored` |
| §5.1 parameter pin (60 s / 1 440 / 4×) | `difficulty_parameters_match_the_p0_vector` |
| D-1 / D-2 / F-6 | `next_difficulty_is_deterministic_and_branch_stable` |
| D-3 / §5.3 | `validate_bits_boundaries` |
| DET-2 / DET-10 | `header_and_pow_are_deterministic` |
| DET-8 | `state_root_is_independent_of_insertion_order` |
| MTP (DET-6, TS-1) | `median_time_past_uses_the_upper_median` |
| DET-11 first-nonce mining | `mining_is_deterministic_for_a_fixed_header` |
| P0 corpus | `python test/harness/run_vectors.py` (117 cases) |
| P0 emitter | `cargo test --test export_baseline_vectors` |

The tests live in `zerocoin/tests/consensus_rules.rs` and reuse, rather than invent, the
values in `test/vectors/` and the pinned constants in `src/consensus/immutability.rs`.
