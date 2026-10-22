# ZeroCoin (ZRO) — C++ Port Compatibility Requirements

Status: **P1 deliverable. Requirements only — no C++ code exists in this milestone.**
Baseline audited: Rust implementation at commit `260d44c4da07cbeb33efccda7e4fbe3e139091ca`.
Companion document: [`CONSENSUS_RULES.md`](./CONSENSUS_RULES.md) (rule IDs referenced below).

> A C++ implementation is **compatible** only if, for every input, it produces the same
> bytes, the same hashes, and the same accept/reject outcome as the Rust implementation
> described in `CONSENSUS_RULES.md`. Compatibility is a property that must be *demonstrated*
> by the conformance suite in §11 — not asserted. This document does not claim that the
> Rust rules are secure, that they match Bitcoin, or that the port has been audited.

Requirement keywords: **MUST** (blocking for the port milestone), **MUST NOT**,
**SHOULD**, **MAY**. Each requirement names its verification method.

---

## 1. Scope

This document covers the rules that decide whether a block or transaction is valid, and the
bytes and hashes those rules depend on. It does **not** cover wallet formats, GUI, storage
layout, RPC surface, or the pool's share accounting beyond the coinbase it produces.

Explicitly out of scope for the C++ port milestone:

- Changing any network parameter, consensus constant, hash function, or encoding.
- Changing the P2P protocol. Blocks and transactions travel as JSON messages
  (`zerocoin/src/network/message.rs:16`); a C++ node that wants to interoperate MUST speak the
  same messages, but JSON is not consensus and may be re-serialized.
- Copying Bitcoin Core source. The Rust implementation is authoritative; where behavior
  differs from Bitcoin (and it does in several places), the Rust behavior wins.
- Any claim of "Bitcoin-equivalent security" or a completed security audit.

---

## 2. Byte-identical artifacts

The following artifacts are compared **byte for byte** between implementations. Any
difference is a compatibility defect, not a formatting preference.

| ID | Artifact | Definition |
|---|---|---|
| C-1 | Transaction serialization | `CONSENSUS_RULES.md` §2.2; `Transaction::serialize` |
| C-2 | Transaction id | `sha256d(serialize())` — never over received bytes (F-5) |
| C-3 | Block-header preimage | 107 bytes, `CONSENSUS_RULES.md` §2.3 |
| C-4 | PoW hash | `engine.hash(preimage, nonce)` for `engine_id` 0 and 1, including the exact engine parameters |
| C-5 | Merkle root | `CONSENSUS_RULES.md` §2.4, including empty tag, single-leaf passthrough, odd duplication |
| C-6 | UTXO state root | Flat `sha256d` concatenation, §2.5, including `BTreeMap` ordering |
| C-7 | Sighash digest | `CONSENSUS_RULES.md` §2.6, including tag, chain id, blanked scripts, `SIGHASH_ALL` |
| C-8 | Compact difficulty encoding | `compact_to_target` / `compact_from_target`, mantissa rounded down |
| C-9 | Coinbase scriptSig | `push(height_num)` followed by `push(b"ZeroCoin")` (solo) or `push(b"ZeroCoin/pool")` (pool) |
| C-10 | Genesis identity | The seven anchors in `CONSENSUS_RULES.md` §9 |

Verification: §11.1 (P0 corpus) and §11.2 (differential harness).

**C-11** — Endianness MUST be explicit at every field boundary. The port MUST NOT rely on
host byte order, struct packing, or `memcpy` of native integers. (Verification: code review +
byte vectors.)

**C-12** — Integer widths MUST be fixed: `u8/u32/u64`/`i32` in the Rust code map to
`uint8_t/uint32_t/uint64_t/int32_t`; `usize` MUST become a fixed 64-bit type (see C-30).
Overflow behavior MUST be explicit: `checked_*` → error, `saturating_*` → clamp,
`wrapping_*` → modulo 2^N. (Verification: review + arithmetic boundary tests.)

---

## 3. Validation outcome compatibility

**C-13** — For a given `(block, expected tip, network params, local clock)`, the port MUST
return the same accept/reject decision and the same *first* failing rule as
`validate_structure` (`CONSENSUS_RULES.md` §3, order B-3 … B-15). The order is observable
because it determines which error is reported; a port that checks PoW before the merkle root
would report a different error for the same block.

**C-14** — The port MUST expose the same error *taxonomy*, even if names differ:
`WrongChain`, `BadHeight`, `BadPreviousHash`, `WrongEngine`, `BadDifficulty`,
`NoTransactions`, `TooManyTransactions(n)`, `FirstNotCoinbase`, `DuplicateCoinbase`,
`TimestampTooOld{median,found}`, `TimestampTooFarFuture{now,found}`, `RootMismatch`,
`InsufficientProofOfWork`; `ZeroTarget`, `TargetAbovePowLimit{found,limit}`;
`NotCoinbase`, `MissingHeightCommitment`, `BadCoinbaseHeight{expected,found}`,
`GenesisPremine{claimed}`, `RewardOverflow`, `TooMuchReward{height,claimed,subsidy,fees}`,
`BelowFees{claimed,fees}`, `SupplyCapExceeded{issued,new}`; `NoInputs`, `MissingInput`,
`ImmatureCoinbase{outpoint,matures,spent}`, `DoubleSpend`, `ScriptInvalid{index,source}`,
`InputOverflow`, `OutputOverflow`, `NegativeFee{inputs,outputs}`.
(Verification: outcome-mapping table in the differential harness.)

**C-15** — State MUST be mutated only after every check passes, matching
`connect_block`'s clone-then-swap (`CONSENSUS_RULES.md` §3 step 4–7). A rejected block MUST
leave the UTXO set, tip, height, `subsidy_issued`, and persistence untouched.

**C-16** — `subsidy_issued` MUST be updated as `claimed - fees` with saturating subtraction,
and MUST be an input to the supply-cap check (R-10, R-13).

**C-17** — The port MUST NOT add a block-size, weight, sigop, or version rule that the Rust
implementation does not have (F-2, F-3). Adding such a rule is a consensus change and
requires a network upgrade, not a port.

**C-18** — The port MUST NOT validate `lock_time`, `sequence`, or transaction `version`
(§8.2, U-2), because the Rust implementation does not.

---

## 4. Proof of work

**C-19** — `engine_id = 0` MUST implement `sha256d(preimage || nonce_u64_le)` exactly
(`CONSENSUS_RULES.md` §6.1).

**C-20** — `engine_id = 1` MUST implement the scratchpad algorithm of §6.2 exactly,
including: sequential fill chain, data-dependent index from `state[0..8]` little-endian,
`state = sha256(state || cell)` read-modify-write, final fold over every cell, and the
five per-network parameter pairs:

| Network | `memory_bytes` | `rounds` | Cell count |
|---|---|---|---|
| mainnet | 2 097 152 | 4 096 | 65 536 |
| devnet | 65 536 | 1 024 | 2 048 |

**C-21** — Scratchpad size and rounds MUST be compile-time constants selected by network,
never derived from peer input, environment, or available RAM. They are **not** committed by
`engine_id` (F-8), so a mismatch is a silent fork.

**C-22** — The port MUST use 64-bit arithmetic for index derivation and MUST use the
power-of-two mask path for both networks (both are powers of two). If the port supports
non-power-of-two cell counts, it MUST implement the modulo branch identically (F-8).

**C-23** — Allocation failure during hashing MUST be a caught error in the port, not an
abort. (This is a deliberate, documented divergence in *robustness* only; it must not change
any accepted hash.)

**C-24** — Hash comparison MUST treat the 32 digest bytes as a big-endian integer and accept
on `hash <= target` inclusive (F-11). Bitcoin's little-endian comparison MUST NOT be used.

**C-25** — Mining MAY differ in search strategy (threads, nonce partitioning), but the first
accepted nonce for a given `(preimage, target, start = 0)` MUST equal the Rust result when
the port is asked for a single-threaded search from zero (DET-10). Multi-threaded mining is
out of consensus scope.

---

## 5. Difficulty

**C-26** — `next_difficulty` MUST reproduce §5.4 exactly: `expected = window.max(1)`,
`factor = max_factor.max(2)`, clamp `[max(expected/factor,1), expected*factor]`, the
`leading_zeros() >= 20` branch with its exact operation order, the clamp to `pow_limit`, and
`to_compact` rounding down (F-6).

**C-27** — `validate_bits` MUST run after the structural schedule check and before UTXO
work, and MUST reject a zero target before checking the pow limit (order matters for the
reported error).

**C-28** — Retarget MUST be evaluated only at `height % retarget_interval == 0`, using
`prev.timestamp - first.timestamp` across the 1440-block window with saturating subtraction,
and MUST be disabled entirely when `allow_pow_retarget == false` (regtest).

**C-29** — The port MUST NOT compute the schedule from an unvalidated height. Where the Rust
code indexes `blocks[height-1]` before validating `height` (F-1), the port MUST validate the
height first. This is a **documented divergence** in failure mode (a clean rejection instead
of a panic/out-of-bounds); it MUST NOT change any accepted or rejected-by-rule block, and it
MUST be recorded in the port's compatibility notes and covered by a test.

---

## 6. Rewards and coinbase

**C-30** — `block_subsidy` MUST be: height 0 → 0; `h / 210000 >= 64` → 0; otherwise
`5_000_000_000 >> (h / 210000)`.

**C-31** — `validate_coinbase` MUST run the checks in the exact order R-3 … R-10, in
particular: height commitment before output summation, output summation overflow before
`GenesisPremine`, `GenesisPremine` before `TooMuchReward`, and `BelowFees` before
`SupplyCapExceeded`.

**C-32** — The port MUST accept under-claiming the subsidy and MUST reject under-claiming
fees (`claimed < fees`), preserving ZeroCoin's divergence from Bitcoin (R-11).

**C-33** — The supply cap MUST be checked against `subsidy_issued + block_subsidy(height)`,
not against the claimed amount (R-12).

**C-34** — Coinbase height decoding MUST use the first push only, accept heights 0–8 bytes,
reject a high-bit-terminated (negative) encoding, and ignore trailing scriptSig bytes
(§7.3, OBSERVED).

**C-35** — `split_reward` MUST use integer arithmetic wide enough for `reward × weight`
(`u128` in Rust), round down, credit the remainder to the first contributor, and drop
zero-value outputs. Its output MUST be byte-identical because it feeds a coinbase (§7.5).

---

## 7. Transactions, scripts, and UTXO

**C-36** — Transaction decoding MUST reject non-minimal varints, truncation, >10 000 inputs,
>10 000 outputs, and scripts >1 000 000 bytes, with the same precedence as
`Transaction::deserialize`.

**C-37** — Transaction decoding MUST accept trailing bytes after a complete transaction
(F-5). `txid` MUST be computed over the canonical re-serialization, never over the input
buffer. A port that rejects trailing bytes is incompatible; a port that hashes the received
bytes is incompatible.

**C-38** — Script execution MUST implement exactly the ten opcodes in §8.4, the four limits
(1000 stack items, 520-byte elements, 201 ops counted only for opcodes above
`OP_PUSHDATA2`, 10 000-byte scripts), the shared stack between `script_sig` and
`script_pubkey`, and the final `is_true` including negative-zero handling. Any other opcode
MUST fail.

**C-39** — Sighash MUST include the domain tag, chain id, blanked sibling scripts, the
signed input's `script_code`, `lock_time`, and the trailing `sighash_type`; only
`SIGHASH_ALL = 0x01` MUST verify, and out-of-range indices MUST return "no digest" (→
`ScriptInvalid`).

**C-40** — UTXO application MUST follow §8.2's order: empty-inputs, duplicate-input,
per-input existence → maturity → script, input sum, output sum, negative fee, then commit.
Validation MUST complete before the first mutation.

**C-41** — Maturity MUST be `is_coinbase ? height + 100 : height`, compared with
`<= spend_height` (U-1). Off-by-one changes here are a hard fork.

**C-42** — The UTXO state root MUST hash entries in lexicographic `(txid bytes, vout)` order
with the exact record layout of §2.5. The port MUST NOT substitute a Merkle tree, an
unordered map iteration, or a different length encoding (F-4).

**C-43** — The port MUST NOT introduce floating point into any acceptance path or state
commitment. Mempool ordering (F-9) MAY use floats or exact arithmetic, but the choice MUST
be documented as non-consensus.

**C-53** — A public key MUST be accepted only as a 33-byte compressed SEC1 encoding
tagged `0x02` or `0x03` that names a point on secp256k1 (`CONSENSUS_RULES.md` §8.4.1,
rule P-1). Every other encoding — including SEC1 tag `0x05` (*compact*, 33 bytes), tags
`0x00`/`0x01`/`0x04`/`0x06`/`0x07`, and any length other than 33 — MUST be rejected
before the signature equation is evaluated, and MUST surface as a failed `OP_CHECKSIG`
(empty push), not as a distinct error. The port MUST NOT normalise, re-encode or alias a
non-canonical spelling into a canonical one: `hash160` commits to the 33 bytes, so one
curve point with two encodings is two P2PKH locks.

> Appended by P2.8 after C-43 rather than renumbering the IDs cited by §8–§10 and by the
> kernel tests. Requirement IDs are permanent labels, not section addresses.

---

## 8. Genesis and boot invariants

**C-44** — The port MUST reproduce `genesis_coinbase()` exactly: one null-outpoint input,
scriptSig `OP_0 || push("No premine, no owner: ZeroCoin is issued only by proof of work")`,
zero outputs, version 1, lock_time 0.

**C-45** — The port MUST reproduce the genesis header (previous hash zero, pinned
timestamp, `genesis_bits`, engine id, `BLOCK_VERSION`) and MUST start mining its nonce at 0.

**C-46** — The port MUST verify the seven anchors of `CONSENSUS_RULES.md` §9 at boot and
refuse to run if any differs. Anchors MUST be compile-time constants in the port, not
configuration.

**C-47** — Opening a persisted chain MUST compare the recomputed genesis identity with the
network's expected genesis and refuse on mismatch.

---

## 9. Environment and determinism

**C-48** — Wall-clock time MUST be an explicit input to block validation (the `now`
parameter). The port MUST NOT read the clock inside the validation function.

**C-49** — The port MUST expose the same `now` semantics: `timestamp > now + 7200` is
rejected, with saturating addition.

**C-50** — All maps/sets that feed a hash or a state root MUST be ordered containers (or be
explicitly sorted before hashing). No iteration order may depend on insertion order, hash
seeds, allocator behavior, or thread scheduling.

**C-51** — The port MUST be deterministic across runs and platforms for all values in §2.
It MUST NOT depend on: pointer width, endianness, `char` signedness, compiler strict-aliasing
assumptions, `unordered_map` iteration, locale, time zone, or `rand()`.

**C-52** — Signing MAY be non-deterministic (DET-12); signature verification MUST be
deterministic. The port MUST NOT require a specific signature encoding beyond DER + one
sighash byte.

---

## 10. Known defects and required disposition

The port MUST take an explicit, recorded position on each finding. Default: reproduce.

| Finding | Rust behavior | Port requirement |
|---|---|---|
| F-1 | `required_bits` called with untrusted height → out-of-bounds panic on retarget networks | **Diverge (safety):** validate height first (C-29). Document; test both. |
| F-2 | `header.version` never validated | Reproduce. Do not add a version rule (C-17). |
| F-3 | No block size/weight limit | Reproduce. Do not add one (C-17). |
| F-4 | `state_root` is a flat hash, not a Merkle tree | Reproduce bytes exactly (C-42). |
| F-5 | Trailing bytes after a tx are ignored | Reproduce (C-37). |
| F-6 | Magnitude-dependent retarget arithmetic | Reproduce exactly (C-26). |
| F-7 | `div_u64` panics on zero; `required_work` overflows at `Uint256::MAX` | Guard in the port; keep `required_work` off the acceptance path. |
| F-8 | Scratchpad params not committed by `engine_id`; `usize`; abort on OOM | Reproduce hashes; fix width and OOM handling (C-21…C-23). |
| F-9 | Mempool fee-rate uses `f64` | Non-consensus; document the choice (C-43). |
| F-10 | `UnexpectedBits` never constructed | No port obligation; may omit or keep as unused. |
| F-11 | Big-endian hash comparison | Reproduce (C-24). |

Any divergence beyond F-1/F-7/F-8 robustness MUST be treated as a consensus change and MUST
NOT be merged under the "port" label.

---

## 11. Conformance suite (acceptance gate)

The C++ port milestone is not complete until all four layers pass.

### 11.1 P0 corpus (mandatory, unchanged)

- `python test/harness/run_vectors.py` MUST report `FAIL 0` and `SKIP 0` for all 117 cases,
  with the five ANCHOR cases passing.
- The corpus MUST NOT be regenerated, edited, or re-pinned by the port. It is the fixed
  reference (`test/vectors/manifest.json` pins the source commit).

### 11.2 Differential harness (mandatory, new)

- A harness MUST feed the same inputs to the Rust binary and the C++ binary and compare
  every field of §2 byte-for-byte, plus the acceptance outcome and error kind of §3.
- At minimum: all 117 P0 cases, the genesis of all three networks, and the regression
  scenarios of `zerocoin/tests/consensus_rules.rs`.

### 11.3 Differential fuzzing (mandatory before mainnet use)

- Random valid blocks: mine on regtest in Rust, replay in C++; hashes, roots and state roots
  MUST match.
- Random mutations: flip bytes in headers, scripts, amounts, varints, and lengths; both
  implementations MUST agree on accept/reject and on the first failing rule.
- Malformed serialization: truncations at every offset, non-minimal varints, oversized
  scripts, trailing bytes (must be accepted), 2000/2001 transactions, 10 000/10 001
  inputs/outputs.

### 11.4 Anchors (mandatory)

- The C++ implementation MUST reproduce all seven anchors of §9 with no configuration.

---

## 12. Definition of done

A C++ port is "P1-compatible" only when:

1. Every MUST above is implemented and reviewable.
2. §11.1, §11.2 and §11.4 pass on the port's CI, on at least two platforms with different
   endianness if available.
3. §11.3 has been run and its corpus committed.
4. The divergence list (F-1, F-7, F-8 robustness items) is documented and signed off.
5. No consensus constant, hash function, encoding, wallet format, or network protocol was
   changed to make a test pass.

This document does not authorize starting the C++ rewrite; it defines what that rewrite must
satisfy when it is authorized.
