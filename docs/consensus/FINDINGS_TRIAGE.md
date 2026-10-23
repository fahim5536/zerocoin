# ZeroCoin P1.1 — Consensus Findings Triage and Risk Verification

**Base commit:** `545cf08` (`docs: audit consensus rules and specify C++ port requirements`)
**Scope:** independent verification of findings F-1 … F-11 from
[`CONSENSUS_RULES.md`](CONSENSUS_RULES.md) §14 against the current tree, plus safe
regression tests. **No consensus rule, parameter, serialization, hash, wallet format
or network protocol was changed in this milestone.** The only code added is a test
file (`zerocoin/tests/findings_regression.rs`).

## 1. Method

1. Re-read every claim in §14 and traced it to source.
2. Audited reachability across every entry point that can carry untrusted data:
   P2P messages, RPC, the GUI, the mobile/in-process session, the CLI, and local
   library callers.
3. Reproduced each reproducible finding in a test that pins *current* behavior.
4. Ran the P0 vector harness and the full Rust test suite before and after.

### 1.1 Reachability audit

| Entry point | Can it deliver a block? | Can it deliver a raw transaction? | Height control |
|---|---|---|---|
| P2P `Message::Block` (`src/node.rs:668`) | Yes, but only after `holds_block` (`node.rs:643`) and `extends_tip` (`node.rs:646-662`) prove `height == next_height()` and `previous_hash == tip_hash()` | — | Forced to `next_height()` |
| P2P `Message::Tx` | No | Yes → `Mempool::admit` → `Chain::validate_transaction` (`src/chain.rs:406`), which never calls `connect_block` | No height input |
| RPC (`handle_rpc`, `src/node.rs:1142`) | No. The surface is exactly 11 methods: `getinfo` (1144), `getnewaddress` (1162), `getbalance` (1167), `generate` (1177), `sendtoaddress` (1251), `getpoolinfo` (1292), `walletstatus` (1312), `createwallet` (1329), `importwallet` (1350), `wallethistory` (1434), `stop` (1446). None accepts a block or raw transaction; `generate` mines at `next_height()`; `sendtoaddress` builds and signs its own transaction | `sendtoaddress` only builds its own tx | None |
| GUI (`src/gui.rs`) | No — it is an RPC client (`gui.rs:76,88`), so it inherits the RPC surface | Same as RPC | None |
| Mobile / in-process session (`src/session.rs:164`) | No — shares `handle_rpc` | Same as RPC | None |
| CLI (`src/bin/zerocoin_cli.rs`) | No — RPC client, no `connect_block` callers | Same as RPC | None |
| Local library callers | Yes: `Chain::connect_block` is `pub` (`src/chain.rs:274`) | Yes (public `validate_transaction`, `UtxoSet::apply_transaction`) | **Arbitrary** |

`connect_block` has exactly two production callers: `src/node.rs:668` (behind the
pre-filter above) and `src/chain.rs:398` (`mine_block_with_coinbase`, which uses
`self.next_height()`).

### 1.2 Severity model

Severity combines **current-node impact** with **migration/port impact**, because the
next milestone is a C++ port that must agree byte-for-byte. Current exploitability is
stated separately in the reachability columns — no finding below is claimed to be
remotely exploitable unless the table says so.

| Level | Meaning |
|---|---|
| **High** | A disagreement here silently splits the chain (consensus identity), or a reachable input can stop a node. |
| **Medium** | Real hazard with bounded reach (local-only panic, acceptance/relay asymmetry, or consensus bytes pinned only by documentation). |
| **Low** | Validation gap or parser-parity concern with no current acceptance change. |
| **Info** | Cosmetic or non-consensus; recorded for completeness. |

Class: **C** consensus-critical · **S** node stability · **N** non-consensus.

## 2. Summary — severity-ranked

| # | ID | Disposition | Severity | Class | Remote peers | RPC/GUI/session | Local callers | Fix compatibility impact | Regression test |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **F-11** | Confirmed | High | C | Safe (all nodes agree) | Safe | Safe | Cannot change without redefining PoW identity / new chain | `f11_hash_target_comparison_is_inclusive_and_big_endian` |
| 2 | **F-6** | Confirmed | High | C | Safe | Safe | Safe | Cannot change without forking at every retarget | `next_difficulty_is_deterministic_and_branch_stable` (P1) |
| 3 | **F-8** | Confirmed | High | C | Safe | Safe | Config-level fork if params ever vary while `engine_id` stays 1 | Same as above; hardening is API-internal | `f8_engine_id_does_not_commit_to_scratchpad_parameters` |
| 4 | **F-4** | Confirmed | Medium | C | Safe | Safe | Safe | Changing the layout changes a consensus commitment (anchors) | `regtest_genesis_matches_the_pinned_anchors`, `state_root_is_independent_of_insertion_order` (P1) |
| 5 | **F-1** | Confirmed (reachability claim corrected) | Medium | S | **Not reachable** (guarded at `node.rs:646-662`) | **Not reachable** (no block submission) | **Reachable panic** | Guard is behavior-preserving for valid blocks; previously-panicking inputs become typed errors | `f1_connect_block_panics_when_height_exceeds_chain_length` |
| 6 | **F-3** | Confirmed | Medium | C | Not deliverable above 4 MiB (frame cap) | Not reachable (no block submission) | Reachable by a local miner; block accepted but unrelayable | Adding a limit **changes acceptance**; requires coordinated activation | `f3_a_block_larger_than_the_frame_cap_is_accepted` |
| 7 | **F-7** | Confirmed | Low | S | Safe | Safe | Reachable helper panic, **not on validation path** | Helper API change only; no consensus effect | `f7_required_work_panics_when_target_is_max`, `f7_uint256_div_u64_panics_on_zero_divisor` |
| 8 | **F-5** | Confirmed | Low | C (port parity) | Not reachable (wire format is JSON) | Not reachable (no raw-tx RPC) | Tooling only | Rust semantics can stay; a stricter port diverges on tooling input, not chain state | `trailing_bytes_after_a_transaction_are_ignored` (P1) |
| 9 | **F-2** | Confirmed | Low | C (forward-compat) | Safe | Safe | Safe | Adding a version check changes acceptance; must be activated | `block_version_is_not_validated` (P1) |
| 10 | **F-9** | Confirmed | Info | N | Safe | Safe | Safe | Block template only; never validity | — (see §4.10) |
| 11 | **F-10** | Confirmed | Info | N | Safe | Safe | Safe | None — dead variant | — |

**Bottom line:** no finding is remotely exploitable on the current P2P/RPC surface.
The high-severity items are all *port-correctness pins*: they are correct in Rust and
must be copied exactly, not “fixed”. The only reachable defects are local-API hazards
(F-1, F-7) and a locally constructible oversized block (F-3).

## 3. Detailed dispositions

### F-1 — `connect_block` reads an untrusted height before validating it

- **Disposition: Confirmed** (panic). The §14 parenthetical that names “RPC/GUI/session
  call paths” is **disproven** — see below.
- **Evidence:**
  - `src/chain.rs:275-277`: `connect_block` computes `expected_bits = self.required_bits(height)`
    with `height = block.header.height` *before* `validate_structure` (line 280).
  - `src/chain.rs:260`: on a retarget-enabled network, `required_bits` indexes
    `&self.blocks[(height - 1) as usize]` unguarded; `height == 0` and
    `!allow_pow_retarget` are the only early returns (256-258).
  - `src/consensus/block.rs:153`: the height is checked only later, inside
    `validate_structure`.
  - Reproduction: `f1_connect_block_panics_when_height_exceeds_chain_length` panics with
    `index out of bounds` on a genesis-only **devnet** chain (retargeting enabled,
    `src/params.rs:148`) when asked to connect a block at height 2.
- **Classification:** node-stability (panic), not a consensus divergence.
- **Reachability:** remote peers **cannot** reach it: `node.rs:646-647` computes
  `extends_tip` from `height == next_height()` and `previous_hash == tip_hash()`, and
  `node.rs:648-662` returns before `connect_block` at `node.rs:668` when it is false.
  RPC, GUI, session and CLI expose no block submission (§1.1). Only local library
  callers can pass an arbitrary height. (This resolves the §15 open question.)
- **Compatibility of a fix:** none for valid blocks. The guard rejects inputs that
  currently panic, so no accepted block changes. This is not a consensus change and can
  ship as an ordinary stability fix.
- **Proposed remediation (R-1, not implemented):** move the expected-height check ahead
  of the schedule lookup in `connect_block` (return `BlockError::BadHeight` before
  `required_bits`), and/or make `required_bits` return `Option`/`Result` and have
  `connect_block` map the failure. Replace the `#[should_panic]` test with a typed-error
  assertion at that time. Prefer reusing the existing `BadHeight` error to avoid a new
  public API surface.

- **P2.11 decision (2026-10-23) — disposition recorded, nothing implemented.** The
  defect is pinned exactly, the port does not inherit it, and a Rust guard is
  scheduled as a separate milestone.
  - **Invalid-height condition (precise).** `allow_pow_retarget == true` **and**
    `height > self.next_height()` — equivalently `(height - 1) as usize >=
    self.blocks.len()`. `height == 0` returns early, and a network with
    `allow_pow_retarget == false` can never reach the index. Every
    `height <= next_height()` is safe, including `height == 1` on a
    genesis-only chain.
  - **Panic path (proven).** `connect_block` → `required_bits(height)`
    (`src/chain.rs:277`) → `self.blocks[(height - 1) as usize]`
    (`src/chain.rs:260`), **before** `validate_structure` (`:280`) can return
    `BadHeight`. Proven by
    `f1_connect_block_panics_when_height_exceeds_chain_length`, which carries
    `#[should_panic(expected = "index out of bounds")]`.
  - **Remote reachability: not established, and none claimed.** The only non-test
    caller outside `chain.rs` is `node.rs:668`, gated by `extends_tip`
    (`node.rs:646`); `mine_block_with_coinbase` passes `next_height()`; no RPC,
    GUI, session or CLI path accepts a block. This is a local-API hazard, **not**
    a remotely exploitable one.
  - **Port implication.** A C++ port with the same call order would read the
    schedule from an unvalidated height. `CPP_PORT_REQUIREMENTS.md` C-29
    therefore allows the port to **diverge for safety** by validating the height
    first. This input class is consequently **excluded from the differential
    corpus**: a differential row over it would encode a Rust panic as expected
    behaviour. No vector is created or regenerated for it.
  - **Selected strategy.** (a) leave Rust behaviour unchanged; (b) pin both
    implementations with targeted robustness tests in the follow-up, not in the
    differential fixture; (c) implement the Rust bounds guard as a separate,
    explicitly scoped **non-consensus** milestone.
  - **Follow-up milestone M-F1 — acceptance criteria** (no consensus change, no
    vector regeneration):
    1. `connect_block` returns the existing `BadHeight` error before
       `required_bits` is called for any height the chain cannot index;
    2. `required_bits` keeps its signature, or a new fallible signature is
       carried through every caller in the same change;
    3. the `#[should_panic]` regression is replaced by an assertion on the typed
       error, and the panic path is no longer reachable;
    4. a matching C++ negative test asserts the same typed rejection, so the
       exemption becomes a tested equivalence; `CPP_PORT_REQUIREMENTS.md` §10's
       F-1 row changes from "Diverge (safety)" to "identical";
    5. no block accepted today becomes rejected, and no verdict in the P0 corpus
       or the 121-case differential fixture changes;
    6. both gates green in fresh build directories, with the change recorded as
       non-consensus in `COMPONENT_OWNERSHIP.md` and `MIGRATION_ROADMAP.md`.

### F-2 — block `version` is never validated

- **Disposition: Confirmed.**
- **Evidence:** `BLOCK_VERSION` is written at `src/chain.rs:380` and `src/genesis.rs:70`
  and committed in the preimage (`src/consensus/block.rs:87`), but
  `validate_structure` (`block.rs:135-209`) contains no read of `header.version`.
  Pinned by `block_version_is_not_validated` (`tests/consensus_rules.rs:341`), which
  accepts `version = 0` and `u32::MAX` after re-solving PoW.
- **Classification:** consensus-critical (forward compatibility), not a present hazard.
- **Reachability:** all block paths — but there is nothing to exploit; the field is
  simply ignored by every node.
- **Compatibility of a fix:** adding a version check changes acceptance, so it is a
  coordinated rule change (activation height / version bump), never a silent patch.
- **Proposed direction:** leave behavior as-is for the port. If version-based signalling
  is ever wanted, specify it as a new rule with an activation gate and a new regression
  test; until then the C++ port must **ignore** `version` exactly like Rust.

### F-3 — no consensus block-size or weight limit

- **Disposition: Confirmed.**
- **Evidence:** `validate_structure` bounds only the transaction count
  (`block.rs:177`, `MAX_BLOCK_TRANSACTIONS = 2000`). Per-transaction bounds are
  `MAX_TX_BYTES`/input/output counts at deserialization (`src/ledger/transaction.rs:20-23`),
  and `UtxoSet::apply_transaction` (`src/ledger/utxo.rs:191-257`) never checks an output
  script's size. The only size ceiling is the 4 MiB transport plaintext cap
  (`MAX_PLAINTEXT_BYTES` in `src/network/frame.rs`).
  Reproduction: `f3_a_block_larger_than_the_frame_cap_is_accepted` builds a spend whose
  single output `script_pubkey` is ~4.7 MB, mines it on regtest, and `connect_block`
  accepts it — the transaction alone is larger than `MAX_PLAINTEXT_BYTES`.
- **Classification:** consensus-critical (acceptance rule absent) with a relay
  consequence. **Not remotely exploitable:** a peer cannot deliver such a block over the
  frame cap, and no RPC accepts blocks. The reachable scenario is a local miner
  producing an unrelayable block — self-inflicted, not a remote DoS.
- **Compatibility of a fix:** adding any limit rejects blocks that are accepted today;
  it is a hard-fork-class change and must be coordinated. Shipping the port with “no
  limit” reproduces Rust exactly.
- **Remediation options (R-2; decision taken in P2.11, recorded below):**
  - **Option A (status quo, recommended until a fork is scheduled):** document “no block
    size limit” as a rule; correct the misleading comment in `src/network/frame.rs`
    (“Blocks are bounded well below this” is false); the C++ node must not add a limit on its own.
  - **Option B (future hardening milestone):** define a serialized-size limit below the
    frame cap, enforce it in `validate_structure` before transaction replay, and activate
    it at a coordinated height. Requires a protocol/consensus change plan, not this
    milestone. The F-3 test then flips from “accepted” to a typed rejection.

- **P2.11 decision (2026-10-23): Option A adopted.** There is **no consensus
  block-size or block-weight rule**, and the port may not add one. The 4 MiB
  `MAX_PLAINTEXT_BYTES` (defined in `src/network/frame.rs`) is a **transport** bound: it
  caps one frame's plaintext before authentication so a hostile length field
  cannot force an unbounded allocation. It is not a validity rule, and
  `connect_block` never consults it —
  `f3_a_block_larger_than_the_frame_cap_is_accepted` proves that a block whose
  single transaction alone exceeds the cap is accepted.
  - **What the port must do:** reproduce "no limit" (C-17), never reject a block
    because it would not fit a frame, and never derive a validity rule from a
    transport constant.
  - **What must not be claimed:** that a block which cannot be relayed is
    invalid. Such a block is consensus-valid but unrelayable; the local-miner
    scenario is self-inflicted, not a remote DoS.
  - **Documentation correction:** the doc comment on `MAX_PLAINTEXT_BYTES` is corrected in
    P2.11 to say the cap is transport-only. Frame limits, transaction/block
    validity and protocol behaviour are unchanged.
  - **Option B** remains a possible future hardening milestone: it needs a
    coordinated activation height, a protocol/consensus plan and regenerated
    vectors. It is not part of P2.11 and not part of P3.

### F-4 — `state_root` is documented as a Merkle root but is a flat hash

- **Disposition: Confirmed.**
- **Evidence:** the doc comment at `src/ledger/utxo.rs:269-271` says “a Merkle root over
  every entry keyed by outpoint”, but the implementation (`utxo.rs:272-284`) concatenates
  every record and returns `sha256d(&hasher_input)`. There is no tree and no inclusion
  proof. The bytes are pinned by `STATE_ROOT_LAYOUT_PROBE`
  (`src/consensus/immutability.rs`) and the genesis anchors.
- **Classification:** consensus-critical bytes; the defect is documentation/naming.
- **Reachability:** the value is computed locally and compared against pinned anchors;
  no remote input selects the layout.
- **Compatibility of a fix:** replacing the commitment with a real Merkle tree changes
  consensus bytes and every anchor — effectively a new chain. Not viable.
- **Proposed direction:** docs-only follow-up: describe it as a “flat SHA-256d
  commitment” and keep the exact byte layout in the port spec. Any C++ implementation
  must copy `utxo.rs:272-284` byte-for-byte, not a Merkle tree.

### F-5 — `Transaction::deserialize` accepts trailing bytes

- **Disposition: Confirmed.**
- **Evidence:** `deserialize` (`src/ledger/transaction.rs:131-180`) returns after
  `lock_time` without checking that the cursor is exhausted. `txid` is over the canonical
  re-serialization (`transaction.rs:183-185`), so trailing bytes do not change identity.
  Pinned by `trailing_bytes_after_a_transaction_are_ignored`
  (`tests/consensus_rules.rs:700`).
- **Classification:** consensus-critical only in the sense of *parser parity*; the wire
  protocol is JSON (`src/network/message.rs:16-21`), so this decoder never sees network
  bytes. `Transaction::deserialize` has no production caller — only unit tests and the
  P0 vector emitter.
- **Reachability:** not remote; not RPC. Offline tooling/library callers only.
- **Compatibility of a fix:** a stricter decoder changes tooling acceptance but not chain
  acceptance or txids. Rust can stay permissive.
- **Proposed direction:** keep Rust semantics; the C++ port must accept prefix-decoding
  (or document a deliberate, tooling-only strict mode). If a binary wire format is ever
  introduced, decode exactly the frame, which removes the ambiguity structurally.

### F-6 — `next_difficulty` is magnitude-dependent

- **Disposition: Confirmed** (citation corrected).
- **Evidence:** the condition is at `src/consensus/difficulty.rs:116`
  (`prev_target.leading_zeros() >= 20`), with `mul → div` at line 117 and `div → mul` at
  line 119. The two orders truncate differently, so the branch result depends on target
  magnitude. Pinned by `next_difficulty_is_deterministic_and_branch_stable`
  (`tests/consensus_rules.rs:742`), which covers both branches.
- **Classification:** consensus-critical arithmetic.
- **Reachability:** every retarget boundary on a retarget-enabled network; all nodes run
  the same code, so no divergence today.
- **Compatibility of a fix:** “fixing” the arithmetic (unifying the formula) changes the
  difficulty at some boundaries and forks the chain. Not viable without a new network.
- **Proposed direction:** the port must reproduce the branch and the truncation order
  exactly. The P0 `difficulty/retarget.json` vectors are the cross-language oracle;
  extend them at the C++ milestone if needed.

### F-7 — division helpers panic; `required_work` can wrap

- **Disposition: Confirmed** (citation corrected: asserts are at
  `src/consensus/uint256.rs:139` and `:153`; the functions start at 138/152).
- **Evidence:** `required_work` (`src/consensus/difficulty.rs:87-94`) computes
  `target.wrapping_add(ONE)`; for `Uint256::MAX` the denominator is zero and
  `divmod` asserts. `div_u64` asserts on a zero divisor. `next_difficulty` guards its own
  divisor with `expected.max(1)` (`difficulty.rs:104`).
  Reproduced by `f7_required_work_panics_when_target_is_max` and
  `f7_uint256_div_u64_panics_on_zero_divisor`.
- **Classification:** node-stability helper hazard. **Not on the validation path**:
  `required_work` is called only by a unit test, the re-export, and the vector emitter.
- **Reachability:** local callers only; no remote or RPC path.
- **Compatibility of a fix:** helper API change only; no block acceptance changes.
- **Proposed remediation (R-4, not implemented):** add `checked_div_u64` /
  `checked_divmod` (or return `Option`) and special-case `target == Uint256::MAX` in
  `required_work`; keep the `assert!` variants for debug-only callers, or migrate callers
  and delete them. The port must not expose these helpers on any consensus path.

### F-8 — engine parameters are not committed by `engine_id`

- **Disposition: Confirmed.**
- **Evidence:** `ScratchPadEngine::id` returns the constant `ENGINE_ID_SCRATCHPAD = 1`
  (`src/consensus/pow.rs:192-194`, constant at line 58) for every configuration, while
  the digest depends on `memory_bytes`/`rounds` (`pow.rs:200-237`). Parameters are pinned
  only by `ChainParams` (`src/params.rs:112-115` mainnet, `137-140` devnet; regtest uses
  the trivial engine). `cells()` uses `usize` (`pow.rs:157-159`), `hash` allocates with
  `vec!` (line 202, abort on OOM), and indexing switches between mask and modulo
  (lines 221-229); `capped_to` (139-146) can produce non-power-of-two cell counts
  locally.
  Reproduced by `f8_engine_id_does_not_commit_to_scratchpad_parameters`: two engines
  report id 1 but produce different digests for the same preimage.
- **Classification:** consensus-critical parameter commitment.
- **Reachability:** not remote input — a block's `engine_id` is checked against the
  local engine id (`block.rs:162-167`), but the parameters behind that id are not.
  A node configured with non-network parameters would compute different hashes while
  advertising the same id — a configuration fork, not an attack.
- **Compatibility of a fix:** changing the digest or the parameter set redefines PoW;
  new id values would be a consensus change. Hardening the local path (refuse
  non-network parameters, use `u64`) is API-internal.
- **Proposed direction:** the port must hard-code per-network parameters (never accept a
  peer- or device-supplied size), use 64-bit indexing arithmetic, and treat allocation
  failure as a startup refusal rather than shrinking the pad. Optionally add a
  `params_fingerprint` to the port's configuration validation in a non-consensus
  release.

### F-9 — mempool ordering uses `f64`

- **Disposition: Confirmed.**
- **Evidence:** `fee_rate = fee as f64 / size as f64` (`src/mempool.rs:105`); ordering at
  `mempool.rs:136-141` sorts by `partial_cmp` and breaks ties by txid.
- **Classification:** non-consensus (block template / fee revenue), as §14 states.
- **Reachability:** local mempool only; remote peers can influence which transactions are
  present, not the comparison.
- **Compatibility of a fix:** an exact rational comparison changes template order, which
  changes which blocks a miner finds but never validity. Safe as a non-consensus change,
  but it must not be described as a consensus rule.
- **Proposed direction:** optional follow-up: compare `fee * other_size` with `u128` and
  keep the txid tie-break. Document that block template order is not consensus.

### F-10 — `DifficultyError::UnexpectedBits` is never constructed

- **Disposition: Confirmed** (citation corrected: the variant is at
  `src/consensus/difficulty.rs:59`; the enum starts at 55).
- **Evidence:** repository-wide search finds the declaration and a display mapping in
  `tests/export_baseline_vectors.rs:170` only; no constructor.
- **Classification:** non-consensus / cosmetic.
- **Proposed direction:** remove the variant or start returning it from a future
  schedule check (e.g. R-1's expected-bits comparison). No behavior change.

### F-11 — `hash_meets_target` interprets the digest big-endian, inclusively

- **Disposition: Confirmed.**
- **Evidence:** `Uint256::from_be_bytes(pow_hash.0) <= *target`
  (`src/consensus/difficulty.rs:81-83`). The first byte of the digest is the most
  significant; the comparison admits equality.
  Reproduced by `f11_hash_target_comparison_is_inclusive_and_big_endian`, which accepts
  `hash == target`, rejects `target + 1`, and rejects a hash whose high byte is large
  (which a little-endian reading would accept).
- **Classification:** consensus-critical comparison semantics.
- **Reachability:** every block-validation path; all Rust nodes agree.
- **Compatibility of a fix:** any change to byte order or strictness rejects all existing
  proofs — a new chain. Not viable.
- **Proposed direction:** the port must compare big-endian with `<=`. Do not adopt
  Bitcoin's reversed display order.

## 4. Corrections to `CONSENSUS_RULES.md` §14

The findings stand; these citations/claims in the P1 text were stale or overstated and
are corrected here (the P1 document is otherwise left intact, per the no-behavior-change
rule):

| Item | P1 text | Verified |
|---|---|---|
| F-6 | branch at `difficulty.rs:117` | condition at **116**, branches at 117 (`mul→div`) and 119 (`div→mul`) |
| F-7 | asserts at `uint256.rs:138,152` | asserts at **139** and **153** (functions start at 138/152) |
| F-10 | variant at `difficulty.rs:55` | variant at **59** (enum starts at 55) |
| F-1 | “`connect_block` is public API (RPC/GUI/session call paths…)” | RPC/GUI/session/CLI have **no** block-submission path; only P2P (guarded) and local library callers reach it |
| F-8 | “`src/params.rs:112,137,161`” | 112-115 and 137-140 are the engine specs; **161** is regtest, which uses the *trivial* engine, not scratchpad |

## 5. Regression tests added (this milestone)

`zerocoin/tests/findings_regression.rs` — six tests, all behavior pins:

| Test | Finding | Pins |
|---|---|---|
| `f1_connect_block_panics_when_height_exceeds_chain_length` | F-1 | index-out-of-bounds on an untrusted height (devnet, retargeting on) |
| `f3_a_block_larger_than_the_frame_cap_is_accepted` | F-3 | a ~4.7 MB output script is accepted; the block exceeds `MAX_PLAINTEXT_BYTES` |
| `f7_required_work_panics_when_target_is_max` | F-7 | `target + 1` wraps to a zero divisor |
| `f7_uint256_div_u64_panics_on_zero_divisor` | F-7 | `div_u64(0)` asserts |
| `f8_engine_id_does_not_commit_to_scratchpad_parameters` | F-8 | constant id, parameter-dependent digest |
| `f11_hash_target_comparison_is_inclusive_and_big_endian` | F-11 | `<=` and big-endian order |

The two `#[should_panic]` tests are deliberately temporary: when R-1/R-4 land they must
be rewritten to assert the typed error/`Option`. F-2, F-5 and F-6 remain pinned by the P1
suite; F-4, F-9 and F-10 have no safe behavioral reproduction (their evidence is the
pinned anchor/implementation, recorded above).

## 6. Verification

Run on the P1.1 branch at `545cf08` + this milestone's two added files, with
`CARGO_TARGET_DIR` outside the repository:

| Check | Result |
|---|---|
| `cargo +stable-x86_64-pc-windows-gnu test` (all targets) | **235 lib + 20 P1 + 2 emitter + 6 new + 0 doc = 263 passed, 0 failed** |
| `cargo test --test findings_regression` | **6 passed, 0 failed** |
| `cargo test --test consensus_rules` (P1 suite) | **20 passed, 0 failed** |
| `cargo test --test export_baseline_vectors` | **2 passed, 0 failed** |
| `python test/harness/run_vectors.py` (P0 corpus, 117 cases) | **PASS 112 / ANCHOR 5 / SKIP 0 / FAIL 0** |

No existing test was modified, skipped or weakened.

## 7. Unresolved risks / follow-ups

1. **F-1 guard** — **decided in P2.11 (Option: separate milestone M-F1).** It remains
   the only reachable panic on a local API path, and remote reachability is still not
   established. Until M-F1 lands, the `#[should_panic]` test documents it; acceptance
   criteria are in §3 F-1.
2. **F-3 policy** — **decided in P2.11: Option A (no consensus limit; the 4 MiB cap is
   transport-only).** The misleading doc comment on `MAX_PLAINTEXT_BYTES` is corrected in the
   same milestone. The port must not add a size or weight rule (C-17).
3. **F-8** has no runtime enforcement that the local engine matches the network; a
   misconfigured node forks silently. A startup parameter-fingerprint check is a
   non-consensus hardening candidate.
4. **F-2 / F-5** are port-parity requirements; they must be stated in the C++ spec as
   “ignore version” and “accept prefix decoding”.
5. Fork choice, block-size limits and version semantics remain unimplemented by design
   (§15 of the P1 document).

## 8. What was not changed

No production file was modified. No consensus rule, parameter, serializer, hash, wallet
format, RPC method or network message changed. The P0 corpus (`test/vectors/`) is
untouched. The only additions are this document and `findings_regression.rs`.
