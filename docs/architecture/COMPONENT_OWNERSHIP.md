# Component ownership

Status: **snapshot** as-built at commit `e8fda7e` (2026-10-18), written during
P2.1. This document assigns exactly one authoritative owner per subsystem. It
changes no code, no vector and no consensus rule.

> **Current status (P2.11 addendum, 2026-10-23).** Rows whose status names a later
> milestone are marked inline (ECDSA: P2.10). Ownership has **not** moved: the
> Rust crate remains the owner of every consensus rule and the shipped node
> remains Rust-based; the C++ kernel is a derived implementation. P3 rows are
> still "Not started".

> **M-F1 addendum (2026-10-23).** F-1 is fixed inside the Rust owner and ownership is
> unchanged: `Block::validate_header_identity` is now the single implementation of the
> chain-id and height checks, called by `validate_structure` and — for the ordering fix —
> by `Chain::connect_block` before `required_bits` is reached. This is a non-consensus
> ordering change inside existing modules: no subsystem changed owner and no phase moved.
> The C++ column below still reads "—" for "Block header and Merkle root" (P3) and
> "`connect_block` and chain replay" (P4), so F-1 has no tested C++ counterpart and the
> port-side guard (`CPP_PORT_REQUIREMENTS.md` C-29) remains a P3 obligation.

> **P3.0 addendum (2026-10-23).** The first P3 derived implementation is registered:
> **difficulty retarget**, mirroring the owner row `src/consensus/difficulty.rs`.
> The C++ column is `kernel/src/difficulty.cpp`; the gate that proves equivalence is
> `kernel_p3_conformance` (`kernel/tools/p3_conformance.py`, 18 cases derived from the
> six corpus cases `g1_conformance.py` defers to G3) plus 16 focused unit tests. The
> port reproduces **F-6** (the magnitude-dependent multiply/divide order) and **F-11**
> (the inclusive big-endian comparison), and diverges deliberately only on **F-7**
> (`required_work` reports the `Uint256::MAX` trap instead of dividing by zero; it is
> not on the acceptance path). Ownership has not moved and no phase moved: Rust is
> still the oracle and the vector file was not touched. This addendum supersedes the
> single clause in the P2.11 addendum that all P3 rows are "Not started"; the other
> seven P3 rows are unchanged, and F-1 still has no tested C++ counterpart.

> **P3.1B addendum (2026-10-23).** The second P3 derived implementation is registered:
> the **block-header slice** of the owner row `src/consensus/block.rs` — the 107-byte
> header preimage (C-3) and `Block::validate_header_identity` — in
> `kernel/src/header.cpp`. The gate that proves equivalence is
> `kernel_p31_conformance` (`kernel/tools/p31_conformance.py`, which replays all 19
> committed P3.1A cases in `test/p31-vectors/chain/` against `source_commit 2ea27f4a`)
> plus 13 focused unit tests. Only that row's header half is covered: the **Merkle root
> (C-5) is not implemented**, and neither is header hashing or the engine dispatch that
> turns the preimage plus a nonce into the block identity (C-4); there is no decoder.
> F-1 still has **no tested C++ counterpart** in the sense that mattered: what the kernel
> reproduces is the identity rule and its chain-before-height precedence, not
> `connect_block` refusing to read the difficulty schedule from an unvalidated height,
> which is C-29's remaining obligation and belongs to P4. Ownership has not moved and no
> phase moved: Rust is still the oracle, and the P0 corpus, the P3.1A fixtures and the
> 121-case differential fixture were not touched. This addendum supersedes the clause in
> the M-F1 addendum that the header row has no C++ module and no structured-error type.

> **P3.2B addendum (2026-10-24).** The third P3 derived implementation is registered, and
> it is the other half of the same owner row: the **leaf-level Merkle root (C-5)** of
> `src/consensus/block.rs`, in `kernel/src/merkle.cpp` as
> `zk::merkle_root(const Hash256*, std::size_t) noexcept`. The gate that proves equivalence
> is `kernel_p32_conformance` (`kernel/tools/p32_conformance.py`, which replays all 20
> committed P3.2 cases in `test/p32-vectors/chain/merkle_root.json` against
> `source_commit b71d769`; the behavior itself entered `zerocoin/src` at
> `reference_commits.merkle_introduced`, `e464695f`) plus 10 focused unit tests. The port
> reproduces the whole leaf contract — the 17-byte empty tag, the single-leaf passthrough,
> the untagged `sha256d` over exactly 64 raw internal bytes, odd-node duplication **at every
> level**, and order preservation — and it deliberately carries **no leaf-count limit**,
> because `MAX_BLOCK_TRANSACTIONS` is a block rule enforced outside `merkle_root`. What is
> *not* covered: the transaction-level leaves of `Block::compute_merkle_root` (that needs a
> C++ transaction-id surface this milestone was told not to invent), the claimed-root
> comparison B-1/B-14, header hashing and the engine dispatch that turns a preimage plus a
> nonce into a block identity (C-4). `test/harness/zro_vectors.py::merkle_root` is wired as
> an independent verifier of the corpus at replay time; it is not the origin of any
> published value. Ownership has not moved and no phase moved: Rust is still the oracle, and
> the P0 corpus, the P3.1A fixtures, the P3.2 fixture exporter's inputs and the 121-case
> differential fixture were not touched. F-1 remains **deferred** and C-29's remaining
> obligation is still P4's. This addendum supersedes the clause in the P3.1B addendum that
> "the **Merkle root (C-5) is not implemented**": the leaf-level rule now is.

> **P3.3B addendum (2026-10-25).** The fourth P3 derived implementation is the composition
> the P3.2B addendum listed as *not* covered, and it stays inside the same owner row and the
> same two modules: `zk::merkle_root_from_transactions(const Transaction*, std::size_t)` in
> `kernel/src/merkle.cpp` ports `Block::compute_merkle_root` (`src/consensus/block.rs:120`)
> by mapping each transaction to the **already-owned** P1 `Transaction::txid()` (C-2) and
> handing that ordered list to the **already-owned** P3.2B `zk::merkle_root` (C-5). It owns no
> new rule: it introduces no hashing, no byte-order reinterpretation, no ordering change and
> no count limit, and the milestone boundary forbade a `Block` type, so the pair of existing
> rules is simply wired together. The gate is `kernel_p33_conformance`
> (`kernel/tools/p33_conformance.py`, which replays all 22 committed cases in
> `test/p33-vectors/chain/merkle_root_from_txs.json` against `source_commit b71d769`; the
> composition itself entered `zerocoin/src` at `reference_commits.compute_merkle_root_introduced`
> and `reference_commits.txid_introduced`, both `e464695f`) plus 8 focused unit
> tests in `kernel/tests/test_merkle.cpp`. `test/harness/zro_vectors.py` is wired as an
> independent verifier of the corpus at replay time — `tx_from_json`, `tx_serialize`,
> `tx_txid` and `merkle_root` re-derive every leaf and every root from the published inputs —
> and it is not the origin of any published value, nor is the C++ kernel. What is *not*
> covered, and is the reason this row does not move to "Done": the claimed-root comparison
> against a header's committed `merkle_root` (B-1/B-14) and the `RootMismatch` taxonomy, a
> header decoder, header hashing and the engine dispatch (C-4), any `Block` abstraction, and
> `connect_block` / chain replay / acceptance (P4). A root can now be computed from
> transactions; **nothing in C++ validates or accepts a block**, and this milestone must not
> be read as a block-validation path. Ownership has not moved and no phase moved: Rust is
> still the oracle, and the P0 corpus, the P3.1A fixtures, the P3.2 corpus, the P3.3
> exporter's inputs and the 121-case differential fixture were not touched. F-1 remains
> **deferred** and C-29's remaining obligation is still P4's. This addendum supersedes the
> clause in the P3.2B addendum that the transaction-level leaves of
> `Block::compute_merkle_root` need "a C++ transaction-id surface this milestone was told not
> to invent": that surface has existed since P1, and is what this slice used.

> **P4.0 addendum (2026-10-25).** The fifth P3/P4 derived implementation is C-4, and it is
> registered here for the first time: this change set is the documentation pass for work that
> landed without one. `kernel/src/pow.cpp` with `kernel/include/zerocoin/pow.h` and
> `kernel/src/pow_internal.h` ports the owner's `TrivialEngine` and `ScratchPadEngine` over the
> P3.1B 107-byte preimage, reusing the already-owned compact-target decode (C-8) and the
> inclusive big-endian `hash <= target` comparison (C-24, F-11) rather than re-deriving either.
> The nonce stays outside the preimage and enters only through the engine, so the digest a
> header commits to is unchanged. `zk::engine_for_id` resolves nothing for an identifier other
> than 0 or 1, so no untrusted byte is ever dispatched onto an engine. Cell count follows
> Rust's truncating budget division; both shipped profiles are powers of two, so the
> mask-versus-remainder branch is pinned only by a test-local differential and is **not** backed
> by any committed vector — recorded here rather than smoothed over. Mining is not in the
> production API; the nonce search lives in the conformance runner and replays `verify_pow`
> (C-25). The gate is `kernel_p4_conformance` (`kernel/tools/p4_conformance.py`, which replays
> all 11 committed cases in `test/vectors/pow/engines.json`; `g1_conformance.py` does not load
> that file because it walks an explicit four-file allowlist) plus 27 tests in
> `kernel/tests/test_pow.cpp`, with **zero** deferred cases and no divergence allowance.
> Ownership has not moved: Rust is still the oracle. Header hashing now exists, but there was
> still no claimed-root comparison at that milestone, so nothing consumed a digest as a
> validation verdict — and that gap is what P4.1B below closes.

> **P4.1B addendum (2026-10-30).** The sixth derived implementation is the comparison the
> P3.3B addendum listed as *not* covered, and it is the first kernel function to return a block
> validation verdict: `zk::compare_claimed_merkle_root(const BlockHeader&, const Transaction*,
> std::size_t)` in `kernel/src/block.cpp` ports rule B-14 (`src/consensus/block.rs:216`–`219`)
> and nothing else — compute the root with the already-owned P3.3B composition, compare the
> header's committed `merkle_root` byte for byte in internal order, return `kNone` or the new
> `BlockErrorKind::kRootMismatch`. The variant is the third rejection kind the kernel declares
> (C-14), appended rather than inserted so `kNone` keeps 0 and no existing value moves; that its
> number happens to equal Rust's `RootMismatch` discriminant is a coincidence, not a contract —
> the kernel's numbering is its own declaration order. It is a unit variant, which is why the
> payload question is answered per variant by `block_error_kind_has_payload` rather than per
> struct. It deliberately owns no *ordering*: B-1…B-13 before it and
> B-15 after it are not ported, there is no `Block` type and no `validate_structure`, so C-13's
> "same first failing rule" obligation is met for this rule in isolation and not for a block.
> The gate is `kernel_p41_conformance` (`kernel/tools/p41_conformance.py`, which replays all 30
> committed cases in `test/p41-vectors/chain/claimed_merkle_root.json` against
> `source_commit b71d769`; the comparison, the `RootMismatch` variant and `validate_structure`
> all entered `zerocoin/src` at `reference_commits.*`, `e464695f`) plus 14 tests in
> `kernel/tests/test_block.cpp`. Every expected outcome is the `Result` that the shipping Rust
> validator itself returned — the P4.1A exporter panics on any other variant — so no verdict in
> that corpus was computed by C++ or written by hand; `test/harness/zro_vectors.py` re-derives
> every leaf, root and the digest comparison independently at replay time and is not the origin
> of any published value. Its one deferred expected key is `guard_before_comparison`, on the two
> `boundary` cases only, because B-8 `NoTransactions` rejects an empty list before B-14 and the
> validator therefore has no comparison verdict to publish there. What is *not* covered, and is
> the reason no row moves to "Done": the other twelve `validate_structure` rules, the ten
> undeclared `BlockError` variants, `connect_block`, chain replay, UTXO effects and acceptance.
> **A root can now be compared to a claim in C++; nothing in C++ validates or accepts a block**,
> and this milestone must not be read as a block-validation path. Ownership has not moved and no
> phase moved: Rust is still the oracle, and the P0 corpus, the P3.1/P3.2/P3.3 fixtures and the
> 121-case differential fixture were not touched. F-1 remains **deferred** and C-29's remaining
> obligation is still P4's. This addendum supersedes the clause in the P3.3B addendum that the
> claimed-root comparison and the `RootMismatch` taxonomy are not covered: they are, for this
> one rule.

> **P4.2A addendum (2026-10-30; fixtures only, no derived implementation).** Ownership has not
> moved, no phase moved, and **no C++ component is registered by this milestone**. What is added
> is an oracle: the `p42_*` exporter inside
> `zerocoin/tests/export_baseline_vectors.rs` now generates
> `test/p42-vectors/chain/block_structure.json` (34 cases) for the owner row
> `src/consensus/block.rs`, covering rules B-3 … B-15 and their relative order. The exporter is
> the sole origin of every expected verdict in that file: it constructs each block from a declared
> construction intent, calls the shipping Rust `Block::validate_structure` **directly** with the
> seven published context arguments, and panics if the returned variant, its payload fields or the
> violated-rule set differ from that declaration. Design-contract predictions are therefore
> inputs to the export, never fields of the corpus, and no expected value is computed by Python,
> transcribed from documentation or typed by hand. `test/harness/zro_vectors.py` re-derives
> published serializations, transaction ids, leaf order, Merkle roots, coinbase flags, PoW status,
> rejection payloads and validation contexts — byte re-derivation only, never a verdict. Two
> relative orders are recorded as **not** owned by any fixture: (B-8, B-9) is non-representable
> because `transactions.is_empty()` and `transactions.len() > 2000` are mutually exclusive, so no
> input distinguishes them and no `.pair_08_09` case exists; (B-13, B-14) is representable but
> unfrozen. Both live in the manifest as `deferred_pairs`, and neither is claimed to be proven.
> `kernel/src/block.cpp` gains nothing: still no header decoder, no `Block` type, no
> `validate_structure`, no B-15 rule, no acceptance path; there is no
> `kernel/tools/p42_conformance.py` and no `kernel_p42_conformance` ctest entry, and
> `run_vectors.py` reports the group as 34 SKIP with exit 1 because it registers no verifier for
> the namespace. **The differential against C++ is P4.2B; nothing here is a parity claim.** The
> P0 corpus, the P3.1/P3.2/P3.3 fixtures, the P4.1 corpus and the 121-case differential fixture
> were not touched, and F-1 remains **deferred**.


Related: `THREE_LANGUAGE_ARCHITECTURE.md` (what each language may do),
`INTERFACE_CONTRACTS.md` (the interfaces owners expose),
`MIGRATION_ROADMAP.md` (when derived implementations are removed), and
`CRYPTO_BACKEND_DECISION.md` (G2c — closed in P2.10; Rust remains the owner).

---

## 1. The rule and the vocabulary

Three words are used with fixed meanings throughout `docs/architecture/`:

| Term | Meaning |
|---|---|
| **Authoritative owner** | The component whose output defines correct behaviour. It is the oracle. A semantic change may originate only here. |
| **Derived implementation** | A second implementation that must reproduce the owner's output. Byte equality is required wherever bytes are consensus (doc `03` §1 rule 4); for protocol messages, acceptance by the owner is sufficient. |
| **Consumer** | Code that uses an owner's interface without owning its semantics. A consumer may not re-serialize or re-validate what it reads. |

The rule: **every subsystem has exactly one authoritative owner.** Ownership is
not exclusive permission to implement — a derived implementation is allowed, but
only where a phase grants it and a gate proves equivalence. Today the owner of
every consensus rule is the Rust crate, because the Rust node is the reference
and the only released binary (doc `03` §1 rule 1).

A derived implementation is never allowed to become the oracle by accident. If
Rust and C++ disagree, the Rust output wins and the C++ gate fails; the
disagreement is recorded as a finding, not resolved by editing the vectors.

---

## 2. Kernel ownership (consensus-critical)

Every row exists in doc `01` §2.3 and doc `03` §3.1. The C++ column names the
file the phase produced or will produce; "—" means no C++ module exists yet.

### 2.1 Primitives and ledger

| Subsystem | Authoritative owner (Rust) | Derived implementation (C++) | Phase | Status at `e8fda7e`, unless dated inline |
|---|---|---|---|---|
| SHA-256, SHA-256d, RIPEMD-160, HASH160 | `src/crypto/hash.rs` | `kernel/src/sha256.cpp`, `ripemd160.cpp`, `hash.cpp` | P1 | Done; G1 vectors |
| Hex and display order as distinct types | `src/crypto/hash.rs` | `kernel/include/zerocoin/hex.h` | P1 | Done; F3 guard |
| Minimal varint | `src/ledger/transaction.rs` | `kernel/src/varint.cpp` | P1 | Done; G1 vectors |
| Transaction codec and `txid` | `src/ledger/transaction.rs` | `kernel/src/transaction.cpp` | P1 | Done; F19 recorded |
| `uint256` and compact targets | `src/consensus/uint256.rs` | `kernel/src/uint256.cpp` | P1 | Done; G1 vectors |
| Script interpreter | `src/ledger/script.rs` | `kernel/src/script.cpp` | P2 | Done |
| Sighash preimage and digest | `src/ledger/sighash.rs` | `kernel/src/sighash.cpp` | P2 | Done |
| ECDSA verification, SEC1, DER | `src/crypto/secp256k1.rs` (`k256 0.13.4`) | `kernel/src/secp256k1_verifier.cpp` (vendored libsecp256k1 0.8.0, PRIVATE link) | P2 / G2c | Done in P2.10 — verification only, signing stays Rust/test-only; `CRYPTO_BACKEND_SELECTION_AUDIT.md` §20 |
| Block header and Merkle root | `src/consensus/block.rs` | `kernel/src/header.cpp`, `kernel/src/merkle.cpp`, `kernel/src/block.cpp` | P3 / P4.1 | Header slice done in P3.1B: the 107-byte preimage (C-3) and `validate_header_identity`. Leaf-level Merkle root (C-5) done in P3.2B: `zk::merkle_root` over 32-byte leaves. Transaction-level Merkle root (C-5) done in P3.3B: `zk::merkle_root_from_transactions`, the composition of the P1 `txid()` with the P3.2B leaf rule. Claimed-root comparison (B-1/B-14) done in P4.1B: `zk::compare_claimed_merkle_root`, the comparison of that computed root against a header's committed `merkle_root`, with the `RootMismatch` outcome. A header decoder, any `Block` type, `validate_structure` and any block acceptance path are not started; since P4.2A the twelve unported rules have a committed Rust oracle (`test/p42-vectors/`) to be diffed against, while C++ still has nothing to diff |
| Difficulty retarget | `src/consensus/difficulty.rs` | `kernel/src/difficulty.cpp` | P3 | Done in P3.0; reproduces F-6 and F-11, diverges deliberately on F-7 |
| Proof of work | `src/consensus/pow.rs` | `kernel/src/pow.cpp` | P3 / P4.0 | Done in P4.0 for C-4: both engines over the 107-byte preimage, the inclusive big-endian target comparison (C-24, F-11), and `engine_for_id` refusing any id other than 0 or 1. Mining is not in the production API — the single-threaded search from zero lives in the conformance runner (C-25) |
| Subsidy, maturity, coinbase split | `src/consensus/reward.rs` | — | P3 | Not started |
| Anchors and state-root probe | `src/consensus/immutability.rs` | — | P3 | Not started |
| Chain parameters | `src/params.rs` | — | P3 | Not started |
| Genesis construction | `src/genesis.rs` | — | P3 | Not started |
| UTXO apply and state root | `src/ledger/utxo.rs` | — | P4 | Not started |
| `connect_block` and chain replay | `src/chain.rs` | — | P4 | Not started |
| Persistent storage | `src/storage.rs` | — | P4 read / P5 write | Not started |
| Mempool admission and ordering | `src/mempool.rs` | — | P5 | Not started |
| P2P handshake and framing | `src/network/handshake.rs`, `frame.rs` | — | P5 | Not started |
| P2P message set | `src/network/message.rs` | — | P5 | Not started |
| Node service and RPC | `src/node.rs` | — | P5 | Not started |
| Wallet and keystore | `src/wallet.rs`, `src/crypto/keystore.rs` | — | P5 | Not started |
| Base58Check addresses | `src/address.rs` | — | P5 | Not started |
| Data directory resolution | `src/datadir.rs` | — | P5 | Not started |
| Session API | `src/session.rs` | — | P5 | Not started |
| Mining pool | `src/pool.rs` | — | P6 (deferrable) | Not started |

The C++ ECDSA row was, until P2.10, the only one where the *owner exists* and
the *derived implementation does not*. The kernel still exposes the two abstract
seams (`zk::SigChecker`, `zk::SigVerifier`) and still fails closed when no
verifier is supplied (`INTERFACE_CONTRACTS.md` §3), but the seam now has the
approved implementation recorded in `INTERFACE_CONTRACTS.md` §3.5. The Rust
owner remains the oracle and the only production signer; a C++ result never
updates a vector.

### 2.2 Front-ends and platforms

| Subsystem | Owner | Derived implementation | Status |
|---|---|---|---|
| Desktop wallet GUI | Rust + Slint: `src/gui.rs`, `ui/wallet.slint`, `src/bin/zerocoin_gui.rs` | **never** — doc `03` §3.3 | Shipped |
| Android native library | Rust `cdylib` (`Cargo.toml` `[lib] crate-type`) | **never before G8** — doc `03` §3.3 | Shipped |
| CLI | Rust `src/bin/zerocoin_cli.rs` | C++ at P5 (planned) | Rust only |
| Daemon binary | Rust `src/bin/zerocoind.rs` | C++ at P5 (planned) | Rust only |

The GUI is a JSON-RPC consumer. It is therefore also the first consumer that can
prove a C++ daemon is a drop-in replacement (doc `03` §3.3), but it never gains
consensus code.

### 2.3 Tooling, corpus and build

| Subsystem | Owner | Why this is the authority | Status |
|---|---|---|---|
| Golden vectors (`test/vectors/**`) | Python capture tooling: `test/harness/zro_vectors.py`, `run_vectors.py` | The bytes are generated from the Rust reference and pinned to `source_commit`; hand edits are forbidden | 117 cases (112 PASS, 5 ANCHOR) |
| G1 conformance mapping | `kernel/tools/g1_conformance.py` | Owns case selection, provenance and exit code | 28 cases |
| P2 conformance mapping | `kernel/tools/p2_conformance.py` | Owns the deferral list, provenance and corruption self-check | 22 cases + 1 deferred (signing) |
| P3 conformance mapping | `kernel/tools/p3_conformance.py` | Owns the P3 slice, the corpus classification and the corruption self-check | 18 cases (6 corpus cases) |
| P3.1 header conformance mapping | `kernel/tools/p31_conformance.py` | Owns the P3.1A corpus slice, the header field mapping, the printed deferral and the corruption self-check | 19 cases (10 preimage + 9 identity) |
| P3.2 Merkle conformance mapping | `kernel/tools/p32_conformance.py` | Owns the P3.2 corpus slice, the repeated-leaf input mapping, the 32-byte leaf gate, the independent Python cross-check and the corruption self-check | 20 cases (0–9 leaves plus edge shapes) |
| P3.3 transaction-to-Merkle conformance mapping | `kernel/tools/p33_conformance.py` | Owns the P3.3 corpus slice, the repeated-transaction input mapping, the per-leaf serialization/txid gates, the independent Python re-derivation of every id and root, the `leaf_txids_hex` mapping check and the corruption self-check | 22 cases (0–17 transactions, coinbases, order and duplicate shapes) |
| P4 proof-of-work conformance mapping | `kernel/tools/p4_conformance.py` | Owns the PoW slice of the P0 root (which `g1_conformance.py` does not load), the engine-name and id mapping, the four `pow_*` verbs and the corruption self-check | 11 cases (`test/vectors/pow/engines.json`), 0 deferred |
| P4.1 claimed-root conformance mapping | `kernel/tools/p41_conformance.py` | Owns the P4.1A corpus slice, the header-plus-repeated-transaction input mapping, the independent Python re-derivation of every leaf, root and digest comparison, the `roots_match` verdict cross-check and the corruption self-check | 30 cases (12 correct claims, 14 wrong, 2 failing-PoW, 2 empty-list boundary) + 1 deferred key (`guard_before_comparison`, B-8) |
| P4.2 block-structure expected verdicts (oracle) | `zerocoin/tests/export_baseline_vectors.rs` (`p42_*` exporter) | Every expected value in `test/p42-vectors/**` is the `Result` the shipping Rust `Block::validate_structure` returned when the exporter called it directly; the exporter panics when the returned variant, its payload or the violated-rule set differs from the fixture's declared construction intent, so no verdict is transcribed from a design document, computed by Python or written by hand | 34 cases (14 isolation, 8 boundary, 11 adjacent-pair, 1 dominance); 5 accepted, 29 rejected; 2 deferred relative orders; deterministic regeneration; **no C++ wrapper exists** |
| P4.2 corpus structural gate | `test/harness/run_vectors.py` | Dispatches by case-id namespace and registers no verifier for `chain.block_structure`, so it validates schema, manifest, ids and provenance only — it cannot disagree with a verdict because it never computes one | 34 SKIP, 0 FAIL, exit 1 by design; P0 gate unchanged |
| Conformance runner protocol | `kernel/conformance/main.cpp` | Owns the 30 verbs and `SUMMARY` output | Stable |
| Build and gate | `kernel/CMakeLists.txt`, `scripts/gate-g1.ps1`, `scripts/gate-p2-6.ps1`, `scripts/gate-p2-10-provenance.ps1` | Exit code is the verdict (doc `03` §1 rule 5) | Green |
| Rust dependency set | `Cargo.toml`, `Cargo.lock` | `k256 0.13.4` is the curve implementation actually shipped | Locked |
| Architecture records | `docs/architecture/**` | This set; decisions are recorded here, not in chat | New |
| Go services | — | No component exists; no owner until an ADR authorises one | Absent |

Note on vector ownership: Python owns the *harness and file format*; Rust owns
the *values*. A vector may only change when the Rust code changes, the capture
script is re-run, and the new `source_commit` is recorded. This is what keeps
"one source of truth for numbers" (doc `03` §1 rule 6) true for fixtures.

---

## 3. Prohibitions that follow from the map

1. **No second consensus engine.** Go may not parse, validate or serialize
   blocks, transactions, scripts or sighashes. A Go service is a client of the
   node's RPC (`THREE_LANGUAGE_ARCHITECTURE.md` §7).
2. **No hand-written elliptic-curve code.** The kernel may contain the hash
   ports because they are pinned byte-for-byte by published vectors and were
   required by P1. ZeroCoin source may never implement field arithmetic, scalar
   arithmetic, point decoding or ECDSA (doc `04` R9). The single exception is
   the pinned upstream libsecp256k1 release under `kernel/third_party/`,
   acquired and integrated per `CRYPTO_BACKEND_DECISION.md`; no ZeroCoin-owned
   file contains curve arithmetic.
3. **No derived implementation as oracle.** A C++ result never updates a vector.
   A disagreement is a C++ defect until proven otherwise.
4. **No consumer re-serialization.** If a component needs consensus bytes, it
   calls the owner; it does not rebuild them from JSON or from its own structs.
5. **No Rust deletion.** No ownership transfer removes, moves or rewrites Rust
   source (doc `03` §1 rule 3, §9). A C++ owner is added *beside* the Rust one.
6. **No unowned subsystem.** A new component without an owner row in this file
   cannot pass review.

---

## 4. Ownership lifecycle

**Registering a derived implementation.** The phase that creates it must:
name the owner row it mirrors; add the gate that proves equivalence; record any
finding (F-number) the port reproduces; and update §2 in the same change.

**Transferring semantic authority.** Requires an ADR in this directory, a gate
that runs both implementations, vector regeneration with a new `source_commit`,
and a written rollback plan. Before G8 the answer is always "authority stays in
Rust" (doc `03` §4 P8 lists the only three permitted outcomes).

**Retiring a derived implementation.** Follows
`MIGRATION_ROADMAP.md` §5: the removal criteria are written before the code is
written, and the Rust owner must still pass its own gate afterwards.

**Changing an interface.** Follows `INTERFACE_CONTRACTS.md` §12: an interface
change is a contract change and needs the owner, the vectors and both gates in
the same change.

---

## 5. Current gaps

| Gap | Consequence | Owner of the gap | Closing criterion |
|---|---|---|---|
| G2c: no C++ curve backend | Closed in P2.10 — `OP_CHECKSIG` succeeds in C++ through the approved backend; one corpus case remains deferred (signing; the runner is verify-only) | Kernel (seam) + maintainers (acquisition) | Closed: `CRYPTO_BACKEND_SELECTION_AUDIT.md` §20, `CRYPTO_BACKEND_READINESS.md` §15 |
| Go: nothing exists | No service layer; no risk yet | — | An approved ADR that names a service and its RPC dependency |
| `kernel/` vs doc `03`'s proposed `cpp/` | Path in the proposal does not match the tree | Documentation | Recorded in `THREE_LANGUAGE_ARCHITECTURE.md` §9; no code move |
| CMake floor 3.20 vs doc `03`'s ≥3.25 | The proposal is stricter than the build | Build engineering | Either raise the floor or amend doc `03`; recorded in `MIGRATION_ROADMAP.md` §8 |
| Stale comment in `kernel/CMakeLists.txt` line 2 | Points at a non-existent filename | Documentation | Closed in P2.10 §7 — the header comment was rewritten with the backend integration (commit `e4e13d4`) |

None of these gaps changes a consensus rule. The first used to be the only one
that blocked a phase; it no longer blocks one (closed in P2.10).

---

## 6. Review checklist

A change is rejected if any answer is "no":

1. Does every touched subsystem have exactly one row in §2, and is the change in
   the row's owner?
2. If a derived implementation changed, is there a gate result in the commit
   message and a vector that would have caught the change?
3. If a vector changed, was it regenerated from a named Rust commit rather than
   edited by hand?
4. If a new file implements consensus behaviour, is it in the owner's tree and
   not in a consumer's?
5. If the change is documentation, does it avoid restating a number that the
   harness generates (F11)?
