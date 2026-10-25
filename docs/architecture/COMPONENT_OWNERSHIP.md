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
| Block header and Merkle root | `src/consensus/block.rs` | `kernel/src/header.cpp`, `kernel/src/merkle.cpp` | P3 | Header slice done in P3.1B: the 107-byte preimage (C-3) and `validate_header_identity`. Leaf-level Merkle root (C-5) done in P3.2B: `zk::merkle_root` over 32-byte leaves. The transaction-level leaves of `Block::compute_merkle_root`, the claimed-root comparison (B-1/B-14), header hashing and PoW dispatch (C-4) are not started |
| Difficulty retarget | `src/consensus/difficulty.rs` | `kernel/src/difficulty.cpp` | P3 | Done in P3.0; reproduces F-6 and F-11, diverges deliberately on F-7 |
| Proof of work | `src/consensus/pow.rs` | — | P3 | Not started |
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
| Conformance runner protocol | `kernel/conformance/main.cpp` | Owns the 24 verbs and `SUMMARY` output | Stable |
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
