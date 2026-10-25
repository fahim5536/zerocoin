# Migration roadmap

Status: **snapshot** as-built at commit `e8fda7e` (2026-10-18), written during
P2.1. Records where the migration stood at that commit, what would close the one
open item, and the conditions under which every temporary compatibility surface
is removed. P2.1 created no service and started no phase.

> **Current status (P2.11 addendum, 2026-10-23).** G2c was closed in P2.10 and the
> C++ verification backend is integrated into the C++ kernel. The executed P2
> result is **22/22** with one named deferral (`ledger.sighash.signature_der`);
> the differential fixture measures **121 cases** (groups V1–V8) and the P0
> corpus stays at **117 cases** — two different artifacts. §1–§8 below are the
> `e8fda7e` record and are preserved as history. §9 is the operative P3 gate; its
> criterion 3 is now satisfied by closure. The shipped node remains Rust-based
> and P3 has not started.

> **M-F1 addendum (2026-10-23).** The untrusted-height defect F-1 is fixed on the Rust
> side: `Chain::connect_block` validates the chain id and height before it asks for the
> difficulty schedule, so an unindexable height returns the existing `BadHeight` error
> instead of reading `blocks[height - 1]`, and the panic-based regression test is replaced
> by typed-error tests. This is a non-consensus stability fix: no parameter, vector,
> serializer, hash, protocol message or acceptance rule changed, the 117-case P0 corpus
> and the 121-case differential fixture are untouched, and `HEAD` still ships a Rust-only
> node. The C++ half of the parity claim was **not** delivered — the kernel has no block
> or chain module, so F-1's disposition is not restated as "identical" (see §8 and
> `CPP_PORT_REQUIREMENTS.md` §10) — and P3 is still not started.

> **P3.0 addendum (2026-10-23).** P3 has started with exactly **one** component. The
> **difficulty retarget** port (`kernel/src/difficulty.cpp`, mirroring the owner
> `src/consensus/difficulty.rs`) is delivered with 16 focused tests and a new
> `kernel_p3_conformance` target that replays the six corpus cases `g1_conformance.py`
> names as deferred to G3, expanded to 18 fixture cases, against
> `source_commit 7cb9017c`. The other seven P3 rows — header and Merkle, proof of work,
> reward, anchors, params, genesis — are **not** started, and P4 (`connect_block`, chain
> replay) was not pulled forward. No vector changed, so the 117-case P0 corpus, the
> 121-case differential fixture, G1 28/28 and P2 22/22 are untouched. F-1 remains
> **deferred**, not identical: the typed height rejection (C-29) still needs a block
> module.

> **P3.1B addendum (2026-10-23).** P3 gains its second derived implementation, and it is
> deliberately a slice: `kernel/src/header.cpp` ports the **107-byte header preimage**
> (C-3) and **`Block::validate_header_identity`** from the owner `src/consensus/block.rs`,
> with 13 focused tests and a new `kernel_p31_conformance` target that replays the 19
> committed P3.1A cases in `test/p31-vectors/chain/` against `source_commit 2ea27f4a`.
> Header hashing and PoW engine dispatch (C-4), the Merkle root (C-5), a header decoder,
> reward, anchors, params and genesis are **not** delivered, and P4 (`connect_block`, chain
> replay) was not pulled forward — so F-1 remains **deferred**, not identical: the kernel
> now reproduces the identity rule and its chain-before-height precedence, but has no chain
> that could read a difficulty schedule from an unvalidated height. No historical fixture,
> vector or gate expectation changed; the new suite is one additive `add_test` entry in a
> ctest set the existing gate scripts already run whole.

> **P3.2B addendum (2026-10-24).** P3 gains its third derived implementation, and it is the
> Merkle slice the P3.1B addendum listed as not delivered: `kernel/src/merkle.cpp` ports the
> **leaf-level Merkle root (C-5)** — `zk::merkle_root(const Hash256*, std::size_t) noexcept`
> over the owner's `merkle_root` in `src/consensus/block.rs` — with 10 focused tests and a
> new `kernel_p32_conformance` target that replays the 20 committed P3.2 cases in
> `test/p32-vectors/chain/merkle_root.json` against `source_commit b71d769`. The corpus was
> generated first, by the Rust exporter, so every expected root is a value the shipping Rust
> reference produced; none is transcribed or hand-calculated. Header hashing and PoW engine
> dispatch (C-4), a header decoder, the transaction-level leaves of
> `Block::compute_merkle_root` and the claimed-root comparison (B-1/B-14), reward, anchors,
> params and genesis are **not** delivered, and P4 (`connect_block`, chain replay) was not
> pulled forward — so F-1 remains **deferred** and C-29's obligation is still P4's. No
> historical fixture, vector or gate expectation changed; the new suite is one additive
> `add_test` entry in a ctest set the existing gate scripts already run whole.

> **P3.3B addendum (2026-10-25).** P3 gains its fourth derived implementation, and it is the
> slice the P3.2B addendum named as undelivered: `kernel/src/merkle.cpp` now also ports
> `Block::compute_merkle_root` (`src/consensus/block.rs:120`) as
> `zk::merkle_root_from_transactions(const Transaction*, std::size_t)`, composing the P1
> `Transaction::txid()` (C-2) with the P3.2B `zk::merkle_root` (C-5) — map each transaction to
> its own id, in order, then apply the leaf rule. It owns no new consensus rule and introduces
> no `Block` type, no ordering, sorting, deduplication, re-encoding or count limit of its own;
> the composition is the two existing rules wired together. It is backed by 8 focused tests in
> `kernel/tests/test_merkle.cpp` and a new `kernel_p33_conformance` target that replays the 22
> committed cases in `test/p33-vectors/chain/merkle_root_from_txs.json` against
> `source_commit b71d769`, re-deriving every transaction id and every root through
> `test/harness/zro_vectors.py` before the runner is invoked and checking the id-to-leaf
> mapping through the runner's `leaf_txids_hex` output. The corpus was generated first, by the
> Rust exporter, so every expected root is a value the shipping reference produced; none is
> transcribed, hand-calculated, or taken from C++ output. Header hashing and PoW engine
> dispatch (C-4), a header decoder, the claimed-root comparison (B-1/B-14) and the
> `RootMismatch` taxonomy, reward, anchors, params and genesis are **not** delivered, and P4
> (`connect_block`, chain replay, acceptance) was not pulled forward: a transaction-level root
> can now be computed in C++, but **no C++ code validates or accepts a block**, and this
> milestone must not be read as a block-validation path. F-1 remains **deferred** and C-29's
> obligation is still P4's. No historical fixture, vector or gate expectation changed; the new
> suite is one additive `add_test` entry in a ctest set the existing gate scripts already run
> whole, and the only documented contract departure is the composition's non-`noexcept`
> signature (§2 rules 2 and 4 of `INTERFACE_CONTRACTS.md`), which follows from the allocating
> P1 API it is built on.

Related: doc `03` (the original phase proposal), `COMPONENT_OWNERSHIP.md`,
`THREE_LANGUAGE_ARCHITECTURE.md`, `INTERFACE_CONTRACTS.md`,
`CRYPTO_BACKEND_DECISION.md`.

---

## 1. Snapshot at `e8fda7e`

Verified on 2026-10-19 against a clean tree:

| Check | Result |
|---|---|
| Repository root | `D:/Downloads/zerocoin/.publish/upstream` |
| Branch, remote | `main`, in sync with `origin/main`, 0 ahead / 0 behind |
| HEAD | `e8fda7eed9c0dd8d9b308cea38d64e38e5189fd7` — `feat(kernel): port script interpreter and sighash (P2)` |
| Working tree | clean |
| Gate `scripts/gate-g1.ps1` | `G1: PASS`, exit 0 |
| ctest | 3/3 (`kernel_unit`, `kernel_conformance`, `kernel_p2_conformance`) |
| Kernel unit tests | 108 run, 0 failed |
| G1 corpus replay | 28/28 cases against `source_commit 7cb9017c…` |
| P2 corpus replay | 21/21 replayed, 2 deferred (G2c), corruption self-check rejected 21/21 |
| Rust suite | 263 passed, 0 failed across 7 targets |
| P0 verifier | `PASS 112  ANCHOR 5  SKIP 0  FAIL 0` (117 cases) |

Nothing in this table is restated in prose elsewhere; the gate regenerates it
(doc `03` §1 rule 6).

---

## 2. Phase ledger

| Phase | Scope | Gate | Status |
|---|---|---|---|
| **P0** | Harness, corpus capture from Rust | G0 | **Complete** — 117 cases, `source_commit` recorded |
| **P1** | Hex, hash, varint, `uint256`, transaction | G1 | **Complete** — 28/28, 108 unit, F3/F4/F19 covered |
| **P2** | Script, sighash, signature verification | G2 | **Partial** at this snapshot — script and sighash complete; ECDSA blocked as G2c. Closed in P2.10: 22/22 with one signing deferral |
| **P2.1** | Backend investigation, three-language architecture | none (documentation) | **Complete in this change** |
| **P2.2–P2.10** | Backend evidence, provenance, integration, conformance, gate closure | G2 | **Complete** — CB-1…CB-4 RESOLVED, CB-5 CLOSED; G2c: GO (`CRYPTO_BLOCKER_REGISTER.md` §6) |
| **P3** | Header, Merkle, difficulty, PoW, reward, anchors, params, genesis | G3 | In progress — P3.0 delivered difficulty; P3.1B delivered the header preimage and identity rule; P3.2B delivered the leaf-level Merkle root; P3.3B delivered the transaction-level Merkle root (PoW, reward, anchors, params, genesis, and the claimed-root comparison plus the block acceptance layer that consumes Merkle remain) |
| **P4** | UTXO apply, `connect_block`, storage read | G4 | Not started |
| **P5** | Storage write, P2P, RPC, wallet, keystore, CLI | G5 | Not started |
| **P6** | Differential soak | G6 | Not started |
| **P7** | Fuzzing, sanitizers, CI, packaging | G7 | Not started |
| **P8** | Cutover decision | G8 | Not started |

P2 cannot be declared complete while G2c is open. The two deferred cases are the
only evidence needed to see that: `ledger.script.p2pkh_spend_accepted` and
`ledger.sighash.signature_der` require a curve backend by name.

> **Superseded by P2.10 (2026-10-23).** G2c is closed and P2 is complete. Of the
> two cases named above, `ledger.script.p2pkh_spend_accepted` is replayed against
> the real verifier; `ledger.sighash.signature_der` remains deferred for
> **signing** (C-52), by name and counted (`deferred=1`).

---

## 3. G2c closure plan

| Step | Action | Evidence |
|---|---|---|
| 1 | Obtain authorisation for one acquisition path (`CRYPTO_BACKEND_DECISION.md` §11) | The authorising brief, quoted in the phase document |
| 2 | Vendor the pinned archive with `LICENSE`, `SHA256SUMS`, `ORIGIN` | Hashes match; tree builds offline |
| 3 | Add `kernel/cmake/Secp256k1.cmake` and a façade under `kernel/src/` that implements `SigVerifier` by parsing and verifying **without normalising `s`** | Wrapper has no C types in its public header and no `normalize` call |
| 4 | Add the SEC1, DER, prehash, boundary and high-S vectors from the compatibility matrix | New vectors cite a Rust `source_commit` |
| 5 | Remove `ledger.script.p2pkh_spend_accepted` from the deferral list; replay 22/23 | `p2_conformance.py` prints exactly one deferral, by name |
| 6 | Add a test proving a high-S signature is **rejected**, matching the reference, and that the low-S original verifies | Test fails if normalisation is ever added |
| 7 | Record that `ledger.sighash.signature_der` stays deferred because it needs **signing**, and close it only under a separate decision about a test-harness signer | Deferral reason names signing, not verification |
| 8 | Run the full gate; record counts in the phase document | G1 28/28, P0 117 unchanged, Rust 263 unchanged |

Entry conditions: an explicit authorisation to fetch, **and** a revised wrapper
plan that drops the normalisation step, **and** the acceptance suite of
`CRYPTO_BACKEND_READINESS.md` §4. The current plan meets none of the last two,
which is why P2.2 recorded NO-GO. Exit condition: every row of
`CRYPTO_BACKEND_DECISION.md` §9 passes, the kernel's dependency set contains
exactly one third-party library, and the only remaining deferral is
`ledger.sighash.signature_der` for signing.

If the authorisation never arrives, G2c stays open, the deferral list stays
non-empty, and the kernel keeps failing closed. That is a valid steady state; it
is not a signature-compatibility claim.

> **Executed in P2.3–P2.10 (2026-10-23).** Authorisation arrived; steps 1–6 were
> executed and step 7 is recorded as the standing single deferral. The exit
> condition is met: every row of `CRYPTO_BACKEND_DECISION.md` §9 passes, the
> kernel's dependency set holds exactly one third-party library, and the only
> remaining deferral is `ledger.sighash.signature_der` for signing. The step 8
> counts are re-measured in every gate: G1 28/28 and P0 117 unchanged, Rust suite
> grown from 263 to 287 **additive** tests (`CRYPTO_BLOCKER_REGISTER.md` §6). The
> steady state described above did not occur.

---

## 4. Amendment to gate G2's wording

Doc `03` §4 states the P2 exit gate as: *"Signatures produced by Rust verify in
C++ and vice versa; the DER encoding and low-S normalisation match."*

The second clause is satisfiable, but not in the sense the original wording
suggests. The reference performs no normalisation **and it rejects high-S**:
`k256-0.13.4/src/ecdsa.rs:201-208` returns an error before the verification
arithmetic. `src/crypto/secp256k1.rs` has no check of its own only because the
check lives one layer down. Doc `08` §6's earlier reading — "no low-S rule" — was
wrong (`CRYPTO_BACKEND_READINESS.md` §2 H1).

"Low-S normalisation match" therefore means: **neither side normalises, and both
reject `s > n/2`.** The gate is read as:

> Signatures produced by Rust verify in C++, and signatures produced by the test
> harness verify in Rust. Strict DER parsing matches. Both reject a high-S
> signature and neither normalises it.

This is the only amendment. It does not relax the gate; it makes the gate
describe the reference instead of an assumption about the reference. The gate is
still unmet until G2c closes, because no C++ verification exists.

> **Superseded by P2.10 (2026-10-23).** C++ verification exists and the amended
> gate is met with executed evidence: 22/22 conformance, 121/121 differential
> matches with two documented adapter-load-bearing rows, high-S rejected on both
> sides and no normalisation added.

---

## 5. Temporary compatibility register

Every entry exists for a stated reason and has an owner and a removal condition.
This is the single list; a new temporary surface that is not here is a review
failure.

| # | Surface | Reason it exists | Removal condition | Owner |
|---|---|---|---|---|
| T1 | `TxSigChecker` with a null `SigVerifier` returns `false` | Fail closed when no verifier is supplied. The original reason — no backend exists — ended in P2.10; the null path is now a defensive guard | `TxSigChecker(..., nullptr)` call sites retire once every script test runs against the real verifier; the fail-closed behaviour stays | Kernel |
| T2 | Deferred case `ledger.sighash.signature_der` | It needs RFC 6979 **signing**; the runner is verify-only (C-52). The verification case `ledger.script.p2pkh_spend_accepted` was re-enabled in P2.10 | Only under a separate signing decision outside the kernel; **not** by closing G2c | Kernel tools |
| T3 | The deferral list in `p2_conformance.py` | Makes the gap visible in code and in output | Deleted when empty | Kernel tools |
| T4 | The C++ kernel itself | Compatibility proof for a possible cutover | G8: ship, keep as candidate, or delete `kernel/` | Maintainers |
| T5 | Doc `03`'s proposed `cpp/` layout | Historical plan written before code existed | Superseded in writing by `THREE_LANGUAGE_ARCHITECTURE.md` §9; no code move | Documentation |
| T6 | Single-host PowerShell gate | Windows is the development host | Replaced by CI in P7; the gate must keep the same exit-code contract | Build engineering |

Not temporary, and therefore never removed as "cleanup": the G1 and P2 wrappers,
the corpus, the gate, the ownership table, and the Rust oracle. Removing those
removes the proof.

---

## 6. Removal criteria by phase

| Phase | What may be removed afterwards | Precondition |
|---|---|---|
| P2 (G2c) | T1, T2, T3 | §3 complete |
| P3 | Nothing — the phase adds consensus modules only | G3 green |
| P4 | The read-only storage shim, if one is introduced for replay | G4 reproduces tip, state root, subsidy and UTXO count at every height |
| P5 | Any dual-write or migration shim for chain/wallet files | Cross-open both ways and the seed/key/address/spend checks in G5 |
| P6 | Temporary divergence logging, once no divergence has been seen for 14 days | G6 |
| P7 | The single-host gate, replaced by CI on three platforms | G7 |
| P8 | The C++ tree, if the decision is "archive" | G8 written record. Rust is untouched by construction |

A removal is only allowed when the gate that covered the surface is green in the
same change, and when the corresponding line in §5 is deleted in that change.

> **P2.10 removal record.** T2's verification half was removed when G2c closed:
> `ledger.script.p2pkh_spend_accepted` left the deferral list. T1, T2's signing
> case and T3 remain live surfaces.

---

## 7. Rollback

- P0–P2 touch no shipped artefact. Rollback is `git revert`; Rust is untouched.
- P3–P4 add a library. Rollback is deleting the new sources and their tests; the
  new library is not linked by any shipped binary.
- P5 introduces a second binary. Rollback is "do not ship it"; the Rust binary
  stays the release. T4 still applies.
- P6–P8 have no automatic rollback for a released C++ node. This is why G6 is a
  14-day soak and G8 is a written decision rather than a commit.
- Because the chain has no reorganisation path (F1), a consensus defect found
  after cutover cannot be repaired by rolling back a few blocks. This asymmetry
  is the reason the gates are strict and the corpus is untouched.

---

## 8. Open items and risks

| Item | Impact | Owner | Exit |
|---|---|---|---|
| G2c (closed in P2.10) | No longer open: C++ verification exists. Kept as history | Maintainers | `CRYPTO_BLOCKER_REGISTER.md` §6 — CB-5 CLOSED, G2c: GO |
| P2.2 NO-GO (superseded by P2.10) | The P2.2 plan normalised high-S; it was withdrawn, not implemented, and the wrapper reproduces the reference | Maintainers | `CRYPTO_BACKEND_DECISION.md` §15 |
| F-1 untrusted-height panic in Rust `connect_block` | **Closed on the Rust side in M-F1 (2026-10-23):** `height > next_height()` no longer reaches the history index on a retargeting network; it returns `BadHeight`. Remote reachability remains **not** established. The C++ counterpart stays open with P3 | Maintainers | `FINDINGS_TRIAGE.md` F-1 (M-F1 record); C++ side needs the P3 block module |
| F-3 block-size policy | Decided in P2.11: no consensus size rule; the 4 MiB cap is transport-only | Documentation | `FINDINGS_TRIAGE.md` F-3, `CPP_PORT_REQUIREMENTS.md` §10 |
| Doc `03` G2 wording (low-S) | A literal reading is ambiguous about normalisation | Documentation | §4 amendment recorded |
| High-S rule lives in `k256`, not in ZeroCoin tests | A dependency update could change consensus unnoticed | Maintainers | Add Rust-side high-S vectors; pin `k256` exactly (readiness §7 R1/R2) |
| `kernel/` vs `cpp/` | Reviewers may look for the wrong path | Documentation | `THREE_LANGUAGE_ARCHITECTURE.md` §9 |
| CMake floor 3.20 vs doc `03` ≥3.25 | A strict reader sees a mismatch | Build engineering | Raise the floor or amend doc `03` |
| Stale comment in `kernel/CMakeLists.txt` line 2 (`03-target-architecture.md`) | Misleading reference | Documentation | Fixed with the next code change |
| Gate is single-host | MSVC and POSIX builds are unproven | Build engineering | G7 CI matrix |
| No sanitizers yet | Undefined behaviour in the kernel would be invisible | Build engineering | G7 |
| R9 residual risk | Backend mismatch could split the network if it ever validates | Maintainers | Compatibility matrix plus soak |

None of these is a reason to change a consensus rule.

---

## 9. P3 entry checklist

P3 may start only when all of the following are true:

1. The repository is clean and `HEAD == origin/main`.
2. `scripts/gate-g1.ps1` exits 0 with the counts in §1 unchanged.
3. G2c is either closed (§3) or the maintainers have explicitly accepted that
   G3's spend-bearing block cases will remain unprovable until it is.
4. The P3 scope is taken from doc `03` §4 and no extra module is added.
5. The P3 vectors are captured from a named Rust commit before any C++ code is
   written.
6. The ownership rows for block, difficulty, PoW, reward, anchors, params and
   genesis are already in `COMPONENT_OWNERSHIP.md` §2.1 (they are).

If G2c is still open, the honest P3 scope is: header, Merkle, difficulty,
subsidy, anchors, params and genesis — everything whose vectors do not require a
signature — with the gate explicitly reporting the deferred spend cases. That is
a maintainer decision, not a default.

> **P2.11 note (2026-10-23).** Criterion 3 is satisfied by closure, not by
> waiver: G2c is GO, so the reduced-scope branch above does not apply. Criterion
> 4 still takes P3 scope from doc `03` §4 — where the header preimage is now
> stated as the measured **107 bytes** (corrected in P2.11; it previously read
> 108). Criteria 1, 2, 5 and 6 are unchanged and must be re-verified when P3
> starts.

---

## 10. Boundary of this milestone

P2.1 ends with this document set and a verified commit. It does not:

- add a dependency or a backend;
- add, remove or modify a vector;
- change a script, sighash, consensus or serialization rule;
- create a Go service;
- start P3.

The next milestone starts from §9, not from here.
