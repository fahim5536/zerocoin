# Migration roadmap

Status: **as-built** at commit `e8fda7e` (2026-10-18), written during P2.1.
Records where the migration actually stands, what closes the one open item, and
the conditions under which every temporary compatibility surface is removed.
P2.1 creates no service and starts no phase.

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
| **P2** | Script, sighash, signature verification | G2 | **Partial** — script and sighash complete; ECDSA blocked as G2c |
| **P2.1** | Backend investigation, three-language architecture | none (documentation) | **Complete in this change** |
| **P3** | Header, Merkle, difficulty, PoW, reward, anchors, params, genesis | G3 | Not started |
| **P4** | UTXO apply, `connect_block`, storage read | G4 | Not started |
| **P5** | Storage write, P2P, RPC, wallet, keystore, CLI | G5 | Not started |
| **P6** | Differential soak | G6 | Not started |
| **P7** | Fuzzing, sanitizers, CI, packaging | G7 | Not started |
| **P8** | Cutover decision | G8 | Not started |

P2 cannot be declared complete while G2c is open. The two deferred cases are the
only evidence needed to see that: `ledger.script.p2pkh_spend_accepted` and
`ledger.sighash.signature_der` require a curve backend by name.

---

## 3. G2c closure plan

| Step | Action | Evidence |
|---|---|---|
| 1 | Obtain authorisation for one acquisition path (`CRYPTO_BACKEND_DECISION.md` §11) | The authorising brief, quoted in the phase document |
| 2 | Vendor the pinned archive with `LICENSE`, `SHA256SUMS`, `ORIGIN` | Hashes match; tree builds offline |
| 3 | Add `kernel/cmake/Secp256k1.cmake` and a façade under `kernel/src/` that implements `SigVerifier` with the high-S normalisation step | Wrapper has no C types in its public header |
| 4 | Add the SEC1, DER, prehash, boundary and cross-signing vectors from the compatibility matrix | New vectors cite a Rust `source_commit` |
| 5 | Remove the two cases from the deferral list; replay 23/23 | `p2_conformance.py` prints an empty deferral list |
| 6 | Add a unit test proving a high-S signature verifies and is **not** reported as an error | Test fails if a low-S rule is ever added |
| 7 | Run the full gate; record counts in the phase document | G1 28/28, P0 117 unchanged, Rust 263 unchanged |

Entry condition: an explicit authorisation to fetch. Exit condition: every row of
`CRYPTO_BACKEND_DECISION.md` §9 passes and the kernel's dependency set contains
exactly one third-party library.

If the authorisation never arrives, G2c stays open, the deferral list stays
non-empty, and the kernel keeps failing closed. That is a valid steady state; it
is not a signature-compatibility claim.

---

## 4. Amendment to gate G2's wording

Doc `03` §4 states the P2 exit gate as: *"Signatures produced by Rust verify in
C++ and vice versa; the DER encoding and low-S normalisation match."*

The second clause cannot be satisfied as written, because **the reference
performs no low-S normalisation**. `src/crypto/secp256k1.rs` verifies with
`verify_prehash` and has no half-order check; doc `08` §6 records the finding and
its consequences.

The gate is therefore read as:

> Signatures produced by Rust verify in C++, and signatures produced by the test
> harness verify in Rust. Both accept a high-S signature; neither normalises it,
> rejects it, or reports it. Strict DER parsing matches.

This is the only amendment. It does not relax the gate; it makes the gate
describe the reference instead of Bitcoin's policy. The gate is still unmet until
G2c closes, because no C++ verification exists.

---

## 5. Temporary compatibility register

Every entry exists for a stated reason and has an owner and a removal condition.
This is the single list; a new temporary surface that is not here is a review
failure.

| # | Surface | Reason it exists | Removal condition | Owner |
|---|---|---|---|---|
| T1 | `TxSigChecker` with a null `SigVerifier` returns `false` | Fail closed while no backend exists | Replaced by a real verifier; the test asserting failure becomes a test asserting a call | Kernel |
| T2 | Deferred cases `ledger.script.p2pkh_spend_accepted`, `ledger.sighash.signature_der` | They need secp256k1 | Re-enabled when G2c closes; the replay count becomes 23/23 | Kernel tools |
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
| G2c blocked | G2 incomplete; no signature compatibility | Maintainers | §3 |
| Doc `03` G2 wording (low-S) | A literal reading would demand a rule the reference does not have | Documentation | §4 amendment recorded |
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

---

## 10. Boundary of this milestone

P2.1 ends with this document set and a verified commit. It does not:

- add a dependency or a backend;
- add, remove or modify a vector;
- change a script, sighash, consensus or serialization rule;
- create a Go service;
- start P3.

The next milestone starts from §9, not from here.
