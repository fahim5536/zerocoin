# Cryptographic blocker register

Status: **created in P2.10 §2** at baseline commit `b0a4292` (equal to
`origin/main`); the statuses below are the *entry* state of P2.10, verified
against that tree. Final dispositions are recorded in the P2.10 addenda
(`CRYPTO_BACKEND_SELECTION_AUDIT.md` §20, `CRYPTO_BACKEND_READINESS.md` §15)
and in the status updates committed at the end of P2.10.

Purpose: the single list of currently open cryptographic blockers for the G2c
release gate, each with the evidence that it still exists. Anything not listed
here is either resolved (§4 names the closing commit) or was never a blocker.
Historical findings F-1 … F-11 (`FINDINGS_TRIAGE.md`) are port and stability
items rather than cryptographic blockers; they are recorded in the annex (§5)
so that their absence from the main register is a decision, not an oversight.

---

## 1. Method

Sources searched at `b0a4292` with a clean working tree:

- All 11 documents under `docs/architecture/` and `docs/consensus/` at their
  actual paths, including the P2.6–P2.9 addenda of
  `CRYPTO_BACKEND_SELECTION_AUDIT.md` (§16–§19) and
  `CRYPTO_BACKEND_READINESS.md` (§11–§14), `CRYPTO_BACKEND_DECISION.md`,
  `PUBLIC_KEY_ENCODING_CONTRACT.md`, `CPP_PORT_REQUIREMENTS.md`,
  `CONSENSUS_RULES.md`, `FINDINGS_TRIAGE.md`, `INTERFACE_CONTRACTS.md`,
  `COMPONENT_OWNERSHIP.md`, `THREE_LANGUAGE_ARCHITECTURE.md`,
  `MIGRATION_ROADMAP.md`.
- `docs/migration/` (README + docs 01–08): historical phase documents, read for
  stale pointers only.
- Marker search across `docs/` for `TODO`, `FIXME`, `deferred`, `NO-GO`,
  `BLOCKED`, `load-bearing`, `limitation`, `unmeasured`, `not claimed`: matches
  concentrate in the two crypto-backend documents; every live match maps to a
  row below, and every other match sits in a section already marked superseded
  by a later addendum.
- Code search for `TODO|FIXME` in `kernel/` and `zerocoin/src/`: **zero
  matches**.
- The differential fixture
  `kernel/differential/vectors/ledger.sighash.differential.txt`
  (META cases=117; groups V1=2, V2=3, V3=18, V4=11, V5=5, V6=2, V7=76) and the
  P0 corpus manifest (`test/vectors/manifest.json`: 117 cases, 13 groups,
  `source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c`).
- `kernel/third_party/secp256k1/SHA256SUMS` recomputed this milestone:
  **60/60 vendored files match**; the remaining line is the documented
  non-vendored archive placeholder.

Superseded-history rule: an issue closed by a later commit is listed in §4 with
the closing evidence, never as an open blocker.

---

## 2. Open blockers

### CB-1 — `ledger.sighash.signature_der` DER signing parity is unmeasured

| Field | Value |
|---|---|
| Location | `test/vectors/ledger/sighash.json`, case `ledger.sighash.signature_der` (digest `e0e7ce17…a237`, key `scalar: 1`, expected 71-byte low-S DER); risk U2 in `CRYPTO_BACKEND_SELECTION_AUDIT.md` §19.2; `CRYPTO_BACKEND_READINESS.md` §14.3 limitation 12; `CRYPTO_BACKEND_DECISION.md` §9.1; `MIGRATION_ROADMAP.md` §3 step 7 and §5 T2 |
| Impact | Testing and signer-provenance only. Signing is **not** on the consensus validation path (`TxSigChecker` is verify-only; C-52 permits future non-deterministic signers while verification stays deterministic). While U2 stands, no second implementation is known to reproduce the committed DER bytes, so any future claim of cross-language signer equivalence would be unsupported |
| Evidence it is still open | Audit §19.2: "byte parity is **unmeasured** (risk U2 stands)". Readiness §14.1: the separate decision for `signature_der` is "**not taken**" |
| Area | Testing (differential harness); indirectly wallet signing |
| Required resolution | Either (a) a **test-only C++ signing adapter** — `secp256k1_ecdsa_sign` (RFC 6979 nonce, SHA-256) plus `secp256k1_ecdsa_signature_serialize_der` — whose output is compared byte-for-byte with the committed `der_hex` (which was produced independently by the pinned Rust reference, never transcribed from C++), with deterministic repeatability across repeated runs, fixed non-secret test keys, malformed-input behaviour, and no link into any production binary; or (b) a formal, evidence-based deferral that keeps U2 open |
| Acceptance test | Executed byte-for-byte comparison with command, exit code and output captured; two consecutive runs produce identical bytes; the adapter target exists only under the differential/test tree. A deferral is accepted only as a recorded decision, never as a "resolved" status |
| Status | **OPEN** |

### CB-2 — S5 scalar-boundary verdicts are measured against Rust only; the C++ column is analytic

| Field | Value |
|---|---|
| Location | `CRYPTO_BACKEND_SELECTION_AUDIT.md` §19.1 (the C++ column is "derived from the vendored source, not from execution"); `CRYPTO_BACKEND_READINESS.md` §14.1 ("the measured C++ acceptance of the four boundary probes remains future work — the audit's V-matrix rows V3–V6 stay open"); probes live in `zerocoin/tests/s5_boundary_probes.rs` |
| Impact | Consensus verification readiness. The four probes (`s = 1`, `s = n − 1`, `s = floor(n/2)`, `s = floor(n/2) + 1`) pin the exact half-order boundary; a C++ backend that disagreed (accepting high-S, or rejecting `floor(n/2)`) would split validation. Until the C++ verdicts are executed, cross-language S5 closure cannot be claimed |
| Evidence it is still open | §19.1 records the analytic derivations (`is_high` strict `a > SECP256K1_N_H`; the public verify returns false before the equation for high-S) precisely because no measured run exists |
| Area | Consensus (verification boundary semantics) |
| Required resolution | Construct the four cases with the sanctioned P2.9 chosen-s method (`z' = z + k·(s_target − s) mod n`, fixed `d = 1`, `k = 3`), independently prove equation validity per digest, and execute them through the actual production-facing C++ verification wrapper (`Secp256k1Verifier::verify`, the seam-shaped gate), not an internal equation helper; include negative controls (wrong digest) and keep the P2.4/P2.9 Rust regressions green |
| Acceptance test | Differential rows added to the fixture with Rust verdicts re-derived by the committed oracle; the C++ runner executed from a fresh build directory; per-case verdicts and exit code captured in the P2.10 addendum |
| Status | **OPEN** |

### CB-3 — Backend provenance is not reproducible from the repository

| Field | Value |
|---|---|
| Location | `kernel/third_party/secp256k1/ORIGIN.md` (acquisition transcript recorded, but archive, `.sig` and keyring not vendored); `CRYPTO_BACKEND_READINESS.md` §12.4 item 7, §13.3 and §14.3 limitation 13; `CRYPTO_BACKEND_SELECTION_AUDIT.md` §17.9 and §19.3 |
| Impact | Release provenance and build reproducibility. `SHA256SUMS` is generated from the tree it validates: it proves non-drift, not upstream identity. A wholesale substitution performed before the checksum file was written would pass the current check, and a third party cannot re-verify the recorded GPG transcript from the repository alone |
| Evidence it is still open | Audit §19.3: "the archive, the `.sig` and the keyring are **not vendored** … Reproducible upstream verification remains **not claimed**". This milestone's recompute (60/60) is again non-drift evidence only |
| Area | Release provenance; build reproducibility |
| Required resolution | Preserve the upstream verification materials in a documented provenance directory, per the recommended option A of `CRYPTO_BACKEND_DECISION.md` §11: the pinned archive (2,436,784 bytes, SHA-256 `dd685546…132b`), the detached signature (566 bytes, SHA-256 `c7eb14bb…7ac8`), and the public verification key for fingerprint `6A8F 9C26 6528 E25A EB1D 7731 C237 1D91 CB71 6EA7` (public keyring only — never a private key). Add a verification step that checks the archive SHA-256, re-verifies the signature against the vendored public key, and compares the archive's inner tree with the vendored tree. Do not upgrade or replace the backend. If any material genuinely cannot be preserved, record the precise limitation and leave this row OPEN |
| Acceptance test | A fresh gate step re-derives upstream identity from the repository (hash + signature + tree comparison) with exit code 0, executed and captured; the transcript is no longer the only evidence |
| Status | **OPEN** |

### CB-4 — The C++ backend is not in the production verification path (integration decision pending)

| Field | Value |
|---|---|
| Location | `CRYPTO_BACKEND_READINESS.md` §11.7 item 1 and §13.4 item 10 (not linked into `zerocoin_kernel`, not reachable from `TxSigChecker`); `kernel/third_party/secp256k1/ORIGIN.md`; `COMPONENT_OWNERSHIP.md` §2 row "ECDSA verification, SEC1, DER — backend: **none** — **Blocked**" |
| Impact | Capability gap, not a defect: Rust `k256` remains the sole production verifier and the kernel fails closed with a null `SigVerifier`. G2c's production-integration condition cannot be met while the backend is differential-only |
| Evidence it is still open | `ORIGIN.md` states the isolation; the kernel build links vendored secp256k1 only into the differential runner target |
| Area | Consensus (production path); release |
| Required resolution | Integrate behind `zk::SigVerifier` only if every acceptance condition of the P2.10 brief §7 holds: measured S5 on both implementations, zero unexplained differential divergences, provenance closed, an explicit versioned interface with defined byte order / widths / error mapping / limits, fail-closed behaviour on malformed input and backend errors, no unsafe FFI, the old implementation retained as differential reference, end-to-end script and transaction verification tests, and wallet/transaction-vector compatibility re-confirmed. Benchmark only after correctness gates pass. If any consensus-sensitive mismatch remains unexplained, record the blocker and leave G2c NO-GO |
| Acceptance test | All fresh gates green from clean build directories with the integration in place, plus end-to-end verification tests; or an explicit record of the blocking mismatch |
| Status | **OPEN** (pending CB-1…CB-3 and the §7 criteria) |

### CB-5 — G2c release gate: NO-GO (aggregate)

| Field | Value |
|---|---|
| Location | `CRYPTO_BACKEND_SELECTION_AUDIT.md` §19.5; `CRYPTO_BACKEND_READINESS.md` §14 (D1 stands); `COMPONENT_OWNERSHIP.md` §3 G2c row; `MIGRATION_ROADMAP.md` §2 ("P2 … Partial — ECDSA blocked as G2c") |
| Impact | Release decision: P2 cannot be declared complete while G2c is open, and the two P2 conformance deferrals (`ledger.script.p2pkh_spend_accepted`, `ledger.sighash.signature_der`) remain in the runner's deferral list |
| Evidence it is still open | §19.5 enumerates the open conditions: no `signature_der` decision, provenance not reproducible, backend outside the production path, S5 against C++ unmeasured |
| Area | Release |
| Required resolution | The G2c GO conditions evaluated at the end of P2.10 with executed evidence: signature-boundary cases measured on both implementations; all differential cases matching with no unexplained divergence; DER signing parity proven or its deferral formally accepted; provenance at the accepted level; any production integration passing all fresh gates; no open consensus-sensitive regression; documentation matching code. A partial result is acceptable; a false GO is not |
| Acceptance test | The §11 decision record of this milestone, with every cited gate actually executed |
| Status | **OPEN** (NO-GO stands) |

## 3. Documented non-defects (permanent; never report as parity evidence)

| Item | Location | Why it is not a blocker |
|---|---|---|
| Adapter-load-bearing rows `V4.uncompressed_65`, `V4.hybrid_prefix_06` (`rust=reject`, `backend=accept`, seam rejects) | Differential fixture V4; audit §16.4 (semantics) and §16.12 (per-case matrix) | The 33-byte compressed-only gate (contract P-1) — not the libsecp256k1 parser — produces the verdict on 65-byte and hybrid keys. Recorded precisely so these rows are never cited as library-parity evidence |
| P2 conformance deferrals `ledger.script.p2pkh_spend_accepted` (needs verification) and `ledger.sighash.signature_der` (needs signing) | `MIGRATION_ROADMAP.md` §5 T2/T3; kernel conformance runner | The visible surface of CB-4 and CB-1: the first re-enables when G2c closes (22/23), the second only under a separate signing decision |

## 4. Resolved or superseded (kept as evidence; not current blockers)

| Item | Closed by | Evidence |
|---|---|---|
| `V4.prefix_05` divergence (Rust accepted SEC1 tag `0x05`; backend rejected) | P2.8 — contract `PUBLIC_KEY_ENCODING_CONTRACT.md` rule P-1 plus the tightened `PublicKey::from_sec1` gate | Fixture row now `RUST reject`; differential 117/117 match, no allowance; regressions in `zerocoin/tests/p2_7_pubkey_encoding.rs` and the V4 group. Must be preserved, not re-opened |
| High-S normalisation plan (the P2.2 plan normalised `s`; the reference rejects high-S) | P2.2 amendment — plan withdrawn | Wrapper must verify the parsed signature unchanged; pinned by `zerocoin/tests/high_s_signature.rs` (4 tests) and the V2 group |
| "23/23" P2 corpus goal | Superseded by the split deferral reasons | 22/23 on verification + a separate `signature_der` signing decision (readiness §3/§5; decision record §9.1) |
| S5 against the Rust reference | P2.9 | 6/6 pinned in `zerocoin/tests/s5_boundary_probes.rs` (2 end-to-end + 4 scalar-boundary probes). Only the C++ half remains open, tracked as CB-2 |

## 5. Annex — deferred project items outside G2c's scope

Recorded so the register is complete; none is cryptographic and none gates G2c:

- **F-1 / R-1** (`connect_block` untrusted-height panic guard), **F-3** (block-size
  policy decision required before the C++ port), **F-8** (engine-parameter
  fingerprint check): P1.1 stability/port follow-ups, dispositioned in
  `FINDINGS_TRIAGE.md` §7 and `CPP_PORT_REQUIREMENTS.md` §10.
- Sanitizers, CI matrix and multi-platform reproducibility: P7 scope
  (`MIGRATION_ROADMAP.md` §8). Windows/MinGW object-level reproducibility is
  what P2.6–P2.9 actually proved; no broader claim is made.
- Stale-documentation candidates to refresh in P2.10 §10 (not blockers):
  `MIGRATION_ROADMAP.md` is an explicit `e8fda7e` snapshot whose §1–§3 counts
  and step states are superseded by the P2.6–P2.9 addenda;
  `COMPONENT_OWNERSHIP.md` §2's "Blocked" ECDSA row needs a pointer to this
  register and to the P2.10 outcome; `CPP_PORT_REQUIREMENTS.md`'s P1 status
  line is historical framing (the requirement IDs remain normative labels).

---

## 6. P2.10 closing status updates (final dispositions)

Recorded at the end of P2.10 as the header promises; the §2 statuses above
remain the verified entry state of the milestone, not its outcome. Commit
chain: `3bb0062` (this register, §1–§2), `046a5c7` (CB-1), `9c90680` (CB-2),
`a7e9fa6` (CB-3), `e4e13d4` (CB-4), plus the documentation commit that closes
CB-5.

| Blocker | Disposition | Evidence |
|---|---|---|
| CB-1 | **RESOLVED** — DER signing parity proven with the test-only C++ adapter, exactly the option (a) this row scoped | Commit `046a5c7`: a differential-tree-only adapter (`secp256k1_ecdsa_sign`, RFC 6979 nonce, SHA-256, fixed non-secret scalar 1) reproduces the committed 71-byte low-S DER byte-for-byte; 28/28 checks green across consecutive runs; ctest 2/2. The adapter target exists only under `kernel/differential/` and is never linked into a production binary; risk U2 is closed |
| CB-2 | **RESOLVED** — the four S5 scalar-boundary verdicts are measured on the C++ backend | Commit `9c90680`: fixture groups V3–V6 constructed with the sanctioned chosen-`s` method and executed through the production-facing wrapper, with negative controls; `s5_boundary_probes` 7/7 and the differential matrix re-run in every later gate |
| CB-3 | **RESOLVED** — provenance reproducible from the repository | Commit `a7e9fa6`: the pinned archive (2,436,784 B, SHA-256 `dd685546…132b`), the detached signature (566 B, SHA-256 `c7eb14bb…7ac8`) and the public signing key are vendored under `kernel/third_party/secp256k1/provenance/`; `scripts/gate-p2-10-provenance.ps1` re-derives upstream identity — sizes, hashes, key fingerprint, GOODSIG/VALIDSIG in an isolated throwaway GnuPG home (TRUST_UNDEFINED expected), and a 60/60 byte-for-byte tree comparison — with exit code 0. No backend upgrade |
| CB-4 | **RESOLVED** — the backend is in the production verification path of the C++ kernel | Commit `e4e13d4`: `zk::Secp256k1Verifier` linked PRIVATE into `zerocoin_kernel`, reachable from `TxSigChecker` and nothing else; every acceptance condition held — measured S5 on both implementations, zero unexplained divergences (two documented adapter-load-bearing rows), provenance closed, versioned interface unchanged, fail-closed behaviour, no unsafe FFI, Rust retained as differential reference, end-to-end script and transaction verification tests, Rust suite 287/0 re-confirming wallet/transaction-vector compatibility. Benchmarks deliberately not run (correctness first) |
| CB-5 | **CLOSED — G2c: GO** | The P2.10 §11 decision record (`CRYPTO_BACKEND_SELECTION_AUDIT.md` §20.5, mirrored in `CRYPTO_BACKEND_READINESS.md` §15): every GO condition of §2 CB-5 evaluated with executed evidence. Recorded limitations, not open blockers: the two adapter-load-bearing rows (contract vs raw library), and the conformance runner's `signature_der` deferral (the runner is verify-only; signing parity itself was proven under CB-1). The shipped node remains Rust/k256; G2c closure changes no shipped binary and transfers no semantic authority |

§3 non-defects, row 2 status: the verification deferral
`ledger.script.p2pkh_spend_accepted` re-enabled in P2.10 §7 — the P2 wrapper
now replays **22/22** with only `ledger.sighash.signature_der` deferred
(signing; C-52). Row 1 stands unchanged and must never be cited as
library-parity evidence.
