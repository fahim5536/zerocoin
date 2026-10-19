# Crypto backend readiness review (P2.2)

Status: **NO-GO for G2c.** The proposed `libsecp256k1` integration plan is not
compatible with the pinned Rust reference as written, one of the two deferred
corpus cases cannot be closed by a verification-only backend, and no dependency
is pinned by tag or archive hash. Nothing was downloaded, vendored, installed or
enabled in this phase.

Baseline: commit `3044af42a46e98d93f0d8efff3b33cb817b65228`, clean working tree,
`HEAD == origin/main`. This document changes documentation only. It authorises no
code, adds no dependency, and claims no signature compatibility.

Evidence labels follow `docs/migration/README.md` §1: `[VERIFIED]` was read from
the pinned source tree or produced by a command whose output is quoted;
`[PROPOSED]` is a recommendation; `[UNVERIFIED]` is an assumption that has not
been established from the repository or from a local copy of the library.

---

## 1. Method

The audit compares three things:

1. **The reference**, as executed by the pinned dependency set in
   `zerocoin/Cargo.lock`: `k256 0.13.4`, `ecdsa 0.16.9`, `elliptic-curve
   0.13.8`, `der 0.7.10`, `sec1 0.7.3` `[VERIFIED]`.
2. **The plan**, as written in `CRYPTO_BACKEND_DECISION.md` §7 and
   `INTERFACE_CONTRACTS.md` §3.3.
3. **The candidate's documented contract**, from upstream documentation only.
   No archive exists on this host, so every libsecp256k1 statement below is
   `[UNVERIFIED]` and is marked as such. It is not a substitute for reading the
   pinned source.

Behaviour is decided at the level a node observes: the boolean returned by
`TxSigChecker::check_signature`. Library-internal error classes do not matter
unless they change that boolean.

---

## 2. Findings

### H1 — The reference rejects high-S. The plan does the opposite. **Blocking.**

This reverses the premise **previously** recorded in `CRYPTO_BACKEND_DECISION.md`
§1 constraint 6, §3, §7.3, §9 and §10; `INTERFACE_CONTRACTS.md` B4;
`MIGRATION_ROADMAP.md` §4; `docs/migration/08-...md` §6; and
`docs/migration/04-risk-register.md` R9. All of them stated that the reference
has no low-S rule. That statement was false. The documents are corrected in
place (§8 below).

The verification path, end to end:

| Step | Location | Behaviour |
|---|---|---|
| 1 | `zerocoin/src/crypto/secp256k1.rs:137-143` | `PublicKey::verify` calls `verify_prehash(&digest.0, &sig)`. No half-order check appears in this file. |
| 2 | `ecdsa-0.16.9/src/verifying.rs:163-165` | `VerifyingKey::verify_prehash` converts the digest to a field element and calls `self.inner.as_affine().verify_prehashed(&field, signature)`. |
| 3 | `k256-0.13.4/src/ecdsa.rs:201-208` | `impl VerifyPrimitive<Secp256k1> for AffinePoint` **returns `Err` when `sig.s().is_high()`**, before any arithmetic. |

The implementing code `[VERIFIED]`:

```rust
impl VerifyPrimitive<Secp256k1> for AffinePoint {
    fn verify_prehashed(&self, z: &FieldBytes, sig: &Signature) -> Result<(), Error> {
        if sig.s().is_high().into() {
            return Err(Error::new());
        }

        hazmat::verify_prehashed(&self.into(), z, sig)
    }
}
```

`k256` is compiled with the `ecdsa` feature
(`zerocoin/Cargo.toml`: `k256 = { version = "0.13", features = ["ecdsa", ...] }`),
so this `impl` is the one in scope. `ecdsa::Signature::normalize_s` exists
(`ecdsa-0.16.9/src/lib.rs:318`) but is never called on the verification path; it
is called only when **signing**, at `k256-0.13.4/src/ecdsa.rs:194`
(`sig.normalize_s().unwrap_or(sig)`), which is why every signature the reference
produces is low-S.

**Consequences.**

- A signature with `s > n/2` is **rejected** by the Rust node. It is not
  normalised, not accepted, and not reported as an error above the boolean.
- `CRYPTO_BACKEND_DECISION.md` §7.3 step 2 — normalise a copy before calling
  `secp256k1_ecdsa_verify` — would make C++ **accept** exactly the signatures
  Rust rejects. That is a consensus divergence, not a compatibility measure. The
  step is withdrawn.
- No low-S rule is *introduced* by this document. The rule already exists in the
  pinned dependency. What is forbidden is removing it by normalisation.
- The rule is inherited from a dependency, not written in ZeroCoin source and
  not pinned by any existing Rust test. That is a residual risk (R1 in §7): a
  `k256` update could change consensus silently. It must be pinned by vectors
  before a second implementation validates it.

### H2 — `ledger.sighash.signature_der` needs signing, not verification. **Blocking for 23/23.**

The fixture's input is `{"digest": {...}, "scalar": 1}`; its expected output is
`der_hex` (71 bytes), `der_len: 71`, `verified: true` and
`verified_under_other_key: false`, with
`independent_check: "RFC 6979 deterministic ECDSA over secp256k1; DER, low-S"`
`[VERIFIED]`. Reproducing it requires producing a signature: RFC 6979 nonce,
scalar multiplication, low-S normalisation and exact DER bytes.

`zk::SigVerifier` (`kernel/include/zerocoin/sighash.h:79-89`) has one method,
`verify`. It cannot sign. `CRYPTO_BACKEND_DECISION.md` §7.1 explicitly states
that the context "is never used for signing, so signing callbacks and RFC 6979
nonces never enter the kernel". A verification-only backend therefore closes at
most **22 of 23** P2 cases: `ledger.script.p2pkh_spend_accepted` becomes
replayable, `ledger.sighash.signature_der` does not.

`MIGRATION_ROADMAP.md` §3 step 5 ("replay 23/23") is unattainable under the
architecture it accompanies. The two cases must stop sharing one deferral
reason: one needs a curve verifier, the other needs a signer.

The other deferred case is genuinely verification-only: its `script_sig_hex`
already embeds the 71-byte DER signature and the SEC1 public key
`[VERIFIED]`. It exercises a valid low-S signature and no high-S case.

### H3 — Parse and verify sets: no other known verdict difference.

All statements about the reference are `[VERIFIED]` from the pinned sources;
all statements about libsecp256k1 are `[UNVERIFIED]` documented behaviour.

| Probe | Reference | libsecp256k1 (documented) | Verdict-equivalent? |
|---|---|---|---|
| Public key, 33-byte `0x02`/`0x03` on curve | accepted (`secp256k1.rs:112-121`) | accepted | Yes |
| Public key, 65-byte uncompressed, hybrid, wrong length | rejected — the length gate runs first | parser accepts 33/65/hybrid, so the wrapper must gate length and prefix | Yes **only if** the wrapper gates; this is B1 and stays |
| DER, non-minimal integer (unnecessary `0x00`) | rejected (`der-0.7.10/src/asn1/integer/uint.rs:273-288`) | rejected (strict parser) | Yes |
| DER, negative integer (high bit without `0x00`) | rejected, same location | rejected | Yes |
| DER, zero `r` or `s` | rejected at parse: `der` → `from_bytes` → `from_scalars` (`ecdsa-0.16.9/src/lib.rs:250-256`) | parse may succeed; `verify` returns 0 | Yes; parse-time vs verify-time rejection both yield `false` |
| DER, `r ≥ n` or `s ≥ n` | rejected at `ScalarPrimitive::from_slice` | rejected | Yes |
| DER, non-minimal length, long form, trailing byte, empty, truncated | rejected (`der.rs`, `reader.finish`) | rejected | Yes |
| 32-byte prehash, no re-hashing | `verify_prehash` only (`secp256k1.rs:137-143`) | `secp256k1_ecdsa_verify` takes a 32-byte message | Yes |
| Digest ≥ n | reduced mod n inside `hazmat::verify_prehashed` | reduced mod n | Yes |
| **High-S** | **rejected** (H1) | **rejected** (`secp256k1_ecdsa_verify` returns 0) | **Yes — if the wrapper does not normalise** |

The table is a hypothesis set, not proof. Every row needs a vector from the
Rust oracle before a backend is linked; §4 defines them.

### H4 — Dependency readiness cannot be compared yet.

The review scope requires a comparison of pin, archive hash, licence, build
reproducibility and platform support. The honest result is that only the licence
has a documented answer, and even that is unverified: there is no local copy to
read.

| Item | Documented requirement | Actual state | Verdict |
|---|---|---|---|
| Release pin | `CRYPTO_BACKEND_DECISION.md` §4.1: exact tag or commit SHA | No tag and no commit SHA is named anywhere in the repository | **Not satisfied** |
| Archive hash | §4.2: SHA-256 recorded in the document and in `kernel/cmake/Secp256k1.cmake` | No hash; `kernel/cmake/` does not exist | **Not satisfied** |
| Vendored subtree | §4.3: `kernel/third_party/secp256k1/` with `LICENSE`, `SHA256SUMS`, `ORIGIN` | Absent | **Not satisfied** |
| Licence | §5: MIT, notice retained | Upstream declares MIT; no local copy to verify, no `LICENSE` fetched | **[UNVERIFIED]** |
| Build reproducibility | §6: offline, read-only source tree, static, no DLL | No archive, no build attempted, no recorded `SECP256K1_*` configuration | **Not demonstrated** |
| Windows | §8: MinGW "expected"; MSVC later | MinGW g++ 16.2.0 and CMake 4.4.3 present; nothing built | **Not demonstrated** |
| Linux / macOS | §8: "expected"; no CI | No CI, no host | **Not demonstrated** |
| Android NDK | §8: "expected"; no C++ node planned | No NDK path exercised | **Not demonstrated** |

The document is a **pinning policy**, not a pin. That distinction matters because
§9's acceptance gate says "pinned by tag and archive SHA-256"; a policy cannot
satisfy a gate.

### H5 — The conformance runner has no signature verb.

`kernel/conformance/main.cpp` dispatches 15 verbs, none of which verify or
produce a signature `[VERIFIED]`. The G1 and P2 wrappers both drive the same
`kernel_conformance` binary (`kernel/CMakeLists.txt:72-84`). A backend suite
therefore needs a new verb and a new wrapper; it must not change
`EXPECTED_CASE_COUNT = 21` or the G1 count of 28.

This is a design gap, not a defect: P2 deliberately stopped at the seam.

---

## 3. Which deferred case can close

| Case | What it needs | Closable by `SigVerifier`? | State after this review |
|---|---|---|---|
| `ledger.script.p2pkh_spend_accepted` | ECDSA verification over the embedded DER and key | Yes | **Deferred.** No backend exists and none is authorised. |
| `ledger.sighash.signature_der` | RFC 6979 signing, low-S normalisation, exact DER | No | **Deferred**, under a separate reason. |

Neither is marked passed. `p2_conformance.py` keeps both names, keeps
`EXPECTED_CASE_COUNT = 21`, and keeps printing the deferral count. A future
change may split the reasons, but it may not delete the second name to make the
list look shorter.

---

## 4. Minimal backend acceptance suite `[PROPOSED]`

Not implemented in P2.2. It is specified here so the next phase has a fixed
target and cannot redefine success after seeing results.

**Rules that apply to every group.**

- The oracle is the Rust reference at the commit recorded in the fixture
  manifest. Expected values are generated by a Rust test target and committed as
  JSON; the C++ side never grades itself.
- Each new fixture file carries `manifest.source_commit`. A mismatch is a hard
  error, as in `p2_conformance.py`.
- The wrapper re-derives whatever it can independently of the backend (DER
  framing, SEC1 length and prefix, digest, expected verdict) and only then calls
  the runner.
- Every group has a corruption self-check: flip one expected byte and require a
  non-zero exit.
- A high-S signature is a **negative** case. It must return `false`; an
  "accepted high-S" row would fail the suite.
- The suite runs as a new CTest target beside `kernel_p2_conformance`; the
  existing counts (G1 28, P2 21 + 2 deferred) are untouched.

### S1 — Valid and invalid signatures (8)

Low-S valid signature; one bit flipped in `r`; one bit flipped in `s`; wrong
public key; wrong digest; wrong chain id; wrong sighash type; wrong input index.
Expected: the first accepts, the rest return `false`.

### S2 — Malformed and boundary DER (13)

Canonical; minimal integer with `0x00` only when the high bit is set; unnecessary
`0x00`; negative `r`; zero `r`; zero `s`; `r = n`; `s = n`; non-minimal length
(`0x81 0x06`); indefinite length (`0x80`); one trailing byte inside the DER
portion; empty; truncated. Expected: canonical accepts, the other twelve return
`false`. This group pins the B2 boundary that H3 asserts.

### S3 — Compressed SEC1 public keys (12)

33-byte `0x02` and `0x03` generator encodings (accept); 65-byte uncompressed
(reject); hybrid `0x06`/`0x07` (reject); prefix `0x00`/`0x04`/`0x05` (reject);
length 32 and 34 (reject); `x = p` (reject); a point not on the curve (reject).
The accept cases also pin that the key is used unchanged, not re-encoded.

### S4 — Prehashed ECDSA (4)

A digest that is not `SHA-256(message)` (must accept, proving no re-hashing); a
digest numerically `≥ n` (verdict from the Rust oracle, proving reduction mod
`n`); an all-zero digest (reject); a 32-byte digest whose first byte is `0x00`
(verdict from the oracle, proving no trimming or padding).

### S5 — High-S behaviour (6)

The high-S twin of a valid signature (must reject); the low-S original (must
accept); `s = 1` (accept when `r` is valid); `s = n-1` (reject); `s = n/2`
(accept); `s = (n/2)+1` (reject). This is the group that decides H1 in code. It
is the minimum evidence required before any backend is linked.

### S6 — Existing ZeroCoin sighash fixtures (23)

Replay the whole P2 slice through the seam, not through a new API. Success is
**22/23 replayed with one named deferral**, never 23/23 while
`signature_der` still requires signing. The corruption guard stays.

### S7 — Cross-signing (conditional)

Rust signs → C++ verifies: required, and covered by S1/S6. C++ signs → Rust
verifies: requires a test-harness signer. That signer is outside the kernel, must
not be linked into a node, and must reproduce the RFC 6979 bytes exactly. Until
that is demonstrated, the direction is not claimed. `signature_der` is the
fixture that would prove it.

### Deliberately excluded from the minimum

Differential fuzzing, sanitizer runs, multi-thread stress, performance, and
signing inside the kernel. They are legitimate later work; adding them now would
turn a readiness gate into a research project.

**Estimated size:** 43 new probes plus the existing 23. Small enough to review by
hand, large enough that a normalising or re-hashing backend fails.

---

## 5. Decision

| # | Decision | Rationale |
|---|---|---|
| D1 | **G2c stays blocked. NO-GO.** | H1 makes the current plan incompatible; H2 makes its exit criterion unattainable; H4 leaves the dependency unpinned. |
| D2 | **No normalisation of high-S, and no new low-S policy.** | The reference rejects high-S (H1). A normalising wrapper would accept what Rust rejects. |
| D3 | **`CRYPTO_BACKEND_DECISION.md` §7.3 is withdrawn.** libsecp256k1 remains the candidate; its wrapper design must be re-issued without step 2. | The candidate is documented to reject high-S, which matches the reference. The wrapper needed less, not more. |
| D4 | **No acquisition.** No download, vendor, submodule, package-manager bootstrap or `FetchContent`. | The review scope forbids it; §11 of the decision record still requires authorisation. |
| D5 | **Rust remains the authoritative consensus reference.** C++ remains a derived compatibility kernel. Go is untouched. | No second consensus implementation is created by this review. |
| D6 | **The two deferred cases stay visible and stay deferred.** | Acceptance forbids marking them passed. |
| D7 | **P3 does not start.** | Explicit boundary of this milestone. |

### What would make G2c a GO

1. A written authorisation naming one acquisition path (decision record §11).
2. A named release tag, archive SHA-256 and `ORIGIN`/`SHA256SUMS`/`LICENSE`
   vendored under `kernel/third_party/secp256k1/`.
3. A wrapper that gates SEC1 to 33 bytes and `0x02`/`0x03`, parses strict DER,
   and **does not normalise `s`**.
4. S1–S6 green, with S5 proving high-S rejection and S6 reporting 22/23 and one
   named deferral.
5. A separate decision for `signature_der`, because it needs a signer, not a
   verifier.

Until all five exist, the answer is NO-GO.

---

## 6. Non-claims

This review does **not** claim: signature compatibility between C++ and Rust; a
working backend; closure of G2c, G2 or the P2 exit criteria; production
readiness; that libsecp256k1 behaves as documented (it was not read from
source); that the acceptance suite exists; that `signature_der` can be closed by
a verifier.

It also does not introduce cryptography. The Python secp256k1 code in
`test/harness/zro_vectors.py` predates this review, is test tooling, and is not
a backend, an oracle for consensus, or a substitute for a vetted library. It
must never be linked into the kernel.

---

## 7. Residual risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | The low-S rule lives in `k256`, not in ZeroCoin code or fixtures | A dependency update could change consensus with no test failing | Add the S5 vectors Rust-side and pin `k256` by exact version and checksum; treat a version change as a consensus change |
| R2 | No existing Rust test asserts high-S rejection | The claim in H1 is proven by reading code, not by a failing test | Add a Rust integration test that a high-S twin is rejected; do not change verification code |
| R3 | `signature_der` has no owner under the current plan | "23/23" is repeated in two documents as if achievable | Split the deferral reason; D6; roadmap §3 corrected |
| R4 | A future wrapper re-adds normalisation "for compatibility" | Silent divergence on exactly the malleated signatures an attacker controls | S5 must fail if normalisation appears; the wrapper must have no `normalize` call |
| R5 | No platform evidence beyond MinGW | The backend may not build where the node is meant to run | G7 CI matrix; do not claim support before it exists |
| R6 | libsecp256k1 behaviour is documented, not read | A parse-set difference could change a verdict | Read the pinned source during acquisition; S1–S3 decide empirically |

---

## 8. Corrections applied to earlier documents

These were factual claims that the pinned sources contradict. They are corrected
in place; the historical phase documents keep their original findings.

| Document | Claim | Corrected to |
|---|---|---|
| `CRYPTO_BACKEND_DECISION.md` §1 constraint 6 | "including the absence of a low-S rule" | The reference rejects high-S in `k256`; see §2 H1 |
| `CRYPTO_BACKEND_DECISION.md` §3 | `k256` "accepts high-S (exact parity)" | `k256` rejects high-S |
| `CRYPTO_BACKEND_DECISION.md` §7.3 | Normalise a copy before verifying | Withdrawn; verify the parsed signature unchanged |
| `CRYPTO_BACKEND_DECISION.md` §9 | "high-S accepted"; "23/23" | High-S rejected; 22/23 plus one signing deferral |
| `INTERFACE_CONTRACTS.md` B4 | "Do not enforce low-S" | Enforce the reference's high-S rejection; do not normalise |
| `MIGRATION_ROADMAP.md` §3 | Step 3 normalisation; step 5 23/23; step 6 accept high-S | Revised to match H1 and H2 |
| `MIGRATION_ROADMAP.md` §4 | "the reference performs no low-S normalisation" | It performs a low-S **rejection**; the amendment is rewritten |
| `docs/migration/08-...md` §6 | "no low-S normalisation or rejection exists anywhere in the reference" | Superseded; the rejection is one layer down, in `k256` |
| `docs/migration/04-risk-register.md` R9 | Mitigate "low-S rules" as if absent | Mitigate high-S **parity**, which means rejection |

`docs/migration/03-module-mapping-and-phased-plan.md:183` keeps its original
gate wording as history; the amendment in `MIGRATION_ROADMAP.md` §4 is the text
that governs.
