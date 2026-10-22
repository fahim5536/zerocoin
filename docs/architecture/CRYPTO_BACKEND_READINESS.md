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
  not pinned by any existing Rust test at the time of this review. That is a
  residual risk (R1 in §7): a `k256` update could change consensus silently. It
  must be pinned by vectors before a second implementation validates it.
  **Update (P2.3):** the high-S verdict is now pinned by
  `zerocoin/tests/high_s_signature.rs`; see §9.

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

**Status after P2.3: partial, not complete.** The twin-rejection and
low-S-acceptance probes are pinned Rust-side (§9); the four scalar-boundary
probes remain open, and S5 as a backend acceptance group is untouched. P2.4
re-examined the four boundary probes and recorded them as blocked; see §10.3.

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
| R1 | The low-S rule lives in `k256`, not in ZeroCoin code or fixtures | A dependency update could change consensus with no test failing | **Partially mitigated in P2.3:** the high-S verdict is pinned Rust-side (§9). `Cargo.toml` still allows the `0.13` range while `Cargo.lock` records `0.13.4`; treat a version change as a consensus change |
| R2 | No existing Rust test asserts high-S rejection | The claim in H1 is proven by reading code, not by a failing test | **Closed in P2.3:** `high_s_twin_is_rejected_at_verification` in `zerocoin/tests/high_s_signature.rs`; verification code unchanged |
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

---

## 9. P2.3 addendum — Rust regression pins for high-S `[VERIFIED]`

Baseline for this addendum: commit `eff89b8`, clean working tree,
`HEAD == origin/main`. P2.3 adds one Rust integration test target. It changes no
production cryptography, no consensus rule, no dependency version, no fixture,
and no C++ or Go code. G2c remains **NO-GO** and no backend was acquired.

### 9.1 Test target and commands

`zerocoin/tests/high_s_signature.rs` contains four tests. It signs a real
ZeroCoin sighash — `ledger::sighash::signature_hash` over the `ZRO/sighash/v1`
preimage with a regtest chain id and `SIGHASH_ALL` — using a fixed key
(`PrivateKey::from_bytes([7u8; 32])`), then verifies through `PublicKey::verify`
and `ECDSA::verify` with the 33-byte compressed SEC1 encoding produced by
`PrivateKey::public_key`. There is no RNG, clock or filesystem input, so the
result is deterministic and isolated.

```powershell
cargo +stable-x86_64-pc-windows-gnu test --test high_s_signature
```

Observed:

```text
running 4 tests
test high_s_twin_is_rejected_at_verification ... ok
test valid_low_s_sighash_signature_is_accepted ... ok
test invalid_signatures_are_still_rejected ... ok
test signing_conventions_are_pinned ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

| Test | What it pins | Observed |
|---|---|---|
| `valid_low_s_sighash_signature_is_accepted` | `PrivateKey::sign` emits low-S; `PublicKey::verify` and `ECDSA::verify` accept it over the exact prehash and compressed key | pass |
| `high_s_twin_is_rejected_at_verification` | `(r, n − s)` parses as DER, is high-S, normalises back to the original byte for byte, and returns `CryptoError::VerificationFailed` | pass |
| `invalid_signatures_are_still_rejected` | flipped `r`; flipped `s` chosen to stay low-S; wrong prehash; wrong key; empty, empty-sequence, trailing-byte and truncated DER | pass |
| `signing_conventions_are_pinned` | RFC 6979 determinism; 32-byte prehash not re-hashed; 70–72-byte DER | pass |

The twin is not hard-coded. For a signature `(r, s)` over digest `z` under key
`Q`, write `w = s^-1`, `u1 = z*w`, `u2 = r*w`; the verifier computes
`R = u1*G + u2*Q` and accepts when `x(R) = r`. For `(r, n − s)`:

```text
w' = (n - s)^-1 = -s^-1 = -w
u1' = -u1,   u2' = -u2
R'  = -(u1*G + u2*Q) = -R
x(R') = x(-R) = x(R) = r
```

with the secp256k1 group order

```text
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

The test computes `n − s` with `k256`'s `Scalar::negate` and asserts
`twin.normalize_s() == Some(original)`, so the twin is proven to be the same
ECDSA point rather than arbitrary bytes.

### 9.2 S5 coverage — partial

| S5 probe | Expected | State after P2.3 |
|---|---|---|
| High-S twin | reject | **Pinned Rust-side** |
| Low-S original | accept | **Pinned Rust-side** |
| `s = 1` | accept | **Open** |
| `s = n-1` | reject | **Open** |
| `s = floor(n/2)` | accept | **Open** |
| `s = floor(n/2)+1` | reject | **Open** |

The boundary semantics are `s > floor(n/2)`, not `>=`: `IsHigh` is
`self.0.ct_gt(&FRAC_MODULUS_2)` with `FRAC_MODULUS_2 = ORDER >> 1`
(`k256-0.13.4/src/arithmetic/scalar.rs:42,481-485`). `n` is odd, so
`floor(n/2)` is low-S and `floor(n/2)+1` is the smallest high-S value.

The four scalar-boundary probes are **not** covered. Changing `s` alone changes
the ECDSA equation, so the result would be rejected as an invalid signature
regardless of its half-order position and would not isolate the rule. Producing
a *valid* signature with a chosen `s` requires controlling the nonce or solving
for the digest, i.e. a test-only signer. P2.3 is not authorised to add one, and
the kernel has no signer (`kernel/include/zerocoin/sighash.h:79-89`). S5 as
written is a backend acceptance group; it stays open until a backend exists and
an oracle that can sign generates its vectors.

### 9.3 Gates observed after the change

| Gate | Command | Result |
|---|---|---|
| G1 | `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\gate-g1.ps1` | **PASS** — build (warnings as errors), ctest, 108 kernel unit tests, 28/28 corpus, 267 Rust tests across 8 targets, P0 `112 PASS / 5 ANCHOR / 0 FAIL` |
| P2 | `python kernel\tools\p2_conformance.py --vectors test\vectors --runner .build\kernel-g1\kernel_conformance.exe` | **PASS** — 21/21 replayed, 2 deferred (G2c), corruption self-check 21/21 |

The Rust total moved from 263 to 267 because of the four new tests; no existing
test changed.

### 9.4 Remaining limitations

1. S5 is **partial**, as detailed in §9.2. It is not marked complete.
2. The pin covers the boolean verdict at the public API, not the internal
   rejection point. A dependency change that preserved the verdict while
   altering unrelated verification behaviour would not be caught here.
3. `zerocoin/Cargo.toml` still requests `k256 = "0.13"`; only `Cargo.lock`
   names `0.13.4`. H4 is unchanged: there is still no archive checksum and no
   vendored subtree.
4. The equivalence assertion uses the same library as the code under test, so
   it proves internal consistency, not an independent big-integer derivation.
   The independent evidence is the algebra in §9.1 and the fixed curve order.
5. C++/libsecp256k1 parity remains unmeasured; no backend exists and none was
   acquired (D4).

---

## 10. P2.4 addendum — boundary-probe feasibility and dependency pin audit `[VERIFIED]`

Baseline for this addendum: commit `aebca30`, clean working tree,
`HEAD == origin/main` before the change. P2.4 adds one Rust integration test
target and this section. It changes no production cryptography, no consensus
rule, no dependency version, and no lockfile. G2c remains **NO-GO** and no
backend was acquired. No C++ parity is claimed.

### 10.1 S5 boundary probes — feasibility verdict

S5 (§4) asks for four scalar-boundary verdicts in addition to the twin. All
four share one requirement: the probe must present a signature that verifies
except for the half-order rule, i.e. a valid ECDSA signature whose `s` is the
chosen value. For key `d`, nonce `k` and digest `z`:

```text
r = x(k*G) mod n
s = k^-1 * (z + r*d) mod n
```

`s` is an output of signing, not an input. A chosen `s` therefore has to be
solved for: fix `k`, compute `r`, then set `z' = z + k*(s_target - s)` (or
search `k` until `s` lands on the target).

| Probe | Verdict sought | Reachable with the existing public APIs? | Status |
|---|---|---|---|
| `s = 1` | accept (when `r` is valid) | no — requires a chosen nonce and a solved digest | **Blocked** |
| `s = n - 1` | reject | no — same construction, or the twin of an `s = 1` signature | **Blocked** |
| `s = floor(n/2)` | accept | no — same construction | **Blocked** |
| `s = floor(n/2) + 1` | reject | no — same construction | **Blocked** |

Why each is blocked, in terms of the APIs that exist:

1. `PrivateKey::sign` (`zerocoin/src/crypto/secp256k1.rs:81-87`) is the only
   signing entry point in the crate. It takes a digest and nothing else: no
   nonce, no target scalar. It delegates to `SigningKey::sign_prehash`, i.e.
   RFC 6979 plus normalisation.
2. `k256`'s `SignPrimitive::try_sign_prehashed` does accept a nonce, but its
   `Secp256k1` implementation normalises the result —
   `let sig_low = sig.normalize_s().unwrap_or(sig);`
   (`k256-0.13.4/src/ecdsa.rs:194`). It therefore cannot emit `s = n-1`, and it
   cannot emit a *chosen* low-S value either: given `k` it computes one `s`,
   with no parameter to steer it.
3. The only unnormalised route in this dependency set is the free function
   `ecdsa::hazmat::sign_prehashed` (`ecdsa-0.16.9/src/hazmat.rs:224-259`),
   re-exported as `k256::ecdsa::hazmat`. It takes `d`, `k` and `z` and returns
   `s = k^-1*(z + r*d)` untouched. Building a chosen-`s` probe from it means
   writing the solve above and wrapping it in a signer: that is a new
   **test-only signing facility**, which P2.4 is explicitly not authorised to
   add. The module header describes it as an easy-to-misuse low-level interface.
4. Changing `s` on an existing signature is not an alternative. It leaves `r`,
   `z` and `Q` fixed, so `u1 = z/s` and `u2 = r/s` change and
   `x(u1*G + u2*Q) != r` with overwhelming probability. Such a probe returns
   `VerificationFailed` because the equation fails, not because of the
   half-order position, and would not isolate S5's rule. §2 H3 already records
   this trap.

Consequence: the four probes are blocked by the milestone's own constraints,
not by a missing test idea. They become reachable only with (a) a
nonce-controlling test signer, or (b) an external oracle that can sign, i.e. the
C++/libsecp256k1 backend that G2c would provide. Neither exists here, and P2.4
adds neither. This is consistent with §9.2: S5 is a backend acceptance group.

### 10.2 Supporting pins added in this phase

`zerocoin/tests/s5_boundary_probes.rs` contains three tests. They do **not**
execute any of the four probes; they pin the two facts that make the blocked
verdict auditable. No production code, dependency or consensus rule was
touched.

```powershell
cargo +stable-x86_64-pc-windows-gnu test --test s5_boundary_probes
```

Observed:

```text
running 3 tests
test high_s_predicate_boundary_is_strictly_above_half_the_group_order ... ok
test high_s_twin_is_equation_valid_but_the_public_api_rejects_it ... ok
test the_public_signing_api_cannot_emit_a_chosen_scalar ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

| Test | What it pins | Observed |
|---|---|---|
| `high_s_predicate_boundary_is_strictly_above_half_the_group_order` | `n-1` equals the secp256k1 order minus one; `2*floor(n/2) = n-1`; `IsHigh` is false at `1` and `floor(n/2)`, true at `n-1` and `floor(n/2)+1` | pass |
| `high_s_twin_is_equation_valid_but_the_public_api_rejects_it` | the P2.3 twin is accepted by `hazmat::verify_prehashed` (equation only) and rejected by `PublicKey::verify` on the same digest and key | pass |
| `the_public_signing_api_cannot_emit_a_chosen_scalar` | over a fixed 32-digest corpus, every `PrivateKey::sign` output is low-S: the sanctioned signer offers no scalar choice | pass |

Two consequences worth stating precisely:

- The predicate row pins *where the gate sits*, not what a signature does. It
  says `floor(n/2)` would pass the gate and `floor(n/2)+1` would fail it if a
  valid signature with that `s` existed. It is not an S5 verdict and is not
  counted as one.
- The equation row closes a gap in the P2.3 evidence. The twin is no longer
  merely "rejected": it is rejected while satisfying the ECDSA equation under
  the library's own equation-only primitive, so the only remaining difference
  from the accepted original is the half-order position. The four blocked
  probes have no such equation-valid witness, which is exactly why they are not
  claimed.

### 10.3 S5 status after P2.4

S5 is **partial**. Two of six probes are pinned end-to-end; four are blocked.

| S5 probe | Expected | State after P2.4 |
|---|---|---|
| High-S twin | reject | **Pinned** (§9.2; equation-validity now also pinned) |
| Low-S original | accept | **Pinned** |
| `s = 1` | accept | **Blocked** — needs a nonce-controlling signer |
| `s = n-1` | reject | **Blocked** — needs a nonce-controlling signer |
| `s = floor(n/2)` | accept | **Blocked** — needs a nonce-controlling signer |
| `s = floor(n/2)+1` | reject | **Blocked** — needs a nonce-controlling signer |

S5 is not complete. G2c remains **NO-GO** (D1) and P3 does not start (D7).

### 10.4 Dependency pin audit

**What the manifest requests.** `zerocoin/Cargo.toml:46`:

```toml
k256 = { version = "0.13", features = ["ecdsa", "arithmetic", "ecdh", "sha256", "pkcs8", "pem"] }
```

`"0.13"` is a caret requirement: `>=0.13.0, <0.14.0`. It does not name a patch
release. The `ecdsa` feature is what compiles the half-order gate in; without
it `VerifyPrimitive` is not implemented and the verify path would not exist.

**What actually resolves.** `zerocoin/Cargo.lock` — tracked by git
(`git ls-files` confirms) and format `version = 3` — records the exact graph.
The consensus-relevant chain `[VERIFIED]`:

| Crate | Version | SHA-256 checksum in `Cargo.lock` |
|---|---|---|
| `k256` | 0.13.4 | `f6e3919bbaa2945715f0bb6d3934a173d1e9a59ac23767fbaaef277265a7411b` |
| `ecdsa` | 0.16.9 | `ee27f32b5c5292967d2d4a9d7f1e0b0aed2c15daded5a60300e4abb9d8020bca` |
| `elliptic-curve` | 0.13.8 | `b5e6043086bf7973472e0c7dff2142ea0b680d30e18d9cc40f267efbf222bd47` |
| `crypto-bigint` | 0.5.5 | `0dc92fb57ca44df6db8059111ab3af99a63d5d0f8375d9972e319a379c6bab76` |
| `rfc6979` | 0.4.0 | `f8dd2a808d456c4a54e300a23e9f5a67e122c3024119acbfd73e3bf664491cb2` |
| `sec1` | 0.7.3 | `d3e97a565f76233a6003f9f5c54be1d9c5bdfa3eccfb189469f11ec4901c47dc` |
| `signature` | 2.2.0 | `77549399552de45a898a580c1b41d445bf730df867cc44e6c0233bbc4b8329de` |
| `sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` |
| `der` | 0.7.10 | `e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb` |
| `digest` | 0.10.7 | `9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292` |
| `base16ct` | 0.2.0 | `4c7f02d4ea65f2c1853089ffd8d2787bdbc63de2f0d29dedbcf8ccdfa0ccd4cf` |

**How it is enforced.** Every entry names
`source = "registry+https://github.com/rust-lang/crates.io-index"` and carries a
checksum, so Cargo verifies the downloaded `.crate` archive against the lock on
every fetch. The repository has no `.cargo/config.toml`, no `[patch]`, no
`[replace]`, no `vendor/` directory and no `url.*.insteadOf` rewrite, so
resolution is exactly "crates.io index + this lock". Any change to a resolved
version therefore appears as a visible diff in `zerocoin/Cargo.lock`.

**What is *not* pinned.** H4 is unchanged. There is no archive hash recorded
out of band, no vendored source subtree, and the manifest does not use
`=0.13.4`. A build that regenerates the lock (a deleted lock, a fresh
`cargo update`, or a resolver run under a different Cargo) can move `k256` to
any `0.13.x`, and every crate in the table with it, without any file under
`zerocoin/src/` changing.

**How an update could change consensus-relevant behaviour.** The verification
verdict is decided by four pieces of the pinned graph, each replaceable by a
patch release:

1. `k256-0.13.4/src/ecdsa.rs:201-208` — the `is_high()` early return. It is the
   only high-S rule in the stack. A patch that dropped, relaxed or reordered it
   would make the Rust node accept signatures the current binary rejects,
   splitting the chain against nodes built from this lock.
2. `k256-0.13.4/src/arithmetic/scalar.rs:42,481-485` — `IsHigh` compares against
   `ORDER >> 1`. A changed threshold would move every boundary in §10.1 by one
   scalar and invert the `floor(n/2)` / `floor(n/2)+1` verdicts.
3. `ecdsa-0.16.9/src/hazmat.rs:270-293` — the equation check itself, over the
   `crypto-bigint` and `elliptic-curve` arithmetic underneath it. A changed
   reduction, inversion or linear combination changes which signatures verify.
4. `sha2 0.10.9` — provides SHA-256, which hashes the `ZRO/sighash/v1`
   preimage. A behavioural change there changes the digest that is signed, which
   is equally consensus-visible.

The C++ kernel links none of these crates (§9.4 item 5), so an update cannot
silently change the reference implementation's behaviour; the risk is entirely
on the Rust side. That asymmetry is the G2c problem, not a mitigation.

**Review and test policy for a future cryptographic dependency update**
`[PROPOSED]`:

1. Treat `k256`, `ecdsa`, `elliptic-curve`, `crypto-bigint`, `rfc6979`, `sec1`,
   `signature` and `sha2` as consensus-critical. A version movement is a
   consensus change and needs its own phase, not a drive-by `cargo update`.
2. Change one crate at a time:
   `cargo +stable-x86_64-pc-windows-gnu update -p <crate> --precise <version>`,
   then read `git diff zerocoin/Cargo.lock` and confirm only the intended
   package's `version` and `checksum` lines moved. Do not run a bare
   `cargo update`.
3. Diff the crate source between the two versions along the paths named in
   items 1-4 above, and confirm the gate, the threshold and the equation are
   unchanged or that the change is understood and intended.
4. Re-run `scripts/gate-g1.ps1`, the P2 conformance runner, and both high-S
   targets (`high_s_signature`, `s5_boundary_probes`). Compare the verdict
   tables in §9.2 and §10.3 against the new output; a green suite with a
   changed verdict is a failure.
5. Commit the lock diff and record the new version and checksum in this
   document. The update is not accepted while G2c is NO-GO unless the C++ /
   oracle comparison in §5 is satisfied.
6. Never regenerate the lock as a side effect of an unrelated change. The lock
   is part of the consensus surface.

### 10.5 Gates observed after the change

| Gate | Command | Result |
|---|---|---|
| G1 | `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\gate-g1.ps1` | **PASS** — build (warnings as errors), ctest, 108 kernel unit tests, 28/28 corpus, 270 Rust tests across 9 targets, P0 `112 PASS / 5 ANCHOR / 0 FAIL` |
| P2 | `python kernel\tools\p2_conformance.py --vectors test\vectors --runner .build\kernel-g1\kernel_conformance.exe` | **PASS** — 21/21 replayed, 2 deferred (G2c), corruption self-check 21/21, exit 0 |
| S5 pins | `cargo +stable-x86_64-pc-windows-gnu test --test s5_boundary_probes` | **PASS** — 3/3 |
| P2.3 pins | `cargo +stable-x86_64-pc-windows-gnu test --test high_s_signature` | **PASS** — unchanged, included in the G1 Rust suite |

The Rust total moved from 267 to 270 because of the three new tests; no existing
test changed. Files changed in this phase: `zerocoin/tests/s5_boundary_probes.rs`
(new) and this section. No `.publish` state, fixture, vector or script was
touched.

### 10.6 Remaining limitations

1. S5 is **partial**: two of six probes are pinned, four are blocked by the
   absence of a nonce-controlling signer (§10.1). It is not marked complete.
2. The predicate pin proves where the gate sits, not that a signature carrying
   that scalar verifies. It is supporting evidence, not an S5 verdict.
3. The equation-validity pin uses the same library family as the code under
   test. It separates the gate from the equation, but it is not an independent
   big-integer derivation; the independent evidence for the twin remains the
   algebra in §9.1.
4. The dependency set is pinned by lockfile and checksum, not by archive hash or
   vendored source. H4 stays open, and the manifest range still permits
   `0.13.x` drift if the lock is regenerated.
5. G2c remains **NO-GO**. No backend exists, C++/libsecp256k1 parity is
   unmeasured, and no parity is claimed.
6. P3 has not started.

---

## 11. P2.6 addendum — backend acquired, built and measured; G2c still NO-GO `[VERIFIED]`

Baseline for this addendum: commit `6435d53`, clean working tree,
`HEAD == origin/main` before the change. P2.6 adds a pinned third-party source
tree, an isolated CMake project, a test-only C++ runner, a Rust-generated fixture,
a grading wrapper, a gate script and documentation. It changes no production
cryptography, no consensus rule, no dependency version and no lockfile. D1
remains in force: **G2c is still NO-GO**, but for a measured reason rather than an
absent backend. Full evidence is in
`CRYPTO_BACKEND_SELECTION_AUDIT.md` §16.

> **Superseded in part by §13.** The pinned `V4.prefix_05` divergence recorded in
> this section was closed by P2.8; §13.2 lists what moved.

### 11.1 Acquisition and build `[VERIFIED]`

libsecp256k1 `v0.8.0` was acquired as the annotated tag archive, verified with
`gpg --verify` against fingerprint
`6A8F 9C26 6528 E25A EB1D 7731 C237 1D91 CB71 6EA7` — established independently
from `SECURITY.md`, the owner's GitHub key endpoint and `keys.openpgp.org`, not
from a key shipped beside the artifact. `GOODSIG`/`VALIDSIG`, exit 0. Archive
SHA-256 `dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b`
(2,436,784 bytes). The first attempt produced `EXPKEYSIG` because the GitHub key
copy was stale; re-importing the same fingerprint from the keyserver resolved it.
That anomaly is recorded in the audit rather than smoothed over.

60 files (3,266,759 bytes) are vendored under
`kernel/third_party/secp256k1/` with `COPYING` (MIT), `ORIGIN.md` and
`SHA256SUMS`; 60/60 re-verified after the final build. The library compiles from
three translation units with `ECMULT_WINDOW_SIZE=15`, `COMB_BLOCKS=43`,
`COMB_TEETH=6` and `SECP256K1_STATIC`; every optional module is off and no
security check is disabled.

Two independent clean builds produced **byte-identical objects** for all three
source files. The static archive (1,306,932 bytes) and the runner executable
(1,397,151 bytes) differ only in metadata: 6-7 bytes of archive container
metadata, and two bytes in the PE image — `TimeDateStamp` and `CheckSum`. No
claim of byte-identical binaries is made.

### 11.2 Verification result — one consensus-relevant divergence `[VERIFIED]`

117 cases derived from the live Rust implementation, replayed through a test-only
C++ adapter that links only the vendored library:

```text
secp256k1 differential: 116/117 cases match the Rust reference (7 accept, 110 reject)
  groups                V1=2, V2=3, V3=18, V4=11, V5=5, V6=2, V7=76
  adapter load-bearing  V4.uncompressed_65 (rust=reject backend=accept)
  adapter load-bearing  V4.hybrid_prefix_06 (rust=reject backend=accept)
  documented divergence 1:
    V4.prefix_05: rust=accept seam=reject backend=reject
```

The divergence is not a fixture artefact. `sec1-0.7.3` maps tag `0x05` to
`Tag::Compact` (`src/point.rs:485-486,491-500`), whose message length is one field
element, and `k256-0.13.4` decompacts it as `decompress(x, y = even)`
(`src/arithmetic/affine.rs:204-211,247-253`). A 33-byte key `0x05 || X` is
therefore a **silent alias for `0x02 || X`** in the Rust reference.
libsecp256k1 admits only `0x02`/`0x03` at 33 bytes
(`src/eckey_impl.h:18-36`).

`zerocoin/src/crypto/secp256k1.rs:112-119` gates the SEC1 key on **length only**,
so the alias reaches the curve maths; the production path
`OP_CHECKSIG → TxSigChecker::check_signature
(zerocoin/src/ledger/sighash.rs:113-126) → PublicKey::from_sec1` accepts it. A
spender can commit `hash160(0x05 || X)` into a P2PKH `scriptPubKey` and the
current Rust node accepts the spend while a libsecp256k1-backed node rejects the
key. Two nodes would disagree on validity.

This is a live property of the Rust reference, independent of whether a C++
backend is ever adopted, and it is the milestone's own stop condition. It was not
normalised away in the adapter: the case is pinned as `--known-divergence`, and
the wrapper fails both if another case diverges and if this one starts matching.

### 11.3 Deterministic signing — still unproven `[UNVERIFIED]`

No signing comparison was performed. Both sides are RFC 6979 with low-S
normalisation (Rust `SigningKey::sign_prehash`; libsecp
`secp256k1_ecdsa_sign`), so byte parity is structurally plausible and entirely
unmeasured. U2 is unchanged, and `ledger.sighash.signature_der` stays deferred.
A green verifier does not imply a green signer.

### 11.4 S5 status — unchanged

Two of six probes pinned, four blocked. P2.6 added no signing oracle and does not
count twins, predicate tests or invalid signatures as boundary evidence. §10.3
still describes the state exactly.

### 11.5 Gates observed after the change `[VERIFIED, fresh]`

| Gate | Command | Result |
|---|---|---|
| P2.6 gate (all steps) | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gate-p2-6.ps1` | **PASS**, exit 0 |
| C++ kernel unit tests | inside the gate, fresh `.build\p26-kernel` | 108 run, 0 failed |
| G1 conformance | inside the gate | 28/28 cases |
| P2 conformance | inside the gate | 21/21 cases, corruption self-check 21/21, 2 deferred (G2c) |
| P0 baseline | `python test\harness\run_vectors.py --quiet` | `PASS 112  ANCHOR 5  SKIP 0  FAIL 0` |
| Rust suite | `cargo +stable-x86_64-pc-windows-gnu test --all-targets` | 271 passed, 0 failed across 10 targets, 1 ignored (emitter) |
| High-S pins | `--test high_s_signature` | 4 passed |
| S5 pins | `--test s5_boundary_probes` | 3 passed |
| Differential build | two empty directories, 7 artefacts each | both exit 0 |
| Differential `ctest` | `ctest --test-dir .build\p26-differential-repro-a` | 1/1 passed |
| Differential verdicts | wrapper over the 117-case fixture | 116/117, 1 pinned |

No cached build was reported. No existing test was weakened. The Rust count moved
from 270 to 271 because of the new oracle test; the fixture emitter is `#[ignore]`d
and is not counted as passing evidence.

### 11.6 Effect on the decision

D1 (NO-GO) stands, and the reason has moved:

| §5 / §14 condition | State after P2.6 |
|---|---|
| a pinned tag with archive SHA-256 and a verified GPG signature | **met** |
| a dependency-free static build from source | **met** |
| a wrapper gating SEC1, strict DER, no `s` normalisation | **met** |
| the V matrix green against Rust-derived fixtures | **not met** — 116/117 |
| S5 closed or explicitly waived | **not met** |
| a separate decision for `signature_der` | **not taken** |

What moves G2c forward, in order: a decision on `V4.prefix_05` (tighten the Rust
SEC1 gate, or authorise bug-for-bug emulation in C++ — both need their own
phase); a re-run of the matrix with that case gone or authorised; an explicit S5
disposition; and a separate `signature_der` decision.

A green isolated verifier would still not authorise production integration, and
the matrix is not green.

### 11.7 Remaining limitations

1. The backend is **isolated**: not linked into `zerocoin_kernel`, not reachable
   from `TxSigChecker`, not part of any node binary.
2. Verification parity holds for 116 of 117 executed cases and for no case that
   was not executed. No extrapolation is made beyond the fixture.
3. Reproducibility evidence covers Windows/MinGW only, and only at the object
   level; the archive and executable differ in metadata.
4. S is unmeasured; S5 is unchanged at two of six.
5. `V4.prefix_05` is an open production-crypto question, not a test gap.
6. P3 has not started, and P2.7 was not begun.

---

## 12. P2.7 addendum — `V4.prefix_05` characterised; D1 unchanged `[VERIFIED]`

P2.7 was an audit, not a fix. It answered the questions that blocked the
remediation decision and changed no production code. Full detail is in
`CRYPTO_BACKEND_SELECTION_AUDIT.md` §17; this section records only what moves
*this* document.

> **Superseded in part by §13.** Present-tense statements in §12 — "the reference
> **accepts** `0x05` today", "B1 cites code that only enforces the length" —
> describe the tree at `65a61cd`. P2.8 tightened the gate; §13 records the
> resulting state.

### 12.1 What is now known

| Question | Answer |
|---|---|
| Can a `0x05` key reach the consensus decision? | **Yes.** Traced `connect_block` / `validate_transaction` -> `script::verify` -> `OP_CHECKSIG` -> `TxSigChecker` -> `from_sec1` -> `verify_prehash`, and reproduced both mempool and block acceptance with a test |
| Does it permit theft or forgery? | **No.** The spender must hold the secret, and the output must already commit to `hash160(0x05 \|\| x)`; `OP_EQUALVERIFY` runs before `OP_CHECKSIG`, so canonical-locked outputs are unaffected in either direction |
| Is acceptance a documented rule? | **No.** `CONSENSUS_RULES` §8.4 and `CPP_PORT_REQUIREMENTS` C-38..C-47 are silent; S3 below says reject; B1 says reject while citing code that only enforces the length |
| Would tightening change the accepted set? | Yes — only spends of compact-locked outputs. Funding transactions and coinbases never parse a public key |
| Is there a live chain to split? | **No.** `README.md:297` — "Mainnet is not launched"; genesis nonce unpinned; P3 not started |

The `0x05` alias is produced by `sec1`'s `Tag::Compact` reached through a
length-only gate (`zerocoin/src/crypto/secp256k1.rs:112-121`), so it is
accidental library behaviour exceeding the type's own documented invariant
("A compressed SEC1 public key", `secp256k1.rs:105`), not a deliberate rule.

### 12.2 Effect on D1

**D1 (G2c stays blocked, NO-GO) is unchanged.** P2.7 could not change it: the
missing input is a protocol decision, and the milestone was explicitly forbidden
from making one. What changed is that the decision is now specified rather than
open-ended — the reference recommends **tightening the Rust SEC1 gate (option
A)**, executed under a separate authorisation, with **option B (C++ emulation)
rejected** because it would reproduce a suspected parser bug and turn the matrix
green without a fixture change.

Until that authorisation exists, the repository is deliberately in option C:
behaviour preserved, divergence pinned, guard bidirectional. That is the correct
state, not an oversight.

### 12.3 Correction to S3

§S3 above lists "prefix `0x00`/`0x04`/`0x05` (reject)" among the probe
expectations. That remains the correct expectation for a C++ backend and for the
intended contract, but it must not be read as a description of the reference:
the reference **accepts** `0x05` today. S3's reject rows are therefore a
specification of the target, and the `V4.prefix_05` differential row is the
evidence that the target is not yet the reference. Do not adjust S3 to match the
implementation; adjust the implementation when option A is authorised.

### 12.4 Limitations after P2.7

Items 1–5 of §11.7 stand. Item 6 is superseded: P2.7 has now been performed, but
P3 still has not started, and no production crypto, consensus rule, dependency
or vendored source was changed in P2.7.

Two limitations are added:

7. The GPG verification of the vendored archive is **not reproducible from the
   repository** — no archive, `.sig` or keyring is vendored, and `SHA256SUMS` is
   generated from the tree it validates. It proves non-drift, not upstream
   equality. See §17.9 of the audit for the evidence that would close this.
8. The recommended remediation has not been applied, so the reference and the
   backend still disagree on one of 117 cases. Any statement that the two
   implementations are compatible remains false until that case changes.

## 13. P2.8 addendum — the gate is closed in the reference `[VERIFIED]`

P2.7 recommended option A (tighten the Rust SEC1 gate) and stopped for an
authorisation. P2.8 supplies both halves: a written contract
(`docs/consensus/PUBLIC_KEY_ENCODING_CONTRACT.md`, rule **P-1**) and the
remediation that implements it. This section records only what moves *this*
document; the audit trail is in `CRYPTO_BACKEND_SELECTION_AUDIT.md` §18.

### 13.1 B1 is now code, not only prose

`PublicKey::from_sec1` (`zerocoin/src/crypto/secp256k1.rs:117-132`) rejects any
33-byte value whose tag is not `0x02` or `0x03`, before
`VerifyingKey::from_sec1_bytes` is called. B1's cited range now implements the
whole obligation, tag half included, so the documentation defect recorded in
§17.2 of the audit is closed by changing the code rather than the sentence.
`INTERFACE_CONTRACTS.md` §3.3 also gains the reconciliation sentence that was
missing: its parse-strictness paragraph constrains a backend *relative to the
reference* and never licensed the reference to exceed B1.

### 13.2 Which readiness findings move

| §2 finding | Before P2.8 | After P2.8 |
|---|---|---|
| The reference accepted a `0x05` key the backend rejects (`V4.prefix_05`) | open divergence, pinned | **closed** — both reject; 117/117 cases agree |
| B1 asserted a tag rule the code did not enforce | documentation defect | **closed** — the code enforces it |
| S3's reject expectation described a target, not the reference | correct but aspirational | **closed** — it now describes the reference |

Nothing else in §2 moves. B2 (strict DER), B3 (digest as given), B4 (high-S) and
their vectors are untouched by P2.8.

### 13.3 Effect on D1

**D1 (G2c stays blocked, NO-GO) is unchanged**, because D1 never depended on this
one case. §14's GO conditions additionally require a closed or waived S5, a
separate decision on `signature_der`, and provenance evidence reproducible from
the repository. What P2.8 does is satisfy the differential-parity condition and
the seventh condition added in §17.11 (`0x05` disposition decided).

| §14 condition | State after P2.8 |
|---|---|
| written authorisation naming one acquisition path | backend: as at P2.6; this fix: recorded in `PUBLIC_KEY_ENCODING_CONTRACT.md` |
| pinned tag, archive SHA-256, GPG signature | unchanged from §12.4 item 7 — non-drift only |
| wrapper gating SEC1 to 33 bytes / `0x02` / `0x03` | satisfied on both sides |
| §9 V matrix green | **satisfied** — 117/117, no allowance |
| S5 closed or explicitly waived | **not satisfied, not waived** |
| separate decision for `signature_der` | **not taken** |
| `0x05` disposition decided | **satisfied** — rule P-1, implemented and pinned |

### 13.4 Limitations after P2.8

Items 1–7 of §11.7 and §12.4 stand; item 8 of §12.4 is closed by §13.1.

9. Green differential parity is **one** G2c condition. It is not evidence that
   the backend is production-correct, that S5 is closed, or that the DER policy
   has been decided.
10. The backend remains outside the production verification path. No production
    code calls into the kernel, and no `SigChecker` other than the built-in
    `k256` one is reachable from `Chain`.
11. Rules P-1 and B1 are enforced at `from_sec1`. A future backend that parses
    public keys through its own path must reproduce the same tag set, and what
    proves it does is the differential corpus, not the Rust source.

## 14. P2.9 addendum — S5 closed against the Rust reference `[VERIFIED]`

P2.9 supplies the S5 half of the G2c conditions without touching production
code. The full trail is in `CRYPTO_BACKEND_SELECTION_AUDIT.md` §19; this section
records only what moves *this* document.

### 14.1 Which readiness findings move

| Condition (§13.3 / §5.1) | State after P2.9 |
|---|---|
| S5 closed or explicitly waived | **satisfied against the Rust reference** — 6/6 pinned: the two end-to-end pins plus the four scalar-boundary probes (`s = 1`, `s = n − 1`, `s = floor(n/2)`, `s = floor(n/2) + 1`), each equation-proven and verdict-recorded |
| separate decision for `signature_der` | **not taken** — unchanged; the audit §19.2 records the RFC 6979 requirement and that signing is not on the consensus validation path |
| pinned tag, archive SHA-256, GPG signature | unchanged from §12.4 item 7 — non-drift re-verified (60/60), upstream identity still not reproducible from the repository |

Nothing else in §2, §13.2 or §13.3 moves. §4's S5 group (six verdicts) is now
fully pinned against the Rust reference; the measured C++ acceptance of the
four boundary probes remains future work — the audit's V-matrix rows V3–V6 stay
open until a backend verifier exists.

### 14.2 The test-only signer is fixture-only

The signer that closes S5 lives only in `zerocoin/tests/s5_boundary_probes.rs`,
an integration-test target that cannot be linked into a node. It uses fixed
public constants (`d = 1`, nonce `k = 3`) through
`ecdsa::hazmat::sign_prehashed`, emits only fixtures, and proves equation
validity independently of the half-order gate. Production signing
(`PrivateKey::sign`, RFC 6979) and consensus verification are untouched; no file
under `zerocoin/src/` changed in P2.9.

### 14.3 Limitations after P2.9

Items 1–11 stand, with item 9 narrowed by §14.1: S5 is no longer an open
condition against the Rust reference; what remains open is S5 *against a
production C++ backend*.

12. `signature_der` remains deferred: RFC 6979 byte parity between `k256`/`ecdsa`
    and a C++ signer is structurally plausible but unmeasured (audit U2).
13. The vendored provenance is re-verified as non-drift (all 60 vendored files
    match `SHA256SUMS`); upstream identity verification remains non-reproducible
    from the repository.
