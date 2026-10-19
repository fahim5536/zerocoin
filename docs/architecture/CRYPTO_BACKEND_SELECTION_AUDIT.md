# Crypto backend selection and reproducibility audit (P2.5)

Status: **audit complete — G2c remains NO-GO, no backend acquired.**
Recorded at commit `22f1de5` (2026-10-19). This document changes no production
cryptography, no consensus rule, no dependency version and no lockfile. It makes
no parity claim: no C++ backend exists, and nothing here was measured against a
linked C++ implementation.

Companion records: `CRYPTO_BACKEND_DECISION.md` (candidate and acquisition
paths), `CRYPTO_BACKEND_READINESS.md` (H1/H2, acceptance suite S1–S7, P2.4
addendum), `INTERFACE_CONTRACTS.md` §3 (the two seams and B1–B7).

---

## 1. Verified starting state

| Item | Observed |
|---|---|
| `git rev-parse HEAD` | `22f1de5f3b5e9f7fc9f937db273c11be29d8e607` |
| Branch | `main` |
| `git status --porcelain` | empty (clean) |
| `origin/main...HEAD` | `0 0` (identical; P2.4 published) |
| P2.4 commit present | yes — `22f1de5 test(crypto): pin the S5 half-order boundary and record the P2.4 audit` |
| Preceding commits | `aebca30` (high-S pins), `eff89b8` (G2c NO-GO record) |

Governance documents read in full or in the cited sections before any judgement
was written: `COMPONENT_OWNERSHIP.md`, `INTERFACE_CONTRACTS.md` §3,
`CRYPTO_BACKEND_DECISION.md`, `CRYPTO_BACKEND_READINESS.md` (§4, §10),
`MIGRATION_ROADMAP.md`, `THREE_LANGUAGE_ARCHITECTURE.md`,
`CONSENSUS_RULES.md` (DET-12), migration `04` (R9), `05`, `06`, `07`, `08`
(§5.5, §6, §7, §8).

The three-language architecture is intact: Rust is the reference implementation
and the only shipped binary; C++ is the derived compatibility kernel; Go has no
component. C++ still depends on no Rust artefact, and Rust on no C++ artefact.

---

## 2. Host re-probe (independent of the P2.1 table)

Re-run on 2026-10-19 rather than inherited from `CRYPTO_BACKEND_DECISION.md` §2.

| Probe | Result |
|---|---|
| `where.exe openssl` | nothing on `PATH` |
| `C:\Program Files\OpenSSL-Win64`, `C:\OpenSSL-Win64` | absent |
| Git for Windows (`D:\Git`) | `usr\bin\openssl.exe` **present**, `OpenSSL 3.5.7 9 Jun 2026`; **no headers** (`usr\include\openssl\ec.h`, `mingw64\include\openssl\ec.h` absent); **no `libcrypto.a`, no `libcrypto.dll.a`**; only the runtime `mingw64\bin\libcrypto-3-x64.dll` |
| WinLibs MinGW-W64 UCRT 16.2.0 | no `include\openssl`, no `*crypto*` in `lib` or `bin` |
| `pkg-config`, `vcpkg`, `C:\vcpkg`, `C:\msys64` | absent |
| Python `coincurve`, `ecdsa`, `cryptography`, `secp256k1` | absent |
| Cargo registry (`index.crates.io-1949cf8c6b5b557f`) | `k256-0.13.4` only; no `secp256k1*`, no `openssl-*` |
| Repository | no `kernel/third_party`, no `kernel/cmake`, no `vendor/`, no `third_party/`; the only ECDSA mention in kernel source is a comment at `kernel/include/zerocoin/sighash.h:76`, and the only others are deferral notes in `kernel/tools/*.py` — no executable C/C++ curve code |
| Toolchain | CMake 4.4.3, g++ 16.2.0 (MinGW-W64 UCRT), Ninja, ctest, cargo 1.99.1, Python 3.15.0 |

Conclusion: unchanged from P2.1. **No linkable secp256k1 implementation and no
linkable OpenSSL development package exist on this host.** The OpenSSL CLI inside
Git is a private runtime, not a dependency: no headers, no import library, no ABI
guarantee, and it changes under Git upgrades. Any acquisition therefore needs
both authorisation and a network or package-manager operation, which P2.5 is
forbidden to perform.

---

## 3. Method and sources

Evidence was taken only from upstream primary sources and from the dependency
sources already on disk. No package was installed, downloaded as a dependency,
built, linked, or vendored.

| Source | Revision examined | Used for |
|---|---|---|
| `bitcoin-core/secp256k1` `include/secp256k1.h` | `master`, read 2026-10-19 (jsDelivr mirror) | API contracts: DER parse, verify, normalise, sign, nonce functions, pubkey parse |
| `bitcoin-core/secp256k1` `src/ecdsa_impl.h` | same | The actual DER reader/parser and serialiser |
| `bitcoin-core/secp256k1` `README.md` | same | Portability, dependencies, release signing, build systems, cross-compilation |
| OpenSSL 3.5 man pages: `ECDSA_sign`, `ECDSA_SIG_new`, `d2i_X509`, `EVP_SIGNATURE-ECDSA`, `provider-signature` | 3.5 documentation set | Deprecation, return values, d2i semantics, `nonce-type`, provider behaviour |
| OpenSSL `crypto/ec/ecdsa_ossl.c` | `master`, read 2026-10-19 | The verify path actually executed by `ECDSA_verify` |
| OpenSSL compilation wiki | current | Build system requirements |
| Local registry sources | `k256-0.13.4`, `ecdsa-0.16.9`, `rfc6979-0.4.0` | The Rust reference's exact sign and verify path |

**Limit of this method — stated up front.** `master` is not a release tag. No
release has been selected, so the parser and API statements below are verified
for `master` as of 2026-10-19 only. A pinned tag must be re-read at acquisition
time and any difference recorded. This is tracked as unknown **U1** in §13.

---

## 4. Candidate 1 — libsecp256k1 (bitcoin-core/secp256k1)

### 4.1 Strict DER parsing and encoding

Read from `src/ecdsa_impl.h`, not from documentation:

| Rule | Implementation | Consequence |
|---|---|---|
| Sequence tag | `secp256k1_ecdsa_sig_parse` requires leading `0x30`; the declared length must equal the remaining bytes (`rlen != sigend - sig` → "Tuple exceeds bounds or garage after tuple") | trailing bytes **outside** the sequence are rejected |
| Inner exhaustion | after two integers, `sig != sigend` → "Trailing garbage inside tuple" | trailing bytes **inside** the sequence are rejected |
| Length octets | `secp256k1_der_read_len` rejects `0xFF`, indefinite `0x80`, a leading zero in long form, and a long form whose value is `< 128` | non-shortest length encodings are rejected |
| Integer tag and length | `secp256k1_der_parse_integer` requires `0x02`, rejects zero length and out-of-bounds length | empty integers rejected |
| Minimal integers | excessive `0x00` padding (`00` followed by a byte `< 0x80`) and excessive `0xFF` padding are rejected | non-minimal integers rejected |
| Sign and width | a high bit marks the value negative (overflow); more than 32 significant bytes is overflow | negatives and oversized integers rejected |
| Range | `secp256k1_ecdsa_signature_parse_der` "will accept any valid DER encoded signature, even if the encoded numbers are out of range" — out-of-range values become scalar `0` | range is a **verification** failure, not a parse failure |

Verdict-relevance: the reference's `Signature::from_der` also rejects
non-canonical encodings and out-of-range scalars, and the seam collapses both
levels to `false`. Parse-level strictness that exceeds the reference is
acceptable only where the verdict cannot change (B5, `INTERFACE_CONTRACTS.md`
§3); the cases above do not change any verdict.

### 4.2 Low-S / high-S behaviour

`secp256k1_ecdsa_verify` documents: "To avoid accepting malleable signatures,
only ECDSA signatures in lower-S form are accepted." The same comment warns that
a caller holding a high-S encoding must normalise it before verification — a step
the wrapper must **never** take, because it would accept what Rust rejects. The
lower-S range is documented as `0x1` … `0x7FFF…B20A0` inclusive — i.e.
`1 ≤ s ≤ floor(n/2)`, the same boundary the Rust reference implements with
`is_high()` at `k256-0.13.4/src/ecdsa.rs:201-208`.

Consequence: **B4 requires no code in the wrapper.** The wrapper must *not* call
`secp256k1_ecdsa_signature_normalize`; doing so would accept what Rust rejects.
This is the opposite of the withdrawn §7.3 plan in `CRYPTO_BACKEND_DECISION.md`,
which is why that plan stays withdrawn.

### 4.3 Compressed public keys and invalid points

`secp256k1_ec_pubkey_parse` accepts **three** encodings:

- compressed: 33 bytes, prefix `0x02`/`0x03`;
- uncompressed: 65 bytes, prefix `0x04`;
- hybrid: 65 bytes, prefix `0x06`/`0x07`.

B1 allows only the first. Therefore the wrapper — not the library — must enforce
**exactly 33 bytes and prefix `0x02`/`0x03`** before calling the parser. Invalid
points, off-curve `x`, and the point at infinity are rejected by the library and
surface as a non-zero return.

### 4.4 Malformed-signature rejection

Every parse path returns an integer status; failures leave the output object
unmodified or zeroed. A wrapper that checks each return value and returns `false`
satisfies B5 without exceptions, without error strings, and without logging key
material. No allocation is retained between calls.

### 4.5 Deterministic signing and RFC 6979 parity

- `secp256k1_nonce_function_rfc6979` is documented as HMAC-SHA256 based.
- `secp256k1_nonce_function_default` is documented as *currently equal* to the
  RFC 6979 function — an explicit reminder that this is policy, not a guarantee.
- `secp256k1_ecdsa_sign` with a `NULL` nonce function uses the default; the
  created signature is **always lower-S**.
- The nonce function is a caller-supplied parameter, so a chosen-nonce signer is
  expressible **outside** the kernel, in a test harness, without touching the
  library.

The Rust reference's path, read from the local registry:

```text
SigningKey::sign_prehash
  → try_sign_prehashed_rfc6979::<Sha256>(&z, &[])      ecdsa-0.16.9/src/signing.rs
  → rfc6979::generate_k(secret, C::ORDER, z, ad = &[])  ecdsa-0.16.9/src/hazmat.rs
  → signature; then normalize_s().unwrap_or(sig)        k256-0.13.4/src/ecdsa.rs:194
```

The two constructions are structurally identical: HMAC-SHA256 RFC 6979, the
secret scalar and the group order as key material, the **raw 32-byte prehash** as
the message, no additional data, and a lower-S result. Structural identity is
not byte identity. Byte-for-byte equality of the emitted DER has **not** been
demonstrated, because that needs both implementations built and compared over the
same `(d, z)` corpus. Tracked as unknown **U2**. This is the difference between
"verification parity" and "deterministic signing parity" in §9.

### 4.6 Licence, provenance, platforms, maintenance

| Aspect | Observation |
|---|---|
| Licence | MIT (per-file headers; `COPYING`) — compatible with the repository's MIT |
| Runtime dependencies | none; no global state; constant-time verification path |
| Portability | documented as portable to any C89 compiler with `uint64_t`; `README` states no runtime dependencies |
| Release integrity | release **tags are GPG-signed**; the README documents `git tag -v` and the maintainer fingerprint used to verify them |
| Build systems | Autotools and CMake both current; cross-compilation toolchain files are shipped for `x86_64-w64-mingw32` and the Android NDK; Windows native build documented with VS2022/clang-cl |
| Generated sources | none are required in-tree; whether the pinned build generates precomputed tables is part of the recorded configuration (U3) |
| Maintenance | active; the de-facto reference implementation of the curve for consensus software |

### 4.7 Testability without changing consensus behaviour

Yes. The library can be linked into the **test-only** conformance binary
(`kernel_conformance`), which doc `08` §8.1 already requires never to be linked
into a node. The production seams (`SigChecker`, `SigVerifier`) keep failing
closed with a null verifier until an authorised phase accepts a wrapper. No
consensus rule has to be re-implemented in the wrapper, which is the decisive
property: the only rule the wrapper would own is the 33-byte/`0x02`/`0x03` gate,
which is an interface restriction, not a curve rule.

---

## 5. Candidate 2 — OpenSSL 3.x (`libcrypto`)

### 5.1 Strict DER and trailing bytes

Two different behaviours exist, and conflating them is an easy mistake:

- **Buffer-level `ECDSA_verify`** decodes with `d2i_ECDSA_SIG`, re-encodes with
  `i2d_ECDSA_SIG`, and requires the re-encoded length and bytes to equal the
  input (`crypto/ec/ecdsa_ossl.c`, `ossl_ecdsa_verify`). That round-trip **does**
  enforce canonical DER and rejects trailing bytes at the buffer level.
- **Raw `d2i_ECDSA_SIG`** accepts BER — the `d2i_X509` man page states the family
  "can also understand BER forms" — and advances the input pointer past the parsed
  object, leaving any trailing bytes to the caller.

So a wrapper built on `d2i` directly must re-implement length and canonicality
checks; a wrapper built on the buffer-level `ECDSA_verify` gets them for free.

### 5.2 Low-S / high-S

`ossl_ecdsa_simple_verify_sig` checks only that `r` and `s` are non-zero,
non-negative and `< order`, then evaluates the equation. **There is no low-S
check.** A high-S signature verifies.

Consequence: to match the reference, the wrapper would have to implement the
half-order rule itself — `s > floor(n/2) → false` — i.e. re-implement a
consensus-relevant rule inside this repository, exactly what constraint 2 and
doc `04` R9 exist to prevent. This is a structural objection, not a bug that can
be patched around.

### 5.3 Compressed keys and malformed input

OpenSSL supports compressed points, but the public key arrives through
`EVP_PKEY`/`EC_POINT` parsing, not through a raw SEC1 length check. The wrapper
would again have to gate 33 bytes and `0x02`/`0x03` explicitly, and would then
depend on OpenSSL's point validation for the remaining cases.

### 5.4 Return-value semantics

`ECDSA_verify` and `ECDSA_do_verify` return **1 valid, 0 invalid, -1 error**. A
wrapper that treats "non-zero" as success would fail **open** on error. Mapping
`-1` to `false` is required and must be tested. The low-level ECDSA functions are
**deprecated since OpenSSL 3.0**, which makes them a poor long-term target.

### 5.5 Deterministic signing

EVP exposes `OSSL_SIGNATURE_PARAM_NONCE_TYPE`; setting it to `1` selects RFC 6979
and **requires the digest parameter to be set explicitly**. The default is `0`
(random, FIPS 186-4 §6.3), and the `provider-signature` documentation records that
deterministic ECDSA reached the FIPS provider only in OpenSSL 3.6. Nothing in the
documentation states that the RFC 6979 output matches RustCrypto's, so signing
parity would be a further unknown (U5) on top of the low-S problem.

### 5.6 Build, licence, provenance

| Aspect | Observation |
|---|---|
| Licence | Apache-2.0 — compatible |
| Build system | custom Perl-based `Configure`, not autotools; the library must be built with a C compiler (not C++); `make test` is required for a trustworthy build; Perl 5.10+ |
| Platforms | Linux, Windows, macOS, Android documented; broad but large |
| Provenance | release tarballs are published with signatures and hashes; the surface is far larger than the kernel needs |
| Host state | no development package, no headers, no import library (§2) |

### 5.7 Verdict

**Fallback only.** It is licence-compatible and its buffer-level verify is
DER-canonical, but it is missing the rule the reference enforces, returns a
three-valued status that fails open if mishandled, deprecates the exact API a
wrapper would use, has no demonstrated RFC 6979 byte parity, and requires a
Perl-driven build. Selecting it would move a consensus rule into this repository.

---

## 6. Candidate 3 — any already-present backend

None exists. The probes in §2 found no C/C++ curve implementation in the
repository, on the host, or in the toolchain. The only curve implementation
present is the Rust `k256` crate, which is:
- the reference implementation itself (so it is the oracle, not an independent
  backend), and
- unlinkable into C++ without a Rust toolchain, which constraint 5 forbids.

The kernel therefore still links nothing, and G2c is blocked for the same reason
as before, not for a new one.

---

## 7. Requirement-by-requirement comparison

Legend: **native** = the library provides it; **wrapper** = the wrapper must
implement it; **diverges** = matching would require re-implementing a consensus
rule here.

| Requirement | libsecp256k1 | OpenSSL 3.x | In-repo |
|---|---|---|---|
| B1: 33-byte compressed only | wrapper gate (library also accepts 65-byte forms) | wrapper gate (EVP parsing) | n/a |
| B2: strict DER, no trailing bytes | **native** (`ecdsa_impl.h`) | native at `ECDSA_verify` buffer level; wrapper needed if `d2i` used | n/a |
| B3: no re-hashing | **native** (takes a 32-byte message) | native (`ECDSA_verify` takes a digest) | n/a |
| B4: high-S rejection, no normalisation | **native** (`verify` rejects high-S) | **diverges** — verifies high-S; wrapper would own the rule | n/a |
| B5: malformed → `false`, never throw | **native** (integer status) | wrapper must map `-1` errors | n/a |
| B6: re-entrant / thread-safe | **native** (immutable context, no globals) | native with care (error queue is per-thread) | n/a |
| B7: no key logging | structural (inputs public; no callbacks) | structural | n/a |
| RFC 6979 signing parity | structurally identical; **byte equality unproven (U2)** | `nonce-type=1` only, parity unproven (U5) | exact, but unlinkable |
| Licence | MIT | Apache-2.0 | MIT |
| Release integrity | GPG-signed tags | signed releases | git tags |
| Platform reach | MinGW, MSVC, Linux, macOS, Android NDK | broader; heavier | n/a |
| Build reproducibility | CMake/autotools, no runtime deps, C89 | Perl-driven, requires C compiler, `make test` | n/a |
| Test without changing consensus | yes — test-only conformance binary | yes, but wrapper must own B4 | n/a |

---

## 8. Recommendation

1. **libsecp256k1 remains the selected candidate.** It is the only candidate that
   supplies B4 natively, which is the requirement that decides G2c. Every other
   requirement is either native or an interface-level gate the wrapper must
   enforce anyway.
2. **Acquisition path A — vendor one pinned source archive** — remains the
   recommendation (`CRYPTO_BACKEND_DECISION.md` §11): exact tag, GPG-verified,
   SHA-256 recorded, committed under `kernel/third_party/secp256k1/` with
   `LICENSE`, `SHA256SUMS` and `ORIGIN`.
3. **OpenSSL is retained only as a fallback** and should not be selected while
   B4 would have to be implemented here.
4. **No decision to proceed.** Acquisition is not authorised in P2.5, so the
   recommendation is a *selection*, not a *commitment*, and the verdict stays
   NO-GO (§14).

What would overturn the recommendation: a pinned release whose parser differs
from the `master` behaviour recorded here (U1); a measured RFC 6979 mismatch
against the Rust reference (U2); or a CMake build in the pinned tag that cannot
produce a dependency-free static library (U3).

---

## 9. Differential conformance matrix (Rust vs C++)

Two axes, deliberately separate:

- **V — verification parity.** The C++ verifier returns the same verdict as the
  Rust reference for the same `(public key, DER signature, 32-byte digest)`.
  Closing V lifts the P2 slice to **22/23** and closes
  `ledger.script.p2pkh_spend_accepted`.
- **S — deterministic signing parity.** Both implementations emit the **same DER
  bytes** for the same `(secret key, 32-byte digest)`. Closing S is what
  `ledger.sighash.signature_der` and the reverse direction of S7 require.

**A verification-only backend does not close S.** Passing every V row below
leaves `signature_der` deferred, and any claim otherwise is false.

Every fixture is generated by the Rust reference first, committed as bytes, and
replayed against both implementations. No expected value is written by hand.

| # | Family | Input construction | Rust oracle | Expected C++ | Axis | Exists today |
|---|---|---|---|---|---|---|
| V1 | Valid low-S | P2 corpus signature, and fresh `PrivateKey::sign` outputs | accept | accept | V | partly (P2.3 pin) |
| V2 | High-S twin | `s' = n - s` of V1 | reject | reject | V | yes (P2.3/P2.4 pins) |
| V3 | Lower-S boundary accept | `s = 1` (valid `r`) | accept | accept | V | **blocked** (§10) |
| V4 | Lower-S boundary reject | `s = n - 1` | reject | reject | V | **blocked** |
| V5 | Half-order accept | `s = floor(n/2)` | accept | accept | V | **blocked** |
| V6 | Half-order reject | `s = floor(n/2) + 1` | reject | reject | V | **blocked** |
| V7 | Malformed DER | non-minimal length; indefinite `0x80`; `0xFF`; truncated integer; empty integer; negative integer; integer > 32 bytes; wrong tag | reject | reject | V | yes (S2, partly) |
| V8 | Trailing bytes | one byte after the sequence; one byte inside the sequence | reject | reject | V | yes (S2, partly) |
| V9 | Scalar range | `r = 0`, `s = 0`, `r ≥ n`, `s ≥ n` | reject | reject | V | yes (S2, partly) |
| V10 | Public keys | 33-byte `0x02`/`0x03` accept; 65-byte `0x04`; hybrid `0x06`/`0x07`; prefixes `0x00`/`0x05`; lengths 32/34; `x = p`; off-curve; infinity | accept/reject set | identical | V | yes (S1) |
| V11 | Digest handling | digest that is not `SHA-256(message)`; digest `≥ n`; all-zero digest; leading `0x00` byte | oracle verdicts | identical | V | yes (S4) |
| V12 | Byte order | 32-byte big-endian scalar interpretation; ZeroCoin sighash preimage with LE-`u32` type fold (F18) | oracle verdicts | identical | V | yes (S3/S6) |
| V13 | P2 corpus | 21 cases in the current fixture; the 23-case P2 slice including both deferrals | 21/21 fixture; 21/23 slice | 21/21 fixture; **22/23** slice once the verifier closes `p2pkh_spend_accepted` | V | yes (21/21) |
| V14 | Corruption guard | every replayed case, one output byte flipped | n/a | all rejected, none accepted | V | yes (21/21) |
| V15 | Error mapping | null/empty signature or key; missing trailing `0x01`; out-of-range input index; null verifier | `false` | `false`, no throw, no log | V | yes (seam tests) |
| S1 | Deterministic DER | same `(d, z)` → both emit identical bytes, lower-S | bytes | **byte-identical** | S | **no — needs signing** |
| S2 | Cross-signing | Rust signs → C++ verifies; C++ test signer → Rust verifies | accept | accept | S | **no** |
| S3 | Signature fixture | `ledger.sighash.signature_der` (`{digest, scalar: 1}`) | expected DER | produced DER | S | **no** |

Ordering rule: V rows must be green **before** S rows are attempted, because a
failing verifier makes a signing result uninterpretable. V and S are reported
separately; a green V table never implies a green S table.

Fail-closed requirements for every C++ row: a parse error, a verify error, a null
pointer, a short buffer, or an unexpected library return value must produce
`false`, never a throw, never a partial success, and never a log line containing
key or signature material.

---

## 10. S5 boundary probes — decision

P2.4 established that the four remaining S5 probes are blocked by the absence of
a nonce-controlling signer, not by a missing test idea
(`CRYPTO_BACKEND_READINESS.md` §10.1). For key `d`, nonce `k` and digest `z`:

```text
r = x(k*G) mod n
s = k^-1 * (z + r*d) mod n
```

`s` is an output of signing. A chosen `s` must be solved for: fix `k`, compute
`r`, then choose `z' = z + k*(s_target − s)` so the equation yields `s_target`.
Mutating `s` in an existing signature does not work — `r`, `z`, `Q` stay fixed, so
`x(u1*G + u2*Q) ≠ r` and the probe fails on the equation rather than on the
half-order position.

**Decision: do not add a signer in P2.5.** Reasons:

1. The brief forbids adding a signer automatically and forbids altering production
   crypto or consensus code. No verification gate in this milestone requires
   one, so the justification for a test-only oracle is absent today.
2. No acceptance criterion requires S5 to be closed before a backend is
   authorised; S5 is a backend acceptance group.
3. A predicate-only test must not be relabelled as a verdict. P2.4's three pins
   stay classified as support, not as S5 probes.

Evidence required to close each probe, recorded now so a future phase is
mechanical:

| Probe | Required construction | Required evidence |
|---|---|---|
| `s = 1` | fixed `k`, `r = x(k*G)`, `z' = z + k*(1 − s)` | the resulting signature verifies **true** through the public verifier, and an independent equation check confirms it is ECDSA-valid |
| `s = n − 1` | same with `s_target = n − 1` | verifies **false**, and the equation-validity proof shows the only failing condition is the half-order gate |
| `s = floor(n/2)` | same with `s_target = floor(n/2)` | verifies **true** |
| `s = floor(n/2) + 1` | same with `s_target = floor(n/2) + 1` | verifies **false**, equation-valid |

A future test-only signer would have to satisfy all of: use
`ecdsa::hazmat::sign_prehashed` (`ecdsa-0.16.9/src/hazmat.rs:224-259`,
re-exported as `k256::ecdsa::hazmat`) or an independent modular derivation;
live in a target that cannot be linked into a node; emit only fixtures; prove
equation validity independently of the gate under test; and never be counted as a
production signing path. Until then the four probes stay **Blocked**, and S5
stays **partial: 2 of 6 pinned**.

---

## 11. Dependency reproducibility policy (recommendation)

No version and no lockfile entry is changed in P2.5. The following is the
recommended policy for the authorised phase.

### 11.1 Cargo.lock enforcement

1. `zerocoin/Cargo.lock` is tracked and is **part of the consensus surface**, not
   build metadata. It is never regenerated by an unrelated change.
2. Every gate and CI invocation of Cargo uses `--locked`. The current
   `scripts/gate-g1.ps1` invokes `cargo test` **without** `--locked`; adding it is
   a gate change and is therefore proposed, not made here.
3. A lock diff is reviewed as a consensus change: the reviewer must be able to
   state which resolved version moved, why, and which source path was read.
4. `cargo update` is never run bare. One crate at a time, with `--precise`, and
   the lock diff must contain only the intended package.

### 11.2 Reviewing cryptographic dependency changes

Adopt §10.4's proposed list as policy: `k256`, `ecdsa`, `elliptic-curve`,
`crypto-bigint`, `rfc6979`, `sec1`, `signature`, `sha2`, `der`, `digest` are
consensus-critical. A version movement is its own phase with: source diff along
the high-S gate, the `ORDER >> 1` threshold, the equation, and the sighash
digest; then `scripts/gate-g1.ps1`, the P2 conformance runner, `high_s_signature`
and `s5_boundary_probes`; then the verdict tables compared line by line. A green
suite with a changed verdict is a failure.

### 11.3 Obtaining and verifying a C++ backend archive

1. Exact release tag (or commit SHA), never a branch, never "latest".
2. Verify the **GPG-signed tag** against the maintainer fingerprint published in
   the upstream README before extracting; record the fingerprint and the
   verification transcript in the acquisition record.
3. Record the **SHA-256 of the source archive** in `ORIGIN` and `SHA256SUMS`
   alongside the vendored subtree; the build re-verifies the tree against those
   hashes.
4. Vendor the upstream `LICENSE`; no file is edited after extraction.
5. No generated sources, no `contrib/` code, no lax parser.
6. Build offline: the build must succeed with the network disabled and the source
   tree read-only.

### 11.4 Version and integrity pinning

Pin by four independent things: tag, archive SHA-256, vendored tree hash, and the
recorded CMake configuration (precomputed tables, field/scalar backend, every
`SECP256K1_*` option that affects behaviour or binary layout). A version range is
never sufficient for a consensus dependency.

### 11.5 Reproducible builds and supported CI platforms

| Platform | Status |
|---|---|
| Windows x86-64, MinGW-w64 UCRT | required now — the only platform exercised by the gate |
| Windows x86-64, MSVC | required at G7 |
| Linux x86-64 | required at G7 |
| macOS Intel/ARM | required at G7 |
| Android arm64 (NDK) | wallet only; the C++ node is not planned there |

Requirements: identical third-party warning policy recorded per platform (the
kernel keeps `-Wall -Wextra -Wpedantic -Werror` for its own sources), recorded
compiler/CMake versions, static linkage with no new DLL dependency on Windows,
and no reliance on the OpenSSL bundled with Git.

---

## 12. Gate results (fresh, this milestone)

All Rust and C++ results below were produced for this audit. The C++ artefacts
come from a **new** build directory (`.build\p25-final`) that compiled every
target from scratch after the last edit to this document; the same gate also
passed from a second new directory (`.build\p25-fresh`) before it, and an earlier
cached build (`ninja: no work to do`) was discarded rather than reported.

| Gate | Command | Observed | Exit |
|---|---|---|---|
| G1 (full) | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gate-g1.ps1 -BuildDir .build\p25-final` | build 23/23 from scratch; ctest 3/3 (`kernel_unit`, `kernel_conformance`, `kernel_p2_conformance`); `kernel unit tests: 108 run, 0 failed`; `g1 conformance: 28/28 cases replayed against source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c`; Rust `270 passed, 0 failed across 9 targets`; P0 `PASS 112  ANCHOR 5  SKIP 0  FAIL 0`; `G1: PASS` | **0** |
| Rust suite (per target) | as invoked by the gate | `235, 0, 0, 0, 20, 2, 6, 4, 3` passed; 0 failed on every target | 0 |
| P0 verifier | `python test\harness\run_vectors.py --quiet` | corpus 117 cases, schema `zro-baseline-vectors/1`; `PASS 112  ANCHOR 5  SKIP 0  FAIL 0` | 0 |
| High-S pins | `cargo +stable-x86_64-pc-windows-gnu test --manifest-path zerocoin\Cargo.toml --test high_s_signature` | 4 tests: `valid_low_s_sighash_signature_is_accepted`, `high_s_twin_is_rejected_at_verification`, `invalid_signatures_are_still_rejected`, `signing_conventions_are_pinned`; `test result: ok. 4 passed; 0 failed` | **0** |
| S5 pins | `cargo +stable-x86_64-pc-windows-gnu test --manifest-path zerocoin\Cargo.toml --test s5_boundary_probes` | 3 tests: `high_s_predicate_boundary_is_strictly_above_half_the_group_order`, `high_s_twin_is_equation_valid_but_the_public_api_rejects_it`, `the_public_signing_api_cannot_emit_a_chosen_scalar`; `test result: ok. 3 passed; 0 failed` | **0** |
| P2 conformance | `python kernel\tools\p2_conformance.py --vectors test\vectors --runner .build\p25-final\kernel_conformance.exe` | `p2 conformance: 21/21 cases replayed against source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c`; `ledger.script 14`; `ledger.sighash 7`; `deferred (G2c) 2: ledger.script.p2pkh_spend_accepted, ledger.sighash.signature_der`; `corruption self-check rejected 21/21 cases` | **0** |

No gate was skipped and no PASS is inherited from an earlier run. The two
deferred corpus cases are reported as deferred, not as passed.

Environment recorded with the run: CMake 4.4.3, g++ 16.2.0 (GNU, WinLibs
MinGW-W64 UCRT), Ninja, cargo 1.99.1 (`5f94df478 2026-08-27`), Python 3.15.0.

---

## 13. Risks and unresolved unknowns

| ID | Unknown / risk | Impact | How it is closed |
|---|---|---|---|
| **U1** | The source statements in §4 come from `master` on 2026-10-19, not from a pinned release | A tag could differ in parser detail or defaults | Read the pinned tag's `secp256k1.h`, `ecdsa_impl.h` and build files at acquisition and record a diff against this audit |
| **U2** | RFC 6979 **byte** parity between `k256`/`ecdsa` and libsecp256k1 is structurally plausible but unmeasured | `signature_der` and S7 reverse direction cannot close on structure alone | Build both, sign the same `(d, z)` corpus, compare DER bytes |
| **U3** | The pinned release's CMake build may not produce a dependency-free static library without autotools | Reproducibility and offline-build requirement | Verify at acquisition; if CMake is insufficient, record the autotools run as its own decision |
| **U4** | Only Windows/MinGW is exercised by any gate | Cross-platform claims are expectations, not evidence | G7 CI matrix |
| **U5** | OpenSSL's RFC 6979 output is not documented to match RustCrypto's | A fallback would need its own parity proof | Only relevant if OpenSSL is ever selected |
| R9 | Incompatible crypto library behaviour (risk register) | Cross-verification failure in G2 | §9 V matrix; no C++ row can be green until a backend exists |
| H2 | `signature_der` needs a signer, not a verifier | Caps verification-only work at 22/23 | A separate decision about a test-only signer (§10) |
| H4 | No backend archive pin, no vendored subtree | Dependency provenance unproven | §11.3, after authorisation |
| S5 | 2 of 6 probes pinned; 4 blocked | High-S boundary evidence incomplete | §10 evidence table |

None of these is a reason to change a consensus rule, a fixture expectation, or
the reference implementation.

---

## 14. G2c and P3 verdict

**G2c: NO-GO.** The decision is unchanged from P2.2 and P2.4
(`CRYPTO_BACKEND_READINESS.md` §5 D1):

- no backend is authorised, acquired, pinned or linked;
- no C++ signature verification exists, so the kernel still cannot validate a
  spend;
- the two corpus cases stay deferred, for two different reasons;
- S5 is partial and no parity is measured.

To become **GO**, all of the following are needed: a written authorisation naming
one acquisition path; a pinned tag with archive SHA-256 and verified GPG
signature; a wrapper that gates SEC1 to 33 bytes/`0x02`/`0x03`, parses strict DER
and **never normalises `s`**; the §9 V matrix green against Rust-generated
fixtures; S5 closed or explicitly waived by the same decision; and a separate
decision for `signature_der` if signing is required.

**P3: not started.** No Go networking work, no service layer, no RPC surface. The
milestone stops here.

---

## 15. Files changed and non-claims

Changed in P2.5:

- this document (new);
- `docs/architecture/CRYPTO_BACKEND_DECISION.md` — P2.5 amendment note, a
  precision fix to §7.2's `[UNVERIFIED]` sentence, and a pointer to this audit;
- `docs/migration/README.md` — document index entry for this audit.

Not changed: any file under `zerocoin/src/`, `kernel/include/`, `kernel/src/`,
`test/`, or `scripts/`; `Cargo.toml`; `Cargo.lock`; any fixture; any vector; any
`.publish` state; Git identity or remote configuration.

Explicitly **not** claimed:

- no signature compatibility between C++ and Rust;
- no closure of G2c, of gate G2, or of the P2 exit criteria;
- no RFC 6979 byte parity;
- no dependency pin, archive hash, or licence verification of an acquired
  artefact;
- no use of Git's bundled OpenSSL;
- no change to the kernel's dependency set — it still links nothing.
