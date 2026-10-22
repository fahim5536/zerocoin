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

> **Executed and superseded by §16.** The table below is the P2.5 *plan*, written
> before a backend existed and using its own `V1..V15` family labels. P2.6 ran a
> 117-case matrix; §16 records the measured per-case results. The `V1..V7`
> labels used there are the **fixture's group labels** and are not the same
> taxonomy as `V1..V15` here.

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

> **Restated with measurements in §16.10.** The reasons below describe the P2.5
> state, when no backend had been acquired. P2.6 acquired, built and measured
> one; the verdict is still NO-GO, for a different and now measured reason
> (§16.6).

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

---

## 16. P2.6 addendum — acquisition, reproducible build, and the measured differential result

This section records what P2.6 **executed**. It replaces §9's planned matrix with
measured results and restates §14's verdict. It does not supersede §10 (S5), §11
(acquisition paths) or §13 (risks); those stay as written, with the status
updates called out below.

Baseline: repository root `D:\Downloads\zerocoin\.publish\upstream`, branch
`main`, `HEAD == origin/main == 6435d53`
(`docs(architecture): record the P2.5 backend selection audit`), remote `origin` →
`https://github.com/fahim5536/zerocoin.git`, working tree clean apart from the
files this milestone adds. No user change was present and none was overwritten.

P2.6 adds a pinned third-party source tree, an isolated CMake project, a test-only
C++ runner, a Rust-generated fixture, a grading wrapper, a gate script and this
section. It changes **no** file under `zerocoin/src/`, no consensus rule, no
kernel source, no existing fixture and no vector.

### 16.1 Provenance and integrity `[VERIFIED]`

`kernel/third_party/secp256k1/ORIGIN.md` is the byte-level record; this is its
summary.

| Field | Value |
|---|---|
| Repository | `https://github.com/bitcoin-core/secp256k1` |
| Release | annotated, PGP-signed tag `v0.8.0` — not a branch, not `master` |
| Tag object | `18f07c42218765cd46148d74d9fe575795f56dce` |
| Commit | `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d` |
| Archive | `libsecp256k1-0.8.0.tar.gz`, 2,436,784 bytes |
| Archive SHA-256 | `dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b` |
| Signature | `libsecp256k1-0.8.0.tar.gz.sig`, 566 bytes, SHA-256 `c7eb14bbd67fe94b9ac4b556df6ae18aebb450092c836d05a6e13ea005fc7ac8` |
| Signer fingerprint | `6A8F 9C26 6528 E25A EB1D  7731 C237 1D91 CB71 6EA7` — RSA 4096, Sebastian Falbesoner (theStack) |
| `gpg --status-fd 1 --verify` | `GOODSIG` and `VALIDSIG`, exit **0** |
| Acquired | 2026-10-19 |
| Licence | MIT, `Copyright (c) 2013 Pieter Wuille` |

The fingerprint was established **independently of the downloaded archive**, from
three sources that agree: `SECURITY.md` at the tag, the owner-controlled GitHub
key endpoint `https://github.com/thestack.gpg`, and `keys.openpgp.org` queried by
fingerprint. `TRUST_UNDEFINED` is expected: this host has no web-of-trust path to
the key, so trust comes from the cross-reference, not from a certification chain.

**Recorded anomaly, not a silent success.** The key copy served by
`https://github.com/thestack.gpg` was stale — it expired `2025-11-20`, before the
signature was made on `2026-08-03` — and the first verification attempt produced
`EXPKEYSIG`. Re-importing the keyserver copy of the *same fingerprint* added the
later self-signatures, and the same signature then verified `GOODSIG`/`VALIDSIG`.
Only the expiry assertion changed; the fingerprint did not.

**Tree integrity.** `SHA256SUMS` covers every vendored file plus the archive
itself. Re-verified after the final build: **60/60 files match, 0 mismatches**,
3,266,759 bytes. Every vendored file except `ORIGIN.md` and `SHA256SUMS` is a
byte-for-byte copy of the upstream path; nothing was edited, patched, generated
or reformatted.

### 16.2 Vendored footprint, licence and attribution `[VERIFIED]`

```text
kernel/third_party/secp256k1/
  COPYING                         upstream MIT licence, verbatim
  ORIGIN.md                       this provenance record
  SHA256SUMS                      per-file and archive digests
  include/secp256k1.h             the whole public API surface used
  include/secp256k1_preallocated.h
  src/*.h                         headers required by the three .c files
  src/secp256k1.c                 the library
  src/precomputed_ecmult.c        shipped verification table
  src/precomputed_ecmult_gen.c    shipped signing table
```

Compiled translation units: exactly the three `.c` files above. Omitted on
purpose: every `src/modules/**`, upstream's own test and benchmark sources, the
`precompute_*.c` generators, the module headers, `cmake/`, `.github/`, `ci/`,
`contrib/`, `doc/`, `sage/`, `tools/`, `examples/`, and upstream's
`CMakeLists.txt` (its option semantics are transcribed in `ORIGIN.md` §4).
`README.md` and `SECURITY.md` are omitted from the tree to keep the footprint
minimal; `SECURITY.md` remains one of the three fingerprint sources.

Defines, all transcribed from upstream `v0.8.0` rather than guessed:

| Define | Value | Why |
|---|---|---|
| `ECMULT_WINDOW_SIZE` | `15` | must match the shipped `precomputed_ecmult.c` table |
| `COMB_BLOCKS` | `43` | must match the shipped `precomputed_ecmult_gen.c` table |
| `COMB_TEETH` | `6` | same |
| `SECP256K1_STATIC` | defined, `PUBLIC` | static linkage on Windows; suppresses `dllimport` |

Deliberately **not** defined: every `ENABLE_MODULE_*`, `USE_EXTERNAL_DEFAULT_CALLBACKS`,
`USE_FORCE_WIDEMUL_*`, `SECP256K1_NO_API_VISIBILITY_ATTRIBUTES`. The field,
scalar and widemul backends are left to upstream's own compile-time detection,
exactly as an upstream default build does. **No security check was disabled**:
the library is compiled whole, with its runtime verification intact.

Licence: `COPYING` is MIT and is vendored verbatim; every `.c`/`.h` file keeps its
upstream copyright header. The library is not linked into any shipped binary in
P2.6, so no release attribution obligation has been triggered yet. That
obligation starts if and when it is linked into a node.

### 16.3 Reproducible build `[VERIFIED]`

Standalone project, outside `kernel/CMakeLists.txt` and outside the
`zerocoin_kernel` target:

```powershell
cmake -S kernel/differential -B .build/p26-differential-repro-a -G Ninja
cmake --build .build/p26-differential-repro-a
ctest --test-dir .build/p26-differential-repro-a --output-on-failure
```

`CMAKE_BUILD_TYPE` defaults to `Release` when neither the cache nor a multi-config
generator supplies one. `CMAKE_C_STANDARD 90` for the vendored C (as upstream
builds it), `CMAKE_CXX_STANDARD 20` for the harness. No optimisation level is
forced, no global compiler flag is added, and no toolchain file is used. Warnings
are errors (`-Wall -Wextra -Wpedantic -Werror`) on ZeroCoin-authored translation
units only — never on the vendored tree, which must stay byte-for-byte upstream.

Toolchain observed for every build below: CMake 4.4.3, Ninja 1.13.2, GCC and G++
16.2.0 (WinLibs MinGW-W64, UCRT, POSIX threads, SEH) from
`...\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_...\mingw64\bin`, Python
3.15.0, cargo 1.99.1 (`5f94df478 2026-08-27`), rustc 1.99.1
(`58cf8f9c3 2026-10-13`), host `x86_64-pc-windows-gnu`.

Two independent clean builds from empty directories (`.build/p26-differential-repro-a`
and `...-b`) produced seven artefacts each. Byte comparison:

| Artefact | Length | Result |
|---|---|---|
| `secp256k1.c.obj` | 167,189 | **byte-identical**, sha256 `18b385efe4f199322b3855ff6c3dd45c3db141d4b9fe67a299cc51a74e97e306` |
| `precomputed_ecmult.c.obj` | 1,049,211 | **byte-identical**, sha256 `93e43da54eddf2975c7b918b33ad44168eb9fdb021943eda4956b11a1e8fde7b` |
| `precomputed_ecmult_gen.c.obj` | 88,681 | **byte-identical**, sha256 `e2cc3bc1080ce0d27f3dec0aa76702d56d2b06a9f581796b5f541e79e9769609` |
| `libsecp256k1_vendored.a` | 1,306,932 | same length, **6 differing bytes** in a clean run (7 in an earlier run) |
| `secp256k1_differential.exe` | 1,397,151 | same length, **2 differing bytes** |

The archive differences sit in container member metadata and are not stable
between runs — the count changed from 7 to 6 — which is itself evidence that they
are timestamp-like rather than code. The executable differences are exactly two
bytes: the PE `TimeDateStamp` (at `e_lfanew + 8` = `0x88` = 136, values
`1792408372` vs `1792408382`) and the PE32+ `CheckSum` (at `0x98 + 64` = 216).
Every code and data section is identical.

**Claim made:** all three source translation units compile to byte-identical
objects across independent clean builds, and the linked image differs only in
link-time metadata. **Claim not made:** byte-identical binaries. The archive and
the executable are not byte-identical, and archive-container timestamps are not
reproducible here without a further change that P2.6 did not authorise.

Only Windows/MinGW was exercised. No Linux, macOS, MSVC or Android build was
run, so no cross-platform reproducibility is claimed (U4 unchanged).

### 16.4 The test-only differential harness `[VERIFIED]`

```text
kernel/differential/backend/secp256k1_verifier.{h,cpp}   zk::SigVerifier over libsecp256k1
kernel/differential/runner/main.cpp                      fixture reader and reporter
kernel/differential/vectors/ledger.sighash.differential.txt   generated fixture
kernel/tools/secp256k1_differential.py                   grading wrapper
zerocoin/tests/differential_vectors.rs                   fixture emitter + live oracle
```

The adapter implements `zk::SigVerifier::verify` and *includes* the kernel header,
so the compiler checks the override — but the target links only
`secp256k1_vendored`. No kernel object, transaction parser or sighash
implementation is pulled in, and nothing here is reachable from `TxSigChecker`
or from a node binary.

The runner prints two verdicts per case, which is the point of the design:

- **`seam`** — the contract gate plus the maths: 33-byte public key with tag
  `0x02`/`0x03`, strict DER, then `secp256k1_ecdsa_verify`;
- **`backend`** — raw `secp256k1_ec_pubkey_parse` + `secp256k1_ecdsa_verify`,
  with no contract gate.

`adapter=faithful` means both agree, i.e. the library alone produced the verdict.
`adapter=load-bearing` means the contract gate changed the answer, so the case is
**not** evidence of library parity and is never reported as such.

Fail-closed: every parse failure, verify failure, short buffer, null pointer and
unexpected library return produces `reject`. There is no path that converts an
error into acceptance, and no key or signature material is logged.

**The Rust verdicts are derived, never hand-written.** The fixture is emitted by
`zerocoin/tests/differential_vectors.rs`; on every `cargo test` run the committed
file is re-parsed and every `RUST` line is re-derived from the live Rust
implementation by `differential_vectors_match_rust_reference`. A hand-edited
expectation therefore fails the Rust suite before it can reach the C++ runner.

**The comparison cannot go dead silently.** `secp256k1_differential.py` enforces
a pinned case count (117), requires every mismatch to be a listed
`--known-divergence`, requires every listed divergence to *still* mismatch (a
stale pin fails), checks the runner exit code against the failure count, and runs
a liveness probe that corrupts one recorded verdict and demands exactly one new
mismatch on top of the known set. A wrapper that stopped comparing would fail
rather than pass.

### 16.5 Measured matrix `[VERIFIED]`

```text
secp256k1 differential: 116/117 cases match the Rust reference (7 accept, 110 reject)
  groups                V1=2, V2=3, V3=18, V4=11, V5=5, V6=2, V7=76
  adapter load-bearing  V4.uncompressed_65 (rust=reject backend=accept)
  adapter load-bearing  V4.hybrid_prefix_06 (rust=reject backend=accept)
  documented divergence 1:
    V4.prefix_05: rust=accept seam=reject backend=reject
```

| Group | Cases | Rust accept | Match | What it covers |
|---|---|---|---|---|
| `V1` | 2 | 2 | 2 | valid low-S signatures: the P2 corpus triple, and the P2.3 scalar-7 fixture |
| `V2` | 3 | 0 | 3 | high-S twins of the V1 rows and of the S5 probe digest — all rejected |
| `V3` | 18 | 0 | 18 | DER structure and scalar range: empty, sequence-only, truncated, trailing byte, trailing byte inside the sequence, non-minimal long-form length, redundant leading zeros, negative integers, wrong integer tag, indefinite length, `r = 0`, `s = 0`, zero-length integer, `r = n`, `s = n`, extra integer |
| `V4` | 11 | 1 | 10 | public-key encodings: 65-byte uncompressed, hybrid `0x06`/`0x07`, lengths 32/34, prefixes `0x00`/`0x05`, all-zero, empty, `x = p`, `x` with no curve point |
| `V5` | 5 | 3 | 5 | digest handling: wrong digest, all-zero digest, `z = n` reducing to 0, `z = n + 1` reducing to 1, all-ones digest reducing |
| `V6` | 2 | 1 | 2 | P2 script level: the corpus triple replayed through the seam, and the 72-byte scriptSig push (DER + `SIGHASH_ALL`) fed as DER |
| `V7` | 76 | 0 | 76 | corruption corpus: 71 single-site DER corruptions, 4 public-key corruptions, 1 digest corruption |

Every accept row, with its identity:

| Case | Note |
|---|---|
| `V1.p2_corpus_low_s` | `ledger.sighash.signature_der` / `ledger.script.p2pkh_spend_accepted` triple: scalar 1 over the regtest P2PKH sighash |
| `V1.p23_scalar7_low_s` | `tests/high_s_signature.rs` fixture: seed `[7u8; 32]`, RFC 6979, low-S |
| `V4.prefix_05` | **the divergence** — §16.6 |
| `V5.digest_equals_n_reduces_to_zero` | `z = n` reduces to 0; the signature was made over `z = 0` |
| `V5.digest_equals_n_plus_one_reduces_to_one` | `z = n + 1` reduces to 1 |
| `V5.digest_all_ones_reduces` | `z = 2^256 - 1` reduces below the group order |
| `V6.p2pkh_spend_accepted` | the corpus triple replayed through the seam; byte-identical to `V1.p2_corpus_low_s` |

The V5 rows matter beyond arithmetic: both implementations reduce a 256-bit
digest modulo `n` rather than rejecting it (`ecdsa-0.16.9/src/hazmat.rs:279`
`Scalar::reduce_bytes`; libsecp `secp256k1_scalar_set_b32` over the overflow
flag), and the measurement confirms the two reductions agree on all three
non-canonical digests. That covers four of §9 V11's five digest shapes; a digest
with a leading `0x00` byte is **not** in the fixture, so nothing is claimed about
it.

The complete 117-row matrix — fixture identifier, Rust verdict, seam verdict,
backend verdict, match flag, adapter class — is in **§16.12**. It is generated
mechanically from the runner's own output, and can be regenerated with the
command in §16.9.

### 16.6 `V4.prefix_05` — a consensus-relevant divergence `[VERIFIED]`

This is the finding that decides the milestone. It is not a rounding error, not a
missing fixture, and not something the adapter may normalise away.

**Observation.** A 33-byte public key whose tag byte is `0x05` is **accepted by
the Rust reference** and **rejected by libsecp256k1** for the same digest and
signature:

```text
CASE V4.prefix_05 group=V4 rust=accept seam=reject backend=reject match=no adapter=faithful
```

**Mechanism in the Rust reference.**

1. `zerocoin/src/crypto/secp256k1.rs:112-119` — `PublicKey::from_sec1` gates on
   **length only** (`bytes.len() != COMPRESSED_PUBKEY_LEN`), then calls
   `VerifyingKey::from_sec1_bytes`.
2. `sec1-0.7.3/src/point.rs:485-486,491-500` — `Tag::Compact = 5`, and
   `Tag::from_u8(5) => Ok(Tag::Compact)`.
3. `sec1-0.7.3/src/point.rs:520-527` — `Tag::Compact.message_len()` is one field
   element, so `0x05 || X` is exactly 33 bytes and passes the length check.
4. `k256-0.13.4/src/arithmetic/affine.rs:247-253` — `from_encoded_point` maps
   `Coordinates::Compact { x } => Self::decompact(x)`.
5. `k256-0.13.4/src/arithmetic/affine.rs:204-211` — `decompact` is
   `Self::decompress(x_bytes, Choice::from(0))`, i.e. **the same `x` with `y`
   forced even**. `0x05 || X` is therefore a silent alias for `0x02 || X`.

**Mechanism in libsecp256k1.**
`kernel/third_party/secp256k1/src/eckey_impl.h:18-36` admits 33 bytes with tag
`SECP256K1_TAG_PUBKEY_EVEN` or `..._ODD` only; 65 bytes with
`UNCOMPRESSED`/`HYBRID_EVEN`/`HYBRID_ODD` plus a parity check on the hybrid
tags; **everything else returns 0**. Tag `0x05` at 33 bytes falls into the final
`else`.

**Why it is consensus-relevant, not a library detail.** The production path is:

```text
OP_CHECKSIG (zerocoin/src/ledger/script.rs:162)
  -> TxSigChecker::check_signature (zerocoin/src/ledger/sighash.rs:113-126)
  -> PublicKey::from_sec1 (zerocoin/src/crypto/secp256k1.rs:112-119)
  -> VerifyingKey::from_sec1_bytes -> sec1 Tag::Compact -> k256 decompact
```

A spender can commit `hash160(0x05 || X)` into a P2PKH `scriptPubKey` and produce
a valid signature under key `X`. The current Rust node accepts that spend; a
libsecp256k1-backed node rejects the public key outright. Two nodes therefore
disagree on whether a transaction is valid — the definition of a consensus
split. This is a **live property of the Rust reference today**, independent of
whether any C++ backend is ever adopted.

**The fixture's own note disagrees with the fixture's verdict.** The generated
`NOTE` for this case reads "prefix 0x05 is not a SEC1 tag", because that is what
the contract intends; the `RUST` line says `accept`, because that is what the
implementation does. Deriving expectations from the implementation rather than
from intent is what exposed this.

**Remediation options, both outside P2.6's authority.**

1. **Tighten the Rust gate** to `0x02 | 0x03` on a 33-byte key. That is a change
   to production cryptography with consensus effect and needs its own phase, its
   own fixtures and its own audit. It is the option that makes the reference
   match its stated contract.
2. **Authorise the C++ adapter to emulate the quirk** — decompact `0x05` with an
   even `y`. This deliberately reproduces a bug and must be a written decision,
   not an implementation detail discovered later.

Neither was done here. The divergence is pinned in `CMakeLists.txt` as
`--known-divergence V4.prefix_05` precisely so that it cannot be forgotten: the
gate fails if any *other* case diverges, and it also fails once this one starts
matching, forcing the allowance to be removed.

### 16.7 Verification parity and deterministic signing `[VERIFIED / UNVERIFIED]`

Kept separate, exactly as §9 requires.

**Verification (V).** Measured, with the single exception above: 116/117 rows
agree, and the incompatible row is recorded rather than papered over. The
verifier is not authorised for production use.

**Deterministic signing (S).** `[UNVERIFIED]` — no signing comparison was
performed in P2.6.

What `ledger.sighash.signature_der` requires is exact DER bytes from
`(d, z)`. The two signing entry points are:

| Side | Entry point | Nonce derivation |
|---|---|---|
| Rust | `PrivateKey::sign` → `SigningKey::sign_prehash` | RFC 6979 HMAC-SHA256 over the 32-byte digest, then low-S normalisation |
| C++ | `secp256k1_ecdsa_sign` | RFC 6979 HMAC-SHA256 seeded with `key32` and `msg32`, then low-S normalisation |

Both implement RFC 6979 with HMAC-SHA256 and both normalise to low-S, so byte
parity is **structurally plausible**. It remains **unmeasured**, and plausible is
not the same as proven: extra-entropy handling, DER minimal-integer emission and
the exact treatment of `h1` are all places where two RFC 6979 implementations can
diverge without either being wrong. No signing code was added to production, and
closing S requires a separate authorisation to build a signer harness and compare
exact DER bytes on deterministic vectors.

A matching verifier does not imply a matching signer: verification accepts a set
of signatures, signing emits one element of that set. §9 states this and P2.6
provides no counter-evidence.

### 16.8 S5 status `[UNCHANGED]`

S5 is **partial — two of six probes pinned, four blocked**. P2.6 changes nothing
here:

| S5 probe | Expected | State after P2.6 |
|---|---|---|
| High-S twin | reject | **Pinned** |
| Low-S original | accept | **Pinned** |
| `s = 1` | accept | **Blocked** |
| `s = n - 1` | reject | **Blocked** |
| `s = floor(n/2)` | accept | **Blocked** |
| `s = floor(n/2) + 1` | reject | **Blocked** |

The four blocked probes still need a mathematically valid signature carrying the
target scalar. P2.6 did **not** add a test-only signing oracle, and does not
count the high-S twins in `V2`, the predicate pins, or any invalid signature as
boundary evidence. `V2.s5_probe_digest_5a_high_s_twin` is a twin, not a probe.

### 16.9 Regression gates `[VERIFIED, fresh]`

One command, every step executed from a fresh build directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gate-p2-6.ps1
```

| Gate | Observed | Exit |
|---|---|---|
| Kernel configure + build | 23/23 targets from scratch, warnings as errors | 0 |
| C++ kernel unit tests | `kernel unit tests: 108 run, 0 failed` | 0 |
| G1 conformance | `28/28 cases replayed against source_commit 7cb9017c…` | 0 |
| P2 conformance | `21/21 cases`; `corruption self-check rejected 21/21 cases`; 2 deferred (G2c) | 0 |
| P0 baseline | `PASS 112  ANCHOR 5  SKIP 0  FAIL 0` | 0 |
| Rust suite (`--all-targets`) | `271 passed, 0 failed across 10 targets`; 1 ignored (the fixture emitter) | 0 |
| `high_s_signature` | `4 passed, 0 failed` | 0 |
| `s5_boundary_probes` | `3 passed, 0 failed` | 0 |
| Differential build A + B | 7 artefacts each, both from empty directories | 0 |
| Reproducibility comparison | `3/3 objects identical; archive=differs; exe=differs` | 0 |
| Differential `ctest` | `1/1 kernel_secp256k1_differential ... Passed 0.30 sec` | 0 |
| Differential verdicts | `116/117 match, 1 pinned (V4.prefix_05)` | 0 |

Final lines of the run:

```text
P2.6 gates: PASS (every step executed; 1 documented divergence pinned)
G2c: NO-GO — V4.prefix_05 is consensus-relevant; see docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md
```

No cached build was reported as evidence. The Rust total rose from 270 to 271
because of the new oracle test; no existing test changed and none was weakened.
The two deferred corpus cases are still reported as deferred, not as passed.

To regenerate the per-case matrix in §16.12:

```powershell
.build\p26-differential-repro-a\secp256k1_differential.exe `
  kernel\differential\vectors\ledger.sighash.differential.txt
```

### 16.10 G2c verdict

**G2c: NO-GO.**

The P2.5 verdict was NO-GO because no backend existed. That reason is gone: one
is now acquired, PGP-verified, hash-pinned, vendored, built reproducibly and
measured against 117 Rust-derived cases. The verdict is unchanged because the
measurement produced a **consensus-relevant disagreement** (§16.6), which is a
stop condition under the milestone's own rules.

Read against §14's GO conditions:

| §14 condition | P2.6 state |
|---|---|
| written authorisation naming one acquisition path | satisfied for the experiment; not for production integration |
| pinned tag with archive SHA-256 and verified GPG signature | **satisfied** (§16.1) |
| wrapper gating SEC1 to 33 bytes / `0x02` / `0x03`, strict DER, no `s` normalisation | **satisfied** — and it is exactly what surfaced the divergence |
| §9 V matrix green against Rust-generated fixtures | **not satisfied** — 116/117; `V4.prefix_05` is not green |
| S5 closed or explicitly waived | not satisfied, not waived |
| separate decision for `signature_der` | not taken |

That third row is the important lesson. §14 assumed the C++ wrapper was the
risk and the Rust reference was canonical. The measurement shows the opposite for
this one case: the wrapper was strict, the reference was lax. A gate on the
wrapper cannot fix a divergence that originates in the reference's own parser.

**What would move G2c to GO**, in order: (1) a decision on `V4.prefix_05` — fix
the Rust gate, or authorise bug-for-bug emulation; (2) a re-run of the 117-case
matrix with the divergence either gone or explicitly authorised; (3) an explicit
S5 disposition; (4) a separate decision on `signature_der`.

A passing isolated verifier does **not** authorise production integration, and
even a fully green matrix would not by itself: the backend remains isolated, the
kernel still links nothing, and the two deferred corpus cases stay deferred.

### 16.11 Files changed and non-claims

Added in P2.6:

- `kernel/third_party/secp256k1/**` — 60 vendored files + `ORIGIN.md` + `SHA256SUMS`;
- `kernel/differential/**` — standalone CMake project, adapter, runner, fixture;
- `kernel/tools/secp256k1_differential.py` — grading wrapper;
- `zerocoin/tests/differential_vectors.rs` — fixture emitter and live oracle;
- `scripts/gate-p2-6.ps1` — the milestone gate;
- this section, and the §11 addendum in `CRYPTO_BACKEND_READINESS.md`.

Not changed: any file under `zerocoin/src/`, `kernel/include/`, `kernel/src/`,
`kernel/tests/`, `test/`; `kernel/CMakeLists.txt`; `Cargo.toml`; `Cargo.lock`;
any existing fixture or vector; any `.publish` state; Git identity or remote
configuration.

Explicitly **not** claimed:

- that C++ verification is compatible with Rust — one row demonstrably is not;
- that the backend may be linked into the kernel or a node binary;
- RFC 6979 or DER byte parity for signing;
- cross-platform build reproducibility — Windows/MinGW only;
- byte-identical binaries — the archive and executable differ in metadata;
- any S5 progress beyond the two previously pinned probes;
- G2c, gate G2, or the P2 exit criteria as closed;
- any start of P2.7, P3, service layer, RPC or Go networking.

### 16.12 Per-case matrix (all 117 executed rows)

Generated from the runner's own output; not hand-transcribed. `seam` is the
contract gate plus the maths, `backend` is raw libsecp256k1. Every row is a case
that was executed; nothing is inferred or extrapolated.

| Fixture | Rust | Seam | Backend | Match | Adapter |
|---|---|---|---|---|---|
| `V1.p2_corpus_low_s` | accept | accept | accept | yes | faithful |
| `V1.p23_scalar7_low_s` | accept | accept | accept | yes | faithful |
| `V2.p2_corpus_high_s_twin` | reject | reject | reject | yes | faithful |
| `V2.p23_scalar7_high_s_twin` | reject | reject | reject | yes | faithful |
| `V2.s5_probe_digest_5a_high_s_twin` | reject | reject | reject | yes | faithful |
| `V3.der_empty` | reject | reject | reject | yes | faithful |
| `V3.der_sequence_only` | reject | reject | reject | yes | faithful |
| `V3.der_truncated` | reject | reject | reject | yes | faithful |
| `V3.der_trailing_byte` | reject | reject | reject | yes | faithful |
| `V3.der_trailing_inside_sequence` | reject | reject | reject | yes | faithful |
| `V3.der_long_form_length` | reject | reject | reject | yes | faithful |
| `V3.der_r_redundant_zero` | reject | reject | reject | yes | faithful |
| `V3.der_s_redundant_zero` | reject | reject | reject | yes | faithful |
| `V3.der_r_negative` | reject | reject | reject | yes | faithful |
| `V3.der_s_negative` | reject | reject | reject | yes | faithful |
| `V3.der_wrong_integer_tag` | reject | reject | reject | yes | faithful |
| `V3.der_indefinite_length` | reject | reject | reject | yes | faithful |
| `V3.der_r_zero` | reject | reject | reject | yes | faithful |
| `V3.der_s_zero` | reject | reject | reject | yes | faithful |
| `V3.der_s_zero_length` | reject | reject | reject | yes | faithful |
| `V3.der_r_equals_n` | reject | reject | reject | yes | faithful |
| `V3.der_s_equals_n` | reject | reject | reject | yes | faithful |
| `V3.der_extra_integer` | reject | reject | reject | yes | faithful |
| `V4.uncompressed_65` | reject | reject | accept | yes | **load-bearing** |
| `V4.hybrid_prefix_06` | reject | reject | accept | yes | **load-bearing** |
| `V4.hybrid_prefix_07` | reject | reject | reject | yes | faithful |
| `V4.length_32` | reject | reject | reject | yes | faithful |
| `V4.length_34` | reject | reject | reject | yes | faithful |
| `V4.prefix_00` | reject | reject | reject | yes | faithful |
| `V4.prefix_05` | accept | reject | reject | **no** | faithful |
| `V4.all_zero_33` | reject | reject | reject | yes | faithful |
| `V4.empty` | reject | reject | reject | yes | faithful |
| `V4.x_equals_field_prime` | reject | reject | reject | yes | faithful |
| `V4.x_without_curve_point` | reject | reject | reject | yes | faithful |
| `V5.wrong_digest` | reject | reject | reject | yes | faithful |
| `V5.zero_digest` | reject | reject | reject | yes | faithful |
| `V5.digest_equals_n_reduces_to_zero` | accept | accept | accept | yes | faithful |
| `V5.digest_equals_n_plus_one_reduces_to_one` | accept | accept | accept | yes | faithful |
| `V5.digest_all_ones_reduces` | accept | accept | accept | yes | faithful |
| `V6.p2pkh_spend_accepted` | accept | accept | accept | yes | faithful |
| `V6.script_sig_push_including_sighash_byte` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_00` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_01` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_02` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_03` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_04` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_05` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_06` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_07` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_08` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_09` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_10` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_11` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_12` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_13` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_14` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_15` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_16` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_17` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_18` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_19` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_20` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_21` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_22` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_23` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_24` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_25` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_26` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_27` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_28` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_29` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_30` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_31` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_32` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_33` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_34` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_35` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_36` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_37` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_38` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_39` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_40` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_41` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_42` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_43` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_44` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_45` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_46` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_47` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_48` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_49` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_50` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_51` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_52` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_53` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_54` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_55` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_56` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_57` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_58` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_59` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_60` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_61` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_62` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_63` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_64` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_65` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_66` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_67` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_68` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_69` | reject | reject | reject | yes | faithful |
| `V7.corrupt_der_70` | reject | reject | reject | yes | faithful |
| `V7.corrupt_pubkey_prefix` | reject | reject | reject | yes | faithful |
| `V7.corrupt_pubkey_x_first_byte` | reject | reject | reject | yes | faithful |
| `V7.corrupt_pubkey_x_last_byte` | reject | reject | reject | yes | faithful |
| `V7.corrupt_pubkey_truncated` | reject | reject | reject | yes | faithful |
| `V7.corrupt_digest_last_byte` | reject | reject | reject | yes | faithful |

Totals: 117 rows, 7 Rust accepts (V1×2, V4×1, V5×3, V6×1), 110 Rust rejects,
116 matches, 1 divergence (`V4.prefix_05`), 2 load-bearing adapter rows
(`V4.uncompressed_65`, `V4.hybrid_prefix_06`).

Input normalisation: **none**. The adapter does not re-encode, right-pad, strip or
reorder any input. DER is passed to `secp256k1_ecdsa_signature_parse_der`
unmodified, the digest is passed as 32 raw bytes in the order the Rust reference
hashes them, and a public key is accepted only at exactly 33 bytes with tag
`0x02`/`0x03`. The two load-bearing rows are the cases where that last gate
differs from raw `secp256k1_ec_pubkey_parse`, which also admits 65-byte keys and
is why `backend=accept` there while the seam rejects.

---

## 17. P2.7 addendum — the `0x05` divergence traced end to end `[VERIFIED]`

P2.6 measured the divergence and stopped at the gate, because a decision between
two remediation options was missing. P2.7 answers the questions that decision
needs: what exactly the parser accepts, whether that acceptance can reach the
consensus decision, what the written contract actually says, and what each
remediation would cost.

**No production behaviour was changed. `V4.prefix_05` still diverges.**

### 17.1 Starting state `[VERIFIED]`

| Item | Observed |
|---|---|
| Repository root | `D:/Downloads/zerocoin/.publish/upstream` |
| Branch | `main`, tracking `origin/main` |
| HEAD | `96678c62969e966316f0927e08cd104428bc6053` ("test(crypto): vendor libsecp256k1 v0.8.0 and measure the differential result") |
| `origin/main` | same commit |
| Working tree | clean apart from one new untracked test file added by this milestone |
| P2.6 commit present | yes — it is HEAD |

No unexplained modifications were found, so the audit proceeded. The working
tree state was clean at the point the tests were written, not merely "clean
after a stash".

### 17.2 The parser gate is length-only; the contract says it is not

The whole of the tag decision lives in six lines:

```rust
pub fn from_sec1(bytes: &[u8]) -> Result<Self, CryptoError> {
    if bytes.len() != COMPRESSED_PUBKEY_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    // Validate that the bytes are a real point on the curve.
    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
    out.copy_from_slice(bytes);
    Ok(PublicKey { bytes: out })
}
```

`zerocoin/src/crypto/secp256k1.rs:112-121`. The comment claims curve
membership; the check is curve membership **plus whatever `sec1` decides a tag
byte means**. The type's own doc comment one line above the struct
(`secp256k1.rs:105`) says "A compressed SEC1 public key", so `0x05` violates the
type's stated invariant while satisfying its code.

This matters for reading the contract. `INTERFACE_CONTRACTS.md` B1 reads:

> Accept **only 33-byte compressed SEC1** public keys; reject 65-byte
> uncompressed, hybrid prefixes, wrong lengths, off-curve `x`, and the point at
> infinity — source of the rule: `src/crypto/secp256k1.rs` 112–121

The cited range implements the *length* half of B1 and none of the tag half.
B1 cites code that does not do what B1 says. That is a documentation defect
independent of the consensus question, and it is why "but B1 says only
compressed" cannot settle the matter on its own.

### 17.3 Complete validation path `[VERIFIED]`

Both entry points converge on the same interpreter:

```text
block acceptance   Chain::connect_block            chain.rs:274
                   -> UtxoSet::apply_transaction    utxo.rs:191
                   -> script::verify                utxo.rs:231 -> script.rs:69
mempool admission  Chain::validate_transaction     chain.rs:406
                   -> (same UtxoSet path)

script::verify
  -> run_script(script_sig); run_script(script_pubkey)
  -> OP_CHECKSIG                                   script.rs:157-162
  -> SigChecker::check_signature                   script.rs:40
  -> TxSigChecker::check_signature                 sighash.rs:114-138
  -> PublicKey::from_sec1(public_key)              sighash.rs:126
  -> PublicKey::verify                             secp256k1.rs:137-143
  -> PublicKey::verifying_key                      secp256k1.rs:145-147
  -> VerifyingKey::verify_prehash
```

The public key that reaches `from_sec1` is the **`scriptSig` push**, not the
`scriptPubKey`. That ordering is the whole reason the impact is bounded:
`P2PKH` is `DUP HASH160 <20> EQUALVERIFY CHECKSIG`, so `OP_EQUALVERIFY`
hashes the pushed bytes and compares them to the committed hash *before*
`OP_CHECKSIG` ever parses them.

The five stages the milestone asks to be kept distinct:

| Stage | Where | What a `0x05` key does |
|---|---|---|
| Input parsing | `from_sec1`, `secp256k1.rs:112` | **accepted** — 33 bytes, `Tag::Compact` |
| Point interpretation | `sec1` -> `k256` `decompact` | same point as `0x02 \|\| x` (y forced even) |
| Signature equation | `verify_prehash` | **succeeds** for the real key holder |
| Script execution | `OP_EQUALVERIFY` then `OP_CHECKSIG` | fails on a canonical-locked coin, succeeds on a compact-locked one |
| Transaction / block | `validate_transaction`, `connect_block` | accepts a spend of a compact-locked coin |

### 17.4 Observed results, every relevant encoding `[VERIFIED]`

Measured by `zerocoin/tests/p2_7_pubkey_encoding.rs` (7 tests). Byte inputs are
literal; nothing is re-encoded before the call.

| Input | Length | Parser | Point | Signature |
|---|---|---|---|---|
| `02 \|\| x` (fixture canonical) | 33 | accept | even-y point | verifies |
| `03 \|\| x` (odd-y key, seed scan 1..64) | 33 | accept | odd-y point, round-trips exactly | verifies |
| `05 \|\| x` (disputed) | 33 | **accept** | even-y point, identical to `02 \|\| x` | **verifies the same signature** |
| `00`, `04`, `06`, `07`, `01`, `ff` `\|\| x` | 33 | reject | — | — |
| `04 \|\| X \|\| Y` (valid point) | 65 | reject | — | — |
| `06`/`07 \|\| X \|\| Y` (hybrid) | 65 | reject | — | — |
| any tag, truncated/padded | 0, 32, 34 | reject | — | — |
| all zero | 33 | reject | — | — |
| `02 \|\| p` (`x` not a field element) | 33 | reject | — | — |
| `04 \|\| ...` (the `V4.uncompressed_65` row) | 65 | reject | — | — |

Two controls matter as much as the accept rows:

* the same signature under `05 \|\| x` and `02 \|\| x` both verify, but a
different digest under `05 \|\| x` returns `VerificationFailed` — the equation
is still an equation, `0x05` is not a bypass;
* `0x05` is rejected by the C++ seam and by raw libsecp256k1 on the same bytes
(`CASE V4.prefix_05 group=V4 rust=accept seam=reject backend=reject match=no
adapter=faithful`).

The disputed fixture row, verbatim:

```text
PUBKEY 05989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f
DIGEST e6d8533d96866eecea284731dac93bce9978750097c45629228e709fc80b7650
```

The canonical spelling of the same point appears elsewhere in the fixture as
`02989c0b...e05f6f`, which is what makes `0x05` a byte-exact alias rather than a
distinct key.

**A note on the fixture's own NOTE.** It reads "prefix 0x05 is not a SEC1 tag".
That is the project's intent. It is not a fact about SEC1: `0x05` *is*
`Tag::Compact` in `sec1-0.7.3`, which is precisely why `k256` accepts it. The
fixture is right about what the contract should say and wrong about what the
encoding standard says.

### 17.5 End-to-end acceptance, and how such a coin arises `[VERIFIED]`

**Acceptance was reproduced, at both levels.**

`divergence_pin_end_to_end_p2pkh_spend_from_a_compact_locked_coin_is_accepted`
mines 100 blocks paying `hash160(0x05 \|\| x)`, takes the matured coinbase, and:

1. builds a spend whose `scriptSig` pushes `05 \|\| x` and a signature over the
   `P2PKH` script code — `Chain::validate_transaction` returns the fee (admitted);
2. mines it — `Chain::mine_block` accepts the block and the recipient is credited;
3. as a negative control, the same spend with the **canonical** `02 \|\| x`
   push is rejected with `ChainError::Utxo(UtxoError::ScriptInvalid { .. })`
   (`EvalFalse` at `OP_CHECKSIG`, not `EqualVerifyFailed`) — proving the hash
   comparison passed and only the key spelling differed.

A second pin shows the two spellings are not interchangeable in either
direction: `divergence_pin_key_hash_commits_to_the_encoding_not_the_point` gets
`EqualVerifyFailed` when a `0x02` `scriptSig` meets a `0x05`-locked output, and
symmetrically. So this is **not** a way to spend somebody else's coin.

**Reachability without hand-built state.** `Message::Share` carries
`SharePayload { header, payout: PublicKey }`; `PublicKey`'s `Deserialize`
(`secp256k1.rs:219-225`) hex-decodes and calls the same `from_sec1`. The node
then records `payload.payout.key_hash()` into the `PoolLedger`, and
`pool_coinbase_transaction` pays `p2pkh_script_pubkey(pubkey_hash)`. A peer that
submits a `0x05` payout therefore causes a compact-locked output to exist
on-chain without anyone editing local state. `divergence_pin_wire_share_payout_accepts_the_compact_tag`
round-trips that message and asserts the decoded payout is byte-identical to the
compact spelling.

**What this does and does not establish.** It establishes a real validity
disagreement: the same block is valid to the Rust reference and invalid to a
libsecp256k1 backend, which is the definition of a consensus split. It does
**not** establish theft or forgery: the spender must hold the secret for `x`,
the coin must already be locked to `hash160(0x05 \|\| x)`, and the stock wallet
cannot produce such a `scriptSig` because it derives the canonical spelling from
the secret (`wallet.rs:352-353`). The honest description is *non-canonical
encodings are accepted for coins already locked with them*, plus a
history-dependent validity question for any node that did not see the funding
transaction.

### 17.6 The intended encoding contract `[VERIFIED]`

The written sources do not agree with each other:

| Source | What it says about the tag set |
|---|---|
| `CONSENSUS_RULES.md` §8.4 | **silent.** Specifies `script::verify`, the four limits, the ten opcodes and the `P2PKH` templates; no statement about public-key encoding |
| `CPP_PORT_REQUIREMENTS.md` C-38..C-47 | **silent.** Covers opcodes, limits, sighash, apply order, maturity, state root, no floats |
| `INTERFACE_CONTRACTS.md` B1 | "Accept **only 33-byte compressed SEC1**" |
| `INTERFACE_CONTRACTS.md` §3.3 ¶3 | "a backend that rejects an unusual-but-valid encoding is not equivalent and is a defect" |
| `CRYPTO_BACKEND_READINESS.md` S3 | `0x02`/`0x03` accept; "prefix `0x00`/`0x04`/`0x05` (reject)" |
| implementation | accepts `0x02`, `0x03` and `0x05`; rejects everything else |

Answering the milestone's questions directly:

* **Which encodings does the documented protocol permit?** The only written
  rule is "33-byte compressed", enumerated as `0x02`/`0x03` in the test plan.
  `0x05` is not authorised anywhere.
* **Does the specification explicitly prohibit it?** `CONSENSUS_RULES` and the
  port requirements do not mention it at all. S3 prohibits it, but S3 is a
  **test plan**, not a consensus rule. B1 prohibits it by wording while citing
  code that does not implement the prohibition.
* **Documented rule, accidental library behaviour, or unresolved ambiguity?**
  **An unresolved specification ambiguity sitting on top of an implementation
  defect.** No documented rule authorises acceptance. Acceptance arises from
  `sec1`'s `Tag::Compact` support reached through a length-only gate, which
  exceeds the type's own documented invariant.
* **Does the implementation differ from the documented contract?** Yes — from
  B1 and S3 it differs by accepting; from §3.3 ¶3 the *rejection* is a defect.
  Both clauses cannot hold at once for `0x05`. That contradiction, not the
  library behaviour, is the finding.
* **Would tightening change the accepted set?** Yes, in exactly one narrow
  class: spends whose `scriptSig` pushes a `0x05` key against an output
  committing to `hash160(0x05 \|\| x)`. Output *creation* never parses a key,
  so no funding transaction and no coinbase changes status.

### 17.7 Remediation options A / B / C `[ANALYSIS]`

#### A — tighten the Rust parser to the protocol-approved encodings

Reject anything at 33 bytes whose tag is not `0x02`/`0x03`.

| Dimension | Assessment |
|---|---|
| Consensus compatibility | Removes the split by making the reference match libsecp256k1 and B1/S3. It is nonetheless a **consensus change**: a node running old code accepts a spend a new node rejects |
| Historical validity | Nothing is retroactively invalidated. No public chain exists (`README.md:297` "**Mainnet is not launched.**"), the genesis nonce is unpinned, P3 has not started, and the kernel links nothing. Within devnet/regtest, a block containing such a spend would become invalid to upgraded nodes |
| Security of accepting non-canonical encodings | The accepted set shrinks. Today one curve point has at least two on-chain identities (`hash160(0x02\|\|x)` and `hash160(0x05\|\|x)`); tightening removes that aliasing class. No forgery is removed, because none existed |
| Wallets, scripts, construction | Zero impact on the stock wallet, which derives canonical spellings from the secret. Only hand-built or third-party scripts that deliberately used `0x05` are affected — and none exist in the repository |
| Activation mechanism | Required if any chain exists at the time of the change: an activation height or protocol-version gate, or a coordinated restart of devnet. The cheapest correct moment is **before the mainnet genesis nonce is pinned**, when the mechanism can simply be "it was never activated" |
| Test and rollback | Flip the `V4.prefix_05` expectation to `reject` in the fixture, drop the `--known-divergence` allowance, add reject rows for `0x05` at 33 bytes. Rollback is `git revert` of a small, isolated diff |

#### B — make the C++ adapter emulate the Rust behaviour

Add a non-SEC1-tag branch that decompacts `0x05` with even `y`.

| Dimension | Assessment |
|---|---|
| Consensus compatibility | Makes both sides agree by preserving the reference's current behaviour. It also permanently contradicts B1/S3 and diverges from upstream libsecp256k1 semantics |
| Historical validity | Unchanged — this option changes only the port |
| Security of accepting non-canonical encodings | Institutionalises the aliasing class and creates a second independent implementation of a suspected parser bug, which must then be maintained and audited forever |
| Wallets, scripts, construction | None |
| Activation mechanism | None needed for the port, which is exactly the problem: it freezes a defect into the new implementation with no protocol decision behind it |
| Test and rollback | The 117-row matrix goes green with **no fixture change** — which is the failure mode the milestone brief explicitly forbids. Rollback means removing adapter code that a green gate now depends on |

#### C — preserve current behaviour, document, and defer

| Dimension | Assessment |
|---|---|
| Consensus compatibility | Status quo exactly. The split stays latent; it cannot manifest on a live chain because there is no live chain |
| Historical validity | Unchanged |
| Security of accepting non-canonical encodings | Unchanged — the acceptance surface remains |
| Wallets, scripts, construction | None |
| Activation mechanism | None now. An explicit decision is required **before** mainnet genesis is pinned and before any C++ backend is linked |
| Test and rollback | Keep the divergence pinned with the allowance. This is the current state and it is why the guard is bidirectional |

Option B must not be chosen merely to make the matrix green. Reproducing a
suspected parser bug in a second implementation is a protocol decision, and no
evidence supports making it: the defect is in the reference, the port is the
side that matches the written contract, and B1's cited source does not
implement B1.

### 17.8 Recommendation `[DECISION]`

**Recommend option A**, executed under a separate, explicitly authorised change,
and **not in this milestone**. Until that authorisation exists, option C is what
this repository is doing, and it is the correct interim state: the divergence is
measured, pinned, guarded in both directions, and cannot be forgotten.

A is preferred on the evidence for four reasons: it makes the reference match
the only written contract (B1, S3); it makes the two implementations agree by
removing behaviour rather than adding it; it touches one narrowly-scoped
predicate with a small, revertible diff and no wallet impact; and the moment to
do it is before genesis is pinned, when no compatibility mechanism has to be
built at all.

The evidence is sufficient to *recommend* A. It is not sufficient to *execute*
A in this milestone, and this document does not claim it is. Three preconditions
belong to that separate change:

1. an explicit recorded decision, since it changes the accepted set;
2. a determination of whether any chain that its operators care about already
   contains a compact-locked output — if none, no activation mechanism is needed;
3. fixture and guard updates in the same commit, so the gate goes from "1 pinned
   divergence" to "0 divergences" deliberately rather than silently.

### 17.9 Backend provenance re-audit `[PARTIALLY VERIFIED]`

Recorded in `kernel/third_party/secp256k1/ORIGIN.md`, re-read and independently
re-checked in this milestone:

| Field | Recorded | Re-checked |
|---|---|---|
| Tag object | `18f07c42218765cd46148d74d9fe575795f56dce` | matches |
| Commit | `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d` | matches |
| Archive size | 2,436,784 bytes | matches |
| Archive SHA-256 | `dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b` | matches the skipped line in `SHA256SUMS` |
| Signature SHA-256 | `c7eb14bbd67fe94b9ac4b556df6ae18aebb450092c836d05a6e13ea005fc7ac8` | recorded only; the `.sig` is not vendored |
| Signer fingerprint | `6A8F 9C26 6528 E25A EB1D 7731 C237 1D91 CB71 6EA7`, RSA 4096, Sebastian Falbesoner (theStack) | recorded only; no keyring is vendored |
| Vendored tree | 60 of 60 files | **re-verified: `match=60 mismatch=0 missing=0 skipped=1`** |

The skip is the `libsecp256k1-0.8.0.tar.gz` line — the upstream archive, which is
intentionally not vendored.

**What `GOODSIG` + `VALIDSIG` (exit 0) establish.** A signature over exactly
those archive bytes was made by the key with that fingerprint, and the archive
was not altered after signing.

**What they do not establish.**

* `TRUST_UNDEFINED 0 pgp` — there is no certification path from this host to the
  key. Trust in the *identity* rests on cross-referencing three sources, and one
  of them (`SECURITY.md`) travels **inside the artifact being verified**, so it is
  circular. The other two (the owner-controlled GitHub key endpoint and a public
  keyserver) are both self-assertions of the same key.
* `EXPKEYSIG` — the first verification attempt **failed**. Recovery was to import
  a second copy of the *same fingerprint* carrying later self-signatures. A
  self-signature extends an expiry claim made by the key itself; it adds no
  independent evidence. The fingerprint never changed, so this is an expiry
  bookkeeping anomaly, not evidence of substitution.
* **Reproducibility.** No archive, no `.sig`, no keyring and no full transcript
  is vendored anywhere under `kernel/`, `docs/` or `scripts/`, so the GPG
  verification cannot be re-run from the repository. `SHA256SUMS` is generated
  from the tree it validates; it proves internal consistency and non-drift, not
  equality with upstream.

No evidence of key compromise was found, and none is claimed. No evidence that
the release is invalid was found, and none is claimed. Equally, no evidence was
found that would justify calling the key independently trusted.

**Independent trust evidence required before production integration:**

1. a reproducible verification path committed to the repository — the `.sig`,
   the archive hash in a tamper-evident record, and a verifier script with a
   pinned fingerprint;
2. at least one trust anchor not controlled by the release author — a second
   maintainer's signature, a reproducible-build comparison against a third-party
   build, or a project-held signing key;
3. a checksum chain that terminates outside the artifact under test;
4. re-verification recorded at adoption time, with the `--status-fd` transcript,
   rather than a single historical transcript.

### 17.10 Regression gates `[VERIFIED, fresh]`

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gate-p2-6.ps1 `
  -BuildDir .build\p27-final-kernel `
  -DifferentialBuildDir .build\p27-final-differential
```

| Gate | Observed | Exit |
|---|---|---|
| Preflight | cmake 4.4.3, MinGW g++ 16.2.0, Python 3.15.0, cargo 1.99.1 | 0 |
| Kernel configure + build | 23/23 targets compiled from an **empty** directory, warnings as errors | 0 |
| C++ kernel unit tests | `kernel unit tests: 108 run, 0 failed` | 0 |
| G1 conformance | `28/28 cases replayed against source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c` | 0 |
| P2 conformance | `21/21 cases`; `corruption self-check rejected 21/21 cases`; 2 deferred (G2c) | 0 |
| P0 deterministic baseline | `PASS 112  ANCHOR 5  SKIP 0  FAIL 0` | 0 |
| Rust suite (`--all-targets`) | **278 passed, 0 failed across 11 targets**; 1 ignored (the fixture emitter) | 0 |
| `high_s_signature` | 4 passed, 0 failed | 0 |
| `s5_boundary_probes` | 3 passed, 0 failed | 0 |
| Differential build A + B | 7 artifacts each, both from empty directories | 0 |
| Reproducibility comparison | `3/3 objects byte-identical`; `archive=differs; exe=differs` | 0 |
| Differential `ctest` | `1/1 kernel_secp256k1_differential ... Passed 0.23 sec` | 0 |
| Differential verdicts | `116/117 match (7 accept, 110 reject)`; groups `V1=2, V2=3, V3=18, V4=11, V5=5, V6=2, V7=76` | 0 |
| Adapter load-bearing rows | `V4.uncompressed_65`, `V4.hybrid_prefix_06` | 0 |
| Known divergence | `1 pinned: V4.prefix_05: rust=accept seam=reject backend=reject` | 0 |

Byte-identical objects: `precomputed_ecmult.c.obj` (1,049,211 B,
`93e43da54eddf2975c7b918b33ad44168eb9fdb021943eda4956b11a1e8fde7b`),
`precomputed_ecmult_gen.c.obj` (88,681 B,
`e2cc3bc1080ce0d27f3dec0aa76702d56d2b06a9f581796b5f541e79e9769609`),
`secp256k1.c.obj` (167,189 B,
`18b385efe4f199322b3855ff6c3dd45c3db141d4b9fe67a299cc51a74e97e306`).

Final lines:

```text
P2.6 gates: PASS (every step executed; 1 documented divergence pinned)
G2c: NO-GO — V4.prefix_05 is consensus-relevant
```

**Guard negative controls, re-run against the final runner.** Both directions
still work, so the allowance narrows the gate rather than disabling it:

| Control | Command | Exit | Message |
|---|---|---|---|
| No allowance | `--expect-cases 117` | **1** | `undocumented divergence(s): V4.prefix_05: rust=accept seam=reject backend=reject` |
| Stale allowance | `--expect-cases 117 --known-divergence V4.prefix_05 --known-divergence V4.prefix_00` | **1** | `stale --known-divergence entry: V4.prefix_00 now matches; remove the allowance` |

**Cached-run disclosure.** The gate was executed three times in P2.7. The first
execution reused an existing kernel build directory and printed `ninja: no work
to do`; that run is **not** treated as fresh-build evidence anywhere above. The
second and third used empty directories and compiled all 23 kernel targets and
all 7 differential artifacts from scratch. The numbers recorded here are from
the final empty-directory run.

The Rust total rose 271 (P2.6) -> 277 -> 278 as the new test file grew from 6 to
7 tests. No existing test changed, none was weakened, no fixture was edited and
the known-divergence allowance was not removed.

### 17.11 G2c verdict and P3 status

**G2c: NO-GO — unchanged.**

P2.6 was NO-GO because the measurement produced a consensus-relevant
disagreement. P2.7 does not lift that, and could not: the missing input is a
**protocol decision**, not another measurement. Measured against §14's GO
conditions, no condition became satisfied — the divergence is now fully
characterised and carries a recommendation, but the condition that gates on it
(`§9 V matrix green`) still fails, and a seventh condition has been added:

| §14 condition | State after P2.7 |
|---|---|
| written authorisation naming one acquisition path | experiment only |
| pinned tag, archive SHA-256, GPG signature | satisfied for the bytes; verification not reproducible from the repo |
| wrapper gating SEC1 to 33 bytes / `0x02` / `0x03` | satisfied |
| §9 V matrix green | **not satisfied** — 116/117, `V4.prefix_05` pinned |
| S5 closed or explicitly waived | not satisfied, not waived |
| separate decision for `signature_der` | not taken |
| **new:** `0x05` disposition decided | **not decided — recommendation recorded in §17.8** |

**P3: not started.** No Go networking, no service layer, no RPC and no P3 work
was performed. The kernel still links nothing, the backend remains isolated, and
the two deferred corpus cases remain deferred.

### 17.12 Files changed and non-claims

Added in P2.7:

- `zerocoin/tests/p2_7_pubkey_encoding.rs` — 7 tests, 445 lines, no production
  module changed;
- this section.

Not changed: any file under `zerocoin/src/`, `kernel/include/`, `kernel/src/`,
`kernel/tests/`, `kernel/differential/`, `test/`; the differential fixture; the
known-divergence allowance in `scripts/gate-p2-6.ps1`; `Cargo.toml`;
`Cargo.lock`; the vendored `secp256k1` tree; any `.publish` state; Git identity
or remote configuration.

Explicitly **not** claimed:

- that the `0x05` acceptance is exploitable for theft or forgery — it is not;
- that any historical block or transaction is invalid;
- that option A is safe to apply without an authorisation and an activation
  decision;
- that libsecp256k1's stricter parser defines ZeroCoin's consensus rules;
- that the signing key is compromised, or that the release is invalid;
- that the key is independently trusted;
- that G2c, gate G2 or the P2 exit criteria are closed;
- that P3, the service layer, RPC or Go networking has begun.
