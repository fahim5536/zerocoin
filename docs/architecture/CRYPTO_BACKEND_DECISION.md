# Cryptographic backend decision record (G2c)

Status: **BLOCKED — no backend acquired, no download performed.**
Recorded during P2.1 at commit `e8fda7e` (2026-10-18); host inventory taken on
2026-10-19. This document authorises no code and makes no compatibility claim.

Scope: the secp256k1 implementation that `zk::SigVerifier`
(`INTERFACE_CONTRACTS.md` §3) needs in order to close G2c. The Rust reference
uses `k256 0.13.4`; the C++ kernel currently links nothing.

---

## 1. Question and constraints

**Question.** Which established, maintained secp256k1 library can the C++ kernel
link, obtained through a reproducible mechanism that this repository can verify
offline, without weakening byte-level compatibility with the Rust reference?

Constraints, all binding:

1. **No download or installation without authorisation.** P2.1 may inspect the
   host only.
2. **No elliptic-curve code written in this repository**, ever (doc `04` R9).
3. **Licence compatibility with MIT** (repository `LICENSE`, Rust crate
   `license = "MIT"`).
4. **Targets:** Windows (MinGW today, MSVC later), Linux, macOS, and eventually
   Android via the NDK.
5. **The kernel stays buildable without Rust.** A backend that requires a Rust
   toolchain is disqualified (`THREE_LANGUAGE_ARCHITECTURE.md` §3 rule 2).
6. **Behaviour must match the reference**, including the absence of a low-S rule
   (doc `08` §6).

---

## 2. Host inventory

Read-only probes. "Absent" means the probe found nothing; it does not imply the
component could not be installed with authorisation.

| Probe | Result |
|---|---|
| `where.exe openssl` | nothing on `PATH` |
| `openssl.exe` under `C:\Program Files`, `C:\Program Files (x86)` (depth 3) | none |
| Git for Windows (`D:\Git`) | `usr\bin\openssl.exe` **present** — OpenSSL 3.5.7 CLI. No development package: `usr\include\openssl\ssl.h` absent, only the runtime `msys-crypto-3.dll`, no import library under `usr\lib` or `mingw64\lib` |
| `where.exe pkg-config` | absent |
| `C:\vcpkg`, `where.exe vcpkg` | absent |
| `C:\msys64`, `where.exe pacman` | absent |
| C++ toolchain library directory (WinLibs MinGW-W64 UCRT, g++ 16.2.0) | no `libcrypto*`, no `libssl*` |
| Python modules `coincurve`, `ecdsa`, `cryptography`, `secp256k1` | all absent |
| Cargo registry sources | `k256-0.13.4` only; no `secp256k1*` crate sources |
| Repository vendor/third-party directories | none |

Conclusion from the inventory: **the host contains no linkable secp256k1
implementation and no linkable OpenSSL development package.** The only OpenSSL
artefact is a CLI inside Git's private runtime, which is not a supported
dependency for a third-party build (no headers, no import library, no ABI
guarantee, and it would change under Git upgrades).

Consequently, obtaining any backend requires either a network fetch or a package
manager bootstrap. Both are authorisation-gated by constraint 1, so P2.1 stops
here and records the decision instead of proceeding.

---

## 3. Candidates considered

| Candidate | Licence | Maintained | On host | Strict DER | High-S behaviour | Verdict |
|---|---|---|---|---|---|---|
| **bitcoin-core/secp256k1** (libsecp256k1) | MIT | Yes, active | No | Yes — `secp256k1_ecdsa_signature_parse_der` rejects non-canonical encodings; the lax parser lives in `contrib/` and is not linked | `secp256k1_ecdsa_verify` **returns 0 for high-S**; wrapper must normalise a copy before verifying | **Selected, blocked** |
| OpenSSL 3.x (`libcrypto`) | Apache-2.0 | Yes | CLI only (Git runtime), no dev package | `d2i_ECDSA_SIG` is BER-tolerant; strictness and trailing-length checks must be re-implemented in the wrapper | Accepts high-S | Rejected as primary; fallback only |
| `k256` via a Rust `staticlib` | Apache-2.0 OR MIT | Yes | Crate present (`k256-0.13.4`) | Exact — it is the reference | Accepts high-S (exact parity) | Rejected: couples the C++ build to a Rust toolchain |
| `secp256k1-sys` vendored C sources from crates.io | MIT | Yes | No | Same as libsecp256k1 | Same as libsecp256k1 | Alternative acquisition path for the selected candidate |
| vcpkg `secp256k1` port | MIT | Yes | No | Same as libsecp256k1 | Same as libsecp256k1 | Alternative acquisition path; requires vcpkg bootstrap |
| Python `coincurve` | MIT | Yes | No | Binding-level | Same as libsecp256k1 | Rejected: test-time only, not a C++ backend |
| In-tree implementation | — | — | — | — | — | **Forbidden** by constraint 2 |

### Why libsecp256k1 is the selection

- It is the reference implementation of the curve used by Bitcoin Core, with a
  narrow C API designed for consensus software, no runtime dependencies and no
  global state.
- Its DER parser is strict by default; the lax parser is opt-in and stays out.
- MIT licence, compatible with the repository.
- It builds with both autotools and CMake in current releases and supports the
  required platforms, including MinGW and the Android NDK.

The one behaviour that does **not** match is high-S rejection in
`secp256k1_ecdsa_verify`. This is a known, documented property, not a defect,
and it is handled in the wrapper (§7.3).

---

## 4. Version pinning strategy

When authorised, the backend is pinned by all of the following, in this order:

1. **Exact upstream release tag or commit SHA**, never a branch and never
   "latest".
2. **SHA-256 of the acquired source archive**, recorded in this document and in
   `kernel/cmake/Secp256k1.cmake` (the file doc `03` §2 already reserves).
3. **A vendored source subtree** at `kernel/third_party/secp256k1/` containing
   the upstream `LICENSE`, a `SHA256SUMS` file and an `ORIGIN` note naming the
   tag, the URL and the hash. Vendoring is preferred because the kernel must
   build offline and reproducibly after acquisition.
4. **Generated sources disabled** where the option exists; only the C sources the
   CMake target needs are compiled, with the same warning flags as the kernel.
5. **A recorded build configuration**: precomputed tables, the field/scalar
   backend selection, and every `SECP256K1_*` option that affects behaviour or
   binary layout.

FetchContent with `URL_HASH` and a vcpkg manifest with `builtin-baseline` are
acceptable alternative mechanisms, but each still requires one network operation
and a package-manager bootstrap. They are recorded as alternatives, not chosen.

---

## 5. Licensing

| Component | Licence | Obligation in this repository |
|---|---|---|
| libsecp256k1 | MIT | Retain the copyright and permission notice in the vendored subtree; note it in the kernel's third-party notice |
| Repository | MIT | No change |
| Rust `k256 0.13.4`, with `ecdsa 0.16.9` (which owns the DER parser) | Apache-2.0 OR MIT | Already recorded in doc `08` §6; no new obligation |

No GPL, LGPL or SSPL component is acceptable. OpenSSL 3.x is Apache-2.0 and
therefore licence-compatible, which is why it remains a fallback rather than
being excluded on licence grounds.

---

## 6. Build requirements (for the authorised follow-up)

- A C compiler and CMake; both are present (g++ 16.2.0, CMake 4.4.3).
- No autotools requirement if the CMake path is used; if the pinned release's
  CMake build is incomplete, the autotools build must be run once and its
  artefacts pinned, which is worse for reproducibility and would need its own
  record.
- The library is C89-compatible and builds as a static library with no runtime
  dependency; linking it into `zerocoin_kernel` must not add a DLL dependency on
  Windows.
- The kernel must keep `-Wall -Wextra -Wpedantic -Werror` for its own sources.
  Third-party sources are compiled with a documented, narrower warning policy so
  that an upstream warning cannot silently disable the kernel's policy.
- The build must work when the source tree is read-only and offline.

---

## 7. API safety

### 7.1 Context and lifetime

- One verification context is created at start-up and destroyed at shutdown; it
  is immutable afterwards and may be shared read-only across threads.
- The context is never used for signing, so signing callbacks and RFC 6979
  nonces never enter the kernel.
- No global mutable state; no callbacks; no allocator hooks.

### 7.2 Parsing

- `secp256k1_ec_pubkey_parse` accepts compressed and uncompressed forms. The
  wrapper must enforce **33 bytes and prefix 0x02/0x03** before calling it, then
  reject any parse failure. This reproduces B1 exactly.
- `secp256k1_ecdsa_signature_parse_der` is used for B2. It rejects non-minimal
  integers, negative values, zero and out-of-range scalars, and bad lengths. The
  `contrib` lax parser must not be linked.
- The trailing sighash byte is removed by `TxSigChecker` before the call; the
  parser sees DER only.

### 7.3 High-S handling (the compatibility-critical step)

`secp256k1_ecdsa_verify` returns 0 when `s` is in the upper half of the group
order. The Rust reference has no such rule. The wrapper therefore:

1. parses the DER into a signature object (accepting either half);
2. copies it and calls `secp256k1_ecdsa_signature_normalize` on the copy;
3. calls `secp256k1_ecdsa_verify` with the normalised copy;
4. returns the result.

Step 2 is an internal transformation required to reproduce reference acceptance.
It is **not** a low-S policy: a high-S signature is accepted, no error is
reported to the caller, and no API exposes the normalised form. B4 stays true.

### 7.4 Failure behaviour

- Every parse and verify failure returns `false`; no exception, no abort, no
  error string, no logging of key material.
- A context creation failure is a start-up error, not a per-signature failure:
  the node must refuse to start rather than fail open.

### 7.5 Memory

- Inputs are public data. No secret is loaded, so constant-time concerns apply
  only to the library's internal verification path, which is why a vetted
  library is used at all.
- No allocation is retained between calls; the wrapper owns only the context.

---

## 8. Cross-platform limitations

| Platform | Status | Notes |
|---|---|---|
| Windows x86-64, MinGW-w64 UCRT | Expected to build | The only platform this repository can currently test; static link, no DLL dependency |
| Windows x86-64, MSVC | Expected to build | Not exercised by the gate; becomes a G7 obligation |
| Linux x86-64 | Expected to build | No CI yet; G7 |
| macOS (Intel/ARM) | Expected to build | No CI yet; G7 |
| Android (arm64, NDK) | Expected to build | The wallet ships as a Rust `cdylib`; a C++ node is not planned for Android |
| 32-bit x86 | Possible, untested | 64-bit assumptions in neighbouring code make this a separate decision |
| Big-endian | Possible, untested | No target |

Limitations that are properties of the choice, not of the port:

- the library is C, so its headers are wrapped by a C++ façade; no C type may
  leak into `kernel/include/zerocoin/`;
- its build system and options change between releases, which is why the pin is
  an exact tag plus an archive hash rather than a version range;
- it provides verification but not the reference's `CryptoError` classes; the
  kernel intentionally collapses those to `bool` (doc `08` §6).

---

## 9. Compatibility matrix (G2c acceptance)

The backend is not accepted until every row passes against the Rust reference.
Rows marked "existing" are already in the corpus; the rest are added with the
backend, each with a Rust-generated vector.

| Family | Cases | Oracle | Pass condition |
|---|---|---|---|
| SEC1 parse (**existing**, partly) | 33-byte generator key; 65-byte uncompressed; prefixes `0x00`, `0x04`, `0x05`, `0x06`, `0x07`; lengths 32/34; `x = p`; `x` off-curve; point at infinity | `PublicKey::from_sec1` | Accept only 33-byte `0x02`/`0x03` with a valid point |
| Strict DER (**existing**, partly) | canonical; minimal integer with a leading zero only when the high bit is set; negative; zero `r`/`s`; `r ≥ n`; `s ≥ n`; non-minimal length; long-form length; trailing bytes; empty; truncated | `Signature::from_der` | Accept canonical only; reject the rest |
| Prehashed verify (**existing**) | 32-byte digest from the P2 sighash corpus; a digest that is not `SHA-256(message)` | `verify_prehash` | No re-hashing; the same digest yields the same verdict |
| Valid and invalid (**existing**) | valid signature; one flipped bit; wrong message; wrong public key; wrong chain id; wrong sighash type; wrong input index | `PublicKey::verify` | Identical verdicts |
| Boundaries (new) | `r = 1`, `s = 1`, `r = n-1`, `s = n-1`, `s = n/2` (both sides), high-S twin of a valid signature | Rust vectors | Identical verdicts; **high-S accepted** |
| ZeroCoin sighash (**existing**) | 15-byte tag, chain id, blanked scriptSigs, LE-u32 type fold (F18), out-of-range index | P2 corpus | 23/23 cases replayed, up from 21/23 |
| Cross-signing (new) | Rust signs RFC 6979 → C++ verifies; C++ signs (test harness only) → Rust verifies | Both | Both directions accept |
| Corruption (existing guard) | Every replayed case with one output byte flipped | `p2_conformance.py` | All rejected, none accepted |

Acceptance also requires: G1 28/28 unchanged; unit tests only added; Rust 263
unchanged; P0 112/5/0/0 unchanged; the deferral list empty; and a written
statement in the phase document that no low-S rule was introduced.

---

## 10. Decision and non-claims

**Decision.** libsecp256k1 (bitcoin-core/secp256k1) is the selected candidate,
pinned by tag and archive SHA-256, MIT-licensed, with the high-S normalisation
step of §7.3. The acquisition is **not authorised in P2.1**, so the candidate is
selected but not obtained.

**Therefore, explicitly not claimed:**

- no signature compatibility between C++ and Rust;
- no closure of G2c, of gate G2, or of doc `03` §4's P2 exit criteria;
- no low-S policy, in either direction;
- no use of the OpenSSL CLI inside Git as a library;
- no change to the kernel's dependency set — it still links nothing.

The kernel keeps failing closed: `TxSigChecker` with a null verifier returns
`false`, and the two corpus cases stay deferred (doc `08` §8.1).

---

## 11. Authorisation required to proceed

One of the following, recorded in the next milestone's brief:

| Option | What is fetched | Reproducibility |
|---|---|---|
| **A. Vendor a pinned source archive** (recommended) | One archive of a named release tag, verified by SHA-256, committed under `kernel/third_party/secp256k1/` with `LICENSE`, `SHA256SUMS` and `ORIGIN` | Highest: offline builds, reviewable bytes, no toolchain bootstrap |
| B. FetchContent with `URL_HASH` | Same archive at configure time | Good, but every build needs the network or a cache |
| C. vcpkg manifest with `builtin-baseline` | vcpkg bootstrap plus the port | Good, but adds a package manager and its own updates |

Whichever is authorised, the follow-up must also add the vectors in §9 before
the backend is linked into a shipping target — and it still may not change the
Rust reference.

---

## 12. Rejected alternatives (summary)

| Alternative | Reason rejected |
|---|---|
| Implement secp256k1 in-tree | Forbidden by constraint 2 and doc `04` R9 |
| Link Rust `k256` into C++ | Couples the C++ build to a Rust toolchain (constraint 5); makes the kernel unbuildable in the environments it exists for |
| Use Git's bundled OpenSSL | No headers, no import library, no ABI guarantee; not a dependency mechanism |
| Use OpenSSL as primary | `d2i` strictness and trailing-data handling would have to be re-implemented, creating a divergence risk exactly where the contract is strictest; larger surface than needed |
| Use a test-only Python binding | Not available in the kernel; would leave C++ unable to verify a spend |
| Skip verification and accept signatures | Violates fail-closed; would make the kernel unable to validate consensus |
