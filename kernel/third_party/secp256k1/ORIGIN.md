# libsecp256k1 — vendored provenance record (P2.6)

Status: **unmodified third-party source**. Vendored for the P2.6 differential
experiment only. It is **not** linked into `zerocoin_kernel`, **not** reachable
from `TxSigChecker`, and **not** part of the production transaction-validation
path.

Every file in this directory except `ORIGIN.md`, `SHA256SUMS` and `provenance/`
is a byte-for-byte copy of the file of the same relative path in the upstream
release archive listed below. Nothing was edited, patched, generated or
reformatted. `provenance/` holds the upstream verification materials
themselves — the release archive, its detached signature, and the public
verification key — preserved since P2.10 so the chain below can be re-derived
from the repository alone (see `provenance/README.md` and
`scripts/gate-p2-10-provenance.ps1`).

## 1. Upstream and release

| Field | Value |
|---|---|
| Repository | `https://github.com/bitcoin-core/secp256k1` |
| Release | `v0.8.0` — annotated, PGP-signed tag (not a branch, not `master`) |
| Tag object | `18f07c42218765cd46148d74d9fe575795f56dce` |
| Commit | `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d` |
| Tagged at | `2026-08-03T21:52:33Z` by Sebastian Falbesoner `<sebastian.falbesoner@gmail.com>` |
| Archive URL | `https://github.com/bitcoin-core/secp256k1/releases/download/v0.8.0/libsecp256k1-0.8.0.tar.gz` |
| Signature URL | `https://github.com/bitcoin-core/secp256k1/releases/download/v0.8.0/libsecp256k1-0.8.0.tar.gz.sig` |
| Archive size | `2436784` bytes |
| Archive SHA-256 | `dd685546f9e717b9adde329acd5a4cd8083d40f710fdb0a603ee5a83f908132b` |
| Signature size | `566` bytes |
| Signature SHA-256 | `c7eb14bbd67fe94b9ac4b556df6ae18aebb450092c836d05a6e13ea005fc7ac8` |
| Acquired | `2026-10-19` |

The commit SHA was resolved from the tag object through the public GitHub API
(`/git/ref/tags/v0.8.0` → `/git/tags/18f07c42…`) after the archive had already
been verified locally. It is recorded for pinning; it is not itself part of the
verification chain that produced the tree.

## 2. Signature verification

Signing key, established **independently of the downloaded artifact** from three
sources that agree:

1. `SECURITY.md` in the same release archive,
2. the owner-controlled GitHub account key endpoint `https://github.com/thestack.gpg`,
3. the public keyserver `https://keys.openpgp.org/vks/v1/by-fingerprint/…`.

```text
Fingerprint: 6A8F 9C26 6528 E25A EB1D  7731 C237 1D91 CB71 6EA7
Long key id: C2371D91CB716EA7
User id:     Sebastian Falbesoner (theStack) <sebastian.falbesoner@gmail.com>
Algorithm:   RSA 4096
```

Observed transcript (`gpg --status-fd 1 --verify`, exit code **0**):

```text
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 6A8F9C266528E25AEB1D7731C2371D91CB716EA7 0
[GNUPG:] SIG_ID LrS5nXK9cUh+AeZN97kKJoKAAeQ 2026-08-03 1785794118
[GNUPG:] GOODSIG C2371D91CB716EA7 Sebastian Falbesoner (theStack) <sebastian.falbesoner@gmail.com>
[GNUPG:] VALIDSIG 6A8F9C266528E25AEB1D7731C2371D91CB716EA7 2026-08-03 1785794118 0 4 0 1 10 00 6A8F9C266528E25AEB1D7731C2371D91CB716EA7
[GNUPG:] TRUST_UNDEFINED 0 pgp
gpg: Good signature from "Sebastian Falbesoner (theStack) <sebastian.falbesoner@gmail.com>" [unknown]
```

`TRUST_UNDEFINED` is expected: this host has no web-of-trust path to the key.
Trust here comes from the independent fingerprint cross-reference in the three
sources above, not from a certification chain.

**Recorded anomaly.** The key copy served from `https://github.com/thestack.gpg`
was stale: it expired `2025-11-20`, before the release signature was made on
`2026-08-03`, and `gpg --verify` against it produced `EXPKEYSIG`. Re-importing
the keyserver copy of the *same fingerprint* added two later self-signatures
extending validity to `2030-12-19` (subkey `2031-06-05`), after which the same
signature verified as `GOODSIG`/`VALIDSIG`. The fingerprint never changed; only
the expiry assertion did. This is recorded rather than hidden because the first
verification attempt did **not** succeed.

Host note: GnuPG 2.4.9 shipped with Git for Windows was used
(`D:\Git\usr\bin\gpg.exe`). It needs an explicit `--keyboxd-program` on this host.

Since P2.10 the three inputs of this verification are vendored at
`provenance/` (archive, `.sig`, public key), and
`scripts/gate-p2-10-provenance.ps1` re-derives the whole chain — pinned sizes
and hashes, key fingerprint, `gpg --verify` in an isolated throwaway GnuPG
home, and a byte-for-byte comparison of the vendored tree against the
archive's inner tree — with exit code 0 as the standing evidence. The
transcript above is the historical acquisition record, no longer the only
proof.

## 3. Licence and attribution

Upstream `COPYING` is the MIT licence, `Copyright (c) 2013 Pieter Wuille`. It is
vendored verbatim at `COPYING`. Every vendored `.c`/`.h` file retains its
upstream copyright header. No attribution is removed, and no file is relicensed.

Upstream is distributed under the MIT licence; the ZeroCoin repository root
`LICENSE` is unaffected. This vendored tree is not linked into any shipped
binary in P2.6, so it does not yet add an attribution obligation to a release
artifact. That obligation starts when (and if) the library is linked into a
shipped node.

## 4. Build configuration

The library is compiled from exactly three translation units:

| Source | Role |
|---|---|
| `src/secp256k1.c` | the whole library; upstream errors out if compiled as C++ |
| `src/precomputed_ecmult.c` | fixed precomputed verification table |
| `src/precomputed_ecmult_gen.c` | fixed precomputed signing table |

The defines below are transcribed from upstream `CMakeLists.txt` and
`src/CMakeLists.txt` at `v0.8.0`; the line references are to that tag.

| Define | Value | Why it is required | Upstream source |
|---|---|---|---|
| `ECMULT_WINDOW_SIZE` | `15` | must match the shipped `precomputed_ecmult.c` table | `CMakeLists.txt:62-66` (default 15) |
| `COMB_BLOCKS` | `43` | must match the shipped `precomputed_ecmult_gen.c` table | `CMakeLists.txt:68-80` |
| `COMB_TEETH` | `6` | same | `CMakeLists.txt:68-80` |
| `SECP256K1_STATIC` | defined | static linkage on Windows; affects only `dllimport` decoration | `src/CMakeLists.txt:86-90` |

Deliberately **not** defined: `ENABLE_MODULE_*` (every optional module is off),
`USE_EXTERNAL_DEFAULT_CALLBACKS`, `USE_FORCE_WIDEMUL_*`,
`SECP256K1_NO_API_VISIBILITY_ATTRIBUTES`. Field/scalar/widemul backends are left
to upstream's own compile-time detection, exactly as an upstream default build
does; selecting them by hand would make the tree build differently from the
release it claims to be.

No optimisation level is forced. No global compiler flag, toolchain file or
`CMAKE_*` toolchain change is applied by the ZeroCoin build system.

## 5. Vendored files

`SHA256SUMS` lists the SHA-256 of every vendored file plus the SHA-256 of the
release archive itself. Regenerate and compare with:

```powershell
cd kernel\third_party\secp256k1
Get-Content SHA256SUMS
```

Since P2.10 the comparison is a gate step rather than a manual procedure:
`scripts/gate-p2-10-provenance.ps1` re-hashes the vendored tree against
`SHA256SUMS` and byte-compares it with the archive's inner tree.

Vendored: `COPYING`, `include/secp256k1.h`, `include/secp256k1_preallocated.h`,
all `src/*.h` needed by the library, and the three `.c` files above — 60 files,
3,266,759 bytes.

## 6. Deliberately omitted upstream files

| Omitted | Reason |
|---|---|
| `src/modules/**` | every optional module is disabled; nothing includes these headers |
| `src/tests.c`, `src/tests_exhaustive.c`, `src/unit_test.c`, `src/ctime_tests.c` | upstream's own test suite is not built; P2.6 tests the library from outside |
| `src/bench*.c`, `src/bench.h` | benchmarks are out of scope |
| `src/precompute_ecmult*.c` | the tables are shipped, not regenerated |
| `src/testrand*.h`, `src/testutil.h`, `src/tests_common.h`, `src/unit_test.h` | test-only helpers |
| `include/secp256k1_<module>.h` | their modules are disabled |
| `.github/`, `ci/`, `contrib/`, `doc/`, `sage/`, `tools/`, `examples/` | not required to build the library |
| upstream `CMakeLists.txt`, `src/CMakeLists.txt`, `cmake/` | the ZeroCoin build defines its own explicit target; the upstream option semantics it replaces are transcribed in §4 |

`README.md` and `SECURITY.md` are omitted from the vendored tree to keep the
footprint minimal; both remain available at the tag they were read from, and
`SECURITY.md` is the first of the three fingerprint sources in §2.
