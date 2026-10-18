# 07 — P1: kernel primitives (gate G1)

> Evidence labels follow `README.md` §1. The gate below was run on 2026-10-18
> against `main` = `76545d641bf07ab65e200bacebc4ab453abd367a`, the commit these
> changes sit on top of, on Windows 24H2 with GNU 16.2.0 (MinGW-W64 UCRT),
> CMake 4.4.3, Ninja 1.13.2, Python 3.15.0 and `cargo` 1.99.1. The Rust
> toolchain is named `+stable-x86_64-pc-windows-gnu` for the reason given in
> `README.md` §2.

P1 (`03` §4) is the first phase that writes C++. It builds the dependency-free
consensus kernel — hash, `uint256`, varint, transaction serialisation, and the
hex types that keep storage order and display order apart — plus the machinery
that replays the P0 corpus against it. It adds no consensus rule, changes no
Rust source file, and the kernel is built by developers and CI only: the shipped
node is still the Rust binary.

---

## 1. Result

| Item | Result | Evidence |
|---|---|---|
| Corpus cases replayed | 28/28, 0 failed, 0 missing | gate output `[VERIFIED]` |
| — `hash` | 5 | `g1_conformance.py` `[VERIFIED]` |
| — `encoding.varint` | 9 | `g1_conformance.py` `[VERIFIED]` |
| — `encoding.transaction` | 5 | `g1_conformance.py` `[VERIFIED]` |
| — `difficulty.compact` | 9 | `g1_conformance.py` `[VERIFIED]` |
| Kernel unit tests | 82 run, 0 failed | `kernel_tests` `[VERIFIED]` |
| CTest registration | 2/2 passed in 0.25 s | `ctest` `[VERIFIED]` |
| Compile-time assertions | 57 — 24 in the five headers, 33 in two test TUs | §3.2 `[VERIFIED]` |
| Storage/display confusion | rejected at compile time; the explicit route compiles | §6 `[VERIFIED]` |
| Tampered expected value | 1/1 detected, exit 1 | §6 `[VERIFIED]` |
| Shrunk case slice | 1/1 detected, exit 2 | §6 `[VERIFIED]` |
| Build | clean for all three targets under `-Werror` | gate output `[VERIFIED]` |
| Rust suite | 263 passed, 0 failed across 7 targets | `cargo test --all-targets` `[VERIFIED]` |
| P0 verifier | `PASS 112 ANCHOR 5 SKIP 0 FAIL 0` | `run_vectors.py --quiet` `[VERIFIED]` |
| Rust sources changed | none | `git status --short` `[VERIFIED]` |
| Corpus changed | none — `test/vectors/` is read-only to this phase | `git status --short` `[VERIFIED]` |
| MSVC build | not attempted | `[UNVERIFIED]` |
| Second host or compiler | not attempted | `[UNVERIFIED]` |

Gate G1 has three clauses (`03` §4). Clause one — every hash, varint and
transaction serialisation vector matches — holds: 19 of the 28 cases are those
three groups, and the other nine are the `uint256` compact vectors that `05` §7
adds to the same gate. Clause two — storage order and display order cannot be
confused at compile time — is §3.2 and §6. Clause three — a `static_assert` on
every width and constant — is the 24 assertions the headers carry, listed in
§2. The gate itself is `scripts/gate-g1.ps1`, and its exit code is the verdict.

---

## 2. What P1 added

| Path | Size | Role |
|---|---|---|
| `kernel/include/zerocoin/hex.h` | 147 lines | `HexString<N>` and `DisplayHex<N>`: the F3 defence |
| `kernel/include/zerocoin/hash.h` | 108 lines | `Hash256`, `Hash160`, `sha256`, `ripemd160`, `sha256d`, `hash160` |
| `kernel/include/zerocoin/uint256.h` | 122 lines | 256-bit integer, compact `nBits`, arithmetic, shifts |
| `kernel/include/zerocoin/varint.h` | 54 lines | CompactSize size/encode/decode |
| `kernel/include/zerocoin/transaction.h` | 126 lines | `Outpoint`, `TxIn`, `TxOut`, `Transaction`, the decoder and its error enum |
| `kernel/src/*.cpp` | 7 files, 955 lines | SHA-256, RIPEMD-160, hex, uint256, varint, transaction codec |
| `kernel/tests/*` | 9 files, 1,153 lines | a 37-line test framework plus 82 tests |
| `kernel/conformance/main.cpp` | 443 lines | fixture interpreter, nine operations |
| `kernel/tools/g1_conformance.py` | 390 lines | corpus → fixture translator and result auditor |
| `kernel/CMakeLists.txt` | 74 lines | static library, test and conformance executables, two CTest tests |
| `scripts/gate-g1.ps1` | 239 lines | gate G1: build, ctest, unit tests, replay, Rust suite, P0 harness |
| `.gitignore` | +14 lines | section 6 keeps in-tree CMake output out of history |

The kernel is 24 files and 3,563 lines in total. It has no third-party
dependency — SHA-256, RIPEMD-160, the 256-bit arithmetic and the codec are all
in-tree — so the build needs a C++20 compiler and CMake, nothing else.

`03` §4 names four modules (`hash`, `uint256`, `transaction`, `util`). In the
tree that is one static library and five headers: `util` is `hex` plus `varint`,
and the target produces `libzerocoin_kernel.a`, the name the plan uses. Splitting
it into four libraries would add build edges without adding a boundary the
compiler enforces.

---

## 3. Design

### 3.1 Shape

The kernel is a pure function library: bytes in, bytes out. It performs no I/O,
reads no clock or environment, starts no thread, and links no crypto library.
The decoder is `noexcept` and reports failure as an enum value rather than an
exception, because every caller in a consensus path has to handle rejection
anyway.

| Header | Mirrors | Owns |
|---|---|---|
| `hex.h` | — (no Rust counterpart) | fixed-width hex text, both byte orders |
| `hash.h` | `crypto/hash.rs` | SHA-256, RIPEMD-160, SHA-256d, HASH160 |
| `uint256.h` | `consensus/uint256.rs` | the difficulty target type |
| `varint.h` | the varint half of `ledger/transaction.rs` | CompactSize |
| `transaction.h` | `ledger/transaction.rs` | the canonical byte string and its txid |

### 3.2 Byte order is a type

Finding F3 is that the node stores digests in internal order and shows them
reversed, and that a port which swaps them produces plausible-looking, wrong
hashes. The kernel makes that swap unrepresentable:

- `HexString<N>` holds the bytes that were hashed; `DisplayHex<N>` holds the
  same bytes reversed. Neither has a converting constructor or conversion
  operator in either direction, so `DisplayHex256 d = internal;` does not
  compile (proved in §6, not assumed).
- The width is part of both types. `Hex256` is not `Hex20`, does not convert to
  it, and is not constructible from it.
- The only way from one order to the other is explicit:
  `Hash256::to_display_hex()` builds a `DisplayHex256`, and
  `DisplayHex<N>::internal_bytes()` goes back.
- The reversal is written once, in `DisplayHex`'s constructor, and
  `display_hex_reversal_is_an_involution` pins it.

Nine assertions in `hex.h` and four in `hash.h` hold the widths, text lengths
and object sizes; `uint256.h` holds three (`4 × 64 = 256` bits, 32 bytes,
`sizeof == 32`); `varint.h` holds four; `transaction.h` holds four (the 1,000,000
byte script bound, the 10,000 input and output bounds, and `0xffffffff` as the
null `vout`). `test_static_asserts.cpp` adds 29 more from outside the headers,
including `is_convertible_v` and `is_constructible_v` in both directions and the
`decltype` of `to_hex()` / `to_display_hex()`.

### 3.3 `Uint256`

Four 64-bit limbs, least significant first, which is the order the Rust
reference uses and therefore the order that makes operation-by-operation
comparison possible. Byte conversion is done byte by byte, so it does not depend
on host endianness.

`from_compact` / `to_compact` implement Bitcoin's `nBits`: a 24-bit mantissa, an
exponent, and a sign bit that means "zero" when set. The corpus pins all of
that, including the two cases that a naive implementation gets wrong —
`0x1d800000` is zero, and `0x2100ffff` is a valid target with a high mantissa
byte. Arithmetic is `wrapping_add`, `wrapping_sub`, `mul_u64`, `div_u64` and a
general `divmod`; division proceeds from the most significant limb.

### 3.4 The codec

`Transaction::serialize()` is the byte string the txid commits to: a fixed field
order, little-endian integers, and minimal CompactSize lengths. The decoder
enforces minimality for the same reason the reference does — `fd0100` is one
encoded in three bytes and is refused with `NonMinimalVarInt` — and bounds the
counts and script sizes with the same constants.

`deserialize_transaction` returns `{tx, error, consumed}` and does not require
that `consumed` reach the end of the buffer. That is finding F-2 in the risk
register: the reference tolerates trailing bytes, and a port that rejects them
would diverge. `transaction_decoder_leaves_trailing_bytes_alone` pins the
tolerance instead of "fixing" it.

`to_string(TxDecodeError)` is the stable spelling the conformance fixture
compares against, so the corpus's `"kind": "NonMinimalVarInt"` and the C++ enum
have exactly one mapping.

### 3.5 What the kernel deliberately does not do

No secp256k1, no script, no sighash, no header, no Merkle, no difficulty
policy, no reward. No constant-time claims: nothing in G1 touches a secret. No
allocation strategy: `std::vector` and `std::array` only. No logging.

---

## 4. Replaying the corpus

### 4.1 The fixture grammar

The C++ runner knows nothing about JSON or Rust. It reads a line-oriented
fixture, one directive per line, where the value is everything after the first
`=`, so empty values are unambiguous:

```
META key=value
CASE <id>
OP <op>
IN key=value      (repeatable)
OUT key=value     (repeatable, the expected value)
END
```

It prints `RESULT <id> ok|fail <message>` per case and
`SUMMARY cases=<n> failures=<n>` at the end, and exits 0 or 1. The Python
wrapper turns a non-0/1 exit into its own exit 2, because that means the runner
crashed rather than disagreed.

### 4.2 The mapping

| Corpus ids | op | Comparisons |
|---|---|---|
| `hash.sha256.*` | `sha256_utf8` | `sha256_hex` |
| `hash.sha256d.*` | `sha256d_utf8` | `internal_hex`, `display_hex` |
| `hash.hash160.*` | `hash160_sec1` | `hash160_hex` |
| `hash.display_*` | `display_reversal` | `display_hex` |
| `encoding.varint.*` | `varint_encode` | `bytes_hex`, `length` |
| `encoding.transaction.{sample,empty,payment}` | `tx_build` | six values, including both txid orders |
| `encoding.transaction.coinbase_147` | `tx_roundtrip` | decode, re-serialise, txid, scripts, counts |
| `encoding.transaction.decode_nonminimal_varint` | `tx_decode_error` | `error`, `consumed` |
| `difficulty.compact.*` | `compact` | `target_be_hex`, `is_zero`, `roundtrip_bits` |

`tx_build` takes inputs as `txid|vout|script_sig_hex|sequence` and
`value|script_pubkey_hex`, so the fixture never needs a JSON parser. The
corpus's nested `txid` object is flattened to `txid_internal_hex` and
`txid_display_hex`; both are compared, which is why a reversal bug cannot hide
in the transaction group any more than in the hash group.

The wrapper does not pass unknown expected keys through. `PRODUCIBLE_KEYS`
declares what each operation can produce, and a corpus key that the operation
cannot produce raises rather than being silently dropped — the failure mode
that would otherwise turn a new expectation into a no-op.

### 4.3 The coinbase case

`encoding.transaction.coinbase_147` has `{height, payout_scalar}` as its input,
which requires secp256k1 key derivation — phase P2. G1 owns the codec, so the
case is replayed from its expected bytes: decode, re-serialise, derive the txid,
read the committed scripts back, and check the decoder consumed everything. Its
`committed_height` expectation is deferred to P3, where `reward.rs` lives.

That is weaker than the other 27 cases and is stated as such: for this case the
expected bytes are also the input, so it proves the codec round-trips and the
txid commits to those bytes — not that C++ can derive the payout script. The
other four transaction cases build the transaction from fields.

### 4.4 The guards

Four things stop the suite from silently shrinking or widening:

1. `check_manifest` compares each file's `case_count` with its `cases` array and
   with the manifest's per-file entry.
2. `EXPECTED_CASE_COUNT = 28` fails the run if the mapped slice is any other
   size, whatever the reason.
3. `DEFERRED_PREFIXES` names, file by file, which cases are deliberately out of
   G1. A new corpus case in a G1 file that is neither mapped nor listed raises.
4. The case list is re-derived from the rendered fixture (`parse_fixture_ids`),
   so the accounting does not trust the mapping that produced it.

Exit codes are 0 clean, 1 for a failed or missing case, 2 for a corpus or
mapping error. `scripts/gate-g1.ps1` treats any non-zero as a gate failure and
refuses to print `G1: PASS`.

---

## 5. Determinism

The kernel reads no clock, no environment and no file. The runner reads exactly
one file — its fixture — and writes only stdout. The wrapper writes the fixture
to a temporary file and removes it. Nothing in the path depends on hash-map
iteration order: produced values are compared by key, and the fixture order is
the corpus order.

The corpus is pinned by `source_commit`, which the wrapper echoes in its summary
line, so a replay is always attributable to the Rust commit that produced the
expected values. The G1 slice uses 28 of the corpus's 117 cases; the other 89
are unchanged and still verified by `run_vectors.py` on every gate run.

What is not proved: that a second compiler or host produces the same bytes. The
kernel has no floating point and no locale-dependent formatting, so the
mechanisms that usually break cross-host determinism are absent by construction
— but absent by construction is an argument, not a measurement, and §8 records
the missing run.

---

## 6. Evidence that the gate bites

A gate that cannot fail is worse than no gate, so three faults were injected
from scratch scripts outside the repository. The control in every case is the
same command on an untouched copy.

| Fault | Injection | Observed |
|---|---|---|
| Type confusion | a temporary TU containing `zk::DisplayHex256 d = internal;` | `error: conversion from 'const zk::Hex256' to non-scalar type 'zk::DisplayHex256' requested`, exit 1; the control TU, which goes through `internal.bytes()`, exits 0 |
| Value tampering | first nibble of `hash.sha256.abc`'s `sha256_hex` flipped | `g1 conformance: FAIL (1 failed, 0 missing)` naming the case and both values, exit 1; the control copy exits 0 |
| Slice shrink | `difficulty.compact.1d800000` removed, with `case_count` and the manifest entry decremented to stay consistent | `g1 conformance: corpus mapping failed: G1 covers 27 cases, expected 28`, exit 2 |

The third injection is the interesting one: every structural check the corpus
itself can make still passed, so only the G1 count guard stood between a silent
loss of one case and a green run.

The unit suite also bit four times while P1 was being written, always in C++
test code rather than in the reference:

- a hand-written `sha256d` display literal was character-reversed instead of
  byte-reversed — exactly the F3 error the type system exists to prevent, caught
  because the literal was transcribed independently;
- `0x2100ffff` was assumed to be the proof-of-work limit; `params.rs` pins
  `0x1e00ffff`, and the test now asserts the ordering of all three;
- `"01000000"` followed by 64 zero bytes was assumed to be a truncated
  transaction; it parses as version, zero inputs, zero outputs and a lock time,
  so the truncation fixture had to end inside a count instead;
- `ff00000000ffffffff` was assumed to be a non-minimal varint; it decodes to
  `0xffffffff00000000`, which is minimal, and the test now uses a genuinely
  non-minimal encoding.

None of those was a reference defect. They are the failure mode the corpus is
for: a plausible value that only an independent oracle rejects.

---

## 7. Coverage: what G1 does not cover

89 of the corpus's 117 cases are outside this phase. Their owners:

| Group | Cases | Rust owner | Phase / gate that owns it |
|---|---|---|---|
| `ledger.script` | 15 | `ledger/script.rs` | P2 / G2 |
| `ledger.sighash` | 8 | `ledger/sighash.rs` | P2 / G2 |
| `ledger.state_root` | 13 | `ledger/utxo.rs` | P3–P4 / G3 state-root probe, G4 replay |
| `chain.header` | 8 | `consensus/block.rs` | P3 / G3 |
| `chain.anchors` | 6 | `genesis.rs`, `consensus/immutability.rs` | P3 / G3 |
| `pow` | 11 | `consensus/pow.rs` | P3 / G3 |
| `difficulty` policy | 6 | `consensus/difficulty.rs` | P3 / G3 |
| `reward.subsidy` | 6 | `consensus/reward.rs` | P3 / G3 |
| `reward.coinbase` | 10 | `consensus/reward.rs` | P3 / G3 (`committed_height`) |
| `crypto.address` | 6 | `address.rs` | no gate names it yet |

The last row is worth stating plainly: `05` §7's G2 covers scripts, sighash and
signatures, and G3 covers the pinned constants and headers, but no gate is
written around address encoding. Either the G2 wording grows a clause or the
address cases stay as corpus-only evidence. That decision is not P1's to take,
and it is not taken by omission here.

Two further limits:

- **The error taxonomy is still corpus-incomplete.** `06` §7 measured 31 of 81
  error variants covered; G1 pins only `NonMinimalVarInt` among the five
  `TxDecodeError` rejections, while the unit suite exercises all five. Turning
  those unit cases into corpus vectors belongs to whoever closes `06` §11 item 1.
- **F16 is still open.** The reference folds the sighash type into the preimage
  and accepts any `u32`, so `SIGHASH_ALL` is a convention rather than a checked
  rule. No C++ code touches sighash yet; the finding must be recorded before P2
  writes any.

---

## 8. Executed tests, and what was not run

| Check | Command | Observed | Executed |
|---|---|---|---|
| Gate G1, end to end | `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\gate-g1.ps1` | `G1: PASS`, exit 0 | yes |
| Unit tests | `.build\kernel-g1\kernel_tests.exe` | `kernel unit tests: 82 run, 0 failed` | yes |
| CTest registration | `ctest --test-dir .build\kernel-g1 --output-on-failure` | `100% tests passed, 0 tests failed out of 2`, 0.25 s | yes |
| Corpus replay | `python kernel\tools\g1_conformance.py --vectors test\vectors --runner .build\kernel-g1\kernel_conformance.exe` | 28/28 against `7cb9017c…` | yes |
| Rust suite | `cargo +stable-x86_64-pc-windows-gnu test --all-targets --manifest-path zerocoin\Cargo.toml` | 263 passed, 0 failed, 7 targets | yes |
| P0 verifier | `python test\harness\run_vectors.py --quiet` | `PASS 112 ANCHOR 5 SKIP 0 FAIL 0` | yes |
| Fault injection | scratch scripts, §6 | 3/3 detected | yes |
| MSVC / `cl.exe` build | — | not attempted | **no** |
| Second host or compiler | — | not attempted | **no** |
| ASan / UBSan | — | not run; MinGW ASan support is weak on this machine | **no** |
| Big-endian host | — | no such host available | **no** |
| Constant-time behaviour | — | not attempted; nothing in G1 handles secrets | **no** |

The Rust suite still reports the 235 tests `README.md` §2 records, plus the 20,
2 and 6 tests that the P1 consensus-integration targets added; the three binary
targets report zero. That is the whole of `--all-targets` on this machine.

---

## 9. Reproduction

From the repository root (`upstream\`), with the crate in `zerocoin\`:

```powershell
# The whole gate: configure, build, ctest, unit, replay, Rust suite, P0 harness
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\gate-g1.ps1

# The C++ half only, step by step
cmake -S kernel -B .build\kernel-g1 -G Ninja
cmake --build .build\kernel-g1
ctest --test-dir .build\kernel-g1 --output-on-failure
.build\kernel-g1\kernel_tests.exe
python kernel\tools\g1_conformance.py --vectors test\vectors `
    --runner .build\kernel-g1\kernel_conformance.exe
```

The default build directory is `.build\kernel-g1` inside the repository; §6 of
`.gitignore` keeps it out of history, and `-BuildDir` moves it elsewhere. The
gate runs `cargo` with `--manifest-path zerocoin\Cargo.toml` because the crate
is not at the repository root — the same trap `06` §9 records for the corpus
test.

---

## 10. Constraints honoured

- **No Rust implementation change.** `git status --short` after the phase shows
  `M .gitignore`, `?? kernel/`, `?? scripts/` — nothing under `zerocoin/src`,
  `zerocoin/tests` or `test/vectors`.
- **Nothing is shipped.** `kernel/` is a developer and CI artefact; the CMake
  project is not referenced by `Cargo.toml`, `build.rs` or any binary target.
- **No consensus change.** The kernel reproduces the reference; the corpus is
  the arbiter, and where the reference looks odd (F-2 trailing bytes) the
  oddity is pinned, not fixed.
- **No new dependency.** No OpenSSL, no Boost, no secp256k1, no package manager.
- **No secrets.** The kernel holds no key material; the tests use published
  digests and the corpus's own values.

---

## 11. Open items

| # | Item | Why it matters |
|---|---|---|
| 1 | Build under MSVC and on a second host | every G1 number comes from one compiler |
| 2 | Run ASan/UBSan somewhere with support | the decoder is the first code that will see hostile bytes |
| 3 | Record F16 before P2 writes sighash | `06` §11 item 3; the convention is not a checked rule |
| 4 | Promote the `TxDecodeError` unit cases into corpus vectors | closes part of the `06` §7 gap with evidence, not prose |
| 5 | Decide the P2 fixture shape | `g1_conformance.py` is phase-specific by name and count; P2 must either add a phase argument or a second wrapper, and the count guard must not be weakened to allow it |
| 6 | Wire the gate into CI | the repository still has no CI (`README.md` §2) |

Item 5 is a design decision P2 inherits rather than a defect: the wrapper's
refusal to accept a different case count is a feature, and a P2 wrapper should
repeat it at its own count instead of relaxing this one.

---

## 12. What P2 inherits

- A build, CTest and gate skeleton that fails on a warning, a failed case or a
  changed slice, and prints the measured numbers it used.
- The byte-order types, proved by `static_assert` and by an injection that
  several C++ compilers would otherwise accept.
- A fixture protocol that grows one operation per behaviour, and a mapping guard
  that refuses an unclassified case.
- A measured baseline: 82 unit tests, 28 corpus cases, 57 compile-time
  assertions, 3,563 lines of kernel.
- The list of what is still deferred, with the Rust file that owns each group.
- One honest weakness in the evidence: every number in §1 is single-compiler.
