# 08 — P2: script, sighash and secp256k1 compatibility

> Evidence labels follow `README.md` §1. The gate below was run on 2026-10-18
> against `main` = `6a6ddc2ad308fa71ea9058d60c81b678edecb0e3`, the commit these
> changes sit on top of, on Windows 24H2 with GNU 16.2.0 (MinGW-W64 UCRT),
> CMake 4.4.3, Ninja 1.13.2, Python 3.15.0 and `cargo` 1.99.1. The Rust
> toolchain is named `+stable-x86_64-pc-windows-gnu` for the reason given in
> `README.md` §2.

P2 (`03` §4) ports the two consensus components that decide whether a spend is
authorized: the script interpreter and the signature hasher. It adds the
`SigVerifier` seam through which a curve backend will later be plugged in, but
it does **not** link a curve backend. Two corpus cases need secp256k1 and are
deferred by name; gate G2 is therefore **not met** in this phase.

No Rust source file, no corpus vector and no G1 guard was modified.

---

## 1. Result

| Item | Result | Evidence |
|---|---|---|
| P2 corpus cases replayed | 21/21, 0 failed, 0 missing | `p2_conformance.py` `[VERIFIED]` |
| — `ledger.script` | 14 of 15 | §5.2 `[VERIFIED]` |
| — `ledger.sighash` | 7 of 8 | §5.2 `[VERIFIED]` |
| Deferred, named | 2 — `p2pkh_spend_accepted`, `signature_der` | §2, §5.3 `[VERIFIED]` |
| Kernel unit tests | 108 run, 0 failed | `kernel_tests` `[VERIFIED]` |
| — new in P2 | 26 (13 script, 13 sighash) | §7 `[VERIFIED]` |
| CTest registration | 3/3 passed — G1, P2, unit | `ctest` `[VERIFIED]` |
| Corruption self-check | 21/21 rejected, runner exit 1 | `p2_conformance.py` `[VERIFIED]` |
| Build | clean under `-Wall -Wextra -Wpedantic -Werror`, C++20 | gate output `[VERIFIED]` |
| G1 gate | PASS — 28/28 corpus cases, unchanged | `scripts/gate-g1.ps1` `[VERIFIED]` |
| Rust suite | 263 passed, 0 failed across 7 targets | `cargo test --all-targets` `[VERIFIED]` |
| P0 verifier | `PASS 112 ANCHOR 5 SKIP 0 FAIL 0` | `run_vectors.py --quiet` `[VERIFIED]` |
| Rust sources changed | none | phase diff `[VERIFIED]` |
| Corpus changed | none — `test/vectors/` is read-only to this phase | phase diff `[VERIFIED]` |
| Custom cryptography | none — the kernel links no crypto library at all | §6 `[VERIFIED]` |
| Signature verification in C++ | **absent** — fail-closed, G2c open | §8.1 `[VERIFIED]` |
| MSVC build, second compiler, fuzzing | not attempted | `[UNVERIFIED]` |

Gate G2 (`03` §4) requires identical script and sighash behaviour **and** real
secp256k1 verification. The first two hold; the third does not exist yet, so
this document reports G2 as not met. It does not claim otherwise anywhere.

---

## 2. Scope and exclusions

**In scope, implemented:**

* the ten-opcode interpreter (`OP_0`, direct pushes, `OP_PUSHDATA1`,
  `OP_PUSHDATA2`, `OP_DROP`, `OP_DUP`, `OP_HASH160`, `OP_EQUAL`,
  `OP_EQUALVERIFY`, `OP_CHECKSIG`) with its four limits;
* the two P2PKH script builders and the minimal push encoder;
* `signature_hash`: the domain tag, the chain id, the legacy scriptSig
  blanking rule, the output section, the type suffix and `sha256d`;
* `TxSigChecker`, which enforces `SIGHASH_ALL` and gate ordering;
* the exported `SigChecker` (script side) and `SigVerifier` (sighash side)
  seams, so a curve backend can be added without touching either component;
* a P2 conformance wrapper, six new runner operations and the fixtures they
  generate.

**Explicitly out of scope, and why:**

| Excluded | Reason |
|---|---|
| secp256k1 point parsing, DER parsing, ECDSA verification | No vetted curve library is available on this host, and the brief forbids custom cryptography. Deferred as G2c (`03` §4). |
| `ledger.script.p2pkh_spend_accepted` | Needs a real signature check *and* carries the schema quirk in F19. |
| `ledger.sighash.signature_der` | Needs RFC 6979 deterministic ECDSA to reproduce the DER bytes. |
| ECDSA signing, key generation, wallet keys | P3/P4 concern; no private key material appears in this phase. |
| P2SH, multisig, timelocks, `OP_RETURN`, `OP_NOP*` | The reference implements none of them (F5). Adding them would be a consensus change. |
| `lock_time` enforcement | The reference signs but never enforces it (F4). |
| Any sighash type other than `SIGHASH_ALL` at the checker | The reference rejects them there (F18). |
| Rust or corpus edits | Forbidden by the brief and by the G1 guard. |

---

## 3. Rust source references

All paths are relative to the published crate `zerocoin/`.

| Reference | Lines | What it pins | C++ counterpart |
|---|---|---|---|
| `src/ledger/script.rs` | 18–27 | the ten opcode constants | `script.h` `kOp*` |
| | 30–33 | `MAX_STACK_ITEMS` 1000, `MAX_SCRIPT_ELEMENT` 520, `MAX_OPS_PER_SCRIPT` 201, `MAX_SCRIPT_SIZE` 10 000 | `script.h` `kMax*` |
| | 37–41 | `SigChecker` trait: `(signature, public_key) -> bool` | `zk::SigChecker` |
| | 44–65 | `ScriptError` variants and their ordering | `zk::ScriptError` |
| | 69–81 | `verify`: scriptSig, then scriptPubKey, one stack, require true on top | `zk::verify` |
| | 83–170 | `run_script`: size check, op budget, dispatch, per-op limits | `run_script` |
| | 172–204 | `push`, `pop`, `read_u8`, `read_push` (failure ordering) | same names |
| | 206–222 | truthiness including negative zero | `is_true` |
| | 226–242 | `p2pkh_script_pubkey`, `p2pkh_script_sig` | same names |
| | 245–258 | `push_data`: inline < 0x4c, PUSHDATA1 ≤ 0xff, else PUSHDATA2 LE | `push_data` |
| `src/ledger/sighash.rs` | 20 | `SIGHASH_ALL = 0x01` | `kSigHashAll` |
| | 23 | `SIGHASH_TAG = b"ZRO/sighash/v1\0"` — **15 bytes** | `kSigHashTag` |
| | 26–27 | `ChainId(pub u32)` | `zk::ChainId` |
| | 45–86 | `signature_hash`: preimage layout, out-of-range `None`, type folded as `u32` LE | `zk::signature_hash` |
| | 90–140 | `TxSigChecker::check_signature`: trailing byte, `SIGHASH_ALL`, DER, SEC1, digest, verify | `TxSigChecker` |
| `src/crypto/secp256k1.rs` | 23 | `COMPRESSED_PUBKEY_LEN = 33` | not ported (G2c) |
| | 112–121 | `from_sec1`: length must be 33, point must be valid | not ported |
| | 137–143 | `verify`: `verify_prehash` over the 32-byte digest | `SigVerifier::verify` |
| | 176–182 | `from_der`: strict DER parse before storage | not ported |

The crate manifest declares `license = "MIT"`; the curve dependency is
`k256 0.13` with the `ecdsa`, `arithmetic`, `ecdh`, `sha256`, `pkcs8` and `pem`
features (`zerocoin/Cargo.toml` lines 44–46).

### 3.1 Differences found during the audit

No behavioural divergence was found. Three non-behavioural differences are
recorded so a later reader does not mistake them for drift:

1. **Checker gate order.** Rust parses the trailing sighash byte, then DER,
   then the public key, then computes the digest, then verifies. C++ checks the
   trailing byte, the type, the digest range, then delegates to the verifier,
   which is where DER and SEC1 parsing will happen. Every path returns `false`
   for the same inputs; only the short-circuit order differs, and the C++
   ordering is the one that fails closed when `verifier_ == nullptr`.
2. **Error payload.** Rust's `ScriptError::UnsupportedOpcode(u8)` carries the
   opcode; the C++ `ScriptResult` carries `error` plus `opcode` for every
   failure. Accepted/rejected and the error name are identical.
3. **Unused parameter.** Rust's `run_script` takes `_count_ops_flag`, which no
   caller uses and the body ignores. The C++ port omits it.

---

## 4. Semantics pinned by the port

### 4.1 Limits and their check order

`ScriptTooLarge` is tested once against each script before execution. The op
budget is counted **per script**, resets between scriptSig and scriptPubKey,
and only counts opcodes strictly greater than `0x4d` — direct pushes,
`OP_PUSHDATA1` and `OP_PUSHDATA2` are free, exactly as in the reference.
`ElementTooLarge` is tested on every `push` before `StackOverflow`, so a
1000-item stack plus a 521-byte element reports `ElementTooLarge`.

### 4.2 Push encoding

`push_data` is minimal: length < `0x4c` inline, ≤ `0xff` with `OP_PUSHDATA1`,
otherwise `OP_PUSHDATA2` little-endian. Above `0xffff` the length is masked and
the full payload still follows — a latent inconsistency reproduced from the
reference and registered as F20. No current caller reaches it.

### 4.3 Truthiness

Empty is false; all-zero bytes are false; a final `0x80` with every other byte
zero is negative zero and false; anything else is true. This governs
`OP_VERIFY`, the final stack test and therefore `EvalFalse`.

### 4.4 Composition and error precedence

`verify` runs scriptSig then scriptPubKey on one stack and requires the top
item to be true. `OP_DUP` on an empty stack is `StackUnderflow`; `OP_DUP` on a
full stack is `StackOverflow` (the push limit wins). `OP_EQUAL` and
`OP_EQUALVERIFY` pop `b` then `a`; equal pushes `{01}`, unequal pushes `{}` for
`OP_EQUAL` and returns `EqualVerifyFailed` for `OP_EQUALVERIFY`. `OP_CHECKSIG`
pops the public key first, then the signature, and pushes `{}` when the checker
returns false — so a failed signature surfaces as `EvalFalse` at the end, not
as a distinct error. The corpus `reject_*` vectors pin each of these names.

### 4.5 Sighash preimage

For the shared 111-byte corpus transaction the preimage is 159 bytes:

```
tag(15) ‖ chain_id LE u32 ‖ version LE u32 ‖ varint(inputs)
  per input: txid(32, internal order) ‖ vout LE u32 ‖ varint(script)
             ‖ script (script_code only for the signed index, else empty)
             ‖ sequence LE u32
varint(outputs)
  per output: value LE u64 ‖ varint(len) ‖ script
lock_time LE u32 ‖ sighash_type LE u32
```

The tag is **15** bytes, `5a524f2f736967686173682f763100`. The sighash type is
the last **four** bytes, so for type `0x01` the final byte is `0x00`; the
fifteen-byte assertion in the header is what keeps this from regressing.

### 4.6 Type folding and the checker

`signature_hash` folds any `u32` type into the digest and returns a digest for
every in-range index (F18). Only `TxSigChecker` enforces `SIGHASH_ALL`, by
reading the signature's trailing byte. The corpus proves the distinction:
`ledger.sighash.type_02_is_folded_in` produces a digest for type 2, while a
type-2 *signature* is rejected by the checker.

### 4.7 Fail-closed default

`TxSigChecker` returns false when the signature is null or empty, when the type
is not `0x01`, when the input index is out of range, and when no verifier is
attached. The last rule is what makes P2 safe without a curve: a valid P2PKH
spend is *rejected*, never accepted by accident.

---

## 5. Fixtures and provenance

### 5.1 Format

`p2_conformance.py` generates, and the runner consumes, the same line format as
G1 with a distinct schema marker:

```
META schema=zro-p2-fixture/1
META source_commit=<manifest source_commit>
META cases=21
CASE ledger.script.p2pkh_script_pubkey
OP p2pkh_script_pubkey
IN pubkey_hash_hex=751e…3bd6
OUT length=25
OUT script_hex=76a914…88ac
END
```

The runner prints `RESULT <id> ok|fail <detail>` per case, then
`SUMMARY cases=<n> failures=<n>`, and exits 0, 1 or 2. It is the same binary as
G1; P2 added six operations to it and changed none of the existing nine.

### 5.2 Mapping

| Corpus case(s) | Runner op | Expected keys |
|---|---|---|
| `ledger.script.push_data.lengths` | `script_push_data` | `len_0, len_1, len_75, len_76, len_255, len_256, len_520` |
| `ledger.script.p2pkh_script_pubkey` | `p2pkh_script_pubkey` | `length`, `script_hex` |
| `ledger.script.p2pkh_script_sig` | `p2pkh_script_sig` | `length`, `script_hex` |
| eleven `ledger.script.reject_*` | `script_verify` (`checker=accept`) | `accepted=false`, `error=<error_kind>` |
| five digest cases | `sighash` | `digest`, `digest_display_hex`, `preimage_hex` |
| `ledger.sighash.out_of_range_index` | `sighash` | `digest=null` |
| `ledger.sighash.digest_stability` | `sighash_distinct` | three booleans, all `false` |

The five digest cases are `regtest_index_0`, `regtest_index_1`,
`mainnet_chain_binding`, `type_02_is_folded_in` and `regtest_index_repeat`.

### 5.3 Deferral guard

`DEFERRED_CASES` names exactly two cases with the reason (`G2c`, no curve
backend). `build_cases` fails with exit 2 if a deferred case is also mapped, if
a named case disappears from the corpus, or if the total is not 21. The slice
therefore cannot shrink silently, which is the same property the G1 guard has.

### 5.4 Independent provenance

The wrapper never trusts the kernel to grade itself. Before rendering a fixture
it re-derives, from the documented rules alone:

| Check | Method |
|---|---|
| push encoding | recompute `minimal_push(b"\xab" * n)` for all seven lengths |
| P2PKH locking script | assert `76 a9 14 <20> 88 ac` and the length |
| P2PKH unlocking script | assert `push(sig) ‖ push(pubkey)` and the length |
| sighash display order | assert `display == reverse(internal)` |
| sighash framing | assert the tag + chain prefix and the type suffix |
| sighash digest | `hashlib.sha256(sha256(preimage)) == internal` |
| shared inputs | all digest siblings share one `tx_hex` and one `script_code_hex` |
| input count | a real varint decode of the shared tx equals `out_of_range.input_count` |
| file counts | `cases == case_count` in each file and in `manifest.json` |

These are independent of both the Rust reference and the C++ kernel: they
recompute from the primitives with Python's own `hashlib`.

### 5.5 Corruption self-check

After a clean replay the wrapper mutates **every** expected value — booleans
flipped, `null` → `nullx`, integers incremented, hex first nibble changed, any
other string suffixed — and requires the runner to exit 1 with
`SUMMARY cases=21 failures=21` and no `ok` result. It does. This proves the
comparison step, not the fixture parser, is what accepts or rejects a value.

---

## 6. Cryptographic dependency and licensing

**C++ adds no dependency.** `libzerocoin_kernel` links no third-party library
and contains no elliptic-curve code; it exposes two abstract seams only:

```cpp
struct SigChecker { virtual bool check_signature(const uint8_t*, size_t,
                                                 const uint8_t*, size_t) const; };
struct SigVerifier { virtual bool verify(const Hash256& digest, const uint8_t* sig,
                                         size_t sig_size, const uint8_t* pubkey,
                                         size_t pubkey_size) const; };
```

**Rust uses `k256 0.13`** (RustCrypto), dual-licensed Apache-2.0 OR MIT, and
the crate itself is MIT. `k256` delegates to the `ecdsa` and `elliptic-curve`
crates; nothing in `secp256k1.rs` re-implements field or scalar arithmetic.

**Why no backend was chosen in P2.** No vetted secp256k1 library is installed
on this host (no libsecp256k1, no OpenSSL), and the brief forbids custom
cryptography. Adding a dependency without a vendor review would satisfy the
letter of "use a library" while violating the review requirement. The decision
is therefore deferred as G2c, and the seam is what keeps the deferral honest.

**Constraints for whichever backend G2c selects** — all derived from the
reference, and all testable without changing this phase:

* public keys are **33-byte compressed SEC1 only**; longer or uncompressed
  encodings are rejected (`secp256k1.rs` 112–121);
* signatures are **strict DER** with no trailing bytes inside the DER portion
  (`176–182`); the trailing sighash byte is stripped by the checker, not the
  parser;
* verification is over the **32-byte digest** with no re-hashing (`137–143`);
* **the reference rejects high-S**, one layer below `secp256k1.rs`:
  `k256-0.13.4/src/ecdsa.rs:201-208` returns an error when `s > n/2`. This
  bullet originally claimed that no low-S rule existed anywhere; that was wrong.
  A backend must return `false` for high-S and must not normalise it
  (`CRYPTO_BACKEND_READINESS.md` §2 H1);
* malformed DER, malformed points and non-`SIGHASH_ALL` types must return
  `false`, never throw across the C boundary.

**No secret material** appears in this phase: fixtures and tests contain only
the generator point (public), its HASH160, a public signature and public
scripts. No scalar, seed, keystore or wallet file is read, written or logged.

---

## 7. Tests

### 7.1 Kernel unit tests — 26 new

`kernel/tests/test_script.cpp` (13): corpus P2PKH pubkey and sig scripts, the
minimal-prefix boundaries, a valid spend under an accepting checker, a
rejecting checker, a wrong pubkey hash, the seven non-limit reject vectors, each
of the four limits at and one past its boundary (which covers the remaining
four corpus rejects), negative-zero truthiness, and the stability of every
error name.

`kernel/tests/test_sighash.cpp` (13): the four distinct corpus preimages and
digests byte for byte (`regtest_index_repeat` duplicates index 0 and is covered
by the conformance replay), `nullopt` for an out-of-range index, the preimage
layout (tag/chain/version, type at `size-4`), blanked scriptSigs, domain
separation by chain/index/type, and the checker gate matrix — accept, wrong type
before the backend, empty signature, missing backend, out-of-range index,
rejecting backend — plus an end-to-end spend where `OP_CHECKSIG` reaches the
backend exactly once with 71 DER bytes.

The suite total is 108, so P2 added 26 tests and changed none of the 82 that
existed at G1.

### 7.2 Conformance — 21 cases plus corruption

The wrapper is registered as CTest `kernel_p2_conformance` with the same
arguments the gate uses. It is a separate test from `kernel_conformance`; the
G1 wrapper, its expected count (28) and its deferred prefixes are untouched.

---

## 8. Limitations and remaining gaps

### 8.1 G2c — no curve backend

The C++ kernel cannot verify a signature. A valid P2PKH spend fails closed at
`TxSigChecker`, and the runner uses accept/reject stubs **only** to exercise
interpreter control flow. Those stubs live in `kernel/conformance/main.cpp`,
not in the library, and must never be linked into a node.

### 8.2 Two corpus cases unreplayed

`ledger.script.p2pkh_spend_accepted` and `ledger.sighash.signature_der` are
deferred by name in the wrapper and counted. The first also carries F19 (its
`expected.txid` is a bare internal-order string, unlike every other corpus
`txid` object). Neither is silently dropped: an unexpected corpus change makes
the wrapper exit 2.

### 8.3 Inherited behaviour that is *not* Bitcoin

`signature_hash` accepts any `u32` type (F18); `lock_time` is signed but never
enforced (F4); `OP_CHECKSIG` failure is reported as `EvalFalse` at the end;
`push_data` masks lengths above `0xffff` (F20). Each is reproduced on purpose.
A future "cleanup" of any of them is a consensus change and needs its own
phase and vectors.

### 8.4 Untested surface

No MSVC build, no second compiler, no differential fuzzing against the Rust
interpreter, and no test of `scriptSig`/`scriptPubKey` combinations beyond the
corpus and the unit matrix. The interpreter is small enough to audit, but it
has not been fuzzed.

### 8.5 Performance

The interpreter allocates a `vector` per stack item and copies pushes. That is
irrelevant at current block sizes and is not measured. It is recorded so no one
mistakes the absence of a benchmark for a performance claim.

---

## 9. Changed files

| Path | Lines | Change |
|---|---|---|
| `kernel/include/zerocoin/script.h` | 131 | new — opcodes, limits, errors, `SigChecker`, builders |
| `kernel/include/zerocoin/sighash.h` | 122 | new — tag, `ChainId`, `SigHash`, `SigVerifier`, `TxSigChecker` |
| `kernel/src/script.cpp` | 327 | new — interpreter |
| `kernel/src/sighash.cpp` | 115 | new — preimage and checker |
| `kernel/tests/test_script.cpp` | 277 | new — 13 tests |
| `kernel/tests/test_sighash.cpp` | 317 | new — 13 tests |
| `kernel/conformance/main.cpp` | 599 | +6 ops, +2 helpers (`parse_u32`, `tx_of`) |
| `kernel/tools/p2_conformance.py` | 583 | new — mapper, provenance guards, corruption check |
| `kernel/CMakeLists.txt` | 84 | +2 sources, +2 test sources, +1 CTest entry |
| `docs/migration/01-architecture-audit.md` | +2 rows | F19, F20 |
| `docs/migration/08-kernel-script-sighash-secp256k1-p2.md` | this file | new |

`kernel/tools/g1_conformance.py`, `scripts/gate-g1.ps1`, `test/vectors/**` and
all Rust sources are unchanged.

---

## 10. Reproduction

From the repository root, PowerShell 5.1:

```powershell
# the whole gate, including the new P2 CTest entry
powershell -ExecutionPolicy Bypass -File scripts\gate-g1.ps1

# P2 alone, with its provenance guards and corruption check
python kernel\tools\p2_conformance.py `
  --vectors test\vectors `
  --runner .build\kernel-g1\kernel_conformance.exe

# the registered tests
ctest --test-dir .build\kernel-g1 --output-on-failure
```

Observed on 2026-10-18 against `6a6ddc2`:

```
p2 conformance: 21/21 cases replayed against source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c
  ledger.script          14
  ledger.sighash         7
  deferred (G2c)         2: ledger.script.p2pkh_spend_accepted, ledger.sighash.signature_der
p2 conformance: corruption self-check rejected 21/21 cases
```

```
1/3 Test #1: kernel_unit ......................   Passed
2/3 Test #2: kernel_conformance ...............   Passed
3/3 Test #3: kernel_p2_conformance ............   Passed
100% tests passed out of 3
```

```
kernel unit tests: 108 run, 0 failed
g1 conformance: 28/28 cases replayed against source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c
G1: PASS
  rust suite             263 passed, 0 failed across 7 targets
  p0 corpus verifier     clean
```

Exit code 0 is the verdict. `SUMMARY cases=21 failures=21` under corruption is
the proof that the 21/21 above is a comparison, not a fixture that always
passes.
