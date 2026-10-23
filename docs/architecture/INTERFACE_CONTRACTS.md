# Interface contracts

Status: **as-built** at commit `e8fda7e` (2026-10-18), written during P2.1.
Defines the interfaces that cross an ownership boundary, the guarantees each one
makes, and the conditions under which a temporary compatibility surface may be
removed. No code changes.

Related: `COMPONENT_OWNERSHIP.md` (who owns each side),
`THREE_LANGUAGE_ARCHITECTURE.md` (which language may implement what),
`MIGRATION_ROADMAP.md` §5 (the removal register).

---

## 1. Contract classes

Every interface in this repository belongs to exactly one class. The class
determines how disagreement is resolved.

| Class | Surface | Requirement | On disagreement |
|---|---|---|---|
| **C0 — consensus bytes** | Hashes, transactions, headers, sighash preimages, state root, scripts | Byte equality | The derived implementation is wrong; the Rust output is the oracle |
| **C1 — protocol acceptance** | Handshake, frames, JSON messages | The Rust peer must accept it; field order is irrelevant | The sender is wrong |
| **C2 — kernel API** | C++ headers in `kernel/include/zerocoin/` | Compiles and behaves as specified here | The header contract wins; a change is a contract change |
| **C3 — operator surface** | RPC methods, CLI output | Same field names and units as the Rust node | The Rust node is the reference |
| **C4 — test interface** | Corpus JSON, conformance fixture text, wrapper output | The wrappers must be able to prove a failure | A wrapper that cannot fail is a defect |

A change that moves a value from one class to another (for example, exposing a
consensus digest in an RPC field) must say so explicitly.

---

## 2. C++ kernel API conventions

These rules apply to every header under `kernel/include/zerocoin/`.

1. **Namespace `zk`.** Functions are `lower_snake_case`, types are `CamelCase`,
   constants are `kCamelCase`.
2. **No exceptions cross the API.** Functions are `noexcept` where the signature
   allows it; failures are `ScriptResult`, `std::optional`, or `bool`.
3. **Pointer plus size, never a container.** A caller owns its buffers; the
   kernel does not retain a pointer past the call unless the class documents it
   (`TxSigChecker` retains `script_code`, and says so).
4. **No allocation in a validation decision** beyond the types returned
   (`std::vector` in builders and `SigHash::preimage` are intentional).
5. **Constants are `inline constexpr` and frozen by `static_assert`.** A change
   to a limit is a consensus change and cannot be a local edit.
6. **Warnings are errors** for every target, tests included
   (`kernel/CMakeLists.txt` lines 34–41).
7. **One approved dependency.** `zerocoin_kernel` links exactly one third-party
   library: the pinned vendored libsecp256k1 v0.8.0 release
   (`kernel/third_party/secp256k1/`), the curve backend approved by
   `CRYPTO_BACKEND_DECISION.md` and integrated in P2.10 §7 behind
   `zk::SigVerifier` (PRIVATE link, verification only). Any further dependency
   requires a new decision record.

---

## 3. Signature verification contract

This is the seam that G2c gated. It is the only place where the kernel touches
elliptic-curve verification. Since P2.10 it has exactly one approved
implementation (§3.5); the interface itself is unchanged, and any further
backend must implement the same methods under the same obligations.

### 3.1 The two interfaces

```cpp
// script.h — called by OP_CHECKSIG.
// `signature` is DER followed by exactly one sighash byte; `public_key` is
// compressed SEC1 (33 bytes).
class SigChecker {
 public:
  virtual ~SigChecker() = default;
  virtual bool check_signature(const std::uint8_t* signature, std::size_t signature_size,
                               const std::uint8_t* public_key,
                               std::size_t public_key_size) const = 0;
};

// sighash.h — the curve backend.
// `der` excludes the trailing sighash byte; `public_key` is compressed SEC1.
// Return true only if both parse and the signature is valid over `digest`.
class SigVerifier {
 public:
  virtual ~SigVerifier() = default;
  virtual bool verify(const Hash256& digest, const std::uint8_t* der, std::size_t der_size,
                      const std::uint8_t* public_key,
                      std::size_t public_key_size) const = 0;
};
```

### 3.2 What `TxSigChecker` guarantees before the backend is called

Order matters and is part of the contract (`kernel/src/sighash.cpp` 90–113):

1. A null pointer or empty signature returns `false`.
2. The **last byte** is the sighash type; anything other than `0x01`
   (`SIGHASH_ALL`) returns `false` without computing a digest.
3. `signature_hash` is called for the bound input index; an out-of-range index
   returns no digest and therefore `false`.
4. A null `SigVerifier` returns `false` — **fail closed**.
5. Otherwise the backend receives the digest, the DER bytes (`size - 1`), and the
   untouched public-key bytes.

The checker never parses DER itself, never re-hashes, and never inspects the
public key. Those are the backend's obligations.

### 3.3 Obligations for any backend

| # | Obligation | Source of the rule |
|---|---|---|
| B1 | Accept **only 33-byte compressed SEC1** public keys, i.e. the leading tag is `0x02` or `0x03`; reject every other tag — `0x05` (SEC1 *compact*), `0x04` (uncompressed), `0x06`/`0x07` (hybrid), `0x00`, `0x01` and the rest — along with wrong lengths, off-curve `x`, and the point at infinity | `src/crypto/secp256k1.rs` 117–132; `CONSENSUS_RULES.md` §8.4.1 rule P-1 |
| B2 | Parse **strict DER** for the signature; reject non-minimal integers, negative values, zero `r`/`s`, out-of-range `r`/`s`, bad lengths and trailing bytes inside the DER portion | `src/crypto/secp256k1.rs` 187–193 |
| B3 | Verify over the **32-byte digest as given**; no hashing, no truncation, no padding | `src/crypto/secp256k1.rs` 148–154 |
| B4 | **Reproduce the reference's high-S rejection; do not normalise.** `k256` rejects `s > n/2` inside `verify_prehashed`; the wrapper must return `false` for the same inputs and must not rewrite `s` | `k256-0.13.4/src/ecdsa.rs:201-208`; `CRYPTO_BACKEND_READINESS.md` §2 H1 |
| B5 | Return `false` for every malformed input; never throw across the C++ boundary | C2 convention 2 |
| B6 | Be re-entrant and thread-safe for concurrent verification with a shared immutable context | P5 node threads |
| B7 | Never log, copy or retain key material; the inputs are public | doc `08` §6 |

B4 has a concrete consequence for the most likely candidate: libsecp256k1's
`secp256k1_ecdsa_verify` returns 0 for a high-S signature by design, and the
reference does the same. A wrapper that calls it directly therefore matches. A
wrapper that normalises a copy before the call would **not** match: it would
accept transactions the Rust node rejects. No normalisation step exists, and none
may be added (`CRYPTO_BACKEND_DECISION.md` §7.3).

B1 is a **tag-set** rule, not only a length rule. `0x02` and `0x03` are the whole of
the *compressed* encoding space; `0x05` is SEC1 *compact*, which names the same
curve point as `0x02 || x` with an even `y`. Admitting both would give one point
two key hashes, because the P2PKH commitment is `hash160` over the 33 bytes and not
over the point, so a backend that accepts `0x05` diverges on which scripts are
spendable even though it verifies the same signatures. Neither side may re-encode,
normalise or alias a non-canonical spelling into a canonical one.

Parse-level strictness may exceed the reference **only where the excess cannot
change a verdict**: a parse the reference accepts and then fails to verify may be
rejected earlier, but a parse the reference accepts and verifies must never be
rejected. A backend that rejects `r = 0` at parse time is equivalent to one that
verifies it and fails, because both produce `false`; a backend that rejects an
unusual-but-valid encoding is not equivalent and is a defect. Where the boundary
is unclear, a vector decides, not an argument.

That paragraph constrains a backend **relative to the reference**; it does not
license the reference to exceed B1. The reference's own accept-set is exactly B1's,
because `PublicKey::from_sec1` rejects a 33-byte `0x05` encoding before the curve is
consulted, so a backend that rejects `0x05` is not stricter than the reference — it
is equal to it. Where the reference did accept `0x05` (its state before P2.8) the
divergence was in the reference; the contract in
`docs/consensus/PUBLIC_KEY_ENCODING_CONTRACT.md` closed it there rather than
widening B1 to match. `CONSENSUS_RULES.md` §8.4.1 records the rule and the
regression coverage that pins both verdicts.

### 3.4 Versioning of the seam

The seam is source-compatible if a new method is added with a default
implementation; anything else is a breaking change and follows §12. Adding a
backend must not change `SigChecker`, `TxSigChecker` or the script interpreter.

### 3.5 The approved implementation (P2.10)

`zk::Secp256k1Verifier` (`kernel/include/zerocoin/secp256k1_verifier.h`,
`kernel/src/secp256k1_verifier.cpp`) is the `SigVerifier` implementation
approved by `CRYPTO_BACKEND_DECISION.md` §11 and integrated in P2.10 §7. It
wraps the vendored libsecp256k1 v0.8.0 (`secp256k1_vendored` target, PRIVATE
link) and discharges the obligations exactly as follows:

1. Fail closed on a null context, a null or empty DER buffer, and any public
   key whose length is not 33 bytes — rule P-1's gate, applied **before any
   curve arithmetic** (B1, B5).
2. `secp256k1_ecdsa_signature_parse_der`: strict DER; non-minimal encodings and
   trailing bytes are rejected by the library (B2).
3. `secp256k1_ec_pubkey_parse`: the 02/03 tag set is enforced by the library
   itself; a parsed key is a validated curve point (B1).
4. `secp256k1_ecdsa_verify`: verifies over the digest as given and rejects a
   high-`s` signature internally before the equation; no normalisation exists
   anywhere in the wrapper (B3, B4).
5. The context is created once (`SECP256K1_CONTEXT_NONE`) and never mutated;
   verification is re-entrant and thread-safe for concurrent use (B6). No key
   material is logged, copied or retained (B7).

The class is `final`, non-copyable and non-movable; it never throws. A test-only
raw probe (`zk::differential::RawBackendVerifier`, differential tree only)
exposes the backend verdict without the P-1 gate so the differential report can
show exactly where the gate is load-bearing; it is never linked into
`zerocoin_kernel`.

Measured evidence at integration time: the Rust/C++ differential matrix matches
on all 121 cases with no allowed divergence (`kernel/tools/secp256k1_differential.py`),
the four S5 scalar-boundary verdicts are measured on both implementations, and
the seven `kernel/tests/test_secp256k1.cpp` tests pin the P-1 gate, the
strict-DER behaviour, the high-S rejection, and two end-to-end P2PKH spends
through `TxSigChecker`.

---

## 4. Sighash contract

| Element | Value | Frozen by |
|---|---|---|
| Domain tag | `ZRO/sighash/v1\0` — 15 bytes, `5a524f2f736967686173682f763100` | `kSigHashTag`, `static_assert(sizeof == 15)` |
| Chain id | mainnet `0x5A524F01`, devnet `0x5A524F02`, regtest `0x5A524F00`, little-endian in the preimage | `ChainId` |
| Accepted type | `SIGHASH_ALL = 0x01` only, enforced by `TxSigChecker` | `kSigHashAll` |
| Folded type | Any `u32` is folded verbatim into the last 4 bytes (F18); the hasher does not validate | doc `08` §3 |
| Layout | tag, chain id, transaction version, input count, per-input outpoint/value/scriptCode/sequence, output count, outputs, lock time, type | `signature_hash` |
| Blanking | Every input's scriptSig is written as a zero-length script; the signed input carries `script_code` | `sighash_blanks_every_script_sig` |
| Out-of-range index | No digest (`std::optional` empty) — never a guessed digest | `signature_hash` |
| Digest | SHA-256d over the preimage | `SigHash::digest` |

`SigHash` exposes both the preimage and the digest. The preimage is part of the
public contract because the corpus pins the bytes, not only the result; a future
port may not compute the digest a different way and still claim equality.

---

## 5. Script contract

### 5.1 Opcodes

`OP_0` (0x00), `OP_PUSHDATA1` (0x4c), `OP_PUSHDATA2` (0x4d), `OP_VERIFY` (0x69),
`OP_DROP` (0x75), `OP_DUP` (0x76), `OP_EQUAL` (0x87), `OP_EQUALVERIFY` (0x88),
`OP_HASH160` (0xa9), `OP_CHECKSIG` (0xac). Anything else is
`UnsupportedOpcode` with the opcode byte attached (`ScriptResult::opcode`).

### 5.2 Limits and counting

| Limit | Value | Counting rule |
|---|---|---|
| Script size | 10 000 bytes | Per script, before execution |
| Stack items | 1 000 | Checked on every push |
| Element size | 520 bytes | Checked on every push |
| Operation budget | 201 | Only opcodes **greater than 0x4d** count; data pushes are free |

The 201-op rule is the one most likely to be "corrected" by a reviewer who knows
Bitcoin's `OP_16` rule. It is deliberate: `kernel/src/script.cpp` 80–86 counts
`opcode > kOpPushData2`, matching `src/ledger/script.rs`. Do not change it.

### 5.3 Error taxonomy

`ScriptError` is a contiguous `enum class` whose spelling is stable because the
corpus stores the names:

`None`, `ScriptTooLarge`, `TooManyOps`, `StackOverflow`, `StackUnderflow`,
`ElementTooLarge`, `EvalFalse`, `VerifyFailed`, `EqualVerifyFailed`,
`Truncated`, `UnsupportedOpcode`.

Mapping that must not drift:

- `OP_VERIFY` on a false value → `VerifyFailed`.
- `OP_EQUALVERIFY` on unequal values → `EqualVerifyFailed`.
- `OP_CHECKSIG` that returns false pushes an empty vector; the spend then fails
  the final truthiness test as `EvalFalse`, not `VerifyFailed`.
- The final stack top must be true; **negative zero is false**.

### 5.4 Builders

`p2pkh_script_pubkey` produces exactly 25 bytes;
`p2pkh_script_sig` produces two minimal pushes; `push_data` uses the minimal
prefix and reproduces the reference's 16-bit mask above `0xffff` (F20). The
latent truncation is recorded, not fixed.

---

## 6. Serialization contract

| Rule | Statement |
|---|---|
| Integer order | Little-endian for every consensus integer |
| Varint | Minimal encoding only; a non-minimal form is a decode error |
| Trailing bytes | A decoder leaves bytes after its object alone; the caller decides |
| `txid` | SHA-256d of the serialized transaction in **internal** byte order (F19); display order is produced only by the display hex type |
| Hex types | `Hash256` / `Hash160` (storage order) are distinct from display hex; mixing them is a compile error (F3) |
| Scripts | Length-prefixed with the minimal varint, exactly as the reference writes them |
| Transaction bounds | The decoder bounds input count, output count and script length; the 1 MB / 10 000 / 10 000 envelope is enforced where the reference enforces it, not in a different layer |

A derived implementation may not add a canonicalisation step (trimming, sorting,
re-encoding) between decode and hash. Byte equality is the test.

---

## 7. Conformance interface (C4)

### 7.1 The runner

`kernel_conformance` is a text-in/text-out process. It knows nothing about JSON,
files or vectors.

```text
usage: kernel_conformance <fixture>

fixture grammar, one directive per line:
  CASE <id>
  OP <verb>
  IN  <key>=<value>
  OUT <key>=<value>          # repeatable; every OUT must be produced
  END

stdout:
  RESULT <id> ok
  RESULT <id> fail <one-line reason>
  SUMMARY cases=<n> failures=<m>

exit: 0 all cases passed | 1 any case failed | 2 usage, fixture or I/O error
```

The 16 verbs: `sha256_utf8`, `sha256d_utf8`, `hash160_sec1`, `display_reversal`,
`varint_encode`, `tx_build`, `tx_roundtrip`, `tx_decode_error`, `compact`,
`script_push_data`, `p2pkh_script_pubkey`, `p2pkh_script_sig`, `script_verify`,
`sighash`, `sighash_distinct`, `p2pkh_spend`.

`p2pkh_spend` (added in P2.10 §7) is the only verb that checks a real
signature: it deserialises the transaction, derives the sighash for the bound
input through the production `zk::Secp256k1Verifier`, and runs the script
interpreter, so the corpus's accepted P2PKH spend is replayed end to end.

### 7.2 The wrappers

`kernel/tools/g1_conformance.py` and `p2_conformance.py` own the translation from
`test/vectors/**` JSON to the fixture grammar. They must:

1. read `source_commit` from the corpus and print it, so a stale build is visible;
2. fail if a case is missing, duplicated or mapped twice;
3. fail if a **deferred** case is also mapped (the deferral list is explicit);
4. run a **corruption self-check** where feasible, proving the comparison can
   fail (P2 rejects 22/22 corrupted cases);
5. exit non-zero if the runner reports any failure or if the counts disagree.

The wrappers are the reason "22/22" means something. A wrapper change is a
change to the proof, and is reviewed as such.

### 7.3 The corpus

`test/vectors/**` is JSON with a schema string (`zro-baseline-vectors/1`) and a
`source` field naming the command that produced each file. Values are generated;
no field is hand-written. Adding a vector without a Rust source commit is a
defect.

`test/p31-vectors/**` is a second corpus with the same schema and the same
generator. It holds the P3.1A header reference groups (`chain.header_preimage`
and `chain.header_identity`) because the P0 manifest carries a single
`source_commit` (7cb9017) that predates `Block::validate_header_identity`;
re-stamping it would rewrite every historical fixture. It is not a third kind of
provenance: its manifest names `source_commit` (the code that produced the
values) and `reference_commits` (where the encoder last changed, and where the
validator entered `zerocoin/src`) separately, so no fixture claims a commit that
did not contain the function it exercises. `run_vectors.py` does not read this
root - it dispatches by case-id namespace and registers no verifier for these
groups - so the Rust exporter is their sole origin and the P0 gate is unchanged.

---

## 8. RPC contract (C3, planned at P5)

No C++ RPC exists. The contract is recorded now so that P5 and any Go service
have the same reference.

- Exactly **12 methods** with the same names, field names and units as the Rust
  node (doc `03` §3.2). A field may be added only when both implementations
  accept it; a field may never be repurposed.
- Values that are consensus bytes are rendered in display hex, as the Rust node
  renders them, and are not re-derived by the client.
- Errors use the reference's classes (`ImmatureCoinbase`, `DoubleSpend`,
  `NegativeFee`, … from doc `01` §13), not free-form strings.
- A client that does not recognise a field must ignore it for forward
  compatibility; a client that requires a field must fail closed if it is absent.
- The RPC has no method that mutates consensus state other than submitting a
  transaction or a block, and no method that exposes key material.

---

## 9. Versioning

| Versioned surface | Current value | Change rule |
|---|---|---|
| Sighash preimage | `ZRO/sighash/v1\0` | A new tag is a new consensus rule; requires a fork decision and a new document |
| Chain ids | `0x5A524F00/01/02` | Frozen per network; a new network gets a new id |
| Corpus schema | `zro-baseline-vectors/1` | Additive fields allowed; a semantic change bumps the number |
| Keystore | version 1, argon2id m=19456 t=2 p=1, AES-256-GCM | A change breaks cross-open at G5 and must be a new version with a migration |
| Wallet/chain JSON | field names as audited | Additive only until G5 proves cross-open both ways |
| P2P handshake and messages | as audited in `src/network/` | Protocol acceptance (C1), not byte equality; version negotiated, unknown messages rejected |
| Conformance fixture grammar | `CASE/OP/IN/OUT/END` | Adding a directive requires updating both wrappers and the runner |

Rule of thumb: **anything a signature or a hash commits to is frozen; anything
only an operator reads may evolve.** There is no third category.

---

## 10. Error handling

| Layer | Mechanism | Forbidden |
|---|---|---|
| C++ kernel functions | Return a result struct or `std::optional` | Throwing, `assert` on untrusted input, `std::terminate` |
| C++ backend boundary | `bool`, all failures collapse to `false` | Propagating library exceptions or aborting |
| Script interpreter | `ScriptResult{error, opcode}` | String-keyed errors, partial results |
| Conformance runner | Exit 0/1/2; `RESULT`/`SUMMARY` lines | Printing a success line for a case it did not run |
| Rust reference | `Result<_, CryptoError>` etc. | Panics reachable from network input |
| RPC | The reference's error classes | Inventing a client-side class |

The asymmetry is intentional: the kernel loses information (a false is a false),
the reference keeps the class, and the RPC is the only place where the class is
visible to operators. A differential test compares classes at the RPC layer, not
inside the kernel.

---

## 11. Resource limits

All limits are consensus, not policy. Each has one owner and one test.

| Limit | Value | Owner | Test |
|---|---|---|---|
| Script size | 10 000 bytes | `script.h` | `script_size_limit_is_10000_bytes` |
| Stack items | 1 000 | `script.h` | `script_stack_limit_is_1000_items` |
| Element size | 520 bytes | `script.h` | `script_element_limit_is_520_bytes` |
| Ops per script | 201 (`opcode > 0x4d`) | `script.h` | `script_op_limit_is_201_ops_and_pushes_are_free` |
| Transaction inputs | 10 000 | `transaction.h` | `transaction_decoder_bounds_the_input_count` |
| Transaction outputs | 10 000 | `transaction.h` | `transaction_decoder_bounds_the_output_count` |
| Script length in a tx | bounded by the decoder | `transaction.h` | `transaction_decoder_bounds_the_script_length` |
| Transaction envelope | 1 MB | reference validation | doc `03` §3.1 |
| P2P frame overhead | 76 bytes | reference `network/frame.rs` | P5 |
| Header preimage | 107 bytes | reference `consensus/block.rs` `preimage()` | `consensus_rules.rs` frozen-length assertion |

> **Corrected in P2.11.** This row read 108 bytes. The tag `"ZRO/header/v1\0"` is
> 14 bytes, not 15, so the preimage is 14 + 4 + 4 + 8 + 32 + 32 + 8 + 4 + 1 =
> **107 bytes**. Three independent artifacts agree: `BlockHeader::preimage()`
> itself, `test/vectors/chain/header.json` (`preimage_len: 107`, 214 hex
> characters, tag prefix `5a524f2f6865616465722f763100`), and the frozen
> assertion `assert_eq!(preimage.len(), 107)` in
> `zerocoin/tests/consensus_rules.rs`. The engine appends the `u64` nonce, so
> 115 bytes are hashed. `docs/migration/01-architecture-audit.md` §4.3 carried
> the same 15-byte tag miscount; it is corrected there with a dated note.

A test that asserts a limit must assert both sides: at the boundary (accepted)
and one past it (rejected). A one-sided limit test cannot detect a widened limit.

---

## 12. Temporary compatibility surfaces and removal

These are the only surfaces that exist for compatibility rather than as a
permanent guard. Each has an owner and a written removal condition.

| Surface | Why it exists | Removal condition | What must stay true |
|---|---|---|---|
| `TxSigChecker` with a null `SigVerifier` returning `false` | Fails closed when no verifier is supplied. It was introduced because no backend existed (G2c); since P2.10 a real backend is registered (`zk::Secp256k1Verifier`), so the null case is a defensive guard, not the production path | Keep as fail-closed behaviour; `TxSigChecker(..., nullptr)` call sites may be retired once every script test runs against the real verifier | No spend may be accepted without a real verification |
| One deferred corpus case (`ledger.sighash.signature_der`) | It needs ECDSA **signing**; the runner is verify-only (C-52) | Not re-enabled by closing G2c — it needs a separate signing decision outside the kernel (`CRYPTO_BACKEND_DECISION.md` §9.1, §15.3). `ledger.script.p2pkh_spend_accepted` was re-enabled in P2.10 when the backend landed | The deferral list must stay explicit and printed; it is exactly one counted entry, so counts can rise but never fall silently |
| The deferral list itself in `p2_conformance.py` | Documents the gap in code | Deleted when the list is empty | A missing case still fails the wrapper |
| The C++ kernel as a whole | Compatibility proof for a possible cutover | G8 decision: ship it, keep it as a candidate, or archive `kernel/` | Rust is never modified by the removal |
| Doc `03`'s `cpp/` proposal | Historical plan | Superseded in writing by `THREE_LANGUAGE_ARCHITECTURE.md` §9 | No code move is implied |

Explicitly **not** temporary: the G1 and P2 wrappers, the corpus, the gate, the
ownership table, and the rule that Rust is the oracle. Removing any of those
would remove the proof, not a compatibility crutch.

---

## 13. Changing a contract

A contract change is one commit that contains all five of:

1. the owner change in Rust (or a written statement that no Rust change is
   needed, with a citation);
2. regenerated vectors with a new `source_commit`;
3. the C++ change and its unit test;
4. both gates green in the commit message;
5. an update to this file and, if authority moved, to
   `COMPONENT_OWNERSHIP.md`.

A contract change that touches a frozen value in §9 is a consensus change and is
out of scope for the migration (doc `03` §1 rule 2).
