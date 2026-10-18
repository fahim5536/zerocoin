# 06 — P0: deterministic baseline vectors

> Evidence labels follow `README.md` §1. The original P0 run was made on
> 2026-10-18 against `main` = `2bc96d2acf9b3b73aea00a766514afb845cdb5e0`; the
> `source_commit` amendment in §3.1 was made the same day against `main` =
> `2ede9f5e006c28b66bcb58bed2f0c766f5d9dc00`, then rebased onto
> `101479892b020aec44458d3639f6ce21de368d35` — which only adds a workflow file —
> and re-run in full before it was pushed. Both used Windows 24H2 with
> `cargo`/`rustc` 1.99.1 and Python 3.15.0. The version is toolchain-specific:
> the default `stable-x86_64-pc-windows-msvc` toolchain on this machine reports
> 1.99.0, while every command here names `+stable-x86_64-pc-windows-gnu`, which
> is the 1.99.1 above — the same rule as `README.md` §2.

P0 builds the artefact that `05-test-strategy.md` §2 calls the golden-vector
corpus, and nothing else. It adds no C++, touches no consensus rule, and leaves
every tracked file in the Rust tree byte-identical to `2bc96d2`.

---

## 1. Result

| Item | Result | Evidence |
|---|---|---|
| Corpus files | 13 vector files + `manifest.json`, 116,383 B total | `test/vectors/` `[VERIFIED]` |
| Cases | 117 — 115 `rule`, 2 `oddity` | `manifest.json` `total_cases` `[VERIFIED]` |
| Recomputed independently | 112 PASS | harness summary `[VERIFIED]` |
| Pinned, not recomputable | 5 ANCHOR | harness summary `[VERIFIED]` |
| No verifier available | 0 SKIP | harness summary `[VERIFIED]` |
| Disagreements | 0 FAIL | harness summary `[VERIFIED]` |
| Rust suite | 235 unit + 2 integration, 0 failed | `cargo test --all-targets` `[VERIFIED]` |
| Corpus regenerable | `ZRO_VECTOR_WRITE=0` compare run passes | `[VERIFIED]` |
| Provenance recorded | `source_commit` in every file and the manifest, cross-checked by the harness | §3.1 `[VERIFIED]` |
| Byte-identical across two generations | yes, in one process | `corpus_generation_is_deterministic` `[VERIFIED]` |
| Byte-identical on a **second machine** | not performed | `[UNVERIFIED]` |
| Verifier is not vacuous | 116/116 injected mutations detected | §6 `[VERIFIED]` |
| `05` §2.4 error-enum completeness | **not met** — 31/81 variants | §7 `[VERIFIED]` |

Gate **G0** (`03` §4) asks for three things. Clause (b) — the Rust suite still
reports 235 passing — holds. Clause (c) — every vector file names the exact
command that produced it — holds literally: the envelope field `source` carries
the command, and since §3.1 every file also names the commit whose code produced
the values. Clause (a) has two halves: the corpus must be
regenerable from the pinned commit (holds, and the comparison is enforced by a
test), and byte-identical across two runs *on two machines* (only one machine was
available, so this half is `[UNVERIFIED]`, see §5).

---

## 2. What P0 added

| Path | Size | Role |
|---|---|---|
| `test/vectors/**` | 13 files + manifest, 116,383 B | the corpus itself |
| `test/harness/zro_vectors.py` | 2,295 lines, 79,398 B | independent verifier — recomputes every expected value from the case's own `input` |
| `test/harness/run_vectors.py` | 195 lines, 7,950 B | corpus structural checker and driver |
| `test/.gitignore` | 2 lines | `__pycache__/`, `*.pyc` — the root ignore file does not cover them |
| `.gitattributes` | 6 lines | pins LF on `test/vectors/**` so a clone with `core.autocrlf=true` cannot break the byte comparison |
| `zerocoin/tests/export_baseline_vectors.rs` | 2,176 lines, 85,094 B | Rust emitter (`--test export_baseline_vectors`) |

That is the whole of P0. The emitter is the crate's **first integration-test
target** — finding F12 records that `tests/` did not exist before.

The `source_commit` amendment (§3.1) touched the same code and corpus paths as
the rest of P0 and nothing else:
the emitter grew 17 lines, `run_vectors.py` 27, and each of the 14 corpus files
gained a metadata line. No input or expected value moved — the parsed `cases`
arrays of all 13 vector files are identical to `2ede9f5` `[VERIFIED]`.

`git status --short` after the work shows exactly two documentation edits
(`docs/migration/README.md` modified, `docs/migration/06-p0-baseline-vectors.md`
added) and three untracked paths (`?? .gitattributes`, `?? test/`,
`?? zerocoin/tests/`). Nothing under `zerocoin/src/` differs from `2bc96d2`
`[VERIFIED]`.

The verifier does not import the Rust tree, does not shell out to `cargo`, and
imports only `hashlib` and `hmac` from the standard library: RIPEMD-160,
SHA-256d, Base58Check, secp256k1 point arithmetic and RFC 6979 signing are
implemented in the harness. The corpus check therefore runs offline in about a
second, on a machine with no Rust toolchain installed.

---

## 3. Corpus layout and format

| File | Group | Cases | Bytes |
|---|---|---|---|
| `hash/primitives.json` | `hash` | 5 | 2,338 |
| `encoding/varint.json` | `encoding.varint` | 9 | 3,298 |
| `encoding/transaction.json` | `encoding.transaction` | 5 | 4,978 |
| `ledger/script.json` | `ledger.script` | 15 | 35,439 |
| `ledger/sighash.json` | `ledger.sighash` | 8 | 8,442 |
| `ledger/state_root.json` | `ledger.state_root` | 13 | 8,383 |
| `chain/header.json` | `chain.header` | 8 | 7,096 |
| `chain/anchors.json` | `chain.anchors` | 6 | 7,709 |
| `pow/engines.json` | `pow` | 11 | 7,044 |
| `difficulty/retarget.json` | `difficulty` | 15 | 8,859 |
| `reward/subsidy.json` | `reward.subsidy` | 6 | 7,734 |
| `reward/coinbase.json` | `reward.coinbase` | 10 | 8,575 |
| `crypto/addresses.json` | `crypto.address` | 6 | 3,607 |

Every file is a self-describing envelope; every case carries its own inputs:

```json
{
  "schema": "zro-baseline-vectors/1",
  "group": "hash",
  "intent": "rule",
  "note": "...",
  "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
  "source_commit": "7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c",
  "provenance": "every expected value was produced by the shipping `zerocoin/` Rust code at `source_commit`; no value is transcribed from another implementation",
  "case_count": 5,
  "cases": [
    {
      "id": "hash.sha256.abc",
      "intent": "rule",
      "input": {"data_utf8": "abc"},
      "expected": {"sha256_hex": "ba7816bf...0015ad"},
      "independent_check": "NIST FIPS 180-4 published vector"
    }
  ]
}
```

`run_vectors.py` rejects the corpus (exit 2) if an envelope key, a case key, a
non-empty `independent_check`, a unique `id`, a case's top-level namespace, the
`case_count`, the manifest's per-file count, the manifest's `total_cases`, or
the "no unlisted file" rule is violated. A file may cover a whole namespace
(`chain/header.json` holds both `chain.header.*` and `chain.merkle.*`), so the
namespace guard is the first id segment, not the full group name.

Byte order is the convention that bites ports (finding F3): `Hash256.0` holds
the raw digest, published as `internal_hex`; `display_hex` is the same bytes
reversed. Both directions appear in the corpus on purpose.

### 3.1 Provenance: the `source_commit` field

An earlier revision of the corpus said the commit responsible for the values was
discoverable with `git log --follow <this file>`. That resolves to the commit
that *added the corpus*, which is not the commit that *produced the values* — the
two differ whenever the corpus lands after the code it describes. Every envelope
and the manifest therefore carry `source_commit`.

The value is a literal in the emitter, not a `git rev-parse` at run time:

```rust
const SOURCE_COMMIT: &str = "7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c";
```

Querying `git` during generation would make the corpus depend on the checkout —
the class of nondeterminism the rest of P0 eliminates — and would fail the
compare test for anyone whose HEAD differs. The update rule is published in the
manifest as `source_commit_rule`: the newest commit touching `zerocoin/src`,
`Cargo.toml`, `Cargo.lock` or `build.rs`, changed in the same commit that
regenerates the corpus.

`7cb9017c…` was verified rather than assumed: `git log -1 --format=%H` over those
four paths returns it, and `git diff 7cb9017c… 2ede9f5 -- <the same paths>` is
empty, so no build input moved between the recorded commit and the corpus commit
`[VERIFIED]`.

`run_vectors.py` enforces the field instead of trusting it. It rejects the
corpus (exit 2) when the manifest lacks `source_commit`, when either the
manifest's or a file's value is not 40 lowercase hex digits, or when a file's
value differs from the manifest's. Three injected faults were each observed to
be rejected: a one-nibble change inside `hash/primitives.json`, the field
deleted from the manifest, and the manifest's value uppercased `[VERIFIED]`.

---

## 4. The verifier and its status model

`zro_vectors.verify_case` dispatches on the case id to a dedicated verifier per
behaviour — hash, varint, transaction, script, sighash, state root, header,
merkle, genesis anchors, pinned anchors, difficulty, PoW, reward subsidy, reward
coinbase, address — and returns one of four statuses:

| Status | Meaning | Counts as verification? |
|---|---|---|
| `PASS` | recomputed from `input` alone and equal to `expected` | yes |
| `ANCHOR` | a constant table transcribed into the harness; agreement proves only that two transcriptions agree | **no** |
| `SKIP` | the verifier has no independent implementation for the case | no — and forces exit 1 |
| `FAIL` | recomputed value disagrees, or the fixture is malformed | — |

The five ANCHOR cases are `chain.anchors.boot_invariants`,
`chain.anchors.network_params`, `difficulty.params`, `pow.engine_ids` and
`reward.constants`. Each is a table of numbers with no input to derive it from,
so publishing one as `PASS` would be a lie about independence; `run_vectors.py`
prints them separately and the manifest note says so. Note that the genesis
blocks are *not* in that set: `chain.anchors.regtest_genesis` and
`chain.anchors.devnet_genesis` are re-mined by the harness from the transcribed
network table and compared hash-for-hash, so only the table itself is an anchor.

`DESCRIPTIVE_FIELDS = {"label"}` is excluded from both directions of the
comparison, so a case may carry a human label without it counting as an
unverified expectation — and, symmetrically, a missing label is not a failure.
Nothing is ever compared against itself: the expected value is discarded before
recomputation and only the recomputed structure is compared.

Exit codes: `0` clean, `1` if any FAIL or SKIP, `2` on a corpus structural error.

---

## 5. Determinism

The emitter writes the corpus only when `ZRO_VECTOR_WRITE` is exactly `"1"`; any
other value — including unset — makes the test compare the committed corpus
against a freshly generated one and fail on the first byte of difference. Two
tests exist:

- `baseline_vectors_match_the_committed_corpus` — regenerate in memory, compare
  with `test/vectors/`; this is what makes the corpus a *checked* artefact
  rather than a snapshot nobody revalidates;
- `corpus_generation_is_deterministic` — generate twice in one process and
  assert the two byte strings are equal.

Inputs are pinned by construction: fixed keys, fixed nonces and timestamps, no
clock, no environment, no filesystem path, no iteration over a hash map. Output
is JSON with sorted keys and a fixed indent, so ordering cannot drift. The
provenance field is pinned the same way (§3.1): `SOURCE_COMMIT` is a `const`, so
generation never reads `.git`.

Determinism was also checked outside the process, which the in-process test
cannot cover: SHA-256 of all 14 files, regenerate, SHA-256 again — 14/14
identical `[VERIFIED]`.

The emitter writes LF and the test compares raw bytes, which makes line endings
part of the contract. The repository had no `.gitattributes`, and a clone with
`core.autocrlf=true` (a common Windows default) would have checked the vectors
out with CRLF and failed the comparison without a single code difference.
`.gitattributes` now pins `test/vectors/**` to `text eol=lf`, which neutralises
that. This machine has `core.autocrlf=false` and `core.eol=lf`, so the committed
bytes and the checked-out bytes are identical here `[VERIFIED]`.

Because the comparison is byte-exact, the committed blobs were inspected
directly: all 14 files contain LF only, none carries a byte-order mark, every
file ends with a newline, and the only non-ASCII bytes in the whole corpus are
two em dashes inside English prose in `chain/header.json` and
`hash/primitives.json` — both sides read the files as UTF-8, and `serde_json`
emits them literally rather than as `\u` escapes `[VERIFIED]`.

What is **not** proven: that a different machine produces the same bytes. Inside
the emitter the only cross-host variables would be map iteration order
(neutralised — `serde_json`'s default map is a `BTreeMap`, so keys are sorted),
floating point (there is none; the corpus holds integers, strings, booleans,
arrays and `null` only) and a dependency version that changes integer
formatting, which would have to be observed to be believed. None of that is
argued away: the second-host run is the cheapest open item in §11.

---

## 6. Evidence that the verifier bites

A verifier that cannot fail is worse than no verifier, so P0 measured the
false-negative rate directly. A throwaway script (not committed, see §11) copied
`test/vectors` to a scratch directory, mutated the last non-`null` leaf of every
case's `expected` value — booleans flipped, integers incremented, hex strings
with their first digit changed, other strings suffixed — re-wrote the files, and
ran the real `run_vectors.py` over the mutant corpus.

| Round | Detected | Blind spots |
|---|---|---|
| first | 114/116 | 2 — both `reward.split_reward.*` |
| after fixes | **116/116** | **none** |

Both blind spots were genuine harness defects, not corpus problems: mutating an
expected row's own `weights` made the row unfindable, and the verifier raised
`Unsupported` (→ SKIP) instead of `VectorMismatch`. The same audit found five
more sites where a *corpus-integrity* violation was reported as a harness
limitation — a changed fixture input count, a missing sibling case, a fixture
value that no longer matched its subsidy, and two missing probe cases. All six
now raise `VectorMismatch`, because a corpus that no longer matches the fixture
it was generated from is drift, not a limitation.

One case cannot be mutated and is therefore outside the 116: 
`ledger.sighash.out_of_range_index` expects `{"digest": null}`, which has no
leaf to corrupt. It is covered structurally instead — the harness asserts the
`None` result rather than a value.

The remaining `Unsupported` sites are deliberate: a nonce search that cannot
terminate, an input index past the end of a transaction, any sighash type other
than `SIGHASH_ALL`, and — defensively — a case id inside a known domain that the
domain verifier does not handle. Those are statements about what the harness
models, and they must stay visible as SKIP rather than be quietly converted into
failures. The last group is empty today: the run reports `SKIP 0`.

---

## 7. Coverage against `05` §2.4 — the one requirement P0 does not meet

`05` §2.4 states the completion rule for the corpus: *every variant of every
consensus error enum has at least one vector that produces it.* Measured against
the published enums, the corpus covers 31 of 81 variants (38%):

| Enum | File | Exercised | In P0 scope? |
|---|---|---|---|
| `UtxoError` | `ledger/utxo.rs` | 8/8 | yes — UTXO state roots and spends |
| `ScriptError` | `ledger/script.rs` | 9/10 | yes — script execution |
| `TxDecodeError` | `ledger/transaction.rs` | 3/5 | yes — transaction serialisation |
| `DifficultyError` | `consensus/difficulty.rs` | 2/3 | yes — retarget |
| `AddressError` | `address.rs` | 2/4 | yes — address encoding |
| `RewardError` | `consensus/reward.rs` | 6/8 | yes — subsidy and coinbase |
| `CryptoError` | `crypto/secp256k1.rs` | 1/4 | yes — signature verification |
| `BlockError` | `consensus/block.rs` | 0/13 | no — block accept/reject is not a P0 domain |
| `PowError` | `consensus/pow.rs` | 0/3 | no — nonce search, `[PROPOSED]` for P1 |
| `ChainError` | `chain.rs` | 0/10 | no — chain orchestration |
| `MempoolError` | `mempool.rs` | 0/4 | no — policy, not consensus |
| `KeystoreError` | `crypto/keystore.rs` | 0/9 | no — wallet sealing, not consensus |

In-scope: **31/42**. The eleven missing variants are

- `ScriptError::VerifyFailed`
- `TxDecodeError::{TooManyInputs, TooManyOutputs}`
- `DifficultyError::UnexpectedBits`
- `AddressError::{BadEncoding, BadLength}`
- `RewardError::{MissingHeightCommitment, RewardOverflow}`
- `CryptoError::{InvalidPublicKey, InvalidSignature, VerificationFailed}`

None of the eleven is intrinsically unmodellable: each is reachable from a
padded or truncated input, a tampered DER signature, or a wrong-network decode.
They are missing because P0 published one or two cases per behaviour and did not
enumerate reject kinds — not because the Rust code cannot produce them.

The honest status is therefore **§2.4 is not satisfied, and P0 does not claim
it.** Fabricating reject vectors that the Rust implementation was never observed
to produce would violate requirement 4 of the task; narrowing the rule to "every
variant reachable through the P0 domain list" would be a documentation change
that hides a real gap. The recommendation is to close the eleven first, before
P1's C++ error taxonomy is written, because `05` §2.4 also says that a new error
variant without a vector fails CI — and CI cannot enforce that until the
baseline is zero. Until then, any CI added in P1 must start from the gap
recorded here rather than from a claim of compliance.

---

## 8. Executed tests, and what was not run

| Check | Command | Observed | Executed |
|---|---|---|---|
| Corpus structure + independent verification | `python test\harness\run_vectors.py --quiet` | `PASS 112 ANCHOR 5 SKIP 0 FAIL 0`, exit 0 | yes |
| Corpus compare mode | `ZRO_VECTOR_WRITE=0 cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors` | `2 passed; 0 failed` in about 5 s | yes |
| Corpus byte-for-byte across two generator runs | SHA-256 of all 14 files before and after a `ZRO_VECTOR_WRITE=1` run | 14/14 identical | yes |
| Provenance enforcement | `run_vectors.py` after three injected faults | three `CORPUS …` rejections, exit 2 | yes |
| Whole Rust suite | `cargo +stable-x86_64-pc-windows-gnu test --all-targets` | `235 passed` in about 42 s, then `2 passed` in about 5 s; 0 failed | yes |
| Verifier mutation self-check | scratch script, see §6 | `detected 116/116`, no blind spots | yes |
| Byte-identical corpus on a second machine | — | not performed | **no** |
| `cargo test --doc` | — | not re-run in P0; `01` §12 records zero doctests | **no** |
| `demos\regtest-maturity.ps1` | — | not re-run in P0; its output at `5248b10` is transcribed in `01` §12 | **no** |

The three unexecuted rows are honest gaps, not omissions by accident. The
two-machine run needs a second host; the doctest and demo runs were last
verified in the audit and P0 changed nothing they exercise.

---

## 9. Reproduction

From the repository root (`upstream\`), with the crate in `zerocoin\`:

```powershell
# 1. Verify the corpus against the independent Python harness (no Rust needed)
python test\harness\run_vectors.py

# 2. Prove the committed corpus is what the pinned Rust sources generate
$env:CARGO_TARGET_DIR = "d:\Downloads\zerocoin\.publish\target\debug"
Push-Location zerocoin
$env:ZRO_VECTOR_WRITE = "0"
cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors
Pop-Location

# 3. Regenerate after a deliberate emitter change (expect a dirty work tree)
Push-Location zerocoin
$env:ZRO_VECTOR_WRITE = "1"
cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors
Pop-Location

# 4. The full suite, including the two corpus tests
Push-Location zerocoin
cargo +stable-x86_64-pc-windows-gnu test --all-targets
Pop-Location
```

Step 2 is the one to run in CI: it fails loudly when the corpus and the Rust
sources disagree, in either direction. Step 3 is the only way to produce a new
corpus, and the diff it leaves is the review artefact.

The integration test lives in the crate, not at the repository root — running
`cargo test --test export_baseline_vectors` from `upstream\` fails with
`no test target named 'export_baseline_vectors'`. Note this when wiring CI.

---

## 10. Constraints honoured

- **No Rust implementation change.** `git status` proves `zerocoin/src/` is
  untouched; the only Rust file touched is the integration test that emits the
  corpus.
- **No C++.** Nothing was written beyond the files in §2.
- **No consensus, wallet-format, or network change.** The corpus only observes.
- **No invented values.** Every `expected` value was produced by the Rust
  emitter; every non-ANCHOR value was then recomputed by a second,
  independent implementation.
- **No secrets, no wallet data.** `test/` contains no private keys beyond the
  published test scalars already in the crate's own tests, no mnemonics, no
  passwords, and no absolute host paths; grep for key material, `d:\Downloads`,
  `C:\Users` and the account name returns zero matches. The manifest states
  explicitly that the published scalars are test values, never wallet keys.

---

## 11. Open items for P1

| # | Item | Why it matters |
|---|---|---|
| 1 | Close the eleven in-scope error variants (§7) | `05` §2.4 cannot be enforced by CI until the gap is zero |
| 2 | Run the determinism check on a second machine | the `[UNVERIFIED]` half of G0 (a) |
| 3 | Register the sighash-type behaviour as a finding | see below |
| 4 | Give `oddity` cases an optional `finding` key | `05` §2.3 shows `"finding": "F3"`; the corpus encodes F3 inside `independent_check` and the sighash oddity has no id at all |
| 5 | Decide whether to promote the mutation self-check | it is currently a scratch tool; committed, it would guard the verifier itself |
| 6 | Cross-check `source_commit` against `git` in CI | the harness checks the field's shape and internal consistency, not that it is still current; a CI job can compare it with `git log -1 --format=%H -- zerocoin/src zerocoin/Cargo.toml zerocoin/Cargo.lock zerocoin/build.rs` |

Item 3 is a real gap in the audit register, discovered by publishing the vector:
`01` §5.2 records that "only `SIGHASH_ALL = 0x01` exists" and that the preimage
ends with `sighash_type u32`, but it does not say what happens when a caller
passes another value. The corpus shows the answer — the type is folded into the
preimage and any `u32` is accepted, so `sighash_type: 2` produces a valid-looking
digest rather than selecting `SIGHASH_NONE`. A C++ port that validates the type
before hashing will diverge. This belongs in the register as F16 before the
sighash module is ported.

---

## 12. What P1 inherits

- A corpus that is **executable evidence**: 112 values agreed on by two
  implementations, 5 constants marked as constants.
- The exact hash convention (F3): `internal_hex` is the raw digest,
  `display_hex` its reverse, both published everywhere both are observable.
- The two oddities that must be reproduced deliberately, not "fixed":
  display reversal (`hash.display_reversal`) and the folded sighash type
  (`ledger.sighash.type_02_is_folded_in`).
- The pinned tables a C++ node must boot on: `chain.anchors.network_params`,
  `chain.anchors.boot_invariants`, `difficulty.params`, `pow.engine_ids`,
  `reward.constants` — enumerated in the corpus, so they can be diffed rather
  than copied by eye.
- A rejection taxonomy with a measured baseline (§7) instead of an assumption of
  completeness.
- `source_commit` in every file (§3.1), so each expected value maps to the exact
  Rust build that produced it and a port can cite that commit rather than a
  directory.
