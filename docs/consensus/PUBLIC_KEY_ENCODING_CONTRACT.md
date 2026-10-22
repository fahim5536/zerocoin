# Public-key encoding contract

Status: **ACCEPTED** — normative for ZeroCoin consensus.
Recorded in P2.8 at commit `65a61cdfa8bb033df41e98e8432043a4f709a58f` + the P2.8 change.
Supersedes: nothing. Fills a gap: `CONSENSUS_RULES.md` and
`CPP_PORT_REQUIREMENTS.md` were silent on public-key encodings, and
`INTERFACE_CONTRACTS.md` B1 stated the rule without naming the tag set.

This document defines which byte strings a ZeroCoin node may interpret as a
public key. It is the authority that `CONSENSUS_RULES.md` §8.4 rule **P-1**,
`CPP_PORT_REQUIREMENTS.md` **C-53**, `INTERFACE_CONTRACTS.md` **B1** and
`CRYPTO_BACKEND_READINESS.md` **S3** now point at.

---

## 1. Question

`OP_CHECKSIG` reads a candidate public key off the stack and hands it to the
signature checker. Which byte strings are acceptable keys, and where must a
non-conforming one be rejected?

## 2. What the written sources said before this record

| Source | Statement about the tag set |
|---|---|
| `CONSENSUS_RULES.md` §8.4 | **silent** — specifies `script::verify`, the four limits, the ten opcodes and the P2PKH templates; no encoding statement |
| `CPP_PORT_REQUIREMENTS.md` C-38..C-47 | **silent** — opcodes, limits, sighash, apply order, maturity, state root, no floats |
| `INTERFACE_CONTRACTS.md` B1 | "Accept **only 33-byte compressed SEC1** public keys; reject 65-byte uncompressed, hybrid prefixes, wrong lengths, off-curve `x`, and the point at infinity" |
| `INTERFACE_CONTRACTS.md` §3.3 ¶3 | "a backend that rejects an unusual-but-valid encoding is not equivalent and is a defect … a vector decides, not an argument" |
| `CRYPTO_BACKEND_READINESS.md` S3 | 33-byte `0x02`/`0x03` accept; "prefix `0x00`/`0x04`/`0x05` (reject)" |
| `zerocoin/src/crypto/secp256k1.rs` 112–121 | length gate only; then `VerifyingKey::from_sec1_bytes`, which also admits SEC1 `Tag::Compact` (`0x05`) |

The contradiction is narrow and was recorded in
`CRYPTO_BACKEND_SELECTION_AUDIT.md` §17.6: B1 says "only compressed", S3's test
plan lists `0x05` as a reject, and yet the implementation accepted `0x05`
because it checked nothing but the length. §3.3 ¶3 pulls in the opposite
direction only if `0x05` is a "valid encoding" of a ZeroCoin public key. This
record settles that question.

## 3. Decision

**P-1 — A ZeroCoin public key is a 33-byte SEC1 encoding whose tag byte is
`0x02` or `0x03` and whose 32-byte `x` coordinate names a point on secp256k1.
Everything else is rejected at parse time, before any ECDSA work.**

Normative table:

| Input | Verdict | Where decided |
|---|---|---|
| 33 bytes, tag `0x02`, `x` on curve | **accept** | parse |
| 33 bytes, tag `0x03`, `x` on curve | **accept** | parse |
| 33 bytes, tag `0x05` | **reject** | parse (tag gate) |
| 33 bytes, any other tag (`0x00`, `0x01`, `0x04`, `0x06`, `0x07`, `0x08`..`0xff`) | **reject** | parse (tag gate) |
| length ≠ 33 (0, 32, 34, 65, …) | **reject** | parse (length gate) |
| 33 bytes, `x ≥ p` or `x` not on curve | **reject** | parse (curve check) |
| 33 bytes, all tags above, valid or invalid point | **no re-encoding** | the accepted bytes are used unchanged |

Corollaries:

* **No aliasing.** `hash160(0x05 || x)` and `hash160(0x02 || x)` are not
  interchangeable, and only the latter can be a key hash. There is exactly one
  accepted spelling per curve point.
* **No normalisation.** A rejected encoding is never rewritten into an accepted
  one. There is no fallback path that tries `0x02` after `0x05` fails.
* **Fail closed.** Rejection surfaces as `CryptoError::InvalidPublicKey`; inside
  the interpreter that becomes `OP_CHECKSIG` pushing false, hence
  `ScriptError::EvalFalse` — the pre-existing error class, not a new one.

## 4. Why this is the project's contract and not libsecp256k1's opinion

The decision is grounded in ZeroCoin's own invariants. Six independent internal
facts agree, and none of them is derived from a C library's parser:

1. **The type says so.** `PublicKey` is documented as "A compressed SEC1 public
   key" (`zerocoin/src/crypto/secp256k1.rs:105`), and the module doc says "a
   [`PublicKey`] is the compressed SEC1 encoding (33 bytes) of the matching curve
   point" (`:4`). A type whose invariant is *compressed* cannot store a *compact*
   encoding without violating its own contract.
2. **The constant is named for the encoding.** `COMPRESSED_PUBKEY_LEN = 33`
   (`:23`) — not `KEY_LEN`. The length is a consequence of the tag, and the name
   records which tag was intended.
3. **The error text is a specification.** `CryptoError::InvalidPublicKey` reads
   "public key is not a valid **compressed** secp256k1 point" (`:31`). The error
   already claims the rule the parser did not enforce.
4. **The project only ever produces two tags.** `PrivateKey::public_key`
   (`:71-78`), `key.sign` fixtures, `PublicKey::to_sec1` and every wallet
   derivation go through `to_encoded_point(true)`, which emits `0x02`/`0x03`
   only. `0x05` appears nowhere in the production tree — it is reachable only by
   feeding hand-built bytes to the parser.
5. **The encoding is committed to, so it is consensus data.** `key_hash()` is
   `hash160(&self.bytes)` (`:132-134`), i.e. over the raw encoding, not over a
   re-derived point. A P2PKH output therefore commits to the spelling. That is
   why the encoding is a protocol fact rather than an internal detail: two
   spellings of one point are two distinct on-chain identities.
6. **The seam description already said compressed.** The differential fixture's
   own header records
   `seam=zk::SigVerifier (33-byte compressed SEC1, strict DER)`, and
   `INTERFACE_CONTRACTS.md` §3.1 documents `public_key` as "compressed SEC1
   (33 bytes)". Both were written before the parser was inspected.

**Why `0x05` is not "compressed".** SEC1 defines four tags, and they are not
synonyms: `0x02`/`0x03` are *compressed* (33 bytes, `y` parity explicit),
`0x04` is *uncompressed*, `0x06`/`0x07` are *hybrid*, and `0x05` is *compact*
(33 bytes, `y` parity fixed even). `0x05 || x` happens to denote the same curve
point as `0x02 || x`, but it is a **different encoding**, and the contract above
is written in terms of encodings. "33-byte compressed SEC1" therefore excludes
`0x05` on the plain meaning of its own words, before any library is consulted.

**Why B1's wording matters beyond length.** B1 rejects "hybrid prefixes", which
are 65 bytes and would be rejected by a length gate anyway. Naming them shows
the author intended a *tag-set* rule, not a length rule; the tag set is exactly
`0x02`/`0x03`. This record makes the implementation say what B1 meant.

## 5. Reconciling §3.3 ¶3

§3.3 ¶3 forbids a backend from being *stricter than the reference* on inputs the
reference accepts and verifies, and it provides that a vector, not an argument,
decides a contested boundary. It is a rule about **parity with the reference**;
it is not a licence for the reference to accept an encoding outside its own
documented key type. Its own example — "a backend that rejects an unusual-but-
valid encoding is not equivalent" — presupposes a definition of *valid*, and B1
supplied that definition from the beginning.

With P-1 recorded:

* B1 is the definition of validity (33 bytes, tag `0x02`/`0x03`, on curve).
* §3.3 ¶3 still binds every backend: a backend may not reject anything P-1
  admits, and may not accept anything P-1 excludes.
* S3's reject row for `0x05` stops describing an aspiration and starts
  describing the reference.
* The three statements are now mutually consistent, and the differential matrix
  is the mechanical check that they stay that way.

Before P-1 there were two coherent readings — "compressed means 0x02/0x03" and
"compressed means anything the parser decompresses" — and the code implemented
the second while the documents described the first. P2.8 removes the ambiguity
rather than picking a side silently.

## 6. Consensus implications

**What changes.** The accepted set of public-key encodings loses exactly one
class: 33-byte strings tagged `0x05`.

* **Output creation is unaffected.** No key is parsed when a `scriptPubKey` is
  built; a `hash160` commitment is opaque bytes. No coinbase, funding
  transaction or wallet script changes classification. `PublicKey` had to exist
  as a valid key before its hash could be committed to, so a compact-locked
  output was only ever constructible by a party that first parsed `0x05`
  somewhere.
* **Spend validation changes only for those outputs.** A spend that pushes
  `0x05 || x` against `DUP HASH160 <hash160(0x05||x)> EQUALVERIFY CHECKSIG` was
  accepted and is now rejected at `from_sec1`, before the curve check. The
  script fails as `EvalFalse` under `ScriptInvalid`, which is the same error
  surface `OP_CHECKSIG` already produces for an invalid signature.
* **Nothing else moves.** The signature equation, the low-S policy, DER
  strictness, the sighash preimage, transaction and block serialisation, the
  UTXO state root and the genesis rules are untouched. `from_sec1` is the only
  changed predicate.

**Reachability of the changed predicate.** Every route into key parsing funnels
through `PublicKey::from_sec1`:

```text
connect_block (chain.rs:274) / validate_transaction (chain.rs:406)
  -> apply_transaction (utxo.rs:191)
  -> script::verify (utxo.rs:231 -> script.rs:69)
  -> OP_CHECKSIG (script.rs:157-162)
  -> TxSigChecker::check_signature (sighash.rs:114)
  -> PublicKey::from_sec1 (sighash.rs:126)          <-- the gate
  -> PublicKey::verify (secp256k1.rs:148)

PublicKey::deserialize (secp256k1.rs:230-236)       <-- same gate
Message::Share payout key (network/message.rs)      <-- same gate
```

One predicate therefore covers the script path, the persisted/JSON path and the
wire path; no caller needed a second check, and none was added.

## 7. Activation

There is no production chain to activate on.

* `README.md` states "Mainnet is not launched" and that "the mainnet genesis
  nonce has not yet been pinned"; pinning it is listed as a launch prerequisite,
  not as completed work.
* The only pinned mainnet genesis artefact is
  `GENESIS_PREIMAGE_DIGEST_MAINNET`, the *nonce-independent* preimage digest.
  `GENESIS_HASH_REGTEST` and `GENESIS_HASH_DEVNET` are pinned, but they belong to
  test networks whose genesis is solved deterministically at the network floor.
* **Genesis cannot depend on this contract at all.** `genesis_coinbase()` has no
  outputs (`genesis.rs`: "Block 0 has *no outputs*"), so block 0 contains no
  `scriptPubKey`, no `hash160` commitment and no public key. Changing which
  encodings `from_sec1` admits cannot move `GENESIS_COINBASE_TXID`,
  `GENESIS_MERKLE_ROOT` or any genesis hash.
* No production protocol release exists: P0–P2 produced evidence and test
  harnesses, not a shipped node; the C++ backend is not in the production path
  and P3 has not started.

So the corrected contract takes effect **at the reference, before genesis**. It
needs no activation height, no protocol-version gate and no coordinated upgrade,
because there is no accepted history for it to reinterpret.

**The one residual case is a local datadir.** `Chain::open` verifies the genesis
hash and then loads the stored blocks and UTXO set without replaying them, so a
datadir written by an earlier build keeps its history. Any output already spent
from it stays spent; any *unspent* output locked to `hash160(0x05 || x)` becomes
permanently unspendable. Such an output cannot come from the wallet, which only
ever emits `to_encoded_point(true)` (`0x02`/`0x03`), so it required deliberate
hand-crafting or a prior `Message::Share` with a `0x05` payout. Discarding
regtest/devnet datadirs is sufficient; no migration is defined or needed.

If a genesis nonce or a production chain is ever pinned before this change is
released, this section is void and a coordinated consensus-upgrade plan is
required instead. No activation height is invented here, and no claim is made
that a split is impossible — only that there is currently nothing to split.

## 8. Non-claims

This record does **not** claim:

* that `0x05` acceptance was exploitable for theft or forgery — it was not; the
  affected set is spends from outputs already locked to a compact spelling;
* that any historical block, transaction or stored wallet state is now invalid —
  none exists in a published chain, and the one local-state case (an unspent
  compact-locked output in an old datadir) is described in §7;
* that libsecp256k1 defines ZeroCoin's consensus rules — it does not; it is one
  independent witness that the two readings differ, and the decision above rests
  on §4;
* that the Rust and C++ implementations are fully compatible — one case improved
  from divergent to agreeing; the rest of G2c, S5 and P3 are unchanged;
* that G2c, gate G2 or the P2 exit criteria are closed.
