# 04 — Risk register

Twelve risks, each with a trigger that can be observed rather than argued about.
Likelihood and impact are rated L / M / H for the **first C++ milestone** (P0–P5),
not for the project's whole future.

Review cadence `[PROPOSED]`: revisit at the end of every phase, and whenever a gate
fails twice for the same reason.

---

## 1. Register

### R1 — Silent consensus divergence

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | H — a fork, or a node that accepts invalid blocks |
| **Trigger** | Any mismatch in tip hash, `state_root`, `subsidy_issued`, or UTXO count during replay or soak |
| **Mitigation** | Golden vectors (P0), replay at *every* height (G4), alternating mining (mode C), differential fuzzing on invalid data (mode D), 14-day soak (G6) |
| **Residual** | Accepted until G6; no C++ binary ships before it |

The single most likely source is not a wrong algorithm but an unexamined *order*:
which check runs first, which error is returned, whether state is cloned or mutated.
`01` §4.4 records the Rust order explicitly for this reason.

### R2 — Endianness and hex-convention confusion

| | |
|---|---|
| **Likelihood** | H |
| **Impact** | H — wrong `tip` strings, wrong txids in RPC, wrong display in the GUI |
| **Trigger** | A hash that matches in C++ but "looks wrong" to `zerocoin-cli`, or vice versa |
| **Mitigation** | Distinct types in P1 (`Hash256` with explicit `storage_hex()` and `display_hex()`); no implicit `operator string`; vectors cover both directions (F3) |
| **Residual** | Low after P1, if the types are enforced by the compiler rather than by review |

This is the most *avoidable* risk on the list and the one most likely to waste a
week if left to convention.

### R3 — Scope creep into consensus changes

| | |
|---|---|
| **Likelihood** | H |
| **Impact** | H — violates requirement 6, forks the existing chain |
| **Trigger** | A pull request that adds reorg handling, RBF, lock-time enforcement, segwit, or a mempool eviction policy "while we are here" |
| **Mitigation** | Change freeze (`README.md` §5); review checklist in `05` §10; any such change requires a separate proposal and a decision about how to deploy it on a chain with no reorg path |
| **Residual** | Medium — social control only |

Note the deployment asymmetry: with no fork choice (F1), a consensus change cannot
be rolled out softly. It needs a new network, a coordinated flag day, or a version
bump with an explicit activation rule that does not yet exist. That cost is itself a
reason to keep the freeze.

### R4 — Accidental Bitcoin Core code import

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | M — licence obligations, and invisible foreign assumptions |
| **Trigger** | A C++ file whose style, naming, or comments do not match the rest of `cpp/`; a missing provenance line |
| **Mitigation** | Copying policy (`02` §4); every kernel file starts with a two-line provenance header naming the Rust file it implements; review asks "which vector proves this?" |
| **Residual** | Low |

### R5 — Scratchpad PoW performance or portability shortfall

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | M — a slower miner changes the security story; a wrong miner changes consensus |
| **Trigger** | P3 benchmark outside ±20 % of the Rust baseline, or a hash mismatch on any vector |
| **Mitigation** | Benchmark in P3 before P4; no `-ffast-math`; differential hashes on a fixed header grid; keep the trivial engine as the first, simplest proof of the interface |
| **Residual** | Accepted if within tolerance |

### R6 — Rust oracle drift during the migration

| | |
|---|---|
| **Likelihood** | H |
| **Impact** | H — the C++ port targets a moving specification |
| **Trigger** | Any commit to `zerocoin/` after P0 that changes consensus behaviour |
| **Mitigation** | Pin the audited commit (`5248b10`) in the corpus metadata; any Rust consensus change must regenerate vectors and be reviewed by both tracks in the same change |
| **Residual** | Medium — the project is actively developed by its owner |

This risk is structural: the repository is live, and the owner may change the Rust
node at any time. The mitigation is process, not code.

### R7 — Golden vectors that encode a defect as truth

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | H — the port becomes bit-compatible with a bug and the bug becomes permanent |
| **Trigger** | A vector whose value cannot be derived independently; a vector added by copying program output with no cross-check |
| **Mitigation** | Every vector carries the command that produced it *and* an independent check for small cases (a hand-computed SHA-256 of a 3-byte input, a one-leaf Merkle tree, a subsidy at height 0); consensus-critical vectors are reviewed by two people |
| **Residual** | Low for primitives, medium for policy |

The findings register (`01` §13) already lists the behaviours that are *known* to be
odd. Those are vectors where "matching Rust" is the correct choice for now and a
change proposal comes later — they must be labelled as such in the corpus, so nobody
later "fixes" a vector by accident.

### R8 — Platform and compiler variance

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | H — a hash that differs on one platform |
| **Trigger** | CI failure on one compiler or OS; UBSan finding |
| **Mitigation** | Fixed-width types everywhere; `static_assert` on sizes; no implementation-defined shifts; UBSan/ASan in CI; MSVC, GCC, Clang all in the matrix; a big-endian job if a runner is available |
| **Residual** | Low |

The kernel does not use floating point, locale, time zones, or unordered containers
for anything consensus-visible. That should stay true.

### R9 — Cryptographic library mismatch

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | H — signatures that verify in one implementation and not the other |
| **Trigger** | A cross-verification failure in G2 |
| **Mitigation** | Cross-sign and cross-verify in both directions; pin DER strictness and the high-S verdict with vectors; do not reimplement secp256k1 |
| **Residual** | Low |

Rust uses `k256`; C++ should use a vetted library (libsecp256k1 is the obvious
choice) rather than hand-written curve code. The two must agree on DER strictness,
**high-S rejection** (both reject `s > n/2`; neither normalises), and the
treatment of the recovery id.

### R10 — Storage and wallet format incompatibility

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | M — a data directory that one binary writes and the other cannot read |
| **Trigger** | Failing round-trip in G5 |
| **Mitigation** | Round-trip tests both ways for `chain.json`; cross-open tests for `wallet.json`; pin the argon2id parameters, the AAD construction, and the JSON field names |
| **Residual** | Low, if the storage encoding is treated as a compatibility surface |

This matters more than it looks: the GUI keeps running through the whole migration,
so a user may switch daemons on an existing data directory.

### R11 — New P2P attack surface

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | H — remote crash or memory exhaustion in the new node |
| **Trigger** | Fuzz finding; a frame that allocates before authenticating |
| **Mitigation** | Reproduce the Rust limits exactly (4 MiB plaintext, 500 inv, 1,000 addr, 2,000 headers, 101 locators); length checks before allocation; authenticated length only after HMAC verification; 24-hour fuzz gate at G7 |
| **Residual** | Medium until fuzzing has run in CI for a release cycle |

The Rust implementation reads a length prefix and caps it at 8 MiB before the frame
layer sees it. The C++ side must not "improve" this by trusting the plaintext length.

### R12 — Abandoned half-port and the mobile dependency

| | |
|---|---|
| **Likelihood** | M |
| **Impact** | M — a `cpp/` tree that nobody maintains, or an Android app stranded by a Rust removal |
| **Trigger** | Two consecutive phases miss their gate; Android build breaks |
| **Mitigation** | Phases are independently valuable (the kernel is a usable library at P3); Rust is never deleted (rule 3); Android keeps the Rust `cdylib` until a separate decision |
| **Residual** | Accepted |

A partially finished `cpp/` tree is not a failure if it is honest about its state.
A partially finished tree that has replaced the working node *is* a failure, which is
why cutover is the last phase and not the fifth.

---

## 2. Residual-risk summary

| Risk | After mitigation |
|---|---|
| R1 consensus divergence | Medium until G6; blocking for release |
| R2 hex conventions | Low |
| R3 scope creep | Medium (process only) |
| R4 copied code | Low |
| R5 PoW performance | Low–Medium |
| R6 oracle drift | Medium (process only) |
| R7 bad vectors | Low |
| R8 platform variance | Low |
| R9 crypto mismatch | Low |
| R10 format incompatibility | Low |
| R11 P2P attack surface | Medium until fuzzing |
| R12 abandoned port / mobile | Accepted |

No risk in this register is rated "critical" *for this milestone*, because this
milestone ships no executable code. The register exists to make P1–P8 safe, not to
justify the audit.

---

## 3. Risks deliberately not mitigated

| Risk | Why it is not mitigated |
|---|---|
| The chain can stall on a height collision (F1) | Fixing it is a consensus change; out of scope by requirement 6 |
| The mempool can be exhausted by a local attacker (F6) | Same |
| The wallet is single-key and unbacked by an HD scheme (F15) | Same; a UX and product decision, not a port decision |
| The scratchpad PoW is unaudited (F9) | A cryptographic audit is a separate engagement; the port only preserves it |
| RPC is unauthenticated (F10) | Loopback-only by construction; hardening would change the operational contract |

Each of these is recorded so that a reader of the migration documents cannot
mistake silence for endorsement.
