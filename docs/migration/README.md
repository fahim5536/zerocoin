# ZeroCoin — C++ migration programme

This directory holds the **milestone 1** deliverable of the ZeroCoin architecture
migration: a complete audit of the existing Rust implementation, a study of Bitcoin
Core used strictly as an educational reference, and a phased plan to build an
independent C++ implementation beside the Rust one.

> **Status: documents 01–05 are documentation only; 06 records phase P0 and 07
> records phase P1 (kernel primitives, gate G1).**
> No Rust source file was modified, moved, or deleted. The Rust crate remains the
> reference implementation and the only thing that currently produces blocks.
> The C++ kernel is built by developers and CI only and is never shipped.
>
> P0 added one Rust integration-test target (`zerocoin/tests/export_baseline_vectors.rs`)
> and a standard-library-only Python harness under `test/`. Neither is part of the
> node build. `06` records what they prove and what is still missing.
>
> The consensus audit added `docs/consensus/` — the audited consensus
> specification and the C++ port requirements — plus one more integration-test
> target (`zerocoin/tests/consensus_rules.rs`). No Rust source file was modified
> and the P0 corpus was not regenerated. It is not one of the numbered port
> phases in `03` §4.
>
> P1 (`03` §4) added the dependency-free C++ kernel under `kernel/` and its gate,
> `scripts/gate-g1.ps1`. `07` records what it proves and what it does not.
>
> P2 (`03` §4) added the script interpreter, sighash and signature-verification
> seam. `08` records it: 21 of 23 corpus cases replay, and the two that need
> secp256k1 stay deferred as G2c because no vetted backend is present on the host.
>
> P2.1 added `docs/architecture/` — ownership, the three-language boundary,
> interface contracts, the roadmap and the backend decision record. It changed no
> code, no vector and no guard count.
>
> P2.2 reviewed backend readiness and recorded **NO-GO** for G2c: the Rust
> reference rejects high-S signatures, the documented wrapper normalised them,
> and one deferred fixture needs signing rather than verification. It changed
> documentation only; no dependency was obtained and no gate count moved.

---

## 1. Evidence labels

Every factual statement in these documents carries one of three labels.

| Label | Meaning | How to check it |
|---|---|---|
| `[VERIFIED]` | Read directly from the source tree at the commit named below, or produced by running a command whose output is quoted. | Re-run the command in section 3, or open the cited file. |
| `[PROPOSED]` | A recommendation of this plan. Not implemented, not agreed, not tested. | Discussion / future milestone. |
| `[UNVERIFIED]` | An assumption, an inference, or something that could not be established from the repository. | Must be proven before anything depends on it. |

Anything not labelled is explanatory prose about labelled facts. Where a claim
sounds like a guarantee ("the chain never reorganises"), the supporting finding is
listed in the register in `01-architecture-audit.md` §13 and is a description of
observed code, not a design endorsement.

---

## 2. Baseline snapshot

| Item | Value |
|---|---|
| Repository | `https://github.com/fahim5536/zerocoin.git` |
| Branch | `main` |
| Audited commit | `5248b10d69c12f4d0af332afb5e67c43605c220c` (`Update README.md`) |
| Crate | `zerocoin` 0.1.0, Rust edition 2021, MSRV 1.75, MIT |
| Rust source | 36 files — 14,986 lines physical, 13,649 non-blank `[VERIFIED]` |
| UI source | `zerocoin/ui/wallet.slint` — 1,314 lines physical, 1,157 non-blank `[VERIFIED]` |
| Test functions | 235 `#[test]` functions in 28 modules `[VERIFIED]` |
| Test result | `235 passed; 0 failed; 0 ignored` in 49.21 s `[VERIFIED]` |
| CI | none — no `.github/` directory exists `[VERIFIED]` |
| Integration-test crate | none — no `tests/` directory exists `[VERIFIED]` |

Toolchain used to produce the evidence:

```
cargo 1.99.1 (5f94df478 2026-08-27)
rustc 1.99.1 (58cf8f9c3 2026-10-13)
cmake version 4.4.3
Python 3.15.0
git version 2.55.0.windows.5
```

The Rust toolchain is addressed explicitly as `+stable-x86_64-pc-windows-gnu`
because that is the toolchain the project is built with on this machine; the
default host triple has no usable linker here.

---

## 3. Reproducing the evidence

From the repository root (the crate lives in `zerocoin/`):

```powershell
# 1. Unit + property tests, all targets
$env:CARGO_TARGET_DIR = "d:\Downloads\zerocoin\target"
cargo +stable-x86_64-pc-windows-gnu test --all-targets

# 2. Documentation tests (expected: zero, the crate has no doctests)
cargo +stable-x86_64-pc-windows-gnu test --doc

# 3. End-to-end proof of the zero-premine genesis and the 100-block maturity rule
#    (expects zerocoind.exe and zerocoin-cli.exe in zerocoin\target\debug)
powershell -NoProfile -ExecutionPolicy Bypass -File .\demos\regtest-maturity.ps1

# 4. Source size table
Get-ChildItem -Recurse -Filter *.rs src |
  ForEach-Object { (Get-Content -LiteralPath $_.FullName | Measure-Object -Line).Lines } |
  Measure-Object -Sum

# 5. Gate G1: build the C++ kernel and replay its corpus slice
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\gate-g1.ps1
```

The observed output of step 3 is transcribed in `01-architecture-audit.md` §12 and
is the strongest single piece of behavioural evidence in this audit: it pins the
genesis block hash, the zero-premine property, and the exact maturity boundary
(height 101 unlocks the coinbases of heights 1 and 2).

`CARGO_TARGET_DIR` is redirected outside the crate so that no build artefact can
ever be mistaken for a source change; the crate's own `target/` is git-ignored.

---

## 4. Document index

| # | Document | Answers |
|---|---|---|
| 01 | [Architecture audit](01-architecture-audit.md) | What does the Rust implementation actually do, module by module, and where are the gaps? |
| 02 | [Bitcoin Core reference study](02-bitcoin-core-reference-study.md) | What is worth imitating in Bitcoin Core's *shape*, and what must not be assumed? |
| 03 | [Module mapping and phased plan](03-module-mapping-and-phased-plan.md) | Which Rust module becomes which C++ module, in what order, gated by what? |
| 04 | [Risk register](04-risk-register.md) | What can go wrong, how would we notice, and what do we do about it? |
| 05 | [Test strategy](05-test-strategy.md) | How do we prove the C++ implementation is equivalent before it is trusted? |
| 06 | [P0 baseline vectors](06-p0-baseline-vectors.md) | Which values must a port reproduce byte for byte, how were they proven, and what is still missing? |
| 07 | [P1 kernel primitives](07-kernel-primitives-g1.md) | Which C++ primitives exist, how is the P0 corpus replayed against them, and what did gate G1 measure? |
| 08 | [P2 script, sighash and secp256k1](08-kernel-script-sighash-secp256k1-p2.md) | Which ledger semantics were ported, what is deferred behind G2c, and what does the P2 replay prove? |
| ARCH | [Architecture set](../architecture/COMPONENT_OWNERSHIP.md) | Who owns each subsystem, what may Rust/C++/Go do, what crosses an interface boundary, and when is temporary compatibility code removed? |
| READY | [Crypto backend readiness review](../architecture/CRYPTO_BACKEND_READINESS.md) | Why is G2c blocked, what does the reference actually do about high-S, what must a backend prove, and is it safe to proceed? |
| P1 | [Consensus rules](../consensus/CONSENSUS_RULES.md) · [C++ port requirements](../consensus/CPP_PORT_REQUIREMENTS.md) | What exactly does consensus require today, with which source references, and what must a C++ port match? |

---

## 5. What this milestone deliberately does not do

Requirement 6 of the task freezes consensus during audit and planning. Concretely,
this work asserts and preserves the following, and any proposal that would change
one of them is out of scope until a separate, explicit decision is taken:

- the three network definitions (chain ids, PoW engines, difficulty parameters,
  address prefixes, ports) `[VERIFIED]` in `zerocoin/src/params.rs`;
- block subsidy, halving interval, supply ceiling, and the 100-block coinbase
  maturity rule `[VERIFIED]` in `zerocoin/src/consensus/reward.rs`;
- the block header layout, its domain-separated preimage, and the PoW engines
  `[VERIFIED]` in `zerocoin/src/consensus/block.rs` and `consensus/pow.rs`;
- the transaction serialisation, the chain-bound sighash, and the script subset
  `[VERIFIED]` in `zerocoin/src/ledger/`;
- the P2P handshake, frame format, and message set `[VERIFIED]` in
  `zerocoin/src/network/`;
- the genesis block, including its empty output list `[VERIFIED]` in
  `zerocoin/src/genesis.rs`;
- the pinned boot anchors `[VERIFIED]` in `zerocoin/src/consensus/immutability.rs`.

The plan in `03` therefore treats the Rust implementation as a **specification by
execution**: the C++ code must reproduce byte-for-byte what Rust produces. Where
the Rust behaviour looks like a defect (see the findings register), the defect is
recorded and fixed *in both implementations together, in a later, explicit
consensus-change milestone* — never silently inside the port.

---

## 6. How to read the rest of the plan

1. Read `01` §13 (findings register) first if you only have five minutes: it is the
   list of things that will bite a reimplementation.
2. Read `03` §4 (phase gates) second: it defines what "done" means for each phase.
3. Read `05` §2 (golden vector corpus) third: it is the concrete artefact the first
   phase of work produces.

The single rule that governs the whole programme:

> The Rust node keeps working, and keeps being the only node that can produce a
> valid block, until the C++ node has been proven equivalent by the gates in `05`.
> Nothing is deleted to make the port easier.
