# Three-language architecture

Status: **as-built** at commit `e8fda7e` (2026-10-18), written during P2.1.
Describes what Rust, C++ and Go are each allowed to do in this repository, how
they depend on each other, and how the boundaries are enforced. It creates no
Go service and changes no code.

Related: `COMPONENT_OWNERSHIP.md` (who owns each subsystem),
`INTERFACE_CONTRACTS.md` (the interfaces at the boundaries),
`MIGRATION_ROADMAP.md` (phase order and removal criteria).

---

## 1. Roles

| Language | Role | Authority | Ships today |
|---|---|---|---|
| **Rust** | Reference implementation and the only released node | Every consensus rule, every wallet format, every RPC field | Yes — `zerocoind`, `zerocoin-cli`, `zerocoin-gui` |
| **C++20** | Compatibility-tested kernel, later a candidate daemon | None of its own; must reproduce Rust byte for byte | No — developer and CI only (`kernel/CMakeLists.txt` line 1) |
| **Go** | Planned networking and service infrastructure | None; a client of the node's RPC | No code exists |
| **Python 3.11+** | Test orchestration, vector capture, conformance mapping | The fixture format and the gate wiring, never a consensus value | Tooling only, never shipped |
| **PowerShell / shell** | Gate, CI steps | Exit codes, not logic | `scripts/gate-g1.ps1` |

The one-sentence contract: **Rust defines correctness, C++ proves it is
reproducible, Go operates it, Python measures it.** Go is not a second consensus
engine and C++ is not a second source of truth.

---

## 2. As-built layout

```text
zerocoin/                  Rust crate — reference and release
├── src/                   consensus, ledger, crypto, network, wallet, GUI
├── ui/wallet.slint        Slint front-end (owned by Rust, never ported)
├── tests/                 Rust integration tests
├── Cargo.toml, Cargo.lock k256 0.13.4 is the curve implementation
└── demos/, DEVNET_GUIDE.md, MOBILE_BUILD.md

kernel/                    C++20 kernel — developer/CI build, never shipped
├── CMakeLists.txt         target zerocoin_kernel, kernel_tests, kernel_conformance
├── include/zerocoin/      hash, hex, uint256, varint, transaction, script, sighash
├── src/                   the nine translation units of the kernel
├── tests/                 unit tests, warnings-as-errors
├── conformance/main.cpp   15-verb JSON runner
└── tools/                 g1_conformance.py, p2_conformance.py

test/
├── harness/               Python vector capture and replay
└── vectors/               committed corpus, pinned to source_commit

scripts/gate-g1.ps1        the gate: configure, build, ctest, replay, Rust, P0
docs/migration/            01–08: audit, study, plan, risk, tests, P0, G1, P2
docs/architecture/         this set
.build/                    git-ignored build output
```

The Rust crate sits at `zerocoin/` inside the published repository and at the
workspace root in the development tree; both are the same source. The kernel
sits at `kernel/`, which is a divergence from doc `03` §2's proposed `cpp/`
(§9 below).

---

## 3. Dependency direction

```text
                    +---------------------------+
                    |   Python harness + gate   |
                    +------------+--------------+
                                 | runs binaries, reads JSON
              +------------------+------------------+
              |                                     |
     +--------v--------+                  +---------v---------+
     |  Rust reference |                  |   C++ kernel      |
     |  (release)      |                  |   (CI only)       |
     +--------+--------+                  +---------+---------+
              |                                     |
   RustCrypto crates                    vetted curve library (future, G2c)
   (k256, sha2, ripemd,                 -- not linked today; the seam
    aes-gcm, argon2, hkdf)                 fails closed
              |
              | JSON-RPC (the only supported remote surface)
              |
     +--------v---------+
     |  Go services     |   planned: clients, never validators
     |  (none exist)    |
     +------------------+
```

Rules for the arrows:

1. **Python may run either binary.** It may not link kernel code or reimplement a
   step to make a test pass.
2. **C++ may not depend on Rust.** A C++ build must work with CMake and a C++
   compiler alone; linking a Rust staticlib would make the kernel unbuildable in
   the environments it exists to serve.
3. **Rust may not depend on C++.** The reference stays buildable with Cargo only.
4. **Go may depend only on the node's RPC.** Not on storage files, not on a
   shared library, not on a consensus header.
5. **The corpus depends on Rust and is consumed by everyone.** It is the only
   shared artefact, and it is data, not code.

---

## 4. Capability matrix

| Capability | Rust | C++ | Go | Python |
|---|---|---|---|---|
| Define consensus semantics | **yes, sole owner** | no | no | no |
| Implement consensus code | yes | yes, as a derived implementation per phase | **no** | no |
| Serialize blocks/transactions/scripts | yes | yes, byte-identical | **no** | only to build fixtures from Rust output |
| Verify signatures | yes (`k256`) | planned, vetted library only | **no** | no |
| Generate or hold keys | yes (wallet, keystore) | P5, same format | **no** | no |
| Serve JSON-RPC | yes (12 methods) | P5 | no — consumes it | no |
| P2P networking | yes | P5 | planned services may *observe* via RPC, not peer | no |
| GUI | yes (Slint) | never | no | no |
| Build/test orchestration | no | CMake | no | **yes** |
| Operate a node | ships it | candidate at P5 | may supervise processes only | no |

"Planned services may observe via RPC" is deliberate: a Go metrics exporter,
indexer or faucet reads chain state through RPC and never touches `chain.json`,
`wallet.json` or the wire protocol.

---

## 5. Release model

- Every published binary is Rust until G8 (doc `03` §1 rule 1).
- `kernel/` is built by developers and CI; `zerocoin_kernel` is a static library
  with no install rule and no packaging target.
- The GUI and the Android `cdylib` remain Rust regardless of G8's outcome
  (doc `03` §3.3).
- A C++ daemon, if G8 ever chooses one, must pass G5–G7 first; until then there
  is no "C++ release" to roll back.

---

## 6. Toolchain as-built

| Tool | Version observed on 2026-10-19 | Used for |
|---|---|---|
| CMake | 4.4.3 (project floor 3.20) | configure and ctest |
| Ninja | generator used by the gate | build |
| g++ (MinGW-W64 UCRT, POSIX threads) | 16.2.0 | C++20 kernel, `-Wall -Wextra -Wpedantic -Werror` |
| cargo (stable, `x86_64-pc-windows-gnu`) | 1.99.1 | Rust suite, 7 targets |
| Python | 3.15.0 | harness, conformance wrappers, P0 verifier |
| PowerShell | 5.1 | `scripts/gate-g1.ps1` |

The C++ standard is C++20 with extensions off. MSVC is supported by the build
file (`/W4 /WX`) but is not exercised by this gate; that becomes a G7 obligation.

---

## 7. Go: planned scope and hard limits

No Go code exists in this repository, and P2.1 does not create any. The role is
recorded now so that when the first service is proposed, its boundary is already
defined.

**Permitted, each behind its own ADR:**

- an indexer or explorer that consumes JSON-RPC and keeps its own derived
  database, clearly labelled as non-authoritative and rebuildable;
- a faucet or testnet utility that asks a node to send a transaction through
  RPC, holding no consensus logic;
- a metrics/status exporter that polls RPC;
- deployment, release and CI tooling that operates binaries without parsing
  consensus objects;
- an RPC load balancer or proxy that forwards bytes without interpreting them.

**Forbidden without exception:**

- parsing, validating or re-serializing blocks, transactions, scripts, sighashes
  or proofs;
- opening `chain.json`, `wallet.json` or any keystore directly;
- implementing key derivation, signing, hashing-for-consensus or address
  encoding;
- acting as a peer on the P2P protocol, or defining a second wire format;
- any rule that could disagree with the Rust node about validity.

**Requirements for the first Go service:**

1. It must name the RPC methods it uses and pin the field names and units from
   `INTERFACE_CONTRACTS.md` §8.
2. It must fail closed: if a field is missing or a unit changed, it refuses to
   start rather than guessing.
3. It must be removable without touching Rust or C++ (no shared library, no
   shared schema file that a consensus component reads).
4. It must state its own version and the node version it was tested against.

Transport TLS and HTTP inside a Go service may use the standard library. That is
transport security, not consensus cryptography, and it never produces a value
that a block or transaction commits to.

---

## 8. How the boundary is enforced

| Mechanism | What it prevents | Where |
|---|---|---|
| Ownership table | A subsystem with two authorities | `COMPONENT_OWNERSHIP.md` §2 |
| Conformance gates | A derived implementation drifting silently | `scripts/gate-g1.ps1`, ctest |
| Vector provenance | Hand-edited or stale fixtures | `source_commit` in every wrapper output |
| Corruption self-check | A wrapper that always passes | P2 replay rejects 21/21 corrupted cases |
| Warnings-as-errors | Undefined behaviour creeping into the kernel | `kernel/CMakeLists.txt` |
| No-dependency kernel | A second copy of a crypto primitive appearing | `kernel/CMakeLists.txt` links nothing |
| Review checklist | An unowned or duplicated component | `COMPONENT_OWNERSHIP.md` §6 |

A new library in the kernel is an architecture change, not a build tweak: it
must appear in `CRYPTO_BACKEND_DECISION.md` (or a successor ADR) before it
appears in `CMakeLists.txt`.

---

## 9. Divergences from the doc `03` proposal

Doc `03` is a proposal written before any C++ file existed. The tree diverged in
five places. Each is recorded here rather than silently "fixed", because the
proposal is the historical record of the plan.

| Doc `03` proposal | As built | Consequence |
|---|---|---|
| C++ root at `cpp/` | `kernel/` at the repository root | Same ownership boundary; the removal story is identical (`kernel/` can be deleted without touching Rust). Doc `03` §2 is not rewritten. |
| `scripts/build.sh`, `test.sh`, `parity.sh` | one `scripts/gate-g1.ps1` | Windows is the development host; the gate is a single command with an exit code. Shell scripts arrive with CI (P7). |
| CMake ≥ 3.25 | floor 3.20, built with 4.4.3 | Nothing in the kernel needs 3.25. Raising the floor is a build-policy decision; recorded in `MIGRATION_ROADMAP.md` §8. |
| `cmake/Sanitizers.cmake`, `Secp256k1.cmake` | not created | Sanitizers are a G7 obligation; `Secp256k1.cmake` appears only when a backend is authorised. |
| `test/functional/` + `test_framework/` | `test/harness/` + `test/vectors/` | The harness is Python either way; the path differs. G5 will add the functional layer. |

None of the divergences changes a semantic rule. The one that matters for
reviewers is the first: **the C++ tree is `kernel/`, not `cpp/`.**

---

## 10. Change control

- Adding a language or a toolchain to the shipped product requires an ADR and a
  gate; P2.1 adds neither.
- Adding a Go service requires the ADR described in §7 and a row in
  `COMPONENT_OWNERSHIP.md` §2.3; it never requires a change to Rust.
- Moving a boundary (for example, letting the C++ kernel link a library) requires
  the interface contract to be updated first.
- Removing the C++ tree is always allowed and is the defined rollback
  (`MIGRATION_ROADMAP.md` §7).
