#!/usr/bin/env python3
"""P4.2B-4E: diff the C++ ScratchPad engine against the oracle at low_spec().

`ScratchPadEngine::low_spec()` is the one production profile the block-structure
corpus could not previously reach: 512 MiB of pad and 2,048 rounds, budgeted from
`LOW_SPEC_SCRATCHPAD_BYTES = 512 * 1024 * 1024` in `zerocoin/src/consensus/pow.rs`.
This wrapper hashes the same bytes twice, once in the shipping kernel through
`zk::PowEngine::hash` and once in the independent reference
`test/harness/zro_vectors.py::scratchpad_hash`, and fails if the two digests differ.

The direction of derivation, stated once:

  * every `OUT` value comes from the Python oracle, which reads the preset table
    and the input bytes and shares no code with kernel/src/;
  * the kernel is never asked what it thinks before an expectation is written;
  * the budget itself is read from the oracle's `SCRATCHPAD_PRESETS`, so a kernel
    that hashed a different pad length or round count would produce a different
    digest and fail -- there is no code path here that could agree with a wrong
    profile.

The two cheaper profiles are replayed in the same run as controls. They are not
padding: `low_spec()`, `balanced()` and `mainnet()` all report engine id 1 and the
name `scratchpad-memory-hard`, so "the name matched" is worthless evidence. What
distinguishes them is the digest, and only a run that produces all three from the
same preimage shows the kernel resolving them differently.

Cost, measured rather than assumed. One low-spec hash is ~24 s in Python and, in
the Debug kernel this milestone builds, ~75 s in C++; the balanced and mainnet
controls are milliseconds. The budget is not reduced to make the gate cheap,
because a smaller pad would stop modelling the production engine and the digests
would then describe something the chain never runs.

Usage:
  python kernel/tools/p42e_low_spec_differential.py --runner .build/p42b3-kernel/kernel_conformance.exe

Exit codes: 0 agrees, 1 disagrees, 2 the run itself could not be performed.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parents[2] / "test" / "harness"

# The preset tokens, spelled exactly as the Rust source names them. A typo here is
# a missing key in the oracle's table, which is a hard error rather than a skip.
LOW_SPEC = "ScratchPadEngine::low_spec()"
BALANCED = "ScratchPadEngine::balanced()"
MAINNET = "ScratchPadEngine::mainnet()"

# The published `zerocoin-pow` preimage from test/vectors/pow/engines.json, so this
# run shares its input bytes with vectors the corpus already pins. ASCII, hex below.
PREIMAGE = b"zerocoin-pow"
PREIMAGE_HEX = PREIMAGE.hex()
NONCE = 1

# Every profile gets a row. `low_spec` is the milestone; the other two are the
# controls that stop "the digest matched" from being satisfied by substitution.
VECTORS = (BALANCED, MAINNET, LOW_SPEC)


class DifferentialError(RuntimeError):
    """The run could not be performed at all, as opposed to a disagreement."""


def load_oracle():
    """Import the reference and freeze the names this differential depends on."""
    path = HARNESS_DIR / "zro_vectors.py"
    if not path.is_file():
        raise DifferentialError(f"oracle not found at {path}")
    if str(HARNESS_DIR) not in sys.path:
        sys.path.insert(0, str(HARNESS_DIR))
    try:
        import zro_vectors  # type: ignore
    except Exception as error:  # pragma: no cover - an import failure is a failure
        raise DifferentialError(f"oracle failed to import: {error}") from error

    required = ("SCRATCHPAD_PRESETS", "SCRATCHPAD_ENGINE_NAME", "ENGINE_ID_SCRATCHPAD",
                "SCRATCHPAD_CELL", "scratchpad_hash")
    missing = [name for name in required if not hasattr(zro_vectors, name)]
    if missing:
        raise DifferentialError(f"oracle is missing {missing}")
    return zro_vectors


def render(case_id: str, inputs: list[tuple[str, str]], outputs: list[tuple[str, str]]) -> str:
    """The fixture dialect `kernel/conformance` reads."""
    lines = [f"CASE {case_id}", "OP pow_scratchpad_hash"]
    lines += [f"IN {key}={value}" for key, value in inputs]
    lines += [f"OUT {key}={value}" for key, value in outputs]
    lines.append("END")
    return "\n".join(lines) + "\n"


def run_fixture(runner: Path, fixture: str) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n",
                                     suffix=".fixture", delete=False) as handle:
        handle.write(fixture)
        fixture_path = Path(handle.name)
    try:
        return subprocess.run([str(runner), str(fixture_path)],
                              capture_output=True, text=True, check=False)
    finally:
        fixture_path.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runner", required=True, type=Path,
                        help="the kernel_conformance binary")
    args = parser.parse_args(argv)

    if not args.runner.is_file():
        print(f"low-spec differential: no runner at {args.runner}", file=sys.stderr)
        return 2

    try:
        oracle = load_oracle()
        budgets = {preset: oracle.SCRATCHPAD_PRESETS[preset] for preset in VECTORS}
    except DifferentialError as error:
        print(f"low-spec differential: {error}", file=sys.stderr)
        return 2

    digests = {preset: budgets[preset] for preset in VECTORS}
    fixtures = []
    for preset in VECTORS:
        memory_bytes, rounds = budgets[preset]
        cells = max(memory_bytes // oracle.SCRATCHPAD_CELL, 1)
        digest = oracle.scratchpad_hash(PREIMAGE, NONCE, memory_bytes, rounds)
        print(f"{preset}")
        print(f"  budget      : {memory_bytes} bytes, {rounds} rounds, {cells} cells")
        print(f"  preimage_hex: {PREIMAGE_HEX}")
        print(f"  nonce       : {NONCE}")
        print(f"  internal_hex: {digest.hex()}")
        fixtures.append(render(
            f"p42e.low_spec.{preset.split('::')[-1].rstrip('()')}",
            [
                ("preimage_hex", PREIMAGE_HEX),
                ("nonce", str(NONCE)),
                ("engine_id", str(oracle.ENGINE_ID_SCRATCHPAD)),
                ("engine_name", oracle.SCRATCHPAD_ENGINE_NAME),
                ("memory_bytes", str(memory_bytes)),
                ("rounds", str(rounds)),
            ],
            [
                ("internal_hex", digest.hex()),
                ("cell_count", str(cells)),
            ],
        ))
        digests[preset] = digest.hex()

    if len(set(digests.values())) != len(VECTORS):
        print("low-spec differential: FAIL — the presets collapsed onto one digest", file=sys.stderr)
        for preset, digest in digests.items():
            print(f"  {preset}: {digest}", file=sys.stderr)
        return 1

    completed = run_fixture(args.runner, "\n".join(fixtures))
    if completed.returncode not in (0, 1):
        print(f"low-spec differential: the runner exited {completed.returncode} "
              "instead of reporting a verdict per case", file=sys.stderr)
        print(completed.stderr.strip(), file=sys.stderr)
        return 2

    expected_ok = {f"RESULT p42e.low_spec.{preset.split('::')[-1].rstrip('()')} ok"
                   for preset in VECTORS}
    reported_ok = {line.strip() for line in completed.stdout.splitlines()
                   if line.strip().startswith("RESULT ") and line.strip().endswith(" ok")}
    missing = sorted(expected_ok - reported_ok)
    if missing or completed.returncode != 0:
        print("low-spec differential: FAIL — the kernel disagreed with the oracle", file=sys.stderr)
        if missing:
            print(f"  cases the kernel did not report ok: {missing}", file=sys.stderr)
        for line in (completed.stdout + completed.stderr).splitlines():
            if line.strip() and not line.strip().startswith("RESULT "):
                print(f"  {line.strip()}", file=sys.stderr)
        return 1

    print()
    print(f"low-spec differential: PASS ({len(VECTORS)} cases, "
          f"{len(set(digests.values()))} distinct digests)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
