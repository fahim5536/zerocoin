#!/usr/bin/env python3
"""Replay the P3.2B leaf-level Merkle corpus against the C++ kernel.

test/p32-vectors/chain/ holds the one file the Rust reference exports for this
slice: `merkle_root.json` (20 cases). It is unreachable from the P0 harness,
which dispatches by case-id namespace and registers no verifier for the
`chain.merkle_root.*` group, so this wrapper is the only consumer of every
expected byte in it.

Two things are checked before the runner is ever invoked, and they are different
checks:

  1. the corpus is internally sound — manifest totals, per-file case counts,
     case-id prefixes, duplicates, leaf widths, root width, the display/internal
     pair, and the frozen contract constants;
  2. the corpus agrees with a genuinely independent implementation —
     test/harness/zro_vectors.py::merkle_root, a dependency-free Python
     re-derivation that shares no code with kernel/src/merkle.cpp and is not
     called by the runner.

A failure in either is reported as a mapping failure (exit 2), never as a root
mismatch: a malformed or self-inconsistent fixture must not be able to look like
a C++ bug. The Rust exporter stays the authority for the expected values; the
Python verifier only proves that what it published is reproducible by something
that is neither Rust nor this kernel.

Nothing is deferred. Every key the corpus publishes is replayed byte for byte,
so DEFERRED_KEYS is empty and stays that way on purpose — an added deferral must
be a documented decision, not a way to keep the gate green.

Usage:
  python kernel/tools/p32_conformance.py --vectors test/p32-vectors --runner <exe>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_FILES = ("chain/merkle_root.json",)

# One fixture case per corpus case: the leaf list goes in as repeated IN lines,
# so there is no expansion here that could silently drop a case.
EXPECTED_FILE_CASES = {"chain/merkle_root.json": 20}
EXPECTED_CASE_COUNT = sum(EXPECTED_FILE_CASES.values())

# The operation the file drives.
OP_BY_FILE = {"chain/merkle_root.json": "merkle_root"}

# Nothing is deferred by this milestone. Kept as a dict, rather than omitted, so
# `split_expected` still refuses to drop an unrecognised expected key and a
# future deferral has to be written down here to take effect.
DEFERRED_KEYS: dict[str, str] = {}

# The contract the exporter freezes in manifest.json, restated here so a corpus
# that quietly changes shape fails instead of being replayed wrongly.
EXPECTED_CONTRACT = {
    "leaf_width_bytes": 32,
    "internal_node_input_bytes": 64,
    "empty_tree_tag_bytes": 17,
}
EXPECTED_EMPTY_TAG_HEX = "5a524f2f6d65726b6c653a656d70747900"

# The keys a case's `expected` object must carry, and the keys its `input` object
# must carry. Anything else is unmapped and fails.
EXPECTED_KEYS = ("root", "root_len")
INPUT_KEYS = ("leaf_count", "leaves")
ROOT_KEYS = ("internal_hex", "display_hex")

# The independent verifier lives in the repository's P0 harness. Resolved from
# this script's own location, so it does not move with --vectors.
HARNESS_DIR = Path(__file__).resolve().parents[2] / "test" / "harness"


@dataclass
class FixtureCase:
    case_id: str
    op: str
    inputs: list[tuple[str, str]] = field(default_factory=list)
    outputs: list[tuple[str, str]] = field(default_factory=list)
    deferred: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"CASE {self.case_id}", f"OP {self.op}"]
        lines += [f"IN {key}={value}" for key, value in self.inputs]
        lines += [f"OUT {key}={value}" for key, value in self.outputs]
        lines.append("END")
        return "\n".join(lines)

    def with_corrupted_output(self, key: str, value: str) -> "FixtureCase":
        outputs = [(name, value if name == key else had)
                   for name, had in self.outputs]
        return FixtureCase(self.case_id, self.op, list(self.inputs), outputs, list(self.deferred))


class MappingError(RuntimeError):
    pass


def text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise MappingError(f"cannot render {type(value).__name__} as fixture text")


def one_line(value: str) -> str:
    return " ".join(value.split())[:240]


def corrupted(value: str) -> str:
    """A value the runner cannot agree with, in the same shape as the real one."""
    if value in ("true", "false"):
        return "false" if value == "true" else "true"
    if re.fullmatch(r"[0-9]+", value):
        return str(int(value) + 1)
    if re.fullmatch(r"[0-9a-f]+", value):
        return value[:-1] + ("0" if value[-1] != "0" else "1")
    return value + "-corrupted"


# --- independent verifier ----------------------------------------------------


def load_python_verifier():
    """Imports the P0 harness's Merkle implementation.

    It is the same module `test/harness/run_vectors.py` uses to check the five
    historical `chain.merkle.*` cases, so it predates this corpus and shares no
    code with the kernel. Failing to import it is a gate failure, not a skip: a
    run without the cross-check would silently be a weaker run.
    """
    if not (HARNESS_DIR / "zro_vectors.py").is_file():
        raise MappingError(f"independent verifier not found at {HARNESS_DIR / 'zro_vectors.py'}")
    if str(HARNESS_DIR) not in sys.path:
        sys.path.insert(0, str(HARNESS_DIR))
    try:
        import zro_vectors  # type: ignore
    except Exception as error:  # pragma: no cover - import failure is a gate failure
        raise MappingError(f"independent verifier failed to import: {error}") from error
    function = getattr(zro_vectors, "merkle_root", None)
    if function is None:
        raise MappingError("independent verifier has no merkle_root")
    tag = getattr(zro_vectors, "EMPTY_MERKLE_TAG", None)
    if not isinstance(tag, (bytes, bytearray)):
        raise MappingError("independent verifier has no EMPTY_MERKLE_TAG")
    if len(tag) != EXPECTED_CONTRACT["empty_tree_tag_bytes"]:
        raise MappingError(
            f"independent verifier tag is {len(tag)} bytes, expected "
            f"{EXPECTED_CONTRACT['empty_tree_tag_bytes']}"
        )
    if tag.hex() != EXPECTED_EMPTY_TAG_HEX:
        raise MappingError(
            f"independent verifier tag {tag.hex()} != corpus tag {EXPECTED_EMPTY_TAG_HEX}"
        )
    return function


# --- corpus -> fixture -------------------------------------------------------


def internal_hex(value: object, case_id: str, what: str) -> str:
    """A strict 32-byte internal digest, or a mapping failure."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise MappingError(
            f"{case_id}: {what} is not 64 lowercase hex characters (32 bytes): {value!r}"
        )
    return value


def split_expected(expected: dict, mapped: set[str], case_id: str) -> list[str]:
    """Returns the deferred keys and refuses to drop an unrecognised one."""
    overlap = sorted(mapped & set(DEFERRED_KEYS))
    if overlap:
        raise MappingError(f"{case_id}: keys {overlap} are both mapped and deferred")
    unknown = sorted(set(expected) - mapped - set(DEFERRED_KEYS))
    if unknown:
        raise MappingError(f"{case_id}: expected keys {unknown} are neither mapped nor deferred")
    return sorted(key for key in expected if key in DEFERRED_KEYS)


def map_merkle(case: dict, verify) -> FixtureCase:
    case_id = case["id"]
    payload = case["input"]
    expected = case["expected"]

    missing = [key for key in INPUT_KEYS if key not in payload]
    if missing:
        raise MappingError(f"{case_id}: input is missing {missing}")
    extra = sorted(set(payload) - set(INPUT_KEYS))
    if extra:
        raise MappingError(f"{case_id}: input keys {extra} are unmapped; map them or defer them")

    raw_leaves = payload["leaves"]
    if not isinstance(raw_leaves, list):
        raise MappingError(f"{case_id}: input.leaves is {type(raw_leaves).__name__}, not a list")
    declared_count = payload["leaf_count"]
    if not isinstance(declared_count, int) or declared_count != len(raw_leaves):
        raise MappingError(
            f"{case_id}: input.leaf_count {declared_count!r} but {len(raw_leaves)} leaves present"
        )

    # Every leaf is validated to exactly 32 bytes here, before the runner is
    # invoked, so an over- or under-width leaf is a fixture defect and never
    # reaches the kernel as a padded value that could still hash to something.
    leaves: list[bytes] = []
    inputs: list[tuple[str, str]] = []
    for index, leaf in enumerate(raw_leaves):
        if not isinstance(leaf, dict) or set(leaf) != set(ROOT_KEYS):
            raise MappingError(f"{case_id}: leaf {index} keys {sorted(leaf) if isinstance(leaf, dict) else leaf!r}")
        internal = internal_hex(leaf["internal_hex"], case_id, f"leaf {index} internal_hex")
        display = leaf["display_hex"]
        if not isinstance(display, str) or display != bytes.fromhex(internal)[::-1].hex():
            raise MappingError(f"{case_id}: leaf {index} display_hex is not the internal bytes reversed")
        leaves.append(bytes.fromhex(internal))
        inputs.append(("leaf", internal))

    unknown = sorted(set(expected) - set(EXPECTED_KEYS))
    if unknown:
        raise MappingError(f"{case_id}: expected keys {unknown} are unmapped; map them or defer them")
    for key in EXPECTED_KEYS:
        if key not in expected:
            raise MappingError(f"{case_id}: expected has no {key}")

    root = expected["root"]
    if not isinstance(root, dict) or set(root) != set(ROOT_KEYS):
        raise MappingError(f"{case_id}: expected.root keys {sorted(root) if isinstance(root, dict) else root!r}")
    root_internal = internal_hex(root["internal_hex"], case_id, "expected root internal_hex")
    root_display = root["display_hex"]
    if not isinstance(root_display, str) or root_display != bytes.fromhex(root_internal)[::-1].hex():
        raise MappingError(f"{case_id}: expected root display_hex is not the internal bytes reversed")

    root_len = expected["root_len"]
    if not isinstance(root_len, int) or root_len != 32 or root_len * 2 != len(root_internal):
        raise MappingError(
            f"{case_id}: expected root_len {root_len!r} does not match a 32-byte internal digest"
        )

    # The independent cross-check, on the corpus's own inputs. A disagreement here
    # means the fixture is wrong and the C++ kernel must not be blamed for it.
    derived = verify(leaves).hex()
    if derived != root_internal:
        raise MappingError(
            f"{case_id}: the independent Python verifier derives {derived} but the corpus "
            f"publishes {root_internal}; the fixture is at fault, not the kernel"
        )

    outputs = [
        ("internal_hex", root_internal),
        ("display_hex", root_display),
        ("root_len", text(root_len)),
        # Not a corpus value: the wrapper's own accounting of how many leaves it
        # handed over, which the runner must echo back.
        ("leaf_count", str(len(leaves))),
    ]
    deferred = split_expected(expected, set(EXPECTED_KEYS), case_id)
    return FixtureCase(case_id, "merkle_root", inputs, outputs, deferred)


MAPPERS = {"chain/merkle_root.json": map_merkle}


# --- checks ------------------------------------------------------------------


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_manifest(vectors: Path, documents: dict[str, dict]) -> str:
    manifest = load_json(vectors / "manifest.json")
    declared = {entry["path"]: entry for entry in manifest["files"]}
    commit = manifest.get("source_commit")
    if not commit or commit == "unknown":
        raise MappingError("manifest.json: no source_commit")
    if sorted(declared) != sorted(SOURCE_FILES):
        raise MappingError(
            f"manifest.json lists {sorted(declared)}, this wrapper consumes "
            f"{sorted(SOURCE_FILES)}"
        )

    contract = manifest.get("contract")
    if not isinstance(contract, dict):
        raise MappingError("manifest.json: no contract object")
    for key, want in EXPECTED_CONTRACT.items():
        if contract.get(key) != want:
            raise MappingError(f"manifest.json: contract {key} is {contract.get(key)!r}, expected {want}")
    if contract.get("empty_tree_tag_hex") != EXPECTED_EMPTY_TAG_HEX:
        raise MappingError(
            f"manifest.json: empty_tree_tag_hex {contract.get('empty_tree_tag_hex')!r} "
            f"!= {EXPECTED_EMPTY_TAG_HEX}"
        )

    provenance = manifest.get("provenance")
    if not isinstance(provenance, str) or "merkle_root" not in provenance:
        raise MappingError("manifest.json: provenance does not name the producing Rust function")

    total = 0
    for name, document in documents.items():
        entry = declared[name]
        if document["group"] != entry["group"]:
            raise MappingError(f"{name}: group {document['group']} != manifest {entry['group']}")
        if document["case_count"] != len(document["cases"]):
            raise MappingError(
                f"{name}: case_count {document['case_count']} but {len(document['cases'])} cases"
            )
        if entry["cases"] != len(document["cases"]):
            raise MappingError(
                f"{name}: manifest says {entry['cases']} cases, file has {len(document['cases'])}"
            )
        if document.get("source_commit") != commit:
            raise MappingError(
                f"{name}: source_commit {document.get('source_commit')} != manifest {commit}"
            )
        total += len(document["cases"])

    declared_total = manifest.get("total_cases")
    if declared_total != total:
        raise MappingError(f"manifest.json: total_cases {declared_total} but {total} cases present")
    return commit


def build_fixture(vectors: Path) -> tuple[str, list[FixtureCase], str]:
    documents = {name: load_json(vectors / name) for name in SOURCE_FILES}
    source_commit = check_manifest(vectors, documents)
    verify = load_python_verifier()

    cases: list[FixtureCase] = []
    for name in SOURCE_FILES:
        document = documents[name]
        if len(document["cases"]) != EXPECTED_FILE_CASES[name]:
            raise MappingError(
                f"{name}: {len(document['cases'])} cases, expected "
                f"{EXPECTED_FILE_CASES[name]}; update this wrapper before changing the corpus"
            )
        mapper = MAPPERS[name]
        seen_in_file: set[str] = set()
        for case in document["cases"]:
            case_id = case["id"]
            if not case_id.startswith(document["group"] + "."):
                raise MappingError(f"{case_id}: outside its file's group {document['group']}")
            if case_id in seen_in_file:
                raise MappingError(f"{name}: duplicate case id {case_id}")
            seen_in_file.add(case_id)
            if not case.get("independent_check"):
                raise MappingError(f"{case_id}: no independent_check")
            if case.get("intent") not in ("rule", "oddity"):
                raise MappingError(f"{case_id}: unknown intent {case.get('intent')!r}")
            cases.append(mapper(case, verify))

    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"P3.2 covers {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )
    ids = [case.case_id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")

    header = [
        "META schema=zro-p32-fixture/1",
        f"META source_commit={source_commit}",
        f"META cases={len(cases)}",
    ]
    return "\n".join(header + [case.render() for case in cases]) + "\n", cases, source_commit


def run_fixture(runner: Path, fixture: str) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".fixture", delete=False
    ) as handle:
        handle.write(fixture)
        fixture_path = Path(handle.name)
    try:
        return subprocess.run(
            [str(runner), str(fixture_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        fixture_path.unlink(missing_ok=True)


def single_case_fixture(case: FixtureCase) -> str:
    return "META schema=zro-p32-fixture/1\n" + case.render() + "\n"


def probe_can_fail(runner: Path, cases: list[FixtureCase]) -> None:
    """Every compared value must be able to fail the run.

    The empty case and a multi-leaf case are each replayed whole, then once per
    declared output with that single value corrupted. The empty case is probed
    separately because it carries no IN line at all, so a runner that ignored its
    input entirely would still have to disagree with `internal_hex`. Without the
    probe, a runner that answered `ok` to everything would keep this gate green.
    """
    probes = [
        next(case for case in cases if case.case_id == "chain.merkle_root.empty"),
        next(case for case in cases if case.case_id == "chain.merkle_root.three_leaves"),
    ]
    for probe in probes:
        right = run_fixture(runner, single_case_fixture(probe))
        if right.returncode != 0 or f"RESULT {probe.case_id} ok" not in right.stdout:
            raise MappingError(
                f"corruption probe: runner rejected the known-good case {probe.case_id}: "
                f"{one_line(right.stdout)} {one_line(right.stderr)}"
            )
        for key, value in probe.outputs:
            mutated = probe.with_corrupted_output(key, corrupted(value))
            wrong = run_fixture(runner, single_case_fixture(mutated))
            if wrong.returncode != 1:
                raise MappingError(
                    f"corruption probe: runner exited {wrong.returncode} on a wrong "
                    f"{key} for {probe.case_id}, expected 1"
                )
            if f"RESULT {probe.case_id} fail" not in wrong.stdout:
                raise MappingError(
                    f"corruption probe: runner did not report the wrong {key} for "
                    f"{probe.case_id}"
                )


def fixture_ids(fixture: str) -> list[str]:
    """Re-reads the rendered fixture so the check is independent of the mapping."""
    return [line[len("CASE ") :] for line in fixture.splitlines() if line.startswith("CASE ")]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        fixture, cases, source_commit = build_fixture(args.vectors)
        probe_can_fail(args.runner, cases)
    except (MappingError, KeyError, StopIteration) as error:
        print(f"p32 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, fixture)
    if completed.returncode not in (0, 1):
        print(f"p32 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    results: dict[str, tuple[str, str]] = {}
    summary: re.Match[str] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                print(f"p32 conformance: malformed runner line: {line}", file=sys.stderr)
                return 2
            case_id, status = parts[1], parts[2]
            detail = parts[3] if len(parts) > 3 else ""
            if case_id in results:
                print(f"p32 conformance: duplicate result for {case_id}", file=sys.stderr)
                return 2
            results[case_id] = (status, detail)
        elif line.startswith("SUMMARY "):
            summary = re.fullmatch(r"SUMMARY cases=(\d+) failures=(\d+)", line)

    expected_ids = fixture_ids(fixture)
    missing = [case_id for case_id in expected_ids if case_id not in results]
    unknown = sorted(case_id for case_id in results if case_id not in set(expected_ids))
    failed = [
        (case_id, detail)
        for case_id, (status, detail) in results.items()
        if status != "ok"
    ]

    if summary is None:
        print("p32 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if unknown:
        print(f"p32 conformance: runner answered unknown cases: {unknown}", file=sys.stderr)
        return 1
    if missing or failed or completed.returncode != 0:
        print(
            f"p32 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)",
            file=sys.stderr,
        )
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"p32 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    print(
        f"p32 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}"
    )
    for name in SOURCE_FILES:
        count = sum(1 for case in cases if case.op == OP_BY_FILE[name])
        print(f"  {name:<32} {count}")
    deferred_cases = sum(1 for case in cases if case.deferred)
    print(
        f"  deferred keys: none ({deferred_cases} cases carry a deferred key); "
        "every published expected value is replayed"
    )
    print(f"  independent verifier: {HARNESS_DIR / 'zro_vectors.py'}::merkle_root, "
          f"{EXPECTED_CASE_COUNT} roots re-derived from the corpus inputs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
