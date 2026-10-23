#!/usr/bin/env python3
"""Replay the P3 difficulty slice of the P0 corpus against the C++ kernel.

test/vectors/difficulty/retarget.json holds 15 cases. Nine of them are the
compact-encoding cases G1 already replays through the `compact` operation; the
other six are the difficulty policy that `g1_conformance.py` names as deferred to
G3. This wrapper owns those six, expands them into one fixture case per published
value (18 in total) and checks the runner answered every one of them `ok`.

Three things are enforced so the slice cannot silently shrink:

* the P3 slice is exactly EXPECTED_CASE_COUNT cases;
* every case in the file is either G1's compact case or one of the six policy
  cases, so a corpus change fails the gate until it is classified;
* the manifest's case count and source commit agree with the file, and one
  deliberately corrupted case proves the comparison can fail.

Usage:
  python kernel/tools/p3_conformance.py --vectors test/vectors --runner <exe>
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

SOURCE_FILE = "difficulty/retarget.json"

# The six cases g1_conformance.py defers to G3, in corpus order.
POLICY_CASES = (
    "difficulty.params",
    "difficulty.validate_bits",
    "difficulty.hash_meets_target",
    "difficulty.required_work",
    "difficulty.retarget.clamps",
    "difficulty.retarget.at_floor",
)

# How many fixture cases each corpus case expands into.
EXPANSION = {
    "difficulty.params": 1,
    "difficulty.validate_bits": 4,
    "difficulty.hash_meets_target": 1,
    "difficulty.required_work": 4,
    "difficulty.retarget.clamps": 7,
    "difficulty.retarget.at_floor": 1,
}

EXPECTED_CASE_COUNT = sum(EXPANSION.values())

# Replayed by the G1 wrapper; counted here only so the file is fully classified.
G1_COMPACT_PREFIX = "difficulty.compact."
G1_CASE_COUNT = 9

# A case the runner must answer, used to prove the comparison can fail.
PROBE_SIGNATURE = "difficulty.p3.probe"


@dataclass
class FixtureCase:
    case_id: str
    op: str
    inputs: list[tuple[str, str]] = field(default_factory=list)
    outputs: list[tuple[str, str]] = field(default_factory=list)

    def render(self) -> str:
        lines = [f"CASE {self.case_id}", f"OP {self.op}"]
        lines += [f"IN {key}={value}" for key, value in self.inputs]
        lines += [f"OUT {key}={value}" for key, value in self.outputs]
        lines.append("END")
        return "\n".join(lines)


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


def error_kind(value: object) -> str:
    """The corpus uses JSON null for "no error"; the runner names kNone."""
    return "None" if value is None else text(value)


def sorted_pairs(expected: dict) -> list[tuple[str, str]]:
    return [(key, text(expected[key])) for key in sorted(expected)]


# --- corpus -> fixture -------------------------------------------------------


def map_params(case: dict) -> list[FixtureCase]:
    network = case["input"]["network"]
    if not isinstance(network, str) or not network.strip():
        raise MappingError("difficulty.params: input.network is empty")
    return [FixtureCase("difficulty.params", "difficulty_params", [], sorted_pairs(case["expected"]))]


def map_validate_bits(case: dict) -> list[FixtureCase]:
    pow_limit_bits = case["input"]["pow_limit_bits"]
    specs = case["input"]["bits"]
    expected = case["expected"]
    if set(specs) != set(expected):
        raise MappingError(
            f"difficulty.validate_bits: input bits {sorted(specs)} "
            f"do not match expected {sorted(expected)}"
        )
    cases = []
    for name, bits in specs.items():
        want = expected[name]
        if want["bits"] != bits:
            raise MappingError(f"difficulty.validate_bits.{name}: expected.bits != input.bits")
        cases.append(
            FixtureCase(
                f"difficulty.validate_bits.{name}",
                "difficulty_validate_bits",
                [("bits", text(bits)), ("pow_limit_bits", text(pow_limit_bits))],
                [
                    ("bits", text(want["bits"])),
                    ("error_kind", error_kind(want["error_kind"])),
                    ("ok", text(want["ok"])),
                ],
            )
        )
    return cases


def map_hash_meets_target(case: dict) -> list[FixtureCase]:
    return [
        FixtureCase(
            "difficulty.hash_meets_target",
            "difficulty_hash_meets_target",
            [("bits", text(case["input"]["bits"]))],
            sorted_pairs(case["expected"]),
        )
    ]


def map_required_work(case: dict) -> list[FixtureCase]:
    specs = case["input"]["bits"]
    expected = case["expected"]
    if set(specs) != set(expected):
        raise MappingError(
            f"difficulty.required_work: input bits {sorted(specs)} "
            f"do not match expected {sorted(expected)}"
        )
    return [
        FixtureCase(
            f"difficulty.required_work.{name}",
            "difficulty_required_work",
            [("bits", text(bits))],
            [("work_be_hex", text(expected[name]))],
        )
        for name, bits in specs.items()
    ]


def map_retarget_clamps(case: dict) -> list[FixtureCase]:
    cases = []
    for name, want in case["expected"].items():
        cases.append(
            FixtureCase(
                f"difficulty.retarget.clamps.{name}",
                "difficulty_next",
                [
                    ("prev_bits", text(want["prev_bits"])),
                    ("actual_window_seconds", text(want["actual_window_seconds"])),
                ],
                [
                    ("next_bits", text(want["next_bits"])),
                    ("next_target_be_hex", text(want["next_target_be_hex"])),
                ],
            )
        )
    return cases


def map_retarget_at_floor(case: dict) -> list[FixtureCase]:
    payload = case["input"]
    return [
        FixtureCase(
            "difficulty.retarget.at_floor",
            "difficulty_next",
            [
                ("prev_bits", text(payload["prev_bits"])),
                ("actual_window_seconds", text(payload["actual_window_seconds"])),
            ],
            [("next_bits", text(case["expected"]["next_bits"]))],
        )
    ]


MAPPERS = {
    "difficulty.params": map_params,
    "difficulty.validate_bits": map_validate_bits,
    "difficulty.hash_meets_target": map_hash_meets_target,
    "difficulty.required_work": map_required_work,
    "difficulty.retarget.clamps": map_retarget_clamps,
    "difficulty.retarget.at_floor": map_retarget_at_floor,
}


# --- checks ------------------------------------------------------------------


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_manifest(vectors: Path, document: dict) -> str:
    manifest = load_json(vectors / "manifest.json")
    declared = {entry["path"]: entry for entry in manifest["files"]}
    entry = declared.get(SOURCE_FILE)
    if entry is None:
        raise MappingError(f"{SOURCE_FILE}: missing from manifest.json")
    if document["case_count"] != len(document["cases"]):
        raise MappingError(
            f"{SOURCE_FILE}: case_count {document['case_count']} "
            f"but {len(document['cases'])} cases"
        )
    if entry["cases"] != len(document["cases"]):
        raise MappingError(
            f"{SOURCE_FILE}: manifest says {entry['cases']} cases, "
            f"file has {len(document['cases'])}"
        )
    commit = manifest.get("source_commit")
    if not commit or commit == "unknown":
        raise MappingError("manifest.json: no source_commit")
    if document.get("source_commit") != commit:
        raise MappingError(
            f"{SOURCE_FILE}: source_commit {document.get('source_commit')} "
            f"!= manifest {commit}"
        )
    return commit


def build_fixture(vectors: Path) -> tuple[str, str]:
    document = load_json(vectors / SOURCE_FILE)
    source_commit = check_manifest(vectors, document)

    by_id: dict[str, dict] = {}
    for case in document["cases"]:
        if case["id"] in by_id:
            raise MappingError(f"{SOURCE_FILE}: duplicate case id {case['id']}")
        if not case.get("independent_check"):
            raise MappingError(f"{SOURCE_FILE}: {case['id']} has no independent_check")
        by_id[case["id"]] = case

    compact = sorted(case_id for case_id in by_id if case_id.startswith(G1_COMPACT_PREFIX))
    if len(compact) != G1_CASE_COUNT:
        raise MappingError(
            f"{SOURCE_FILE}: {len(compact)} compact cases, expected {G1_CASE_COUNT}; "
            "update the G1 wrapper before changing the split"
        )

    cases: list[FixtureCase] = []
    for case_id in POLICY_CASES:
        if case_id not in by_id:
            raise MappingError(f"{SOURCE_FILE}: missing policy case {case_id}")
        produced = MAPPERS[case_id](by_id[case_id])
        if len(produced) != EXPANSION[case_id]:
            raise MappingError(
                f"{case_id}: produced {len(produced)} cases, expected {EXPANSION[case_id]}"
            )
        cases.extend(produced)

    unclassified = sorted(set(by_id) - set(compact) - set(POLICY_CASES))
    if unclassified:
        raise MappingError(f"{SOURCE_FILE}: no P3 classification for {unclassified}")

    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"P3 covers {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )

    ids = [case.case_id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")

    header = [
        "META schema=zro-p3-fixture/1",
        f"META source_commit={source_commit}",
        f"META cases={len(cases)}",
    ]
    body = [case.render() for case in cases]
    return "\n".join(header + body) + "\n", source_commit


def probe_can_fail(runner: Path) -> None:
    """A wrong expected value must fail, and the right one must pass.

    Without this the gate would also be green if the runner silently answered
    `ok` to everything.
    """
    def fixture(next_bits: int) -> str:
        lines = [
            "META schema=zro-p3-fixture/1",
            f"CASE {PROBE_SIGNATURE}",
            "OP difficulty_next",
            "IN prev_bits=469827583",
            "IN actual_window_seconds=86400",
            f"OUT next_bits={next_bits}",
            "END",
        ]
        return "\n".join(lines) + "\n"

    wrong = run_fixture(runner, fixture(0))
    if wrong.returncode != 1:
        raise MappingError(
            f"corruption probe: runner exited {wrong.returncode} on a wrong value, expected 1"
        )
    if f"RESULT {PROBE_SIGNATURE} fail" not in wrong.stdout:
        raise MappingError("corruption probe: runner did not report the wrong value")

    right = run_fixture(runner, fixture(469827583))
    if right.returncode != 0 or f"RESULT {PROBE_SIGNATURE} ok" not in right.stdout:
        raise MappingError("corruption probe: runner did not accept the known-good value")


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


def fixture_ids(fixture: str) -> list[str]:
    """Re-reads the rendered fixture so the check is independent of the mapping."""
    return [line[len("CASE ") :] for line in fixture.splitlines() if line.startswith("CASE ")]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        fixture, source_commit = build_fixture(args.vectors)
        probe_can_fail(args.runner)
    except (MappingError, KeyError) as error:
        print(f"p3 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, fixture)
    if completed.returncode not in (0, 1):
        print(f"p3 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    results: dict[str, tuple[str, str]] = {}
    summary: re.Match[str] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                print(f"p3 conformance: malformed runner line: {line}", file=sys.stderr)
                return 2
            case_id, status = parts[1], parts[2]
            detail = parts[3] if len(parts) > 3 else ""
            if case_id in results:
                print(f"p3 conformance: duplicate result for {case_id}", file=sys.stderr)
                return 2
            results[case_id] = (status, detail)
        elif line.startswith("SUMMARY "):
            summary = re.fullmatch(r"SUMMARY cases=(\d+) failures=(\d+)", line)

    expected_ids = fixture_ids(fixture)
    missing = [case_id for case_id in expected_ids if case_id not in results]
    failed = [
        (case_id, detail)
        for case_id, (status, detail) in results.items()
        if status != "ok"
    ]

    if summary is None:
        print("p3 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if missing or failed or completed.returncode != 0:
        print(f"p3 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)", file=sys.stderr)
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"p3 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    print(
        f"p3 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}"
    )
    for case_id in POLICY_CASES:
        print(f"  {case_id:<32} {EXPANSION[case_id]}")
    print(f"  {G1_COMPACT_PREFIX + '*':<32} {G1_CASE_COUNT} (replayed by G1)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
