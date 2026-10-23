#!/usr/bin/env python3
"""Replay the P3.1A header corpus against the C++ kernel.

test/p31-vectors/chain/ holds the two files the Rust reference exports for the
header slice: `header_preimage.json` (10 cases) and `header_identity.json`
(9 cases). Neither is reachable from the P0 harness, which dispatches by case-id
namespace and registers no verifier for these groups, so this wrapper is the
only consumer of every expected byte in them.

Unlike the P0 corpora this one lives outside `test/vectors`, so it takes its own
`--vectors` root and gets its own ctest entry. One corpus case maps to exactly
one fixture case: the exporter already split the preimage field by field into
single-value cases, so there is no expansion to keep honest here. Instead the
count check is per file, and every published expected key is either mapped or
named in DEFERRED_KEYS below — an unrecognised key fails the gate rather than
being quietly dropped.

Usage:
  python kernel/tools/p31_conformance.py --vectors test/p31-vectors --runner <exe>
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

SOURCE_FILES = (
    "chain/header_preimage.json",
    "chain/header_identity.json",
)

# One fixture case per corpus case, so the expected count is the corpus count.
EXPECTED_FILE_CASES = {
    "chain/header_preimage.json": 10,
    "chain/header_identity.json": 9,
}
EXPECTED_CASE_COUNT = sum(EXPECTED_FILE_CASES.values())

# The operation each file drives.
OP_BY_FILE = {
    "chain/header_preimage.json": "header_preimage",
    "chain/header_identity.json": "header_identity",
}

# Expected keys this milestone deliberately does not replay, with the reason
# printed at the end of every run. INTERFACE_CONTRACTS.md §12 requires the
# deferral list to stay explicit: a silent skip is how a corpus stops proving.
DEFERRED_KEYS = {
    "preimage_digest": (
        "sha256d of the preimage, which is a header hash. Header hashing and "
        "engine dispatch are outside P3.1B (CPP_PORT_REQUIREMENTS.md C-4), and the "
        "block's own identity is engine.hash(preimage, nonce), not this. The bytes it "
        "digests are replayed in full by preimage_hex."
    ),
}

# The two values the validator is handed, as opposed to the header's own fields.
VALIDATOR_INPUTS = ("expected_chain", "expected_height")

# The header field names, in the order the exporter publishes them.
HEADER_FIELDS = (
    "version",
    "chain",
    "height",
    "previous_hash_hex",
    "merkle_root_hex",
    "timestamp",
    "difficulty_bits",
    "engine_id",
    "nonce",
)


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


def error_kind(value: object) -> str:
    """The corpus uses JSON null for "no error"; the runner names kNone."""
    return "None" if value is None else text(value)


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


# --- corpus -> fixture -------------------------------------------------------


def header_inputs(payload: dict, prefix: str) -> list[tuple[str, str]]:
    missing = [name for name in HEADER_FIELDS if name not in payload]
    if missing:
        raise MappingError(f"header is missing {missing}")
    extra = sorted(set(payload) - set(HEADER_FIELDS))
    if extra:
        raise MappingError(f"header has unmapped fields {extra}; map them or defer them")
    return [(prefix + name, text(payload[name])) for name in HEADER_FIELDS]


def split_expected(expected: dict, mapped: set[str], case_id: str) -> list[str]:
    """Returns the deferred keys and refuses to drop an unrecognised one."""
    unknown = sorted(set(expected) - mapped - set(DEFERRED_KEYS))
    if unknown:
        raise MappingError(f"{case_id}: expected keys {unknown} are neither mapped nor deferred")
    return sorted(key for key in expected if key in DEFERRED_KEYS)


def map_preimage(case: dict) -> FixtureCase:
    expected = case["expected"]
    if "preimage_len" not in expected or "preimage_hex" not in expected:
        raise MappingError(f"{case['id']}: expected has no preimage_hex/preimage_len")
    hex_length = len(expected["preimage_hex"])
    if hex_length % 2 != 0:
        raise MappingError(f"{case['id']}: preimage_hex has an odd length")
    if hex_length // 2 != expected["preimage_len"]:
        raise MappingError(
            f"{case['id']}: preimage_hex is {hex_length // 2} bytes, not the published "
            f"{expected['preimage_len']}"
        )
    mapped = {"preimage_hex", "preimage_len"}
    if "tag_hex" in expected:
        mapped.add("tag_hex")
    deferred = split_expected(expected, mapped, case["id"])

    outputs = [
        ("preimage_hex", text(expected["preimage_hex"])),
        ("preimage_len", text(expected["preimage_len"])),
    ]
    if "tag_hex" in expected:
        if not expected["preimage_hex"].startswith(expected["tag_hex"]):
            raise MappingError(f"{case['id']}: preimage_hex does not begin with tag_hex")
        outputs.append(("tag_hex", text(expected["tag_hex"])))
    return FixtureCase(
        case["id"], "header_preimage", header_inputs(case["input"], ""), outputs, deferred
    )


def map_identity(case: dict) -> FixtureCase:
    case_id = case["id"]
    expected = case["expected"]
    split_expected(expected, {"accepted", "error_kind", "error_payload"}, case_id)

    payload = case["input"]
    if "header" not in payload:
        raise MappingError(f"{case_id}: input has no header")
    missing = [name for name in VALIDATOR_INPUTS if name not in payload]
    if missing:
        raise MappingError(f"{case_id}: input is missing {missing}")
    inputs = [(name, text(payload[name])) for name in VALIDATOR_INPUTS]
    inputs += header_inputs(payload["header"], "header.")

    if expected["accepted"] == (expected["error_kind"] is not None):
        raise MappingError(f"{case_id}: accepted and error_kind contradict each other")
    want = expected["error_payload"]
    if (want is not None) == expected["accepted"]:
        raise MappingError(f"{case_id}: error_payload and accepted contradict each other")

    outputs = [
        ("accepted", text(expected["accepted"])),
        ("error_kind", error_kind(expected["error_kind"])),
        ("error_payload_present", text(want is not None)),
    ]
    if want is not None:
        if set(want) != {"expected", "found"}:
            raise MappingError(f"{case_id}: error_payload keys {sorted(want)}")
        outputs.append(("error_payload_expected", text(want["expected"])))
        outputs.append(("error_payload_found", text(want["found"])))
    return FixtureCase(case_id, "header_identity", inputs, outputs, [])


MAPPERS = {
    "chain/header_preimage.json": map_preimage,
    "chain/header_identity.json": map_identity,
}


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
            cases.append(mapper(case))

    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"P3.1 covers {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )
    ids = [case.case_id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")

    header = [
        "META schema=zro-p31-fixture/1",
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
    return "META schema=zro-p31-fixture/1\n" + case.render() + "\n"


def probe_can_fail(runner: Path, cases: list[FixtureCase]) -> None:
    """Every compared value must be able to fail the run.

    One case per operation is replayed whole, then once per declared output with
    that single value corrupted. Without this the gate would also be green if the
    runner silently answered `ok` to everything, or if a key it never produced
    were quietly missing from the comparison.
    """
    probes = [next(case for case in cases if case.op == op) for op in ("header_preimage",
                                                                       "header_identity")]
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
        print(f"p31 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, fixture)
    if completed.returncode not in (0, 1):
        print(f"p31 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    results: dict[str, tuple[str, str]] = {}
    summary: re.Match[str] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                print(f"p31 conformance: malformed runner line: {line}", file=sys.stderr)
                return 2
            case_id, status = parts[1], parts[2]
            detail = parts[3] if len(parts) > 3 else ""
            if case_id in results:
                print(f"p31 conformance: duplicate result for {case_id}", file=sys.stderr)
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
        print("p31 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if missing or failed or completed.returncode != 0:
        print(
            f"p31 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)",
            file=sys.stderr,
        )
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"p31 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    print(
        f"p31 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}"
    )
    for name in SOURCE_FILES:
        count = sum(1 for case in cases if case.op == OP_BY_FILE[name])
        print(f"  {name:<32} {count}")
    deferred_cases = sum(1 for case in cases if case.deferred)
    for key, reason in DEFERRED_KEYS.items():
        print(f"  deferred {key} ({deferred_cases} cases): {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
