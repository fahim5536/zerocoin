#!/usr/bin/env python3
"""Replay the G1 slice of the P0 corpus against the C++ kernel.

The corpus in test/vectors is the oracle: this script does not recompute a
single hash, it only translates JSON cases into the line-oriented fixture that
kernel/conformance/main.cpp understands, then checks that the runner answered
every case and answered it `ok`.

Three things are enforced here so the suite cannot silently shrink:

* the G1 slice is exactly EXPECTED_CASE_COUNT cases;
* every case in the four G1 files is either mapped to an operation or listed
  as explicitly deferred, so a new corpus case fails the gate until it is
  classified;
* the manifest's own case counts agree with the files.

Usage:
  python kernel/tools/g1_conformance.py --vectors test/vectors --runner <exe>
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

# G1 covers the primitives owned by libzerocoin_kernel: hash, uint256 (compact),
# transaction and varint. Difficulty policy (params, validate_bits,
# hash_meets_target, required_work, retarget) lives in difficulty.rs and is
# deferred to G3; committed_height lives in reward.rs and is deferred to P3.
EXPECTED_CASE_COUNT = 28

G1_FILES = {
    "hash": "hash/primitives.json",
    "encoding.varint": "encoding/varint.json",
    "encoding.transaction": "encoding/transaction.json",
    "difficulty.compact": "difficulty/retarget.json",
}

DEFERRED_PREFIXES = {
    "difficulty/retarget.json": (
        "difficulty.params",
        "difficulty.validate_bits",
        "difficulty.hash_meets_target",
        "difficulty.required_work",
        "difficulty.retarget.",
    ),
}

# Expected keys the runner can produce, by operation. Anything else in a corpus
# case is a translation bug, not a value to pass through.
PRODUCIBLE_KEYS = {
    "sha256_utf8": {"sha256_hex"},
    "sha256d_utf8": {"internal_hex", "display_hex"},
    "hash160_sec1": {"hash160_hex"},
    "display_reversal": {"display_hex"},
    "varint_encode": {"bytes_hex", "length"},
    "tx_build": {
        "serialized_hex",
        "serialized_len",
        "txid_internal_hex",
        "txid_display_hex",
        "is_coinbase",
        "output_value",
        "roundtrip",
    },
    "tx_roundtrip": {
        "serialized_hex",
        "serialized_len",
        "txid_internal_hex",
        "txid_display_hex",
        "is_coinbase",
        "output_value",
        "script_sig_hex",
        "script_pubkey_hex",
        "input_count",
        "output_count",
        "version",
        "lock_time",
        "consumed",
    },
    "tx_decode_error": {"error", "consumed"},
    "compact": {"target_be_hex", "is_zero", "roundtrip_bits"},
}


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


def expected_pairs(expected: dict, op: str) -> list[tuple[str, str]]:
    """Flattens a corpus `expected` object into runner output keys."""
    pairs: list[tuple[str, str]] = []
    for key, value in expected.items():
        if key == "txid":
            pairs.append(("txid_internal_hex", value["internal_hex"]))
            pairs.append(("txid_display_hex", value["display_hex"]))
        elif key == "hash256":
            pairs.append(("internal_hex", value["internal_hex"]))
            pairs.append(("display_hex", value["display_hex"]))
        elif key == "kind":
            pairs.append(("error", value))
        elif key == "committed_height":
            # reward.rs, phase P3. The case is still covered as a parse and
            # re-serialise round trip, which is what G1 owns.
            continue
        elif key == "script_sig_hex" and op == "tx_build":
            # tx_build reads scripts from its inputs; the corpus repeats them
            # as expected output for the coinbase case, which uses
            # tx_roundtrip instead.
            raise MappingError("script_sig_hex is not a tx_build output")
        else:
            pairs.append((key, text(value)))
    allowed = PRODUCIBLE_KEYS[op]
    unknown = sorted({key for key, _ in pairs} - allowed)
    if unknown:
        raise MappingError(f"op {op} cannot produce {unknown}")
    return pairs


def tx_build_inputs(case: dict) -> list[tuple[str, str]]:
    payload = case["input"]
    inputs: list[tuple[str, str]] = [
        ("version", text(payload["version"])),
        ("lock_time", text(payload["lock_time"])),
    ]
    raw_inputs = payload["inputs"]
    if isinstance(raw_inputs, int) and raw_inputs == 0:
        raw_inputs = []
    for item in raw_inputs:
        spec = "|".join(
            [
                item["txid_hex"],
                text(item["vout"]),
                item["script_sig_hex"],
                text(item["sequence"]),
            ]
        )
        inputs.append(("in", spec))
    raw_outputs = payload["outputs"]
    if isinstance(raw_outputs, int) and raw_outputs == 0:
        raw_outputs = []
    for item in raw_outputs:
        inputs.append(("out", "|".join([text(item["value"]), item["script_pubkey_hex"]])))
    return inputs


def map_case(case: dict, relative_path: str) -> FixtureCase | None:
    case_id = case["id"]
    payload = case["input"]
    expected = case["expected"]

    if case_id.startswith("hash.sha256."):
        op = "sha256_utf8"
        inputs = [("text_utf8", payload["data_utf8"])]
    elif case_id.startswith("hash.sha256d."):
        op = "sha256d_utf8"
        inputs = [("text_utf8", payload["data_utf8"])]
    elif case_id.startswith("hash.hash160."):
        op = "hash160_sec1"
        inputs = [("pubkey_sec1_hex", payload["pubkey_sec1_hex"])]
    elif case_id.startswith("hash.display_"):
        op = "display_reversal"
        inputs = [("internal_hex", payload["internal_hex"])]
    elif case_id.startswith("encoding.varint."):
        op = "varint_encode"
        inputs = [("value", text(payload["value"]))]
    elif case_id in (
        "encoding.transaction.sample",
        "encoding.transaction.empty",
        "encoding.transaction.payment",
    ):
        op = "tx_build"
        inputs = tx_build_inputs(case)
    elif case_id == "encoding.transaction.coinbase_147":
        # The corpus input is {height, payout_scalar}, which needs secp256k1
        # key derivation (phase P2). G1 owns the codec, so the case is replayed
        # from the expected bytes: decode, re-serialise, derive the txid, read
        # the committed scripts back.
        op = "tx_roundtrip"
        inputs = [("bytes_hex", expected["serialized_hex"])]
    elif case_id == "encoding.transaction.decode_nonminimal_varint":
        op = "tx_decode_error"
        inputs = [("bytes_hex", payload["bytes_hex"])]
    elif case_id.startswith("difficulty.compact."):
        op = "compact"
        inputs = [("bits", text(payload["bits"]))]
    else:
        if relative_path in DEFERRED_PREFIXES and case_id.startswith(
            DEFERRED_PREFIXES[relative_path]
        ):
            return None
        raise MappingError(f"{relative_path}: no G1 mapping for case {case_id}")

    return FixtureCase(
        case_id=case_id, op=op, inputs=inputs, outputs=expected_pairs(expected, op)
    )


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_manifest(vectors: Path, documents: dict[str, dict]) -> str:
    manifest = load_json(vectors / "manifest.json")
    declared = {entry["path"]: entry for entry in manifest["files"]}
    total = 0
    for relative_path, document in documents.items():
        if len(document["cases"]) != document["case_count"]:
            raise MappingError(
                f"{relative_path}: case_count {document['case_count']} "
                f"but {len(document['cases'])} cases"
            )
        entry = declared.get(relative_path)
        if entry is None:
            raise MappingError(f"{relative_path}: missing from manifest.json")
        if entry["cases"] != len(document["cases"]):
            raise MappingError(
                f"{relative_path}: manifest says {entry['cases']} cases, "
                f"file has {len(document['cases'])}"
            )
        total += len(document["cases"])
    return manifest.get("source_commit", "unknown")


def build_fixture(vectors: Path) -> tuple[str, dict[str, int], str]:
    documents = {relative: load_json(vectors / relative) for relative in G1_FILES.values()}
    source_commit = check_manifest(vectors, documents)

    cases: list[FixtureCase] = []
    counts: dict[str, int] = {}
    for group, relative in G1_FILES.items():
        document = documents[relative]
        group_cases = [map_case(case, relative) for case in document["cases"]]
        kept = [case for case in group_cases if case is not None]
        counts[group] = len(kept)
        cases.extend(kept)

    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"G1 covers {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )

    ids = [case.case_id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")

    header = [
        "META schema=zro-g1-fixture/1",
        f"META source_commit={source_commit}",
        f"META cases={len(cases)}",
    ]
    body = [case.render() for case in cases]
    return "\n".join(header + body) + "\n", counts, source_commit


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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        fixture, counts, source_commit = build_fixture(args.vectors)
    except (MappingError, KeyError) as error:
        print(f"g1 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, fixture)
    if completed.returncode not in (0, 1):
        print(f"g1 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    results: dict[str, tuple[str, str]] = {}
    summary: re.Match[str] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                print(f"g1 conformance: malformed runner line: {line}", file=sys.stderr)
                return 2
            _, case_id, status = parts[0], parts[1], parts[2]
            detail = parts[3] if len(parts) > 3 else ""
            if case_id in results:
                print(f"g1 conformance: duplicate result for {case_id}", file=sys.stderr)
                return 2
            results[case_id] = (status, detail)
        elif line.startswith("SUMMARY "):
            summary = re.fullmatch(r"SUMMARY cases=(\d+) failures=(\d+)", line)

    expected_ids = [case.case_id for case in parse_fixture_ids(fixture)]
    missing = [case_id for case_id in expected_ids if case_id not in results]
    failed = [
        (case_id, detail)
        for case_id, (status, detail) in results.items()
        if status != "ok"
    ]

    if summary is None:
        print("g1 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if missing or failed or completed.returncode != 0:
        print(f"g1 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)", file=sys.stderr)
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"g1 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    print(
        f"g1 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}"
    )
    for group, count in counts.items():
        print(f"  {group:<22} {count}")
    return 0


def parse_fixture_ids(fixture: str) -> list[FixtureCase]:
    """Re-reads the rendered fixture so the check is independent of the mapping."""
    cases: list[FixtureCase] = []
    current: FixtureCase | None = None
    for line in fixture.splitlines():
        if line.startswith("CASE "):
            current = FixtureCase(case_id=line[len("CASE ") :], op="")
        elif line.startswith("OP ") and current is not None:
            current.op = line[len("OP ") :]
        elif line == "END" and current is not None:
            cases.append(current)
            current = None
    return cases


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
