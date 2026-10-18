#!/usr/bin/env python3
"""Replay the P2 slice of the P0 corpus against the C++ kernel.

P2 owns the script interpreter and the signature hasher. Two corpus cases in
this group need a secp256k1 backend that is not linked in this phase
(`ledger.script.p2pkh_spend_accepted` and `ledger.sighash.signature_der`); they
are deferred by name and counted here, so the slice cannot shrink silently.

The corpus is the oracle and this script never trusts the kernel to grade
itself. Before rendering the fixture it re-derives, from the documented rules
alone, the expected minimal pushes, the P2PKH scripts, the preimage framing, the
digest = sha256d(preimage) relation, and the digest display reversal. Only then
does it ask the runner to reproduce them.

Finally it corrupts every expected value and requires the runner to reject all
cases with exit code 1, proving the comparison step is live.

Usage:
  python kernel/tools/p2_conformance.py --vectors test/vectors --runner <exe>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# The P2 slice: the ten-opcode interpreter and the chain-bound sighash.
P2_FILES = {
    "ledger.script": "ledger/script.json",
    "ledger.sighash": "ledger/sighash.json",
}

# 14 of 15 script cases and 7 of 8 sighash cases; the two crypto cases below
# account for the difference.
EXPECTED_CASE_COUNT = 21

DEFERRED_CASES = {
    "ledger.script.p2pkh_spend_accepted": (
        "requires secp256k1 ECDSA verification; no vetted curve backend is linked (G2c)"
    ),
    "ledger.sighash.signature_der": (
        "requires RFC 6979 deterministic ECDSA over secp256k1 (G2c)"
    ),
}

# Every script rejection the interpreter can report, mirrored from script.h.
SCRIPT_ERRORS = {
    "None",
    "ScriptTooLarge",
    "TooManyOps",
    "StackOverflow",
    "StackUnderflow",
    "ElementTooLarge",
    "EvalFalse",
    "VerifyFailed",
    "EqualVerifyFailed",
    "Truncated",
    "UnsupportedOpcode",
}

SIGHASH_TAG = b"ZRO/sighash/v1\0"
STABILITY_PAIR_IDS = (
    "ledger.sighash.regtest_index_0",
    "ledger.sighash.regtest_index_1",
    "ledger.sighash.mainnet_chain_binding",
    "ledger.sighash.type_02_is_folded_in",
)


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


def minimal_push(payload: bytes) -> bytes:
    """The documented encoding: inline below 0x4c, PUSHDATA1 to 0xff, else PUSHDATA2."""
    size = len(payload)
    if size < 0x4C:
        return bytes([size]) + payload
    if size <= 0xFF:
        return b"\x4c" + bytes([size]) + payload
    return b"\x4d" + size.to_bytes(2, "little") + payload


def tx_input_count(encoded: bytes) -> int:
    """Reads version then the varint input count; independent of the kernel."""
    if len(encoded) < 5:
        raise MappingError("transaction is too short to hold a version and a count")
    first = encoded[4]
    if first < 0xFD:
        return first
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    end = 5 + width
    if len(encoded) < end:
        raise MappingError("transaction ends inside its input count")
    return int.from_bytes(encoded[5:end], "little")


def check_push_vectors(lengths: list[int], expected: dict) -> None:
    """Each expected script must equal the minimal push of a uniform 0xab payload."""
    keys = {f"len_{length}" for length in lengths}
    if set(expected) != keys:
        raise MappingError(
            f"push_data.lengths: expected keys {sorted(keys)}, found {sorted(expected)}"
        )
    for length in lengths:
        want = minimal_push(bytes([0xAB]) * length).hex()
        if expected[f"len_{length}"] != want:
            raise MappingError(
                f"push_data.lengths: len_{length} is not the minimal push of {length} bytes"
            )


def check_script_pubkey_vector(pubkey_hash_hex: str, expected: dict) -> None:
    want = "76a914" + pubkey_hash_hex + "88ac"
    if expected.get("script_hex") != want:
        raise MappingError("p2pkh_script_pubkey: script is not OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG")
    if expected.get("length") != len(bytes.fromhex(want)):
        raise MappingError("p2pkh_script_pubkey: length does not match the script")


def check_script_sig_vector(signature_hex: str, pubkey_hex: str, expected: dict) -> None:
    want = minimal_push(bytes.fromhex(signature_hex)) + minimal_push(bytes.fromhex(pubkey_hex))
    if expected.get("script_hex") != want.hex():
        raise MappingError("p2pkh_script_sig: script is not <push sig> <push pubkey>")
    if expected.get("length") != len(want):
        raise MappingError("p2pkh_script_sig: length does not match the script")


def check_sighash_vector(case: dict) -> None:
    """Re-derives the digest framing and the sha256d relation from the vector."""
    payload = case["input"]
    expected = case["expected"]
    internal = bytes.fromhex(expected["digest"]["internal_hex"])
    display = bytes.fromhex(expected["digest"]["display_hex"])
    if display != internal[::-1]:
        raise MappingError(f"{case['id']}: display_hex is not the reversal of internal_hex")

    preimage = bytes.fromhex(expected["preimage_hex"])
    prefix = SIGHASH_TAG + int(payload["chain_id"]).to_bytes(4, "little")
    if not preimage.startswith(prefix):
        raise MappingError(f"{case['id']}: preimage does not start with the tag and chain id")
    if preimage[-4:] != int(payload["sighash_type"]).to_bytes(4, "little"):
        raise MappingError(f"{case['id']}: preimage does not end with the sighash type")

    # The digest is SHA-256 applied twice to the preimage. hashlib is used on
    # purpose: the fixture's provenance is checked without the kernel.
    digest = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    if digest != internal:
        raise MappingError(f"{case['id']}: digest is not sha256d(preimage)")


def map_script_case(case: dict) -> FixtureCase | None:
    case_id = case["id"]
    payload = case["input"]
    expected = case["expected"]

    if case_id in DEFERRED_CASES:
        return None

    if case_id == "ledger.script.push_data.lengths":
        lengths = payload["lengths"]
        check_push_vectors(lengths, expected)
        inputs = [("fill", "ab")] + [("len", str(length)) for length in lengths]
        outputs = [(f"len_{length}", expected[f"len_{length}"]) for length in lengths]
        return FixtureCase(case_id, "script_push_data", inputs, outputs)

    if case_id == "ledger.script.p2pkh_script_pubkey":
        pubkey_hash = payload["pubkey_hash_hex"]
        check_script_pubkey_vector(pubkey_hash, expected)
        return FixtureCase(
            case_id,
            "p2pkh_script_pubkey",
            [("pubkey_hash_hex", pubkey_hash)],
            [("length", text(expected["length"])), ("script_hex", expected["script_hex"])],
        )

    if case_id == "ledger.script.p2pkh_script_sig":
        signature = payload["signature_with_sighash_hex"]
        pubkey = payload["pubkey_sec1_hex"]
        check_script_sig_vector(signature, pubkey, expected)
        return FixtureCase(
            case_id,
            "p2pkh_script_sig",
            [("signature_hex", signature), ("pubkey_sec1_hex", pubkey)],
            [("length", text(expected["length"])), ("script_hex", expected["script_hex"])],
        )

    if case_id.startswith("ledger.script.reject_"):
        if expected.get("accepted") is not False:
            raise MappingError(f"{case_id}: a reject case must expect accepted=false")
        error_kind = expected["error_kind"]
        if error_kind not in SCRIPT_ERRORS:
            raise MappingError(f"{case_id}: unknown script error {error_kind}")
        # The accept stub pins control flow only: no reject case reaches
        # OP_CHECKSIG with a signature, so no curve backend is involved.
        return FixtureCase(
            case_id,
            "script_verify",
            [
                ("script_sig_hex", payload["script_sig_hex"]),
                ("script_pubkey_hex", payload["script_pubkey_hex"]),
                ("checker", "accept"),
            ],
            [("accepted", "false"), ("error", error_kind)],
        )

    raise MappingError(f"ledger/script.json: no P2 mapping for case {case_id}")


def map_sighash_cases(document: dict) -> list[FixtureCase]:
    cases = document["cases"]
    by_id = {case["id"]: case for case in cases}
    mapped: list[FixtureCase] = []

    digest_cases = [case for case in cases if case["expected"].get("digest") is not None]
    if not digest_cases:
        raise MappingError("ledger/sighash.json: no case pins a digest")

    shared_tx = digest_cases[0]["input"]["tx_hex"]
    shared_script = digest_cases[0]["input"]["script_code_hex"]
    for case in digest_cases:
        if case["input"]["tx_hex"] != shared_tx:
            raise MappingError(f"{case['id']}: siblings must share one transaction")
        if case["input"]["script_code_hex"] != shared_script:
            raise MappingError(f"{case['id']}: siblings must share one script_code")
        check_sighash_vector(case)
        payload = case["input"]
        mapped.append(
            FixtureCase(
                case["id"],
                "sighash",
                [
                    ("tx_hex", payload["tx_hex"]),
                    ("input_index", text(payload["input_index"])),
                    ("script_code_hex", payload["script_code_hex"]),
                    ("chain_id", text(payload["chain_id"])),
                    ("sighash_type", text(payload["sighash_type"])),
                ],
                [
                    ("digest", case["expected"]["digest"]["internal_hex"]),
                    ("digest_display_hex", case["expected"]["digest"]["display_hex"]),
                    ("preimage_hex", case["expected"]["preimage_hex"]),
                ],
            )
        )

    out_of_range = by_id.get("ledger.sighash.out_of_range_index")
    if out_of_range is None:
        raise MappingError("ledger.sighash.out_of_range_index is missing from the corpus")
    if out_of_range["expected"].keys() != {"digest"} or out_of_range["expected"]["digest"] is not None:
        raise MappingError("out_of_range_index must expect exactly {digest: null}")
    if tx_input_count(bytes.fromhex(shared_tx)) != out_of_range["input"]["input_count"]:
        raise MappingError("out_of_range_index: input_count disagrees with the shared transaction")
    reference = by_id[STABILITY_PAIR_IDS[0]]["input"]
    mapped.append(
        FixtureCase(
            out_of_range["id"],
            "sighash",
            [
                ("tx_hex", shared_tx),
                ("input_index", text(out_of_range["input"]["input_index"])),
                ("script_code_hex", shared_script),
                ("chain_id", text(reference["chain_id"])),
                ("sighash_type", text(reference["sighash_type"])),
            ],
            [("digest", "null")],
        )
    )

    stability = by_id.get("ledger.sighash.digest_stability")
    if stability is None:
        raise MappingError("ledger.sighash.digest_stability is missing from the corpus")
    if set(stability["expected"]) != {
        "index_0_equals_index_1",
        "regtest_equals_mainnet",
        "type_all_equals_type_02",
    }:
        raise MappingError("digest_stability: unexpected expected keys")
    if any(value is not False for value in stability["expected"].values()):
        raise MappingError("digest_stability: every pair must be declared distinct")

    def triple(case_id: str) -> tuple[str, str, str]:
        payload = by_id[case_id]["input"]
        return (text(payload["chain_id"]), text(payload["input_index"]), text(payload["sighash_type"]))

    index_0 = triple("ledger.sighash.regtest_index_0")
    index_1 = triple("ledger.sighash.regtest_index_1")
    mainnet = triple("ledger.sighash.mainnet_chain_binding")
    type_02 = triple("ledger.sighash.type_02_is_folded_in")
    pairs = [
        ("index_0_equals_index_1", index_0, index_1),
        ("regtest_equals_mainnet", index_0, mainnet),
        ("type_all_equals_type_02", index_0, type_02),
    ]
    inputs: list[tuple[str, str]] = [("tx_hex", shared_tx), ("script_code_hex", shared_script)]
    for name, left, right in pairs:
        inputs.append(("pair", "|".join([name, *left, *right])))
    mapped.append(
        FixtureCase(
            stability["id"],
            "sighash_distinct",
            inputs,
            [(name, "false") for name, _, _ in pairs],
        )
    )

    return mapped


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_manifest(vectors: Path, documents: dict[str, dict]) -> str:
    manifest = load_json(vectors / "manifest.json")
    declared = {entry["path"]: entry for entry in manifest["files"]}
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
    return manifest.get("source_commit", "unknown")


def build_cases(vectors: Path) -> tuple[list[FixtureCase], dict[str, int], str]:
    documents = {relative: load_json(vectors / relative) for relative in P2_FILES.values()}
    source_commit = check_manifest(vectors, documents)

    cases: list[FixtureCase] = []
    counts: dict[str, int] = {}

    script_cases = [map_script_case(case) for case in documents["ledger/script.json"]["cases"]]
    kept_script = [case for case in script_cases if case is not None]
    counts["ledger.script"] = len(kept_script)
    cases.extend(kept_script)

    kept_sighash = map_sighash_cases(documents["ledger/sighash.json"])
    deferred_sighash = sum(
        1 for case in documents["ledger/sighash.json"]["cases"] if case["id"] in DEFERRED_CASES
    )
    counts["ledger.sighash"] = len(kept_sighash)
    cases.extend(kept_sighash)

    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"P2 covers {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )

    present = {case.case_id for case in cases}
    for case_id in DEFERRED_CASES:
        document_cases = {
            case["id"]
            for document in documents.values()
            for case in document["cases"]
        }
        if case_id in present or case_id not in document_cases:
            raise MappingError(f"{case_id}: declared deferred but not present exactly once")

    ids = [case.case_id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")

    counts["deferred"] = len(DEFERRED_CASES)
    counts["sighash-deferred"] = deferred_sighash
    return cases, counts, source_commit


def render(cases: list[FixtureCase], source_commit: str) -> str:
    header = [
        "META schema=zro-p2-fixture/1",
        f"META source_commit={source_commit}",
        f"META cases={len(cases)}",
    ]
    return "\n".join(header + [case.render() for case in cases]) + "\n"


def corrupt(value: str) -> str:
    """Turns one expected value into a different, still well-formed value."""
    if value == "true":
        return "false"
    if value == "false":
        return "true"
    if value == "null":
        return "nullx"
    if value.isdigit():
        return str(int(value) + 1)
    if value and len(value) % 2 == 0 and all(char in "0123456789abcdef" for char in value):
        return ("1" if value[0] != "1" else "0") + value[1:]
    return value + "x"


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


def parse_results(completed: subprocess.CompletedProcess[str]) -> dict[str, tuple[str, str]]:
    results: dict[str, tuple[str, str]] = {}
    for line in completed.stdout.splitlines():
        if not line.startswith("RESULT "):
            continue
        parts = line.split(" ", 3)
        if len(parts) < 3:
            raise MappingError(f"malformed runner line: {line}")
        _, case_id, status = parts[0], parts[1], parts[2]
        detail = parts[3] if len(parts) > 3 else ""
        if case_id in results:
            raise MappingError(f"duplicate result for {case_id}")
        results[case_id] = (status, detail)
    return results


def summary_of(completed: subprocess.CompletedProcess[str]) -> re.Match[str] | None:
    for line in completed.stdout.splitlines():
        if line.startswith("SUMMARY "):
            return re.fullmatch(r"SUMMARY cases=(\d+) failures=(\d+)", line)
    return None


def check_corruption(runner: Path, cases: list[FixtureCase], source_commit: str) -> int:
    """Every expected value is wrong, so every case must be reported failed."""
    corrupted = [
        FixtureCase(
            case.case_id,
            case.op,
            case.inputs,
            [(key, corrupt(value)) for key, value in case.outputs],
        )
        for case in cases
    ]
    for original, mutated in zip(cases, corrupted):
        if [value for _, value in original.outputs] == [value for _, value in mutated.outputs]:
            print(f"p2 conformance: corruption did not change {original.case_id}", file=sys.stderr)
            return 2

    completed = run_fixture(runner, render(corrupted, source_commit))
    if completed.returncode != 1:
        print(
            f"p2 conformance: corrupted fixture exited {completed.returncode}, expected 1",
            file=sys.stderr,
        )
        print(completed.stdout, file=sys.stderr)
        return 2

    summary = summary_of(completed)
    if summary is None or int(summary.group(1)) != len(cases) or int(summary.group(2)) != len(cases):
        print(
            f"p2 conformance: corrupted fixture summary was {summary.group(0) if summary else 'missing'}",
            file=sys.stderr,
        )
        return 2

    results = parse_results(completed)
    accepted = [case_id for case_id, (status, _) in results.items() if status == "ok"]
    if accepted or len(results) != len(cases):
        print(
            f"p2 conformance: corruption survived in {len(accepted)} cases with "
            f"{len(results)} results",
            file=sys.stderr,
        )
        return 2

    print(f"p2 conformance: corruption self-check rejected {len(cases)}/{len(cases)} cases")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        cases, counts, source_commit = build_cases(args.vectors)
    except (MappingError, KeyError) as error:
        print(f"p2 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, render(cases, source_commit))
    if completed.returncode not in (0, 1):
        print(f"p2 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    try:
        results = parse_results(completed)
    except MappingError as error:
        print(f"p2 conformance: {error}", file=sys.stderr)
        return 2
    summary = summary_of(completed)

    expected_ids = [case.case_id for case in cases]
    missing = [case_id for case_id in expected_ids if case_id not in results]
    failed = [
        (case_id, detail)
        for case_id, (status, detail) in results.items()
        if status != "ok"
    ]

    if summary is None:
        print("p2 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if missing or failed or completed.returncode != 0:
        print(f"p2 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)", file=sys.stderr)
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"p2 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    print(
        f"p2 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}"
    )
    print(f"  ledger.script          {counts['ledger.script']}")
    print(f"  ledger.sighash         {counts['ledger.sighash']}")
    print(f"  deferred (G2c)         {counts['deferred']}: {', '.join(sorted(DEFERRED_CASES))}")

    return check_corruption(args.runner, cases, source_commit)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
