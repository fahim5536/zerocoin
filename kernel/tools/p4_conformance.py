#!/usr/bin/env python3
"""Replay the committed Rust Proof-of-Work corpus against the C++ kernel.

test/vectors/pow/engines.json holds the 11 cases the Rust reference exports for
C-4: two engine identities, four trivial-engine hashes, five scratchpad hashes
across both shipped profiles, and one mined nonce. `g1_conformance.py` does not
read this file — it loads an explicit four-file allowlist (`G1_FILES`: hash
primitives, varint, transaction, difficulty retarget) and never walks the
manifest for groups it has not been told about — so this wrapper is the only
consumer of every expected byte in it, and it is registered as its own CTest case
for the same reason P2, P3, P3.1, P3.2 and P3.3 each are.

One fixture case per corpus case. There is no expansion here, so the count the
gate asserts is the count the corpus publishes and a case cannot be dropped by a
mapping change.

Three things are enforced before the runner is asked anything:

  1. the corpus is internally sound — manifest totals, group, source commit,
     corpus schema, case ids against a named table, duplicates, hex width, and
     the internal/display digest pair;
  2. the corpus agrees with a genuinely independent implementation —
     test/harness/zro_vectors.py's `trivial_hash`, `scratchpad_hash`, `mine`,
     `compact_to_target` and `hash_meets_target`. That is the same harness the P0
     gate uses, it shares no code with kernel/src/pow.cpp, and the Rust exporter
     remains the authority for the expected values: agreement proves a corpus row
     is reproducible by something that is neither Rust nor this kernel, so a C++
     match is not resting on one shared assumption;
  3. every key the corpus publishes is either handed to the runner as input or
     compared. DEFERRED_KEYS is empty and stays that way on purpose, and an
     `engine_id` other than the scratchpad one on a scratchpad row is a mapping
     failure naming the unsupported identifier — never a silent re-dispatch.

A failure in any of them is reported as a mapping failure (exit 2), never as a
hash mismatch: a malformed or self-inconsistent fixture must not be able to look
like a C++ bug.

Usage:
  python kernel/tools/p4_conformance.py --vectors test/vectors --runner <exe>
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

SOURCE_FILE = "pow/engines.json"

# The corpus's own schema, restated so a file that quietly changes shape fails
# instead of being replayed wrongly.
EXPECTED_SCHEMA = "zro-baseline-vectors/1"
EXPECTED_GROUP = "pow"

# The eleven committed case ids, named rather than pattern-matched: a corpus that
# grows or renames a row fails this gate until the row is classified here, which
# is the only way "no silent skips" can be enforced from outside the file.
ENGINE_IDS_CASE = "pow.engine_ids"
MINE_CASE = "pow.trivial.mine_from_zero"
TRIVIAL_HASH_CASES = (
    "pow.trivial.raw_nonce_0",
    "pow.trivial.raw_nonce_1",
    "pow.trivial.header_nonce_0",
    "pow.trivial.header_nonce_42",
)
SCRATCHPAD_HASH_CASES = (
    "pow.scratchpad.devnet_nonce_0",
    "pow.scratchpad.devnet_nonce_1",
    "pow.scratchpad.devnet_nonce_42",
    "pow.scratchpad.mainnet_nonce_0",
    "pow.scratchpad.mainnet_nonce_1",
)

EXPECTED_CASE_COUNT = (
    1 + 1 + len(TRIVIAL_HASH_CASES) + len(SCRATCHPAD_HASH_CASES)
)

# Nothing is deferred by this milestone. Kept as a set, rather than omitted, so
# `require_expected_keys` still refuses to drop an unrecognised expected key and a
# future deferral has to be written down here to take effect.
DEFERRED_KEYS: set[str] = set()

# The keys each shape of case must carry in `input`, and the two forms a published
# digest takes.
ENGINE_IDS_INPUT_KEYS = ("engines",)
ENGINE_IDS_EXPECTED_KEYS = ("trivial_id", "trivial_name", "scratchpad_id", "scratchpad_name")
TRIVIAL_INPUT_KEYS = ("nonce", "preimage_hex")
SCRATCHPAD_INPUT_KEYS = ("engine_id", "engine_name", "memory_bytes", "nonce", "preimage_hex", "rounds")
MINE_INPUT_KEYS = ("preimage_hex", "target_bits")
MINE_EXPECTED_KEYS = ("nonce",)
HASH_KEYS = ("display_hex", "internal_hex")

# The engine identifiers the corpus is allowed to declare. `1` is the scratchpad;
# anything else on a scratchpad row is an unsupported identifier and a mapping
# failure, because replaying a memory-hard row through another engine would report
# a consensus rule as a passing byte comparison.
SCRATCHPAD_ENGINE_ID = 1

# Two cases carry every output key the runner can produce, so corrupting one value
# in each of them proves the comparison can fail without re-running the profiles
# that take longest.
PROBE_CASES = (
    "pow.trivial.raw_nonce_1",
    "pow.scratchpad.devnet_nonce_42",
    ENGINE_IDS_CASE,
    MINE_CASE,
)

# The independent verifier lives in the repository's P0 harness. Resolved from this
# script's own location, so it does not move with --vectors.
HARNESS_DIR = Path(__file__).resolve().parents[2] / "test" / "harness"


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

    def with_corrupted_output(self, key: str, value: str) -> "FixtureCase":
        outputs = [(name, value if name == key else had) for name, had in self.outputs]
        return FixtureCase(self.case_id, self.op, list(self.inputs), outputs)


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


def load_python_verifier() -> dict:
    """Imports the P0 harness's proof-of-work implementations.

    They are the harness's own re-derivation of the reference engines, so they
    share nothing with `kernel/src/pow.cpp` and are not called by the runner.
    Failing to import them is a gate failure, not a skip: a run without the
    cross-check would silently be a weaker run. The differential needs five
    functions and four committed constants, so all nine are checked for presence
    before any case is mapped.
    """
    path = HARNESS_DIR / "zro_vectors.py"
    if not path.is_file():
        raise MappingError(f"independent verifier not found at {path}")
    if str(HARNESS_DIR) not in sys.path:
        sys.path.insert(0, str(HARNESS_DIR))
    try:
        import zro_vectors  # type: ignore
    except Exception as error:  # pragma: no cover - import failure is a gate failure
        raise MappingError(f"independent verifier failed to import: {error}") from error

    out: dict = {}
    for name in ("trivial_hash", "scratchpad_hash", "mine", "compact_to_target", "hash_meets_target"):
        function = getattr(zro_vectors, name, None)
        if not callable(function):
            raise MappingError(f"independent verifier has no callable {name}")
        out[name] = function

    for name in (
        "ENGINE_ID_TRIVIAL",
        "ENGINE_ID_SCRATCHPAD",
        "TRIVIAL_ENGINE_NAME",
        "SCRATCHPAD_ENGINE_NAME",
        "SCRATCHPAD_CELL",
    ):
        value = getattr(zro_vectors, name, None)
        if value is None:
            raise MappingError(f"independent verifier has no {name}")
        out[name] = value

    # The verifier's own constants must agree with the identifiers this wrapper
    # refuses to re-dispatch, or the cross-check would be measuring a different
    # engine than the corpus names.
    if out["ENGINE_ID_SCRATCHPAD"] != SCRATCHPAD_ENGINE_ID:
        raise MappingError(
            f"independent verifier ENGINE_ID_SCRATCHPAD {out['ENGINE_ID_SCRATCHPAD']} "
            f"!= {SCRATCHPAD_ENGINE_ID}"
        )
    if int(out["SCRATCHPAD_CELL"]) != 32:
        raise MappingError(f"independent verifier SCRATCHPAD_CELL is {out['SCRATCHPAD_CELL']}, expected 32")
    return out


# --- corpus -> fixture -------------------------------------------------------


def hex_bytes(value: object, case_id: str, what: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value or ""):
        raise MappingError(f"{case_id}: {what} is not an even-length lowercase hex string: {value!r}")
    return bytes.fromhex(value)


def internal_hex(value: object, case_id: str, what: str) -> str:
    """A strict 32-byte internal digest, or a mapping failure."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise MappingError(
            f"{case_id}: {what} is not 64 lowercase hex characters (32 bytes): {value!r}"
        )
    return value


def display_of(internal: str) -> str:
    return bytes.fromhex(internal)[::-1].hex()


def nonneg_int(value: object, case_id: str, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MappingError(f"{case_id}: {what} is {type(value).__name__}, not an integer: {value!r}")
    if value < 0:
        raise MappingError(f"{case_id}: {what} is negative: {value}")
    return value


def require_input_keys(case_id: str, payload: object, wanted: tuple[str, ...]) -> dict:
    if not isinstance(payload, dict):
        raise MappingError(f"{case_id}: input is {type(payload).__name__}, not an object")
    missing = [key for key in wanted if key not in payload]
    if missing:
        raise MappingError(f"{case_id}: input is missing {missing}")
    extra = sorted(set(payload) - set(wanted))
    if extra:
        raise MappingError(f"{case_id}: input keys {extra} are unmapped; map them or defer them")
    return payload


def require_hash_expected(case_id: str, expected: object) -> dict:
    """The published digest, with its two forms cross-checked against each other."""
    if not isinstance(expected, dict):
        raise MappingError(f"{case_id}: expected is {type(expected).__name__}, not an object")
    unknown = sorted(set(expected) - {"hash"} - DEFERRED_KEYS)
    if unknown:
        raise MappingError(f"{case_id}: expected keys {unknown} are unmapped; map them or defer them")
    want = expected.get("hash")
    if not isinstance(want, dict) or set(want) != set(HASH_KEYS):
        raise MappingError(
            f"{case_id}: expected.hash keys "
            f"{sorted(want) if isinstance(want, dict) else type(want).__name__}, expected {sorted(HASH_KEYS)}"
        )
    internal = internal_hex(want["internal_hex"], case_id, "hash.internal_hex")
    display = internal_hex(want["display_hex"], case_id, "hash.display_hex")
    if display != display_of(internal):
        raise MappingError(
            f"{case_id}: hash.display_hex {display} is not hash.internal_hex {internal} reversed; "
            "the corpus publishes a digest and its display form must be the same bytes"
        )
    return want


def require_digest_pair(case_id: str, produced: bytes, want: dict) -> None:
    """The third way: the independent implementation must reach the published byte."""
    internal = want["internal_hex"]
    got = produced.hex()
    if got != internal:
        raise MappingError(
            f"{case_id}: the independent Python engine produced {got} where the corpus publishes "
            f"{internal}; the corpus and the harness disagree, so neither can be replayed as truth"
        )


def map_engine_ids(case: dict, verifier: dict) -> FixtureCase:
    case_id = case["id"]
    payload = require_input_keys(case_id, case["input"], ENGINE_IDS_INPUT_KEYS)
    expected = case["expected"]
    if not isinstance(expected, dict):
        raise MappingError(f"{case_id}: expected is {type(expected).__name__}, not an object")

    missing = [key for key in ENGINE_IDS_EXPECTED_KEYS if key not in expected]
    if missing:
        raise MappingError(f"{case_id}: expected is missing {missing}")
    extra = sorted(set(expected) - set(ENGINE_IDS_EXPECTED_KEYS) - DEFERRED_KEYS)
    if extra:
        raise MappingError(f"{case_id}: expected keys {extra} are unmapped; map them or defer them")

    names = payload["engines"]
    if not isinstance(names, list):
        raise MappingError(f"{case_id}: input.engines is {type(names).__name__}, not a list")
    if len(names) != 2 or sorted(names) != ["scratchpad", "trivial"]:
        raise MappingError(
            f"{case_id}: input.engines {names!r} is not exactly the two engines the corpus declares"
        )

    # The identifiers and the names are the two things a header and a log commit
    # to, so the harness's own constants have to be the ones being asserted.
    pairs = {
        "trivial_id": verifier["ENGINE_ID_TRIVIAL"],
        "trivial_name": verifier["TRIVIAL_ENGINE_NAME"],
        "scratchpad_id": verifier["ENGINE_ID_SCRATCHPAD"],
        "scratchpad_name": verifier["SCRATCHPAD_ENGINE_NAME"],
    }
    for key, independent in pairs.items():
        if expected[key] != independent:
            raise MappingError(
                f"{case_id}: expected.{key} {expected[key]!r} != the independent verifier's "
                f"{independent!r}"
            )

    outputs = [(key, text(expected[key])) for key in ENGINE_IDS_EXPECTED_KEYS]
    inputs = [("engine", text(name)) for name in names]
    return FixtureCase(case_id, "pow_engine_ids", inputs, outputs)


def map_trivial_hash(case: dict, verifier: dict) -> FixtureCase:
    case_id = case["id"]
    payload = require_input_keys(case_id, case["input"], TRIVIAL_INPUT_KEYS)
    want = require_hash_expected(case_id, case["expected"])

    preimage = hex_bytes(payload["preimage_hex"], case_id, "preimage_hex")
    nonce = nonneg_int(payload["nonce"], case_id, "nonce")

    require_digest_pair(case_id, verifier["trivial_hash"](preimage, nonce), want)

    inputs = [("preimage_hex", text(payload["preimage_hex"])), ("nonce", text(nonce))]
    outputs = [("internal_hex", want["internal_hex"]), ("display_hex", want["display_hex"])]
    return FixtureCase(case_id, "pow_trivial_hash", inputs, outputs)


def map_scratchpad_hash(case: dict, verifier: dict) -> FixtureCase:
    case_id = case["id"]
    payload = require_input_keys(case_id, case["input"], SCRATCHPAD_INPUT_KEYS)
    want = require_hash_expected(case_id, case["expected"])

    preimage = hex_bytes(payload["preimage_hex"], case_id, "preimage_hex")
    nonce = nonneg_int(payload["nonce"], case_id, "nonce")
    memory_bytes = nonneg_int(payload["memory_bytes"], case_id, "memory_bytes")
    rounds = nonneg_int(payload["rounds"], case_id, "rounds")
    engine_id = nonneg_int(payload["engine_id"], case_id, "engine_id")
    engine_name = text(payload["engine_name"])

    # Unsupported identifier: refuse, rather than mapping it to an engine and
    # reporting the row as a passing byte comparison.
    if engine_id != SCRATCHPAD_ENGINE_ID:
        raise MappingError(
            f"{case_id}: input.engine_id {engine_id} is not the scratchpad id "
            f"{SCRATCHPAD_ENGINE_ID}; this wrapper replays no other engine for a memory-hard row"
        )
    if engine_name != verifier["SCRATCHPAD_ENGINE_NAME"]:
        raise MappingError(
            f"{case_id}: input.engine_name {engine_name!r} != the reference name "
            f"{verifier['SCRATCHPAD_ENGINE_NAME']!r}"
        )

    require_digest_pair(case_id, verifier["scratchpad_hash"](preimage, nonce, memory_bytes, rounds), want)

    # The cell count the kernel derives from the budget, computed here from the
    # corpus's own input and the harness's own cell width.
    cells = max(memory_bytes // int(verifier["SCRATCHPAD_CELL"]), 1)

    inputs = [
        ("preimage_hex", text(payload["preimage_hex"])),
        ("nonce", text(nonce)),
        ("memory_bytes", text(memory_bytes)),
        ("rounds", text(rounds)),
        ("engine_id", text(engine_id)),
        ("engine_name", engine_name),
    ]
    outputs = [
        ("internal_hex", want["internal_hex"]),
        ("display_hex", want["display_hex"]),
        ("cell_count", text(cells)),
    ]
    return FixtureCase(case_id, "pow_scratchpad_hash", inputs, outputs)


def map_mine_from_zero(case: dict, verifier: dict) -> FixtureCase:
    case_id = case["id"]
    payload = require_input_keys(case_id, case["input"], MINE_INPUT_KEYS)
    expected = case["expected"]
    if not isinstance(expected, dict):
        raise MappingError(f"{case_id}: expected is {type(expected).__name__}, not an object")
    missing = [key for key in MINE_EXPECTED_KEYS if key not in expected]
    if missing:
        raise MappingError(f"{case_id}: expected is missing {missing}")
    extra = sorted(set(expected) - set(MINE_EXPECTED_KEYS) - DEFERRED_KEYS)
    if extra:
        raise MappingError(f"{case_id}: expected keys {extra} are unmapped; map them or defer them")

    preimage = hex_bytes(payload["preimage_hex"], case_id, "preimage_hex")
    bits = nonneg_int(payload["target_bits"], case_id, "target_bits")
    if bits > 0xFFFFFFFF:
        raise MappingError(f"{case_id}: target_bits {bits} does not fit in 32 bits")

    want = nonneg_int(expected["nonce"], case_id, "expected.nonce")

    # The independent search, from nonce 0 upward, through the harness's own
    # target decoding and inclusive comparison. Agreement here means the mined
    # nonce is not an artefact of one implementation's bound or byte order.
    target = verifier["compact_to_target"](bits)
    found, digest = verifier["mine"](verifier["trivial_hash"], preimage, target, 0)
    if found != want:
        raise MappingError(
            f"{case_id}: the independent Python search reached nonce {found} where the corpus "
            f"publishes {want}"
        )
    if not verifier["hash_meets_target"](digest, target):
        raise MappingError(f"{case_id}: the published nonce's digest does not meet its own target")
    if want > 0 and verifier["hash_meets_target"](verifier["trivial_hash"](preimage, want - 1), target):
        raise MappingError(
            f"{case_id}: nonce {want - 1} already meets the target, so {want} is not the first "
            "solution from zero"
        )

    inputs = [("preimage_hex", text(payload["preimage_hex"])), ("target_bits", text(bits))]
    outputs = [("nonce", text(want))]
    return FixtureCase(case_id, "pow_mine_from_zero", inputs, outputs)


MAPPERS = {
    ENGINE_IDS_CASE: map_engine_ids,
    MINE_CASE: map_mine_from_zero,
    **{case_id: map_trivial_hash for case_id in TRIVIAL_HASH_CASES},
    **{case_id: map_scratchpad_hash for case_id in SCRATCHPAD_HASH_CASES},
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

    if document.get("schema") != EXPECTED_SCHEMA:
        raise MappingError(
            f"{SOURCE_FILE}: schema {document.get('schema')!r} != {EXPECTED_SCHEMA!r}"
        )
    if document.get("group") != entry["group"]:
        raise MappingError(f"{SOURCE_FILE}: group {document.get('group')} != manifest {entry['group']}")
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
            f"{SOURCE_FILE}: source_commit {document.get('source_commit')} != manifest {commit}"
        )
    if not document.get("provenance") or "Rust" not in document["provenance"]:
        raise MappingError(f"{SOURCE_FILE}: provenance does not state that the Rust code produced it")
    return commit


def build_fixture(vectors: Path) -> tuple[str, list[FixtureCase], str]:
    document = load_json(vectors / SOURCE_FILE)
    source_commit = check_manifest(vectors, document)
    verifier = load_python_verifier()

    cases = document["cases"]
    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"{SOURCE_FILE}: {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update this wrapper before changing the corpus"
        )

    mapped: list[FixtureCase] = []
    seen: set[str] = set()
    for case in cases:
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise MappingError(f"{SOURCE_FILE}: a case has no id")
        if case_id in seen:
            raise MappingError(f"{SOURCE_FILE}: duplicate case id {case_id}")
        seen.add(case_id)
        if not case_id.startswith(EXPECTED_GROUP + "."):
            raise MappingError(f"{case_id}: outside the {EXPECTED_GROUP} group")
        if not case.get("independent_check"):
            raise MappingError(f"{case_id}: no independent_check")
        if case.get("intent") not in ("rule", "oddity"):
            raise MappingError(f"{case_id}: unknown intent {case.get('intent')!r}")
        mapper = MAPPERS.get(case_id)
        if mapper is None:
            raise MappingError(
                f"{case_id}: no P4 classification; the corpus gained a case that this "
                "wrapper has not been told how to replay"
            )
        mapped.append(mapper(case, verifier))

    unclassified = sorted(set(MAPPERS) - seen)
    if unclassified:
        raise MappingError(f"{SOURCE_FILE}: committed cases absent from the file: {unclassified}")

    ids = [case.case_id for case in mapped]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")
    if len(mapped) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"P4 covers {len(mapped)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )

    header = [
        "META schema=zro-p4-fixture/1",
        f"META source_commit={source_commit}",
        f"META cases={len(mapped)}",
    ]
    return "\n".join(header + [case.render() for case in mapped]) + "\n", mapped, source_commit


def run_fixture(runner: Path, fixture: str) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".fixture", delete=False) as handle:
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
    return "META schema=zro-p4-fixture/1\n" + case.render() + "\n"


def fixture_ids(fixture: str) -> list[str]:
    """Re-reads the rendered fixture so the check is independent of the mapping."""
    return [line[len("CASE "):] for line in fixture.splitlines() if line.startswith("CASE ")]


def probe_can_fail(runner: Path, cases: list[FixtureCase]) -> None:
    """Every compared value must be able to fail the run.

    Each probe case is replayed whole, then once per declared output with that one
    value corrupted. The scratchpad probe runs on the devnet row, not mainnet, so
    the gate stays fast while still covering `internal_hex`, `display_hex` and
    `cell_count` — the three keys every scratchpad row publishes. Without the
    probe, a runner that answered `ok` to everything would keep this gate green.
    """
    by_id = {case.case_id: case for case in cases}
    for case_id in PROBE_CASES:
        probe = by_id.get(case_id)
        if probe is None:
            raise MappingError(f"corruption probe: {case_id} is not in the mapped fixture")
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
                    f"corruption probe: runner did not report the wrong {key} for {probe.case_id}"
                )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        fixture, cases, source_commit = build_fixture(args.vectors)
        probe_can_fail(args.runner, cases)
    except (MappingError, KeyError) as error:
        print(f"p4 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, fixture)
    if completed.returncode not in (0, 1):
        print(f"p4 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    results: dict[str, tuple[str, str]] = {}
    summary: re.Match[str] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                print(f"p4 conformance: malformed runner line: {line}", file=sys.stderr)
                return 2
            case_id, status = parts[1], parts[2]
            detail = parts[3] if len(parts) > 3 else ""
            if case_id in results:
                print(f"p4 conformance: duplicate result for {case_id}", file=sys.stderr)
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
        print("p4 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if missing or failed or completed.returncode != 0:
        print(f"p4 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)", file=sys.stderr)
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"p4 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    # An auditable statement of what was not compared. It is empty, and the line
    # below would print the names if a future milestone ever added one.
    deferred_names = ", ".join(sorted(DEFERRED_KEYS)) or "none"
    print(
        f"p4 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}, "
        f"{len(DEFERRED_KEYS)} deferred ({deferred_names})"
    )
    for case in cases:
        print(f"  {case.case_id:<36} {case.op:<21} {len(case.outputs)} compared")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
