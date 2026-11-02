#!/usr/bin/env python3
"""P4.2B-3: diff the C++ Block structure validator against the Python oracle.

test/p42-vectors/chain/block_structure.json holds the 35 `chain.block_structure.*`
cases the P4.2A exporter published from a direct call to the shipping Rust
`Block::validate_structure`. Every one of them is replayed here through
`zk::validate_block_structure` — the production ordering in kernel/src/block.cpp,
B-3 through B-15 — and the kernel's answer is compared field by field against what
`test/harness/zro_vectors.py::_verify_block_structure` independently derives from
the same published input.

The direction of derivation is the whole point, so it is stated once, plainly:

  * every `OUT` value below comes from the Python oracle, which reads only
    `case["input"]` and shares no code with kernel/src/;
  * nothing in this file asks the runner what it thinks before deciding what to
    expect, and no expectation is edited to agree with a kernel answer;
  * the oracle's output is first required to equal the corpus's published
    `expected` (Rust's own verdict), so the differential is between Rust, Python
    and C++ three ways rather than between C++ and a Python that could drift.

Matching exit codes is not the comparison. `kernel/conformance/main.cpp` serialises
the verdict into named fields and the runner's own `compare` reports the first
field on which the two implementations disagree, so a mismatch prints the fixture
id, the field, the oracle's value and the kernel's value. This wrapper then adds
the context a reader needs: the oracle's `violated_rules`, `reported_rule`, the
engine, the transaction count and the two time literals.

Why precedence is diffed on `error_kind` and not on a rule set. The reference
short-circuits — `validate_structure` returns the first rejection it reaches — and
so does the port. The complete set of rows an input fails is therefore something
only the oracle computes, by evaluating every condition without returning; asking
the kernel for it would mean restating B-5 and B-7 through B-13 inside the test
binary, which is a second implementation of the consensus rules and is exactly what
this milestone may not write. The ordering claim survives intact: for a case whose
published input violates rows X and Y, the oracle expects the variant of row X, and
a kernel that checked Y first would name a different variant and fail. That is a
falsifiable diff, and `manifest.precedence.basis` is the corpus's own definition of
what a witness is.

Three more compared fields stop that diff from being a tautology, because they are
evidence about rules the reported verdict never reached:

  * `roots_match` and `proof_of_work_meets_target` come from production calls
    (`merkle_root_from_transactions`, `header_meets_own_target`) the runner makes
    unconditionally, so `pair_13_14_future_and_stale_root` shows row 14 failing
    underneath the row-13 verdict rather than showing nothing;
  * `future_limit` is `zk::future_timestamp_limit(context.now)` — the saturating
  bound B-13 compares against — so `bnd_13_near_max_*` distinguishes a saturating
  port from a wrapping one even where the two would return the same verdict.

`violated_rules`, `reported_rule`, `is_first_violation`, `leaves` and
`computed_root_len` are published by the oracle and deliberately not replayed; they
are named in DEFERRED_KEYS with the reason each one cannot be. None of them is
silently dropped: an expected key that is neither mapped nor deferred is a mapping
failure (exit 2), and so is any input the current C++ API cannot represent — the
kernel has no engine for an unmodelled algorithm, and an unsupported fixture is
reported as unsupported rather than converted into a pass.

Usage:
  python kernel/tools/p42_conformance.py --vectors test/p42-vectors --runner <exe>
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

SOURCE_FILES = ("chain/block_structure.json",)

EXPECTED_FILE_CASES = {"chain/block_structure.json": 35}
EXPECTED_CASE_COUNT = sum(EXPECTED_FILE_CASES.values())

# The one operation this corpus drives, and the only place its rules are decided.
OP = "block_structure"

EXPECTED_PHASE = "P4.2A"
EXPECTED_SCHEMA = "zro-baseline-vectors/1"
EXPECTED_GROUP = "chain.block_structure"
EXPECTED_SOURCE_COMMIT = "b71d769be8357bcf10d768d915770125cf7f7c24"

# The exact case-id table, in the order the corpus publishes it. Matching no id
# pattern is deliberate: a corpus that gained, lost or renamed one case has to be
# re-read by whoever extends this differential, and a 36th case must never be able
# to slip through a wildcard into a run that reports "35".
EXPECTED_CASE_IDS = (
    "chain.block_structure.iso_03_wrong_chain",
    "chain.block_structure.iso_04_bad_height",
    "chain.block_structure.iso_05_bad_previous_hash",
    "chain.block_structure.iso_06_wrong_engine",
    "chain.block_structure.iso_07_bad_difficulty",
    "chain.block_structure.iso_08_no_transactions",
    "chain.block_structure.iso_09_too_many_transactions",
    "chain.block_structure.iso_10_first_not_coinbase",
    "chain.block_structure.iso_11_duplicate_coinbase",
    "chain.block_structure.iso_11_duplicate_coinbase_at_last_index",
    "chain.block_structure.iso_12_timestamp_too_old",
    "chain.block_structure.iso_13_timestamp_too_far_future",
    "chain.block_structure.iso_14_root_mismatch",
    "chain.block_structure.iso_15_insufficient_pow",
    "chain.block_structure.bnd_09_count_at_limit_accept",
    "chain.block_structure.bnd_12_equal_median_reject",
    "chain.block_structure.bnd_12_one_above_median_accept",
    "chain.block_structure.bnd_13_equal_limit_accept",
    "chain.block_structure.bnd_13_one_above_reject",
    "chain.block_structure.bnd_13_near_max_edge_reject",
    "chain.block_structure.bnd_13_near_max_last_exact_accept",
    "chain.block_structure.bnd_13_near_max_saturating_accept",
    "chain.block_structure.pair_03_04_chain_and_height",
    "chain.block_structure.pair_04_05_height_and_previous",
    "chain.block_structure.pair_05_06_previous_and_engine",
    "chain.block_structure.pair_06_07_engine_and_bits",
    "chain.block_structure.pair_07_08_bits_and_empty",
    "chain.block_structure.pair_09_10_over_limit_and_first_not_coinbase",
    "chain.block_structure.pair_10_11_first_not_coinbase_and_duplicate",
    "chain.block_structure.pair_11_12_duplicate_and_old_timestamp",
    "chain.block_structure.pair_12_13_old_and_future",
    "chain.block_structure.pair_13_14_future_and_stale_root",
    "chain.block_structure.pair_14_15_root_mismatch_and_failing_pow",
    "chain.block_structure.pair_14_15_zero_root_claim_and_failing_pow",
    "chain.block_structure.chaos_all_later_guards_broken",
)

# The oracle's own rule numbering, restated as the literals this differential
# depends on. `MAX_BLOCK_TRANSACTIONS` and `MAX_FUTURE_SECONDS` are checked against
# the Python oracle's values below rather than trusted here: they are the two
# consensus constants B-9 and B-13 read, and a port that changed one would have to
# be caught by the corpus, not accommodated by this file.
RULE_FIRST, RULE_LAST = 3, 15
EXPECTED_MAX_TRANSACTIONS = 2_000
EXPECTED_MAX_FUTURE_SECONDS = 7_200

# `enum class BlockErrorKind` in kernel/include/zerocoin/header.h: the frozen
# numeric taxonomy, append-only since P4.1 and pinned by the `static_assert`s in
# block.h. Rule row -> numeric, because the corpus numbers rows and the kernel
# numbers the enum, and the two agree only by coincidence — row 14 (`RootMismatch`)
# is the numeric 3 P4.1 froze, and it is the eleventh alternative declared in
# block.h. This table is a restatement of a declaration, not a reading of a run:
# the kernel's answer is `error_kind`, and a disagreement between the name and the
# number is exactly the drift this key exists to catch.
KERNEL_NUMERIC_BY_RULE = {
    3: 1,   # WrongChain
    4: 2,   # BadHeight
    5: 4,   # BadPreviousHash
    6: 5,   # WrongEngine
    7: 6,   # BadDifficulty
    8: 7,   # NoTransactions
    9: 8,   # TooManyTransactions
    10: 9,  # FirstNotCoinbase
    11: 10,  # DuplicateCoinbase
    12: 11,  # TimestampTooOld
    13: 12,  # TimestampTooFarFuture
    14: 3,   # RootMismatch, the value P4.1 froze
    15: 13,  # InsufficientProofOfWork
}
KERNEL_NUMERIC_NONE = 0  # BlockErrorKind::kNone, named "None" by header.cpp.

# Published expectations this differential does not replay, and why. Each is
# validated before the runner sees the case, so a deferral cannot hide a shape
# change; none of them is a kernel failure and none is counted as a pass.
DEFERRED_KEYS: dict[str, str] = {
    "violated_rules": (
        "`validate_structure` returns the first rejection it reaches, so the complete "
        "set of rows an input fails is not observable through the production validator; "
        "recovering it here would restate B-5 and B-7 through B-13 in a test binary"
    ),
    "reported_rule": (
        "the evaluation row of the returned variant, which the kernel names through "
        "`error_kind` and this file maps back with the oracle's own BLOCK_RULE_ERRORS; "
        "the runner publishes no row number because a row number is a property of "
        "block.rs's body, not a value the C++ type carries"
    ),
    "is_first_violation": (
        "an assertion about `violated_rules`, which is deferred above; it is true for "
        "every case by the oracle's own construction and needs no kernel evidence"
    ),
    "leaves": (
        "the per-transaction ids the reference hashed. The ported composition "
        "(`merkle_root_from_transactions`) returns only the root, and asking for the "
        "leaves would mean calling `Transaction::txid` from the runner per leaf, which "
        "is a P3.3/P4.1 job and already replayed by those gates"
    ),
    "computed_root_len": (
        "the digest width is `Hash256::kWidth`, a compile-time constant; the compared "
        "`computed_root_internal_hex` already fixes it because the runner rejects any "
        "digest that is not exactly 32 bytes"
    ),
}

# The two engines the kernel can build, by the reference's own names. Anything else
# is unsupported: the runner refuses it rather than hashing with a different
# algorithm, and this file reports the case as unsupported rather than as a failure
# of the consensus rules.
KERNEL_ENGINES = ("sha256d-trivial", "scratchpad-memory-hard")

# The fields `header_of` reads under its `header.` prefix. Nine, because the header
# owns a nonce it never validates. A corpus header that grew a tenth field would be
# a different block type, not this one.
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
CONTEXT_FIELDS = (
    "engine",
    "expected_chain",
    "expected_height",
    "expected_previous_hex",
    "expected_bits",
    "median_time_past",
    "now",
)
RICH_TX_FIELDS = (
    "inputs",
    "is_coinbase",
    "lock_time",
    "outputs",
    "serialized_hex",
    "serialized_len",
    "version",
)
# Every input key except the transaction list, whose two legal spellings
# (`transactions`, rich, or `transactions_hex`, raw bytes) are chosen by the shape
# check in `transaction_inputs`. A ninth input key would be a field the differential
# does not read, and reading the other eight would quietly ignore it.
INPUT_KEYS = (
    "group",
    "tx_count",
    "engine_config",
    "reused_from",
    "synthetic_context",
    "header",
    "validation_context",
)

# The corpus's own published totals. Restated so a corpus that quietly changed its
# shape is caught before 35 cases are replayed against the wrong question.
EXPECTED_MANIFEST_GROUPS = {"A_isolation": 14, "B_boundary": 8, "C_adjacent_pair": 12,
                            "D_dominance": 1}
EXPECTED_GROUP_LETTERS = {"A": 14, "B": 8, "C": 12, "D": 1}
EXPECTED_INTENTS = {"rule": 14, "boundary": 8, "ordering": 13}
EXPECTED_ACCEPTED_IDS = (
    "chain.block_structure.bnd_09_count_at_limit_accept",
    "chain.block_structure.bnd_12_one_above_median_accept",
    "chain.block_structure.bnd_13_equal_limit_accept",
    "chain.block_structure.bnd_13_near_max_last_exact_accept",
    "chain.block_structure.bnd_13_near_max_saturating_accept",
)
EXPECTED_RULE_COVERAGE = list(range(RULE_FIRST, RULE_LAST + 1))
# `manifest.precedence.adjacent_pairs_represented`: the eleven adjacent pairs one
# case or another violates together, with the smaller row named. (B-8, B-9) is
# absent on purpose — the two conditions are mutually exclusive, so no input can
# order them, and the corpus says so in `deferred_pairs`.
EXPECTED_ADJACENT_PAIRS = [
    [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [9, 10], [10, 11], [11, 12],
    [12, 13], [13, 14], [14, 15],
]
EXPECTED_RESOLVED_PAIRS = [[13, 14]]
EXPECTED_DEFERRED_PAIRS = [[8, 9]]
EXPECTED_REUSED_FROM_P41 = (
    "chain.block_structure.iso_08_no_transactions",
    "chain.block_structure.iso_14_root_mismatch",
    "chain.block_structure.bnd_13_near_max_saturating_accept",
    "chain.block_structure.pair_14_15_root_mismatch_and_failing_pow",
    "chain.block_structure.pair_14_15_zero_root_claim_and_failing_pow",
)
EXPECTED_SYNTHETIC = (
    "chain.block_structure.pair_12_13_old_and_future",
    "chain.block_structure.chaos_all_later_guards_broken",
)

# The coverage the phase is required to demonstrate, expressed as corpus facts this
# wrapper proves before it runs anything. If any of them stopped being true the
# differential would silently stop covering it, so each names the cases that carry
# it and `check_required_coverage` insists they are still there and still mean what
# they say.
PRECEDENCE_WITNESSES = {
    # row -> rows it must dominate in the named case
    "chain.block_structure.pair_13_14_future_and_stale_root": (13, 14),
    "chain.block_structure.pair_14_15_root_mismatch_and_failing_pow": (14, 15),
    "chain.block_structure.pair_14_15_zero_root_claim_and_failing_pow": (14, 15),
}
COUNT_BOUNDARY_CASES = {
    "chain.block_structure.bnd_09_count_at_limit_accept": EXPECTED_MAX_TRANSACTIONS,
    "chain.block_structure.iso_09_too_many_transactions": EXPECTED_MAX_TRANSACTIONS + 1,
    "chain.block_structure.pair_09_10_over_limit_and_first_not_coinbase": (
        EXPECTED_MAX_TRANSACTIONS + 1),
}
SATURATING_CASES = (
    "chain.block_structure.bnd_13_near_max_edge_reject",
    "chain.block_structure.bnd_13_near_max_last_exact_accept",
    "chain.block_structure.bnd_13_near_max_saturating_accept",
)
# The two boundary pairs the phase must show it actually sat on, by name. Each is a
# corpus fact, and `check_required_coverage` proves the named case still sits where
# its name claims rather than merely still existing.
MEDIAN_BOUNDARY_CASES = (
    "chain.block_structure.bnd_12_equal_median_reject",
    "chain.block_structure.bnd_12_one_above_median_accept",
)
FUTURE_BOUNDARY_CASES = (
    "chain.block_structure.bnd_13_equal_limit_accept",
    "chain.block_structure.bnd_13_one_above_reject",
)
MULTIPLE_VIOLATION_MIN_ROWS = 3

# The rows whose variant carries data, read off the oracle's own payloads. They have
# to agree with the `std::get_if` chain in `op_block_structure`, because a tenth
# payload-bearing row would make the kernel publish a key no fixture declared while
# still agreeing on `error_payload_present` — a hole in the diff, not a rule change.
EXPECTED_PAYLOAD_RULES = (3, 4, 6, 7, 9, 12, 13)

# The fixture dialect this wrapper writes and `kernel/conformance` reads. The runner
# ignores META, so it is here to make a captured fixture self-describing.
FIXTURE_SCHEMA = "zro-p42-fixture/1"

# The three cases the corruption probe replays one output at a time. Small, trivial
# engine, and between them they cover an accepted case, a payload-bearing rejection,
# and a rejection whose evidence is the whole point: `iso_14_root_mismatch` is the
# one whose `roots_match` has to be able to fail.
PROBE_CASE_IDS = (
    "chain.block_structure.bnd_12_one_above_median_accept",
    "chain.block_structure.iso_03_wrong_chain",
    "chain.block_structure.iso_14_root_mismatch",
)

MASK64 = (1 << 64) - 1
HARNESS_DIR = Path(__file__).resolve().parents[2] / "test" / "harness"


class MappingError(RuntimeError):
    """The corpus, the oracle or the C++ API cannot be reconciled. Exit 2."""


class UnsupportedCase(RuntimeError):
    """One fixture the current C++ API cannot represent. Never a pass, never a skip."""


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
        return FixtureCase(self.case_id, self.op, list(self.inputs), outputs,
                           list(self.deferred))


@dataclass
class Evidence:
    """What the oracle says about one case, kept for the report and the diff.

    `violated_rules` and `reported_rule` are the precedence expectations: the runner
    never sees them, and the only reason they appear in the output of this program is
    so a reader can see which row the kernel was required to reach first.
    """

    case_id: str
    accepted: bool
    reported_rule: object
    violated_rules: list[int]
    error_kind: object
    error_payload: object
    engine: str
    leaf_count: int
    timestamp: int
    median_time_past: int
    now: int
    roots_match: bool
    pow_meets_target: bool
    deferred: list[str] = field(default_factory=list)


def text(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise MappingError(f"cannot render {type(value).__name__} as fixture text")


def error_kind_text(value: object) -> str:
    """The oracle emits JSON null for "no rejection"; the kernel names kNone "None"."""
    return "None" if value is None else text(value)


def one_line(value: str) -> str:
    return " ".join(str(value).split())[:300]


def corrupted(value: str) -> str:
    """A value the runner cannot agree with, in the same shape as the real one."""
    if value in ("true", "false"):
        return "false" if value == "true" else "true"
    if re.fullmatch(r"[0-9]+", value):
        return str(int(value) + 1)
    if re.fullmatch(r"[0-9a-f]+", value):
        return value[:-1] + ("0" if value[-1] != "0" else "1")
    return value + "-corrupted"


def load_json(path: Path) -> dict:
    if not path.is_file():
        raise MappingError(f"corpus file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as error:
        raise MappingError(f"{path}: is not valid JSON ({error})") from error


def require_rust_origin(where: str, value: object) -> None:
    """The corpus must keep naming Rust as the origin of its expected values.

    This is the one provenance claim a differential can depend on without checking
    it: if the exporter ever stopped being the origin, the published verdicts would
    be describing something other than the reference, and a green run here would mean
    nothing about consensus.
    """
    if not isinstance(value, str) or "Rust" not in value:
        raise MappingError(f"{where}: does not name Rust as the origin of its values: {value!r}")


# --- the independent oracle --------------------------------------------------

ORACLE_NAMES = (
    "_verify_block_structure",
    "BLOCK_RULE_ERRORS",
    "BLOCK_STRUCTURE_GROUP",
    "MAX_BLOCK_TRANSACTIONS",
    "MAX_FUTURE_SECONDS",
    "SCRATCHPAD_PRESETS",
    "TRIVIAL_ENGINE_NAME",
    "SCRATCHPAD_ENGINE_NAME",
    "ENGINE_ID_TRIVIAL",
    "ENGINE_ID_SCRATCHPAD",
    "MASK64",
    # The exception the oracle raises for an input no reference implementation can
    # evaluate. It has to come from the oracle itself: class identity is not
    # something a `except` clause can be written against by name.
    "Unsupported",
)


def load_oracle():
    """Imports the P4.2B-2 verifier and freezes the contract this diff relies on.

    The oracle is `zro_vectors._verify_block_structure` — the same function
    `test/harness/test_block_structure_verifier.py` tests and `run_vectors.py` never
    registers for this group. It reads only `case["input"]`, evaluates every rule
    condition without short-circuiting, and shares no code with kernel/src/. Failing
    to import it fails the gate rather than skipping the comparison, because a run
    without the oracle would have nothing to diff against.
    """
    path = HARNESS_DIR / "zro_vectors.py"
    if not path.is_file():
        raise MappingError(f"oracle not found at {path}")
    if str(HARNESS_DIR) not in sys.path:
        sys.path.insert(0, str(HARNESS_DIR))
    try:
        import zro_vectors  # type: ignore
    except Exception as error:  # pragma: no cover - an import failure is a gate failure
        raise MappingError(f"oracle failed to import: {error}") from error

    oracle = {}
    for name in ORACLE_NAMES:
        if not hasattr(zro_vectors, name):
            raise MappingError(f"oracle has no {name}")
        oracle[name] = getattr(zro_vectors, name)

    if oracle["BLOCK_STRUCTURE_GROUP"] != "chain.block_structure.":
        raise MappingError(f"oracle group prefix changed: {oracle['BLOCK_STRUCTURE_GROUP']!r}")
    if oracle["MAX_BLOCK_TRANSACTIONS"] != EXPECTED_MAX_TRANSACTIONS:
        raise MappingError(
            f"oracle MAX_BLOCK_TRANSACTIONS is {oracle['MAX_BLOCK_TRANSACTIONS']}, "
            f"the corpus and the kernel both say {EXPECTED_MAX_TRANSACTIONS}")
    if oracle["MAX_FUTURE_SECONDS"] != EXPECTED_MAX_FUTURE_SECONDS:
        raise MappingError(
            f"oracle MAX_FUTURE_SECONDS is {oracle['MAX_FUTURE_SECONDS']}, "
            f"the kernel's kMaxFutureSeconds says {EXPECTED_MAX_FUTURE_SECONDS}")
    if oracle["MASK64"] != MASK64:
        raise MappingError("oracle MASK64 is not 2**64 - 1")
    rows = sorted(oracle["BLOCK_RULE_ERRORS"])
    if rows != EXPECTED_RULE_COVERAGE:
        raise MappingError(f"oracle BLOCK_RULE_ERRORS covers rows {rows}, expected {EXPECTED_RULE_COVERAGE}")
    if sorted(KERNEL_NUMERIC_BY_RULE) != rows:
        raise MappingError(
            "this file's row -> BlockErrorKind numeric table no longer covers exactly the rows "
            f"the oracle names ({rows}); a row would be replayed with no numeric expectation")
    names = sorted(oracle["BLOCK_RULE_ERRORS"].values())
    if len(set(names)) != len(names):
        raise MappingError("oracle BLOCK_RULE_ERRORS names one variant twice")
    for name in KERNEL_ENGINES:
        if name not in (oracle["TRIVIAL_ENGINE_NAME"], oracle["SCRATCHPAD_ENGINE_NAME"]):
            raise MappingError(f"oracle names no {name}")
    return oracle


def rule_of_kind(oracle: dict, kind: object) -> object:
    """Inverts the oracle's own row -> variant table.

    Deliberately not a second table: the mapping from a variant name to a rule row
    belongs to the oracle, so this differential cannot end up disagreeing with the
    verifier about which row `RootMismatch` is.
    """
    if kind is None:
        return None
    by_name = {name: row for row, name in oracle["BLOCK_RULE_ERRORS"].items()}
    if kind not in by_name:
        raise MappingError(f"oracle names variant {kind!r}, which no rule row returns")
    return by_name[kind]


def oracle_verdict(oracle: dict, case: dict) -> dict:
    """The independent expectation for one case, or a classified failure."""
    try:
        return oracle["_verify_block_structure"](case)
    except oracle["Unsupported"] as error:  # type: ignore[misc]
        raise UnsupportedCase(f"{case.get('id')}: {error}") from error
    except Exception as error:
        # A VectorMismatch here means the fixture is malformed, and a malformed
        # fixture must never be allowed to look like a C++ bug.
        raise MappingError(f"{case.get('id')}: the oracle could not re-derive it ({error})") from error


# --- corpus -> fixture -------------------------------------------------------

def internal_hex(value: object, case_id: str, what: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise MappingError(
            f"{case_id}: {what} is not 64 lowercase hex characters (32 bytes): {value!r}")
    return value


def digest_pair(value: object, case_id: str, what: str) -> tuple[str, str]:
    """Both published forms of one digest, with the display form verified against
    the internal one rather than trusted."""
    if not isinstance(value, dict) or set(value) != {"display_hex", "internal_hex"}:
        keys = sorted(value) if isinstance(value, dict) else repr(value)
        raise MappingError(f"{case_id}: {what} keys {keys}, expected the digest pair")
    internal = internal_hex(value["internal_hex"], case_id, f"{what}.internal_hex")
    display = value["display_hex"]
    if not isinstance(display, str) or display != bytes.fromhex(internal)[::-1].hex():
        raise MappingError(f"{case_id}: {what}.display_hex is not the internal bytes reversed")
    return internal, display


def hex_bytes(value: object, case_id: str, what: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value or ""):
        raise MappingError(f"{case_id}: {what} is not even-length lowercase hex: {value!r}")
    return value


def exact_keys(mapping: dict, wanted: tuple[str, ...], case_id: str, what: str) -> None:
    missing = [name for name in wanted if name not in mapping]
    if missing:
        raise MappingError(f"{case_id}: {what} is missing {missing}")
    extra = sorted(set(mapping) - set(wanted))
    if extra:
        raise MappingError(f"{case_id}: {what} keys {extra} are unmapped; map them or defer them")


def integer(value: object, case_id: str, what: str, width: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MappingError(f"{case_id}: {what} is {value!r}, not an integer")
    if not 0 <= value <= width:
        raise MappingError(f"{case_id}: {what}={value} is outside 0..{width}")
    return int(value)


def split_expected(expected: dict, mapped: set[str], case_id: str) -> list[str]:
    """Returns the deferred keys and refuses to drop an unrecognised one."""
    overlap = sorted(mapped & set(DEFERRED_KEYS))
    if overlap:
        raise MappingError(f"{case_id}: keys {overlap} are both mapped and deferred")
    unknown = sorted(set(expected) - mapped - set(DEFERRED_KEYS))
    if unknown:
        raise MappingError(f"{case_id}: expected keys {unknown} are neither mapped nor deferred")
    return sorted(key for key in expected if key in DEFERRED_KEYS)


# The expected keys this file replays, before any case is read. `split_expected`
# turns the difference between that and the corpus's published set into the deferral
# list, so the two can never silently disagree about what was covered.
MAPPED_EXPECTED_KEYS = {
    "accepted",
    "claimed_root",
    "coinbase_count",
    "coinbase_flags",
    "computed_root",
    "error_kind",
    "error_payload",
    "first_is_coinbase",
    "leaf_count",
    "proof_of_work_meets_target",
    "roots_match",
}


def transaction_inputs(case: dict) -> list[str]:
    """One `IN tx_hex=` per published transaction, in corpus order.

    Both shapes the corpus uses are accepted because both are bytes the codec can
    read: the rich shape publishes `serialized_hex` beside its fields (the oracle has
    already proved the fields re-encode to those bytes), and the `transactions_hex`
    shape publishes the bytes alone. Either way the kernel decodes the bytes the
    fixture published rather than a re-encoding this file could have got wrong.
    """
    case_id = case["id"]
    data = case["input"]
    rich = "transactions" in data
    if rich == ("transactions_hex" in data):
        raise MappingError(
            f"{case_id}: input must carry exactly one of 'transactions' or 'transactions_hex'")
    published = data["transactions"] if rich else data["transactions_hex"]
    if not isinstance(published, list):
        raise MappingError(f"{case_id}: the transaction list is not a list")
    if int(data["tx_count"]) != len(published):
        raise MappingError(
            f"{case_id}: tx_count is {data['tx_count']}, {len(published)} transactions published")
    out: list[str] = []
    for index, item in enumerate(published):
        spot = f"{case_id}.transactions[{index}]"
        if rich:
            if not isinstance(item, dict):
                raise MappingError(f"{spot}: a transaction is not an object")
            exact_keys(item, RICH_TX_FIELDS, case_id, f"transactions[{index}]")
            if int(item["serialized_len"]) * 2 != len(item["serialized_hex"]):
                raise MappingError(f"{spot}: serialized_len disagrees with serialized_hex")
            out.append(hex_bytes(item["serialized_hex"], spot, "serialized_hex"))
        else:
            out.append(hex_bytes(item, spot, "transaction hex"))
    return out


def engine_inputs(case: dict, oracle: dict) -> list[tuple[str, str]]:
    """The IN lines that tell the runner which engine this node is configured with.

    The context's engine name is what B-6 compares against and what B-15 hashes with,
    so it comes from `validation_context.engine` and its budget from
    `engine_config.preset`, through the oracle's own preset table. The header's
    `engine_id` byte is a peer's claim and is deliberately never consulted here —
    selecting an engine from it would let the fixture choose the hash function the
    validator used, which is the trust boundary pow.h documents.
    """
    case_id = case["id"]
    context = case["input"]["validation_context"]
    name = context["engine"]
    if name == oracle["TRIVIAL_ENGINE_NAME"]:
        if case["input"].get("engine_config") is not None:
            raise MappingError(f"{case_id}: a trivial context still publishes an engine_config")
        return [("engine", name)]
    if name == oracle["SCRATCHPAD_ENGINE_NAME"]:
        config = case["input"].get("engine_config")
        if not isinstance(config, dict):
            raise MappingError(f"{case_id}: a scratchpad context publishes no engine_config")
        if config.get("engine_name") != oracle["SCRATCHPAD_ENGINE_NAME"]:
            raise MappingError(f"{case_id}: engine_config names {config.get('engine_name')!r}")
        if config.get("engine_id") != oracle["ENGINE_ID_SCRATCHPAD"]:
            raise MappingError(f"{case_id}: engine_config ids the scratchpad engine "
                               f"{config.get('engine_id')!r}")
        preset = config.get("preset")
        presets = oracle["SCRATCHPAD_PRESETS"]
        if preset not in presets:
            raise UnsupportedCase(
                f"{case_id}: scratchpad preset {preset!r} is not modelled by the oracle, "
                "so no budget can be handed to the kernel for it")
        memory_bytes, rounds = presets[preset]
        return [
            ("engine", name),
            ("engine_id", text(oracle["ENGINE_ID_SCRATCHPAD"])),
            ("memory_bytes", text(memory_bytes)),
            ("rounds", text(rounds)),
        ]
    raise UnsupportedCase(
        f"{case_id}: context engine {name!r} has no kernel implementation; the fixture "
        "cannot be replayed rather than replayed under a different algorithm")


def map_case(case: dict, oracle: dict) -> tuple[FixtureCase, Evidence]:
    """One fixture, its oracle-derived expectations, and the evidence behind them."""
    case_id = case["id"]
    expected = case["expected"]
    verdict = oracle_verdict(oracle, case)
    if verdict != expected:
        differing = sorted(k for k in set(verdict) | set(expected)
                           if verdict.get(k) != expected.get(k))
        raise MappingError(
            f"{case_id}: the independent oracle disagrees with the published expectation "
            f"on {differing}; the corpus and the verifier must be reconciled before any "
            "kernel is blamed for a diff")

    data = case["input"]
    header, context = data["header"], data["validation_context"]
    exact_keys(header, HEADER_FIELDS, case_id, "input.header")
    exact_keys(context, CONTEXT_FIELDS, case_id, "input.validation_context")
    for key in ("group", "tx_count", "engine_config", "reused_from", "synthetic_context"):
        if key not in data:
            raise MappingError(f"{case_id}: input.{key} is missing")

    inputs: list[tuple[str, str]] = list(engine_inputs(case, oracle))
    # `engine_inputs` already emitted the `engine` line — it is the field the engine
    # resolution branches on — and `Case::one` fails a duplicate rather than picking
    # one, so the context loop has to skip it instead of writing it a second time.
    for name in CONTEXT_FIELDS:
        if name == "engine":
            continue
        inputs.append((name, text(context[name])))
    for name in HEADER_FIELDS:
        value = header[name]
        if name.endswith("_hex"):
            value = internal_hex(value, case_id, f"header.{name}")
        else:
            width = MASK64 if name in ("height", "timestamp", "nonce") else (1 << 32) - 1
            if name == "engine_id":
                width = 0xFF
            value = text(integer(value, case_id, f"header.{name}", width))
        inputs.append((f"header.{name}", value))
    inputs += [("tx_hex", blob) for blob in transaction_inputs(case)]

    # The compared set, in a fixed order, because the runner reports the FIRST
    # differing field and that answer should read as the verdict first and the
    # evidence second. Every value below is the oracle's; none is the kernel's.
    outputs: list[tuple[str, str]] = [
        ("accepted", text(verdict["accepted"])),
        ("error_kind", error_kind_text(verdict["error_kind"])),
    ]
    reported = verdict["reported_rule"]
    numeric = KERNEL_NUMERIC_NONE if reported is None else KERNEL_NUMERIC_BY_RULE[reported]
    outputs.append(("error_kind_numeric", text(numeric)))
    payload = verdict["error_payload"]
    outputs.append(("error_payload_present", text(payload is not None)))
    if payload is not None:
        if not isinstance(payload, dict) or not payload:
            raise MappingError(f"{case_id}: error_payload is {payload!r}, expected a non-empty object")
        for name in sorted(payload):
            outputs.append((f"error_payload_{name}",
                            text(integer(payload[name], case_id, f"error_payload.{name}", MASK64))))
    outputs += [
        ("leaf_count", text(verdict["leaf_count"])),
        ("coinbase_count", text(verdict["coinbase_count"])),
        ("coinbase_flags", text(verdict["coinbase_flags"])),
        ("first_is_coinbase", text(verdict["first_is_coinbase"])),
        ("claimed_root_internal_hex", digest_pair(verdict["claimed_root"], case_id,
                                                  "claimed_root")[0]),
        ("computed_root_internal_hex", digest_pair(verdict["computed_root"], case_id,
                                                   "computed_root")[0]),
        ("roots_match", text(verdict["roots_match"])),
        ("proof_of_work_meets_target", text(verdict["proof_of_work_meets_target"])),
        # B-13's bound, derived from the published clock through the reference's own
        # saturating addition. The kernel answers with `future_timestamp_limit`, so
        # this is the field that separates a saturating port from a wrapping one.
        ("future_limit", text(min(int(context["now"]) + oracle["MAX_FUTURE_SECONDS"], MASK64))),
    ]

    mapped = set(MAPPED_EXPECTED_KEYS)
    deferred = split_expected(expected, mapped, case_id)
    fixture = FixtureCase(case_id, OP, inputs, outputs, deferred)

    engine = str(context["engine"])
    evidence = Evidence(
        case_id=case_id,
        accepted=bool(verdict["accepted"]),
        reported_rule=reported,
        violated_rules=list(verdict["violated_rules"]),
        error_kind=verdict["error_kind"],
        error_payload=payload,
        engine=engine,
        leaf_count=int(verdict["leaf_count"]),
        timestamp=int(header["timestamp"]),
        median_time_past=int(context["median_time_past"]),
        now=int(context["now"]),
        roots_match=bool(verdict["roots_match"]),
        pow_meets_target=bool(verdict["proof_of_work_meets_target"]),
        deferred=deferred,
    )
    return fixture, evidence


# --- corpus integrity --------------------------------------------------------

def expect(where: str, actual: object, wanted: object) -> None:
    """One integrity fact about the corpus, checked before anything is replayed.

    Every failure here is a mapping failure (exit 2), never a differential mismatch:
    the question at this stage is whether the file is still the file this wrapper
    knows how to read, not whether the kernel agrees with it.
    """
    if actual != wanted:
        raise MappingError(f"{where}: {actual!r}, expected {wanted!r}")


def load_corpus(vectors: Path) -> tuple[list[dict], str]:
    """Reads the one file this differential replays and freezes its envelope."""
    cases: list[dict] = []
    source_commit = ""
    for name in SOURCE_FILES:
        document = load_json(vectors / name)
        for key in ("group", "schema", "source_commit", "case_count", "provenance"):
            if key not in document:
                raise MappingError(f"{name}: top-level {key} is missing")
        expect(f"{name}.group", document["group"], EXPECTED_GROUP)
        expect(f"{name}.schema", document["schema"], EXPECTED_SCHEMA)
        expect(f"{name}.case_count", document["case_count"], EXPECTED_FILE_CASES[name])
        require_rust_origin(f"{name}.provenance", document["provenance"])
        published = document["source_commit"]
        if not isinstance(published, str) or not re.fullmatch(r"[0-9a-f]{40}", published):
            raise MappingError(f"{name}.source_commit is not a commit hash: {published!r}")
        if source_commit and source_commit != published:
            raise MappingError(f"{name}.source_commit disagrees with the other corpus file")
        source_commit = published
        listed = document["cases"]
        held = len(listed) if isinstance(listed, list) else "not a list"
        if not isinstance(listed, list) or held != document["case_count"]:
            raise MappingError(f"{name}: case_count says {document['case_count']}, "
                               f"the array holds {held}")
        cases.extend(listed)
    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(f"corpus holds {len(cases)} cases, this differential expects "
                           f"{EXPECTED_CASE_COUNT}")
    return cases, source_commit


def check_manifest(vectors: Path) -> dict:
    """The manifest's own claims about the corpus, kept for the witness cross-check.

    This is not a re-read of the published numbers for their own sake. It is the
    proof that the totals the phase's coverage claims rest on are still the totals of
    the array being replayed: a manifest that said 36 while the file held 35 would
    otherwise let a case go unprocessed in a run that reported success.
    """
    manifest = load_json(vectors / "manifest.json")
    for key in ("phase", "schema", "group", "total_cases", "case_ids", "files", "groups",
                "intents", "verdicts", "rule_coverage", "precedence", "resolved_pairs",
                "deferred_pairs", "reused_from_p41", "synthetic_context_cases",
                "authority_split", "source_commit", "provenance"):
        if key not in manifest:
            raise MappingError(f"manifest.json: {key} is missing")
    expect("manifest.phase", manifest["phase"], EXPECTED_PHASE)
    expect("manifest.schema", manifest["schema"], EXPECTED_SCHEMA)
    expect("manifest.group", manifest["group"], EXPECTED_GROUP)
    expect("manifest.total_cases", manifest["total_cases"], EXPECTED_CASE_COUNT)
    expect("manifest.source_commit", manifest["source_commit"], EXPECTED_SOURCE_COMMIT)
    require_rust_origin("manifest.provenance", manifest["provenance"])

    # The published id table, in the corpus's order, exactly.
    expect("manifest.case_ids", list(manifest["case_ids"]), list(EXPECTED_CASE_IDS))

    files = manifest["files"]
    if not isinstance(files, list) or len(files) != len(SOURCE_FILES):
        raise MappingError(f"manifest.files: {files!r}, expected {len(SOURCE_FILES)} entry/entries")
    for entry in files:
        path = entry.get("path")
        if path not in EXPECTED_FILE_CASES:
            raise MappingError(f"manifest.files names an unplanned corpus file: {path!r}")
        expect(f"manifest.files[{path}].group", entry.get("group"), EXPECTED_GROUP)
        expect(f"manifest.files[{path}].cases", entry.get("cases"), EXPECTED_FILE_CASES[path])

    groups = {key: value for key, value in manifest["groups"].items() if key != "sum"}
    expect("manifest.groups", groups, EXPECTED_MANIFEST_GROUPS)
    expect("manifest.groups.sum", manifest["groups"].get("sum"), EXPECTED_CASE_COUNT)
    expect("manifest.intents", manifest["intents"], EXPECTED_INTENTS)

    verdicts = manifest["verdicts"]
    expect("manifest.verdicts.accepted", verdicts.get("accepted"), len(EXPECTED_ACCEPTED_IDS))
    expect("manifest.verdicts.rejected", verdicts.get("rejected"),
           EXPECTED_CASE_COUNT - len(EXPECTED_ACCEPTED_IDS))
    expect("manifest.verdicts.accepted_case_ids", sorted(verdicts.get("accepted_case_ids", [])),
           sorted(EXPECTED_ACCEPTED_IDS))
    if verdicts.get("accepted", 0) + verdicts.get("rejected", 0) != EXPECTED_CASE_COUNT:
        raise MappingError("manifest.verdicts does not account for every case")

    coverage = manifest["rule_coverage"]
    expect("manifest.rule_coverage.rules_covered", sorted(coverage.get("rules_covered", [])),
           EXPECTED_RULE_COVERAGE)
    for key in ("reported_by_at_least_one_case", "violated_in_at_least_one_case"):
        if key not in coverage:
            raise MappingError(f"manifest.rule_coverage is missing {key}")
        expect(f"manifest.rule_coverage.{key}", sorted(coverage[key]), EXPECTED_RULE_COVERAGE)

    precedence = manifest["precedence"]
    expect("manifest.precedence.adjacent_pairs_represented",
           [list(pair) for pair in precedence.get("adjacent_pairs_represented", [])],
           EXPECTED_ADJACENT_PAIRS)
    if "basis" not in precedence:
        raise MappingError("manifest.precedence no longer states what a witness is")
    origin = manifest["authority_split"].get("rust_is_the_only_origin_of")
    if not isinstance(origin, list) or not origin:
        raise MappingError("manifest.authority_split no longer lists what only Rust originates")
    require_rust_origin("manifest.description", manifest.get("description"))
    expect("manifest.resolved_pairs",
           [list(entry.get("pair", [])) for entry in manifest["resolved_pairs"]],
           EXPECTED_RESOLVED_PAIRS)

    deferred = manifest["deferred_pairs"]
    expect("manifest.deferred_pairs", [list(entry.get("pair", [])) for entry in deferred],
           EXPECTED_DEFERRED_PAIRS)
    # The limitation the phase is required to preserve, quoted back from the corpus
    # rather than restated in this file's own words: if the corpus ever decides the
    # pair is representable, this wrapper stops rather than keeping the disclaimer
    # alive on someone else's behalf.
    for entry in deferred:
        if entry.get("pair") != [8, 9]:
            continue
        reason = str(entry.get("reason", ""))
        if "mutually exclusive" not in reason:
            raise MappingError("manifest.deferred_pairs[8,9].reason no longer states the "
                               f"mutual exclusion that makes the pair unrepresentable: {reason!r}")
        claimed = str(entry.get("not_claimed", ""))
        if "pair_08_09" not in claimed:
            raise MappingError("manifest.deferred_pairs[8,9].not_claimed no longer disclaims "
                               f"a pair_08_09 witness: {claimed!r}")

    expect("manifest.reused_from_p41", list(manifest["reused_from_p41"]),
           list(EXPECTED_REUSED_FROM_P41))
    expect("manifest.synthetic_context_cases", list(manifest["synthetic_context_cases"]),
           list(EXPECTED_SYNTHETIC))
    return manifest


def check_case_shape(cases: list[dict], oracle: dict) -> None:
    """Per-case facts, taken from the array itself instead of the manifest about it."""
    expect("corpus case ids", [case.get("id") for case in cases], list(EXPECTED_CASE_IDS))
    prefix = oracle["BLOCK_STRUCTURE_GROUP"]
    for case in cases:
        case_id = case["id"]
        if not case_id.startswith(prefix):
            raise MappingError(f"{case_id}: outside the oracle's group prefix {prefix!r}")
        expect(f"{case_id}.keys", sorted(case), ["expected", "id", "independent_check",
                                                 "input", "intent"])
        # `independent_check` is the corpus's own prose claim about what makes the
        # case falsifiable from its published input. It is not an expected value and
        # is not replayed; requiring a non-empty string only stops the field from
        # becoming a placeholder.
        claim = case["independent_check"]
        if not isinstance(claim, str) or not claim.strip():
            raise MappingError(f"{case_id}: independent_check is {claim!r}, expected prose")
        # The transaction list is the one input key with two legal spellings, so its
        # shape is settled in `transaction_inputs`; here the other seven must be
        # exactly present and nothing else may have appeared.
        names = sorted(set(case["input"]) - {"transactions", "transactions_hex"})
        expect(f"{case_id}.input keys", names, sorted(INPUT_KEYS))

    letter = {"iso": "A", "bnd": "B", "pair": "C", "chaos": "D"}
    counts: dict[str, int] = {}
    intents: dict[str, int] = {}
    for case in cases:
        stem = case["id"][len(prefix):].split("_", 1)[0]
        if stem not in letter:
            raise MappingError(f"{case['id']}: no group letter for {stem!r}")
        expect(f"{case['id']}.input.group", case["input"]["group"], letter[stem])
        counts[letter[stem]] = counts.get(letter[stem], 0) + 1
        intents[case["intent"]] = intents.get(case["intent"], 0) + 1
    expect("group letters counted from the cases", counts, EXPECTED_GROUP_LETTERS)
    expect("intents counted from the cases", intents, EXPECTED_INTENTS)

    accepted = sorted(case["id"] for case in cases if case["expected"]["accepted"] is True)
    expect("accepted cases counted from the corpus", accepted, sorted(EXPECTED_ACCEPTED_IDS))
    reused = sorted(case["id"] for case in cases if case["input"]["reused_from"] is not None)
    expect("cases carrying a reused_from", reused, sorted(EXPECTED_REUSED_FROM_P41))
    synthetic = sorted(case["id"] for case in cases if case["input"]["synthetic_context"])
    expect("cases carrying synthetic_context", synthetic, sorted(EXPECTED_SYNTHETIC))


# --- required coverage -------------------------------------------------------

def check_required_coverage(evidences: list[Evidence], oracle: dict,
                            manifest: dict) -> list[str]:
    """Proves the coverage the phase is required to demonstrate is still being shown.

    Every assertion below reads the oracle's independently derived verdicts, so a
    corpus that lost a witness loses the attestation instead of quietly weakening the
    run. The return value is the list of attestation lines the report prints — evidence
    for a reader, not a second set of expectations.
    """
    notes: list[str] = []
    by_id = {evidence.case_id: evidence for evidence in evidences}
    if len(by_id) != len(evidences):
        raise MappingError("duplicate case id reached the differential")

    # 1. The precedence invariant, case by case. The reported row is the smallest row
    #    the input fails, and the variant name is the one the oracle's own table binds
    #    to that row. Without this, "the diff is against the reported rule" would say
    #    nothing about ordering at all.
    for evidence in evidences:
        smallest = min(evidence.violated_rules) if evidence.violated_rules else None
        if evidence.reported_rule != smallest:
            raise MappingError(
                f"{evidence.case_id}: reported_rule is {evidence.reported_rule!r} while the "
                f"oracle's violated set {evidence.violated_rules} starts at {smallest!r}")
        variant = None if smallest is None else oracle["BLOCK_RULE_ERRORS"][smallest]
        if evidence.error_kind != variant:
            raise MappingError(
                f"{evidence.case_id}: error_kind {evidence.error_kind!r} is not the variant "
                f"row {smallest} returns ({variant!r})")
    notes.append(f"reported == min(violated) and variant == BLOCK_RULE_ERRORS[row] for all "
                 f"{len(evidences)} cases")

    # 2. The corpus's own witness table, agreed with by the independent oracle. These
    #    are the rows the manifest claims one guard dominates another; the oracle had
    #    to reach the same set and the same head from the published input alone.
    checked = 0
    for witness in manifest["precedence"].get("witnesses", []):
        evidence = by_id.get(witness.get("id"))
        if evidence is None:
            raise MappingError(f"manifest witness {witness.get('id')!r} is not a case here")
        expect(f"manifest witness {evidence.case_id}.violated_rules",
               sorted(evidence.violated_rules), sorted(witness["violated_rules"]))
        expect(f"manifest witness {evidence.case_id}.reported_rule",
               evidence.reported_rule, witness["reported_rule"])
        checked += 1
    notes.append(f"{checked} manifest precedence witnesses re-derived by the oracle from the "
                 "published input, agreeing on both the set and the head")

    # 3. B-3 through B-15, each named by at least one case's own verdict.
    reported = {int(evidence.reported_rule) for evidence in evidences
                if evidence.reported_rule is not None}
    missing = [row for row in EXPECTED_RULE_COVERAGE if row not in reported]
    if missing:
        raise MappingError(f"no case reports rule row(s) {missing}, so B-{missing[0]} is "
                           "no longer covered")
    notes.append("B-3 through B-15 each reported by at least one case")

    # 4. The three precedence witnesses the phase names, and the observable fact that
    #    makes each a witness rather than a single-rule observation: the dominated row
    #    has to be visibly failing underneath the verdict that stopped earlier.
    dominated = {(13, 14): ("roots_match", lambda e: e.roots_match is False),
                 (14, 15): ("pow_meets_target", lambda e: e.pow_meets_target is False)}
    for case_id, pair in PRECEDENCE_WITNESSES.items():
        evidence = by_id.get(case_id)
        if evidence is None:
            raise MappingError(f"required precedence witness {case_id} is not in the corpus")
        if sorted(evidence.violated_rules) != sorted(pair):
            raise MappingError(
                f"{case_id}: the oracle says it violates {evidence.violated_rules}, expected "
                f"exactly {list(pair)} — a witness that also fails an earlier row proves "
                "nothing about this pair")
        if evidence.reported_rule != pair[0]:
            raise MappingError(f"{case_id}: reported row {evidence.reported_rule}, expected "
                               f"B-{pair[0]} to dominate B-{pair[1]}")
        field, holds = dominated[pair]
        if not holds(evidence):
            raise MappingError(
                f"{case_id}: {field} no longer shows B-{pair[1]} failing underneath the "
                f"B-{pair[0]} verdict, so the case has stopped witnessing the ordering")
    notes.append("B-13 -> B-14 and both B-14 -> B-15 witnesses, each with the dominated row's "
                 "own production-evidence field agreeing that it really was failing")

    # 5. The transaction-count boundary, both sides of it.
    for case_id, wanted in COUNT_BOUNDARY_CASES.items():
        evidence = by_id.get(case_id)
        if evidence is None:
            raise MappingError(f"required count boundary {case_id} is not in the corpus")
        if evidence.leaf_count != wanted:
            raise MappingError(f"{case_id}: publishes {evidence.leaf_count} transactions, "
                               f"expected {wanted}")
        admissible = wanted <= oracle["MAX_BLOCK_TRANSACTIONS"]
        if evidence.accepted is not admissible:
            verdict = "accepted" if evidence.accepted else "rejected"
            raise MappingError(
                f"{case_id}: {wanted} transactions was {verdict}, but the guard is "
                f"`len() > {oracle['MAX_BLOCK_TRANSACTIONS']}`, so it must be "
                f"{'accepted' if admissible else 'rejected'}")
        if not admissible:
            payload = evidence.error_payload if isinstance(evidence.error_payload, dict) else {}
            if payload.get("count") != wanted:
                raise MappingError(
                    f"{case_id}: the rejection does not read the length back out of the "
                    f"variant: payload={payload}, list={wanted}")
    notes.append(f"{EXPECTED_MAX_TRANSACTIONS} transactions accepted, "
                 f"{EXPECTED_MAX_TRANSACTIONS + 1} rejected, the count read back out of the "
                 "variant as the exact payload")

    # 6. Median-time-past equality, and the one-above neighbour that accepts.
    equal, above = (by_id[name] for name in MEDIAN_BOUNDARY_CASES)
    payload = equal.error_payload if isinstance(equal.error_payload, dict) else {}
    if equal.accepted or payload.get("median") != equal.median_time_past:
        raise MappingError(f"{equal.case_id}: no longer the reject at timestamp == median "
                           f"(timestamp={equal.timestamp}, median={equal.median_time_past}, "
                           f"payload={equal.error_payload})")
    if payload.get("found") != equal.timestamp or equal.timestamp != equal.median_time_past:
        raise MappingError(f"{equal.case_id}: the payload does not report the equality it "
                           f"claims: {payload} vs timestamp {equal.timestamp}")
    if not above.accepted or above.timestamp != above.median_time_past + 1:
        raise MappingError(
            f"{above.case_id}: expected timestamp == median + 1 and an accept, got "
            f"timestamp={above.timestamp}, median={above.median_time_past}, "
            f"accepted={above.accepted}")
    notes.append("median-time-past equality rejects with {median, found}, one above accepts")

    # 7. Future-time equality and one second over it.
    at_limit, over = (by_id[name] for name in FUTURE_BOUNDARY_CASES)
    span = oracle["MAX_FUTURE_SECONDS"]
    if not at_limit.accepted or at_limit.timestamp != min(at_limit.now + span, MASK64):
        raise MappingError(f"{at_limit.case_id}: no longer exactly on now + {span} "
                           f"(timestamp={at_limit.timestamp}, now={at_limit.now})")
    over_payload = over.error_payload if isinstance(over.error_payload, dict) else {}
    if over.accepted or over.reported_rule != 13 or over.timestamp != over.now + span + 1:
        raise MappingError(f"{over.case_id}: no longer the one-second-over reject "
                           f"(timestamp={over.timestamp}, now={over.now}, "
                           f"reported={over.reported_rule})")
    if over_payload.get("now") != over.now or over_payload.get("found") != over.timestamp:
        raise MappingError(f"{over.case_id}: the B-13 payload does not carry the published "
                           f"clock and timestamp back: {over_payload}")
    notes.append(f"timestamp == now + {span} accepts, == now + {span} + 1 rejects as B-13 "
                 "with {now, found}")

    # 8. Saturating u64 future-time behaviour. `now + 7200` has to overflow in at least
    #    one case, or these three prove nothing a wrapping port could not also pass.
    saturated = 0
    for case_id in SATURATING_CASES:
        evidence = by_id.get(case_id)
        if evidence is None:
            raise MappingError(f"required saturating boundary {case_id} is not in the corpus")
        limit = min(evidence.now + span, MASK64)
        rejects = 13 in evidence.violated_rules
        if (evidence.timestamp > limit) is not rejects:
            raise MappingError(
                f"{case_id}: timestamp {evidence.timestamp} against the oracle's own limit "
                f"{limit} says {'reject' if evidence.timestamp > limit else 'accept'}, the "
                f"verdict says {evidence.error_kind!r}")
        if evidence.now + span > MASK64:
            saturated += 1
            if limit != MASK64:
                raise MappingError(f"{case_id}: the oracle's limit did not saturate at MASK64")
            if not evidence.accepted:
                raise MappingError(f"{case_id}: a saturating bound admits this timestamp, "
                                   "but the corpus rejected it")
    if not saturated:
        raise MappingError(f"no B-13 case overflows now + {span}, so saturating behaviour is "
                           "no longer distinguished from wrapping")
    notes.append(f"{saturated} case(s) where now + {span} overflows u64 and the bound "
                 "saturates at u64::MAX; the verdict agrees with the saturating bound")

    # 9. Simultaneous violations, and the limitation that has to survive.
    multi = [evidence.case_id for evidence in evidences
             if len(evidence.violated_rules) >= MULTIPLE_VIOLATION_MIN_ROWS]
    if not multi:
        raise MappingError("no case violates three or more rows at once, so the differential "
                           "no longer covers simultaneous violations")
    if any(8 in evidence.violated_rules and 9 in evidence.violated_rules
           for evidence in evidences):
        raise MappingError("a case now violates both B-8 and B-9, which the corpus declares "
                           "mutually exclusive; its precedence claim would have to be "
                           "re-derived before this diff could report it")
    if any("pair_08_09" in evidence.case_id for evidence in evidences):
        raise MappingError("the corpus grew a pair_08_09 witness, so the documented B-8/B-9 "
                           "limitation would have to be withdrawn rather than kept silently")
    if 8 not in reported or 9 not in reported:
        raise MappingError("B-8 or B-9 stopped being the reported row of a case of its own")
    notes.append(f"{len(multi)} case(s) violate at least {MULTIPLE_VIOLATION_MIN_ROWS} rows at "
                 "once; B-8 and B-9 stay mutually exclusive, so their relative order stays "
                 "unproven and unclaimed")

    # 10. The payload taxonomy the runner's `std::get_if` chain can serialise at all.
    with_payload = {int(evidence.reported_rule) for evidence in evidences
                    if evidence.reported_rule is not None
                    and evidence.error_payload is not None}
    if sorted(with_payload) != list(EXPECTED_PAYLOAD_RULES):
        raise MappingError(
            f"the oracle attaches a payload to rows {sorted(with_payload)}, while "
            f"op_block_structure serialises payload members for {list(EXPECTED_PAYLOAD_RULES)}; "
            "the diff would compare a payload the runner never publishes")
    for evidence in evidences:
        if evidence.reported_rule is None and evidence.error_payload is not None:
            raise MappingError(f"{evidence.case_id}: an accepted case publishes an error payload")
    notes.append(f"exact payloads replayed for the {len(EXPECTED_PAYLOAD_RULES)} "
                 "payload-bearing rows and for no others")
    return notes


# --- fixture assembly and the runner -----------------------------------------

@dataclass
class Bundle:
    """Everything one run needs, produced before the runner is ever invoked."""

    fixture: str
    cases: list[FixtureCase]
    evidences: list[Evidence]
    unsupported: list[str]
    notes: list[str]
    source_commit: str


def build_fixture(vectors: Path, oracle: dict) -> Bundle:
    """Maps every case the current C++ API can represent and names the ones it cannot."""
    manifest = check_manifest(vectors)
    cases, source_commit = load_corpus(vectors)
    check_case_shape(cases, oracle)

    mapped: list[FixtureCase] = []
    evidences: list[Evidence] = []
    unsupported: list[str] = []
    for case in cases:
        try:
            fixture_case, evidence = map_case(case, oracle)
        except UnsupportedCase as error:
            # An input the kernel cannot build is reported, never dropped, and never
            # counted as agreement: a fixture the API cannot represent is a finding
            # about the API, not a pass.
            unsupported.append(one_line(str(error)))
            continue
        mapped.append(fixture_case)
        evidences.append(evidence)

    notes = check_required_coverage(evidences, oracle, manifest)
    body = (f"META schema={FIXTURE_SCHEMA}\n"
            + f"META source_commit={source_commit}\n"
            + "\n".join(fixture_case.render() for fixture_case in mapped) + "\n")
    return Bundle(body, mapped, evidences, unsupported, notes, source_commit)


def run_fixture(runner: Path, fixture: str) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", suffix=".fixture", delete=False
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
    return f"META schema={FIXTURE_SCHEMA}\n" + case.render() + "\n"


def fixture_ids(fixture: str) -> list[str]:
    """Re-reads the rendered text, so the count does not depend on the mapping."""
    return [line[len("CASE "):] for line in fixture.splitlines() if line.startswith("CASE ")]


def parse_results(output: str) -> tuple[dict[str, tuple[str, str]], "re.Match"]:
    """`RESULT <id> ok|fail <message>` lines, and the final SUMMARY."""
    results: dict[str, tuple[str, str]] = {}
    summary: re.Match | None = None
    for line in output.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                raise MappingError(f"malformed runner line: {one_line(line)}")
            case_id, status = parts[1], parts[2]
            if case_id in results:
                raise MappingError(f"duplicate result for {case_id}")
            results[case_id] = (status, parts[3] if len(parts) > 3 else "")
        elif line.startswith("SUMMARY "):
            summary = re.fullmatch(r"SUMMARY cases=(\d+) failures=(\d+)", line)
    if summary is None:
        raise MissingSummary()
    return results, summary


class MissingSummary(RuntimeError):
    """The runner finished without ever saying how many cases it saw."""


def probe_can_fail(runner: Path, cases: list[FixtureCase]) -> list[tuple[str, int]]:
    """Proves the diff is the comparison and not the exit code.

    Each probe case is replayed whole and required to pass, then replayed once per
    declared output with that single value changed to something the kernel cannot agree
    with. The mutated run must exit 1 and must name the corrupted key in its own report.
    A runner that answered `ok` to everything, or that silently compared only some of
    the fields, would fail here long before it could fail the gate.

    Returns one `(case_id, probed field count)` entry per probe case so the report can
    state the evidence instead of leaving it implied by the absence of an error.
    """
    by_id = {case.case_id: case for case in cases}
    probes: list[tuple[str, int]] = []
    for case_id in PROBE_CASE_IDS:
        probe = by_id.get(case_id)
        if probe is None:
            raise MappingError(f"corruption probe: the corpus no longer provides {case_id}")
        right = run_fixture(runner, single_case_fixture(probe))
        if right.returncode != 0 or f"RESULT {probe.case_id} ok" not in right.stdout:
            raise MappingError(
                f"corruption probe: the kernel disagrees with the oracle on the known-good "
                f"case {probe.case_id} before anything was mutated: "
                f"{one_line(right.stdout)} {one_line(right.stderr)}")
        for key, value in probe.outputs:
            mutated = probe.with_corrupted_output(key, corrupted(value))
            wrong = run_fixture(runner, single_case_fixture(mutated))
            if wrong.returncode != 1:
                raise MappingError(
                    f"corruption probe: a wrong {key} left the runner at exit "
                    f"{wrong.returncode}, expected 1 — that field is not being compared")
            if f"RESULT {probe.case_id} fail" not in wrong.stdout:
                raise MappingError(
                    f"corruption probe: a wrong {key} was not reported for {probe.case_id}")
            if f"'{key}'" not in wrong.stdout:
                raise MappingError(
                    f"corruption probe: {probe.case_id} failed on a wrong {key} without "
                    f"naming it, so the reported field cannot be trusted: "
                    f"{one_line(wrong.stdout)}")
        probes.append((probe.case_id, len(probe.outputs)))
    return probes


# --- report ------------------------------------------------------------------

def short(case_id: str) -> str:
    return case_id[len(EXPECTED_GROUP) + 1:]


def row_text(evidence: Evidence, status: str, detail: str) -> str:
    rule = "-" if evidence.reported_rule is None else f"B-{evidence.reported_rule}"
    violated = ",".join(str(row) for row in evidence.violated_rules) or "-"
    engine = "trivial" if evidence.engine == "sha256d-trivial" else "scratchpad"
    kind = str(evidence.error_kind)
    return (f"  {status:<10} {short(evidence.case_id):<48} {rule:<5} {kind:<23} "
            f"violated=[{violated}] tx={evidence.leaf_count} {engine} "
            f"roots={'match' if evidence.roots_match else 'differ'} "
            f"pow={'pass' if evidence.pow_meets_target else 'fail'}"
            + (f"  ->  {detail}" if detail else ""))


def oracle_summary(evidence: Evidence) -> str:
    """The §6 mismatch context: expectation, and the input that produced it."""
    payload = "none" if evidence.error_payload is None else json.dumps(
        evidence.error_payload, sort_keys=True)
    return (f"python expected accepted={evidence.accepted} error_kind={evidence.error_kind} "
            f"rule={'B-' + str(evidence.reported_rule) if evidence.reported_rule is not None else '-'} "
            f"violated={evidence.violated_rules} payload={payload}; "
            f"input: engine={evidence.engine} tx={evidence.leaf_count} "
            f"timestamp={evidence.timestamp} median_time_past={evidence.median_time_past} "
            f"now={evidence.now} roots_match={evidence.roots_match} "
            f"pow_meets_target={evidence.pow_meets_target}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        oracle = load_oracle()
        bundle = build_fixture(args.vectors, oracle)
        probes = probe_can_fail(args.runner, bundle.cases)
    except (MappingError, KeyError, OSError) as error:
        print(f"p42 conformance: mapping or environment failure: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, bundle.fixture)
    if completed.returncode not in (0, 1):
        print(f"p42 conformance: the runner exited {completed.returncode} instead of "
              "reporting a verdict per case", file=sys.stderr)
        print(one_line(completed.stderr), file=sys.stderr)
        return 2

    try:
        results, summary = parse_results(completed.stdout)
    except MissingSummary:
        print("p42 conformance: the runner printed no SUMMARY line", file=sys.stderr)
        print(one_line(completed.stdout), file=sys.stderr)
        return 2
    except MappingError as error:
        print(f"p42 conformance: {error}", file=sys.stderr)
        return 2

    sent = fixture_ids(bundle.fixture)
    by_id = {evidence.case_id: evidence for evidence in bundle.evidences}
    missing = [case_id for case_id in sent if case_id not in results]
    unknown = sorted(case_id for case_id in results if case_id not in set(sent))
    mismatches = sorted((case_id, detail) for case_id, (status, detail) in results.items()
                        if status != "ok")

    print(f"p42 differential: {len(sent)}/{EXPECTED_CASE_COUNT} fixtures processed, "
          f"source_commit {bundle.source_commit}")
    print("  production validator: zk::validate_block_structure in kernel/src/block.cpp, "
          "rules B-3 through B-15 in that order, and nothing else")
    print("  independent oracle: zro_vectors._verify_block_structure, evaluated without "
          "short-circuit; every expected value below comes from it, none from the kernel")
    print(f"  falsifiability: {len(probes)} probe case(s) replayed clean, then "
          f"{sum(count for _, count in probes)} single-output mutation(s) each rejected "
          "by name, so a runner that ignored a field would not reach this line")
    for note in bundle.notes:
        print(f"  coverage: {note}")
    for evidence in bundle.evidences:
        status, detail = results.get(evidence.case_id, ("missing", ""))
        label = {"ok": "MATCH", "fail": "MISMATCH", "missing": "NO-RESULT"}.get(status, status)
        print(row_text(evidence, label, detail))

    print(f"  counts: processed={len(sent)} matched={len(sent) - len(mismatches) - len(missing)} "
          f"mismatched={len(mismatches)} missing={len(missing)} "
          f"unsupported={len(bundle.unsupported)}")
    print(f"  replayed expected keys: {len(MAPPED_EXPECTED_KEYS)} of "
          f"{len(MAPPED_EXPECTED_KEYS) + len(DEFERRED_KEYS)} published; deferred:")
    for name, reason in sorted(DEFERRED_KEYS.items()):
        print(f"    {name}: {one_line(reason)}")

    if unknown:
        print("p42 conformance: the runner answered cases this corpus does not publish: "
              f"{unknown}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != len(sent) or int(summary.group(2)) != len(mismatches):
        print(f"p42 conformance: runner summary {summary.group(0)} disagrees with the "
              f"{len(sent)} cases sent and {len(mismatches)} reported failures",
              file=sys.stderr)
        return 1
    if bundle.unsupported:
        print(f"p42 conformance: {len(bundle.unsupported)} fixture(s) the current C++ API "
              "cannot represent, reported rather than skipped or passed:", file=sys.stderr)
        for line in bundle.unsupported:
            print(f"  unsupported {line}", file=sys.stderr)
    if mismatches or missing or completed.returncode != 0 or bundle.unsupported:
        print(f"p42 conformance: FAIL ({len(mismatches)} mismatched, {len(missing)} missing, "
              f"{len(bundle.unsupported)} unsupported)", file=sys.stderr)
        for case_id, detail in mismatches:
            evidence = by_id.get(case_id)
            print(f"  mismatch {case_id}", file=sys.stderr)
            print(f"    first differing field: {one_line(detail)}", file=sys.stderr)
            if evidence is not None:
                print(f"    {oracle_summary(evidence)}", file=sys.stderr)
        for case_id in missing:
            print(f"  no result for {case_id}", file=sys.stderr)
        return 1

    print(f"p42 conformance: {len(sent)}/{EXPECTED_CASE_COUNT} fixtures agree with the "
          "independent oracle on verdict, reported rule, error kind, exact payload and "
          "precedence; 0 mismatches, 0 unsupported")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
