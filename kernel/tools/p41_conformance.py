#!/usr/bin/env python3
"""Replay the P4.1A claimed-Merkle-root corpus against the C++ kernel.

test/p41-vectors/chain/ holds the one file the Rust reference exports for this
slice: `claimed_merkle_root.json` (30 cases), every verdict of which came out of
the shipping `Block::validate_structure` itself. Like the earlier corpora it is
unreachable from the P0 harness, which dispatches by case-id namespace and
registers no verifier for the `chain.claimed_merkle_root.*` group, so this
wrapper is the only consumer of every expected byte in it.

Three things are checked before the runner is ever invoked, and they are three
different checks:

  1. the corpus is internally sound — manifest totals, per-file case counts,
     case-id prefixes, duplicates, the digest pairs, the frozen contract
     constants, and the prose claims this wrapper's own logic depends on;
  2. the corpus agrees with a genuinely independent implementation —
     test/harness/zro_vectors.py's `tx_from_json`, `tx_serialize`, `tx_txid` and
     `merkle_root` composed in that order, exactly the four functions
     `manifest.independent_verifier` promises. That is a dependency-free Python
     re-derivation of C-1, C-2 and C-5 together; it shares no code with
     kernel/src/merkle.cpp, kernel/src/block.cpp or kernel/src/transaction.cpp
     and is not called by the runner;
  3. the mapping is case by case, not just digest at the top of the tree: each
     published transaction must re-encode to the bytes published beside it, those
     bytes must hash to the leaf id published for it, and the leaf ids must
     compose to the computed root the case publishes. A corpus that got a root
     right by luck would still fail here.

A failure in any of them is reported as a mapping failure (exit 2), never as a
root mismatch: a malformed or self-inconsistent fixture must not be able to look
like a C++ bug. The Rust exporter stays the authority for the expected values;
the Python verifier only proves that what it published is reproducible by
something that is neither Rust nor this kernel.

The one mapping decision that is not obvious, and the reason `tx_count` sits
beside `leaf_count` in the compared set: the corpus's `accepted` is the
*validator's* verdict, the sum of B-1 through B-15, while
`zk::compare_claimed_merkle_root` returns the verdict of B-14 alone. The two are
the same answer only where every other guard in the reference passed, and the
exporter guarantees exactly that by panicking on any variant besides `Ok` and
`RootMismatch`. So this wrapper checks `accepted == roots_match` for every case
before it maps anything and raises a mapping failure if the corpus ever grows a
case where they differ — which can only mean an unported B-15 has started to
change the verdict. The fixture would then be at fault for pretending a
comparison-only verb could replay a validator's answer; the kernel must not be
blamed for it.

Two published things are validated and deliberately not replayed:

  * `expected.guard_before_comparison`, deferred below, is the verdict B-8
    `NoTransactions` returns for an empty list before B-14 is reached. The kernel
    has no `Block` type and no guard ordering, so no comparison verb can
    reproduce it, and the corpus says so itself.
  * `input.validation_context` is the context the validator consumed to reach
    the comparison. The comparison consumes none of it, so the wrapper checks
    that it agrees with the header published beside it — and fails if it does
    not, because then the verdict would be evidence about a different block than
    the bytes handed to the kernel — without handing any of it to the runner.

Usage:
  python kernel/tools/p41_conformance.py --vectors test/p41-vectors --runner <exe>
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

SOURCE_FILES = ("chain/claimed_merkle_root.json",)

# One fixture case per corpus case: the header and the transaction list go in as
# IN lines, so there is no expansion here that could silently drop a case.
EXPECTED_FILE_CASES = {"chain/claimed_merkle_root.json": 30}
EXPECTED_CASE_COUNT = sum(EXPECTED_FILE_CASES.values())

# The operation the file drives.
OP_BY_FILE = {"chain/claimed_merkle_root.json": "claimed_merkle_root"}

EXPECTED_PHASE = "P4.1A"
EXPECTED_SCHEMA = "zro-baseline-vectors/1"

# The only key this milestone defers, and why. It is validated before the runner
# sees the case, so the deferral cannot hide a shape change, and it names the
# guard that would have to be ported for the deferral to go away.
DEFERRED_KEYS: dict[str, str] = {
    "guard_before_comparison": (
        "B-8 `NoTransactions` runs in `validate_structure` before B-14 and is not ported; "
        "`compare_claimed_merkle_root` has no guard to run, so it cannot reproduce this key"
    ),
}

# The contract the exporter freezes in manifest.json, restated here so a corpus
# that quietly changes shape fails instead of being replayed wrongly. Only the
# two numeric constants are pinned by value; the rest of the contract is prose,
# and CONTRACT_CLAIMS below pins the phrases this wrapper's logic actually leans
# on rather than the whole sentence.
EXPECTED_CONTRACT = {
    "digest_width_bytes": 32,
    "header_preimage_len_bytes": 107,
}

CONTRACT_CLAIMS = {
    # The comparison is a byte-for-byte equality over internal digests, so the
    # wrapper refuses a case whose display form is anything but a reversal.
    "byte_order": "internal byte order",
    # Coinbase position is not part of B-14, and the wrapper enforces the claim
    # so that an unported B-10 or B-11 cannot be the reason a case fails.
    "coinbase_position": "position zero",
    "comparison_site": "B-14",
    # The single justification for deferring `guard_before_comparison`.
    "empty_input": "B-8",
    # The reason `accepted` may be replayed by a comparison-only verb at all.
    "guard_order": "B-15",
    "invariant": "accepted == (roots_match && proof_of_work_meets_target)",
    # The wrapper pins every header's difficulty bits to this literal.
    "proof_of_work": "0x207fffff",
    "scope": "comparison only",
    # No transaction-count limit is exercised or implied, so the wrapper applies
    # none and the corpus says so.
    "transaction_count_limit": "none",
    "verdict": "RootMismatch",
}

# The four functions `manifest.independent_verifier` promises, plus two the
# wrapper needs for its own per-leaf checks and that the P0 harness already
# provides: `sha256d` for "these bytes hash to this id", and `tx_is_coinbase` for
# the coinbase-position claim.
VERIFIER_FUNCTIONS = (
    "tx_from_json",
    "tx_serialize",
    "tx_txid",
    "merkle_root",
    "sha256d",
    "tx_is_coinbase",
)
VERIFIER_TAG = "EMPTY_MERKLE_TAG"

# The domain tag the empty tree is the digest of, as the P3.3B corpus freezes it.
# The p41 manifest does not restate it, so it is asserted here only to prove the
# two `boundary` cases really do publish the tagged empty digest — which is what
# `contract.empty_input` claims of them.
EXPECTED_EMPTY_TAG_HEX = "5a524f2f6d65726b6c653a656d70747900"

# What every case in this corpus is built on. `contract.proof_of_work` names the
# bits, `manifest.determinism` names the two time literals, and the trivial
# engine is the only one whose name the runner is willing to replay.
EXPECTED_ENGINE = "sha256d-trivial"
EXPECTED_ENGINE_ID = 0
TRIVIAL_FLOOR_BITS = 0x207FFFFF
EXPECTED_MEDIAN_TIME_PAST = 0
EXPECTED_NOW = (1 << 64) - 1

# The two verdicts the comparison layer can produce, in the reference's own
# words. Anything else in the corpus is a rule the kernel has not ported, and the
# case cannot be replayed rather than quietly compared against a wrong answer.
VERDICT_KINDS = (None, "RootMismatch")

# The variants that carry data, mirroring `block_error_kind_has_payload`. Written
# out here so the wrapper's `error_payload_present` is a restatement of the
# taxonomy instead of a literal; no case in this corpus reaches the non-empty
# branch, because `VERDICT_KINDS` already excludes the payload-bearing variants.
PAYLOAD_KINDS = ("WrongChain", "BadHeight")

# The keys a case must carry, and the keys inside each of those. Anything else is
# unmapped and fails, so a corpus that grows a field cannot be replayed as though
# it had not.
INPUT_KEYS = ("header", "transactions", "tx_count", "validation_context")
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
CONTEXT_KEYS = (
    "engine",
    "expected_bits",
    "expected_chain",
    "expected_height",
    "expected_previous_hex",
    "median_time_past",
    "now",
)
TRANSACTION_KEYS = (
    "inputs",
    "is_coinbase",
    "lock_time",
    "outputs",
    "serialized_hex",
    "serialized_len",
    "version",
)
EXPECTED_KEYS = (
    "accepted",
    "claimed_root",
    "computed_root",
    "computed_root_len",
    "error_kind",
    "error_payload",
    "leaf_count",
    "leaves",
    "proof_of_work_meets_target",
    "roots_match",
)
LEAF_KEYS = ("txid",)
HASH_KEYS = ("internal_hex", "display_hex")
GUARD_KEYS = ("accepted", "error_kind", "error_payload", "note")

# The keys the runner publishes for this verb, in its own order. Checked against
# every mapped case, so the wrapper and the runner cannot drift apart silently
# into a run that compares less than it used to.
RUNNER_OUTPUTS = (
    "accepted",
    "error_kind",
    "error_payload_present",
    "computed_root_internal_hex",
    "computed_root_display_hex",
    "computed_root_len",
    "claimed_root_internal_hex",
    "claimed_root_display_hex",
    "roots_match",
    "tx_count",
    "leaf_count",
    "leaf_txids_hex",
    "proof_of_work_meets_target",
)

# The context fields that must agree with the header's own bytes. The comparison
# reads none of them, which is why they are validated here and not handed over.
CONTEXT_FOR_HEADER = (
    ("expected_chain", "chain"),
    ("expected_height", "height"),
    ("expected_previous_hex", "previous_hash_hex"),
    ("expected_bits", "difficulty_bits"),
)

# Intents the exporter publishes for this group, from the corpus itself: `rule`
# for the comparison, `ordering` for the two cases that reach B-14 with a nonce
# that misses the target, `boundary` for the two empty-list cases.
EXPECTED_INTENTS = ("rule", "ordering", "boundary")

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


def error_kind_text(value: object) -> str:
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


# --- independent verifier ----------------------------------------------------


def load_python_verifier():
    """Imports the P0 harness's transaction, Merkle and hashing primitives.

    The first four names are what `manifest.independent_verifier` promises, and
    they are the same functions `test/harness/run_vectors.py` uses to check the
    historical `encoding.transaction` and `chain.merkle.*` cases, so they predate
    this corpus and share no code with the kernel. Failing to import is a gate
    failure, not a skip: a run without the cross-check would silently be a weaker
    run. The composition here needs callables rather than a single one, so every
    name is checked for presence before any case is mapped.
    """
    if not (HARNESS_DIR / "zro_vectors.py").is_file():
        raise MappingError(f"independent verifier not found at {HARNESS_DIR / 'zro_vectors.py'}")
    if str(HARNESS_DIR) not in sys.path:
        sys.path.insert(0, str(HARNESS_DIR))
    try:
        import zro_vectors  # type: ignore
    except Exception as error:  # pragma: no cover - import failure is a gate failure
        raise MappingError(f"independent verifier failed to import: {error}") from error

    functions = {}
    for name in VERIFIER_FUNCTIONS:
        function = getattr(zro_vectors, name, None)
        if not callable(function):
            raise MappingError(f"independent verifier has no callable {name}")
        functions[name] = function

    tag = getattr(zro_vectors, VERIFIER_TAG, None)
    if not isinstance(tag, (bytes, bytearray)):
        raise MappingError(f"independent verifier has no {VERIFIER_TAG}")
    if tag.hex() != EXPECTED_EMPTY_TAG_HEX:
        raise MappingError(
            f"independent verifier tag {tag.hex()} != the tag the P3.3B corpus freezes "
            f"({EXPECTED_EMPTY_TAG_HEX})"
        )
    return functions


def derive_leaves_and_root(verifier: dict, transactions: list[dict]) -> tuple[list[bytes], bytes]:
    """The corpus's own inputs, run through the independent implementation.

    Each published transaction is turned back into the harness's own structure,
    re-encoded, and hashed; the ordered ids then go through the harness's Merkle
    rule, which is the one that returns the tagged digest for an empty list.
    """
    txs = [verifier["tx_from_json"](item) for item in transactions]
    ids = [verifier["tx_txid"](tx) for tx in txs]
    return ids, verifier["merkle_root"](ids)


# --- corpus -> fixture -------------------------------------------------------


def internal_hex(value: object, case_id: str, what: str) -> str:
    """A strict 32-byte internal digest, or a mapping failure."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise MappingError(
            f"{case_id}: {what} is not 64 lowercase hex characters (32 bytes): {value!r}"
        )
    return value


def display_of(internal: str) -> str:
    return bytes.fromhex(internal)[::-1].hex()


def digest_pair(value: object, case_id: str, what: str) -> tuple[str, str]:
    """Both forms of one published digest, with the display form checked against
    the internal one rather than trusted. `contract.byte_order` says the reversal
    is printing-only, so a corpus that published a mismatched pair is describing a
    digest the comparison never saw."""
    if not isinstance(value, dict) or set(value) != set(HASH_KEYS):
        keys = sorted(value) if isinstance(value, dict) else repr(value)
        raise MappingError(f"{case_id}: {what} keys {keys}, expected {sorted(HASH_KEYS)}")
    internal = internal_hex(value["internal_hex"], case_id, f"{what}.internal_hex")
    display = value["display_hex"]
    if not isinstance(display, str) or display != display_of(internal):
        raise MappingError(
            f"{case_id}: {what}.display_hex is not the internal bytes reversed"
        )
    return internal, display


def split_expected(expected: dict, mapped: set[str], case_id: str) -> list[str]:
    """Returns the deferred keys and refuses to drop an unrecognised one."""
    overlap = sorted(mapped & set(DEFERRED_KEYS))
    if overlap:
        raise MappingError(f"{case_id}: keys {overlap} are both mapped and deferred")
    unknown = sorted(set(expected) - mapped - set(DEFERRED_KEYS))
    if unknown:
        raise MappingError(f"{case_id}: expected keys {unknown} are neither mapped nor deferred")
    return sorted(key for key in expected if key in DEFERRED_KEYS)


def hex_bytes(value: object, case_id: str, what: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value or ""):
        raise MappingError(f"{case_id}: {what} is not an even-length lowercase hex string: {value!r}")
    return bytes.fromhex(value)


def exact_keys(payload: dict, wanted: tuple[str, ...], case_id: str, what: str) -> None:
    missing = [name for name in wanted if name not in payload]
    if missing:
        raise MappingError(f"{case_id}: {what} is missing {missing}")
    extra = sorted(set(payload) - set(wanted))
    if extra:
        raise MappingError(f"{case_id}: {what} keys {extra} are unmapped; map them or defer them")


def flag(value: object, case_id: str, what: str) -> bool:
    if not isinstance(value, bool):
        raise MappingError(f"{case_id}: {what} is {value!r}, not a boolean")
    return bool(value)


def check_verdict(expected: dict, case_id: str) -> tuple[bool, object, bool]:
    """The three published verdicts, reconciled before anything is mapped.

    Returns (accepted, error_kind, roots_match). Every failure here is about the
    fixture's right to be replayed by this kernel, not about the kernel itself.
    """
    accepted = flag(expected["accepted"], case_id, "expected.accepted")
    roots_match = flag(expected["roots_match"], case_id, "expected.roots_match")
    meets_target = flag(expected["proof_of_work_meets_target"], case_id,
                        "expected.proof_of_work_meets_target")
    kind = expected["error_kind"]

    if kind not in VERDICT_KINDS:
        raise MappingError(
            f"{case_id}: error_kind {kind!r} is a block rule the kernel has not ported; "
            f"this corpus may only be replayed while every verdict is one of "
            f"{[error_kind_text(v) for v in VERDICT_KINDS]}"
        )
    if accepted == (kind is not None):
        raise MappingError(f"{case_id}: accepted and error_kind contradict each other")
    if expected["error_payload"] is not None:
        raise MappingError(
            f"{case_id}: error_payload published for {error_kind_text(kind)}, but the "
            "reference declares `BlockError::RootMismatch` as a unit variant and "
            "contract.verdict says so"
        )
    # The line that licenses everything else in this file: the validator's verdict
    # and the comparison's own verdict must be the same answer.
    if accepted != roots_match:
        raise MappingError(
            f"{case_id}: the validator returned accepted={accepted} for a comparison whose "
            f"roots_match is {roots_match}, so an unported rule outside B-14 changed the "
            "verdict. `compare_claimed_merkle_root` returns B-14 alone and cannot replay "
            "this case; the fixture is at fault, not the kernel"
        )
    # The corpus's own published invariant, checked from the published fields, so
    # a reader of this gate sees it enforced rather than described.
    if accepted != (roots_match and meets_target):
        raise MappingError(
            f"{case_id}: contract.invariant is broken by this case: accepted "
            f"{accepted} != roots_match {roots_match} && proof_of_work "
            f"{meets_target}"
        )
    return accepted, kind, roots_match


def check_context(ctx: dict, header: dict, case_id: str) -> None:
    """Validates the validator's context without handing it to the runner.

    The comparison consumes none of these fields, so none of them are inputs to
    the verb. They still have to describe the same header the kernel is about to
    be given, or the verdict published for this case is evidence about a block
    other than the one being replayed.
    """
    exact_keys(ctx, CONTEXT_KEYS, case_id, "input.validation_context")
    for ctx_key, header_key in CONTEXT_FOR_HEADER:
        if ctx[ctx_key] != header[header_key]:
            raise MappingError(
                f"{case_id}: {ctx[ctx_key]!r} (context) disagrees with header.{header_key} "
                f"{header[header_key]!r}; the verdict would not be about this header"
            )
    if ctx["engine"] != EXPECTED_ENGINE:
        raise MappingError(
            f"{case_id}: context names engine {ctx['engine']!r}; this runner replays only "
            f"{EXPECTED_ENGINE!r}"
        )
    if header["engine_id"] != EXPECTED_ENGINE_ID:
        raise MappingError(
            f"{case_id}: header.engine_id {header['engine_id']} is not the byte "
            f"{EXPECTED_ENGINE} is registered under"
        )
    if header["difficulty_bits"] != TRIVIAL_FLOOR_BITS:
        raise MappingError(
            f"{case_id}: header.difficulty_bits {header['difficulty_bits']} is not the "
            f"trivial floor {TRIVIAL_FLOOR_BITS} that contract.proof_of_work names"
        )
    if ctx["median_time_past"] != EXPECTED_MEDIAN_TIME_PAST or ctx["now"] != EXPECTED_NOW:
        raise MappingError(
            f"{case_id}: validation context carries a time other than the literals "
            "manifest.determinism promises (0 and u64::MAX), so a guard that reads one "
            "could not be replayed deterministically"
        )


def check_guard(expected: dict, raw_txs: list[dict], case_id: str) -> None:
    """Validates the one deferred key instead of ignoring it.

    The deferral is only sound while it is B-8 on an empty list: the case that
    publishes it must be a case whose own comparison verdict survives, and whose
    guard is exactly the variant the corpus names beside it.
    """
    guard = expected.get("guard_before_comparison")
    if guard is None:
        return
    if not isinstance(guard, dict):
        raise MappingError(f"{case_id}: guard_before_comparison is not an object")
    exact_keys(guard, GUARD_KEYS, case_id, "expected.guard_before_comparison")
    if raw_txs:
        raise MappingError(
            f"{case_id}: a guard_before_comparison on a non-empty list is not the B-8 "
            "deferral this wrapper documents"
        )
    if guard["accepted"] or guard["error_kind"] != "NoTransactions" or guard["error_payload"]:
        raise MappingError(
            f"{case_id}: guard_before_comparison is {guard['error_kind']!r} at "
            f"accepted={guard['accepted']}; this wrapper defers only "
            "`NoTransactions`, which is B-8"
        )
    if not isinstance(guard["note"], str) or not guard["note"].strip():
        raise MappingError(f"{case_id}: guard_before_comparison carries no note")


def map_claimed_root(case: dict, verifier: dict) -> FixtureCase:
    case_id = case["id"]
    payload = case["input"]
    expected = case["expected"]

    exact_keys(payload, INPUT_KEYS, case_id, "input")
    # The expected shape, checked up front because every later step here reads one
    # of these keys by name: the ten this verb replays, plus whatever
    # DEFERRED_KEYS allows. `split_expected` runs again at the end to produce the
    # deferral list, so the two share one source of truth for what is allowed.
    missing_expected = [name for name in EXPECTED_KEYS if name not in expected]
    if missing_expected:
        raise MappingError(f"{case_id}: expected is missing {missing_expected}")
    extra_expected = sorted(set(expected) - set(EXPECTED_KEYS) - set(DEFERRED_KEYS))
    if extra_expected:
        raise MappingError(
            f"{case_id}: expected keys {extra_expected} are unmapped; map them or defer them"
        )

    header = payload["header"]
    if not isinstance(header, dict):
        raise MappingError(f"{case_id}: input.header is {type(header).__name__}, not an object")
    exact_keys(header, HEADER_FIELDS, case_id, "input.header")
    check_context(payload["validation_context"], header, case_id)

    raw_txs = payload["transactions"]
    if not isinstance(raw_txs, list):
        raise MappingError(
            f"{case_id}: input.transactions is {type(raw_txs).__name__}, not a list"
        )
    declared_count = payload["tx_count"]
    if not isinstance(declared_count, int) or declared_count != len(raw_txs):
        raise MappingError(
            f"{case_id}: input.tx_count {declared_count!r} but {len(raw_txs)} transactions "
            "present"
        )

    raw_leaves = expected["leaves"]
    if not isinstance(raw_leaves, list):
        raise MappingError(
            f"{case_id}: expected.leaves is {type(raw_leaves).__name__}, not a list"
        )
    leaf_count = expected["leaf_count"]
    if not isinstance(leaf_count, int) or leaf_count != len(raw_txs) or leaf_count != len(raw_leaves):
        raise MappingError(
            f"{case_id}: {len(raw_leaves)} leaves and leaf_count {leaf_count!r} for "
            f"{len(raw_txs)} transactions; the comparison publishes one leaf per transaction"
        )

    accepted, kind, roots_match = check_verdict(expected, case_id)
    claimed_internal, claimed_display = digest_pair(
        expected["claimed_root"], case_id, "expected.claimed_root")
    computed_internal, computed_display = digest_pair(
        expected["computed_root"], case_id, "expected.computed_root")
    # The claim is the header's own field, and the only reason the comparison has
    # anything to compare against. The runner echoes `header.merkle_root_hex` back
    # as `claimed_root_internal_hex`, so a published claim that differs from the
    # header it was read from describes a block the kernel was never given.
    header_claim = internal_hex(header["merkle_root_hex"], case_id,
                                "input.header.merkle_root_hex")
    if header_claim != claimed_internal:
        raise MappingError(
            f"{case_id}: expected.claimed_root is {claimed_internal} but the header it is "
            f"read from publishes {header_claim}"
        )
    if roots_match != (claimed_internal == computed_internal):
        raise MappingError(
            f"{case_id}: roots_match {roots_match} while the published digests "
            f"{'are' if claimed_internal == computed_internal else 'are not'} equal"
        )
    root_len = expected["computed_root_len"]
    if not isinstance(root_len, int) or root_len != 32 or root_len * 2 != len(computed_internal):
        raise MappingError(
            f"{case_id}: expected computed_root_len {root_len!r} does not match a 32-byte "
            "internal digest"
        )
    check_guard(expected, raw_txs, case_id)

    # contract.coinbase_position: the coinbase is at position zero and nowhere
    # else, in every case. Enforced rather than trusted, because B-10 and B-11 are
    # not ported and must not be able to be the reason a case is rejected.
    for index, item in enumerate(raw_txs):
        if not isinstance(item, dict):
            raise MappingError(f"{case_id}: transaction {index} is not an object")
        exact_keys(item, TRANSACTION_KEYS, case_id, f"transaction {index}")
        if item["is_coinbase"] and index != 0:
            raise MappingError(
                f"{case_id}: transaction {index} is a coinbase, but contract"
                ".coinbase_position puts the coinbase at position zero and nowhere else"
            )
        if verifier["tx_is_coinbase"](verifier["tx_from_json"](item)) != item["is_coinbase"]:
            raise MappingError(
                f"{case_id}: transaction {index} publishes is_coinbase "
                f"{item['is_coinbase']!r} where the independent verifier derives the other "
                "answer; the fixture is at fault, not the kernel"
            )
    if raw_txs and not raw_txs[0]["is_coinbase"]:
        raise MappingError(
            f"{case_id}: contract.coinbase_position says the coinbase is at position zero, "
            "but this case's first transaction is not one"
        )

    # Each leaf is the id of the bytes this case publishes as its input, so the
    # encoding, the id and the leaf order are all pinned before the kernel is
    # asked anything. This is the step that would catch a corpus that published a
    # root without a reproducible route to it.
    inputs: list[tuple[str, str]] = header_inputs(header)
    inputs.append(("engine", text(payload["validation_context"]["engine"])))
    leaf_ids: list[str] = []
    for index, (item, leaf) in enumerate(zip(raw_txs, raw_leaves)):
        if not isinstance(leaf, dict) or set(leaf) != set(LEAF_KEYS):
            raise MappingError(
                f"{case_id}: leaf {index} keys "
                f"{sorted(leaf) if isinstance(leaf, dict) else leaf!r}"
            )

        serialized = hex_bytes(item["serialized_hex"], case_id, f"transaction {index} serialized_hex")
        declared_len = item["serialized_len"]
        if not isinstance(declared_len, int) or declared_len != len(serialized):
            raise MappingError(
                f"{case_id}: transaction {index} serialized_len {declared_len!r} but "
                f"{len(serialized)} bytes published"
            )

        txid = internal_hex(leaf["txid"]["internal_hex"], case_id, f"leaf {index} txid internal_hex")
        if leaf["txid"]["display_hex"] != display_of(txid):
            raise MappingError(
                f"{case_id}: leaf {index} txid display_hex is not the internal bytes reversed"
            )

        # Two separate routes to the same leaf, neither of them the kernel's.
        if verifier["sha256d"](serialized).hex() != txid:
            raise MappingError(
                f"{case_id}: leaf {index} is not sha256d of the bytes published beside it"
            )
        reencoded = verifier["tx_serialize"](verifier["tx_from_json"](item))
        if reencoded != serialized:
            raise MappingError(
                f"{case_id}: transaction {index} publishes {serialized.hex()} but its own "
                f"fields encode to {reencoded.hex()}; the fixture is at fault, not the kernel"
            )

        inputs.append(("tx_hex", serialized.hex()))
        leaf_ids.append(txid)

    # The independent cross-check, on the corpus's own inputs: fields to encoding,
    # encoding to id, ids to root. A disagreement here means the fixture is wrong
    # and the C++ kernel must not be blamed for it.
    derived_ids, derived_root = derive_leaves_and_root(verifier, raw_txs)
    if [digest.hex() for digest in derived_ids] != leaf_ids:
        raise MappingError(
            f"{case_id}: the independent verifier derives leaves {[d.hex() for d in derived_ids]} "
            f"but the corpus publishes {leaf_ids}; the fixture is at fault, not the kernel"
        )
    if derived_root.hex() != computed_internal:
        raise MappingError(
            f"{case_id}: the independent Python verifier derives {derived_root.hex()} but the "
            f"corpus publishes {computed_internal}; the fixture is at fault, not the kernel"
        )
    # The claim `contract.empty_input` makes about the two boundary cases, checked
    # rather than read: the comparison layer's answer for an empty list is the
    # digest of the domain tag, and it is the only thing that can be.
    if not raw_txs:
        tagged = verifier["sha256d"](bytes.fromhex(EXPECTED_EMPTY_TAG_HEX)).hex()
        if computed_internal != tagged:
            raise MappingError(
                f"{case_id}: the empty list publishes computed_root {computed_internal} "
                f"where the tagged empty digest is {tagged}"
            )

    outputs = [
        # The validator's verdict, replayable as the comparison's own because
        # `check_verdict` established the two are the same answer for this case.
        ("accepted", text(accepted)),
        ("error_kind", error_kind_text(kind)),
        # Always false here, and compared anyway: a kernel that claimed a payload
        # for the unit variant `RootMismatch` fails this line.
        ("error_payload_present", text(kind in PAYLOAD_KINDS)),
        ("computed_root_internal_hex", computed_internal),
        ("computed_root_display_hex", computed_display),
        ("computed_root_len", text(root_len)),
        ("claimed_root_internal_hex", claimed_internal),
        ("claimed_root_display_hex", claimed_display),
        ("roots_match", text(roots_match)),
        # Neither a corpus value nor a guess: the wrapper's own accounting of how
        # many transactions it handed over, which the runner must echo back. It is
        # what proves the repeated `tx_hex` lines all reached the kernel.
        ("tx_count", str(len(raw_txs))),
        ("leaf_count", text(leaf_count)),
        # Every published leaf id, in list order, as one compared value. This is
        # what makes the mapping itself a checked output rather than a side effect,
        # and it is where a port that reorders or deduplicates the list is caught.
        ("leaf_txids_hex", "".join(leaf_ids)),
        # Published, not consulted: the runner answers it from the header the case
        # hands over, so B-15 is recorded as an observation and cannot be the
        # reason a B-14 verdict came out the way it did.
        ("proof_of_work_meets_target", text(expected["proof_of_work_meets_target"])),
    ]
    deferred = split_expected(expected, set(EXPECTED_KEYS), case_id)
    return FixtureCase(case_id, "claimed_merkle_root", inputs, outputs, deferred)


def header_inputs(header: dict) -> list[tuple[str, str]]:
    """The nine header fields, nested under `header.` so the validator's own
    context can never be confused with the bytes being validated — the same
    convention `header_identity` uses."""
    return [("header." + name, text(header[name])) for name in HEADER_FIELDS]


MAPPERS = {"chain/claimed_merkle_root.json": map_claimed_root}


# --- checks ------------------------------------------------------------------


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


# The four Rust calls that must be named by any provenance statement in this
# corpus. Together they cover every value a case publishes: the verdict, the
# computed root, the leaf ids, and the nonce that lets the header be fed at all.
RUST_ORIGINS = (
    "Block::validate_structure",
    "Block::compute_merkle_root",
    "Transaction::txid",
    "consensus::pow::mine",
)


def require_rust_origin(where: str, value: object) -> None:
    """A provenance statement must name the code that produced the values.

    Checked on both documents, and on each in its own words: the manifest and the
    corpus file phrase this differently on purpose, so requiring the same
    four call sites in both is the check, while requiring the same sentence would
    only pin the wording.
    """
    if not isinstance(value, str):
        raise MappingError(f"{where}: no provenance")
    for name in RUST_ORIGINS:
        if name not in value:
            raise MappingError(
                f"{where}: provenance does not name {name}, so some published value "
                "here has no Rust origin"
            )


def check_manifest(vectors: Path, documents: dict[str, dict]) -> str:
    manifest = load_json(vectors / "manifest.json")
    declared = {entry["path"]: entry for entry in manifest["files"]}
    commit = manifest.get("source_commit")
    if not commit or commit == "unknown":
        raise MappingError("manifest.json: no source_commit")
    if re.fullmatch(r"[0-9a-f]{40}", str(commit)) is None:
        raise MappingError(f"manifest.json: source_commit {commit!r} is not a full hash")
    if sorted(declared) != sorted(SOURCE_FILES):
        raise MappingError(
            f"manifest.json lists {sorted(declared)}, this wrapper consumes "
            f"{sorted(SOURCE_FILES)}"
        )
    if manifest.get("phase") != EXPECTED_PHASE:
        raise MappingError(f"manifest.json: phase {manifest.get('phase')!r}, expected {EXPECTED_PHASE}")
    if manifest.get("schema") != EXPECTED_SCHEMA:
        raise MappingError(f"manifest.json: schema {manifest.get('schema')!r}, expected {EXPECTED_SCHEMA}")

    contract = manifest.get("contract")
    if not isinstance(contract, dict):
        raise MappingError("manifest.json: no contract object")
    for key, want in EXPECTED_CONTRACT.items():
        if contract.get(key) != want:
            raise MappingError(f"manifest.json: contract {key} is {contract.get(key)!r}, expected {want}")
    for key, phrase in CONTRACT_CLAIMS.items():
        value = contract.get(key)
        if not isinstance(value, str) or phrase not in value:
            raise MappingError(
                f"manifest.json: contract.{key} is {value!r}; this wrapper's mapping leans on "
                f"the phrase {phrase!r}"
            )

    # The anti-fabrication statement, in both places that make it. Every verdict
    # here has to come out of the reference's own code, and this wrapper is the
    # only thing checking that the corpus said so.
    require_rust_origin("manifest.json", manifest.get("provenance"))
    verifier_claim = manifest.get("independent_verifier")
    if not isinstance(verifier_claim, str):
        raise MappingError("manifest.json: no independent_verifier")
    for name in ("tx_from_json", "tx_serialize", "tx_txid", "merkle_root"):
        if name not in verifier_claim:
            raise MappingError(
                f"manifest.json: independent_verifier does not name {name}, which this "
                "wrapper requires to run the cross-check"
            )

    commits = manifest.get("reference_commits")
    if not isinstance(commits, dict) or len(commits) != 3:
        raise MappingError("manifest.json: reference_commits does not name the three sites")
    for name, value in commits.items():
        if re.fullmatch(r"[0-9a-f]{40}", str(value)) is None:
            raise MappingError(f"manifest.json: reference_commits.{name} is {value!r}")

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
        if document.get("schema") != EXPECTED_SCHEMA:
            raise MappingError(f"{name}: schema {document.get('schema')!r}")
        require_rust_origin(name, document.get("provenance"))
        # The bytes being compared, in the file's own words, must be the ones the
        # wrapper maps: one id per leaf and nothing else.
        for case in document["cases"]:
            for index, leaf in enumerate(case["expected"]["leaves"]):
                if not isinstance(leaf, dict) or set(leaf) != set(LEAF_KEYS):
                    raise MappingError(
                        f"{case['id']}: leaf {index} keys "
                        f"{sorted(leaf) if isinstance(leaf, dict) else leaf!r} before mapping"
                    )
        total += len(document["cases"])

    declared_total = manifest.get("total_cases")
    if declared_total != total:
        raise MappingError(f"manifest.json: total_cases {declared_total} but {total} cases present")
    return commit


def build_fixture(vectors: Path) -> tuple[str, list[FixtureCase], str]:
    documents = {name: load_json(vectors / name) for name in SOURCE_FILES}
    source_commit = check_manifest(vectors, documents)
    verifier = load_python_verifier()

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
            if case.get("intent") not in EXPECTED_INTENTS:
                raise MappingError(f"{case_id}: unknown intent {case.get('intent')!r}")
            mapped = mapper(case, verifier)
            if tuple(key for key, _ in mapped.outputs) != RUNNER_OUTPUTS:
                raise MappingError(
                    f"{case_id}: mapped outputs "
                    f"{[key for key, _ in mapped.outputs]} do not name the "
                    f"{len(RUNNER_OUTPUTS)} values the runner publishes"
                )
            cases.append(mapped)

    if len(cases) != EXPECTED_CASE_COUNT:
        raise MappingError(
            f"P4.1 covers {len(cases)} cases, expected {EXPECTED_CASE_COUNT}; "
            "update the phase document before changing the slice"
        )
    ids = [case.case_id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise MappingError(f"duplicate case ids: {duplicates}")

    header = [
        "META schema=zro-p41-fixture/1",
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
    return "META schema=zro-p41-fixture/1\n" + case.render() + "\n"


def probe_can_fail(runner: Path, cases: list[FixtureCase]) -> None:
    """Every compared value must be able to fail the run.

    Three cases are each replayed whole, then once per declared output with that
    single value corrupted:

      * a three-transaction accepted case, the only shape where dropping, adding
        or reordering a leaf has to be visible in `leaf_txids_hex`;
      * a three-transaction rejected case whose claim is the all-zero digest, so a
        runner that answered `RootMismatch` to everything is caught by `accepted`,
        `error_kind` and `roots_match` at once;
      * the empty list against a claim it does not match, which carries no
        `tx_hex` line at all — a runner that ignored its input entirely would
        still have to disagree with `computed_root_internal_hex`.

    Without the probe, a runner that answered `ok` to everything would keep this
    gate green.
    """
    wanted = [
        "chain.claimed_merkle_root.three_transaction_block",
        "chain.claimed_merkle_root.zero_claim",
        "chain.claimed_merkle_root.empty_list_mismatching_claim",
    ]
    by_id = {case.case_id: case for case in cases}
    for case_id in wanted:
        probe = by_id.get(case_id)
        if probe is None:
            raise MappingError(f"corruption probe: the corpus no longer has {case_id}")
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
    except (MappingError, KeyError) as error:
        print(f"p41 conformance: corpus mapping failed: {error}", file=sys.stderr)
        return 2

    completed = run_fixture(args.runner, fixture)
    if completed.returncode not in (0, 1):
        print(f"p41 conformance: runner failed with {completed.returncode}", file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return 2

    results: dict[str, tuple[str, str]] = {}
    summary: re.Match[str] | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                print(f"p41 conformance: malformed runner line: {line}", file=sys.stderr)
                return 2
            case_id, status = parts[1], parts[2]
            detail = parts[3] if len(parts) > 3 else ""
            if case_id in results:
                print(f"p41 conformance: duplicate result for {case_id}", file=sys.stderr)
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
        print("p41 conformance: runner printed no SUMMARY line", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        return 2
    if unknown:
        print(f"p41 conformance: runner answered unknown cases: {unknown}", file=sys.stderr)
        return 1
    if missing or failed or completed.returncode != 0:
        print(
            f"p41 conformance: FAIL ({len(failed)} failed, {len(missing)} missing)",
            file=sys.stderr,
        )
        for case_id, detail in failed:
            print(f"  fail {case_id}: {detail}", file=sys.stderr)
        for case_id in missing:
            print(f"  missing {case_id}", file=sys.stderr)
        return 1
    if int(summary.group(1)) != EXPECTED_CASE_COUNT or int(summary.group(2)) != 0:
        print(f"p41 conformance: unexpected summary: {summary.group(0)}", file=sys.stderr)
        return 1

    print(
        f"p41 conformance: {len(expected_ids)}/{EXPECTED_CASE_COUNT} cases replayed "
        f"against source_commit {source_commit}"
    )
    for name in SOURCE_FILES:
        count = sum(1 for case in cases if case.op == OP_BY_FILE[name])
        print(f"  {name:<36} {count}")
    deferred_cases = sum(1 for case in cases if case.deferred)
    print(
        f"  deferred keys: {', '.join(sorted(DEFERRED_KEYS)) or 'none'} "
        f"({deferred_cases} cases carry one); the other "
        f"{len(EXPECTED_KEYS)} published expected keys are replayed"
    )
    print(
        f"  validator verdict replayed as the comparison's own: `accepted == roots_match` "
        f"checked for all {EXPECTED_CASE_COUNT} cases"
    )
    print(
        f"  independent verifier: {HARNESS_DIR / 'zro_vectors.py'}::tx_from_json + "
        f"tx_serialize + tx_txid + merkle_root, {EXPECTED_CASE_COUNT} leaf lists and roots "
        "re-derived from the corpus inputs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
