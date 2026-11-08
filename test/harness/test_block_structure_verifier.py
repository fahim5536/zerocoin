#!/usr/bin/env python3
"""Focused tests for the independent P4.2B block-structure verifier.

`zro_vectors._verify_block_structure` re-derives every published field of the
37 `chain.block_structure.*` fixtures in `test/p42-vectors/` from the case's own
`input`: it re-serializes each transaction, recomputes each transaction id and
the Merkle root, rebuilds the header preimage, re-runs proof of work, and then
evaluates rules B-3 through B-15 in the order `Block::validate_structure` writes
them. These tests hold that implementation to three things:

  1. agreement with every committed fixture, case by case, with no fixture
     expectation edited to get there;
  2. the ordering claims the corpus was built to pin -- every isolated rule,
     every representable adjacent pair, B-13 before B-14, B-14 before B-15 --
     and the two limitations it cannot pin (see
     `TestCoverageLimitations`);
  3. that the verdict really is derived, not copied. `TestDerivedVerdicts`
     mutates a fixture's *input* and asserts the recomputed verdict moves to the
     rule the mutation creates, and `TestMalformedFixtures` asserts a fixture
     that lies about its own bytes is reported as a failure instead of passing.

A fixture that has to be edited to make a verifier pass would defeat the entire
purpose of the corpus, so nothing here writes to `test/p42-vectors/`; the
mutations operate on in-memory copies.

Run:
  python test/harness/test_block_structure_verifier.py
  python -m unittest discover -s test/harness -p "test_block_structure_verifier.py"
"""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_vectors  # noqa: E402
import zro_vectors as zv  # noqa: E402

CORPUS_ROOT = HERE.parent / "p42-vectors"
GROUP = "chain.block_structure."
RULES = tuple(range(3, 16))
MASK32 = zv.MASK32
MASK64 = zv.MASK64

# The adjacency pairs `manifest.precedence.adjacent_pairs_represented` claims the
# corpus demonstrates. (8, 9) is deliberately absent: see `TestCoverageLimitations`.
REPRESENTED_PAIRS = (
    (3, 4), (4, 5), (5, 6), (6, 7), (7, 8), (9, 10),
    (10, 11), (11, 12), (12, 13), (13, 14), (14, 15),
)

_UNIT_VARIANTS = {
    "BadPreviousHash", "NoTransactions", "FirstNotCoinbase", "DuplicateCoinbase",
    "RootMismatch", "InsufficientProofOfWork",
}

_INDEX, CASES, MANIFEST = run_vectors.load_corpus(CORPUS_ROOT)
_BY_SUFFIX = {case["id"][len(GROUP):]: case for case in CASES}


def case(suffix):
    """A detached copy of one committed fixture, safe to mutate in memory."""
    return copy.deepcopy(_BY_SUFFIX[suffix])


def recompute(sample):
    """The verifier's own answer for a case, before anything is compared."""
    return zv._verify_block_structure(sample)


def inputs(sample):
    return sample["input"]


def transactions_of(sample):
    """The case's transactions, rebuilt the way the verifier rebuilds them."""
    data = inputs(sample)
    if "transactions" in data:
        return [zv.tx_from_json(item) for item in data["transactions"]]
    return [zv.tx_deserialize(zv.unhex(text)) for text in data["transactions_hex"]]


class TestCommittedCorpus(unittest.TestCase):
    """The corpus is the one this milestone was asked to verify, unedited."""

    def test_corpus_is_the_37_block_structure_fixtures(self):
        self.assertEqual(MANIFEST["total_cases"], 37)
        self.assertEqual(len(CASES), 37)
        self.assertEqual(MANIFEST["phase"], "P4.2A")
        for sample in CASES:
            self.assertTrue(sample["id"].startswith(GROUP), sample["id"])

    def test_every_fixture_verifies_and_none_is_skipped(self):
        statuses = [zv.verify_case(sample, _INDEX) for sample in CASES]
        self.assertEqual(statuses, ["PASS"] * 37)
        self.assertNotIn("ANCHOR", statuses)

    def test_the_tally_reports_the_number_of_verified_cases(self):
        zv.reset_verified_block_structure_count()
        self.assertEqual(zv.verified_block_structure_count(), 0)
        for sample in CASES:
            zv.verify_case(sample, _INDEX)
        self.assertEqual(zv.verified_block_structure_count(), 37)

    def test_the_tally_excludes_a_case_that_does_not_verify(self):
        zv.reset_verified_block_structure_count()
        tampered = case("iso_03_wrong_chain")
        tampered["input"]["header"]["chain"] = 999
        with self.assertRaises(zv.VectorMismatch):
            zv.verify_case(tampered, _INDEX)
        self.assertEqual(zv.verified_block_structure_count(), 0)


class TestIsolatedRules(unittest.TestCase):
    """Each rule B-3..B-15 is demonstrated by a fixture that breaks it alone."""

    def test_every_rule_has_an_isolated_fixture(self):
        isolated = {}
        for suffix, sample in _BY_SUFFIX.items():
            if not suffix.startswith("iso_"):
                continue
            rules = sample["expected"]["violated_rules"]
            self.assertEqual(len(rules), 1, f"{suffix} violates {rules}, not one rule")
            isolated.setdefault(rules[0], []).append(suffix)
        self.assertEqual(sorted(isolated), list(RULES))

    def test_isolated_fixtures_report_their_own_rule_and_no_other(self):
        for rule in RULES:
            sample = next(
                s for suffix, s in _BY_SUFFIX.items()
                if suffix.startswith("iso_") and s["expected"]["violated_rules"] == [rule]
            )
            got = recompute(sample)
            self.assertEqual(got["reported_rule"], rule, sample["id"])
            self.assertEqual(got["violated_rules"], [rule], sample["id"])
            self.assertEqual(got["error_kind"], zv.BLOCK_RULE_ERRORS[rule], sample["id"])
            self.assertFalse(got["accepted"], sample["id"])
            self.assertTrue(got["is_first_violation"], sample["id"])


class TestPrecedence(unittest.TestCase):
    """Where two rules hold at once, the earlier row in Rust source order wins."""

    def test_every_representable_adjacent_pair_is_demonstrated(self):
        for lower, upper in REPRESENTED_PAIRS:
            with self.subTest(pair=(lower, upper)):
                matches = [
                    s for s in CASES
                    if s["id"].rsplit(".", 1)[1].startswith(f"pair_{lower:02d}_{upper:02d}")
                ]
                self.assertTrue(matches, f"no fixture demonstrates ({lower}, {upper})")
                for sample in matches:
                    got = recompute(sample)
                    self.assertIn(lower, got["violated_rules"], sample["id"])
                    self.assertIn(upper, got["violated_rules"], sample["id"])
                    self.assertEqual(got["reported_rule"], lower, sample["id"])
                    self.assertEqual(got["error_kind"], zv.BLOCK_RULE_ERRORS[lower], sample["id"])

    def test_b13_is_reported_before_b14(self):
        sample = case("pair_13_14_future_and_stale_root")
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [13, 14])
        self.assertEqual(got["reported_rule"], 13)
        self.assertEqual(got["error_kind"], "TimestampTooFarFuture")
        self.assertFalse(got["roots_match"])

    def test_b14_is_reported_before_b15(self):
        for suffix in ("pair_14_15_root_mismatch_and_failing_pow",
                       "pair_14_15_zero_root_claim_and_failing_pow"):
            sample = case(suffix)
            got = recompute(sample)
            self.assertEqual(got["violated_rules"], [14, 15], sample["id"])
            self.assertEqual(got["reported_rule"], 14, sample["id"])
            self.assertEqual(got["error_kind"], "RootMismatch", sample["id"])
            self.assertFalse(got["proof_of_work_meets_target"], sample["id"])

    def test_b15_is_only_reachable_once_b14_has_passed(self):
        sample = case("iso_15_insufficient_pow")
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [15])
        self.assertTrue(got["roots_match"], "B-15 needs a block whose root already matches")

    def test_the_dominance_fixture_reports_the_earliest_row_of_eleven(self):
        sample = case("chaos_all_later_guards_broken")
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15])
        self.assertEqual(got["reported_rule"], 3)
        self.assertEqual(got["error_kind"], "WrongChain")

    def test_a_reported_rule_is_always_the_first_violated_one(self):
        for sample in CASES:
            got = recompute(sample)
            self.assertEqual(got["violated_rules"], sorted(got["violated_rules"]), sample["id"])
            if got["violated_rules"]:
                self.assertEqual(got["reported_rule"], got["violated_rules"][0], sample["id"])
                self.assertTrue(got["is_first_violation"], sample["id"])
            else:
                self.assertIsNone(got["reported_rule"], sample["id"])
                self.assertIsNone(got["is_first_violation"], sample["id"])


class TestCoverageLimitations(unittest.TestCase):
    """The two orderings this corpus cannot pin, asserted rather than claimed."""

    def test_b8_and_b9_are_mutually_exclusive_so_their_order_is_unobservable(self):
        # `manifest.deferred_pairs` says it and the arithmetic agrees: a list
        # cannot be both empty and longer than 2,000. Nothing can violate B-8 and
        # B-9 together, so which of the two rows Rust writes first has no
        # observable consequence and this suite asserts no precedence for it.
        for sample in CASES:
            got = recompute(sample)
            self.assertFalse(8 in got["violated_rules"] and 9 in got["violated_rules"], sample["id"])
        empty = [s for s in CASES if s["input"]["tx_count"] == 0]
        # Two fixtures carry an empty block: the isolated one and the pair that
        # deliberately breaks B-7 first. Both put 8 in the violated set, and no
        # case anywhere in the corpus can hold 8 and 9 together.
        self.assertEqual(len(empty), 2, [s["id"] for s in empty])
        for sample in empty:
            got = recompute(sample)
            self.assertIn(8, got["violated_rules"], sample["id"])
            self.assertNotIn(9, got["violated_rules"], sample["id"])

    def test_b8_over_b14_and_b15_is_inferred_from_source_order_not_demonstrated(self):
        # The isolated empty fixture is otherwise sound: its claimed root is the
        # tagged empty digest and its proof of work meets the target, so it never
        # reaches a B-14 or B-15 disagreement while B-8 holds. No committed fixture
        # shows B-8 beating B-14 or B-15; the verifier orders them that way only
        # because that is the order the rows appear in `validate_structure`.
        empty = case("iso_08_no_transactions")
        got = recompute(empty)
        self.assertEqual(got["violated_rules"], [8], empty["id"])
        self.assertTrue(got["roots_match"], empty["id"])
        self.assertTrue(got["proof_of_work_meets_target"], empty["id"])
        self.assertNotIn(14, got["violated_rules"])
        self.assertNotIn(15, got["violated_rules"])


class TestTransactionCountBoundaries(unittest.TestCase):
    """`transactions.len() > MAX_BLOCK_TRANSACTIONS`, evaluated at the edge."""

    def test_limit_constant_is_the_one_the_reference_uses(self):
        self.assertEqual(zv.MAX_BLOCK_TRANSACTIONS, 2_000)
        self.assertEqual(zv.MAX_FUTURE_SECONDS, 2 * 60 * 60)

    def test_two_thousand_is_accepted_and_two_thousand_and_one_is_rejected(self):
        at_limit = case("bnd_09_count_at_limit_accept")
        self.assertEqual(at_limit["input"]["tx_count"], 2_000)
        got = recompute(at_limit)
        self.assertEqual(got["leaf_count"], 2_000)
        self.assertEqual(got["violated_rules"], [])
        self.assertTrue(got["accepted"])

        over = case("iso_09_too_many_transactions")
        self.assertEqual(over["input"]["tx_count"], 2_001)
        got = recompute(over)
        self.assertEqual(got["violated_rules"], [9])
        self.assertEqual(got["error_payload"], {"count": 2_001})

    def test_the_over_limit_pair_reports_the_count_before_the_coinbase(self):
        sample = case("pair_09_10_over_limit_and_first_not_coinbase")
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [9, 10])
        self.assertEqual(got["reported_rule"], 9)
        self.assertFalse(got["first_is_coinbase"])

    def test_the_hex_shape_carries_no_leaves_and_the_rich_shape_does(self):
        for sample in CASES:
            got = recompute(sample)
            if "transactions_hex" in sample["input"]:
                self.assertNotIn("leaves", got, sample["id"])
                self.assertGreaterEqual(sample["input"]["tx_count"], 2_000, sample["id"])
            else:
                self.assertEqual(len(got["leaves"]), got["leaf_count"], sample["id"])

    def test_the_coinbase_flags_are_one_character_per_transaction(self):
        for sample in CASES:
            got = recompute(sample)
            flags = got["coinbase_flags"]
            self.assertEqual(len(flags), got["leaf_count"], sample["id"])
            self.assertEqual(sum(character == "1" for character in flags), got["coinbase_count"], sample["id"])


class TestFutureTimeSaturation(unittest.TestCase):
    """B-13 is `timestamp > now.saturating_add(7200)`, and the corpus proves it."""

    def test_the_limit_is_inclusive_and_one_second_past_it_is_rejected(self):
        equal = case("bnd_13_equal_limit_accept")
        stamp, now = equal["input"]["header"]["timestamp"], equal["input"]["validation_context"]["now"]
        self.assertEqual(stamp, now + zv.MAX_FUTURE_SECONDS)
        self.assertEqual(recompute(equal)["violated_rules"], [])

        above = case("bnd_13_one_above_reject")
        stamp, now = above["input"]["header"]["timestamp"], above["input"]["validation_context"]["now"]
        self.assertEqual(stamp, now + zv.MAX_FUTURE_SECONDS + 1)
        got = recompute(above)
        self.assertEqual(got["violated_rules"], [13])
        self.assertEqual(got["error_payload"], {"found": stamp, "now": now})

    def test_a_saturating_bound_accepts_where_a_wrapping_one_would_reject(self):
        # Only this fixture puts `now` on the u64::MAX ceiling. There Rust's
        # `now.saturating_add(7200)` stays u64::MAX and the block is accepted;
        # a wrapping read would land on 7199 and reject a perfectly ordinary
        # timestamp. Saturating is the only reading that matches the fixture.
        sample = case("bnd_13_near_max_saturating_accept")
        now = sample["input"]["validation_context"]["now"]
        stamp = sample["input"]["header"]["timestamp"]
        self.assertEqual(now, MASK64, sample["id"])
        self.assertLess(stamp, now, sample["id"])
        self.assertEqual((now + zv.MAX_FUTURE_SECONDS) & MASK64, zv.MAX_FUTURE_SECONDS - 1, sample["id"])
        got = recompute(sample)
        self.assertTrue(got["accepted"], sample["id"])
        self.assertEqual(got["violated_rules"], [], sample["id"])

    def test_the_ceiling_boundaries_either_side_of_saturation_are_exact(self):
        # `last_exact` is the largest `now` whose +7200 is still exact (it lands
        # on u64::MAX and accepts); `edge_reject` is one second below it and
        # rejects. Saturating and wrapping agree on both, so these two pin the
        # inclusive bound rather than the saturation itself.
        exact = case("bnd_13_near_max_last_exact_accept")
        self.assertEqual(
            exact["input"]["validation_context"]["now"] + zv.MAX_FUTURE_SECONDS, MASK64, exact["id"]
        )
        self.assertEqual(recompute(exact)["violated_rules"], [], exact["id"])

        edge = case("bnd_13_near_max_edge_reject")
        now = edge["input"]["validation_context"]["now"]
        self.assertEqual(now + zv.MAX_FUTURE_SECONDS, MASK64 - 1, edge["id"])
        got = recompute(edge)
        self.assertEqual(got["violated_rules"], [13], edge["id"])
        self.assertEqual(got["error_payload"], {"found": edge["input"]["header"]["timestamp"], "now": now}, edge["id"])

    def test_the_saturating_bound_is_the_max_of_the_two_representations(self):
        for sample in CASES:
            now = sample["input"]["validation_context"]["now"]
            bound = min(now + zv.MAX_FUTURE_SECONDS, MASK64)
            self.assertLessEqual(bound, MASK64)
            self.assertGreaterEqual(bound, now)

    def test_median_time_is_inclusive_on_the_wrong_side(self):
        equal = case("bnd_12_equal_median_reject")
        self.assertEqual(
            equal["input"]["header"]["timestamp"], equal["input"]["validation_context"]["median_time_past"]
        )
        self.assertEqual(recompute(equal)["violated_rules"], [12])

        above = case("bnd_12_one_above_median_accept")
        self.assertEqual(
            above["input"]["header"]["timestamp"],
            above["input"]["validation_context"]["median_time_past"] + 1,
        )
        self.assertEqual(recompute(above)["violated_rules"], [])


class TestErrorPayloads(unittest.TestCase):
    """Every payload field is the exact published input number, at the exact width."""

    def test_payload_key_set_matches_the_variant(self):
        for sample in CASES:
            got = recompute(sample)
            kind, payload = got["error_kind"], got["error_payload"]
            if kind is None:
                self.assertIsNone(payload, sample["id"])
            elif kind in _UNIT_VARIANTS:
                self.assertIsNone(payload, sample["id"])
            elif kind == "TooManyTransactions":
                self.assertEqual(set(payload), {"count"}, sample["id"])
            elif kind == "TimestampTooOld":
                self.assertEqual(set(payload), {"found", "median"}, sample["id"])
            elif kind == "TimestampTooFarFuture":
                self.assertEqual(set(payload), {"found", "now"}, sample["id"])
            else:
                self.assertEqual(set(payload), {"expected", "found"}, sample["id"])

    def test_payload_values_are_the_input_numbers_they_claim_to_be(self):
        for sample in CASES:
            got, data = recompute(sample), sample["input"]
            header, context = data["header"], data["validation_context"]
            payload = got["error_payload"]
            if payload is None:
                continue
            rule = got["reported_rule"]
            if rule in (3, 7):
                self.assertEqual(payload["found"], header[("chain", "difficulty_bits")[rule == 7]], sample["id"])
                self.assertEqual(payload["expected"], context[("expected_chain", "expected_bits")[rule == 7]], sample["id"])
            elif rule == 4:
                self.assertEqual(payload["found"], header["height"], sample["id"])
                self.assertEqual(payload["expected"], context["expected_height"], sample["id"])
            elif rule == 6:
                self.assertEqual(payload["found"], header["engine_id"], sample["id"])
            elif rule == 9:
                self.assertEqual(payload["count"], data["tx_count"], sample["id"])
            elif rule == 12:
                self.assertEqual(payload["found"], header["timestamp"], sample["id"])
                self.assertEqual(payload["median"], context["median_time_past"], sample["id"])
            elif rule == 13:
                self.assertEqual(payload["found"], header["timestamp"], sample["id"])
                self.assertEqual(payload["now"], context["now"], sample["id"])

    def test_payload_numbers_fit_the_types_that_carry_them(self):
        for sample in CASES:
            got = recompute(sample)
            payload, rule = got["error_payload"], got["reported_rule"]
            if payload is None:
                continue
            narrow = MASK32 if rule in (3, 6, 7) else MASK64
            for key, value in payload.items():
                self.assertIsInstance(value, int, f"{sample['id']}.{key}")
                self.assertNotIsInstance(value, bool, f"{sample['id']}.{key}")
                self.assertLessEqual(value, narrow, f"{sample['id']}.{key} exceeds {narrow}")

    def test_the_wrong_engine_payload_names_the_context_engines_id(self):
        sample = case("iso_06_wrong_engine")
        got = recompute(sample)
        self.assertEqual(got["error_payload"], {"expected": zv.ENGINE_ID_SCRATCHPAD, "found": 0})


class TestDigestDerivation(unittest.TestCase):
    """Serialization, transaction ids and Merkle roots are recomputed, not copied."""

    def test_every_published_transaction_re_encodes_to_its_own_bytes(self):
        for sample in CASES:
            data = sample["input"]
            if "transactions" in data:
                for index, item in enumerate(data["transactions"]):
                    blob = zv.tx_serialize(zv.tx_from_json(item))
                    self.assertEqual(blob, zv.unhex(item["serialized_hex"]), f"{sample['id']}[{index}]")
                    self.assertEqual(len(blob), item["serialized_len"], f"{sample['id']}[{index}]")
            else:
                for index, text in enumerate(data["transactions_hex"]):
                    blob = zv.unhex(text)
                    self.assertEqual(zv.tx_serialize(zv.tx_deserialize(blob)), blob, f"{sample['id']}[{index}]")

    def test_transaction_ids_compose_into_the_published_computed_root(self):
        for sample in CASES:
            got = recompute(sample)
            leaves = [zv.tx_txid(tx) for tx in transactions_of(sample)]
            self.assertEqual(got["computed_root"], zv.hash256_json(zv.merkle_root(leaves)), sample["id"])
            self.assertEqual(got["computed_root_len"], 32, sample["id"])
            if "leaves" in got:
                self.assertEqual([leaf["txid"] for leaf in got["leaves"]], [zv.hash256_json(l) for l in leaves])

    def test_display_hex_is_the_reversal_of_internal_hex(self):
        for sample in CASES:
            got = recompute(sample)
            digests = [got["claimed_root"], got["computed_root"]]
            digests += [leaf["txid"] for leaf in got.get("leaves", [])]
            for digest in digests:
                internal = digest["internal_hex"]
                self.assertEqual(digest["display_hex"], bytes.fromhex(internal)[::-1].hex())

    def test_the_claimed_root_is_the_header_field_and_roots_match_only_when_equal(self):
        for sample in CASES:
            got = recompute(sample)
            claim = sample["input"]["header"]["merkle_root_hex"]
            self.assertEqual(got["claimed_root"]["internal_hex"], claim, sample["id"])
            self.assertEqual(
                got["roots_match"], claim == got["computed_root"]["internal_hex"], sample["id"]
            )

    def test_the_empty_block_root_is_the_tagged_empty_digest(self):
        empty = case("iso_08_no_transactions")
        got = recompute(empty)
        self.assertEqual(got["computed_root"], zv.hash256_json(zv.sha256d(zv.EMPTY_MERKLE_TAG)))
        self.assertTrue(got["roots_match"], "the fixture claims the empty digest it publishes")

    def _expected_pow(self, sample):
        """Recompute proof of work from the fixture's own header, context engine and its
        *own* difficulty bits -- written here so the test is a second implementation."""
        header = sample["input"]["header"]
        preimage = zv.header_preimage(zv._header_from_json(header))
        context = sample["input"]["validation_context"]
        if context["engine"] == zv.SCRATCHPAD_ENGINE_NAME:
            memory_bytes, rounds = zv.SCRATCHPAD_PRESETS[sample["input"]["engine_config"]["preset"]]
            digest = zv.scratchpad_hash(preimage, header["nonce"], memory_bytes, rounds)
        elif context["engine"] == zv.TRIVIAL_ENGINE_NAME:
            digest = zv.trivial_hash(preimage, header["nonce"])
        else:  # pragma: no cover - the corpus has no other engine
            self.fail(f"unmodelled engine in fixture: {context['engine']}")
        return zv.hash_meets_target(digest, zv.compact_to_target(header["difficulty_bits"]))

    def test_proof_of_work_uses_the_headers_own_bits_and_the_context_engine(self):
        for sample in CASES:
            self.assertEqual(
                recompute(sample)["proof_of_work_meets_target"],
                self._expected_pow(sample),
                sample["id"],
            )

    def test_the_scratchpad_cases_resolve_the_preset_each_one_publishes(self):
        scratchpad = [s for s in CASES if s["input"]["validation_context"]["engine"] == zv.SCRATCHPAD_ENGINE_NAME]
        # Six fixtures set the context engine to scratchpad: the isolated wrong
        # engine case, the two non-default witnesses (`mainnet()` from P4.2B-4C and
        # `low_spec()` from P4.2B-4E), two precedence pairs that straddle it, and
        # the chaos case.
        self.assertEqual(len(scratchpad), 6, [s["id"] for s in scratchpad])
        for sample in scratchpad:
            config = sample["input"]["engine_config"]
            self.assertEqual(config["engine_id"], zv.ENGINE_ID_SCRATCHPAD, sample["id"])
            self.assertEqual(config["engine_name"], zv.SCRATCHPAD_ENGINE_NAME, sample["id"])
            self.assertIn(config["preset"], zv.SCRATCHPAD_PRESETS, sample["id"])
            self.assertEqual(recompute(sample)["proof_of_work_meets_target"], self._expected_pow(sample), sample["id"])

    def test_the_corpus_carries_a_non_default_scratchpad_witness(self):
        """P4.2B-4C pinned `mainnet()`; P4.2B-4E adds `low_spec()` beside it.

        Each witness is found through the preset token it publishes, never through
        its id, and its budget comes from the oracle's own preset table. The nonce
        is then shown to be load-bearing: it solves the published preset and it
        does not solve `balanced()`. That is what makes the case evidence about a
        configuration rather than a label on one -- a consumer that substituted
        the default preset would reject a case the corpus publishes as accepted.
        """
        balanced_budget = zv.SCRATCHPAD_PRESETS["ScratchPadEngine::balanced()"]
        self.assertEqual(balanced_budget, (64 * 1024, 1_024))

        witnesses = [
            s for s in CASES
            if s["input"]["validation_context"]["engine"] == zv.SCRATCHPAD_ENGINE_NAME
            and s["input"]["engine_config"]["preset"] in zv.SCRATCHPAD_PRESETS
            and zv.SCRATCHPAD_PRESETS[s["input"]["engine_config"]["preset"]] != balanced_budget
        ]
        self.assertEqual(len(witnesses), 2, [s["id"] for s in witnesses])

        # Two witnesses have to mean two configurations. Pinning `low_spec()` by
        # budget rather than by fixture id keeps this a statement about the corpus
        # contract, not about a name: a second copy of `mainnet()` would fail here.
        budgets = {
            zv.SCRATCHPAD_PRESETS[s["input"]["engine_config"]["preset"]]
            for s in witnesses
        }
        self.assertEqual(len(budgets), len(witnesses), [s["id"] for s in witnesses])
        self.assertIn(
            zv.SCRATCHPAD_PRESETS["ScratchPadEngine::low_spec()"],
            budgets,
            [s["id"] for s in witnesses],
        )

        for sample in witnesses:
            memory_bytes, rounds = zv.SCRATCHPAD_PRESETS[
                sample["input"]["engine_config"]["preset"]
            ]
            self.assertNotEqual(
                (memory_bytes, rounds), balanced_budget, sample["id"]
            )

            header = sample["input"]["header"]
            preimage = zv.header_preimage(zv._header_from_json(header))
            target = zv.compact_to_target(header["difficulty_bits"])
            self.assertTrue(
                zv.hash_meets_target(
                    zv.scratchpad_hash(preimage, header["nonce"], memory_bytes, rounds),
                    target,
                ),
                f"{sample['id']}: the nonce does not solve the preset the fixture publishes",
            )
            self.assertFalse(
                zv.hash_meets_target(
                    zv.scratchpad_hash(preimage, header["nonce"], *balanced_budget), target
                ),
                f"{sample['id']}: the nonce also solves `balanced()`, so it is not evidence "
                "about the preset the fixture names",
            )

            # It is an accept, so B-15 is actually evaluated rather than short-circuited.
            got = recompute(sample)
            self.assertTrue(got["accepted"], sample["id"])
            self.assertEqual(got["violated_rules"], [], sample["id"])
            self.assertTrue(got["proof_of_work_meets_target"], sample["id"])


class TestDerivedVerdicts(unittest.TestCase):
    """Mutating an input moves the verdict, so the verdict cannot be a copy."""

    def test_the_verifier_never_reads_the_published_expectation(self):
        for sample in CASES:
            stripped = case(sample["id"][len(GROUP):])
            stripped["expected"] = {}
            self.assertEqual(recompute(stripped), recompute(sample), sample["id"])

    def _base(self):
        sample = case("bnd_12_one_above_median_accept")
        self.assertEqual(recompute(sample)["violated_rules"], [])
        return sample

    def test_a_foreign_chain_id_becomes_b3(self):
        sample = self._base()
        sample["input"]["header"]["chain"] ^= 0x0100
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [3])
        self.assertEqual(got["error_kind"], "WrongChain")
        self.assertEqual(got["error_payload"]["found"], sample["input"]["header"]["chain"])

    def test_a_stale_previous_hash_becomes_b5(self):
        sample = self._base()
        sample["input"]["header"]["previous_hash_hex"] = "ab" * 32
        sample["input"]["validation_context"]["expected_previous_hex"] = "cd" * 32
        got = recompute(sample)
        self.assertEqual(got["reported_rule"], 5)
        self.assertEqual(got["error_kind"], "BadPreviousHash")
        self.assertIsNone(got["error_payload"])
        # The previous hash is inside the header preimage, so replacing it also
        # moves the proof-of-work digest away from the mined nonce. B-5 is still
        # the row reported, which is the whole point of the ordering.
        self.assertEqual(got["violated_rules"], [5, 15])

    def test_moving_the_coinbase_out_of_slot_zero_becomes_b10(self):
        sample = case("bnd_13_near_max_saturating_accept")
        before = recompute(sample)
        self.assertEqual(before["coinbase_flags"], "10000", sample["id"])
        self.assertEqual(before["violated_rules"], [], sample["id"])
        data = inputs(sample)
        # The whole published transactions are swapped, so each one still
        # re-encodes to the bytes beside it and only its position in the block
        # changes. Patching individual fields would break that proof.
        transactions = data["transactions"]
        transactions[0], transactions[1] = transactions[1], transactions[0]
        got = recompute(sample)
        self.assertEqual(got["coinbase_flags"], "01000")
        self.assertFalse(got["first_is_coinbase"])
        self.assertEqual(got["coinbase_count"], 1, "still one coinbase, just not in slot zero")
        self.assertEqual(got["reported_rule"], 10)
        self.assertEqual(got["error_kind"], "FirstNotCoinbase")
        self.assertIn(11, got["violated_rules"], "the coinbase now sits in the tail as well")
        self.assertIn(14, got["violated_rules"], "the merkle root is order-sensitive, so the reordering moved it too")
        self.assertEqual(got["violated_rules"], [10, 11, 14], "and B-10 is the row reported first")

    def test_a_timestamp_past_the_saturating_bound_becomes_b13(self):
        sample = self._base()
        header, context = sample["input"]["header"], sample["input"]["validation_context"]
        context["now"] = header["timestamp"] - zv.MAX_FUTURE_SECONDS - 1
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [13])
        self.assertEqual(got["error_payload"], {"found": header["timestamp"], "now": context["now"]})

    def test_a_tampered_root_claim_becomes_b14(self):
        sample = self._base()
        sample["input"]["header"]["merkle_root_hex"] = "11" * 32
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [14])
        self.assertFalse(got["roots_match"])

    def test_repairing_the_root_claim_from_the_leaves_removes_b14(self):
        sample = case("iso_14_root_mismatch")
        data = sample["input"]
        before = recompute(sample)
        self.assertFalse(before["roots_match"])
        # Repairing the claim from the published transactions proves the root the
        # verifier computed is the one the bytes describe.
        data["header"]["merkle_root_hex"] = before["computed_root"]["internal_hex"]
        after = recompute(sample)
        self.assertTrue(after["roots_match"])
        self.assertEqual(after["computed_root"], before["computed_root"], "the leaves did not move")
        self.assertNotIn(14, after["violated_rules"], "the mismatch B-14 reported is gone")
        # The claimed root is itself part of the header preimage, so repairing it
        # takes the digest off the nonce the fixture was mined with. B-15 becomes
        # the only remaining complaint -- an honest consequence of the ordering,
        # not a defect in the repair.
        self.assertEqual(after["violated_rules"], [15], sample["id"])

    def test_a_byte_flipped_in_a_hex_transaction_breaks_the_root_it_was_mined_for(self):
        sample = case("bnd_09_count_at_limit_accept")
        self.assertEqual(recompute(sample)["violated_rules"], [])
        blobs = sample["input"]["transactions_hex"]
        last = bytes.fromhex(blobs[-1])
        blobs[-1] = (last[:-1] + bytes([last[-1] ^ 0x01])).hex()
        got = recompute(sample)
        self.assertEqual(got["violated_rules"], [14])
        self.assertEqual(got["leaf_count"], 2_000, "the count is untouched, only the root moved")

    def test_an_unmodelled_engine_is_unsupported_and_never_a_pass(self):
        sample = self._base()
        sample["input"]["validation_context"]["engine"] = "sha256d-shiny-new"
        sample["input"]["engine_config"] = None
        with self.assertRaises(zv.Unsupported):
            recompute(sample)
        with self.assertRaises(zv.Unsupported):
            zv.verify_case(sample, _INDEX)

    def test_an_unmodelled_scratchpad_preset_is_unsupported(self):
        sample = case("iso_06_wrong_engine")
        sample["input"]["engine_config"]["preset"] = "ScratchPadEngine::unbounded()"
        with self.assertRaises(zv.Unsupported):
            zv.verify_case(sample, _INDEX)


class TestMalformedFixtures(unittest.TestCase):
    """A fixture that contradicts itself is a failure, never a pass."""

    def _expect_rejection(self, sample, fragment):
        with self.assertRaises(zv.VectorMismatch) as caught:
            zv._verify_block_structure(sample)
        self.assertIn(fragment, str(caught.exception))

    def test_unknown_case_id_is_unsupported_not_passing(self):
        sample = case("iso_03_wrong_chain")
        sample["id"] = "chain.something_else.unheard_of"
        with self.assertRaises(zv.Unsupported) as caught:
            zv.verify_case(sample, _INDEX)
        self.assertIn("no verifier is registered", str(caught.exception))

    def test_a_transaction_that_does_not_re_encode_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        blob = sample["input"]["transactions"][0]["serialized_hex"]
        sample["input"]["transactions"][0]["serialized_hex"] = blob[:-2] + "ff"
        self._expect_rejection(sample, "re-encode")

    def test_a_wrong_serialized_len_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["transactions"][0]["serialized_len"] += 1
        self._expect_rejection(sample, "serialized_len")

    def test_a_lying_coinbase_flag_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["transactions"][0]["is_coinbase"] = False
        self._expect_rejection(sample, "is_coinbase")

    def test_a_disagreeing_tx_count_is_rejected(self):
        for suffix in ("iso_03_wrong_chain", "bnd_09_count_at_limit_accept"):
            sample = case(suffix)
            sample["input"]["tx_count"] += 1
            self._expect_rejection(sample, "tx_count")

    def test_both_or_neither_transaction_shapes_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["transactions_hex"] = ["00"]
        self._expect_rejection(sample, "exactly one of")

        sample = case("bnd_09_count_at_limit_accept")
        del sample["input"]["transactions_hex"]
        self._expect_rejection(sample, "exactly one of")

    def test_a_truncated_digest_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["header"]["previous_hash_hex"] = "33" * 31
        self._expect_rejection(sample, "64-digit hex")

    def test_a_non_hex_digest_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["header"]["merkle_root_hex"] = "zz" * 32
        self._expect_rejection(sample, "not hex")

    def test_an_oversized_fixed_width_field_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["header"]["chain"] = MASK32 + 1
        self._expect_rejection(sample, "outside")

        sample = case("iso_03_wrong_chain")
        sample["input"]["validation_context"]["now"] = MASK64 + 1
        self._expect_rejection(sample, "outside")

    def test_an_unpublished_input_field_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["validation_context"]["expected_next_block_reward"] = 50
        self._expect_rejection(sample, "unpublished fields")

        sample = case("iso_03_wrong_chain")
        sample["input"]["consensus_hints"] = {}
        self._expect_rejection(sample, "unpublished input fields")

    def test_a_missing_required_field_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        del sample["input"]["header"]["nonce"]
        self._expect_rejection(sample, "missing")

    def test_a_scratchpad_context_without_a_config_is_rejected(self):
        sample = case("iso_06_wrong_engine")
        sample["input"]["engine_config"] = None
        self._expect_rejection(sample, "no engine_config")

    def test_a_trivial_context_with_a_config_is_rejected(self):
        sample = case("iso_03_wrong_chain")
        sample["input"]["engine_config"] = {"engine_id": 1}
        self._expect_rejection(sample, "engine_config")

    def test_a_mismatched_expected_verdict_is_reported_as_a_failure(self):
        sample = case("iso_03_wrong_chain")
        sample["expected"]["error_kind"] = "BadHeight"
        with self.assertRaises(zv.VectorMismatch):
            zv.verify_case(sample, _INDEX)

    def test_an_added_leaf_is_reported_as_a_failure(self):
        sample = case("iso_11_duplicate_coinbase")
        sample["expected"]["leaves"].append(sample["expected"]["leaves"][0])
        with self.assertRaises(zv.VectorMismatch) as caught:
            zv.verify_case(sample, _INDEX)
        self.assertIn("leaves", str(caught.exception))


class TestUntouchedRegressions(unittest.TestCase):
    """P4.2B-2 must not change what the P0 corpus or the runner already did."""

    def test_the_p0_corpus_still_resolves_every_registered_case(self):
        p0_root = HERE.parent / "vectors"
        if not p0_root.exists():
            self.skipTest(f"{p0_root} is not present in this checkout")
        index, ordered, _ = run_vectors.load_corpus(p0_root)
        unsupported = []
        mismatched = []
        for sample in ordered:
            try:
                zv.verify_case(sample, index)
            except zv.Unsupported as error:
                unsupported.append(str(error))
            except zv.VectorMismatch as error:
                mismatched.append(f"{sample['id']}: {error}")
        self.assertEqual(mismatched, [])
        self.assertEqual(unsupported, [], "the P0 corpus is expected to be fully registered")

    def test_the_group_prefix_does_not_shadow_an_existing_verifier(self):
        for name in ("chain.header.preimage_regtest_mainnet", "chain.merkle.four_leaves"):
            self.assertFalse(name.startswith(GROUP))

    def test_the_verdict_helpers_agree_with_the_corpus_group_name(self):
        self.assertEqual(GROUP, "chain.block_structure.")
        self.assertEqual(sorted(zv.BLOCK_RULE_ERRORS), list(RULES))


def main():
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print()
    print(
        f"block-structure fixtures independently verified: "
        f"{sum(1 for s in CASES if zv.verify_case(s, _INDEX) == 'PASS')} of {len(CASES)}"
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
