#!/usr/bin/env python3
"""Independent checks that the reference models `ScratchPadEngine::low_spec()`.

`low_spec()` is the one production preset whose budget is large enough that a
mistake is invisible: it shares `id()` (1) and `name()` (`scratchpad-memory-hard`)
with `balanced()` and `mainnet()`, so nothing in a fixture's header distinguishes
it from either. The only thing that does is the `engine_config.preset` token.
These tests hold the reference to that token: the exact budget it resolves to,
the digest that budget produces for a published probe input, and the fact that a
preset outside the table is `Unsupported` rather than quietly replayed under
`balanced()`.

The budget is 512 MiB and 2,048 rounds, so one digest costs tens of seconds in
pure Python. `_probe` memoises, which keeps the whole file at a single low-spec
hash no matter how many tests read it; the balanced (64 KiB) and mainnet (2 MiB)
probes are cheap enough to recompute. The cost is deliberately not reduced by
shrinking the budget: a smaller pad would stop modelling the production engine.

The pinned digest is a regression anchor, not evidence of correctness on its own
-- it was produced by this same implementation. What makes it worth pinning is
that the Rust production engine and the C++ production engine are required to
reproduce it: see `zerocoin/tests/p42_block_structure_parity.rs` and the
`p42_conformance` differential. Those are what turn the pin into a three-way
agreement rather than a self-portrait.

Run:
  python test/harness/test_low_spec_engine.py
"""

from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import zro_vectors as zv  # noqa: E402

LOW_SPEC = "ScratchPadEngine::low_spec()"
BALANCED = "ScratchPadEngine::balanced()"
MAINNET = "ScratchPadEngine::mainnet()"
MOBILE = "ScratchPadEngine::mobile()"

# Literal in `zerocoin/src/consensus/pow.rs`:
#   LOW_SPEC_SCRATCHPAD_BYTES = 512 * 1024 * 1024
#   pub const fn low_spec() -> Self { ScratchPadEngine::new(LOW_SPEC_SCRATCHPAD_BYTES, 2_048) }
LOW_SPEC_MEMORY_BYTES = 512 * 1024 * 1024
LOW_SPEC_ROUNDS = 2_048

# 512 MiB / 32-byte cells. 2**24, so the engine takes the `index_word & mask`
# branch rather than `index_word % cells`.
LOW_SPEC_CELLS = 16_777_216

# The fixed input these tests hash. Carries a domain tag and a terminator so it
# cannot collide with a header preimage, which always starts with `ZRO/header/v1\0`.
PROBE_INPUT = b"zro/p42b/low-spec/probe\0"
PROBE_NONCE = 0

# `zro_vectors.scratchpad_hash(PROBE_INPUT, PROBE_NONCE, <budget>)`, one per
# preset. The low-spec value is 32.6 s of work on the machine this was pinned on.
PINNED = {
    BALANCED: "72ad9435ced6d58a2967394bbcee1f4d9e35b6d7493c42b9cb5990aa6648d3e4",
    MAINNET: "153688438f694f469b79038bab3f909f003917d4038ccc75aede104d4aa86d15",
    LOW_SPEC: "73f7e9a84f1720501e2dd4c3c5f0042112f9cfddf19462538678494e594819e7",
}

_cache: dict[str, bytes] = {}
_resolved_cache: dict[str, bytes] = {}


def _probe(preset: str) -> bytes:
    """The digest `preset` produces for the shared published probe input."""
    if preset not in _cache:
        memory_bytes, rounds = zv.SCRATCHPAD_PRESETS[preset]
        _cache[preset] = zv.scratchpad_hash(PROBE_INPUT, PROBE_NONCE, memory_bytes, rounds)
    return _cache[preset]


def _resolved_probe(preset: str) -> bytes:
    """The same digest, but through the resolver a fixture's config goes through.

    Cached separately from `_probe` on purpose: comparing the two is what proves
    the resolver honours the table, and caching would erase the distinction.
    """
    if preset not in _resolved_cache:
        _, hasher = zv._block_pow_engine(preset, _scratchpad_context(), _scratchpad_config(preset))
        _resolved_cache[preset] = hasher(PROBE_INPUT, PROBE_NONCE)
    return _resolved_cache[preset]


def _scratchpad_config(preset: str, budget: tuple[int, int] | None = None) -> dict:
    """The `engine_config` a fixture publishes for a scratchpad preset.

    `budget` is passed explicitly for a preset the reference does not model, so
    the unsupported cases can publish the budget production would use without
    putting that budget in `SCRATCHPAD_PRESETS`.
    """
    resolved = budget if budget is not None else zv.SCRATCHPAD_PRESETS.get(preset)
    config = {
        "engine_name": zv.SCRATCHPAD_ENGINE_NAME,
        "engine_id": zv.ENGINE_ID_SCRATCHPAD,
        "preset": preset,
    }
    if resolved is not None:
        config["memory_bytes"], config["rounds"] = resolved
    return config


def _scratchpad_context() -> dict:
    return {"engine": zv.SCRATCHPAD_ENGINE_NAME}


class TestLowSpecConfiguration(unittest.TestCase):
    """The preset resolves to the budget the Rust constructor was given."""

    def test_the_preset_resolves_to_512_mib_and_2048_rounds(self):
        self.assertIn(LOW_SPEC, zv.SCRATCHPAD_PRESETS)
        self.assertEqual(zv.SCRATCHPAD_PRESETS[LOW_SPEC], (LOW_SPEC_MEMORY_BYTES, LOW_SPEC_ROUNDS))
        # Pinned as literals, not just as an expression, so a silent edit to the
        # numbers above cannot make this test agree with itself.
        self.assertEqual(LOW_SPEC_MEMORY_BYTES, 536_870_912)
        self.assertEqual(LOW_SPEC_ROUNDS, 2_048)

    def test_the_cell_count_is_the_power_of_two_the_engine_branches_on(self):
        memory_bytes, _ = zv.SCRATCHPAD_PRESETS[LOW_SPEC]
        cells = max(memory_bytes // zv.SCRATCHPAD_CELL, 1)
        self.assertEqual(cells, LOW_SPEC_CELLS)
        self.assertEqual(cells & (cells - 1), 0, "the preset must take the bitmask index path")

    def test_the_budget_differs_from_every_other_preset(self):
        budgets = {name: budget for name, budget in zv.SCRATCHPAD_PRESETS.items()}
        self.assertNotEqual(budgets[LOW_SPEC], budgets[BALANCED])
        self.assertNotEqual(budgets[LOW_SPEC], budgets[MAINNET])
        self.assertNotEqual(budgets[LOW_SPEC][0], budgets[BALANCED][0])
        self.assertNotEqual(budgets[LOW_SPEC][0], budgets[MAINNET][0])

    def test_the_preset_token_is_the_only_thing_that_distinguishes_them(self):
        # Every scratchpad preset reports the same id and name in production, so
        # a verifier that keys off either one cannot tell low_spec() from
        # balanced(). That is why the budget comes from this table and nowhere
        # else, and why the tests below compare digests rather than identities.
        self.assertEqual(zv.ENGINE_ID_SCRATCHPAD, 1)
        self.assertEqual(zv.SCRATCHPAD_ENGINE_NAME, "scratchpad-memory-hard")

    def test_mobile_is_still_not_modelled(self):
        # P4.2B-4E supports one new preset, not two. `mobile()` stays a
        # deliberate `Unsupported`, not a silent substitution.
        self.assertNotIn(MOBILE, zv.SCRATCHPAD_PRESETS)


class TestLowSpecDigest(unittest.TestCase):
    """A fixed published input produces a fixed, low-spec-only digest."""

    def test_the_probe_digest_is_stable(self):
        digest = _probe(LOW_SPEC)
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest.hex(), PINNED[LOW_SPEC])

    def test_the_probe_digest_is_not_any_other_preset_s(self):
        selected = _probe(LOW_SPEC)
        self.assertNotEqual(selected, _probe(BALANCED))
        self.assertNotEqual(selected, _probe(MAINNET))
        self.assertNotEqual(_probe(BALANCED), _probe(MAINNET))

    def test_a_silent_substitution_would_be_caught(self):
        # The whole point of the pin: if the resolver handed back balanced()'s
        # hasher for the low_spec token, this comparison is what fails.
        substituted = zv.scratchpad_hash(PROBE_INPUT, PROBE_NONCE, *zv.SCRATCHPAD_PRESETS[BALANCED])
        self.assertNotEqual(substituted.hex(), PINNED[LOW_SPEC])


class TestLowSpecEngineSelection(unittest.TestCase):
    """A low-spec config resolves to the scratchpad engine with its own budget."""

    def test_a_low_spec_config_resolves_to_engine_1(self):
        engine_id, _ = zv._block_pow_engine("low_spec", _scratchpad_context(), _scratchpad_config(LOW_SPEC))
        self.assertEqual(engine_id, zv.ENGINE_ID_SCRATCHPAD)

    def test_the_resolved_hasher_uses_the_low_spec_budget(self):
        self.assertEqual(_resolved_probe(LOW_SPEC).hex(), PINNED[LOW_SPEC])

    def test_the_resolved_hasher_is_not_the_balanced_one(self):
        self.assertNotEqual(_resolved_probe(LOW_SPEC), _resolved_probe(BALANCED))

    def test_a_mislabelled_engine_config_is_a_mismatch_not_a_fallback(self):
        config = _scratchpad_config(LOW_SPEC)
        config["engine_id"] = zv.ENGINE_ID_TRIVIAL
        with self.assertRaises(zv.VectorMismatch):
            zv._block_pow_engine("low_spec", _scratchpad_context(), config)

        config = _scratchpad_config(LOW_SPEC)
        config["engine_name"] = zv.TRIVIAL_ENGINE_NAME
        with self.assertRaises(zv.VectorMismatch):
            zv._block_pow_engine("low_spec", _scratchpad_context(), config)


class TestLowSpecIsNotAFallback(unittest.TestCase):
    """Presets outside the table stay `Unsupported`."""

    def test_mobile_is_unsupported(self):
        # `mobile()` is 256 MiB / 1,024 in production; the budget is published
        # here precisely so the rejection cannot be blamed on a missing field.
        mobile_budget = (256 * 1024 * 1024, 1_024)
        with self.assertRaises(zv.Unsupported) as caught:
            zv._block_pow_engine("mobile", _scratchpad_context(), _scratchpad_config(MOBILE, mobile_budget))
        self.assertIn(MOBILE, str(caught.exception))

    def test_an_invented_preset_is_unsupported(self):
        with self.assertRaises(zv.Unsupported) as caught:
            zv._block_pow_engine(
                "invented", _scratchpad_context(), _scratchpad_config("ScratchPadEngine::turbo()")
            )
        self.assertIn("ScratchPadEngine::turbo()", str(caught.exception))

    def test_a_missing_preset_is_unsupported_rather_than_balanced(self):
        config = _scratchpad_config(LOW_SPEC)
        del config["preset"]
        with self.assertRaises(zv.Unsupported):
            zv._block_pow_engine("missing", _scratchpad_context(), config)

    def test_unsupported_is_not_a_verdict(self):
        # `Unsupported` must be its own exception type: the corpus runner treats
        # it as "unimplemented", never as a pass and never as a mismatch.
        self.assertTrue(issubclass(zv.Unsupported, Exception))
        self.assertFalse(issubclass(zv.Unsupported, zv.VectorMismatch))


class TestExistingPresetsUnchanged(unittest.TestCase):
    """Adding low_spec() must not have moved balanced() or mainnet()."""

    def test_the_balanced_budget_and_digest_are_unchanged(self):
        self.assertEqual(zv.SCRATCHPAD_PRESETS[BALANCED], (64 * 1024, 1_024))
        self.assertEqual(_probe(BALANCED).hex(), PINNED[BALANCED])

    def test_the_mainnet_budget_and_digest_are_unchanged(self):
        self.assertEqual(zv.SCRATCHPAD_PRESETS[MAINNET], (2 * 1024 * 1024, 4_096))
        self.assertEqual(_probe(MAINNET).hex(), PINNED[MAINNET])

    def test_the_trivial_engine_is_unchanged(self):
        self.assertEqual(
            zv.trivial_hash(PROBE_INPUT, PROBE_NONCE).hex(),
            zv.sha256d(PROBE_INPUT + zv.le64(PROBE_NONCE)).hex(),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
