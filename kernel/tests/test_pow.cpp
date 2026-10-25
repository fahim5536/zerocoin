// Proof-of-work engine tests. test/vectors/pow/engines.json is the value oracle
// for everything the corpus publishes, and kernel/tools/p4_conformance.py replays
// those eleven rows byte for byte through the conformance runner; what the corpus
// cannot express is the structure around them — that the nonce never enters the
// 107-byte preimage, that the engine id is compared rather than dispatched, that
// the finalizer folds the state AND every cell, and which of the two indexing
// formulas a non-power-of-two pad uses. Those are what this file pins.
//
// Every expected digest below is copied from the committed fixture, so nothing
// here derives an expected value by calling the implementation under test. The one
// branch no committed vector reaches (a pad whose cell count is not a power of two)
// is handled by `reference_image` below, which says so explicitly.

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "pow_internal.h"
#include "test_framework.h"
#include "zerocoin/difficulty.h"
#include "zerocoin/hash.h"
#include "zerocoin/header.h"
#include "zerocoin/hex.h"
#include "zerocoin/pow.h"
#include "zerocoin/uint256.h"

namespace {

using zk::BlockHeader;
using zk::Hash256;
using zk::PowEngine;
using zk::ScratchPadParams;

// The committed raw preimage, `b"zerocoin-pow"`, and the committed 107-byte header
// preimage, both straight from test/vectors/pow/engines.json. The raw one is
// written as an ASCII literal and then checked against the fixture hex below, so a
// mistyped literal fails loudly instead of silently retargeting every vector.
constexpr std::string_view kRawPreimage = "zerocoin-pow";
constexpr const char* kRawPreimageHex = "7a65726f636f696e2d706f77";
constexpr const char* kHeaderPreimageHex =
    "5a524f2f6865616465722f76310001000000004f525a0100000000000000"
    "3333333333333333333333333333333333333333333333333333333333333333"
    "4444444444444444444444444444444444444444444444444444444444444444"
    "01f1536500000000ffff7f2000";

// The committed internal digests, keyed by the case that publishes them.
constexpr const char* kTrivialRaw0 = "d52bccadf38bd3e746697b398139e6d78ba89ed9ee77b9d40241e9e8e2350deb";
constexpr const char* kTrivialRaw1 = "52aca33d20c3095974c67099781ac338208a67081a6e333b43b567b3f0df89c6";
constexpr const char* kTrivialHeader0 = "b4ee94b88bdc749805fce49a5e9d361a31e0980f4bbdc97b101a62279f5899a3";
constexpr const char* kTrivialHeader42 = "c7c8857039fb5bd117c7a295621df6e370fd51c36d155b24052732d206a53439";
constexpr const char* kScratchDevnet0 = "767eb23ee64fec30fd2a0fe6cdec344430e70aa7366dfc9d3d8658a6c6ce9fca";
constexpr const char* kScratchDevnet1 = "3efa396d1920fea0e3d7b942de423a5dd101e20a14eea042ecee4fd159997d1a";
constexpr const char* kScratchDevnet42 = "a6c380c7ed1e30c6e517ce20c19067debaf4b5bc3d3ff7632a51029aef5353ff";
constexpr const char* kScratchMainnet0 = "da324a51e074a7018a162d3b02553bf7375bfa77dab35a77767205aecdaaa55a";
constexpr const char* kScratchMainnet1 = "b0c6929750813bcb5280a5172f25583de55876eb9c70eb6b7c84a8cbda6fd9ec";

// The header the 214-character preimage above decodes to. Every field was read off
// that byte string, little-endian, and the engine byte is the fixture's 0.
BlockHeader fixture_header(std::uint64_t nonce) {
  BlockHeader header{};
  header.version = 1;
  header.chain = 0x5A524F00u;
  header.height = 1;
  for (std::size_t i = 0; i < Hash256::kWidth; ++i) {
    header.previous_hash.bytes[i] = 0x33;
    header.merkle_root.bytes[i] = 0x44;
  }
  header.timestamp = 1700000001;
  header.difficulty_bits = 0x207FFFFFu;
  header.engine_id = zk::kEngineIdTrivial;
  header.nonce = nonce;
  return header;
}

std::string internal(const Hash256& hash) { return hash.to_hex().str(); }

std::vector<std::uint8_t> committed_preimage() {
  const auto bytes = zk::from_hex(kRawPreimageHex);
  ZK_CHECK(bytes.has_value());
  return *bytes;
}

std::vector<std::uint8_t> committed_header_preimage() {
  const auto bytes = zk::from_hex(kHeaderPreimageHex);
  ZK_CHECK(bytes.has_value());
  ZK_CHECK(bytes->size() == zk::kHeaderPreimageSize);
  return *bytes;
}

Hash256 hash_raw(const PowEngine& engine, std::uint64_t nonce) {
  const std::vector<std::uint8_t> preimage = committed_preimage();
  return engine.hash(preimage.data(), preimage.size(), nonce);
}

/// A committed internal digest as the value the comparison layer would receive.
/// Used where a test needs to hold the DIGEST fixed and vary only the target.
Hash256 committed_hash(const char* internal_hex) {
  const auto bytes = zk::from_hex(internal_hex);
  ZK_CHECK(bytes.has_value() && bytes->size() == Hash256::kWidth);
  std::array<std::uint8_t, Hash256::kWidth> raw{};
  std::copy_n(bytes->begin(), Hash256::kWidth, raw.begin());
  const Hash256 hash(raw);
  // Guard the decode itself: if this ever disagreed with the literal the fixture
  // would no longer be the oracle for the rows that use it.
  ZK_CHECK(internal(hash) == std::string(internal_hex));
  return hash;
}

void expect_internal(const Hash256& hash, const char* expected) {
  ZK_CHECK(internal(hash) == expected);
  // The display form is the same 32 bytes reversed, so a row cannot pass by
  // publishing one order and comparing the other.
  std::string reversed;
  for (std::size_t i = Hash256::kWidth; i > 0; --i) {
    const std::uint8_t byte = hash.bytes[i - 1];
    reversed += "0123456789abcdef"[byte >> 4];
    reversed += "0123456789abcdef"[byte & 0x0f];
  }
  ZK_CHECK(hash.to_display_hex().str() == reversed);
}

void append_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (unsigned i = 0; i < sizeof(std::uint64_t); ++i) {
    out.push_back(static_cast<std::uint8_t>(value >> (8U * i)));
  }
}

std::uint64_t read_le64(const std::uint8_t* bytes) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < sizeof(std::uint64_t); ++i) {
    value |= static_cast<std::uint64_t>(bytes[i]) << (8U * i);
  }
  return value;
}

/// An independent re-derivation of the reference's scratchpad steps, for the one
/// branch the committed corpus does not cover.
///
/// Both shipped profiles are powers of two (2,048 and 65,536 cells), so every
/// committed ScratchPad row would produce the same bytes whether the index came
/// from `& (cells - 1)` or from `% cells`, and the corpus therefore pins neither
/// formula against the other. `mask_index` is the non-conforming hypothesis, kept
/// so a test can show the two really diverge for a cell count of 3 and that the
/// engine lands on the remainder side. This is not an oracle for a consensus
/// value — no such value is published for this branch — it is a guard that the
/// branch Rust takes is the branch this kernel takes, and it is written from
/// pow.cpp's documented rule rather than by calling pow.cpp. It uses only
/// `zk::sha256`, which test_hash.cpp and the G1 corpus pin on their own.
std::vector<std::uint8_t> reference_image(const std::vector<std::uint8_t>& preimage,
                                          std::uint64_t nonce, std::size_t cells,
                                          std::size_t rounds, bool mask_index) {
  std::vector<std::uint8_t> seed_input = preimage;
  append_le64(seed_input, nonce);
  std::array<std::uint8_t, zk::kScratchpadCellBytes> state =
      zk::sha256(seed_input.data(), seed_input.size());

  std::vector<std::uint8_t> image(zk::detail::scratchpad_image_bytes(cells));
  std::uint8_t* const cells_begin = image.data() + zk::kScratchpadCellBytes;
  for (std::size_t cell = 0; cell < cells; ++cell) {
    state = zk::sha256(state.data(), state.size());
    std::copy_n(state.begin(), zk::kScratchpadCellBytes,
                cells_begin + zk::kScratchpadCellBytes * cell);
  }

  const std::uint64_t mask = static_cast<std::uint64_t>(cells - 1);
  const std::uint64_t width = static_cast<std::uint64_t>(cells);
  for (std::size_t round = 0; round < rounds; ++round) {
    const std::uint64_t index_word = read_le64(state.data());
    const std::size_t index =
        mask_index ? static_cast<std::size_t>(index_word & mask)
                   : static_cast<std::size_t>(index_word % width);
    std::array<std::uint8_t, zk::kScratchpadCellBytes * 2> mixed{};
    std::copy_n(state.begin(), zk::kScratchpadCellBytes, mixed.begin());
    std::copy_n(cells_begin + zk::kScratchpadCellBytes * index, zk::kScratchpadCellBytes,
                mixed.begin() + zk::kScratchpadCellBytes);
    state = zk::sha256(mixed.data(), mixed.size());
    std::copy_n(state.begin(), zk::kScratchpadCellBytes,
                cells_begin + zk::kScratchpadCellBytes * index);
  }
  std::copy_n(state.begin(), zk::kScratchpadCellBytes, image.begin());
  return image;
}

/// A budget small enough to hash on every test run, with the same shape as the
/// profiles: a whole number of cells. 1,024 bytes is 32 cells, a power of two.
constexpr ScratchPadParams kTinyPowerOfTwo{1024, 8};
/// The same budget with a cell count that is not a power of two: 96 / 32 = 3.
constexpr ScratchPadParams kTinyRemainder{96, 64};

std::vector<std::uint8_t> production_image(const ScratchPadParams& params,
                                           const std::vector<std::uint8_t>& preimage,
                                           std::uint64_t nonce) {
  const std::size_t cells = zk::scratchpad_cell_count(params.memory_bytes);
  std::vector<std::uint8_t> image(zk::detail::scratchpad_image_bytes(cells));
  zk::detail::write_scratchpad_image(image.data(), image.size(), params, preimage.data(),
                                     preimage.size(), nonce);
  return image;
}

}  // namespace

// --- identities and dispatch -------------------------------------------------

ZK_TEST(engine_identities_are_the_reference_constants) {
  const PowEngine trivial = PowEngine::trivial();
  ZK_CHECK(trivial.id() == 0);
  ZK_CHECK(trivial.name() == "sha256d-trivial");
  // There is no default engine and there is deliberately never going to be one:
  // the two factories are the only way to obtain a PowEngine, so no caller can
  // hold an engine whose id it did not choose. Pinning the absence here is what
  // keeps a future `PowEngine()` from silently becoming a third, undeclared path
  // into the hash function.
  static_assert(!std::is_default_constructible_v<PowEngine>,
                "an engine must come from a factory, never from a default value");
  static_assert(std::is_copy_constructible_v<PowEngine>,
                "the factories return by value, so the type must stay copyable");

  const PowEngine pad = PowEngine::scratchpad(zk::kScratchpadDevnet);
  ZK_CHECK(pad.id() == 1);
  ZK_CHECK(pad.name() == "scratchpad-memory-hard");
  ZK_CHECK(pad.scratchpad_params() == zk::kScratchpadDevnet);
  // The trivial engine reads neither field, so it reports the empty budget rather
  // than inventing one.
  ZK_CHECK(trivial.scratchpad_params().memory_bytes == 0);
  ZK_CHECK(trivial.scratchpad_params().rounds == 0);
}

ZK_TEST(both_shipped_profiles_keep_their_declared_budget) {
  ZK_CHECK(zk::kScratchpadDevnet.memory_bytes == 64u * 1024u);
  ZK_CHECK(zk::kScratchpadDevnet.rounds == 1024);
  ZK_CHECK(zk::kScratchpadMainnet.memory_bytes == 2u * 1024u * 1024u);
  ZK_CHECK(zk::kScratchpadMainnet.rounds == 4096);
  // No clamping, no rounding: `capped_to` is a mining helper the reference says
  // never redefines the consensus engine, so the kernel must hand back exactly
  // what it was given.
  ZK_CHECK(PowEngine::scratchpad(zk::kScratchpadMainnet).scratchpad_params() ==
           zk::kScratchpadMainnet);
  const ScratchPadParams odd{1023, 7};
  ZK_CHECK(PowEngine::scratchpad(odd).scratchpad_params() == odd);
  ZK_CHECK(PowEngine::scratchpad(odd).scratchpad_params() != zk::kScratchpadDevnet);
}

ZK_TEST(engine_for_id_resolves_the_two_declared_ids_and_nothing_else) {
  const auto trivial = zk::engine_for_id(0, zk::kScratchpadDevnet);
  ZK_CHECK(trivial.has_value());
  ZK_CHECK(trivial->id() == 0);
  ZK_CHECK(trivial->name() == "sha256d-trivial");

  const auto pad = zk::engine_for_id(1, zk::kScratchpadMainnet);
  ZK_CHECK(pad.has_value());
  ZK_CHECK(pad->id() == 1);
  ZK_CHECK(pad->name() == "scratchpad-memory-hard");
  ZK_CHECK(pad->scratchpad_params() == zk::kScratchpadMainnet);

  // Round-trip: the function is the inverse of `id()` for the ids that exist.
  ZK_CHECK(zk::engine_for_id(trivial->id(), zk::kScratchpadDevnet)->id() == trivial->id());
  ZK_CHECK(zk::engine_for_id(pad->id(), zk::kScratchpadDevnet)->id() == pad->id());
}

ZK_TEST(engine_for_id_refuses_every_undeclared_byte) {
  // 2 through 255 have no engine. A default here would let a byte this module did
  // not choose select the hash function, so the requirement is that nothing is
  // returned — not something plausible, not the cheaper algorithm.
  for (unsigned id = 2; id <= 255; ++id) {
    const auto engine = zk::engine_for_id(static_cast<std::uint8_t>(id), zk::kScratchpadDevnet);
    ZK_CHECK(!engine.has_value());
  }
}

ZK_TEST(a_peer_engine_byte_is_compared_never_dispatched) {
  const BlockHeader declared = fixture_header(0);
  const PowEngine trivial = PowEngine::trivial();
  const PowEngine pad = PowEngine::scratchpad(zk::kScratchpadDevnet);
  ZK_CHECK(zk::header_engine_matches(declared, trivial));
  ZK_CHECK(!zk::header_engine_matches(declared, pad));

  BlockHeader other = declared;
  other.engine_id = zk::kEngineIdScratchpad;
  ZK_CHECK(!zk::header_engine_matches(other, trivial));
  ZK_CHECK(zk::header_engine_matches(other, pad));

  // An id with no engine still fails every comparison rather than matching a
  // default, which is what `validate_structure`'s WrongEngine produces.
  other.engine_id = 7;
  ZK_CHECK(!zk::header_engine_matches(other, trivial));
  ZK_CHECK(!zk::header_engine_matches(other, pad));
}

// --- the 107-byte preimage and the nonce -------------------------------------

ZK_TEST(the_committed_header_preimage_is_reproduced_without_the_nonce) {
  const std::vector<std::uint8_t> want = committed_header_preimage();
  // Two headers that differ only in the nonce must share one preimage: this is the
  // whole of C-4's "the nonce is not part of the block's identity input".
  for (const std::uint64_t nonce : {0ULL, 1ULL, 42ULL}) {
    const auto preimage = zk::header_preimage(fixture_header(nonce));
    ZK_CHECK(preimage.size() == 107);
    ZK_CHECK(std::equal(preimage.begin(), preimage.end(), want.begin()));
  }
  ZK_CHECK(zk::header_preimage(fixture_header(0)) == zk::header_preimage(fixture_header(42)));
}

ZK_TEST(nonce_and_engine_byte_enter_the_digest_not_the_field_layout) {
  // The engine byte is inside the 107 bytes, so an id change moves the identity;
  // the nonce is outside them, so it moves only the hash.
  const std::vector<std::uint8_t> want = committed_header_preimage();
  BlockHeader scratchpad_header = fixture_header(0);
  scratchpad_header.engine_id = zk::kEngineIdScratchpad;
  const auto preimage = zk::header_preimage(scratchpad_header);
  ZK_CHECK(!std::equal(preimage.begin(), preimage.end(), want.begin()));
  ZK_CHECK(preimage[106] == zk::kEngineIdScratchpad);
  ZK_CHECK(want[106] == zk::kEngineIdTrivial);

  const Hash256 at_zero = zk::header_pow_hash(fixture_header(0), PowEngine::trivial());
  const Hash256 at_one = zk::header_pow_hash(fixture_header(1), PowEngine::trivial());
  ZK_CHECK(at_zero != at_one);
  expect_internal(at_zero, kTrivialHeader0);
}

ZK_TEST(hash_never_extends_the_callers_buffer) {
  std::vector<std::uint8_t> preimage = committed_preimage();
  const std::vector<std::uint8_t> before = preimage;
  const PowEngine pad = PowEngine::scratchpad(kTinyPowerOfTwo);
  (void)pad.hash(preimage.data(), preimage.size(), 0x0102030405060708ULL);
  (void)PowEngine::trivial().hash(preimage.data(), preimage.size(), 0x0102030405060708ULL);
  // The nonce is appended to a copy. If either engine wrote through, the caller's
  // 107-byte preimage would stop being the identity input it is specified to be.
  ZK_CHECK(preimage == before);
  ZK_CHECK(preimage.size() == 12);
}

// --- TrivialEngine against the committed vectors -----------------------------

ZK_TEST(trivial_engine_matches_the_committed_raw_vectors) {
  // Self-check the literal against the fixture hex before trusting either.
  ZK_CHECK(zk::to_hex(reinterpret_cast<const std::uint8_t*>(kRawPreimage.data()),
                      kRawPreimage.size()) == std::string(kRawPreimageHex));
  const PowEngine engine = PowEngine::trivial();
  expect_internal(hash_raw(engine, 0), kTrivialRaw0);
  expect_internal(hash_raw(engine, 1), kTrivialRaw1);
}

ZK_TEST(trivial_engine_is_the_double_hash_of_the_appended_le64_nonce) {
  // Built by hand from the rule, so the byte order is asserted rather than echoed.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  std::vector<std::uint8_t> input = preimage;
  append_le64(input, 0x0102030405060708ULL);
  ZK_CHECK(input.size() == preimage.size() + 8);
  ZK_CHECK(input[preimage.size()] == 0x08);       // least significant byte first
  ZK_CHECK(input[input.size() - 1] == 0x01);      // most significant byte last
  const Hash256 by_hand = zk::sha256d(input.data(), input.size());
  ZK_CHECK(internal(by_hand) ==
           internal(hash_raw(PowEngine::trivial(), 0x0102030405060708ULL)));
}

ZK_TEST(trivial_engine_matches_the_committed_header_vectors) {
  expect_internal(zk::header_pow_hash(fixture_header(0), PowEngine::trivial()), kTrivialHeader0);
  expect_internal(zk::header_pow_hash(fixture_header(42), PowEngine::trivial()), kTrivialHeader42);
}

// --- ScratchPadEngine against the committed vectors --------------------------

ZK_TEST(scratchpad_engine_matches_the_committed_devnet_vectors) {
  const PowEngine engine = PowEngine::scratchpad(zk::kScratchpadDevnet);
  expect_internal(hash_raw(engine, 0), kScratchDevnet0);
  expect_internal(hash_raw(engine, 1), kScratchDevnet1);
  expect_internal(hash_raw(engine, 42), kScratchDevnet42);
}

ZK_TEST(scratchpad_engine_matches_the_committed_mainnet_vectors) {
  const PowEngine engine = PowEngine::scratchpad(zk::kScratchpadMainnet);
  expect_internal(hash_raw(engine, 0), kScratchMainnet0);
  expect_internal(hash_raw(engine, 1), kScratchMainnet1);
}

ZK_TEST(scratchpad_engine_and_trivial_engine_never_agree) {
  // Same preimage, same nonce, different engine: the digests must differ, or a
  // header could be valid under two algorithms at once.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  for (const std::uint64_t nonce : {0ULL, 1ULL, 42ULL}) {
    const Hash256 trivial = hash_raw(PowEngine::trivial(), nonce);
    const Hash256 pad = hash_raw(PowEngine::scratchpad(zk::kScratchpadDevnet), nonce);
    ZK_CHECK(trivial != pad);
  }
}

// --- cell count, budget arithmetic and bounds --------------------------------

ZK_TEST(cell_count_floors_at_one_cell) {
  // `(memory_bytes / CELL).max(1)` in the reference: a usize division, so the
  // budget is truncated DOWN to whole cells and only the sub-one-cell case is
  // raised by the floor. 33 bytes is therefore ONE cell, not two — asserting 2
  // here would have invented a rounding rule the reference does not have.
  ZK_CHECK(zk::scratchpad_cell_count(0) == 1);
  ZK_CHECK(zk::scratchpad_cell_count(1) == 1);
  ZK_CHECK(zk::scratchpad_cell_count(31) == 1);
  ZK_CHECK(zk::scratchpad_cell_count(32) == 1);
  ZK_CHECK(zk::scratchpad_cell_count(33) == 1);
  ZK_CHECK(zk::scratchpad_cell_count(63) == 1);
  ZK_CHECK(zk::scratchpad_cell_count(64) == 2);
  ZK_CHECK(zk::scratchpad_cell_count(65) == 2);
  ZK_CHECK(zk::scratchpad_cell_count(95) == 2);
  ZK_CHECK(zk::scratchpad_cell_count(96) == 3);
  ZK_CHECK(zk::scratchpad_cell_count(1024) == 32);
  ZK_CHECK(zk::scratchpad_cell_count(zk::kScratchpadDevnet.memory_bytes) == 2048);
  ZK_CHECK(zk::scratchpad_cell_count(zk::kScratchpadMainnet.memory_bytes) == 65536);
  // Any budget below 64 bytes addresses the same single cell, so all of them hash
  // alike. That is the truncation's consequence, not a new rule.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const ScratchPadParams under_one_cell{31, 4};
  const ScratchPadParams exactly_one_cell{32, 4};
  const ScratchPadParams one_cell_plus_a_byte{33, 4};
  ZK_CHECK(zk::scratchpad_cell_count(under_one_cell.memory_bytes) ==
           zk::scratchpad_cell_count(exactly_one_cell.memory_bytes));
  ZK_CHECK(PowEngine::scratchpad(under_one_cell).hash(preimage.data(), preimage.size(), 7) ==
           PowEngine::scratchpad(exactly_one_cell).hash(preimage.data(), preimage.size(), 7));
  ZK_CHECK(PowEngine::scratchpad(one_cell_plus_a_byte).hash(preimage.data(), preimage.size(), 7) ==
           PowEngine::scratchpad(exactly_one_cell).hash(preimage.data(), preimage.size(), 7));
}

ZK_TEST(zero_rounds_and_empty_preimage_are_well_defined) {
  // `rounds = 0` leaves the pad exactly as the fill left it; the fold still covers
  // the state and every cell, so a digest exists and is stable.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const ScratchPadParams no_rounds{1024, 0};
  const PowEngine engine = PowEngine::scratchpad(no_rounds);
  const Hash256 once = engine.hash(preimage.data(), preimage.size(), 3);
  ZK_CHECK(once == engine.hash(preimage.data(), preimage.size(), 3));
  ZK_CHECK(!once.is_zero());
  ZK_CHECK(once != engine.hash(preimage.data(), preimage.size(), 4));

  // The reference's empty `&[u8]`: null is allowed with size 0 and only there.
  ZK_CHECK(PowEngine::trivial().hash(nullptr, 0, 0) ==
           PowEngine::trivial().hash(preimage.data(), 0, 0));
  const ScratchPadParams devnet_like{64, 2};
  ZK_CHECK(PowEngine::scratchpad(devnet_like).hash(nullptr, 0, 0) !=
           PowEngine::scratchpad(devnet_like).hash(nullptr, 0, 1));
  bool threw = false;
  try {
    (void)zk::detail::write_scratchpad_image(nullptr, 0, devnet_like, nullptr, 1, 0);
  } catch (const std::invalid_argument&) {
    threw = true;
  }
  ZK_CHECK(threw);
}

ZK_TEST(image_size_arithmetic_is_checked_before_it_is_used) {
  ZK_CHECK(zk::detail::scratchpad_image_bytes(1) == 64);
  ZK_CHECK(zk::detail::scratchpad_image_bytes(3) == 128);
  ZK_CHECK(zk::detail::scratchpad_image_bytes(2048) == 2049 * 32);
  ZK_CHECK(zk::detail::scratchpad_image_bytes(65536) == 65537 * 32);

  // The overflow band: a cell count near SIZE_MAX / 32 would make
  // `(1 + cells) * 32` wrap to a buffer smaller than the pad, which is the failure
  // that yields a plausible digest over a truncated fold. It must throw instead —
  // and throw before anything is allocated.
  constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
  static_assert(kMax / 32 - 1 + 1 <= kMax / 32, "the boundary cell count still fits");
  bool threw = false;
  try {
    (void)zk::detail::scratchpad_image_bytes(kMax / 32);
  } catch (const std::length_error&) {
    threw = true;
  }
  ZK_CHECK(threw);

  // The same wall, reached through the public API: the engine must not allocate a
  // truncated buffer or return a digest for a budget it cannot size.
  const ScratchPadParams absurd{kMax - 1, 1};
  const std::vector<std::uint8_t> preimage = committed_preimage();
  threw = false;
  try {
    (void)PowEngine::scratchpad(absurd).hash(preimage.data(), preimage.size(), 0);
  } catch (const std::length_error&) {
    threw = true;
  }
  ZK_CHECK(threw);
}

ZK_TEST(the_writer_demands_the_exact_image_size) {
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const std::size_t cells = zk::scratchpad_cell_count(kTinyPowerOfTwo.memory_bytes);
  const std::size_t want = zk::detail::scratchpad_image_bytes(cells);
  ZK_CHECK(want == 33 * 32);

  for (const std::size_t size : {std::size_t{0}, want - 1, want + 1}) {
    std::vector<std::uint8_t> buffer(want + 8, 0xAB);
    bool threw = false;
    try {
      zk::detail::write_scratchpad_image(buffer.data(), size, kTinyPowerOfTwo, preimage.data(),
                                         preimage.size(), 0);
    } catch (const std::invalid_argument&) {
      threw = true;
    }
    // Too small would write past the caller's buffer; too large would leave the
    // tail uninitialised and fold it into the digest. Both must be refused, and
    // refused before a single byte is written.
    ZK_CHECK(threw);
    ZK_CHECK(std::all_of(buffer.begin(), buffer.end(),
                         [](std::uint8_t byte) { return byte == 0xAB; }));
  }

  bool null_out = false;
  try {
    zk::detail::write_scratchpad_image(nullptr, want, kTinyPowerOfTwo, preimage.data(),
                                       preimage.size(), 0);
  } catch (const std::invalid_argument&) {
    null_out = true;
  }
  ZK_CHECK(null_out);
}

// --- the two indexing formulas -----------------------------------------------

ZK_TEST(a_non_power_of_two_pad_indexes_by_remainder) {
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const std::size_t cells = zk::scratchpad_cell_count(kTinyRemainder.memory_bytes);
  ZK_CHECK(cells == 3);

  const std::vector<std::uint8_t> remainder =
      reference_image(preimage, 42, cells, kTinyRemainder.rounds, false);
  const std::vector<std::uint8_t> masked =
      reference_image(preimage, 42, cells, kTinyRemainder.rounds, true);
  // If the two hypotheses agreed for this input the test would prove nothing, so
  // their disagreement is asserted first.
  ZK_CHECK(remainder != masked);

  const std::vector<std::uint8_t> produced = production_image(kTinyRemainder, preimage, 42);
  ZK_CHECK(produced.size() == zk::detail::scratchpad_image_bytes(cells));
  ZK_CHECK(produced == remainder);
  ZK_CHECK(produced != masked);
  ZK_CHECK(zk::detail::scratchpad_finalize(produced.data(), produced.size()) ==
           hash_raw(PowEngine::scratchpad(kTinyRemainder), 42));
}

ZK_TEST(a_power_of_two_pad_gives_the_same_answer_whichever_formula_is_chosen) {
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const std::size_t cells = zk::scratchpad_cell_count(kTinyPowerOfTwo.memory_bytes);
  ZK_CHECK(cells == 32);
  ZK_CHECK((cells & (cells - 1)) == 0);

  // Masking and taking a remainder are the same function on a power-of-two width,
  // which is why the corpus cannot tell them apart — and why the shipped profiles
  // are safe however the branch is written. The engine must agree with both.
  const std::vector<std::uint8_t> remainder =
      reference_image(preimage, 8, cells, kTinyPowerOfTwo.rounds, false);
  const std::vector<std::uint8_t> masked =
      reference_image(preimage, 8, cells, kTinyPowerOfTwo.rounds, true);
  ZK_CHECK(remainder == masked);
  const std::vector<std::uint8_t> produced = production_image(kTinyPowerOfTwo, preimage, 8);
  ZK_CHECK(produced == remainder);
}

// --- the finalization fold (through the internal seam) -----------------------

ZK_TEST(hash_is_exactly_finalize_of_write) {
  // Binds the seam to production: what the corruption tests below mutate is the
  // image `hash()` itself folds, not a parallel implementation of it.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const std::vector<std::uint8_t> image = production_image(kTinyPowerOfTwo, preimage, 5);
  ZK_CHECK(zk::detail::scratchpad_finalize(image.data(), image.size()) ==
           hash_raw(PowEngine::scratchpad(kTinyPowerOfTwo), 5));
  // And the fold is one SHA-256 over the whole image, with no separator, length
  // prefix or padding.
  ZK_CHECK(internal(Hash256(zk::sha256(image.data(), image.size()))) ==
           internal(zk::detail::scratchpad_finalize(image.data(), image.size())));
}

ZK_TEST(finalization_folds_the_prefix_and_every_cell) {
  // The property `PowEngine::hash` cannot show on its own: dropping the reserved
  // prefix, or folding only the first cell, or only the last, would still return a
  // well-formed 32-byte digest. Flipping one byte in each position and requiring the
  // digest to move is what proves each is actually an input to the hash.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const std::size_t cells = zk::scratchpad_cell_count(kTinyPowerOfTwo.memory_bytes);
  const std::vector<std::uint8_t> base = production_image(kTinyPowerOfTwo, preimage, 11);
  const Hash256 base_digest = zk::detail::scratchpad_finalize(base.data(), base.size());

  // The reserved prefix, the first cell, an interior cell, and the last cell.
  for (const std::size_t unit : {std::size_t{0}, std::size_t{1}, std::size_t{cells / 2}, cells}) {
    ZK_CHECK(unit * 32 < base.size());
    std::vector<std::uint8_t> mutated = base;
    mutated[unit * 32] = static_cast<std::uint8_t>(mutated[unit * 32] ^ 0x01);
    const Hash256 moved = zk::detail::scratchpad_finalize(mutated.data(), mutated.size());
    ZK_CHECK(moved != base_digest);
    // Only that one unit changed, so the rest of the image is still the fold the
    // engine itself would produce.
    ZK_CHECK(mutated.size() == base.size());
  }

  // Every byte of the image is covered, not just the first of each unit.
  std::vector<std::uint8_t> last_byte = base;
  last_byte.back() = static_cast<std::uint8_t>(last_byte.back() ^ 0x80);
  ZK_CHECK(zk::detail::scratchpad_finalize(last_byte.data(), last_byte.size()) != base_digest);
  std::vector<std::uint8_t> middle = base;
  middle[base.size() / 2] = static_cast<std::uint8_t>(middle[base.size() / 2] ^ 0x40);
  ZK_CHECK(zk::detail::scratchpad_finalize(middle.data(), middle.size()) != base_digest);
}

ZK_TEST(corrupting_a_consensus_input_changes_the_identity) {
  // The §6 corruption list, at the level a node actually sees: one preimage byte,
  // the nonce, the engine id, and each ScratchPad budget parameter must each move
  // the digest. "Did not crash" is not the assertion; "the answer is different" is.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const PowEngine pad = PowEngine::scratchpad(kTinyPowerOfTwo);
  const Hash256 base = pad.hash(preimage.data(), preimage.size(), 1);

  std::vector<std::uint8_t> bent = preimage;
  bent[4] = static_cast<std::uint8_t>(bent[4] ^ 0x20);
  ZK_CHECK(pad.hash(bent.data(), bent.size(), 1) != base);
  ZK_CHECK(pad.hash(preimage.data(), preimage.size(), 2) != base);
  ZK_CHECK(pad.hash(preimage.data(), preimage.size(), 0xFFFFFFFFFFFFFFFFULL) != base);
  ZK_CHECK(PowEngine::trivial().hash(preimage.data(), preimage.size(), 1) != base);
  ZK_CHECK(PowEngine::scratchpad(ScratchPadParams{1024 + 32, 8})
               .hash(preimage.data(), preimage.size(), 1) != base);
  ZK_CHECK(PowEngine::scratchpad(ScratchPadParams{1024, 9})
               .hash(preimage.data(), preimage.size(), 1) != base);
  // A longer preimage with the same prefix is a different input, not a padded one.
  ZK_CHECK(pad.hash(preimage.data(), preimage.size() - 1, 1) != base);
}

// --- verification semantics --------------------------------------------------

ZK_TEST(verify_pow_reproduces_the_committed_mine_result) {
  // The corpus publishes `pow.trivial.mine_from_zero`: at bits 0x207FFFFF the first
  // solution from zero is nonce 1. Both halves are asserted — the acceptance and
  // the rejection that had to come first — and the rejected digest is the one the
  // fixture publishes, because the reference's error carries it.
  const std::vector<std::uint8_t> preimage = committed_header_preimage();
  const zk::Uint256 target = zk::block_target(0x207FFFFFu);

  const zk::PowVerifyResult low =
      zk::verify_pow(PowEngine::trivial(), preimage.data(), preimage.size(), 0, target);
  ZK_CHECK(!low.ok());
  ZK_CHECK(low.kind == zk::PowErrorKind::kInsufficientWork);
  expect_internal(low.hash, kTrivialHeader0);

  const zk::PowVerifyResult met =
      zk::verify_pow(PowEngine::trivial(), preimage.data(), preimage.size(), 1, target);
  ZK_CHECK(met.ok());
  ZK_CHECK(met.kind == zk::PowErrorKind::kNone);
  ZK_CHECK(zk::hash_meets_target(met.hash, target));

  // Nonce 42 is the other committed header row and its first byte, 0xc7, is above
  // the target's 0x7f, so it must be rejected with its own hash attached.
  const zk::PowVerifyResult high =
      zk::verify_pow(PowEngine::trivial(), preimage.data(), preimage.size(), 42, target);
  ZK_CHECK(!high.ok());
  expect_internal(high.hash, kTrivialHeader42);
}

ZK_TEST(pow_error_names_are_the_reference_variants) {
  ZK_CHECK(std::string(zk::pow_error_kind_name(zk::PowErrorKind::kNone)) == "None");
  ZK_CHECK(std::string(zk::pow_error_kind_name(zk::PowErrorKind::kInsufficientWork)) ==
           "InsufficientWork");
  // `kNone` occupies 0 so a default-constructed result means accepted, and the two
  // variants the reference reserves for the mining loop are not reachable here:
  // `NonceExhausted` and `Aborted` must not have been invented as names.
  ZK_CHECK(static_cast<std::uint8_t>(zk::PowErrorKind::kNone) == 0);
  ZK_CHECK(zk::PowVerifyResult{}.ok());
  ZK_CHECK(zk::PowVerifyResult{}.hash.is_zero());
}

ZK_TEST(header_meets_own_target_reads_the_headers_own_bits) {
  // Both rows are committed facts: at the header's own 0x207FFFFF the corpus's
  // `pow.trivial.mine_from_zero` rejects nonce 0 and returns nonce 1, so these two
  // verdicts come from the fixture and not from the function under test.
  ZK_CHECK(!zk::header_meets_own_target(fixture_header(0), PowEngine::trivial()));
  ZK_CHECK(zk::header_meets_own_target(fixture_header(1), PowEngine::trivial()));

  // The target half, pinned with the digest held FIXED. This cannot be done by
  // editing a header's bits field, because `bits` is one of the fields inside the
  // 107-byte preimage: rewriting it re-hashes the block's identity, and the corpus
  // publishes 0x207FFFFF alone — every other bits value has an unpublished digest
  // whose verdict could only be invented here. So committed digests are kept and
  // only the declaration varies, and each verdict follows from the published hex
  // plus the reference's compact rule: a 23-BIT mantissa, and any bits whose
  // 0x00800000 flag is set decodes to ZERO ("negative", matching Bitcoin's
  // consensus handling) instead of to a looser target. The largest target leading
  // byte therefore reachable by any bits value is 0x7f:
  //   0x207FFFFF -> 0x7fffff then 29 zero bytes. The rejected header digest starts
  //                0xb4, above it; the committed raw nonce-1 digest starts 0x52,
  //                under it — so the same declaration accepts one and rejects the
  //                other, which is the direction of the comparison itself.
  //   0x203FFFFF -> 0x3fffff then 29 zeros, now below 0x52, so that same digest
  //                fails it. One committed value flipping on a declaration change is
  //                what shows the bound is read from the bits and not hard-coded.
  //   0x1D00FFFF -> a 28-byte bound, below any digest with non-zero top bytes.
  //   0x20FFFFFF -> zero, by the sign rule — NOT the loosest target, which is the
  //                trap a 24-bit-mantissa reading of nBits falls into.
  const Hash256 rejected = committed_hash(kTrivialHeader0);
  const Hash256 solution = committed_hash(kTrivialRaw1);
  ZK_CHECK(!zk::hash_meets_target(rejected, zk::block_target(0x207FFFFFu)));
  ZK_CHECK(zk::hash_meets_target(solution, zk::block_target(0x207FFFFFu)));
  ZK_CHECK(!zk::hash_meets_target(solution, zk::block_target(0x203FFFFFu)));
  ZK_CHECK(!zk::hash_meets_target(solution, zk::block_target(0x1D00FFFFu)));
  ZK_CHECK(zk::block_target(0x20FFFFFFu).is_zero());

  // The structural half of "its own": the predicate has no target parameter for a
  // caller to pass the chain's requirement into, and takes exactly the header and
  // the engine it is documented to use.
  static_assert(std::is_same_v<decltype(&zk::header_meets_own_target),
                                bool (*)(const BlockHeader&, const PowEngine&)>,
                "meets-own-target must not be able to receive an injected target");

  // And the engine is not borrowable either: the two engines over the same header
  // give different digests, so a proof can never be evaluated with the wrong
  // algorithm's hash against the right target.
  BlockHeader pad_header = fixture_header(0);
  pad_header.engine_id = zk::kEngineIdScratchpad;
  ZK_CHECK(zk::header_pow_hash(pad_header, PowEngine::scratchpad(zk::kScratchpadDevnet)) !=
           zk::header_pow_hash(pad_header, PowEngine::trivial()));
}

ZK_TEST(scratchpad_digests_are_stable_and_budget_specific) {
  // The engine's memory-hard path must be a function, not a race: two calls over
  // the same input agree, including across two separately constructed engines, and a
  // budget one cell apart differs from the one the corpus pinned.
  const std::vector<std::uint8_t> preimage = committed_preimage();
  const PowEngine a = PowEngine::scratchpad(zk::kScratchpadDevnet);
  const PowEngine b = zk::engine_for_id(1, zk::kScratchpadDevnet).value();
  ZK_CHECK(a.hash(preimage.data(), preimage.size(), 1) == b.hash(preimage.data(), preimage.size(), 1));
  expect_internal(b.hash(preimage.data(), preimage.size(), 1), kScratchDevnet1);

  const PowEngine one_cell_more =
      PowEngine::scratchpad(ScratchPadParams{zk::kScratchpadDevnet.memory_bytes + 32,
                                             zk::kScratchpadDevnet.rounds});
  ZK_CHECK(a.hash(preimage.data(), preimage.size(), 1) !=
           one_cell_more.hash(preimage.data(), preimage.size(), 1));
}
