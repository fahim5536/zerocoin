// Difficulty policy tests. The corpus in test/vectors/difficulty/retarget.json
// is the value oracle (kernel/tools/p3_conformance.py replays it); these tests
// pin the behaviour the corpus cannot express: the F-6 branch, the clamp edges,
// the inclusive big-endian comparison (F-11) and the F-7 guard.

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "test_framework.h"
#include "zerocoin/difficulty.h"
#include "zerocoin/hex.h"

namespace {

using zk::DifficultyErrorKind;
using zk::Hash256;
using zk::Uint256;

Uint256 target_of_hex(const std::string& hex) {
  const std::optional<std::vector<std::uint8_t>> bytes = zk::from_hex(hex);
  ZK_CHECK(bytes.has_value());
  ZK_CHECK(bytes->size() == Uint256::kBytes);
  std::array<std::uint8_t, Uint256::kBytes> raw{};
  std::copy(bytes->begin(), bytes->end(), raw.begin());
  return Uint256::from_be_bytes(raw);
}

// A 5 s window, at most 2x per retarget, regtest's pow limit. Small enough that
// the F-6 threshold can be crossed on both sides without either cap binding.
constexpr zk::DifficultyParams kProbeParams{1, 5, 2, 0x207f'ffffu};

}  // namespace

ZK_TEST(difficulty_params_match_the_schedule) {
  ZK_CHECK(zk::kDifficultyParams.target_spacing_seconds == 60u);
  ZK_CHECK(zk::kDifficultyParams.retarget_interval == 1'440u);
  ZK_CHECK(zk::kDifficultyParams.max_adjustment_factor == 4u);
  ZK_CHECK(zk::kDifficultyParams.pow_limit_bits == 503'382'015u);
  ZK_CHECK(zk::kDifficultyParams.target_window_seconds() == 86'400u);
  ZK_CHECK(zk::kDifficultyParams.pow_limit() ==
           target_of_hex("000000ffff000000000000000000000000000000000000000000000000000000"));
  // The decoded limit is exactly the compact encoding's own round trip.
  ZK_CHECK(zk::kDifficultyParams.pow_limit().to_compact() == 503'382'015u);
}

ZK_TEST(difficulty_block_target_is_compact_to_target) {
  const std::uint32_t samples[] = {0u,       0x0100'3456u, 0x1c00'ffffu, 0x1d00'ffffu,
                                   0x1e00'ffffu, 0x207f'ffffu, 0x2100'ffffu, 0x1d80'0000u};
  for (const std::uint32_t bits : samples) {
    ZK_CHECK(zk::block_target(bits) == zk::compact_to_target(bits));
    ZK_CHECK(zk::compact_from_target(zk::block_target(bits)) ==
             zk::block_target(bits).to_compact());
  }
}

ZK_TEST(difficulty_hash_meets_target_is_inclusive) {
  const Uint256 target = zk::block_target(486'604'799u);  // 0x1d00ffff
  ZK_CHECK(target.to_compact() == 486'604'799u);
  ZK_CHECK(zk::hash_meets_target(Hash256::zero(), target));
  // F-11: a digest exactly equal to the target is accepted.
  ZK_CHECK(zk::hash_meets_target(Hash256(target.to_be_bytes()), target));
  ZK_CHECK(!zk::hash_meets_target(
      Hash256(target.wrapping_add(Uint256::one()).to_be_bytes()), target));

  std::array<std::uint8_t, Hash256::kWidth> all_ones{};
  all_ones.fill(0xff);
  ZK_CHECK(!zk::hash_meets_target(Hash256(all_ones), target));
}

ZK_TEST(difficulty_hash_meets_target_reads_the_digest_big_endian) {
  // 0xff00...00 is 0xff * 2^248, far above any target. Read in Bitcoin's
  // reversed display order it would be 0xff and pass, so this pins F-11's
  // direction rather than just its bound.
  std::array<std::uint8_t, Hash256::kWidth> raw{};
  raw[0] = 0xff;
  ZK_CHECK(!zk::hash_meets_target(Hash256(raw), zk::block_target(486'604'799u)));
}

ZK_TEST(difficulty_required_work_matches_difficulty_one) {
  const std::optional<Uint256> work = zk::required_work(zk::block_target(486'604'799u));
  ZK_CHECK(work.has_value());
  ZK_CHECK(*work == Uint256::from_u64(4'295'032'833ull));  // 0x0000000100010001

  const std::optional<Uint256> floor_work = zk::required_work(zk::block_target(503'382'015u));
  ZK_CHECK(floor_work.has_value());
  ZK_CHECK(*floor_work == Uint256::from_u64(16'777'472ull));  // 0x0000000001000100

  const std::optional<Uint256> trivial_work = zk::required_work(zk::block_target(545'259'519u));
  ZK_CHECK(trivial_work.has_value());
  ZK_CHECK(*trivial_work == Uint256::from_u64(2));
}

ZK_TEST(difficulty_required_work_handles_the_endpoints) {
  const std::optional<Uint256> zero = zk::required_work(Uint256::zero());
  ZK_CHECK(zero.has_value());
  ZK_CHECK(zero->is_zero());

  // (~1) / (1 + 1) + 1 == 2^255.
  const std::optional<Uint256> one = zk::required_work(Uint256::one());
  ZK_CHECK(one.has_value());
  ZK_CHECK(*one == Uint256::one().shl_bits(255));

  // F-7: `target + 1` wraps to zero here, so the reference divides by zero.
  // required_work is off the acceptance path and reports the trap instead.
  ZK_CHECK(!zk::required_work(Uint256::max()).has_value());
}

ZK_TEST(difficulty_retarget_multiplies_first_below_the_f6_threshold) {
  const Uint256 prev = Uint256::one().shl_bits(57);  // 2^57, leading_zeros() == 198
  ZK_CHECK(prev.leading_zeros() >= 20);
  const Uint256 multiply_first = prev.mul_u64(3).div_u64(5);
  const Uint256 divide_first = prev.div_u64(5).mul_u64(3);
  // If the two orders agreed this test would prove nothing.
  ZK_CHECK(multiply_first != divide_first);
  ZK_CHECK(divide_first.wrapping_add(Uint256::one()) == multiply_first);

  // 0x0a000002: exponent 10, mantissa 2, so the target is 2 * 256^7 == 2^57.
  const zk::RetargetResult result = zk::next_difficulty_target(0x0a00'0002u, 3, kProbeParams);
  ZK_CHECK(result.target == multiply_first);
  ZK_CHECK(result.target == Uint256::from_u64(86'469'112'845'513'523ull));
  ZK_CHECK(result.bits == zk::compact_from_target(result.target));
}

ZK_TEST(difficulty_retarget_divides_first_above_the_f6_threshold) {
  const Uint256 prev = Uint256::one().shl_bits(237);  // 2^237, leading_zeros() == 18
  ZK_CHECK(prev.leading_zeros() < 20);
  const Uint256 multiply_first = prev.mul_u64(3).div_u64(5);
  const Uint256 divide_first = prev.div_u64(5).mul_u64(3);
  ZK_CHECK(multiply_first != divide_first);

  // 0x1e200000: exponent 30, mantissa 0x200000 == 2^21, so the target is 2^237.
  const zk::RetargetResult result = zk::next_difficulty_target(0x1e20'0000u, 3, kProbeParams);
  ZK_CHECK(result.target == divide_first);
  ZK_CHECK(result.target != multiply_first);
}

ZK_TEST(difficulty_retarget_caps_before_the_order_can_matter) {
  // Under the shipped schedule a previous target with fewer than 20 leading
  // zeros already exceeds 0x1e00ffff, so the cap decides the answer whatever
  // order ran. The branch still has to exist: next_difficulty_target takes its
  // parameters, and a higher pow limit makes it observable.
  const zk::RetargetResult result =
      zk::next_difficulty_target(0x1e20'0000u, 86'400, zk::kDifficultyParams);
  ZK_CHECK(result.target == zk::kDifficultyParams.pow_limit());
  ZK_CHECK(result.bits == 503'382'015u);
}

ZK_TEST(difficulty_retarget_clamps_the_window) {
  struct Sample {
    std::uint64_t window;
    std::uint32_t bits;
    const char* target_hex;
  };
  const Sample samples[] = {
      {86'400, 469'827'583u,
       "0000000000ffff00000000000000000000000000000000000000000000000000"},
      {43'200, 461'373'312u,
       "00000000007fff80000000000000000000000000000000000000000000000000"},
      {1, 457'179'072u,
       "00000000003fffc0000000000000000000000000000000000000000000000000"},
      {21'600, 457'179'072u,
       "00000000003fffc0000000000000000000000000000000000000000000000000"},
      {172'800, 469'893'118u,
       "0000000001fffe00000000000000000000000000000000000000000000000000"},
      {345'600, 470'024'188u,
       "0000000003fffc00000000000000000000000000000000000000000000000000"},
      {0xffff'ffff'ffff'ffffull, 470'024'188u,
       "0000000003fffc00000000000000000000000000000000000000000000000000"},
  };
  for (const Sample& sample : samples) {
    const zk::RetargetResult result =
        zk::next_difficulty_target(469'827'583u, sample.window, zk::kDifficultyParams);
    ZK_CHECK(result.bits == sample.bits);
    // The published target is the capped value, not the re-decoded encoding.
    ZK_CHECK(result.target == target_of_hex(sample.target_hex));
    ZK_CHECK(result.target.to_compact() == sample.bits);
    ZK_CHECK(zk::next_difficulty(469'827'583u, sample.window, zk::kDifficultyParams) ==
             sample.bits);
  }
}

ZK_TEST(difficulty_retarget_clamp_boundaries_are_inclusive) {
  // 21,600 s is exactly expected/4 and 345,600 s exactly expected*4, so one
  // second outside either bound must land on the bound's own answer.
  ZK_CHECK(zk::next_difficulty(469'827'583u, 21'600, zk::kDifficultyParams) ==
           zk::next_difficulty(469'827'583u, 21'599, zk::kDifficultyParams));
  ZK_CHECK(zk::next_difficulty(469'827'583u, 345'600, zk::kDifficultyParams) ==
           zk::next_difficulty(469'827'583u, 345'601, zk::kDifficultyParams));
  // ... and the clamp is a clamp, not a constant: inside the range the answer moves.
  ZK_CHECK(zk::next_difficulty(469'827'583u, 172'800, zk::kDifficultyParams) !=
           zk::next_difficulty(469'827'583u, 345'600, zk::kDifficultyParams));
}

ZK_TEST(difficulty_retarget_never_eases_past_the_pow_limit) {
  const zk::RetargetResult floor_result =
      zk::next_difficulty_target(503'382'015u, 0xffff'ffff'ffff'ffffull, zk::kDifficultyParams);
  ZK_CHECK(floor_result.target == zk::kDifficultyParams.pow_limit());
  ZK_CHECK(floor_result.bits == 503'382'015u);

  // A zero previous target is re-earned at the floor rather than left at zero.
  const zk::RetargetResult zero_result =
      zk::next_difficulty_target(0u, 86'400, zk::kDifficultyParams);
  ZK_CHECK(zero_result.target == zk::kDifficultyParams.pow_limit());
  ZK_CHECK(zero_result.bits == 503'382'015u);
}

ZK_TEST(difficulty_validate_bits_reports_zero_target_before_the_limit) {
  const zk::DifficultyError zero = zk::validate_bits(0u, zk::kDifficultyParams);
  ZK_CHECK(!zero.ok());
  ZK_CHECK(zero.kind == DifficultyErrorKind::kZeroTarget);
  ZK_CHECK(zero.found == 0u);

  // A set sign bit decodes to a zero target. Were the pow-limit test first, a
  // zero target would be below every limit and accepted outright.
  const zk::DifficultyError sign_bit = zk::validate_bits(0x1d80'0000u, zk::kDifficultyParams);
  ZK_CHECK(!sign_bit.ok());
  ZK_CHECK(sign_bit.kind == DifficultyErrorKind::kZeroTarget);
  ZK_CHECK(sign_bit.found == 0x1d80'0000u);
}

ZK_TEST(difficulty_validate_bits_rejects_targets_above_the_pow_limit) {
  const zk::DifficultyError above = zk::validate_bits(553'713'663u, zk::kDifficultyParams);
  ZK_CHECK(!above.ok());
  ZK_CHECK(above.kind == DifficultyErrorKind::kTargetAbovePowLimit);
  ZK_CHECK(above.found == 553'713'663u);
  ZK_CHECK(above.limit == 503'382'015u);
}

ZK_TEST(difficulty_validate_bits_accepts_the_floor_and_difficulty_one) {
  ZK_CHECK(zk::validate_bits(503'382'015u, zk::kDifficultyParams).ok());  // 0x1e00ffff
  ZK_CHECK(zk::validate_bits(486'604'799u, zk::kDifficultyParams).ok());  // 0x1d00ffff
  // 0x207fffff is regtest's genesis bits; under the shared 0x1e00ffff floor it
  // is easier than the limit allows and must be rejected.
  const zk::DifficultyError regtest =
      zk::validate_bits(545'259'519u, zk::kDifficultyParams);
  ZK_CHECK(regtest.kind == DifficultyErrorKind::kTargetAbovePowLimit);
  ZK_CHECK(regtest.found == 545'259'519u);
}

ZK_TEST(difficulty_error_kind_names_are_stable) {
  ZK_CHECK(std::string(zk::difficulty_error_kind_name(DifficultyErrorKind::kNone)) == "None");
  ZK_CHECK(std::string(zk::difficulty_error_kind_name(DifficultyErrorKind::kTargetAbovePowLimit)) ==
           "TargetAbovePowLimit");
  ZK_CHECK(std::string(zk::difficulty_error_kind_name(DifficultyErrorKind::kZeroTarget)) ==
           "ZeroTarget");
  ZK_CHECK(std::string(zk::difficulty_error_kind_name(DifficultyErrorKind::kUnexpectedBits)) ==
           "UnexpectedBits");
}
