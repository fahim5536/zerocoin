// Difficulty policy. See difficulty.h for the two compatibility requirements
// (F-6, F-11) and the one deliberate divergence (F-7).

#include "zerocoin/difficulty.h"

#include <utility>

namespace zk {
namespace {

/// The two u64 products the reference performs unguarded. Saturating keeps the
/// port free of any overflow path (CPP_PORT_REQUIREMENTS.md C-12) and is
/// unreachable for the shipped schedule.
std::uint64_t saturating_mul(std::uint64_t lhs, std::uint64_t rhs) noexcept {
  constexpr std::uint64_t kMax = 0xffff'ffff'ffff'ffffull;
  if (lhs != 0 && rhs > kMax / lhs) {
    return kMax;
  }
  return lhs * rhs;
}

/// The reference's `expected.max(1)` / `min_timespan.max(1)`.
std::uint64_t at_least_one(std::uint64_t value) noexcept { return value == 0 ? 1 : value; }

}  // namespace

Uint256 DifficultyParams::pow_limit() const noexcept { return Uint256::from_compact(pow_limit_bits); }

Uint256 compact_to_target(std::uint32_t bits) noexcept { return Uint256::from_compact(bits); }

std::uint32_t compact_from_target(const Uint256& target) noexcept { return target.to_compact(); }

Uint256 block_target(std::uint32_t bits) noexcept { return Uint256::from_compact(bits); }

bool hash_meets_target(const Hash256& pow_hash, const Uint256& target) noexcept {
  // F-11: big-endian byte value, inclusive bound. The digest is already stored
  // in internal order, which is that same big-endian order.
  return Uint256::from_be_bytes(pow_hash.bytes) <= target;
}

std::optional<Uint256> required_work(const Uint256& target) noexcept {
  if (target.is_zero()) {
    return Uint256::zero();
  }
  // F-7: `target + 1` wraps to zero at Uint256::MAX, where the reference divides
  // by zero. required_work is not on the acceptance path, so report the trap
  // instead of reproducing it.
  const Uint256 denominator = target.wrapping_add(Uint256::one());
  if (denominator.is_zero()) {
    return std::nullopt;
  }
  const std::pair<Uint256, Uint256> division = target.bitwise_not().divmod(denominator);
  return division.first.wrapping_add(Uint256::one());
}

RetargetResult next_difficulty_target(std::uint32_t prev_bits,
                                      std::uint64_t actual_window_seconds,
                                      const DifficultyParams& params) noexcept {
  const Uint256 prev_target = compact_to_target(prev_bits);

  const std::uint64_t expected = at_least_one(params.target_window_seconds());
  const std::uint64_t factor =
      params.max_adjustment_factor < 2 ? 2 : params.max_adjustment_factor;
  const std::uint64_t min_timespan = at_least_one(expected / factor);
  const std::uint64_t max_timespan = saturating_mul(expected, factor);

  // clamp(actual, min_timespan, max_timespan). The reference's clamp panics if
  // min > max; applying the lower bound first makes the order total, which
  // cannot happen for the shipped schedule.
  std::uint64_t actual = actual_window_seconds;
  if (actual < min_timespan) {
    actual = min_timespan;
  }
  if (actual > max_timespan) {
    actual = max_timespan;
  }

  // F-6: the magnitude of the previous target selects the arithmetic order.
  Uint256 new_target{};
  if (prev_target.leading_zeros() >= 20) {
    new_target = prev_target.mul_u64(actual).div_u64(expected);
  } else {
    new_target = prev_target.div_u64(expected).mul_u64(actual);
  }

  const Uint256 pow_limit = params.pow_limit();
  const Uint256 capped =
      (new_target > pow_limit || new_target.is_zero()) ? pow_limit : new_target;
  return RetargetResult{capped, compact_from_target(capped)};
}

std::uint32_t next_difficulty(std::uint32_t prev_bits,
                              std::uint64_t actual_window_seconds,
                              const DifficultyParams& params) noexcept {
  return next_difficulty_target(prev_bits, actual_window_seconds, params).bits;
}

DifficultyError validate_bits(std::uint32_t bits, const DifficultyParams& params) noexcept {
  const Uint256 target = compact_to_target(bits);
  // C-27: zero is reported first. A target can only be above the limit if it is
  // non-zero, so the order is invisible except for the sign-bit case, where
  // reversing it would accept a zero target outright.
  if (target.is_zero()) {
    return DifficultyError{DifficultyErrorKind::kZeroTarget, bits, 0};
  }
  if (target > params.pow_limit()) {
    return DifficultyError{DifficultyErrorKind::kTargetAbovePowLimit, bits, params.pow_limit_bits};
  }
  return DifficultyError{};
}

const char* difficulty_error_kind_name(DifficultyErrorKind kind) noexcept {
  switch (kind) {
    case DifficultyErrorKind::kNone:
      return "None";
    case DifficultyErrorKind::kTargetAbovePowLimit:
      return "TargetAbovePowLimit";
    case DifficultyErrorKind::kUnexpectedBits:
      return "UnexpectedBits";
    case DifficultyErrorKind::kZeroTarget:
      return "ZeroTarget";
  }
  return "Unknown";
}

}  // namespace zk
