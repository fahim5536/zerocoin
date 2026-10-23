// Difficulty policy, mirroring zerocoin/src/consensus/difficulty.rs.
//
// Two behaviours in here are compatibility requirements rather than bugs to
// clean up:
//
//   F-6  next_difficulty_target chooses its multiplication/division order from
//        the magnitude of the previous target (`leading_zeros() >= 20` means
//        multiply first). When the remainder crosses the divisor the two orders
//        differ by whole units, so the threshold and the order inside each arm
//        are part of the rule.
//   F-11 hash_meets_target compares the digest as a big-endian integer and the
//        bound is inclusive. Bitcoin's reversed display order is a rendering
//        concern only; comparing in that order here would reject valid blocks.
//
// F-7 is the one place the port must not follow the reference: Rust's
// required_work divides by `target + 1`, which wraps to zero at Uint256::MAX and
// panics. required_work is not on the block-acceptance path
// (CPP_PORT_REQUIREMENTS.md §10), so the port returns std::nullopt there.

#ifndef ZEROCOIN_KERNEL_DIFFICULTY_H
#define ZEROCOIN_KERNEL_DIFFICULTY_H

#include <cstdint>
#include <optional>

#include "zerocoin/hash.h"
#include "zerocoin/uint256.h"

namespace zk {

/// The retarget schedule. All three networks share one schedule; only the
/// genesis bits and the genesis hash differ per network (CONSENSUS_RULES.md
/// §1, §5.1).
struct DifficultyParams {
  std::uint64_t target_spacing_seconds;
  std::uint64_t retarget_interval;
  std::uint64_t max_adjustment_factor;
  std::uint32_t pow_limit_bits;

  /// retarget_interval * target_spacing_seconds, saturating instead of wrapping.
  /// The reference multiplies unguarded, which traps in a debug build; no
  /// shipped parameter set comes close to the bound.
  constexpr std::uint64_t target_window_seconds() const noexcept {
    constexpr std::uint64_t kMax = 0xffff'ffff'ffff'ffffull;
    if (retarget_interval != 0 && target_spacing_seconds > kMax / retarget_interval) {
      return kMax;
    }
    return retarget_interval * target_spacing_seconds;
  }

  /// The pow limit decoded from its compact form.
  Uint256 pow_limit() const noexcept;
};

/// 1,440 blocks x 60 s = 86,400 s, at most 4x per retarget, floor 0x1e00ffff.
inline constexpr DifficultyParams kDifficultyParams{60, 1'440, 4, 0x1e00'ffffu};

/// The reference error taxonomy (CPP_PORT_REQUIREMENTS.md C-14).
/// kUnexpectedBits is declared but never constructed, exactly as in the
/// reference (F-10).
enum class DifficultyErrorKind : std::uint8_t {
  kNone = 0,
  kTargetAbovePowLimit = 1,
  kUnexpectedBits = 2,
  kZeroTarget = 3,
};

struct DifficultyError {
  DifficultyErrorKind kind = DifficultyErrorKind::kNone;
  /// The bits value that was rejected.
  std::uint32_t found = 0;
  /// pow_limit_bits; set for kTargetAbovePowLimit only.
  std::uint32_t limit = 0;

  constexpr bool ok() const noexcept { return kind == DifficultyErrorKind::kNone; }
};

/// The stable name the conformance fixture asserts against.
const char* difficulty_error_kind_name(DifficultyErrorKind kind) noexcept;

/// Compact nBits -> target.
Uint256 compact_to_target(std::uint32_t bits) noexcept;

/// Target -> compact nBits, rounding the mantissa down so the encoded target is
/// never larger than the true one.
std::uint32_t compact_from_target(const Uint256& target) noexcept;

/// The target a block header's own bits field denotes.
Uint256 block_target(std::uint32_t bits) noexcept;

/// Inclusive, big-endian comparison of a proof-of-work digest against a target.
bool hash_meets_target(const Hash256& pow_hash, const Uint256& target) noexcept;

/// `(~target) / (target + 1) + 1`: the work a target represents. std::nullopt
/// only for Uint256::MAX, where the reference divides by zero (F-7).
std::optional<Uint256> required_work(const Uint256& target) noexcept;

/// The retarget result: the capped target and its compact encoding. The target
/// is retained because `next_target_be_hex` is a published vector and
/// re-decoding the compact form would fold a rounding step into the answer.
struct RetargetResult {
  Uint256 target{};
  std::uint32_t bits = 0;
};

RetargetResult next_difficulty_target(std::uint32_t prev_bits,
                                      std::uint64_t actual_window_seconds,
                                      const DifficultyParams& params) noexcept;

/// The same computation, compact encoding only: the reference signature.
std::uint32_t next_difficulty(std::uint32_t prev_bits,
                              std::uint64_t actual_window_seconds,
                              const DifficultyParams& params) noexcept;

/// Rejects a zero target before a target above the pow limit, so the reported
/// kind is the reference's (CPP_PORT_REQUIREMENTS.md C-27).
DifficultyError validate_bits(std::uint32_t bits, const DifficultyParams& params) noexcept;

static_assert(kDifficultyParams.target_window_seconds() == 86'400,
              "the shipped retarget window is 24 hours");
static_assert(kDifficultyParams.pow_limit_bits == 0x1e00'ffffu,
              "the shipped pow limit is 0x1e00ffff");
static_assert(kDifficultyParams.max_adjustment_factor >= 2,
              "the adjustment factor is clamped to >= 2");
static_assert(DifficultyParams{1, 0xffff'ffff'ffff'ffffull, 2, 0}
                      .target_window_seconds() == 0xffff'ffff'ffff'ffffull,
              "the window product saturates rather than wrapping");
static_assert(Hash256::kWidth == Uint256::kBytes, "a digest and a target are the same width");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_DIFFICULTY_H
