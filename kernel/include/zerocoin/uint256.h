// A 256-bit unsigned integer, mirroring zerocoin/src/consensus/uint256.rs.
//
// Storage is four little-endian 64-bit limbs, `limbs[0]` least significant, so
// every operation follows the same order of operations as the Rust reference.
// Byte conversion is done byte by byte and is independent of host endianness.

#ifndef ZEROCOIN_KERNEL_UINT256_H
#define ZEROCOIN_KERNEL_UINT256_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace zk {

class Uint256 {
 public:
  static constexpr std::size_t kLimbs = 4;
  static constexpr std::size_t kBits = 256;
  static constexpr std::size_t kBytes = 32;
  static constexpr unsigned kLimbBits = 64;

  std::array<std::uint64_t, kLimbs> limbs{};

  constexpr Uint256() noexcept = default;
  explicit constexpr Uint256(const std::array<std::uint64_t, kLimbs>& raw) noexcept
      : limbs(raw) {}

  static constexpr Uint256 zero() noexcept { return Uint256{}; }
  static constexpr Uint256 one() noexcept {
    return Uint256(std::array<std::uint64_t, kLimbs>{1, 0, 0, 0});
  }
  static constexpr Uint256 max() noexcept {
    return Uint256(std::array<std::uint64_t, kLimbs>{~std::uint64_t{0}, ~std::uint64_t{0},
                                                     ~std::uint64_t{0}, ~std::uint64_t{0}});
  }
  static constexpr Uint256 from_u64(std::uint64_t value) noexcept {
    return Uint256(std::array<std::uint64_t, kLimbs>{value, 0, 0, 0});
  }

  /// Big-endian bytes: `bytes[0]` is the most significant.
  static Uint256 from_be_bytes(const std::array<std::uint8_t, kBytes>& bytes) noexcept;
  std::array<std::uint8_t, kBytes> to_be_bytes() const noexcept;

  constexpr bool is_zero() const noexcept {
    return (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0;
  }

  /// Bitcoin's compact "nBits" encoding. A set sign bit (0x00800000) means zero.
  static Uint256 from_compact(std::uint32_t bits) noexcept;
  std::uint32_t to_compact() const noexcept;

  Uint256 wrapping_add(const Uint256& rhs) const noexcept;
  Uint256 wrapping_sub(const Uint256& rhs) const noexcept;
  Uint256 mul_u64(std::uint64_t rhs) const noexcept;

  /// Requires `rhs != 0`; the precondition is checked with an assert.
  Uint256 div_u64(std::uint64_t rhs) const;

  /// Requires `!divisor.is_zero()`; the precondition is checked with an assert.
  std::pair<Uint256, Uint256> divmod(const Uint256& divisor) const;

  constexpr bool bit(std::size_t index) const noexcept {
    if (index >= kBits) {
      return false;
    }
    return ((limbs[index / kLimbBits] >> (index % kLimbBits)) & std::uint64_t{1}) != 0;
  }

  constexpr void set_bit(std::size_t index) noexcept {
    if (index >= kBits) {
      return;
    }
    limbs[index / kLimbBits] |= std::uint64_t{1} << (index % kLimbBits);
  }

  Uint256 shl_one() const noexcept { return shl_bits(1); }
  Uint256 shl_bits(unsigned count) const noexcept;
  Uint256 shr_one() const noexcept { return shr_bits(1); }
  Uint256 shr_bits(unsigned count) const noexcept;

  Uint256 bitwise_not() const noexcept;
  unsigned leading_zeros() const noexcept;

  /// `0x` followed by 64 lowercase hex characters, most significant first.
  std::string to_string() const;

  friend constexpr bool operator==(const Uint256& lhs, const Uint256& rhs) noexcept {
    return lhs.limbs == rhs.limbs;
  }
  friend constexpr bool operator!=(const Uint256& lhs, const Uint256& rhs) noexcept {
    return !(lhs == rhs);
  }
  friend constexpr bool operator<(const Uint256& lhs, const Uint256& rhs) noexcept {
    for (std::size_t i = kLimbs; i-- > 0;) {
      if (lhs.limbs[i] != rhs.limbs[i]) {
        return lhs.limbs[i] < rhs.limbs[i];
      }
    }
    return false;
  }
  friend constexpr bool operator>(const Uint256& lhs, const Uint256& rhs) noexcept {
    return rhs < lhs;
  }
  friend constexpr bool operator<=(const Uint256& lhs, const Uint256& rhs) noexcept {
    return !(rhs < lhs);
  }
  friend constexpr bool operator>=(const Uint256& lhs, const Uint256& rhs) noexcept {
    return !(lhs < rhs);
  }
};

static_assert(Uint256::kLimbs * Uint256::kLimbBits == Uint256::kBits,
              "four 64-bit limbs make 256 bits");
static_assert(Uint256::kBits / 8 == Uint256::kBytes, "256 bits is 32 bytes");
static_assert(sizeof(Uint256) == 32, "Uint256 is exactly its four limbs");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_UINT256_H
