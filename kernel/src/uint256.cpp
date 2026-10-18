#include "zerocoin/uint256.h"

#include <bit>
#include <cstdio>
#include <cstdlib>

#include "zerocoin/hex.h"

namespace zk {
namespace {

struct Wide {
  std::uint64_t hi;
  std::uint64_t lo;
};

/// Exact 64x64 -> 128 bit product without compiler intrinsics, so the kernel
/// builds the same way on every toolchain in the matrix.
Wide mul_64x64(std::uint64_t lhs, std::uint64_t rhs) noexcept {
  const std::uint64_t lhs_lo = lhs & 0xffff'ffffu;
  const std::uint64_t lhs_hi = lhs >> 32;
  const std::uint64_t rhs_lo = rhs & 0xffff'ffffu;
  const std::uint64_t rhs_hi = rhs >> 32;

  const std::uint64_t p0 = lhs_lo * rhs_lo;
  const std::uint64_t p1 = lhs_lo * rhs_hi;
  const std::uint64_t p2 = lhs_hi * rhs_lo;
  const std::uint64_t p3 = lhs_hi * rhs_hi;

  const std::uint64_t middle = (p0 >> 32) + (p1 & 0xffff'ffffu) + (p2 & 0xffff'ffffu);

  Wide product;
  product.lo = (middle << 32) | (p0 & 0xffff'ffffu);
  product.hi = p3 + (p1 >> 32) + (p2 >> 32) + (middle >> 32);
  return product;
}

[[noreturn]] void division_by_zero(const char* function) noexcept {
  std::fprintf(stderr, "zk::Uint256::%s: division by zero\n", function);
  std::abort();
}

}  // namespace

Uint256 Uint256::from_be_bytes(const std::array<std::uint8_t, kBytes>& bytes) noexcept {
  Uint256 out{};
  for (std::size_t limb = 0; limb < kLimbs; ++limb) {
    // limbs[3] holds bytes[0..8]: the most significant eight bytes.
    const std::size_t base = (kLimbs - 1 - limb) * 8;
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      value = (value << 8) | bytes[base + i];
    }
    out.limbs[limb] = value;
  }
  return out;
}

std::array<std::uint8_t, Uint256::kBytes> Uint256::to_be_bytes() const noexcept {
  std::array<std::uint8_t, kBytes> bytes{};
  for (std::size_t limb = 0; limb < kLimbs; ++limb) {
    const std::size_t base = (kLimbs - 1 - limb) * 8;
    const std::uint64_t value = limbs[limb];
    for (std::size_t i = 0; i < 8; ++i) {
      bytes[base + 7 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
  }
  return bytes;
}

Uint256 Uint256::from_compact(std::uint32_t bits) noexcept {
  const std::uint32_t exponent = bits >> 24;
  const std::uint32_t mantissa = bits & 0x007f'ffffu;
  if ((bits & 0x0080'0000u) != 0) {
    return Uint256::zero();
  }
  Uint256 result = Uint256::from_u64(mantissa);
  if (exponent <= 3) {
    result = result.shr_bits(8 * (3 - exponent));
  } else {
    result = result.shl_bits(8 * (exponent - 3));
  }
  return result;
}

std::uint32_t Uint256::to_compact() const noexcept {
  if (is_zero()) {
    return 0;
  }
  const unsigned bit_length = static_cast<unsigned>(kBits - leading_zeros());
  const std::uint32_t size = (bit_length + 7) / 8;
  const Uint256 shifted = (size <= 3) ? shl_bits(8 * (3 - size)) : shr_bits(8 * (size - 3));

  std::uint32_t mantissa = static_cast<std::uint32_t>(shifted.limbs[0] & 0x00ff'ffffu);
  std::uint32_t exponent = size;
  if ((mantissa & 0x0080'0000u) != 0) {
    mantissa >>= 8;
    exponent += 1;
  }
  return (exponent << 24) | (mantissa & 0x007f'ffffu);
}

Uint256 Uint256::wrapping_add(const Uint256& rhs) const noexcept {
  Uint256 out{};
  std::uint64_t carry = 0;
  for (std::size_t i = 0; i < kLimbs; ++i) {
    const std::uint64_t sum = limbs[i] + rhs.limbs[i];
    const std::uint64_t carry_from_sum = (sum < limbs[i]) ? 1u : 0u;
    const std::uint64_t total = sum + carry;
    const std::uint64_t carry_from_total = (total < sum) ? 1u : 0u;
    out.limbs[i] = total;
    carry = carry_from_sum | carry_from_total;
  }
  return out;
}

Uint256 Uint256::wrapping_sub(const Uint256& rhs) const noexcept {
  Uint256 out{};
  std::uint64_t borrow = 0;
  for (std::size_t i = 0; i < kLimbs; ++i) {
    const std::uint64_t difference = limbs[i] - rhs.limbs[i];
    const std::uint64_t borrow_from_difference = (limbs[i] < rhs.limbs[i]) ? 1u : 0u;
    const std::uint64_t total = difference - borrow;
    const std::uint64_t borrow_from_total = (difference < borrow) ? 1u : 0u;
    out.limbs[i] = total;
    borrow = borrow_from_difference | borrow_from_total;
  }
  return out;
}

Uint256 Uint256::mul_u64(std::uint64_t rhs) const noexcept {
  Uint256 out{};
  std::uint64_t carry = 0;
  for (std::size_t i = 0; i < kLimbs; ++i) {
    const Wide product = mul_64x64(limbs[i], rhs);
    std::uint64_t low = product.lo + carry;
    const std::uint64_t carry_out = product.hi + ((low < product.lo) ? 1u : 0u);
    out.limbs[i] = low;
    carry = carry_out;
  }
  return out;
}

Uint256 Uint256::div_u64(std::uint64_t rhs) const {
  if (rhs == 0) {
    division_by_zero("div_u64");
  }
  return divmod(Uint256::from_u64(rhs)).first;
}

std::pair<Uint256, Uint256> Uint256::divmod(const Uint256& divisor) const {
  if (divisor.is_zero()) {
    division_by_zero("divmod");
  }
  Uint256 quotient{};
  Uint256 remainder{};
  for (std::size_t index = kBits; index-- > 0;) {
    // The remainder can need 257 bits for one step; `carry` holds that bit. When
    // it is set the true remainder is at least 2^256 and therefore larger than
    // any non-zero divisor, so the subtract is unconditional and its low 256
    // bits are the exact result.
    const bool carry = remainder.bit(kBits - 1);
    remainder = remainder.shl_one();
    if (bit(index)) {
      remainder.set_bit(0);
    }
    if (carry || remainder >= divisor) {
      remainder = remainder.wrapping_sub(divisor);
      quotient.set_bit(index);
    }
  }
  return {quotient, remainder};
}

Uint256 Uint256::shl_bits(unsigned count) const noexcept {
  if (count >= kBits) {
    return Uint256::zero();
  }
  Uint256 out{};
  const std::size_t limb_shift = count / kLimbBits;
  const unsigned bit_shift = count % kLimbBits;
  for (std::size_t i = kLimbs; i-- > 0;) {
    if (i < limb_shift) {
      break;
    }
    out.limbs[i] = limbs[i - limb_shift] << bit_shift;
    if (bit_shift != 0 && i > limb_shift) {
      out.limbs[i] |= limbs[i - limb_shift - 1] >> (kLimbBits - bit_shift);
    }
  }
  return out;
}

Uint256 Uint256::shr_bits(unsigned count) const noexcept {
  if (count >= kBits) {
    return Uint256::zero();
  }
  Uint256 out{};
  const std::size_t limb_shift = count / kLimbBits;
  const unsigned bit_shift = count % kLimbBits;
  for (std::size_t i = 0; i < kLimbs; ++i) {
    const std::size_t source = i + limb_shift;
    if (source >= kLimbs) {
      break;
    }
    out.limbs[i] = limbs[source] >> bit_shift;
    if (bit_shift != 0 && source + 1 < kLimbs) {
      out.limbs[i] |= limbs[source + 1] << (kLimbBits - bit_shift);
    }
  }
  return out;
}

Uint256 Uint256::bitwise_not() const noexcept {
  Uint256 out{};
  for (std::size_t i = 0; i < kLimbs; ++i) {
    out.limbs[i] = ~limbs[i];
  }
  return out;
}

unsigned Uint256::leading_zeros() const noexcept {
  for (std::size_t i = kLimbs; i-- > 0;) {
    const std::uint64_t limb = limbs[i];
    if (limb != 0) {
      const unsigned zero_limbs = static_cast<unsigned>((kLimbs - 1 - i) * kLimbBits);
      return zero_limbs + static_cast<unsigned>(std::countl_zero(limb));
    }
  }
  return static_cast<unsigned>(kBits);
}

std::string Uint256::to_string() const {
  const std::array<std::uint8_t, kBytes> bytes = to_be_bytes();
  return "0x" + to_hex(bytes.data(), bytes.size());
}

}  // namespace zk
