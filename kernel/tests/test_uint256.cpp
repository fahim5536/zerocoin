#include "test_framework.h"

#include "zerocoin/hex.h"
#include "zerocoin/uint256.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace {

using zk::Uint256;

constexpr std::array<std::uint8_t, 32> kAscending32 = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

Uint256 from_be_hex(std::string_view text) {
  const auto bytes = zk::from_hex(text);
  ZK_CHECK(bytes.has_value());
  ZK_CHECK(bytes->size() == Uint256::kBytes);
  std::array<std::uint8_t, Uint256::kBytes> be{};
  std::copy(bytes->begin(), bytes->end(), be.begin());
  return Uint256::from_be_bytes(be);
}

std::string be_hex(const Uint256& value) {
  const auto bytes = value.to_be_bytes();
  return zk::to_hex(bytes.data(), bytes.size());
}

struct CompactVector {
  std::uint32_t bits;
  const char* target_be_hex;
  std::uint32_t roundtrip_bits;
};

// The difficulty.compact.* corpus, in the same order it appears in
// test/vectors/difficulty/retarget.json.
constexpr CompactVector kCompactVectors[] = {
    {0x0000'0000, "0000000000000000000000000000000000000000000000000000000000000000", 0},
    {0x0300'0001, "0000000000000000000000000000000000000000000000000000000000000001",
     0x0101'0000},
    {0x0100'3456, "0000000000000000000000000000000000000000000000000000000000000000", 0},
    {0x1c00'ffff, "0000000000ffff00000000000000000000000000000000000000000000000000",
     0x1c00'ffff},
    {0x1d00'ffff, "00000000ffff0000000000000000000000000000000000000000000000000000",
     0x1d00'ffff},
    {0x1e00'ffff, "000000ffff000000000000000000000000000000000000000000000000000000",
     0x1e00'ffff},
    {0x207f'ffff, "7fffff0000000000000000000000000000000000000000000000000000000000",
     0x207f'ffff},
    {0x2100'ffff, "ffff000000000000000000000000000000000000000000000000000000000000",
     0x2100'ffff},
    {0x1d80'0000, "0000000000000000000000000000000000000000000000000000000000000000", 0},
};

}  // namespace

ZK_TEST(uint256_constants_are_the_multiplicative_identities) {
  ZK_CHECK(Uint256::zero().is_zero());
  ZK_CHECK(!Uint256::one().is_zero());
  ZK_CHECK(Uint256::one() == Uint256::from_u64(1));
  ZK_CHECK(Uint256::max() == Uint256::max());
  ZK_CHECK(Uint256::max() != Uint256::zero());
  ZK_CHECK(Uint256::max() > Uint256::one());
  ZK_CHECK(Uint256::zero() < Uint256::one());
}

ZK_TEST(uint256_orders_by_most_significant_limb) {
  const Uint256 low = Uint256::from_u64(0xffff'ffff'ffff'ffffull);
  const Uint256 next_limb =
      Uint256(std::array<std::uint64_t, 4>{0, 1, 0, 0});
  const Uint256 top_only = Uint256(std::array<std::uint64_t, 4>{0, 0, 0, 1});

  ZK_CHECK(low < next_limb);
  ZK_CHECK(next_limb < top_only);
  ZK_CHECK(top_only < Uint256::max());
  ZK_CHECK(next_limb <= next_limb);
  ZK_CHECK(next_limb >= next_limb);
}

ZK_TEST(uint256_be_bytes_round_trip) {
  const Uint256 value = Uint256::from_be_bytes(kAscending32);
  ZK_CHECK(value.to_be_bytes() == kAscending32);

  ZK_CHECK(from_be_hex(std::string(64, '0')).is_zero());
  ZK_CHECK(from_be_hex(std::string(63, '0') + "1") == Uint256::one());
  ZK_CHECK(from_be_hex(std::string(64, 'f')) == Uint256::max());
}

ZK_TEST(uint256_from_u64_places_the_value_in_the_low_limb) {
  const Uint256 value = Uint256::from_u64(0x0102'0304'0506'0708ull);
  ZK_CHECK(value.limbs[0] == 0x0102'0304'0506'0708ull);
  ZK_CHECK(value.limbs[1] == 0);
  ZK_CHECK(value.limbs[2] == 0);
  ZK_CHECK(value.limbs[3] == 0);
  ZK_CHECK(be_hex(value) == "0000000000000000000000000000000000000000000000000102030405060708");
}

ZK_TEST(uint256_compact_matches_the_corpus) {
  for (const CompactVector& vector : kCompactVectors) {
    const Uint256 target = Uint256::from_compact(vector.bits);
    ZK_CHECK(be_hex(target) == vector.target_be_hex);
    ZK_CHECK(target.is_zero() == (vector.roundtrip_bits == 0));
    ZK_CHECK(target.to_compact() == vector.roundtrip_bits);
  }
}

ZK_TEST(uint256_compact_reads_the_sign_bit_as_zero) {
  ZK_CHECK(Uint256::from_compact(0x1d80'0000).is_zero());
  ZK_CHECK(Uint256::from_compact(0x0080'0000).is_zero());
  ZK_CHECK(Uint256::from_compact(0x0080'0001).is_zero());
  ZK_CHECK(Uint256::from_compact(0x1c80'0000).is_zero());
}

ZK_TEST(uint256_compact_of_zero_is_zero) {
  ZK_CHECK(Uint256::zero().to_compact() == 0);
}

ZK_TEST(uint256_compact_of_the_pow_limit) {
  // DIFFICULTY_PARAMS.pow_limit_bits is 0x1e00ffff: 0xffff shifted up 216 bits.
  const Uint256 pow_limit = Uint256::from_compact(0x1e00'ffff);
  ZK_CHECK(be_hex(pow_limit) ==
           "000000ffff000000000000000000000000000000000000000000000000000000");
  ZK_CHECK(pow_limit.to_compact() == 0x1e00'ffff);
  ZK_CHECK(Uint256::from_compact(pow_limit.to_compact()) == pow_limit);
  ZK_CHECK(Uint256::from_compact(0x1d00'ffff) < pow_limit);
  ZK_CHECK(pow_limit < Uint256::from_compact(0x2100'ffff));
}

ZK_TEST(uint256_wrapping_add_carries_across_limbs) {
  const Uint256 low_max = Uint256(std::array<std::uint64_t, 4>{~0ull, 0, 0, 0});
  const Uint256 carry = low_max.wrapping_add(Uint256::one());
  ZK_CHECK(carry == Uint256(std::array<std::uint64_t, 4>{0, 1, 0, 0}));

  ZK_CHECK(Uint256::max().wrapping_add(Uint256::one()).is_zero());
  ZK_CHECK(Uint256::max().wrapping_add(Uint256::max()) == Uint256::max().wrapping_sub(Uint256::one()));
}

ZK_TEST(uint256_wrapping_sub_borrows_across_limbs) {
  const Uint256 one_limb = Uint256(std::array<std::uint64_t, 4>{0, 1, 0, 0});
  ZK_CHECK(one_limb.wrapping_sub(Uint256::one()) ==
           Uint256(std::array<std::uint64_t, 4>{~0ull, 0, 0, 0}));
  ZK_CHECK(Uint256::zero().wrapping_sub(Uint256::one()) == Uint256::max());
  ZK_CHECK(Uint256::one().wrapping_sub(Uint256::one()).is_zero());
}

ZK_TEST(uint256_mul_u64_multiplies_every_limb) {
  ZK_CHECK(Uint256::from_u64(3).mul_u64(7) == Uint256::from_u64(21));
  ZK_CHECK(Uint256::max().mul_u64(2) == Uint256::max().wrapping_sub(Uint256::one()));
  ZK_CHECK(Uint256::zero().mul_u64(~0ull).is_zero());

  const Uint256 shifted = Uint256::one().mul_u64(~0ull);
  ZK_CHECK(shifted == Uint256(std::array<std::uint64_t, 4>{~0ull, 0, 0, 0}));
}

ZK_TEST(uint256_div_u64_divides_from_the_top_limb) {
  ZK_CHECK(Uint256::from_u64(100).div_u64(7) == Uint256::from_u64(14));
  ZK_CHECK(Uint256::from_u64(6).div_u64(7).is_zero());
  ZK_CHECK(Uint256::max().div_u64(1) == Uint256::max());
  ZK_CHECK(Uint256::max().div_u64(~0ull) ==
           Uint256(std::array<std::uint64_t, 4>{1, 1, 1, 1}));
}

ZK_TEST(uint256_divmod_returns_quotient_and_remainder) {
  const auto [quotient, remainder] = Uint256::from_u64(1000).divmod(Uint256::from_u64(7));
  ZK_CHECK(quotient == Uint256::from_u64(142));
  ZK_CHECK(remainder == Uint256::from_u64(6));

  const auto [same, nothing] = Uint256::max().divmod(Uint256::max());
  ZK_CHECK(same == Uint256::one());
  ZK_CHECK(nothing.is_zero());

  const auto [identity, none] = Uint256::max().divmod(Uint256::one());
  ZK_CHECK(identity == Uint256::max());
  ZK_CHECK(none.is_zero());
}

ZK_TEST(uint256_divmod_preserves_the_257th_bit) {
  // A dividend at the top of the range divided by a small divisor: the first
  // iteration of the long division sets the carry bit, which a naive shift
  // would drop.
  const Uint256 dividend = Uint256(std::array<std::uint64_t, 4>{0, 0, 0, 1ull << 63});
  const Uint256 three = Uint256::from_u64(3);
  const auto [quotient, remainder] = dividend.divmod(three);

  ZK_CHECK(remainder < three);
  ZK_CHECK(quotient.mul_u64(3).wrapping_add(remainder) == dividend);

  const auto [q_max, r_max] = Uint256::max().divmod(three);
  ZK_CHECK(r_max < three);
  ZK_CHECK(q_max.mul_u64(3).wrapping_add(r_max) == Uint256::max());
}

ZK_TEST(uint256_divmod_with_a_multi_limb_divisor) {
  const Uint256 divisor = Uint256::one().shl_bits(128);
  const Uint256 expected(std::array<std::uint64_t, 4>{~0ull, ~0ull, 0, 0});
  const auto [quotient, remainder] = Uint256::max().divmod(divisor);

  ZK_CHECK(quotient == expected);
  ZK_CHECK(remainder == expected);
  ZK_CHECK(remainder < divisor);
}

ZK_TEST(uint256_shifts_move_bits_between_limbs) {
  ZK_CHECK(Uint256::one().shl_one() == Uint256::from_u64(2));
  ZK_CHECK(Uint256::from_u64(2).shr_one() == Uint256::one());
  ZK_CHECK(Uint256::max().shl_one() == Uint256::max().wrapping_sub(Uint256::one()));
  ZK_CHECK(Uint256::max().shr_one() ==
           Uint256(std::array<std::uint64_t, 4>{~0ull, ~0ull, ~0ull, 0x7fff'ffff'ffff'ffffull}));

  const Uint256 shifted = Uint256::one().shl_bits(64);
  ZK_CHECK(shifted == Uint256(std::array<std::uint64_t, 4>{0, 1, 0, 0}));
  ZK_CHECK(shifted.shr_bits(64) == Uint256::one());

  ZK_CHECK(Uint256::max().shl_bits(0) == Uint256::max());
  ZK_CHECK(Uint256::max().shr_bits(0) == Uint256::max());
  ZK_CHECK(Uint256::max().shl_bits(256).is_zero());
  ZK_CHECK(Uint256::max().shr_bits(256).is_zero());
  ZK_CHECK(Uint256::max().shl_bits(300).is_zero());
}

ZK_TEST(uint256_bit_accessors_are_bounded) {
  Uint256 value = Uint256::zero();
  ZK_CHECK(!value.bit(0));
  value.set_bit(0);
  ZK_CHECK(value == Uint256::one());
  ZK_CHECK(value.bit(0));

  value.set_bit(255);
  ZK_CHECK(value.bit(255));
  ZK_CHECK(value.leading_zeros() == 0);

  ZK_CHECK(!value.bit(256));
  value.set_bit(256);
  ZK_CHECK(!value.bit(256));
}

ZK_TEST(uint256_leading_zeros_counts_from_the_top) {
  ZK_CHECK(Uint256::zero().leading_zeros() == 256);
  ZK_CHECK(Uint256::one().leading_zeros() == 255);
  ZK_CHECK(Uint256::max().leading_zeros() == 0);
  ZK_CHECK(Uint256::one().shl_bits(255).leading_zeros() == 0);
  ZK_CHECK(Uint256::one().shl_bits(200).leading_zeros() == 55);
}

ZK_TEST(uint256_bitwise_not_is_an_involution) {
  ZK_CHECK(Uint256::zero().bitwise_not() == Uint256::max());
  ZK_CHECK(Uint256::max().bitwise_not().is_zero());
  ZK_CHECK(Uint256::max().bitwise_not().bitwise_not() == Uint256::max());
  ZK_CHECK(Uint256::from_u64(0x0f0f).bitwise_not() ==
           Uint256::max().wrapping_sub(Uint256::from_u64(0x0f0f)));
}

ZK_TEST(uint256_to_string_is_zero_padded_lowercase_hex) {
  ZK_CHECK(Uint256::zero().to_string() == "0x" + std::string(64, '0'));
  ZK_CHECK(Uint256::one().to_string() == "0x" + std::string(63, '0') + "1");
  ZK_CHECK(Uint256::max().to_string() == "0x" + std::string(64, 'f'));
  ZK_CHECK(Uint256::from_be_bytes(kAscending32).to_string() ==
           "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}
