// G1's second acceptance criterion, as a program: "hex types are compile-time
// distinct" (docs/migration/05-verification-plan.md §7).
//
// Every assertion here fails the build, not a test run. If someone adds a
// converting constructor to collapse Hex256 into Hex20, or makes the display
// type interchangeable with the internal one, compilation stops.

#include "test_framework.h"

#include "zerocoin/hash.h"
#include "zerocoin/hex.h"
#include "zerocoin/transaction.h"
#include "zerocoin/uint256.h"
#include "zerocoin/varint.h"

#include <array>
#include <cstdint>
#include <type_traits>

namespace {

using zk::DisplayHex20;
using zk::DisplayHex256;
using zk::Hash160;
using zk::Hash256;
using zk::Hex20;
using zk::Hex256;

// Width is part of the type.
static_assert(!std::is_same_v<Hex256, Hex20>, "a 256-bit digest is not a 160-bit one");
static_assert(!std::is_convertible_v<Hex256, Hex20>, "widths do not convert");
static_assert(!std::is_convertible_v<Hex20, Hex256>, "widths do not convert");
static_assert(!std::is_constructible_v<Hex256, Hex20>, "widths do not construct into each other");
static_assert(sizeof(Hex256) != sizeof(Hex20), "the two widths differ in size");

// Byte order is part of the type.
static_assert(!std::is_same_v<Hex256, DisplayHex256>, "display order is a distinct type");
static_assert(!std::is_same_v<Hex20, DisplayHex20>, "display order is a distinct type");
static_assert(!std::is_convertible_v<Hex256, DisplayHex256>, "internal order does not become display order");
static_assert(!std::is_convertible_v<DisplayHex256, Hex256>, "display order does not become internal order");
static_assert(!std::is_convertible_v<Hex20, DisplayHex20>, "internal order does not become display order");
static_assert(!std::is_convertible_v<DisplayHex20, Hex20>, "display order does not become internal order");
static_assert(!std::is_constructible_v<DisplayHex256, Hex256>, "no silent reversal");
static_assert(!std::is_constructible_v<Hex256, DisplayHex256>, "no silent reversal");

// The hash wrappers keep the two orders apart as well.
static_assert(std::is_same_v<decltype(Hash256{}.to_hex()), Hex256>);
static_assert(std::is_same_v<decltype(Hash256{}.to_display_hex()), DisplayHex256>);
static_assert(std::is_same_v<decltype(Hash160{}.to_hex()), Hex20>);
static_assert(std::is_same_v<decltype(Hash160{}.to_display_hex()), DisplayHex20>);
static_assert(!std::is_same_v<Hash256, Hash160>, "the two digest widths are distinct types");
static_assert(!std::is_convertible_v<Hash256, Hash160>);

// The byte accessors expose the width they were built with.
static_assert(std::is_same_v<decltype(Hex256{}.bytes()), const std::array<std::uint8_t, 32>&>);
static_assert(std::is_same_v<decltype(Hex20{}.bytes()), const std::array<std::uint8_t, 20>&>);

// Constants frozen with the codec.
static_assert(Hex256::kTextLength == 64);
static_assert(Hex20::kTextLength == 40);
static_assert(zk::Uint256::kBits == 256);
static_assert(zk::Uint256::kBytes == 32);
static_assert(zk::kNullVout == 0xffff'ffff);
static_assert(zk::kMaxTxInputs == 10'000);
static_assert(zk::kMaxTxOutputs == 10'000);
static_assert(zk::kVarIntMaxBytes == 9);

}  // namespace

ZK_TEST(static_width_checks_hold_at_runtime_too) {
  ZK_CHECK(Hex256::kWidth != Hex20::kWidth);
  ZK_CHECK(sizeof(Hex256) == 32);
  ZK_CHECK(sizeof(Hex20) == 20);
  ZK_CHECK(sizeof(zk::Uint256) == 32);
  ZK_CHECK(sizeof(Hash256) == 32);
  ZK_CHECK(sizeof(Hash160) == 20);
}
