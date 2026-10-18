#include "test_framework.h"

#include "zerocoin/hex.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using zk::DisplayHex20;
using zk::DisplayHex256;
using zk::Hex20;
using zk::Hex256;

constexpr std::array<std::uint8_t, 32> kAscending32 = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

}  // namespace

ZK_TEST(hex_nibble_reads_both_cases) {
  ZK_CHECK(zk::hex_nibble('0') == 0);
  ZK_CHECK(zk::hex_nibble('9') == 9);
  ZK_CHECK(zk::hex_nibble('a') == 10);
  ZK_CHECK(zk::hex_nibble('f') == 15);
  ZK_CHECK(zk::hex_nibble('A') == 10);
  ZK_CHECK(zk::hex_nibble('F') == 15);
}

ZK_TEST(hex_nibble_rejects_non_hex) {
  ZK_CHECK(zk::hex_nibble('g') == -1);
  ZK_CHECK(zk::hex_nibble(' ') == -1);
  ZK_CHECK(zk::hex_nibble('\0') == -1);
  ZK_CHECK(zk::hex_nibble('0' - 1) == -1);
  ZK_CHECK(zk::hex_nibble('f' + 1) == -1);
}

ZK_TEST(to_hex_is_lowercase_and_bytewise) {
  const std::vector<std::uint8_t> bytes{0x00, 0x0f, 0x10, 0xa5, 0xff};
  ZK_CHECK(zk::to_hex(bytes.data(), bytes.size()) == "000f10a5ff");
  ZK_CHECK(zk::to_hex(nullptr, 0) == "");
}

ZK_TEST(from_hex_round_trips) {
  const auto bytes = zk::from_hex("000f10a5ff");
  ZK_CHECK(bytes.has_value());
  ZK_CHECK(zk::to_hex(bytes->data(), bytes->size()) == "000f10a5ff");
}

ZK_TEST(from_hex_accepts_uppercase) {
  const auto bytes = zk::from_hex("DEADbeef");
  ZK_CHECK(bytes.has_value());
  ZK_CHECK(zk::to_hex(bytes->data(), bytes->size()) == "deadbeef");
}

ZK_TEST(from_hex_accepts_empty) {
  const auto bytes = zk::from_hex("");
  ZK_CHECK(bytes.has_value());
  ZK_CHECK(bytes->empty());
}

ZK_TEST(from_hex_rejects_odd_length) {
  ZK_CHECK(!zk::from_hex("abc").has_value());
  ZK_CHECK(!zk::from_hex("0").has_value());
}

ZK_TEST(from_hex_rejects_non_hex) {
  ZK_CHECK(!zk::from_hex("zz").has_value());
  ZK_CHECK(!zk::from_hex("0g").has_value());
  ZK_CHECK(!zk::from_hex("00 11").has_value());
}

ZK_TEST(hex256_parses_exactly_64_characters) {
  const std::string text(64, 'a');
  const auto parsed = Hex256::parse(text);
  ZK_CHECK(parsed.has_value());
  ZK_CHECK(parsed->str() == text);
  ZK_CHECK(parsed->bytes()[0] == 0xaa);
}

ZK_TEST(hex256_rejects_wrong_widths) {
  ZK_CHECK(!Hex256::parse(std::string(62, 'a')).has_value());
  ZK_CHECK(!Hex256::parse(std::string(66, 'a')).has_value());
  ZK_CHECK(!Hex256::parse("").has_value());
  ZK_CHECK(!Hex20::parse(std::string(64, 'a')).has_value());
}

ZK_TEST(hex256_rejects_non_hex_of_the_right_length) {
  std::string text(64, '0');
  ZK_CHECK(Hex256::parse(text).has_value());
  text[17] = 'x';
  ZK_CHECK(!Hex256::parse(text).has_value());
}

ZK_TEST(hex20_parses_exactly_40_characters) {
  const std::string text(40, '5');
  const auto parsed = Hex20::parse(text);
  ZK_CHECK(parsed.has_value());
  ZK_CHECK(parsed->str() == text);
  ZK_CHECK(parsed->bytes().size() == 20);
}

ZK_TEST(display_hex_reverses_storage_order) {
  const Hex256 internal(kAscending32);
  ZK_CHECK(internal.str() ==
           "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

  const DisplayHex256 display(internal.bytes());
  ZK_CHECK(display.str() ==
           "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
  ZK_CHECK(display.display_bytes()[0] == 0x1f);
}

ZK_TEST(display_hex_reversal_is_an_involution) {
  const DisplayHex256 display(kAscending32);
  ZK_CHECK(display.internal_bytes() == kAscending32);

  const DisplayHex256 twice(display.internal_bytes());
  ZK_CHECK(twice.display_bytes() == display.display_bytes());
}

ZK_TEST(display_hex_keeps_the_width) {
  static_assert(DisplayHex256::kWidth == 32);
  static_assert(DisplayHex20::kWidth == 20);
  static_assert(DisplayHex256::kTextLength == 64);
  static_assert(DisplayHex20::kTextLength == 40);

  std::array<std::uint8_t, 20> internal{};
  internal[0] = 0xab;
  const DisplayHex20 display(internal);
  ZK_CHECK(display.str() == "00000000000000000000000000000000000000ab");
}
