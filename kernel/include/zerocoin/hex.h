// Fixed-width hex types for the ZeroCoin kernel.
//
// Finding F3 (docs/migration/04-risk-register.md): the node stores digests in
// internal big-endian order but shows them to humans reversed, "explorer" style.
// Swapping the two is the easiest way to produce a plausible-looking-but-wrong
// hash, so byte order is part of the type:
//
//   Hex256 / Hex20                internal order: the bytes that are hashed
//   DisplayHex256 / DisplayHex20  display order:  the same bytes, reversed
//
// Neither converts into the other. Width is part of the type as well, so a
// 160-bit digest cannot be passed where a 256-bit one is expected. The
// static_asserts at the bottom of this header and in tests/test_static_asserts.cpp
// hold that guarantee at compile time.

#ifndef ZEROCOIN_KERNEL_HEX_H
#define ZEROCOIN_KERNEL_HEX_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace zk {

/// Hex value of one character, or -1 when it is not a hex digit.
constexpr int hex_nibble(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/// Lowercase hex of a byte range.
std::string to_hex(const std::uint8_t* data, std::size_t size);

/// Bytes of a hex string. Rejects odd lengths and non-hex characters.
std::optional<std::vector<std::uint8_t>> from_hex(std::string_view text);

/// A byte string of exactly `N` bytes whose text form is lowercase hex in
/// storage order. `N` is part of the type: `Hex256` and `Hex20` are unrelated.
template <std::size_t N>
class HexString {
 public:
  static constexpr std::size_t kWidth = N;
  static constexpr std::size_t kTextLength = 2 * N;

  constexpr HexString() noexcept = default;

  explicit constexpr HexString(const std::array<std::uint8_t, N>& bytes) noexcept
      : bytes_(bytes) {}

  /// Parses exactly 2N hex characters; any other length is rejected.
  static std::optional<HexString> parse(std::string_view text) noexcept {
    if (text.size() != kTextLength) {
      return std::nullopt;
    }
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i) {
      const int high = hex_nibble(text[2 * i]);
      const int low = hex_nibble(text[2 * i + 1]);
      if (high < 0 || low < 0) {
        return std::nullopt;
      }
      bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return HexString(bytes);
  }

  std::string str() const { return to_hex(bytes_.data(), N); }

  constexpr const std::array<std::uint8_t, N>& bytes() const noexcept { return bytes_; }

  friend constexpr bool operator==(const HexString& lhs, const HexString& rhs) noexcept {
    return lhs.bytes_ == rhs.bytes_;
  }
  friend constexpr bool operator!=(const HexString& lhs, const HexString& rhs) noexcept {
    return !(lhs == rhs);
  }

 private:
  std::array<std::uint8_t, N> bytes_{};
};

using Hex256 = HexString<32>;
using Hex20 = HexString<20>;

/// A digest rendered in display order: the internal bytes reversed.
///
/// This is a distinct type on purpose. A `DisplayHex256` is not a `Hex256`, so
/// display output can never be fed back in as storage-order input without an
/// explicit trip through `internal_bytes()`.
template <std::size_t N>
class DisplayHex {
 public:
  static constexpr std::size_t kWidth = N;
  static constexpr std::size_t kTextLength = 2 * N;

  explicit DisplayHex(const std::array<std::uint8_t, N>& internal) noexcept {
    for (std::size_t i = 0; i < N; ++i) {
      bytes_[i] = internal[N - 1 - i];
    }
  }

  std::string str() const { return to_hex(bytes_.data(), N); }

  const std::array<std::uint8_t, N>& display_bytes() const noexcept { return bytes_; }

  /// The storage-order bytes this display form was built from.
  std::array<std::uint8_t, N> internal_bytes() const noexcept {
    std::array<std::uint8_t, N> internal{};
    for (std::size_t i = 0; i < N; ++i) {
      internal[i] = bytes_[N - 1 - i];
    }
    return internal;
  }

 private:
  std::array<std::uint8_t, N> bytes_{};
};

using DisplayHex256 = DisplayHex<32>;
using DisplayHex20 = DisplayHex<20>;

// Every width the kernel relies on, checked where the types are defined.
static_assert(Hex256::kWidth == 32, "a 256-bit hash is 32 bytes");
static_assert(Hex20::kWidth == 20, "a 160-bit hash is 20 bytes");
static_assert(Hex256::kTextLength == 64, "a 256-bit hash is 64 hex characters");
static_assert(Hex20::kTextLength == 40, "a 160-bit hash is 40 hex characters");
static_assert(DisplayHex256::kWidth == 32, "display order does not change the width");
static_assert(DisplayHex20::kWidth == 20, "display order does not change the width");
static_assert(sizeof(Hex256) == 32, "Hex256 is exactly its bytes");
static_assert(sizeof(Hex20) == 20, "Hex20 is exactly its bytes");
static_assert(sizeof(Hex256) != sizeof(Hex20), "the two widths are distinct");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_HEX_H
