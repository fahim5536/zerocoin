// Hash primitives, mirroring zerocoin/src/crypto/hash.rs.
//
// Digest bytes are stored in internal big-endian order, exactly as the Rust
// implementation does. The display form (reversed bytes) is a different type;
// see hex.h for why that matters.

#ifndef ZEROCOIN_KERNEL_HASH_H
#define ZEROCOIN_KERNEL_HASH_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "zerocoin/hex.h"

namespace zk {

/// SHA-256 (FIPS 180-4).
std::array<std::uint8_t, 32> sha256(const std::uint8_t* data, std::size_t size);
std::array<std::uint8_t, 32> sha256(std::string_view text);

/// RIPEMD-160.
std::array<std::uint8_t, 20> ripemd160(const std::uint8_t* data, std::size_t size);
std::array<std::uint8_t, 20> ripemd160(std::string_view text);

/// A 256-bit digest in internal order.
struct Hash256 {
  static constexpr std::size_t kWidth = 32;

  std::array<std::uint8_t, kWidth> bytes{};

  constexpr Hash256() noexcept = default;
  explicit constexpr Hash256(const std::array<std::uint8_t, kWidth>& raw) noexcept
      : bytes(raw) {}

  static constexpr Hash256 zero() noexcept { return Hash256{}; }

  constexpr bool is_zero() const noexcept {
    for (const std::uint8_t byte : bytes) {
      if (byte != 0) {
        return false;
      }
    }
    return true;
  }

  static Hash256 from_hex(Hex256 internal) noexcept { return Hash256(internal.bytes()); }
  Hex256 to_hex() const noexcept { return Hex256(bytes); }
  DisplayHex256 to_display_hex() const noexcept { return DisplayHex256(bytes); }

  friend constexpr bool operator==(const Hash256& lhs, const Hash256& rhs) noexcept {
    return lhs.bytes == rhs.bytes;
  }
  friend constexpr bool operator!=(const Hash256& lhs, const Hash256& rhs) noexcept {
    return !(lhs == rhs);
  }
};

/// A 160-bit digest in internal order.
struct Hash160 {
  static constexpr std::size_t kWidth = 20;

  std::array<std::uint8_t, kWidth> bytes{};

  constexpr Hash160() noexcept = default;
  explicit constexpr Hash160(const std::array<std::uint8_t, kWidth>& raw) noexcept
      : bytes(raw) {}

  static constexpr Hash160 zero() noexcept { return Hash160{}; }

  constexpr bool is_zero() const noexcept {
    for (const std::uint8_t byte : bytes) {
      if (byte != 0) {
        return false;
      }
    }
    return true;
  }

  static Hash160 from_hex(Hex20 internal) noexcept { return Hash160(internal.bytes()); }
  Hex20 to_hex() const noexcept { return Hex20(bytes); }
  DisplayHex20 to_display_hex() const noexcept { return DisplayHex20(bytes); }

  friend constexpr bool operator==(const Hash160& lhs, const Hash160& rhs) noexcept {
    return lhs.bytes == rhs.bytes;
  }
  friend constexpr bool operator!=(const Hash160& lhs, const Hash160& rhs) noexcept {
    return !(lhs == rhs);
  }
};

/// SHA-256 applied twice: the transaction and block identifier.
Hash256 sha256d(const std::uint8_t* data, std::size_t size);
Hash256 sha256d(std::string_view text);

/// RIPEMD-160(SHA-256(data)): the public-key hash behind every address.
Hash160 hash160(const std::uint8_t* data, std::size_t size);
Hash160 hash160(std::string_view text);

static_assert(Hash256::kWidth == Hex256::kWidth, "Hash256 and Hex256 share a width");
static_assert(Hash160::kWidth == Hex20::kWidth, "Hash160 and Hex20 share a width");
static_assert(Hash160::kWidth * 8 == 160, "HASH160 is 160 bits");
static_assert(Hash256::kWidth * 8 == 256, "SHA-256 is 256 bits");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_HASH_H
