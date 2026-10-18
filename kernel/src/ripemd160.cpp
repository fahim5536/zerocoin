// RIPEMD-160. Dependency-free, like the SHA-256 alongside it.

#include "zerocoin/hash.h"

#include <cstring>

namespace zk {
namespace {

// Message word order, one row per 16-step round, left and right lines.
constexpr unsigned kLeftWordOrder[5][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8},
    {3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12},
    {1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2},
    {4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13},
};

constexpr unsigned kRightWordOrder[5][16] = {
    {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12},
    {6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2},
    {15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13},
    {8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14},
    {12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11},
};

// Rotation amounts, one row per 16-step round, left and right lines.
constexpr unsigned kLeftRotations[5][16] = {
    {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8},
    {7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12},
    {11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5},
    {11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12},
    {9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6},
};

constexpr unsigned kRightRotations[5][16] = {
    {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6},
    {9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11},
    {9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5},
    {15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8},
    {8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11},
};

constexpr std::uint32_t kLeftConstants[5] = {0x00000000u, 0x5a827999u, 0x6ed9eba1u,
                                             0x8f1bbcdcu, 0xa953fd4eu};
constexpr std::uint32_t kRightConstants[5] = {0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u,
                                              0x7a6d76e9u, 0x00000000u};

constexpr std::uint32_t rol(std::uint32_t value, unsigned count) noexcept {
  return (value << count) | (value >> (32 - count));
}

std::uint32_t loading_le32(const std::uint8_t* data) noexcept {
  return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
         (static_cast<std::uint32_t>(data[2]) << 16) |
         (static_cast<std::uint32_t>(data[3]) << 24);
}

/// f1..f5, selected by round index 0..4.
std::uint32_t round_function(unsigned round, std::uint32_t x, std::uint32_t y,
                             std::uint32_t z) noexcept {
  switch (round) {
    case 0:
      return x ^ y ^ z;
    case 1:
      return (x & y) | (~x & z);
    case 2:
      return (x | ~y) ^ z;
    case 3:
      return (x & z) | (y & ~z);
    default:
      return x ^ (y | ~z);
  }
}

void compress(std::uint32_t state[5], const std::uint8_t* block) noexcept {
  std::uint32_t x[16];
  for (unsigned i = 0; i < 16; ++i) {
    x[i] = loading_le32(block + 4 * i);
  }

  std::uint32_t al = state[0];
  std::uint32_t bl = state[1];
  std::uint32_t cl = state[2];
  std::uint32_t dl = state[3];
  std::uint32_t el = state[4];
  std::uint32_t ar = state[0];
  std::uint32_t br = state[1];
  std::uint32_t cr = state[2];
  std::uint32_t dr = state[3];
  std::uint32_t er = state[4];

  for (unsigned round = 0; round < 5; ++round) {
    for (unsigned step = 0; step < 16; ++step) {
      std::uint32_t t = rol(al + round_function(round, bl, cl, dl) +
                                x[kLeftWordOrder[round][step]] + kLeftConstants[round],
                            kLeftRotations[round][step]) +
                        el;
      al = el;
      el = dl;
      dl = rol(cl, 10);
      cl = bl;
      bl = t;

      t = rol(ar + round_function(4 - round, br, cr, dr) +
                  x[kRightWordOrder[round][step]] + kRightConstants[round],
              kRightRotations[round][step]) +
          er;
      ar = er;
      er = dr;
      dr = rol(cr, 10);
      cr = br;
      br = t;
    }
  }

  const std::uint32_t t = state[1] + cl + dr;
  state[1] = state[2] + dl + er;
  state[2] = state[3] + el + ar;
  state[3] = state[4] + al + br;
  state[4] = state[0] + bl + cr;
  state[0] = t;
}

}  // namespace

std::array<std::uint8_t, 20> ripemd160(const std::uint8_t* data, std::size_t size) {
  std::uint32_t state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};

  std::size_t offset = 0;
  while (size - offset >= 64) {
    compress(state, data + offset);
    offset += 64;
  }

  std::array<std::uint8_t, 128> tail{};
  const std::size_t remaining = size - offset;
  if (remaining != 0) {
    std::memcpy(tail.data(), data + offset, remaining);
  }
  tail[remaining] = 0x80;
  const std::size_t tail_len = (remaining + 1 + 8 <= 64) ? 64 : 128;

  const std::uint64_t bit_length = static_cast<std::uint64_t>(size) * 8;
  for (unsigned i = 0; i < 8; ++i) {
    tail[tail_len - 8 + i] = static_cast<std::uint8_t>(bit_length >> (8 * i));
  }

  compress(state, tail.data());
  if (tail_len == 128) {
    compress(state, tail.data() + 64);
  }

  std::array<std::uint8_t, 20> digest{};
  for (unsigned i = 0; i < 5; ++i) {
    digest[4 * i] = static_cast<std::uint8_t>(state[i]);
    digest[4 * i + 1] = static_cast<std::uint8_t>(state[i] >> 8);
    digest[4 * i + 2] = static_cast<std::uint8_t>(state[i] >> 16);
    digest[4 * i + 3] = static_cast<std::uint8_t>(state[i] >> 24);
  }
  return digest;
}

std::array<std::uint8_t, 20> ripemd160(std::string_view text) {
  return ripemd160(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

}  // namespace zk
