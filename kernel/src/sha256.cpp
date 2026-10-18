// SHA-256, FIPS 180-4. Dependency-free so the kernel has no external build
// requirements.

#include "zerocoin/hash.h"

#include <cstring>

namespace zk {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u,
};

constexpr std::uint32_t kInitialState[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32 - count));
}

std::uint32_t load_be32(const std::uint8_t* data) noexcept {
  return (static_cast<std::uint32_t>(data[0]) << 24) |
         (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) | static_cast<std::uint32_t>(data[3]);
}

void compress(std::uint32_t state[8], const std::uint8_t* block) noexcept {
  std::uint32_t w[64];
  for (unsigned i = 0; i < 16; ++i) {
    w[i] = load_be32(block + 4 * i);
  }
  for (unsigned i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state[0];
  std::uint32_t b = state[1];
  std::uint32_t c = state[2];
  std::uint32_t d = state[3];
  std::uint32_t e = state[4];
  std::uint32_t f = state[5];
  std::uint32_t g = state[6];
  std::uint32_t h = state[7];

  for (unsigned i = 0; i < 64; ++i) {
    const std::uint32_t sigma1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t choose = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + sigma1 + choose + kRoundConstants[i] + w[i];
    const std::uint32_t sigma0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = sigma0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

}  // namespace

std::array<std::uint8_t, 32> sha256(const std::uint8_t* data, std::size_t size) {
  std::uint32_t state[8];
  std::memcpy(state, kInitialState, sizeof(state));

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
    tail[tail_len - 1 - i] = static_cast<std::uint8_t>(bit_length >> (8 * i));
  }

  compress(state, tail.data());
  if (tail_len == 128) {
    compress(state, tail.data() + 64);
  }

  std::array<std::uint8_t, 32> digest{};
  for (unsigned i = 0; i < 8; ++i) {
    digest[4 * i] = static_cast<std::uint8_t>(state[i] >> 24);
    digest[4 * i + 1] = static_cast<std::uint8_t>(state[i] >> 16);
    digest[4 * i + 2] = static_cast<std::uint8_t>(state[i] >> 8);
    digest[4 * i + 3] = static_cast<std::uint8_t>(state[i]);
  }
  return digest;
}

std::array<std::uint8_t, 32> sha256(std::string_view text) {
  return sha256(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

}  // namespace zk
