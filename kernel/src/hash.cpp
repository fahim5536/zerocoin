#include "zerocoin/hash.h"

namespace zk {

Hash256 sha256d(const std::uint8_t* data, std::size_t size) {
  const std::array<std::uint8_t, 32> first = sha256(data, size);
  return Hash256(sha256(first.data(), first.size()));
}

Hash256 sha256d(std::string_view text) {
  return sha256d(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

Hash160 hash160(const std::uint8_t* data, std::size_t size) {
  const std::array<std::uint8_t, 32> digest = sha256(data, size);
  return Hash160(ripemd160(digest.data(), digest.size()));
}

Hash160 hash160(std::string_view text) {
  return hash160(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

}  // namespace zk
