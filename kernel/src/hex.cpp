#include "zerocoin/hex.h"

namespace zk {
namespace {

constexpr char kDigits[] = "0123456789abcdef";

}  // namespace

std::string to_hex(const std::uint8_t* data, std::size_t size) {
  std::string out;
  out.resize(2 * size);
  for (std::size_t i = 0; i < size; ++i) {
    out[2 * i] = kDigits[data[i] >> 4];
    out[2 * i + 1] = kDigits[data[i] & 0x0f];
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> from_hex(std::string_view text) {
  if (text.size() % 2 != 0) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> bytes;
  bytes.reserve(text.size() / 2);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int high = hex_nibble(text[i]);
    const int low = hex_nibble(text[i + 1]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return bytes;
}

}  // namespace zk
