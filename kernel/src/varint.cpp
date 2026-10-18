#include "zerocoin/varint.h"

namespace zk {
namespace {

/// Little-endian payload of `count` bytes.
void append_le(std::uint64_t value, std::size_t count, std::vector<std::uint8_t>& out) {
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
  }
}

bool read_le(const std::uint8_t* data, std::size_t size, std::size_t offset, std::size_t count,
             std::uint64_t& out) noexcept {
  if (size - offset < count) {
    return false;
  }
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < count; ++i) {
    value |= static_cast<std::uint64_t>(data[offset + i]) << (8 * i);
  }
  out = value;
  return true;
}

}  // namespace

std::size_t varint_size(std::uint64_t value) noexcept {
  if (value <= kVarIntDirectMax) {
    return 1;
  }
  if (value <= kVarInt16Max) {
    return 3;
  }
  if (value <= kVarInt32Max) {
    return 5;
  }
  return 9;
}

void write_varint(std::uint64_t value, std::vector<std::uint8_t>& out) {
  if (value <= kVarIntDirectMax) {
    out.push_back(static_cast<std::uint8_t>(value));
  } else if (value <= kVarInt16Max) {
    out.push_back(kVarIntPrefix16);
    append_le(value, 2, out);
  } else if (value <= kVarInt32Max) {
    out.push_back(kVarIntPrefix32);
    append_le(value, 4, out);
  } else {
    out.push_back(kVarIntPrefix64);
    append_le(value, 8, out);
  }
}

VarIntStatus read_varint(const std::uint8_t* data, std::size_t size, std::size_t& offset,
                         std::uint64_t& value) noexcept {
  if (size - offset < 1) {
    return VarIntStatus::Truncated;
  }
  const std::uint8_t first = data[offset];
  if (first <= kVarIntDirectMax) {
    value = first;
    offset += 1;
    return VarIntStatus::Ok;
  }

  std::size_t payload = 0;
  std::uint64_t minimum = 0;
  switch (first) {
    case kVarIntPrefix16:
      payload = 2;
      minimum = kVarIntDirectMax + 1;
      break;
    case kVarIntPrefix32:
      payload = 4;
      minimum = kVarInt16Max + 1;
      break;
    default:  // kVarIntPrefix64
      payload = 8;
      minimum = kVarInt32Max + 1;
      break;
  }

  std::uint64_t decoded = 0;
  if (!read_le(data, size, offset + 1, payload, decoded)) {
    return VarIntStatus::Truncated;
  }
  if (decoded < minimum) {
    return VarIntStatus::NonMinimal;
  }
  value = decoded;
  offset += 1 + payload;
  return VarIntStatus::Ok;
}

}  // namespace zk
