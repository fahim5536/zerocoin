#include "zerocoin/header.h"

#include <algorithm>

namespace zk {
namespace {

// Every offset is derived from the field widths rather than written as a
// literal, so the index expressions and `kHeaderPreimageSize` cannot drift
// apart. Asserted against the frozen total at the bottom of this file.
constexpr std::size_t kVersionOffset = kHeaderTagSize;
constexpr std::size_t kChainOffset = kVersionOffset + sizeof(std::uint32_t);
constexpr std::size_t kHeightOffset = kChainOffset + sizeof(std::uint32_t);
constexpr std::size_t kPreviousHashOffset = kHeightOffset + sizeof(std::uint64_t);
constexpr std::size_t kMerkleRootOffset = kPreviousHashOffset + Hash256::kWidth;
constexpr std::size_t kTimestampOffset = kMerkleRootOffset + Hash256::kWidth;
constexpr std::size_t kBitsOffset = kTimestampOffset + sizeof(std::uint64_t);
constexpr std::size_t kEngineOffset = kBitsOffset + sizeof(std::uint32_t);

// C-11: the value is unsigned and each byte is shifted out of it explicitly, so
// the result does not depend on the host byte order and no native integer is
// ever copied. The shifts are always < the width of the promoted operand, so
// there is no undefined behaviour at the top byte either.
void write_le32(std::uint32_t value, std::uint8_t* out) noexcept {
  for (unsigned i = 0; i < sizeof(std::uint32_t); ++i) {
    out[i] = static_cast<std::uint8_t>(value >> (8U * i));
  }
}

void write_le64(std::uint64_t value, std::uint8_t* out) noexcept {
  for (unsigned i = 0; i < sizeof(std::uint64_t); ++i) {
    out[i] = static_cast<std::uint8_t>(value >> (8U * i));
  }
}

void write_raw(const std::uint8_t* src, std::size_t size, std::uint8_t* out) noexcept {
  std::copy_n(src, size, out);
}

}  // namespace

std::array<std::uint8_t, kHeaderPreimageSize> header_preimage(const BlockHeader& header) noexcept {
  std::array<std::uint8_t, kHeaderPreimageSize> out{};
  std::uint8_t* bytes = out.data();

  write_raw(kHeaderTag, kHeaderTagSize, bytes);
  write_le32(header.version, bytes + kVersionOffset);
  write_le32(header.chain, bytes + kChainOffset);
  write_le64(header.height, bytes + kHeightOffset);
  // The digests go in as stored: `extend_from_slice(&hash.0)` in the reference
  // is a plain byte copy, with no reversal into the display ("little-endian
  // hex") order anywhere.
  write_raw(header.previous_hash.bytes.data(), Hash256::kWidth, bytes + kPreviousHashOffset);
  write_raw(header.merkle_root.bytes.data(), Hash256::kWidth, bytes + kMerkleRootOffset);
  write_le64(header.timestamp, bytes + kTimestampOffset);
  write_le32(header.difficulty_bits, bytes + kBitsOffset);
  bytes[kEngineOffset] = header.engine_id;
  // `header.nonce` is deliberately unread here: the engine appends it after the
  // preimage is built (C-4), and this module does not run an engine.
  return out;
}

const char* block_error_kind_name(BlockErrorKind kind) noexcept {
  switch (kind) {
    case BlockErrorKind::kNone:
      return "None";
    case BlockErrorKind::kWrongChain:
      return "WrongChain";
    case BlockErrorKind::kBadHeight:
      return "BadHeight";
    case BlockErrorKind::kRootMismatch:
      // The reference's name is `BlockError::RootMismatch`; the fixture asserts
      // it verbatim, and it has no payload to name afterwards (C-14).
      return "RootMismatch";
  }
  return "Unknown";
}

BlockIdentityError validate_header_identity(const BlockHeader& header,
                                            std::uint32_t expected_chain,
                                            std::uint64_t expected_height) noexcept {
  // Chain first. `validate_structure` in the reference calls this before any
  // height-dependent lookup, and the fixture pins the order by asserting
  // `WrongChain` for a header that is wrong about both (C-13, C-29).
  if (header.chain != expected_chain) {
    return BlockIdentityError{BlockErrorKind::kWrongChain, expected_chain, header.chain, 0, 0};
  }
  if (header.height != expected_height) {
    return BlockIdentityError{BlockErrorKind::kBadHeight, 0, 0, expected_height, header.height};
  }
  return BlockIdentityError{};
}

// The last field ends exactly where the frozen total says it does; a layout
// change that adds or removes a byte fails to compile instead of silently
// truncating the array.
static_assert(kEngineOffset + sizeof(std::uint8_t) == kHeaderPreimageSize,
              "the derived offsets must cover the frozen 107-byte preimage");
static_assert(kPreviousHashOffset == 30 && kMerkleRootOffset == 62 && kTimestampOffset == 94 &&
                  kBitsOffset == 102 && kEngineOffset == 106,
              "the field positions the P3.1A corpus pins");

}  // namespace zk
