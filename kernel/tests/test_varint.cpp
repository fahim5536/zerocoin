#include "test_framework.h"

#include "zerocoin/hex.h"
#include "zerocoin/varint.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {

using zk::VarIntStatus;

std::vector<std::uint8_t> encode(std::uint64_t value) {
  std::vector<std::uint8_t> out;
  zk::write_varint(value, out);
  return out;
}

std::string encode_hex(std::uint64_t value) {
  const std::vector<std::uint8_t> bytes = encode(value);
  return zk::to_hex(bytes.data(), bytes.size());
}

struct VarIntVector {
  std::uint64_t value;
  const char* bytes_hex;
};

// The encoding.varint.* corpus, boundary by boundary.
constexpr VarIntVector kVarIntVectors[] = {
    {0, "00"},
    {1, "01"},
    {252, "fc"},
    {253, "fdfd00"},
    {65'535, "fdffff"},
    {65'536, "fe00000100"},
    {4'294'967'295, "feffffffff"},
    {4'294'967'296, "ff0000000001000000"},
    {18'446'744'073'709'551'615ull, "ffffffffffffffffff"},
};

VarIntStatus decode_hex(const std::string& text, std::uint64_t& value, std::size_t& offset) {
  const auto bytes = zk::from_hex(text);
  ZK_CHECK(bytes.has_value());
  offset = 0;
  return zk::read_varint(bytes->data(), bytes->size(), offset, value);
}

}  // namespace

ZK_TEST(varint_encodes_every_boundary) {
  for (const VarIntVector& vector : kVarIntVectors) {
    ZK_CHECK(encode_hex(vector.value) == vector.bytes_hex);
  }
}

ZK_TEST(varint_size_matches_the_encoding) {
  for (const VarIntVector& vector : kVarIntVectors) {
    ZK_CHECK(zk::varint_size(vector.value) == encode(vector.value).size());
  }
  ZK_CHECK(zk::varint_size(0) == 1);
  ZK_CHECK(zk::varint_size(zk::kVarIntDirectMax) == 1);
  ZK_CHECK(zk::varint_size(zk::kVarIntDirectMax + 1) == 3);
  ZK_CHECK(zk::varint_size(zk::kVarInt16Max) == 3);
  ZK_CHECK(zk::varint_size(zk::kVarInt16Max + 1) == 5);
  ZK_CHECK(zk::varint_size(zk::kVarInt32Max) == 5);
  ZK_CHECK(zk::varint_size(std::uint64_t{zk::kVarInt32Max} + 1) == 9);
  ZK_CHECK(zk::varint_size(UINT64_MAX) == zk::kVarIntMaxBytes);
}

ZK_TEST(varint_round_trips_at_every_boundary) {
  for (const VarIntVector& vector : kVarIntVectors) {
    const std::vector<std::uint8_t> bytes = encode(vector.value);
    std::size_t offset = 0;
    std::uint64_t decoded = 0;
    const VarIntStatus status =
        zk::read_varint(bytes.data(), bytes.size(), offset, decoded);
    ZK_CHECK(status == VarIntStatus::Ok);
    ZK_CHECK(decoded == vector.value);
    ZK_CHECK(offset == bytes.size());
  }
}

ZK_TEST(varint_reader_advances_the_offset) {
  const std::vector<std::uint8_t> bytes{0x01, 0xfc, 0xfd, 0xfd, 0x00, 0x7f};
  std::size_t offset = 0;
  std::uint64_t value = 0;

  ZK_CHECK(zk::read_varint(bytes.data(), bytes.size(), offset, value) == VarIntStatus::Ok);
  ZK_CHECK(value == 1);
  ZK_CHECK(offset == 1);

  ZK_CHECK(zk::read_varint(bytes.data(), bytes.size(), offset, value) == VarIntStatus::Ok);
  ZK_CHECK(value == 0xfc);
  ZK_CHECK(offset == 2);

  ZK_CHECK(zk::read_varint(bytes.data(), bytes.size(), offset, value) == VarIntStatus::Ok);
  ZK_CHECK(value == 0xfd);
  ZK_CHECK(offset == 5);

  ZK_CHECK(zk::read_varint(bytes.data(), bytes.size(), offset, value) == VarIntStatus::Ok);
  ZK_CHECK(value == 0x7f);
  ZK_CHECK(offset == 6);
}

ZK_TEST(varint_reports_truncation) {
  std::uint64_t value = 0;
  std::size_t offset = 0;

  ZK_CHECK(decode_hex("", value, offset) == VarIntStatus::Truncated);
  ZK_CHECK(decode_hex("fd", value, offset) == VarIntStatus::Truncated);
  ZK_CHECK(decode_hex("fd01", value, offset) == VarIntStatus::Truncated);
  ZK_CHECK(decode_hex("fe010203", value, offset) == VarIntStatus::Truncated);
  ZK_CHECK(decode_hex("ffffffffffffffff", value, offset) == VarIntStatus::Truncated);
  ZK_CHECK(decode_hex("fdffff", value, offset) == VarIntStatus::Ok);
  ZK_CHECK(value == 0xffff);
}

ZK_TEST(varint_refuses_non_minimal_encodings) {
  std::uint64_t value = 0;
  std::size_t offset = 0;

  ZK_CHECK(decode_hex("fd0000", value, offset) == VarIntStatus::NonMinimal);
  ZK_CHECK(decode_hex("fdfc00", value, offset) == VarIntStatus::NonMinimal);
  ZK_CHECK(decode_hex("feffff0000", value, offset) == VarIntStatus::NonMinimal);
  ZK_CHECK(decode_hex("ff00000000ffffffff", value, offset) == VarIntStatus::Ok);
  ZK_CHECK(value == 0xffff'ffff'0000'0000ull);
  ZK_CHECK(decode_hex("ffffffffff00000000", value, offset) == VarIntStatus::NonMinimal);
}

ZK_TEST(varint_accepts_the_smallest_form_of_each_prefix) {
  std::uint64_t value = 0;
  std::size_t offset = 0;

  ZK_CHECK(decode_hex("fdfd00", value, offset) == VarIntStatus::Ok);
  ZK_CHECK(value == 0xfd);
  ZK_CHECK(decode_hex("fe00000100", value, offset) == VarIntStatus::Ok);
  ZK_CHECK(value == 0x1'0000);
  ZK_CHECK(decode_hex("ff0000000001000000", value, offset) == VarIntStatus::Ok);
  ZK_CHECK(value == 0x1'0000'0000ull);
}

ZK_TEST(varint_reader_leaves_trailing_bytes_alone) {
  std::uint64_t value = 0;
  std::size_t offset = 0;

  ZK_CHECK(decode_hex("00ff", value, offset) == VarIntStatus::Ok);
  ZK_CHECK(value == 0);
  ZK_CHECK(offset == 1);
}

ZK_TEST(varint_encoder_appends_without_clearing) {
  std::vector<std::uint8_t> out{0xaa, 0xbb};
  zk::write_varint(0, out);
  zk::write_varint(0xffff, out);
  ZK_CHECK(out.size() == 6);
  ZK_CHECK(out[0] == 0xaa);
  ZK_CHECK(out[1] == 0xbb);
  ZK_CHECK(out[2] == 0x00);
  ZK_CHECK(out[3] == 0xfd);
  ZK_CHECK(out[4] == 0xff);
  ZK_CHECK(out[5] == 0xff);
}
