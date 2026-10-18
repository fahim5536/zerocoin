// Bitcoin's CompactSize unsigned integer encoding, mirroring the `write_varint`
// and `Cursor::read_varint` pair in zerocoin/src/ledger/transaction.rs.
//
// The reader refuses non-minimal encodings: a value must use the shortest form
// available, so a transaction has exactly one canonical byte string and
// therefore exactly one txid.

#ifndef ZEROCOIN_KERNEL_VARINT_H
#define ZEROCOIN_KERNEL_VARINT_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace zk {

inline constexpr std::uint8_t kVarIntPrefix16 = 0xfd;
inline constexpr std::uint8_t kVarIntPrefix32 = 0xfe;
inline constexpr std::uint8_t kVarIntPrefix64 = 0xff;

/// Highest value that encodes as a single byte.
inline constexpr std::uint64_t kVarIntDirectMax = 0xfc;
/// Highest value that encodes with the 0xfd prefix.
inline constexpr std::uint64_t kVarInt16Max = 0xffff;
/// Highest value that encodes with the 0xfe prefix.
inline constexpr std::uint64_t kVarInt32Max = 0xffff'ffff;
/// Widest possible encoding: one prefix byte plus eight payload bytes.
inline constexpr std::size_t kVarIntMaxBytes = 9;

/// Encoded length of `value` in bytes.
std::size_t varint_size(std::uint64_t value) noexcept;

/// Appends the minimal CompactSize encoding of `value`.
void write_varint(std::uint64_t value, std::vector<std::uint8_t>& out);

enum class VarIntStatus : std::uint8_t {
  Ok = 0,
  Truncated,
  NonMinimal,
};

/// Reads one CompactSize value starting at `offset` and advances it on success.
/// On failure `offset` is left where the caller can resume diagnostics from.
VarIntStatus read_varint(const std::uint8_t* data, std::size_t size, std::size_t& offset,
                         std::uint64_t& value) noexcept;

static_assert(kVarIntDirectMax == 0xfc, "one byte holds 0..=0xfc");
static_assert(kVarInt16Max == 0xffff, "two bytes hold up to 0xffff");
static_assert(kVarInt32Max == 0xffff'ffffull, "four bytes hold up to 0xffffffff");
static_assert(kVarIntMaxBytes == 1 + 8, "the widest form is a prefix plus eight bytes");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_VARINT_H
