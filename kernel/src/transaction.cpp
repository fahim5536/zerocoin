#include "zerocoin/transaction.h"

#include <cstring>
#include <limits>
#include <utility>

namespace zk {
namespace {

void append_le32(std::uint32_t value, std::vector<std::uint8_t>& out) {
  out.push_back(static_cast<std::uint8_t>(value));
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value >> 16));
  out.push_back(static_cast<std::uint8_t>(value >> 24));
}

void append_le64(std::uint64_t value, std::vector<std::uint8_t>& out) {
  for (unsigned i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
  }
}

/// A bounded reader over a byte range that refuses to run off the end.
class Cursor {
 public:
  Cursor(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

  std::size_t offset() const noexcept { return offset_; }

  bool read(std::uint8_t* out, std::size_t count) noexcept {
    if (size_ - offset_ < count) {
      return false;
    }
    std::memcpy(out, data_ + offset_, count);
    offset_ += count;
    return true;
  }

  bool read_bytes(std::size_t count, std::vector<std::uint8_t>& out) {
    if (size_ - offset_ < count) {
      return false;
    }
    out.assign(data_ + offset_, data_ + offset_ + count);
    offset_ += count;
    return true;
  }

  bool read_le32(std::uint32_t& out) noexcept {
    std::uint8_t raw[4];
    if (!read(raw, sizeof(raw))) {
      return false;
    }
    out = static_cast<std::uint32_t>(raw[0]) | (static_cast<std::uint32_t>(raw[1]) << 8) |
          (static_cast<std::uint32_t>(raw[2]) << 16) | (static_cast<std::uint32_t>(raw[3]) << 24);
    return true;
  }

  bool read_le64(std::uint64_t& out) noexcept {
    std::uint8_t raw[8];
    if (!read(raw, sizeof(raw))) {
      return false;
    }
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
      value |= static_cast<std::uint64_t>(raw[i]) << (8 * i);
    }
    out = value;
    return true;
  }

  VarIntStatus read_varint(std::uint64_t& out) noexcept {
    std::size_t next = offset_;
    const VarIntStatus status = zk::read_varint(data_, size_, next, out);
    if (status == VarIntStatus::Ok) {
      offset_ = next;
    }
    return status;
  }

 private:
  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t offset_ = 0;
};

TxDecodeError varint_error(VarIntStatus status) noexcept {
  switch (status) {
    case VarIntStatus::Ok:
      return TxDecodeError::None;
    case VarIntStatus::Truncated:
      return TxDecodeError::Truncated;
    case VarIntStatus::NonMinimal:
      return TxDecodeError::NonMinimalVarInt;
  }
  return TxDecodeError::Truncated;
}

}  // namespace

std::vector<std::uint8_t> Transaction::serialize() const {
  std::vector<std::uint8_t> out;

  append_le32(static_cast<std::uint32_t>(version), out);

  write_varint(inputs.size(), out);
  for (const TxIn& input : inputs) {
    out.insert(out.end(), input.previous_output.txid.bytes.begin(),
               input.previous_output.txid.bytes.end());
    append_le32(input.previous_output.vout, out);
    write_varint(input.script_sig.size(), out);
    out.insert(out.end(), input.script_sig.begin(), input.script_sig.end());
    append_le32(input.sequence, out);
  }

  write_varint(outputs.size(), out);
  for (const TxOut& output : outputs) {
    append_le64(output.value, out);
    write_varint(output.script_pubkey.size(), out);
    out.insert(out.end(), output.script_pubkey.begin(), output.script_pubkey.end());
  }

  append_le32(lock_time, out);
  return out;
}

Hash256 Transaction::txid() const {
  const std::vector<std::uint8_t> bytes = serialize();
  return sha256d(bytes.data(), bytes.size());
}

bool Transaction::is_coinbase() const noexcept {
  return inputs.size() == 1 && inputs[0].previous_output.is_null();
}

std::optional<std::uint64_t> Transaction::output_value() const noexcept {
  std::uint64_t total = 0;
  for (const TxOut& output : outputs) {
    if (total > std::numeric_limits<std::uint64_t>::max() - output.value) {
      return std::nullopt;
    }
    total += output.value;
  }
  return total;
}

const char* to_string(TxDecodeError error) noexcept {
  switch (error) {
    case TxDecodeError::None:
      return "None";
    case TxDecodeError::Truncated:
      return "Truncated";
    case TxDecodeError::NonMinimalVarInt:
      return "NonMinimalVarInt";
    case TxDecodeError::TooManyInputs:
      return "TooManyInputs";
    case TxDecodeError::TooManyOutputs:
      return "TooManyOutputs";
    case TxDecodeError::ScriptTooLarge:
      return "ScriptTooLarge";
  }
  return "Unknown";
}

TxDecodeResult deserialize_transaction(const std::uint8_t* data, std::size_t size) noexcept {
  TxDecodeResult result;
  Cursor cursor(data, size);

  std::uint32_t version = 0;
  if (!cursor.read_le32(version)) {
    result.error = TxDecodeError::Truncated;
    return result;
  }
  result.tx.version = static_cast<std::int32_t>(version);

  std::uint64_t input_count = 0;
  TxDecodeError error = varint_error(cursor.read_varint(input_count));
  if (error != TxDecodeError::None) {
    result.error = error;
    return result;
  }
  if (input_count > kMaxTxInputs) {
    result.error = TxDecodeError::TooManyInputs;
    return result;
  }
  result.tx.inputs.reserve(static_cast<std::size_t>(input_count));

  for (std::uint64_t i = 0; i < input_count; ++i) {
    TxIn input;
    if (!cursor.read(input.previous_output.txid.bytes.data(), Hash256::kWidth)) {
      result.error = TxDecodeError::Truncated;
      return result;
    }
    if (!cursor.read_le32(input.previous_output.vout)) {
      result.error = TxDecodeError::Truncated;
      return result;
    }
    std::uint64_t script_len = 0;
    error = varint_error(cursor.read_varint(script_len));
    if (error != TxDecodeError::None) {
      result.error = error;
      return result;
    }
    if (script_len > kMaxTxBytes) {
      result.error = TxDecodeError::ScriptTooLarge;
      return result;
    }
    if (!cursor.read_bytes(static_cast<std::size_t>(script_len), input.script_sig)) {
      result.error = TxDecodeError::Truncated;
      return result;
    }
    if (!cursor.read_le32(input.sequence)) {
      result.error = TxDecodeError::Truncated;
      return result;
    }
    result.tx.inputs.push_back(std::move(input));
  }

  std::uint64_t output_count = 0;
  error = varint_error(cursor.read_varint(output_count));
  if (error != TxDecodeError::None) {
    result.error = error;
    return result;
  }
  if (output_count > kMaxTxOutputs) {
    result.error = TxDecodeError::TooManyOutputs;
    return result;
  }
  result.tx.outputs.reserve(static_cast<std::size_t>(output_count));

  for (std::uint64_t i = 0; i < output_count; ++i) {
    TxOut output;
    if (!cursor.read_le64(output.value)) {
      result.error = TxDecodeError::Truncated;
      return result;
    }
    std::uint64_t script_len = 0;
    error = varint_error(cursor.read_varint(script_len));
    if (error != TxDecodeError::None) {
      result.error = error;
      return result;
    }
    if (script_len > kMaxTxBytes) {
      result.error = TxDecodeError::ScriptTooLarge;
      return result;
    }
    if (!cursor.read_bytes(static_cast<std::size_t>(script_len), output.script_pubkey)) {
      result.error = TxDecodeError::Truncated;
      return result;
    }
    result.tx.outputs.push_back(std::move(output));
  }

  if (!cursor.read_le32(result.tx.lock_time)) {
    result.error = TxDecodeError::Truncated;
    return result;
  }

  result.consumed = cursor.offset();
  return result;
}

}  // namespace zk
