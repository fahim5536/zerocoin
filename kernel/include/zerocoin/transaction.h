// Transaction structure and canonical serialisation, mirroring
// zerocoin/src/ledger/transaction.rs.
//
// The serialised byte string is what the txid commits to, so it is consensus
// data: every field is written little-endian in a fixed order and lengths are
// minimal CompactSize varints.

#ifndef ZEROCOIN_KERNEL_TRANSACTION_H
#define ZEROCOIN_KERNEL_TRANSACTION_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "zerocoin/hash.h"
#include "zerocoin/varint.h"

namespace zk {

/// Largest script this decoder will accept, and the same bound the Rust
/// reference applies per script.
inline constexpr std::size_t kMaxTxBytes = 1'000'000;
inline constexpr std::size_t kMaxTxInputs = 10'000;
inline constexpr std::size_t kMaxTxOutputs = 10'000;

/// The `vout` of the outpoint a coinbase spends.
inline constexpr std::uint32_t kNullVout = 0xffff'ffff;

/// A reference to one output of one earlier transaction.
struct Outpoint {
  Hash256 txid{};
  std::uint32_t vout = 0;

  /// The all-zero txid plus `vout == 0xffffffff`: unspendable by construction.
  static Outpoint null() noexcept { return Outpoint{Hash256::zero(), kNullVout}; }

  [[nodiscard]] bool is_null() const noexcept { return vout == kNullVout && txid.is_zero(); }

  friend constexpr bool operator==(const Outpoint& lhs, const Outpoint& rhs) noexcept {
    return lhs.vout == rhs.vout && lhs.txid == rhs.txid;
  }
  friend constexpr bool operator!=(const Outpoint& lhs, const Outpoint& rhs) noexcept {
    return !(lhs == rhs);
  }
};

struct TxIn {
  Outpoint previous_output{};
  std::vector<std::uint8_t> script_sig;
  std::uint32_t sequence = 0;

  friend bool operator==(const TxIn& lhs, const TxIn& rhs) {
    return lhs.previous_output == rhs.previous_output && lhs.script_sig == rhs.script_sig &&
           lhs.sequence == rhs.sequence;
  }
  friend bool operator!=(const TxIn& lhs, const TxIn& rhs) { return !(lhs == rhs); }
};

struct TxOut {
  std::uint64_t value = 0;
  std::vector<std::uint8_t> script_pubkey;

  friend bool operator==(const TxOut& lhs, const TxOut& rhs) {
    return lhs.value == rhs.value && lhs.script_pubkey == rhs.script_pubkey;
  }
  friend bool operator!=(const TxOut& lhs, const TxOut& rhs) { return !(lhs == rhs); }
};

struct Transaction {
  std::int32_t version = 0;
  std::vector<TxIn> inputs;
  std::vector<TxOut> outputs;
  std::uint32_t lock_time = 0;

  /// Canonical encoding; the byte string the txid commits to.
  std::vector<std::uint8_t> serialize() const;

  /// Double SHA-256 of `serialize()`.
  Hash256 txid() const;

  /// True when there is exactly one input and it spends the null outpoint.
  [[nodiscard]] bool is_coinbase() const noexcept;

  /// Sum of the output values, or `nullopt` if the sum would overflow.
  [[nodiscard]] std::optional<std::uint64_t> output_value() const noexcept;

  friend bool operator==(const Transaction& lhs, const Transaction& rhs) {
    return lhs.version == rhs.version && lhs.inputs == rhs.inputs &&
           lhs.outputs == rhs.outputs && lhs.lock_time == rhs.lock_time;
  }
  friend bool operator!=(const Transaction& lhs, const Transaction& rhs) { return !(lhs == rhs); }
};

enum class TxDecodeError : std::uint8_t {
  None = 0,
  Truncated,
  NonMinimalVarInt,
  TooManyInputs,
  TooManyOutputs,
  ScriptTooLarge,
};

/// Stable spelling used by the conformance runner and the corpus.
const char* to_string(TxDecodeError error) noexcept;

struct TxDecodeResult {
  Transaction tx;
  TxDecodeError error = TxDecodeError::None;
  /// Bytes consumed on success; the decoder does not require them to be all of
  /// the input, matching the reference (finding F-2 in the risk register).
  std::size_t consumed = 0;

  explicit operator bool() const noexcept { return error == TxDecodeError::None; }
};

TxDecodeResult deserialize_transaction(const std::uint8_t* data, std::size_t size) noexcept;

static_assert(kMaxTxBytes == 1'000'000, "the script bound is frozen with the codec");
static_assert(kMaxTxInputs == 10'000, "the input bound is frozen with the codec");
static_assert(kMaxTxOutputs == 10'000, "the output bound is frozen with the codec");
static_assert(kNullVout == 0xffff'ffff, "the null outpoint is all ones");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_TRANSACTION_H
