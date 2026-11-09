// P4.2B-4F, field 1 of 5: `leaves` — the ordered per-transaction txid list the
// P4.2 corpus publishes for verbose cases (eight or fewer transactions).
//
// Six focused behaviours, labelled A through F after the milestone's spec:
//
//   A  every leaf in a multi-transaction list carries the transaction's own
//      internal and display txid;
//   B  leaf order follows the transaction list order, not any other order;
//   C  an empty list renders as the literal `[]`;
//   D  a declared eight-transaction list publishes the key with eight entries;
//   E  an undeclared nine-transaction list publishes no key at all;
//   F  the renderer agrees with txids computed independently here through the
//      raw `serialize()` + `sha256d` path rather than through `Transaction::
//      txid()`, so the check is not a self-comparison.
//
// None of this touches production consensus code: the subject is the
// conformance-side renderer in conformance/p42_evidence.h, and the gate it
// tests — declaration-driven emission — is what makes the reference's verbose
// limit (the corpus publishes `leaves` only for eight or fewer transactions)
// fall out of the fixture without hardcoding the number 8 in the runner.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "test_framework.h"
#include "zerocoin/hash.h"
#include "zerocoin/transaction.h"

#include "../conformance/p42_evidence.h"

namespace {

using zk::Hash256;
using zk::Outpoint;
using zk::Transaction;
using zk::TxIn;
using zk::TxOut;

// Byte-ramp hash, so every ordinary transaction spends a distinct outpoint and
// every transaction serialises to distinct bytes.
Hash256 ramp(std::uint8_t seed) {
  Hash256 value{};
  for (std::size_t i = 0; i < Hash256::kWidth; ++i) {
    value.bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  return value;
}

std::vector<std::uint8_t> script_of(std::size_t index) {
  return {0x51, static_cast<std::uint8_t>(index >> 24), static_cast<std::uint8_t>(index >> 16),
          static_cast<std::uint8_t>(index >> 8), static_cast<std::uint8_t>(index)};
}

/// A coinbase by the reference's shape: exactly one input, spending the null
/// outpoint.
Transaction coinbase(std::size_t index) {
  Transaction tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{Outpoint::null(), script_of(index), 0xffff'ffff});
  tx.outputs.push_back(TxOut{5'000'000'000ull + index, script_of(index + 1)});
  tx.lock_time = 0;
  return tx;
}

/// An ordinary transaction: one input that spends a real-looking outpoint.
Transaction ordinary(std::size_t index) {
  Transaction tx;
  tx.version = 1;
  tx.inputs.push_back(
      TxIn{Outpoint{ramp(static_cast<std::uint8_t>(index)), 0}, script_of(index), 0xffff'ffff});
  tx.outputs.push_back(TxOut{1'000ull + index, script_of(index + 2)});
  tx.lock_time = 0;
  return tx;
}

/// The list a valid block is expected to carry: the coinbase first, then
/// `count - 1` ordinary transactions.
std::vector<Transaction> tx_list(std::size_t count) {
  std::vector<Transaction> txs;
  txs.reserve(count);
  if (count > 0) {
    txs.push_back(coinbase(0));
  }
  for (std::size_t i = 1; i < count; ++i) {
    txs.push_back(ordinary(i));
  }
  return txs;
}

/// `leaves_text` renders one `internal|display` per transaction, `;`-joined.
std::vector<std::string> split_leaves(const std::string& text) {
  std::vector<std::string> entries;
  std::size_t start = 0;
  while (true) {
    const std::size_t end = text.find(';', start);
    if (end == std::string::npos) {
      entries.push_back(text.substr(start));
      return entries;
    }
    entries.push_back(text.substr(start, end - start));
    start = end + 1;
  }
}

/// The txid computed independently of `Transaction::txid()`: the same bytes
/// through a different call path, for test F.
std::string expected_leaf(const Transaction& tx) {
  const std::vector<std::uint8_t> raw = tx.serialize();
  const Hash256 id = zk::sha256d(raw.data(), raw.size());
  return id.to_hex().str() + "|" + id.to_display_hex().str();
}

ZK_TEST(p42_evidence_leaves_multi_tx_correct) {  // A
  const std::vector<Transaction> txs = {coinbase(0), ordinary(1), ordinary(2)};
  const std::vector<std::string> entries = split_leaves(p42_evidence::leaves_text(txs));
  ZK_CHECK(entries.size() == 3);
  for (std::size_t i = 0; i < txs.size(); ++i) {
    const Hash256 id = txs[i].txid();
    ZK_CHECK(entries[i] == id.to_hex().str() + "|" + id.to_display_hex().str());
  }
}

ZK_TEST(p42_evidence_leaves_order_follows_list) {  // B
  const Transaction cb = coinbase(0);
  const Transaction first = ordinary(1);
  const Transaction second = ordinary(2);
  const std::vector<Transaction> forward = {cb, first, second};
  const std::vector<Transaction> reversed = {second, first, cb};
  const std::vector<std::string> forward_entries =
      split_leaves(p42_evidence::leaves_text(forward));
  const std::vector<std::string> reversed_entries =
      split_leaves(p42_evidence::leaves_text(reversed));
  ZK_CHECK(forward_entries.size() == 3);
  ZK_CHECK(reversed_entries.size() == 3);
  ZK_CHECK(forward_entries[0] == reversed_entries[2]);
  ZK_CHECK(forward_entries[1] == reversed_entries[1]);
  ZK_CHECK(forward_entries[2] == reversed_entries[0]);
  ZK_CHECK(forward_entries[0] != forward_entries[2]);
}

ZK_TEST(p42_evidence_leaves_empty_list) {  // C
  const std::vector<Transaction> none;
  ZK_CHECK(p42_evidence::leaves_text(none) == "[]");
}

ZK_TEST(p42_evidence_leaves_eight_declared_present) {  // D
  const std::vector<Transaction> txs = tx_list(8);
  const std::optional<std::string> out = p42_evidence::leaves_out(txs, true);
  ZK_CHECK(out.has_value());
  ZK_CHECK(split_leaves(*out).size() == 8);
}

ZK_TEST(p42_evidence_leaves_nine_undeclared_absent) {  // E
  const std::vector<Transaction> txs = tx_list(9);
  ZK_CHECK(!p42_evidence::leaves_out(txs, false).has_value());
}

ZK_TEST(p42_evidence_leaves_independent_txids) {  // F
  const std::vector<Transaction> txs = {coinbase(0), ordinary(1), ordinary(2), ordinary(3)};
  const std::vector<std::string> entries = split_leaves(p42_evidence::leaves_text(txs));
  ZK_CHECK(entries.size() == 4);
  for (std::size_t i = 0; i < txs.size(); ++i) {
    ZK_CHECK(entries[i] == expected_leaf(txs[i]));
  }
}

}  // namespace
