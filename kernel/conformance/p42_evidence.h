// P4.2B-4F evidence rendering, shared by `conformance/main.cpp` and
// `tests/test_p42_evidence.cpp`.
//
// `leaves` is field 1 of the five P4.2B-4F fields. The canonical OUT text,
// agreed with tools/p42_conformance.py, is one `internal_hex|display_hex`
// pair per transaction in list order, `;`-joined; the empty list renders as
// the literal `[]` so an absent key and an empty list stay distinguishable.
//
// The runner publishes the key only when the fixture declares `OUT leaves`,
// which is exactly the reference's verbose gate: the P4.2 corpus publishes
// the key only for eight or fewer transactions, so an over-limit list keeps
// the key absent. The gate is the fixture's declaration, not a count compared
// here — the limit lives in the exporter, and this file renders whatever list
// it is handed.

#ifndef ZEROCOIN_KERNEL_CONFORMANCE_P42_EVIDENCE_H
#define ZEROCOIN_KERNEL_CONFORMANCE_P42_EVIDENCE_H

#include <optional>
#include <string>
#include <vector>

#include "zerocoin/transaction.h"

namespace p42_evidence {

/// One `internal_hex|display_hex` per transaction in list order, `;`-joined;
/// the empty list is the literal `[]`.
inline std::string leaves_text(const std::vector<zk::Transaction>& transactions) {
  if (transactions.empty()) {
    return "[]";
  }
  std::string text;
  for (const zk::Transaction& tx : transactions) {
    const auto id = tx.txid();  // one sha256d per transaction, no second call
    if (!text.empty()) {
      text += ';';
    }
    text += id.to_hex().str();
    text += '|';
    text += id.to_display_hex().str();
  }
  return text;
}

/// The rendered key when the fixture declares it, nothing otherwise.
inline std::optional<std::string> leaves_out(
    const std::vector<zk::Transaction>& transactions, bool declared) {
  if (!declared) {
    return std::nullopt;
  }
  return leaves_text(transactions);
}

}  // namespace p42_evidence

#endif  // ZEROCOIN_KERNEL_CONFORMANCE_P42_EVIDENCE_H
