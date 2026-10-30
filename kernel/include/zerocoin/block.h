// The claimed-Merkle-root comparison: rule B-14, the part of
// zerocoin/src/consensus/block.rs `Block::validate_structure` that decides
// whether a header commits to the transactions actually present.
//
// The reference site is three lines (block.rs:216-220):
//
//     let root = Self::compute_merkle_root(&self.transactions);
//     if h.merkle_root != root {
//         return Err(BlockError::RootMismatch);
//     }
//
// The kernel has no `Block` type and this file does not create one. The
// reference reaches those lines through `self.header` and `self.transactions`,
// so a header plus a transaction array is the same data: the parameters are the
// two things the rule actually reads, and the function is behaviour-identical to
// the method on the inputs where the method is reachable. The P4.1A corpus
// publishes exactly that shape, which is what makes the equivalence checkable.
//
// What deliberately stays OUT of this module, each for a reason the corpus
// records rather than a reason of taste:
//
//   ordering   B-1 through B-13 run before this comparison and B-15 runs after
//              it. None of them is ported here, so the verdict below is the
//              verdict of the comparison layer, not the verdict a node
//              publishes. The two `boundary` cases in
//              test/p41-vectors/chain/claimed_merkle_root.json exist to make
//              that difference visible rather than to hide it: for an empty
//              transaction list production returns B-8 `NoTransactions` first —
//              published beside the verdict there as `guard_before_comparison` —
//              while the comparison itself does have an answer, because
//              `compute_merkle_root` is defined on an empty slice.
//   count      B-9 `MAX_BLOCK_TRANSACTIONS` is not here. No transaction-count
//              limit appears on this path, matching the reference, which checks
//              the limit in `validate_structure` before reaching the comparison;
//              a second copy inside it would be a different consensus rule.
//   proof      B-15 and C-4 are not here. This function reads no nonce, no
//              `difficulty_bits` and no `timestamp`, and takes no engine: the
//              reference's comparison is reached whether or not the header's
//              work meets its own target, which is what the corpus's two
//              `ordering` cases pin with a real failing nonce.
//   position   B-10 and B-11 (the coinbase must be first, and only once) are not
//              here. The comparison is over the list as given.
//
// The comparison itself is a byte-for-byte equality of two 32-byte digests in
// stored, internal order — the same `!=` Rust performs on `Hash256`. No
// reversal, no hex string, no numeric or lexicographic ordering, no shortened
// prefix. `chain.claimed_merkle_root.display_order_claim` is the case that
// rejects a port which compares the printing form, and it is rejected rather
// than merely untested because the display bytes of a digest are a different
// 32-byte string than its internal bytes.

#ifndef ZEROCOIN_KERNEL_BLOCK_H
#define ZEROCOIN_KERNEL_BLOCK_H

#include <cstddef>
#include <cstdint>

#include "zerocoin/header.h"
#include "zerocoin/transaction.h"

namespace zk {

/// `BlockError::RootMismatch` or nothing: rule B-14 on its own.
///
/// Computes the root of `count` transactions exactly the way the reference does
/// — `merkle_root_from_transactions`, which is `Block::compute_merkle_root` and
/// therefore each transaction's own id, in list order, through the leaf rule —
/// and compares it with the root the header claims. `BlockErrorKind` is declared
/// with the header taxonomy in header.h because it is the same Rust enum
/// (`BlockError`) that the header identity validator already produces; the only
/// variant this function can return is `kRootMismatch`.
///
/// Null-pointer contract, the same shape merkle.h documents: `txs` may be null
/// if and only if `count == 0`, because an empty list produces the tagged
/// empty-tree digest before any buffer is read. That is the reference's own
/// behaviour for `&[]`, and it is why the boundary cases above are comparable
/// even though a node never reaches them. For any other `count`, `txs` must
/// point to `count` valid `Transaction` objects. The range is read, never
/// written, and no transaction is re-ordered, re-encoded or mutated.
///
/// Not `noexcept`: the composition calls `Transaction::serialize()`, which is
/// itself not `noexcept`. An exhausted allocator propagates instead of returning
/// a verdict computed from a partial tree — the same stance
/// `merkle_root_from_transactions` takes, for the same reason.
BlockErrorKind compare_claimed_merkle_root(const BlockHeader& header,
                                           const Transaction* txs,
                                           std::size_t count);

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_BLOCK_H
