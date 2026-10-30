#include "zerocoin/block.h"

#include "zerocoin/merkle.h"

namespace zk {

BlockErrorKind compare_claimed_merkle_root(const BlockHeader& header,
                                           const Transaction* txs,
                                           std::size_t count) {
  // `Block::compute_merkle_root`, and nothing else: the ids are taken in list
  // order by the composition, the leaf rule then applies C-5. No digest is
  // reversed, re-encoded or re-hashed on the way, and no count limit is applied
  // — both would be a second, different rule.
  const Hash256 root = merkle_root_from_transactions(txs, count);

  // The reference compares the digests as stored. `Hash256::operator!=` is the
  // byte array comparison, so this is the same three lines block.rs writes.
  if (header.merkle_root != root) {
    return BlockErrorKind::kRootMismatch;
  }
  return BlockErrorKind::kNone;
}

}  // namespace zk
