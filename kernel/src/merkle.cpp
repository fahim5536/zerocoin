// Leaf-level Merkle root. See merkle.h for the C-5 contract, the null-pointer
// rule and the list of things this module deliberately does not do.

#include "zerocoin/merkle.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>
#include <vector>

namespace zk {
namespace {

/// One internal node: `sha256d(left || right)` over the two children as stored.
///
/// This mirrors `let mut pair = [0u8; 64]; pair[..32].copy_from_slice(&left.0);
/// pair[32..].copy_from_slice(&right.0); sha256d(&pair)` — the buffer width is
/// `kMerklePairSize`, so the 64-byte input length is structural instead of
/// recomputed, and there is no node tag, separator or length prefix that could
/// be added by mistake. The copy is byte for byte in storage order: no reversal
/// into display form happens here (that would be a different digest).
Hash256 combine(const Hash256& left, const Hash256& right) noexcept {
  std::array<std::uint8_t, kMerklePairSize> pair{};
  std::copy_n(left.bytes.begin(), Hash256::kWidth, pair.begin());
  std::copy_n(right.bytes.begin(), Hash256::kWidth, pair.begin() + Hash256::kWidth);
  return sha256d(pair.data(), pair.size());
}

/// How many nodes a level of `width` reduces to: `width.div_ceil(2)` in the
/// reference. Spelled as `width / 2 + width % 2` so the arithmetic never forms a
/// `width + 1` that could wrap.
constexpr std::size_t parents_of(std::size_t width) noexcept {
  return width / 2 + width % 2;
}

}  // namespace

Hash256 merkle_root(const Hash256* leaves, std::size_t count) noexcept {
  // The order is the reference's: `if leaves.is_empty()` is decided before the
  // slice is copied, so nothing here reads `leaves` when `count == 0`. That is
  // what makes a null pointer with a zero count well defined rather than a
  // latent dereference.
  if (count == 0) {
    return sha256d(kEmptyMerkleTag, kEmptyMerkleTagSize);
  }

  // A single leaf is already the root: the reference copies the leaves and then
  // its `while level.len() > 1` body never runs, so no hash is applied to the
  // leaf. This branch exists to keep that visible; `merkle_root(&a, 1)` and
  // `merkle_root(&a, 2)` with the same leaf therefore differ, which is exactly
  // what a promoted-single-leaf rule would get wrong.
  if (count == 1) {
    return leaves[0];
  }

  // `level` is the caller's leaves, in order. `next` is built into a separate
  // buffer each round, so nothing writes an element that a later pair in the
  // same round still has to read.
  std::vector<Hash256> level(leaves, leaves + count);
  while (level.size() > 1) {
    std::vector<Hash256> next;
    next.reserve(parents_of(level.size()));

    // Index of the final node of this level. `level.size() >= 2` in the loop
    // body, so the subtraction cannot underflow, and testing `i < last` avoids
    // ever using `i + 1` as a bound that could wrap.
    const std::size_t last = level.size() - 1;
    // Step by two over an even-or-odd width: on the last step of an odd level,
    // `i` is `size - 1` and `i += 2` lands on `size + 1`, which is still short of
    // any `std::size_t` overflow (that would need an unrepresentable allocation),
    // so the loop terminates by comparison alone.
    for (std::size_t i = 0; i < level.size(); i += 2) {
      const Hash256& left = level[i];
      // Odd level: the final node pairs with a copy of itself rather than being
      // promoted (C-5). Even position: pair with the immediate successor, so the
      // leaf order survives every level.
      const Hash256& right = (i < last) ? level[i + 1] : level[i];
      next.push_back(combine(left, right));
    }
    level = std::move(next);
  }
  return level[0];
}

// The pairing rule is width-driven, so the reduction arithmetic above is only
// exact for the level widths it was written against. These fail to compile if
// `parents_of` stops matching the duplicate-the-last-node rule.
static_assert(parents_of(1) == 1, "a level of one node is already the root");
static_assert(parents_of(2) == 1, "an even level of two folds to one");
static_assert(parents_of(3) == 2, "an odd level duplicates the last node, it does not drop it");
static_assert(parents_of(9) == 5, "the widths the P3.2B corpus reduces through");

}  // namespace zk
