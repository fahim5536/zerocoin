// Merkle root tests: the leaf-level rule and the transaction-level composition.
// The corpora in test/p32-vectors/chain/ and test/p33-vectors/chain/ are the
// value oracles (kernel/tools/p32_conformance.py and p33_conformance.py replay
// them byte for byte), so nothing here copies an expected root out of a fixture
// and no test types a hash by hand. What these tests pin instead is the
// structure a fixed corpus cannot express on its own: which branch produces
// which digest, the direction of the bytes inside a pair, the level at which the
// odd node gets duplicated, the fact that order matters, that the composition
// adds nothing between a transaction's id and its leaf, and that neither entry
// point has a count limit.
//
// Three helpers do the independent work. `fold_pair` re-derives one internal
// node from the C-5 wording instead of calling anything in merkle.cpp,
// `spec_root` is a second, differently-shaped implementation of the whole loop
// (it widens an odd level by copying its last node, then folds pairs with no odd
// case left in it), and `id_from_encoding` re-derives a transaction id from the
// C-2 wording instead of calling `Transaction::txid()`. A mutation in merkle.cpp
// therefore disagrees with this file rather than being repeated by it.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.h"
#include "zerocoin/hash.h"
#include "zerocoin/hex.h"
#include "zerocoin/merkle.h"
#include "zerocoin/transaction.h"

namespace {

using zk::Hash256;
using zk::Outpoint;
using zk::Transaction;
using zk::TxIn;
using zk::TxOut;

constexpr std::size_t kWidth = Hash256::kWidth;
constexpr std::size_t kPair = kWidth * 2;

// A leaf of one repeated byte.
Hash256 filled(std::uint8_t value) {
  Hash256 leaf{};
  leaf.bytes.fill(value);
  return leaf;
}

// A leaf with pairwise distinct, asymmetric bytes, so a reversal, a rotation or
// a wrong-offset copy can never equal what it replaced.
Hash256 ramp(std::uint8_t seed) {
  Hash256 leaf{};
  for (std::size_t i = 0; i < kWidth; ++i) {
    leaf.bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  return leaf;
}

std::vector<Hash256> ramps(std::size_t count, std::uint8_t seed) {
  std::vector<Hash256> leaves;
  leaves.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    leaves.push_back(ramp(static_cast<std::uint8_t>(seed + i)));
  }
  return leaves;
}

Hash256 root_of(const std::vector<Hash256>& leaves) noexcept {
  return zk::merkle_root(leaves.data(), leaves.size());
}

/// One internal node, written from `sha256d(left_internal || right_internal)`.
/// Deliberately not the implementation under test.
Hash256 fold_pair(const Hash256& left, const Hash256& right) {
  std::array<std::uint8_t, kPair> buffer{};
  std::copy_n(left.bytes.begin(), kWidth, buffer.begin());
  std::copy_n(right.bytes.begin(), kWidth, buffer.begin() + kWidth);
  return zk::sha256d(buffer.data(), buffer.size());
}

/// A second implementation of the whole reduction, shaped differently from
/// merkle.cpp: an odd level is widened with a copy of its own final node first,
/// after which every fold is an unguarded pair. Equal rules, different code.
Hash256 spec_root(const std::vector<Hash256>& leaves) {
  if (leaves.empty()) {
    return zk::sha256d(zk::kEmptyMerkleTag, zk::kEmptyMerkleTagSize);
  }
  std::vector<Hash256> level = leaves;
  while (level.size() > 1) {
    if (level.size() % 2 != 0) {
      level.push_back(level.back());
    }
    std::vector<Hash256> parents;
    parents.reserve(level.size() / 2);
    for (std::size_t i = 0; i < level.size(); i += 2) {
      parents.push_back(fold_pair(level[i], level[i + 1]));
    }
    level = std::move(parents);
  }
  return level.front();
}

std::vector<Hash256> concat(const Hash256& a, const Hash256& b) { return {a, b}; }

// A transaction whose every field is a function of one seed byte, so a list of
// them is a list of distinct serialisations that needs no lookup table. The same
// shape the P3.3B corpus uses for its width cases.
Transaction seeded(std::uint8_t seed) {
  Transaction tx;
  tx.version = 1;
  tx.inputs.push_back(
      TxIn{Outpoint{ramp(seed), seed}, {seed, static_cast<std::uint8_t>(seed + 1)}, 0xffff'ffff});
  tx.outputs.push_back(
      TxOut{(static_cast<std::uint64_t>(seed) + 1) * 1000, {0x76, 0xa9, 0x14, seed}});
  tx.lock_time = seed;
  return tx;
}

/// A coinbase by shape: one input that spends the null outpoint. Used to show the
/// composition never consults it — B-12 and B-13 belong to `validate_structure`.
Transaction coinbase_like(std::uint8_t seed) {
  Transaction tx;
  tx.version = 1;
  tx.inputs.push_back(
      TxIn{Outpoint::null(), {seed, static_cast<std::uint8_t>(seed + 1)}, 0xffff'ffff});
  tx.outputs.push_back(
      TxOut{(static_cast<std::uint64_t>(seed) + 1) * 1000, {0x76, 0xa9, 0x14, seed}});
  tx.lock_time = 0;
  return tx;
}

std::vector<Transaction> seeded_list(std::size_t count, std::uint8_t seed) {
  std::vector<Transaction> txs;
  txs.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    txs.push_back(seeded(static_cast<std::uint8_t>(seed + i)));
  }
  return txs;
}

Hash256 root_of_txs(const std::vector<Transaction>& txs) {
  return zk::merkle_root_from_transactions(txs.data(), txs.size());
}

/// The id re-derived from the C-2 wording — sha256d over the canonical
/// serialisation — which is what `Transaction::txid()` does at
/// `src/transaction.cpp:126-129`. Writing it out here is what catches a
/// composition that fed something else to the tree.
Hash256 id_from_encoding(const Transaction& tx) {
  const std::vector<std::uint8_t> bytes = tx.serialize();
  return zk::sha256d(bytes.data(), bytes.size());
}

std::vector<Hash256> ids_from_encoding(const std::vector<Transaction>& txs) {
  std::vector<Hash256> ids;
  ids.reserve(txs.size());
  for (const Transaction& tx : txs) {
    ids.push_back(id_from_encoding(tx));
  }
  return ids;
}

}  // namespace

ZK_TEST(merkle_empty_tree_is_the_tag_digest_and_reads_nothing) {
  // count == 0 must not touch the pointer, in either spelling.
  const Hash256 sentinel = filled(0xa5);
  const Hash256 via_null = zk::merkle_root(nullptr, 0);
  const Hash256 via_buffer = zk::merkle_root(&sentinel, 0);

  // The expectation is the public hash primitive over the tag, not a call into
  // merkle.cpp.
  const Hash256 expected = zk::sha256d(zk::kEmptyMerkleTag, zk::kEmptyMerkleTagSize);
  ZK_CHECK(via_null == expected);
  ZK_CHECK(via_buffer == expected);
  ZK_CHECK(via_null == via_buffer);

  // Not the zero digest, and not the tag itself: the point of the tag is that
  // the empty tree has a fixed non-zero identity.
  ZK_CHECK(!via_null.is_zero());
  ZK_CHECK(std::equal(std::begin(zk::kEmptyMerkleTag), std::end(zk::kEmptyMerkleTag),
                      via_null.bytes.begin()) == false);
  ZK_CHECK(zk::kEmptyMerkleTagSize == 17);

  // The spelling, not only the length. A one-character change to the tag is a
  // different consensus commitment, and the compile-time freeze in merkle.h can
  // only see the width and the terminating byte — so the ASCII itself is pinned
  // here, against the string the Rust owner writes at
  // `src/consensus/block.rs:28`. The C string's implicit NUL and the Rust
  // literal's explicit `\0` are the same seventeenth byte.
  static constexpr char kExpectedTag[] = "ZRO/merkle:empty";
  static_assert(sizeof(kExpectedTag) == zk::kEmptyMerkleTagSize,
                "the tag is sixteen visible characters plus one NUL");
  ZK_CHECK(std::equal(std::begin(kExpectedTag), std::begin(kExpectedTag) + 16,
                      std::begin(zk::kEmptyMerkleTag),
                      [](char lhs, std::uint8_t rhs) {
                        return static_cast<std::uint8_t>(lhs) == rhs;
                      }));
  ZK_CHECK(zk::kEmptyMerkleTag[16] == 0);
}

ZK_TEST(merkle_single_leaf_is_returned_unchanged) {
  const Hash256 leaf = ramp(0x11);
  ZK_CHECK(zk::merkle_root(&leaf, 1) == leaf);

  // A single leaf is never hashed, so it is not its own pair digest, and the
  // two-copy tree above it is something else entirely.
  const Hash256 doubled = fold_pair(leaf, leaf);
  ZK_CHECK(zk::merkle_root(&leaf, 1) != doubled);
  const std::vector<Hash256> two_copies = {leaf, leaf};
  ZK_CHECK(root_of(two_copies) == doubled);
  ZK_CHECK(root_of(two_copies) != leaf);

  // The empty-tree root used as a single leaf passes through unchanged: the
  // root of one leaf is that leaf even when the leaf is itself a root.
  const Hash256 empty = zk::merkle_root(nullptr, 0);
  ZK_CHECK(zk::merkle_root(&empty, 1) == empty);
}

ZK_TEST(merkle_internal_node_is_the_ordered_pair_digest_over_64_bytes) {
  const Hash256 a = ramp(0x01);
  const Hash256 b = ramp(0x40);

  // Exactly 64 bytes in, no tag, no separator, no length.
  static_assert(kPair == 64, "an internal node input is 64 bytes");
  ZK_CHECK(root_of(concat(a, b)) == fold_pair(a, b));

  // The children are not sorted, so the lower-valued child is not always first.
  ZK_CHECK(root_of(concat(a, b)) != root_of(concat(b, a)));
  ZK_CHECK(root_of(concat(a, b)) == spec_root(concat(a, b)));

  // Byte direction: the implementation must feed the internal bytes to the hash.
  // A port that reversed into display order would agree with nothing here.
  ZK_CHECK(a.to_hex().str() ==
           "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
  ZK_CHECK(a.to_display_hex().str() ==
           "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201");
  const Hash256 root = root_of(concat(a, b));
  ZK_CHECK(root != a && root != b);
  ZK_CHECK(root.to_hex().str().size() == 64);
}

ZK_TEST(merkle_three_leaves_duplicates_the_last_leaf) {
  const Hash256 a = ramp(0x01);
  const Hash256 b = ramp(0x02);
  const Hash256 c = ramp(0x03);
  const std::vector<Hash256> leaves = {a, b, c};

  // Level 1: fold(a,b) and fold(c,c). Level 2: the pair of those. Written out by
  // hand from the spec, so a promoted-final-node rule fails here.
  const Hash256 expected = fold_pair(fold_pair(a, b), fold_pair(c, c));
  ZK_CHECK(root_of(leaves) == expected);
  ZK_CHECK(root_of(leaves) == spec_root(leaves));

  // Duplication, not promotion: dropping the odd leaf, or carrying it forward
  // unhashed, both give a different answer than the reference contract.
  ZK_CHECK(root_of(leaves) != root_of(concat(a, b)));
  ZK_CHECK(root_of(leaves) != fold_pair(fold_pair(a, b), c));

  // [a,b,c] and [a,b,c,c] are the same tree, because the third level-1 node is
  // the copy that the odd rule makes anyway.
  const std::vector<Hash256> four = {a, b, c, c};
  ZK_CHECK(root_of(leaves) == root_of(four));

  // ... but the reverse ordering is a different tree.
  const std::vector<Hash256> reversed = {c, b, a};
  ZK_CHECK(root_of(reversed) != root_of(leaves));
}

ZK_TEST(merkle_odd_duplication_happens_at_every_odd_level) {
  // Five leaves: widths 5 -> 3 -> 2 -> 1. Both 5 and 3 are odd, so the rule
  // fires twice; a single-level fix does not survive this.
  const std::vector<Hash256> five = ramps(5, 0x10);
  const Hash256 n0 = fold_pair(five[0], five[1]);
  const Hash256 n1 = fold_pair(five[2], five[3]);
  const Hash256 n2 = fold_pair(five[4], five[4]);
  const Hash256 m0 = fold_pair(n0, n1);
  const Hash256 m1 = fold_pair(n2, n2);
  ZK_CHECK(root_of(five) == fold_pair(m0, m1));
  ZK_CHECK(root_of(five) == spec_root(five));

  // Six leaves: widths 6 -> 3 -> 2 -> 1. The first level is even, the second is
  // odd, so the duplication happens one level down from where it does for five.
  const std::vector<Hash256> six = ramps(6, 0x20);
  const Hash256 s0 = fold_pair(six[0], six[1]);
  const Hash256 s1 = fold_pair(six[2], six[3]);
  const Hash256 s2 = fold_pair(six[4], six[5]);
  ZK_CHECK(root_of(six) == fold_pair(fold_pair(s0, s1), fold_pair(s2, s2)));
  ZK_CHECK(root_of(six) == spec_root(six));

  // Seven leaves: widths 7 -> 4 -> 2 -> 1, odd only at the bottom.
  const std::vector<Hash256> seven = ramps(7, 0x30);
  const Hash256 q3 = fold_pair(seven[6], seven[6]);
  const Hash256 q0 = fold_pair(seven[0], seven[1]);
  const Hash256 q1 = fold_pair(seven[2], seven[3]);
  const Hash256 q2 = fold_pair(seven[4], seven[5]);
  ZK_CHECK(root_of(seven) == fold_pair(fold_pair(q0, q1), fold_pair(q2, q3)));
  ZK_CHECK(root_of(seven) == spec_root(seven));
}

ZK_TEST(merkle_root_depends_on_leaf_order_at_every_width) {
  const std::vector<Hash256> abc = ramps(3, 0x01);
  std::vector<Hash256> cba = abc;
  std::reverse(cba.begin(), cba.end());
  ZK_CHECK(root_of(abc) != root_of(cba));
  ZK_CHECK(root_of(cba) == spec_root(cba));

  // A swap of two adjacent leaves changes the root: no sorting is applied.
  const std::vector<Hash256> four = ramps(4, 0x40);
  std::vector<Hash256> swapped = four;
  std::swap(swapped[1], swapped[2]);
  ZK_CHECK(root_of(four) != root_of(swapped));

  // Even the smallest asymmetric case is order-sensitive, so a lexicographic
  // child-ordering rule cannot hide behind a symmetric pair of leaves.
  const Hash256 low = ramp(0x01);
  const Hash256 high = ramp(0xf0);
  ZK_CHECK(root_of(concat(low, high)) == root_of(concat(low, high)));
  ZK_CHECK(root_of(concat(low, high)) != root_of(concat(high, low)));
  ZK_CHECK(fold_pair(low, high) != fold_pair(high, low));
}

ZK_TEST(merkle_repeated_leaves_are_never_deduplicated) {
  const Hash256 x = filled(0x7f);
  const std::vector<Hash256> two = {x, x};
  const std::vector<Hash256> three = {x, x, x};

  ZK_CHECK(root_of(two) == fold_pair(x, x));
  ZK_CHECK(root_of(three) == fold_pair(fold_pair(x, x), fold_pair(x, x)));
  ZK_CHECK(root_of(three) == spec_root(three));

  // Three is not one, and not two: a deduplicating port would collapse them.
  ZK_CHECK(root_of(three) != zk::merkle_root(&x, 1));
  ZK_CHECK(root_of(three) != root_of(two));

  // All-0xff and all-zero leaves are ordinary values, not sentinels.
  const Hash256 ff = filled(0xff);
  const Hash256 zero = Hash256::zero();
  ZK_CHECK(root_of(concat(zero, ff)) == fold_pair(zero, ff));
  ZK_CHECK(root_of(concat(zero, ff)) != root_of(concat(ff, zero)));
  ZK_CHECK(zk::merkle_root(&zero, 1) == zero);
  ZK_CHECK(zk::merkle_root(&ff, 1) == ff);

  // A high-bit first byte must not be treated as a sign or an end marker.
  const Hash256 high_bit = [] {
    Hash256 leaf = ramp(0x00);
    leaf.bytes[0] = 0x80;
    leaf.bytes[31] = 0x01;
    return leaf;
  }();
  ZK_CHECK(root_of({high_bit, high_bit}) == fold_pair(high_bit, high_bit));
  ZK_CHECK(root_of({high_bit, zero, high_bit}) == spec_root({high_bit, zero, high_bit}));
}

ZK_TEST(merkle_accepts_more_leaves_than_the_block_rule_allows) {
  // MAX_BLOCK_TRANSACTIONS is a block rule checked outside merkle_root, so the
  // leaf function must not grow its own limit. 2049 is both above that rule and
  // an odd width, so it exercises the duplication path at depth as well.
  const std::vector<Hash256> many = ramps(2049, 0x00);
  const Hash256 first = root_of(many);
  ZK_CHECK(!first.is_zero());
  ZK_CHECK(first == spec_root(many));

  // Deterministic and independent of how the buffer was built.
  ZK_CHECK(first == root_of(many));

  // A power-of-two width reaches the root without a single duplication.
  const std::vector<Hash256> power = ramps(1024, 0x00);
  ZK_CHECK(root_of(power) == spec_root(power));

  // And one more leaf changes it, so the deep path is not being truncated.
  std::vector<Hash256> power_plus = power;
  power_plus.push_back(ramp(0x80));
  ZK_CHECK(root_of(power_plus) != root_of(power));
}

ZK_TEST(merkle_never_writes_to_the_caller_leaf_buffer) {
  std::vector<Hash256> leaves = ramps(9, 0x07);
  const std::vector<Hash256> snapshot = leaves;
  const Hash256 root = root_of(leaves);

  ZK_CHECK(leaves == snapshot);
  ZK_CHECK(root == spec_root(snapshot));

  // Nine leaves reduce 9 -> 5 -> 3 -> 2 -> 1, so the odd rule fires on three
  // consecutive levels. Every node below is written from the leaves in order.
  const Hash256 n0 = fold_pair(leaves[0], leaves[1]);
  const Hash256 n1 = fold_pair(leaves[2], leaves[3]);
  const Hash256 n2 = fold_pair(leaves[4], leaves[5]);
  const Hash256 n3 = fold_pair(leaves[6], leaves[7]);
  const Hash256 n4 = fold_pair(leaves[8], leaves[8]);
  const Hash256 m0 = fold_pair(n0, n1);
  const Hash256 m1 = fold_pair(n2, n3);
  const Hash256 m2 = fold_pair(n4, n4);
  const Hash256 p0 = fold_pair(m0, m1);
  const Hash256 p1 = fold_pair(m2, m2);
  ZK_CHECK(root == fold_pair(p0, p1));
}

ZK_TEST(merkle_widths_from_two_to_nine_match_the_spec_implementation) {
  for (std::size_t count = 0; count <= 9; ++count) {
    const std::vector<Hash256> leaves = ramps(count, 0x60);
    ZK_CHECK(root_of(leaves) == spec_root(leaves));
  }
  // Every width is distinct: none of these roots collide, which is what a
  // silently truncated or short-circuited level would break.
  std::vector<Hash256> roots;
  for (std::size_t count = 1; count <= 9; ++count) {
    roots.push_back(root_of(ramps(count, 0x60)));
  }
  for (std::size_t i = 0; i < roots.size(); ++i) {
    for (std::size_t j = i + 1; j < roots.size(); ++j) {
      ZK_CHECK(roots[i] != roots[j]);
    }
  }
}

// ---------------------------------------------------------------------------
// Transaction-level composition (P3.3B): zk::merkle_root_from_transactions
// ---------------------------------------------------------------------------

ZK_TEST(merkle_txs_empty_list_takes_the_reference_empty_branch) {
  // A zero count is decided before the buffer is read, in both spellings, which
  // is the order the reference uses and what makes a null list well defined.
  const Transaction sentinel = seeded(0x5a);
  const std::vector<Transaction> one{sentinel};
  const Hash256 via_null = zk::merkle_root_from_transactions(nullptr, 0);
  const Hash256 via_buffer = zk::merkle_root_from_transactions(one.data(), 0);

  // The expectation is the public hash primitive over the tag — the same digest
  // the leaf rule gives for no leaves — not a value copied from a fixture.
  const Hash256 expected = zk::sha256d(zk::kEmptyMerkleTag, zk::kEmptyMerkleTagSize);
  ZK_CHECK(via_null == expected);
  ZK_CHECK(via_buffer == expected);
  ZK_CHECK(via_null == zk::merkle_root(nullptr, 0));
  ZK_CHECK(!via_null.is_zero());

  // The empty tree is its own commitment, not some transaction's id.
  ZK_CHECK(via_null != sentinel.txid());

  // Reading a zero-length range wrote nothing and changed nothing.
  ZK_CHECK(one.size() == 1 && one[0] == sentinel);
}

ZK_TEST(merkle_txs_single_transaction_root_is_that_transactions_id) {
  // Three different one-item lists, including a coinbase-shaped one: in every
  // case the root is the id that transaction's own encoding commits to, with no
  // hash applied on top and no coinbase rule consulted.
  const std::vector<Transaction> singles = {seeded(0x11), coinbase_like(0x27), seeded(0xff)};
  for (const Transaction& tx : singles) {
    const std::vector<Transaction> one{tx};
    const Hash256 id = id_from_encoding(tx);
    ZK_CHECK(id == tx.txid());
    ZK_CHECK(root_of_txs(one) == id);
    ZK_CHECK(root_of_txs(one) == zk::merkle_root(&id, 1));

    // One transaction is not two copies of it, so a promoted-or-duplicated
    // single leaf cannot masquerade as this result.
    ZK_CHECK(root_of_txs(one) != fold_pair(id, id));
    const std::vector<Transaction> twice{tx, tx};
    ZK_CHECK(root_of_txs(twice) == fold_pair(id, id));
    ZK_CHECK(root_of_txs(twice) != root_of_txs(one));
  }

  // A coinbase is an ordinary transaction here: the composition never asks.
  const Transaction cb = coinbase_like(0x01);
  ZK_CHECK(cb.is_coinbase());
  ZK_CHECK(root_of_txs(std::vector<Transaction>{cb}) == cb.txid());
}

ZK_TEST(merkle_txs_composition_adds_nothing_between_the_id_and_the_leaf) {
  // The whole contract of the new function in one statement: for every width,
  // its root is the leaf rule applied to the ids re-derived here from the
  // encodings — a second implementation of both halves, neither of which calls
  // merkle_root_from_transactions.
  for (std::size_t count = 0; count <= 9; ++count) {
    const std::vector<Transaction> txs = seeded_list(count, 0x40);
    const std::vector<Hash256> ids = ids_from_encoding(txs);
    ZK_CHECK(ids.size() == count);
    for (std::size_t i = 0; i < count; ++i) {
      ZK_CHECK(ids[i] == txs[i].txid());
    }
    ZK_CHECK(root_of_txs(txs) == root_of(ids));
    ZK_CHECK(root_of_txs(txs) == spec_root(ids));
  }

  // Seventeen transactions reach five levels deep, 17 -> 9 -> 5 -> 3 -> 2 -> 1.
  const std::vector<Transaction> many = seeded_list(17, 0x10);
  ZK_CHECK(root_of_txs(many) == spec_root(ids_from_encoding(many)));

  // And the result is the stored digest, not its printing form: the display
  // string is the same bytes reversed, and the two never coincide here.
  const Hash256 root = root_of_txs(many);
  std::array<std::uint8_t, kWidth> reversed{};
  std::copy_n(root.bytes.rbegin(), kWidth, reversed.begin());
  ZK_CHECK(root.to_hex().str() == zk::to_hex(root.bytes.data(), kWidth));
  ZK_CHECK(root.to_display_hex().str() == zk::to_hex(reversed.data(), kWidth));
  ZK_CHECK(root.to_hex().str() != root.to_display_hex().str());
}

ZK_TEST(merkle_txs_root_follows_transaction_order) {
  // Two transactions, swapped. Asymmetric fixtures, so a rule that sorted the
  // children by value would show up.
  const Transaction a = seeded(0x01);
  const Transaction b = seeded(0x02);
  const std::vector<Transaction> ab{a, b};
  const std::vector<Transaction> ba{b, a};
  ZK_CHECK(root_of_txs(ab) == fold_pair(id_from_encoding(a), id_from_encoding(b)));
  ZK_CHECK(root_of_txs(ab) != root_of_txs(ba));

  // Three transactions, reversed, and a single adjacent swap in a wider list.
  const std::vector<Transaction> abc = seeded_list(3, 0x70);
  std::vector<Transaction> cba = abc;
  std::reverse(cba.begin(), cba.end());
  ZK_CHECK(root_of_txs(abc) != root_of_txs(cba));
  ZK_CHECK(root_of_txs(cba) == spec_root(ids_from_encoding(cba)));

  const std::vector<Transaction> four = seeded_list(4, 0x20);
  std::vector<Transaction> swapped = four;
  std::swap(swapped[1], swapped[2]);
  ZK_CHECK(root_of_txs(four) != root_of_txs(swapped));

  // Same transactions, same length, different order: the ids are a permutation of
  // each other, so only the tree can differ.
  const std::vector<Hash256> ids_ab = ids_from_encoding(abc);
  const std::vector<Hash256> ids_cb = ids_from_encoding(cba);
  ZK_CHECK(ids_ab.size() == ids_cb.size());
  for (std::size_t i = 0; i < ids_ab.size(); ++i) {
    ZK_CHECK(ids_ab[i] == ids_cb[ids_cb.size() - 1 - i]);
  }
}

ZK_TEST(merkle_txs_odd_final_transaction_is_duplicated_not_promoted) {
  const Transaction a = seeded(0x01);
  const Transaction b = seeded(0x02);
  const Transaction c = seeded(0x03);
  const Hash256 ia = id_from_encoding(a);
  const Hash256 ib = id_from_encoding(b);
  const Hash256 ic = id_from_encoding(c);

  // Level 1 folds (a,b) and (c,c); nothing carries c forward unhashed.
  const std::vector<Transaction> three{a, b, c};
  const Hash256 expected = fold_pair(fold_pair(ia, ib), fold_pair(ic, ic));
  ZK_CHECK(root_of_txs(three) == expected);
  ZK_CHECK(root_of_txs(three) != fold_pair(fold_pair(ia, ib), ic));
  ZK_CHECK(root_of_txs(three) != root_of_txs(std::vector<Transaction>{a, b}));

  // Appending a copy of the final transaction cannot change the root, because the
  // odd rule makes that copy anyway. Stated as an equality over transactions.
  const std::vector<Transaction> four{a, b, c, c};
  ZK_CHECK(root_of_txs(four) == root_of_txs(three));

  // Five transactions duplicate at two different levels: widths 5 -> 3 -> 2 -> 1.
  const std::vector<Transaction> five = seeded_list(5, 0x30);
  const std::vector<Hash256> five_ids = ids_from_encoding(five);
  const Hash256 p0 = fold_pair(five_ids[0], five_ids[1]);
  const Hash256 p1 = fold_pair(five_ids[2], five_ids[3]);
  const Hash256 p2 = fold_pair(five_ids[4], five_ids[4]);
  ZK_CHECK(root_of_txs(five) == fold_pair(fold_pair(p0, p1), fold_pair(p2, p2)));
}

ZK_TEST(merkle_txs_root_follows_transaction_content) {
  const Transaction base = seeded(0x44);

  // One field at a time, each a single byte wide in the encoding: every change
  // moves the id, and so moves the root of an otherwise identical list.
  Transaction value = base;
  value.outputs[0].value += 1;
  Transaction script = base;
  script.outputs[0].script_pubkey.push_back(0xac);
  Transaction sequence = base;
  sequence.inputs[0].sequence -= 1;
  Transaction outpoint = base;
  outpoint.inputs[0].previous_output.vout += 1;
  Transaction timelock = base;
  timelock.lock_time += 1;
  Transaction version = base;
  version.version += 1;

  const Transaction others = seeded(0x45);
  const std::vector<Transaction> tail{others};
  for (const Transaction& changed :
       {base, value, script, sequence, outpoint, timelock, version}) {
    std::vector<Transaction> list{changed};
    list.insert(list.end(), tail.begin(), tail.end());
    ZK_CHECK(id_from_encoding(changed) == changed.txid());
    ZK_CHECK(root_of_txs(list) == spec_root(ids_from_encoding(list)));
  }

  // Each mutated transaction gives a different root against the same partner.
  std::vector<Hash256> roots;
  for (const Transaction& changed :
       {value, script, sequence, outpoint, timelock, version}) {
    std::vector<Transaction> list{changed};
    list.insert(list.end(), tail.begin(), tail.end());
    roots.push_back(root_of_txs(list));
  }
  std::vector<Transaction> unperturbed{base};
  unperturbed.insert(unperturbed.end(), tail.begin(), tail.end());
  roots.push_back(root_of_txs(unperturbed));
  for (std::size_t i = 0; i < roots.size(); ++i) {
    for (std::size_t j = i + 1; j < roots.size(); ++j) {
      ZK_CHECK(roots[i] != roots[j]);
    }
  }

  // The leaf source is the encoding, not the object graph: a transaction decoded
  // from its own bytes composes to the same root.
  const std::vector<std::uint8_t> bytes = base.serialize();
  const zk::TxDecodeResult decoded = zk::deserialize_transaction(bytes.data(), bytes.size());
  ZK_CHECK(static_cast<bool>(decoded));
  ZK_CHECK(decoded.tx == base);
  ZK_CHECK(root_of_txs(std::vector<Transaction>{decoded.tx, others}) ==
           root_of_txs(std::vector<Transaction>{base, others}));
}

ZK_TEST(merkle_txs_never_writes_to_the_caller_transaction_list) {
  std::vector<Transaction> txs = seeded_list(9, 0x0c);
  const std::vector<Transaction> snapshot = txs;
  const std::vector<std::string> encodings_before = [&txs] {
    std::vector<std::string> out;
    for (const Transaction& tx : txs) {
      const std::vector<std::uint8_t> bytes = tx.serialize();
      out.push_back(zk::to_hex(bytes.data(), bytes.size()));
    }
    return out;
  }();

  const Hash256 root = root_of_txs(txs);
  ZK_CHECK(txs == snapshot);

  std::vector<std::string> encodings_after;
  for (const Transaction& tx : txs) {
    const std::vector<std::uint8_t> bytes = tx.serialize();
    encodings_after.push_back(zk::to_hex(bytes.data(), bytes.size()));
  }
  ZK_CHECK(encodings_before == encodings_after);
  ZK_CHECK(root == spec_root(ids_from_encoding(snapshot)));

  // A second call over the unchanged input repeats the first answer exactly.
  ZK_CHECK(root_of_txs(txs) == root);
}

ZK_TEST(merkle_txs_accepts_more_transactions_than_the_block_rule_allows) {
  // MAX_BLOCK_TRANSACTIONS (B-9) is enforced by validate_structure, outside the
  // root rule. The composition must not grow its own limit, so a list above that
  // count still reduces to the same root the leaf rule gives over its ids.
  const std::vector<Transaction> many = seeded_list(2049, 0x00);
  const Hash256 first = root_of_txs(many);
  ZK_CHECK(!first.is_zero());
  ZK_CHECK(first == root_of(ids_from_encoding(many)));
  ZK_CHECK(first == spec_root(ids_from_encoding(many)));

  // Seed bytes repeat past 256 entries, so this list is mostly duplicates and is
  // still counted leaf by leaf — no deduplication at depth.
  std::vector<Transaction> one_more = many;
  one_more.push_back(many.back());
  one_more.back().lock_time += 1;
  ZK_CHECK(root_of_txs(one_more) != first);
  ZK_CHECK(root_of_txs(one_more) == spec_root(ids_from_encoding(one_more)));

  // A power-of-two width above the block bound reduces without any duplication.
  const std::vector<Transaction> power = seeded_list(2048, 0x00);
  ZK_CHECK(root_of_txs(power) == spec_root(ids_from_encoding(power)));
  ZK_CHECK(root_of_txs(power) != first);
}
