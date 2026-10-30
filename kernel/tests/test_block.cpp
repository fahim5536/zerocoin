// The claimed-Merkle-root comparison: rule B-14 on its own. The corpus in
// test/p41-vectors/chain/ is the value oracle (kernel/tools/p41_conformance.py
// replays all thirty cases byte for byte), so nothing here copies an expected
// root out of a fixture and no test types a hash by hand. What these tests pin
// is what a fixed corpus cannot express on its own: that the verdict is the
// digest comparison and nothing else — not the header's other fields, not its
// proof of work, not the transaction count, not the coinbase's position, and not
// the printing order of the bytes.
//
// The expected root is re-derived here by `spec_root`, a second implementation of
// the reduction written from the C-5 wording, over ids re-derived by
// `id_from_encoding` from the C-2 wording. Neither calls anything in block.cpp,
// so a mutation in the rule under test disagrees with this file instead of being
// repeated by it. merkle.cpp is a collaborator that the P3.2B and P3.3B corpora
// already verified; one test below (block_verdict_is_the_reference_comparison)
// does call it, precisely to show that B-14 adds nothing between it and the
// verdict.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "test_framework.h"
#include "zerocoin/block.h"
#include "zerocoin/hash.h"
#include "zerocoin/header.h"
#include "zerocoin/merkle.h"
#include "zerocoin/pow.h"
#include "zerocoin/transaction.h"

namespace {

using zk::BlockErrorKind;
using zk::BlockHeader;
using zk::Hash256;
using zk::Outpoint;
using zk::Transaction;
using zk::TxIn;
using zk::TxOut;

constexpr std::size_t kWidth = Hash256::kWidth;
constexpr std::size_t kPair = kWidth * 2;

// The regtest chain id and the difficulty bits the P4.1A corpus publishes, so a
// locally built header is the same shape as a replayed case.
constexpr std::uint32_t kRegtestChain = 1'515'343'616u;
constexpr std::uint32_t kCorpusBits = 545'259'519u;  // 0x207FFFFF

Hash256 ramp(std::uint8_t seed) {
  Hash256 leaf{};
  for (std::size_t i = 0; i < kWidth; ++i) {
    leaf.bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  return leaf;
}

/// The printing form of a digest: the same thirty-two bytes in the opposite
/// order. Not a call into anything — `to_display_hex` is the reference's own
/// display convention, and the test that uses this asserts the two agree.
Hash256 reversed(const Hash256& hash) {
  Hash256 out{};
  std::reverse_copy(hash.bytes.begin(), hash.bytes.end(), out.bytes.begin());
  return out;
}

// A transaction whose every field is a function of one seed byte, so a list of
// them is a list of distinct serialisations that needs no lookup table.
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

/// A coinbase by shape: one input that spends the null outpoint. Used only to
/// show the comparison never consults it — B-10 and B-11 are not on this path.
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

/// The id re-derived from the C-2 wording — sha256d over the canonical
/// serialisation — instead of calling `Transaction::txid()`.
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

/// One internal node, written from the C-5 wording: sha256d over the two children
/// as stored, with no tag and no reversal.
Hash256 fold_pair(const Hash256& left, const Hash256& right) {
  std::array<std::uint8_t, kPair> buffer{};
  std::copy_n(left.bytes.begin(), kWidth, buffer.begin());
  std::copy_n(right.bytes.begin(), kWidth, buffer.begin() + kWidth);
  return zk::sha256d(buffer.data(), buffer.size());
}

/// A second implementation of the whole reduction, shaped differently from
/// merkle.cpp: an odd level is widened with a copy of its own final node first,
/// after which every fold is an unguarded pair.
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

/// The root this file believes the list commits to, built from the transaction
/// ids rather than from the function under test.
Hash256 claim_root(const std::vector<Transaction>& txs) {
  return spec_root(ids_from_encoding(txs));
}

/// A header that claims `root` and is otherwise the corpus's shape. Everything a
/// test mutates is one of the fields `header_claiming` fills, so the claim is the
/// only thing two of these can differ in unless the test says otherwise.
BlockHeader header_claiming(const Hash256& root) {
  BlockHeader header{};
  header.version = 1;
  header.chain = kRegtestChain;
  header.height = 1;
  header.previous_hash = ramp(0x70);
  header.merkle_root = root;
  header.timestamp = 1'700'000'000;
  header.difficulty_bits = kCorpusBits;
  header.engine_id = 0;
  header.nonce = 0;
  return header;
}

BlockErrorKind verdict(const BlockHeader& header, const std::vector<Transaction>& txs) {
  return zk::compare_claimed_merkle_root(header, txs.data(), txs.size());
}

}  // namespace

ZK_TEST(block_matching_claim_is_accepted_from_one_to_eight_transactions) {
  // Every count in the range the corpus covers, odd and even, so a wrong
  // duplicate-or-promote decision at any level shows up here rather than only at
  // the one length the boundary cases happen to use.
  for (std::size_t count = 1; count <= 8; ++count) {
    const std::vector<Transaction> txs = seeded_list(count, 0x20);
    const Hash256 root = claim_root(txs);
    ZK_CHECK(verdict(header_claiming(root), txs) == BlockErrorKind::kNone);
  }

  // The single-leaf list is its own root, so a port that always folded would
  // reject its own shortest valid block here rather than in a comment.
  const std::vector<Transaction> one = seeded_list(1, 0x20);
  ZK_CHECK(claim_root(one) == id_from_encoding(one.front()));
  ZK_CHECK(verdict(header_claiming(id_from_encoding(one.front())), one) == BlockErrorKind::kNone);
}

ZK_TEST(block_zero_claim_is_rejected_for_every_list_length) {
  const Hash256 zero = Hash256::zero();
  for (std::size_t count = 1; count <= 4; ++count) {
    const std::vector<Transaction> txs = seeded_list(count, 0x40);
    // The claim is a real rejection, not a tautology: the true root is non-zero.
    ZK_CHECK(!claim_root(txs).is_zero());
    ZK_CHECK(verdict(header_claiming(zero), txs) == BlockErrorKind::kRootMismatch);
  }
}

ZK_TEST(block_one_bit_change_in_the_claim_is_rejected) {
  const std::vector<Transaction> txs = seeded_list(3, 0x30);
  const Hash256 root = claim_root(txs);

  Hash256 low_bit = root;
  low_bit.bytes[kWidth - 1] ^= 0x01;
  Hash256 high_bit = root;
  high_bit.bytes[0] ^= 0x80;
  ZK_CHECK(low_bit != root);
  ZK_CHECK(high_bit != root);

  ZK_CHECK(verdict(header_claiming(low_bit), txs) == BlockErrorKind::kRootMismatch);
  ZK_CHECK(verdict(header_claiming(high_bit), txs) == BlockErrorKind::kRootMismatch);

  // Restoring the bit restores the verdict, so the two rejections above are the
  // distance of the claim and not an artefact of the byte position.
  ZK_CHECK(verdict(header_claiming(root), txs) == BlockErrorKind::kNone);
}

ZK_TEST(block_display_order_claim_is_rejected) {
  // The case that separates a byte comparison from a printing comparison. The
  // claim here is the right digest written in the wrong order, so a port that
  // compared hex strings or display bytes would accept it and this one must not.
  const std::vector<Transaction> txs = seeded_list(2, 0x50);
  const Hash256 root = claim_root(txs);
  const Hash256 display = reversed(root);

  // The premise, checked rather than assumed: `display` is exactly what
  // `to_display_hex` prints for `root`, and it is a different 32-byte value.
  ZK_CHECK(display.to_hex().str() == root.to_display_hex().str());
  ZK_CHECK(display != root);

  ZK_CHECK(verdict(header_claiming(display), txs) == BlockErrorKind::kRootMismatch);
  ZK_CHECK(verdict(header_claiming(root), txs) == BlockErrorKind::kNone);
}

ZK_TEST(block_stale_claim_is_rejected_in_both_directions) {
  const std::vector<Transaction> one = seeded_list(1, 0x60);
  const std::vector<Transaction> two = seeded_list(2, 0x60);
  const std::vector<Transaction> three = seeded_list(3, 0x60);

  // A header left behind by one more transaction, and one written for a longer
  // block than the one presented. Neither is the other's root.
  ZK_CHECK(claim_root(one) != claim_root(two));
  ZK_CHECK(claim_root(two) != claim_root(three));
  ZK_CHECK(verdict(header_claiming(claim_root(two)), three) == BlockErrorKind::kRootMismatch);
  ZK_CHECK(verdict(header_claiming(claim_root(three)), two) == BlockErrorKind::kRootMismatch);

  // Each list still accepts its own commitment, so the two rejections above are
  // staleness and not a broken oracle.
  ZK_CHECK(verdict(header_claiming(claim_root(one)), one) == BlockErrorKind::kNone);
  ZK_CHECK(verdict(header_claiming(claim_root(two)), two) == BlockErrorKind::kNone);
  ZK_CHECK(verdict(header_claiming(claim_root(three)), three) == BlockErrorKind::kNone);
}

ZK_TEST(block_list_order_is_the_order_compared) {
  const Transaction a = seeded(0x71);
  const Transaction b = seeded(0x72);
  const std::vector<Transaction> ab{a, b};
  const std::vector<Transaction> ba{b, a};

  // The fold is not symmetric, so a list that merely swapped two transactions is
  // a different commitment — the same leaf set, a different root.
  ZK_CHECK(claim_root(ab) != claim_root(ba));
  ZK_CHECK(verdict(header_claiming(claim_root(ba)), ab) == BlockErrorKind::kRootMismatch);
  ZK_CHECK(verdict(header_claiming(claim_root(ab)), ab) == BlockErrorKind::kNone);
  ZK_CHECK(verdict(header_claiming(claim_root(ba)), ba) == BlockErrorKind::kNone);
}

ZK_TEST(block_duplicating_the_final_leaf_of_an_odd_list_leaves_the_root_unchanged) {
  // C-5 duplicates the odd tail instead of promoting it, which makes an odd list
  // and the same list with its last transaction repeated commit to one root. The
  // comparison must accept both, because the rule it implements is that fold and
  // not a length check.
  const std::vector<Transaction> abc = seeded_list(3, 0x80);
  const Transaction c = abc.back();
  const std::vector<Transaction> abcc{abc[0], abc[1], c, c};
  ZK_CHECK(claim_root(abc) == claim_root(abcc));

  ZK_CHECK(verdict(header_claiming(claim_root(abcc)), abc) == BlockErrorKind::kNone);
  ZK_CHECK(verdict(header_claiming(claim_root(abc)), abcc) == BlockErrorKind::kNone);

  // A fourth transaction that is not a copy of the third is a different tree, so
  // the equality above is the duplicate rule and not a "long lists are ignored".
  const std::vector<Transaction> abcd = seeded_list(4, 0x80);
  ZK_CHECK(claim_root(abc) != claim_root(abcd));
  ZK_CHECK(verdict(header_claiming(claim_root(abc)), abcd) == BlockErrorKind::kRootMismatch);
}

ZK_TEST(block_empty_list_is_compared_and_not_guarded) {
  // B-8 `NoTransactions` runs before B-14 in production, so a node never reports
  // this verdict for an empty block. The corpus publishes that fact beside the
  // two boundary cases as `guard_before_comparison` and this port deliberately
  // does not reproduce it: `compute_merkle_root` is defined on an empty slice, so
  // the comparison has an answer, and inventing a guard here would be a second
  // rule that the reference applies somewhere else.
  const Hash256 empty = zk::sha256d(zk::kEmptyMerkleTag, zk::kEmptyMerkleTagSize);
  ZK_CHECK(!empty.is_zero());

  // count == 0 must not read the pointer, in either spelling block.h allows.
  ZK_CHECK(zk::compare_claimed_merkle_root(header_claiming(empty), nullptr, 0) ==
           BlockErrorKind::kNone);
  const std::vector<Transaction> nothing;
  ZK_CHECK(verdict(header_claiming(empty), nothing) == BlockErrorKind::kNone);

  // A header that commits to anything else is rejected, including the zero digest
  // and a leaf-shaped value: the empty tree has one fixed identity.
  ZK_CHECK(zk::compare_claimed_merkle_root(header_claiming(Hash256::zero()), nullptr, 0) ==
           BlockErrorKind::kRootMismatch);
  ZK_CHECK(verdict(header_claiming(ramp(0x77)), nothing) == BlockErrorKind::kRootMismatch);
  ZK_CHECK(verdict(header_claiming(reversed(empty)), nothing) == BlockErrorKind::kRootMismatch);
}

ZK_TEST(block_verdict_ignores_the_headers_own_proof_of_work) {
  // The corpus's two `ordering` cases pin that B-14 is reached with a failing
  // proof of work. Reproduced locally with a target small enough that no honest
  // nonce in the test's range meets it, so the flag is observably false while the
  // claim is observably accepted.
  const std::vector<Transaction> txs = seeded_list(2, 0x90);
  const Hash256 root = claim_root(txs);
  const zk::PowEngine engine = zk::PowEngine::trivial();

  BlockHeader weak = header_claiming(root);
  weak.difficulty_bits = 0x03010000u;  // a 3-byte target of 65536
  ZK_CHECK(!zk::header_meets_own_target(weak, engine));
  ZK_CHECK(verdict(weak, txs) == BlockErrorKind::kNone);

  // The verdict does not move with the nonce either: none of these meets the
  // target, and all of them keep their own commitment.
  for (const std::uint64_t nonce : {0ULL, 1ULL, 2ULL, 7ULL, 1'000'000ULL}) {
    BlockHeader mined = weak;
    mined.nonce = nonce;
    ZK_CHECK(!zk::header_meets_own_target(mined, engine));
    ZK_CHECK(verdict(mined, txs) == BlockErrorKind::kNone);
  }

  // And an easy target does not rescue a wrong claim.
  BlockHeader weak_and_wrong = weak;
  weak_and_wrong.merkle_root = Hash256::zero();
  ZK_CHECK(verdict(weak_and_wrong, txs) == BlockErrorKind::kRootMismatch);
}

ZK_TEST(block_comparison_reads_only_the_claimed_root) {
  // B-14 is the Merkle commitment alone. Every other field the header carries
  // belongs to a different rule — identity (B-4, B-5), time (B-7), bits (B-6),
  // engine (B-3) — so changing one must not change this verdict in either
  // direction. This is the F-2 boundary stated as an assertion.
  const std::vector<Transaction> txs = seeded_list(3, 0xa0);
  const Hash256 root = claim_root(txs);
  const BlockHeader base = header_claiming(root);
  const BlockHeader base_wrong = header_claiming(Hash256::zero());

  const std::vector<BlockHeader> mutations = [&base, &base_wrong]() {
    std::vector<BlockHeader> out;
    for (const BlockHeader& source : {base, base_wrong}) {
      BlockHeader version = source;
      version.version = source.version + 1;
      BlockHeader chain = source;
      chain.chain = 1;
      BlockHeader height = source;
      height.height = source.height + 5;
      BlockHeader previous = source;
      previous.previous_hash = ramp(0x11);
      BlockHeader timestamp = source;
      timestamp.timestamp = source.timestamp + 3600;
      BlockHeader bits = source;
      bits.difficulty_bits = 0x03000001u;
      BlockHeader engine = source;
      engine.engine_id = 1;
      BlockHeader nonce = source;
      nonce.nonce = 12345;
      for (const BlockHeader& mutated :
           {version, chain, height, previous, timestamp, bits, engine, nonce}) {
        ZK_CHECK(mutated != source);
        out.push_back(mutated);
      }
    }
    return out;
  }();

  ZK_CHECK(mutations.size() == 16);
  for (std::size_t i = 0; i < mutations.size(); ++i) {
    const BlockErrorKind want =
        i < 8 ? BlockErrorKind::kNone : BlockErrorKind::kRootMismatch;
    ZK_CHECK(verdict(mutations[i], txs) == want);
  }
}

ZK_TEST(block_coinbase_position_is_not_part_of_the_comparison) {
  // B-10 and B-11 require the coinbase first and only once. The comparison does
  // not know what a coinbase is: it commits to the list as given, so a block with
  // the coinbase last is accepted here and rejected by production.
  const Transaction regular = seeded(0xb1);
  const Transaction coinbase = coinbase_like(0xb2);
  const std::vector<Transaction> coinbase_last{regular, coinbase};
  const std::vector<Transaction> coinbase_first{coinbase, regular};

  ZK_CHECK(claim_root(coinbase_last) != claim_root(coinbase_first));
  ZK_CHECK(verdict(header_claiming(claim_root(coinbase_last)), coinbase_last) ==
           BlockErrorKind::kNone);
  ZK_CHECK(verdict(header_claiming(claim_root(coinbase_first)), coinbase_last) ==
           BlockErrorKind::kRootMismatch);
}

ZK_TEST(block_no_transaction_count_limit_is_applied) {
  // B-9 `MAX_BLOCK_TRANSACTIONS` is checked before the comparison in the
  // reference, so a second copy inside it would be a different consensus rule.
  // These counts are far above anything a leaf-level test needs and the verdict
  // is still the digest comparison.
  const std::vector<Transaction> thirty_seven = seeded_list(37, 0xc0);
  ZK_CHECK(verdict(header_claiming(claim_root(thirty_seven)), thirty_seven) ==
           BlockErrorKind::kNone);

  const std::vector<Transaction> sixty_four = seeded_list(64, 0xd0);
  ZK_CHECK(verdict(header_claiming(claim_root(sixty_four)), sixty_four) == BlockErrorKind::kNone);

  // Dropping one transaction from either list is a mismatch, so the long lists
  // above were folded and not truncated to a fixed window.
  const std::vector<Transaction> sixty_three(sixty_four.begin(), sixty_four.end() - 1);
  ZK_CHECK(verdict(header_claiming(claim_root(sixty_four)), sixty_three) ==
           BlockErrorKind::kRootMismatch);
}

ZK_TEST(block_verdict_is_the_reference_comparison_and_nothing_else) {
  // The whole of B-14 is three lines: compute, compare, reject. Walking a matrix
  // of lists against four candidate claims, the verdict must equal the byte
  // comparison of the claim with the root merkle.cpp produces — the composition
  // the P3.3B corpus already verified. If block.cpp added a guard, a normalisation
  // or a second hash anywhere, a cell here stops agreeing.
  bool accepted_seen = false;
  bool rejected_seen = false;
  for (std::size_t count = 0; count <= 5; ++count) {
    const std::vector<Transaction> txs = seeded_list(count, 0xe0);
    const Hash256 true_root = zk::merkle_root_from_transactions(txs.data(), txs.size());
    ZK_CHECK(true_root == claim_root(txs));

    const std::array<Hash256, 4> claims{Hash256::zero(), true_root, reversed(true_root),
                                        ramp(0xee)};
    for (const Hash256& claim : claims) {
      const BlockHeader header = header_claiming(claim);
      const BlockErrorKind got = verdict(header, txs);
      const BlockErrorKind want = claim == true_root ? BlockErrorKind::kNone
                                                     : BlockErrorKind::kRootMismatch;
      ZK_CHECK(got == want);
      accepted_seen = accepted_seen || (got == BlockErrorKind::kNone);
      rejected_seen = rejected_seen || (got == BlockErrorKind::kRootMismatch);
    }
  }
  ZK_CHECK(accepted_seen);
  ZK_CHECK(rejected_seen);
}

ZK_TEST(block_root_mismatch_is_named_as_the_reference_and_carries_no_payload) {
  const std::vector<Transaction> txs = seeded_list(1, 0xf0);
  const BlockErrorKind kind = verdict(header_claiming(Hash256::zero()), txs);

  ZK_CHECK(kind == BlockErrorKind::kRootMismatch);
  ZK_CHECK(std::string(zk::block_error_kind_name(kind)) == "RootMismatch");

  // The fixture publishes `error_kind: "RootMismatch"` with `error_payload: null`.
  // A runner that answered "payload present" for this variant would be reporting
  // a shape the reference does not have, so the per-variant rule is asserted here
  // and the two identity variants keep theirs.
  ZK_CHECK(!zk::block_error_kind_has_payload(kind));
  ZK_CHECK(zk::block_error_kind_has_payload(BlockErrorKind::kWrongChain));
  ZK_CHECK(zk::block_error_kind_has_payload(BlockErrorKind::kBadHeight));

  // The variant the identity validator shares this enum with is still its own:
  // B-14 cannot produce a payload-bearing rejection and B-4/B-5 cannot produce
  // this one.
  ZK_CHECK(kind != BlockErrorKind::kWrongChain);
  ZK_CHECK(kind != BlockErrorKind::kBadHeight);
  ZK_CHECK(verdict(header_claiming(claim_root(txs)), txs) == BlockErrorKind::kNone);
}
