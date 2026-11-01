// The block-structure ordering: rules B-3 through B-15 in
// `Block::validate_structure`'s order (block.rs:173-225). The P4.2A corpus is the
// value oracle for each rule's predicate and will be replayed by the P4.2B-2
// differential runner; it is not what this file pins. What a fixture cannot
// express is the two things a first-failure ordering actually has to get right:
// WHICH rule a multi-fault block reports, and WHAT it carries when it does. So
// almost every test here breaks a later rule as well as the one it names, checks
// that both are really broken, and then asserts which single verdict the ordering
// publishes.
//
// The order under test is the one written in block.h and numbered in
// CONSENSUS_RULES.md §2.4:
//
//   B-3  WrongChain      B-7  BadDifficulty          B-11 DuplicateCoinbase
//   B-4  BadHeight       B-8  NoTransactions         B-12 TimestampTooOld
//   B-5  BadPreviousHash B-9  TooManyTransactions    B-13 TimestampTooFarFuture
//   B-6  WrongEngine     B-10 FirstNotCoinbase       B-14 RootMismatch
//                                                    B-15 InsufficientProofOfWork
//
// Two deliberate absences. Nothing here copies an expected Merkle root out of a
// fixture: the roots the valid-path fixtures use come from
// `merkle_root_from_transactions`, whose own behaviour the P3.3B and P4.1A corpora
// verified and which B-14 reuses unchanged — this file's subject is where that
// verb sits in the sequence, not what it computes. And no fixture assumes a proof
// of work: `seal_nonce` searches a nonce that meets the header's own target and
// every caller asserts the search succeeded, so an accept path is an accept path
// for the reason the rule gives rather than because a constant was hand-picked
// once and nobody noticed it stopped matching.
//
// Rust remains the oracle. These tests establish the ordering and the payload
// mapping of the ported structure rules; they are not consensus parity, and
// `connect_block`, `required_bits`, UTXO, reward, signature and fork-choice
// validation are not covered here because they are not ported.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "test_framework.h"
#include "zerocoin/block.h"
#include "zerocoin/difficulty.h"
#include "zerocoin/header.h"
#include "zerocoin/merkle.h"
#include "zerocoin/pow.h"
#include "zerocoin/transaction.h"

namespace {

using zk::BadDifficultyError;
using zk::BadHeightError;
using zk::BadPreviousHashError;
using zk::Block;
using zk::BlockAccepted;
using zk::BlockErrorKind;
using zk::BlockHeader;
using zk::BlockStructureResult;
using zk::DuplicateCoinbaseError;
using zk::FirstNotCoinbaseError;
using zk::Hash256;
using zk::InsufficientProofOfWorkError;
using zk::NoTransactionsError;
using zk::Outpoint;
using zk::PowEngine;
using zk::RootMismatchError;
using zk::TooManyTransactionsError;
using zk::TimestampTooFarFutureError;
using zk::TimestampTooOldError;
using zk::Transaction;
using zk::TxIn;
using zk::TxOut;
using zk::ValidationContext;
using zk::WrongChainError;
using zk::WrongEngineError;

// The regtest chain id the P3.1A and P4.1A corpora publish, so a locally built
// header is the same shape as a replayed case.
constexpr std::uint32_t kRegtestChain = 1'515'343'616u;
constexpr std::uint64_t kHeight = 1;

// 0x207fffff: the largest target a compact value can name without tripping the
// sign bit. `from_compact` masks the mantissa with 0x007fffff and returns zero
// when 0x00800000 is set, so 0x20ffffff — which looks like "the widest possible
// easy target" — actually decodes to a target of zero and can never be met. The
// value here decodes to 0x7fffff * 2^232 = 2^255 - 2^232, i.e. bytes
// 7F FF FF 00..00, so a trivial-engine digest clears it with probability
// just under 1/2. `seal_nonce` therefore finds one in a couple of candidates.
// The target is above the pow limit, which is deliberate and asserted by the B-7
// test: the structure ordering never asks the bits policy about it.
constexpr std::uint32_t kEasyBits = 0x20'7fffffu;

// 0x1d00ffff: one exponent step below the pow limit floor, target
// 0xffff * 2^208 = 2^224 - 2^208. A trivial-engine digest clears it with
// probability ~2^-32, so no nonce search is attempted against it and the B-15
// tests assert the failure instead of assuming one.
constexpr std::uint32_t kHardBits = 0x1d00'ffffu;

constexpr std::uint64_t kNow = 1'700'000'000;
constexpr std::uint64_t kMedian = kNow - 10;
constexpr std::uint64_t kTimestamp = kNow;

constexpr std::uint64_t kMaxClock = std::numeric_limits<std::uint64_t>::max();

// The bound on `seal_nonce`'s search. Generous by many orders of magnitude
// relative to the roughly 1-in-2 per-candidate success rate of `kEasyBits`
// (exhausting it is a 2^-1024 event), and small enough that a fixture bug
// reports itself as a failed check instead of hanging.
constexpr std::uint64_t kNonceSearchBound = 1024;

Hash256 ramp(std::uint8_t seed) {
  Hash256 value{};
  for (std::size_t i = 0; i < Hash256::kWidth; ++i) {
    value.bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  return value;
}

/// Four bytes of the index, so a list of a thousand transactions has a thousand
/// distinct ids and no test depends on a seed byte wrapping.
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
  tx.inputs.push_back(TxIn{Outpoint{ramp(static_cast<std::uint8_t>(index)), 0}, script_of(index),
                           0xffff'ffff});
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

/// A list that breaks B-10 and B-11 at once: no coinbase in position 0, one
/// further down.
std::vector<Transaction> misplaced_coinbase_list() {
  std::vector<Transaction> txs{ordinary(0), ordinary(1), coinbase(2)};
  return txs;
}

/// A list with a second coinbase after a valid first one, for B-11.
std::vector<Transaction> duplicate_coinbase_list() {
  std::vector<Transaction> txs{coinbase(0), ordinary(1), coinbase(2)};
  return txs;
}

/// The root the list commits to, from the verb B-14 itself calls. See the file
/// header: this pinning is about position in the ordering, not about the tree.
Hash256 root_of(const std::vector<Transaction>& txs) {
  return zk::merkle_root_from_transactions(txs.data(), txs.size());
}

/// A context naming this node's own configuration and chain state. The engine is
/// a parameter because B-6 and B-15 must not be able to take it from the header.
/// The aggregate is initialised rather than defaulted: `ValidationContext` cannot
/// be default-constructed precisely because `PowEngine` cannot, which is the
/// guarantee that a context always names the engine this process actually runs.
ValidationContext make_context(const PowEngine& engine, std::uint32_t expected_bits,
                               std::uint64_t median, std::uint64_t now,
                               const Hash256& expected_previous) {
  return ValidationContext{engine,
                           kRegtestChain,
                           kHeight,
                           expected_previous,
                           expected_bits,
                           median,
                           now};
}

/// The trivial-engine context every accept path is built against.
ValidationContext default_context(std::uint32_t expected_bits = kEasyBits,
                                 std::uint64_t median = kMedian, std::uint64_t now = kNow) {
  return make_context(PowEngine::trivial(), expected_bits, median, now, ramp(0x70));
}

/// A header that agrees with `context` on every field the ordering compares,
/// claims the root `txs` actually commit to, and carries `timestamp`.
BlockHeader honest_header(const std::vector<Transaction>& txs, const ValidationContext& context,
                          std::uint64_t timestamp) {
  BlockHeader header{};
  header.version = 1;
  header.chain = context.expected_chain;
  header.height = context.expected_height;
  header.previous_hash = context.expected_previous;
  header.merkle_root = root_of(txs);
  header.timestamp = timestamp;
  header.difficulty_bits = context.expected_bits;
  header.engine_id = context.engine.id();
  header.nonce = 0;
  return header;
}

/// Searches a nonce that makes `header` meet its OWN target, from zero, bounded.
/// Returns false when the bound is exhausted, which is a fixture problem and is
/// always checked by the caller rather than ignored.
bool seal_nonce(BlockHeader& header, const PowEngine& engine) {
  for (std::uint64_t candidate = 0; candidate < kNonceSearchBound; ++candidate) {
    header.nonce = candidate;
    if (zk::header_meets_own_target(header, engine)) {
      return true;
    }
  }
  header.nonce = 0;
  return false;
}

/// A block valid against `context` in all thirteen rules, carrying `count`
/// transactions and this timestamp. The caller changes exactly one thing to
/// produce each rejection, and every field it does not change is the context's own.
Block valid_block(const ValidationContext& context, std::size_t count,
                  std::uint64_t timestamp = kTimestamp) {
  Block block;
  block.transactions = tx_list(count);
  block.header = honest_header(block.transactions, context, timestamp);
  ZK_CHECK(seal_nonce(block.header, context.engine));
  return block;
}

/// Runs the ordering. One call site so no test can accidentally reach a different
/// entry point.
BlockStructureResult validate(const Block& block, const ValidationContext& context) {
  return zk::validate_block_structure(block, context);
}

/// A block with an honest header over `txs` and no nonce search. Every rejection
/// test that stops before B-15 builds its fixture this way: the proof of work is
/// not on the path, and a test that needs the path to reach B-15 says so by
/// asserting the predicate itself rather than by sealing a nonce.
Block plain_block(const ValidationContext& context, std::vector<Transaction> txs,
                  std::uint64_t timestamp = kTimestamp) {
  Block block;
  block.transactions = std::move(txs);
  block.header = honest_header(block.transactions, context, timestamp);
  return block;
}

/// The kind the ordering published, read the only way this module allows.
BlockErrorKind kind_of(const Block& block, const ValidationContext& context) {
  return zk::block_structure_kind(validate(block, context));
}

template <typename Alternative>
const Alternative* alternative_is(const BlockStructureResult& result) {
  return std::get_if<Alternative>(&result);
}

}  // namespace

// The payload widths the reference gives each variant (C-12), frozen here so a
// widened or narrowed field in the header is a compile failure rather than a
// fixture that quietly stops asserting the narrow type.
static_assert(std::is_same_v<decltype(WrongChainError::expected), std::uint32_t> &&
                  std::is_same_v<decltype(WrongChainError::found), std::uint32_t>,
              "WrongChain carries two u32s");
static_assert(std::is_same_v<decltype(BadHeightError::expected), std::uint64_t> &&
                  std::is_same_v<decltype(BadHeightError::found), std::uint64_t>,
              "BadHeight carries two u64s");
static_assert(std::is_same_v<decltype(WrongEngineError::expected), std::uint8_t> &&
                  std::is_same_v<decltype(WrongEngineError::found), std::uint8_t>,
              "WrongEngine carries two u8s");
static_assert(std::is_same_v<decltype(BadDifficultyError::expected), std::uint32_t> &&
                  std::is_same_v<decltype(BadDifficultyError::found), std::uint32_t>,
              "BadDifficulty carries two u32s, the compact bits");
static_assert(std::is_same_v<decltype(TooManyTransactionsError::count), std::size_t>,
              "TooManyTransactions wraps the reference's usize");
static_assert(std::is_same_v<decltype(TimestampTooOldError::median), std::uint64_t> &&
                  std::is_same_v<decltype(TimestampTooOldError::found), std::uint64_t>,
              "TimestampTooOld carries {median, found}");
static_assert(std::is_same_v<decltype(TimestampTooFarFutureError::now), std::uint64_t> &&
                  std::is_same_v<decltype(TimestampTooFarFutureError::found), std::uint64_t>,
              "TimestampTooFarFuture carries {now, found}");

// The block owns its transactions, so the null-pointer-with-nonzero-count shape
// this entry point is asked to be safe about does not exist to be unsafe about.
static_assert(std::is_default_constructible_v<Block>, "a default Block is an empty block");
static_assert(!std::is_default_constructible_v<ValidationContext>,
              "a context cannot invent an engine, so it cannot be defaulted");

ZK_TEST(the_fixture_bits_decode_to_the_targets_the_helpers_claim) {
  // Every accept path in this file rests on `seal_nonce` finding a digest under
  // `kEasyBits`'s target, and every rejection path rests on `kHardBits`'s target
  // being unreachable. Both were nearly defeated by one assumption: a compact
  // value whose mantissa has bit 23 set is NEGATIVE, and `from_compact` returns
  // zero for it — so the intuitive "easiest possible" bits, 0x20ffffff, is in
  // fact an unmeetable target. The trap is asserted here, next to the values the
  // helpers actually use, so a future edit that re-picks them fails visibly.
  ZK_CHECK(zk::block_target(0x20ff'ffffu).is_zero());

  const zk::Uint256 easy = zk::block_target(kEasyBits);
  ZK_CHECK(!easy.is_zero());
  ZK_CHECK(easy.leading_zeros() == 1);
  ZK_CHECK(easy > zk::kDifficultyParams.pow_limit());
  ZK_CHECK(!zk::validate_bits(kEasyBits, zk::kDifficultyParams).ok());

  const zk::Uint256 hard = zk::block_target(kHardBits);
  ZK_CHECK(!hard.is_zero());
  ZK_CHECK(hard < zk::kDifficultyParams.pow_limit());
  ZK_CHECK(zk::validate_bits(kHardBits, zk::kDifficultyParams).ok());

  // The two policy verdicts above are the ones the B-7 test relies on, and they
  // are only reachable because the ordering never consults the policy itself.
  ZK_CHECK(zk::validate_bits(0, zk::kDifficultyParams).kind ==
           zk::DifficultyErrorKind::kZeroTarget);
}

ZK_TEST(a_fully_valid_block_is_accepted) {
  const ValidationContext context = default_context();
  const Block block = valid_block(context, 3);

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(zk::block_structure_accepted(result));
  ZK_CHECK(alternative_is<BlockAccepted>(result) != nullptr);
  ZK_CHECK(zk::block_structure_kind(result) == BlockErrorKind::kNone);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "None");
}

ZK_TEST(each_error_alternative_is_a_distinct_type_with_its_own_payload) {
  // One alternative per Rust variant, and each one's fields are the values the
  // reference would have published — not a shared struct with every field in it.
  const ValidationContext context = default_context();

  Block wrong_chain = valid_block(context, 2);
  ++wrong_chain.header.chain;
  const BlockStructureResult chain_result = validate(wrong_chain, context);
  const WrongChainError* wrong = alternative_is<WrongChainError>(chain_result);
  ZK_CHECK(wrong != nullptr);
  ZK_CHECK(wrong->expected == context.expected_chain);
  ZK_CHECK(wrong->found == wrong_chain.header.chain);

  Block bad_height = valid_block(context, 2);
  ++bad_height.header.height;
  const BadHeightError* height = alternative_is<BadHeightError>(validate(bad_height, context));
  ZK_CHECK(height != nullptr);
  ZK_CHECK(height->expected == context.expected_height);
  ZK_CHECK(height->found == bad_height.header.height);

  Block wrong_engine = valid_block(context, 2);
  wrong_engine.header.engine_id = zk::kEngineIdScratchpad;
  const ValidationContext trivial_context = default_context();
  const WrongEngineError* engine = alternative_is<WrongEngineError>(
      validate(wrong_engine, trivial_context));
  ZK_CHECK(engine != nullptr);
  ZK_CHECK(engine->expected == zk::kEngineIdTrivial);
  ZK_CHECK(engine->found == zk::kEngineIdScratchpad);

  Block bad_difficulty = valid_block(context, 2);
  ++bad_difficulty.header.difficulty_bits;
  const BadDifficultyError* difficulty =
      alternative_is<BadDifficultyError>(validate(bad_difficulty, context));
  ZK_CHECK(difficulty != nullptr);
  ZK_CHECK(difficulty->expected == context.expected_bits);
  ZK_CHECK(difficulty->found == bad_difficulty.header.difficulty_bits);

  const TooManyTransactionsError* many = alternative_is<TooManyTransactionsError>(
      validate(plain_block(context, tx_list(zk::kMaxBlockTransactions + 1)), context));
  ZK_CHECK(many != nullptr);
  ZK_CHECK(many->count == zk::kMaxBlockTransactions + 1);

  Block too_old = valid_block(context, 2, context.median_time_past);
  const TimestampTooOldError* old = alternative_is<TimestampTooOldError>(validate(too_old, context));
  ZK_CHECK(old != nullptr);
  ZK_CHECK(old->median == context.median_time_past);
  ZK_CHECK(old->found == too_old.header.timestamp);

  Block far_future = valid_block(context, 2, zk::future_timestamp_limit(context.now) + 1);
  const TimestampTooFarFutureError* future =
      alternative_is<TimestampTooFarFutureError>(validate(far_future, context));
  ZK_CHECK(future != nullptr);
  ZK_CHECK(future->now == context.now);
  ZK_CHECK(future->found == far_future.header.timestamp);

  // The unit variants carry nothing, which is what the corpus's null payloads say.
  static_assert(std::is_empty_v<BadPreviousHashError> && std::is_empty_v<NoTransactionsError> &&
                    std::is_empty_v<FirstNotCoinbaseError> &&
                    std::is_empty_v<DuplicateCoinbaseError> &&
                    std::is_empty_v<zk::RootMismatchError> &&
                    std::is_empty_v<InsufficientProofOfWorkError>,
                "six unit alternatives, six empty types");
}

ZK_TEST(b3_wrong_chain_is_reported_even_when_every_later_rule_is_broken) {
  // The rule that decides what a multi-fault block is *called* starts here. This
  // fixture breaks B-3 through B-7 in the header, B-10 and B-11 in the list, B-12
  // in the timestamp, and leaves B-15 unsatisfied, and every one of those is
  // checked below rather than assumed. The published verdict is still WrongChain.
  const ValidationContext context = default_context();
  Block block = plain_block(context, misplaced_coinbase_list(), kMedian);
  block.header.chain = kRegtestChain ^ 0xdead'beefu;
  block.header.height = context.expected_height + 7;
  block.header.previous_hash = ramp(0x11);
  block.header.engine_id = zk::kEngineIdScratchpad;
  // A bits value that both differs from the schedule's and denotes an unmeetable
  // target, so the B-15 witness below is structural rather than a property of one
  // particular hash.
  block.header.difficulty_bits = 0;

  ZK_CHECK(block.header.chain != context.expected_chain);
  ZK_CHECK(block.header.height != context.expected_height);
  ZK_CHECK(block.header.previous_hash != context.expected_previous);
  ZK_CHECK(!zk::header_engine_matches(block.header, context.engine));
  ZK_CHECK(block.header.difficulty_bits != context.expected_bits);
  ZK_CHECK(!block.transactions.front().is_coinbase());
  ZK_CHECK(block.header.timestamp <= context.median_time_past);
  ZK_CHECK(!zk::header_meets_own_target(block.header, context.engine));

  const BlockStructureResult result = validate(block, context);
  const WrongChainError* wrong = alternative_is<WrongChainError>(result);
  ZK_CHECK(wrong != nullptr);
  ZK_CHECK(wrong->expected == context.expected_chain);
  ZK_CHECK(wrong->found == block.header.chain);
  ZK_CHECK(zk::block_structure_kind(result) == BlockErrorKind::kWrongChain);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "WrongChain");
  ZK_CHECK(!zk::block_structure_accepted(result));
}

ZK_TEST(b4_bad_height_follows_wrong_chain_and_precedes_the_rest) {
  // C-29 is `validate_header_identity`'s own precedence and the P3.1A corpus pins
  // it; what this adds is that the ordering honours it as position 2 of 13. The
  // chain field is the context's, so B-3 passes and B-4 is the first break.
  const ValidationContext context = default_context();
  Block block = plain_block(context, misplaced_coinbase_list(), kMedian);
  block.header.height = context.expected_height + 1;
  block.header.previous_hash = ramp(0x11);
  block.header.engine_id = zk::kEngineIdScratchpad;
  // Differs from the schedule's and denotes an unmeetable target, so the B-15
  // witness is structural.
  block.header.difficulty_bits = 0;

  ZK_CHECK(block.header.chain == context.expected_chain);
  ZK_CHECK(block.header.height != context.expected_height);
  ZK_CHECK(zk::validate_header_identity(block.header, context.expected_chain,
                                        context.expected_height)
               .kind == BlockErrorKind::kBadHeight);
  ZK_CHECK(!zk::header_meets_own_target(block.header, context.engine));

  const BlockStructureResult result = validate(block, context);
  const BadHeightError* wrong = alternative_is<BadHeightError>(result);
  ZK_CHECK(wrong != nullptr);
  ZK_CHECK(wrong->expected == context.expected_height);
  ZK_CHECK(wrong->found == block.header.height);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "BadHeight");
}

ZK_TEST(b5_bad_previous_hash_precedes_engine_difficulty_and_list_rules) {
  // The tip hash is the first comparison that reads chain state rather than the
  // header's own numbers, and it is a unit variant: nothing to carry, so the
  // fixture's `error_payload: null` is the whole payload.
  const ValidationContext context = default_context();
  Block block = plain_block(context, misplaced_coinbase_list(), kMedian);
  block.header.previous_hash = ramp(0x11);
  block.header.engine_id = zk::kEngineIdScratchpad;
  ++block.header.difficulty_bits;

  ZK_CHECK(zk::validate_header_identity(block.header, context.expected_chain,
                                        context.expected_height)
               .ok());
  ZK_CHECK(block.header.previous_hash != context.expected_previous);
  ZK_CHECK(!zk::header_engine_matches(block.header, context.engine));
  ZK_CHECK(!block.transactions.front().is_coinbase());
  ZK_CHECK(block.header.timestamp <= context.median_time_past);

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(alternative_is<BadPreviousHashError>(result) != nullptr);
  ZK_CHECK(zk::block_structure_kind(result) == BlockErrorKind::kBadPreviousHash);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "BadPreviousHash");
  ZK_CHECK(!zk::block_error_kind_has_payload(BlockErrorKind::kBadPreviousHash));
}

ZK_TEST(b6_the_engine_comes_from_the_context_never_from_the_header_byte) {
  // Two nodes, one header. The byte a peer sent is only ever the `found` side:
  // the `expected` side is whatever this process was configured with, which is
  // the entire point of the rule (pow.h trust boundary).
  const ValidationContext trivial_context = default_context();
  const ValidationContext scratch_context = make_context(
      PowEngine::scratchpad(zk::kScratchpadDevnet), kEasyBits, kMedian, kNow, ramp(0x70));

  Block claims_scratchpad = plain_block(trivial_context, tx_list(2));
  claims_scratchpad.header.engine_id = zk::kEngineIdScratchpad;
  const WrongEngineError* against_trivial =
      alternative_is<WrongEngineError>(validate(claims_scratchpad, trivial_context));
  ZK_CHECK(against_trivial != nullptr);
  ZK_CHECK(against_trivial->expected == zk::kEngineIdTrivial);
  ZK_CHECK(against_trivial->found == zk::kEngineIdScratchpad);

  // The same bytes, the same bits, the same everything — only the node's own
  // configuration differs, and now the header's claim of the trivial engine is
  // the rejection. Building the engine from the byte instead would have produced
  // no error at all here, which is why that is not what the reference does.
  const Block claims_trivial = plain_block(trivial_context, tx_list(2));
  const WrongEngineError* against_scratchpad =
      alternative_is<WrongEngineError>(validate(claims_trivial, scratch_context));
  ZK_CHECK(against_scratchpad != nullptr);
  ZK_CHECK(against_scratchpad->expected == zk::kEngineIdScratchpad);
  ZK_CHECK(against_scratchpad->found == zk::kEngineIdTrivial);
  ZK_CHECK(zk::header_engine_matches(claims_trivial.header, trivial_context.engine));
  ZK_CHECK(!zk::header_engine_matches(claims_trivial.header, scratch_context.engine));

  // The counter-example, stated: the engine the header asks for is a real,
  // constructible engine that is not the one the rejecting node runs.
  const std::optional<PowEngine> asked_for =
      zk::engine_for_id(claims_trivial.header.engine_id, zk::kScratchpadDevnet);
  ZK_CHECK(asked_for.has_value());
  ZK_CHECK(asked_for->id() != scratch_context.engine.id());

  // B-6 is also reached before B-7, so a header that mismatches on both is
  // reported as an engine problem and its bits value is never looked at.
  Block both = plain_block(trivial_context, tx_list(2));
  both.header.engine_id = zk::kEngineIdScratchpad;
  ++both.header.difficulty_bits;
  ZK_CHECK(both.header.difficulty_bits != trivial_context.expected_bits);
  ZK_CHECK(alternative_is<WrongEngineError>(validate(both, trivial_context)) != nullptr);
}

ZK_TEST(b7_bad_difficulty_is_equality_and_not_the_pow_limit_policy) {
  // The requirement in one fixture: bits 0 is a value `validate_bits` rejects
  // (C-27, zero target) and a value B-7 accepts, because the reference compares
  // the header's bits with the schedule's and never consults the policy on this
  // path. So the ordering walks past B-7 and stops at the first rule that is
  // genuinely unsatisfied — the proof of work against a zero target.
  const ValidationContext zero_bits_context = default_context(0);
  const Block block = plain_block(zero_bits_context, tx_list(2));
  ZK_CHECK(block.header.difficulty_bits == zero_bits_context.expected_bits);
  ZK_CHECK(!zk::validate_bits(block.header.difficulty_bits, zk::kDifficultyParams).ok());
  ZK_CHECK(zk::compare_claimed_merkle_root(block.header, block.transactions.data(),
                                          block.transactions.size()) ==
           BlockErrorKind::kNone);
  ZK_CHECK(!zk::header_meets_own_target(block.header, zero_bits_context.engine));

  const BlockStructureResult equality_result = validate(block, zero_bits_context);
  ZK_CHECK(alternative_is<BadDifficultyError>(equality_result) == nullptr);
  ZK_CHECK(alternative_is<InsufficientProofOfWorkError>(equality_result) != nullptr);

  // And the other direction: two values are a BadDifficulty as soon as they
  // differ, with the pair carried in the payload. The pair is chosen so the
  // divergence from the policy verb is unavoidable: the header's value is one the
  // policy accepts, the context's is one the policy rejects, and yet the published
  // reason is neither of those judgements — it is the inequality. A port that
  // substituted `validate_bits` here would report the same kind for the wrong
  // reason, and would accept a header whose bits differ from the schedule's as
  // long as both happened to be policy-valid.
  const ValidationContext context = default_context(kEasyBits);
  Block mismatching = plain_block(context, tx_list(2));
  mismatching.header.difficulty_bits = kHardBits;
  ZK_CHECK(zk::validate_bits(mismatching.header.difficulty_bits, zk::kDifficultyParams).ok());
  ZK_CHECK(!zk::validate_bits(context.expected_bits, zk::kDifficultyParams).ok());
  // The header would also fail on its own (unmeetable) target, so the reported
  // kind is evidence about position as well as about equality.
  ZK_CHECK(!zk::header_meets_own_target(mismatching.header, context.engine));
  const BadDifficultyError* wrong =
      alternative_is<BadDifficultyError>(validate(mismatching, context));
  ZK_CHECK(wrong != nullptr);
  ZK_CHECK(wrong->expected == kEasyBits);
  ZK_CHECK(wrong->found == kHardBits);

  // B-7 is reached before B-8, so an empty block with wrong bits is a difficulty
  // rejection rather than a NoTransactions one.
  Block empty_with_wrong_bits = plain_block(context, std::vector<Transaction>{});
  ++empty_with_wrong_bits.header.difficulty_bits;
  ZK_CHECK(empty_with_wrong_bits.transactions.empty());
  ZK_CHECK(alternative_is<BadDifficultyError>(validate(empty_with_wrong_bits, context)) !=
           nullptr);
}

ZK_TEST(b8_the_empty_list_is_rejected_before_the_merkle_comparison) {
  // The P4.2A corpus cannot demonstrate this skip: its only empty-list case
  // publishes `roots_match: true` and `proof_of_work_meets_target: true`, so it
  // reports NoTransactions without being able to show that the comparison was
  // avoided. Here the comparison is made reachable and deliberately answered, so
  // the verdict is the only proof of position.
  // The context names the unreachable target so the position claim is real: the
  // block genuinely fails B-15, and the published verdict still says the list was
  // empty. An easy target would have let the fixture pass the last rule by
  // accident and told us nothing about where the comparison sits.
  const ValidationContext context = default_context(kHardBits);

  // A header that claims exactly the root an empty list commits to. The verb —
  // P4.1's, unchanged — says the claim is true, so a port that reached the
  // comparison would have gone on to B-15 and reported the digest.
  const Block matching = plain_block(context, std::vector<Transaction>{});
  ZK_CHECK(matching.transactions.empty());
  ZK_CHECK(matching.header.merkle_root == root_of(matching.transactions));
  ZK_CHECK(zk::compare_claimed_merkle_root(matching.header, nullptr, 0) ==
           BlockErrorKind::kNone);
  ZK_CHECK(!zk::header_meets_own_target(matching.header, context.engine));
  const BlockStructureResult matching_result = validate(matching, context);
  ZK_CHECK(alternative_is<NoTransactionsError>(matching_result) != nullptr);
  ZK_CHECK(alternative_is<InsufficientProofOfWorkError>(matching_result) == nullptr);
  ZK_CHECK(alternative_is<RootMismatchError>(matching_result) == nullptr);

  // A header that claims a root the empty list does not have. B-14 would say
  // RootMismatch if it were reached; it is not.
  Block mismatching = plain_block(context, std::vector<Transaction>{});
  mismatching.header.merkle_root = ramp(0xEE);
  ZK_CHECK(zk::compare_claimed_merkle_root(mismatching.header, nullptr, 0) ==
           BlockErrorKind::kRootMismatch);
  ZK_CHECK(alternative_is<NoTransactionsError>(validate(mismatching, context)) != nullptr);

  ZK_CHECK(std::string(zk::block_structure_name(matching_result)) == "NoTransactions");
  ZK_CHECK(kind_of(matching, context) == BlockErrorKind::kNoTransactions);
  ZK_CHECK(!zk::block_error_kind_has_payload(BlockErrorKind::kNoTransactions));
}

ZK_TEST(b9_two_thousand_transactions_is_accepted_at_the_count_boundary) {
  // `>` and not `>=`, so the limit itself is a valid block. The fixture has to be
  // honest in all twelve other rules for the accept to mean anything, so this is
  // also the largest end-to-end pass in the file.
  const ValidationContext context = default_context();
  const Block block = valid_block(context, zk::kMaxBlockTransactions);
  ZK_CHECK(block.transactions.size() == zk::kMaxBlockTransactions);
  ZK_CHECK(!(block.transactions.size() > zk::kMaxBlockTransactions));
  ZK_CHECK(block.transactions.front().is_coinbase());

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(zk::block_structure_accepted(result));
  ZK_CHECK(alternative_is<TooManyTransactionsError>(result) == nullptr);
}

ZK_TEST(b9_two_thousand_one_transactions_is_rejected_with_its_count) {
  const ValidationContext context = default_context();
  std::vector<Transaction> over = tx_list(zk::kMaxBlockTransactions + 1);
  over[0] = ordinary(9'000);  // no coinbase at the front, so B-10 is broken too
  const Block block = plain_block(context, std::move(over), kMedian);  // B-12 broken too
  ZK_CHECK(block.transactions.size() == zk::kMaxBlockTransactions + 1);
  ZK_CHECK(!block.transactions.front().is_coinbase());
  ZK_CHECK(block.header.timestamp <= context.median_time_past);

  // B-9 therefore also outranks B-10, B-11, B-12, B-13, B-14 and B-15.
  const BlockStructureResult result = validate(block, context);
  const TooManyTransactionsError* many = alternative_is<TooManyTransactionsError>(result);
  ZK_CHECK(many != nullptr);
  ZK_CHECK(many->count == zk::kMaxBlockTransactions + 1);
  ZK_CHECK(zk::block_structure_kind(result) == BlockErrorKind::kTooManyTransactions);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "TooManyTransactions");
  ZK_CHECK(zk::block_error_kind_has_payload(BlockErrorKind::kTooManyTransactions));
}

ZK_TEST(b10_first_not_coinbase_precedes_the_duplicate_and_the_later_rules) {
  // One list that breaks both coinbase rules: an ordinary transaction in
  // position 0 and a coinbase further down. Only the first is reported. The
  // context names the unreachable target so the header genuinely breaks B-15 as
  // well, and the timestamp breaks B-12; neither is what the ordering publishes.
  const ValidationContext context = default_context(kHardBits);
  Block block = plain_block(context, misplaced_coinbase_list(), kMedian);
  ZK_CHECK(block.transactions.size() <= zk::kMaxBlockTransactions);
  ZK_CHECK(!block.transactions.front().is_coinbase());
  ZK_CHECK(block.transactions[2].is_coinbase());
  ZK_CHECK(block.header.timestamp <= context.median_time_past);
  ZK_CHECK(!zk::header_meets_own_target(block.header, context.engine));

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(alternative_is<FirstNotCoinbaseError>(result) != nullptr);
  ZK_CHECK(alternative_is<DuplicateCoinbaseError>(result) == nullptr);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "FirstNotCoinbase");
  ZK_CHECK(!zk::block_error_kind_has_payload(BlockErrorKind::kFirstNotCoinbase));
}

ZK_TEST(b11_duplicate_coinbase_precedes_the_timestamp_and_root_rules) {
  const ValidationContext context = default_context();
  Block block = plain_block(context, duplicate_coinbase_list(), kMedian);
  block.header.merkle_root = ramp(0xEE);  // B-14 broken too
  ZK_CHECK(block.transactions.front().is_coinbase());
  ZK_CHECK(block.transactions[2].is_coinbase());
  ZK_CHECK(block.header.timestamp <= context.median_time_past);
  ZK_CHECK(block.header.merkle_root != root_of(block.transactions));

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(alternative_is<DuplicateCoinbaseError>(result) != nullptr);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "DuplicateCoinbase");

  // The other side of the rule: a lone coinbase is the whole list and is valid,
  // because `transactions[1..]` is empty and nothing repeats.
  const Block single = valid_block(context, 1);
  ZK_CHECK(single.transactions.size() == 1);
  ZK_CHECK(single.transactions.front().is_coinbase());
  ZK_CHECK(zk::block_structure_accepted(validate(single, context)));
}

ZK_TEST(b12_rejects_the_median_itself_and_accepts_the_second_after_it) {
  // `<=`, not `<`: a block that carries the median timestamp of the previous
  // eleven blocks is too old. The payload is the pair the reference publishes,
  // `{median, found}`, in that field order.
  const ValidationContext context = default_context();
  const Block equal = valid_block(context, 2, context.median_time_past);
  ZK_CHECK(equal.header.timestamp == context.median_time_past);
  const BlockStructureResult equal_result = validate(equal, context);
  const TimestampTooOldError* old = alternative_is<TimestampTooOldError>(equal_result);
  ZK_CHECK(old != nullptr);
  ZK_CHECK(old->median == context.median_time_past);
  ZK_CHECK(old->found == equal.header.timestamp);
  ZK_CHECK(std::string(zk::block_structure_name(equal_result)) == "TimestampTooOld");

  const Block one_more = valid_block(context, 2, context.median_time_past + 1);
  ZK_CHECK(one_more.header.timestamp == context.median_time_past + 1);
  ZK_CHECK(zk::block_structure_accepted(validate(one_more, context)));
}

ZK_TEST(b13_accepts_the_limit_itself_and_rejects_the_second_after_it) {
  const ValidationContext context = default_context();
  const std::uint64_t limit = zk::future_timestamp_limit(context.now);
  ZK_CHECK(limit == context.now + zk::kMaxFutureSeconds);

  const Block at_limit = valid_block(context, 2, limit);
  ZK_CHECK(at_limit.header.timestamp == limit);
  ZK_CHECK(zk::block_structure_accepted(validate(at_limit, context)));

  const Block one_more = valid_block(context, 2, limit + 1);
  ZK_CHECK(one_more.header.timestamp > limit);
  const BlockStructureResult result = validate(one_more, context);
  const TimestampTooFarFutureError* future = alternative_is<TimestampTooFarFutureError>(result);
  ZK_CHECK(future != nullptr);
  ZK_CHECK(future->now == context.now);
  ZK_CHECK(future->found == one_more.header.timestamp);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "TimestampTooFarFuture");
}

ZK_TEST(b13_saturates_at_the_clock_maximum_instead_of_wrapping) {
  // The witness against `now + 7200`. With a clock this high an unchecked
  // addition lands back in 1970 and every real timestamp reads as far-future,
  // while the reference's `saturating_add` reaches `u64::MAX` and stops there.
  ZK_CHECK(zk::future_timestamp_limit(0) == zk::kMaxFutureSeconds);
  ZK_CHECK(zk::future_timestamp_limit(kMaxClock - zk::kMaxFutureSeconds - 1) == kMaxClock - 1);
  ZK_CHECK(zk::future_timestamp_limit(kMaxClock - zk::kMaxFutureSeconds) == kMaxClock);
  ZK_CHECK(zk::future_timestamp_limit(kMaxClock - zk::kMaxFutureSeconds + 1) == kMaxClock);
  ZK_CHECK(zk::future_timestamp_limit(kMaxClock - 1) == kMaxClock);
  ZK_CHECK(zk::future_timestamp_limit(kMaxClock) == kMaxClock);
  ZK_CHECK(zk::future_timestamp_limit(kMaxClock) != kMaxClock + zk::kMaxFutureSeconds);

  // A clock at the maximum: nothing can be later than it, so B-13 is unsatisfiable
  // and an otherwise-valid block carrying `u64::MAX` is accepted.
  const ValidationContext max_clock = default_context(kEasyBits, kMedian, kMaxClock);
  const Block at_max = valid_block(max_clock, 2, kMaxClock);
  ZK_CHECK(at_max.header.timestamp == kMaxClock);
  ZK_CHECK(zk::block_structure_accepted(validate(at_max, max_clock)));

  // The last clock whose addition is exact, at the timestamp it reaches.
  const ValidationContext exact =
      default_context(kEasyBits, kMedian, kMaxClock - zk::kMaxFutureSeconds);
  const Block at_edge = valid_block(exact, 2, kMaxClock);
  ZK_CHECK(zk::block_structure_accepted(validate(at_edge, exact)));

  // The first clock that clamps: the limit stays `u64::MAX` rather than wrapping,
  // so `u64::MAX` is now one second past it and is rejected — with the raw clock
  // in the payload, not the clamped limit.
  const ValidationContext clamped =
      default_context(kEasyBits, kMedian, kMaxClock - zk::kMaxFutureSeconds - 1);
  ZK_CHECK(zk::future_timestamp_limit(clamped.now) == kMaxClock - 1);
  const Block past = valid_block(clamped, 2, kMaxClock);
  const TimestampTooFarFutureError* rejected =
      alternative_is<TimestampTooFarFutureError>(validate(past, clamped));
  ZK_CHECK(rejected != nullptr);
  ZK_CHECK(rejected->now == clamped.now);
  ZK_CHECK(rejected->found == kMaxClock);

  // And the mid-range case a wrapping implementation gets wrong in the other
  // direction: now = MAX - 3600 wraps to 3599, so a bare `+` rejects every block
  // while the reference accepts this one.
  const ValidationContext wrapped_port_would_fail =
      default_context(kEasyBits, kMedian, kMaxClock - zk::kMaxFutureSeconds / 2);
  ZK_CHECK(wrapped_port_would_fail.now + zk::kMaxFutureSeconds < kMaxClock);
  const Block still_valid = valid_block(wrapped_port_would_fail, 2, kMaxClock);
  ZK_CHECK(zk::block_structure_accepted(validate(still_valid, wrapped_port_would_fail)));
}

ZK_TEST(b12_is_reached_before_b13_when_one_timestamp_breaks_both) {
  // A median beyond the future window cannot occur on a running chain — it means
  // the previous eleven blocks are all in the node's future. The context exists
  // only so a single field breaks B-12 and B-13 at once, which is what makes the
  // precedence observable.
  const ValidationContext context = default_context(kEasyBits, 10'000, 0);
  const Block block = plain_block(context, tx_list(2), 8'000);
  ZK_CHECK(block.header.timestamp <= context.median_time_past);
  ZK_CHECK(block.header.timestamp > zk::future_timestamp_limit(context.now));
  ZK_CHECK(zk::future_timestamp_limit(context.now) == zk::kMaxFutureSeconds);

  const BlockStructureResult result = validate(block, context);
  const TimestampTooOldError* old = alternative_is<TimestampTooOldError>(result);
  ZK_CHECK(old != nullptr);
  ZK_CHECK(old->median == 10'000);
  ZK_CHECK(old->found == 8'000);
  ZK_CHECK(alternative_is<TimestampTooFarFutureError>(result) == nullptr);
}

ZK_TEST(b13_is_reached_before_b14_when_both_are_broken) {
  // The unreachable target makes the third witness below structural: the block
  // breaks B-13, B-14 and B-15 at once and is named by the earliest of them.
  const ValidationContext context = default_context(kHardBits);
  Block block = plain_block(context, tx_list(2), zk::future_timestamp_limit(context.now) + 1);
  block.header.merkle_root = ramp(0xEE);
  ZK_CHECK(block.header.timestamp > zk::future_timestamp_limit(context.now));
  ZK_CHECK(block.header.merkle_root != root_of(block.transactions));
  ZK_CHECK(zk::compare_claimed_merkle_root(block.header, block.transactions.data(),
                                           block.transactions.size()) ==
           BlockErrorKind::kRootMismatch);
  ZK_CHECK(!zk::header_meets_own_target(block.header, context.engine));

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(alternative_is<TimestampTooFarFutureError>(result) != nullptr);
  ZK_CHECK(alternative_is<RootMismatchError>(result) == nullptr);
}

ZK_TEST(b14_is_reached_before_b15_when_both_are_broken) {
  // The ordering the task requires and the corpus cannot show: a block whose root
  // claim is false AND whose work falls short reports the root, because the
  // reference compares the root first. Both predicates are asserted here, so the
  // verdict is evidence about position and not about which fixture happens to be
  // weaker.
  const ValidationContext context = default_context(kHardBits);
  Block block = plain_block(context, tx_list(2));
  block.header.merkle_root = ramp(0xEE);
  ZK_CHECK(block.header.merkle_root != root_of(block.transactions));
  ZK_CHECK(!zk::header_meets_own_target(block.header, context.engine));

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(alternative_is<RootMismatchError>(result) != nullptr);
  ZK_CHECK(alternative_is<InsufficientProofOfWorkError>(result) == nullptr);
  ZK_CHECK(zk::block_structure_kind(result) == BlockErrorKind::kRootMismatch);
}

ZK_TEST(b14_is_the_p41_verb_reached_by_the_ordering_not_restated_in_it) {
  // The claim is that B-14 has one implementation. So the ordering's answer must
  // be exactly the verb's answer, for both sides of the comparison, and the verb
  // must still do the thing the P4.1A corpus pinned it for: answer for an empty
  // list from a null buffer.
  const ValidationContext context = default_context();
  const std::vector<Transaction> txs = tx_list(2);

  Block matching = plain_block(context, txs);
  ZK_CHECK(zk::compare_claimed_merkle_root(matching.header, txs.data(), txs.size()) ==
           BlockErrorKind::kNone);
  ZK_CHECK(seal_nonce(matching.header, context.engine));
  const BlockStructureResult accepted_result = validate(matching, context);
  ZK_CHECK(zk::block_structure_accepted(accepted_result));

  Block claiming = plain_block(context, txs);
  claiming.header.merkle_root = ramp(0xEE);
  const BlockErrorKind verb =
      zk::compare_claimed_merkle_root(claiming.header, txs.data(), txs.size());
  ZK_CHECK(verb == BlockErrorKind::kRootMismatch);
  const BlockStructureResult rejected_result = validate(claiming, context);
  ZK_CHECK(alternative_is<RootMismatchError>(rejected_result) != nullptr);
  ZK_CHECK(zk::block_structure_kind(rejected_result) == verb);
  ZK_CHECK(static_cast<std::uint8_t>(verb) == 3);

  // The untouched P4.1 boundary: null is legal with count 0 and the answer is the
  // tagged empty tree, so a claim of it matches and any other claim does not.
  BlockHeader empty_claim{};
  empty_claim.merkle_root = zk::merkle_root_from_transactions(nullptr, 0);
  ZK_CHECK(zk::compare_claimed_merkle_root(empty_claim, nullptr, 0) == BlockErrorKind::kNone);
  empty_claim.merkle_root = ramp(0x01);
  ZK_CHECK(zk::compare_claimed_merkle_root(empty_claim, nullptr, 0) ==
           BlockErrorKind::kRootMismatch);
}

ZK_TEST(b15_insufficient_proof_of_work_is_the_last_rule) {
  // Everything the ordering checks before the digest is satisfied here — the bits
  // match the context, the list is well-formed, both timestamps are in range and
  // the header claims the root the transactions really commit to — and the only
  // thing wrong is the work. `header_meets_own_target` is asserted rather than
  // assumed, because nothing in this file trusts a hand-picked nonce.
  const ValidationContext context = default_context(kHardBits);
  const Block block = plain_block(context, tx_list(2));
  ZK_CHECK(block.header.difficulty_bits == context.expected_bits);
  ZK_CHECK(zk::validate_header_identity(block.header, context.expected_chain,
                                        context.expected_height)
               .ok());
  ZK_CHECK(zk::header_engine_matches(block.header, context.engine));
  ZK_CHECK(block.header.timestamp > context.median_time_past);
  ZK_CHECK(block.header.timestamp <= zk::future_timestamp_limit(context.now));
  ZK_CHECK(zk::compare_claimed_merkle_root(block.header, block.transactions.data(),
                                           block.transactions.size()) == BlockErrorKind::kNone);
  ZK_CHECK(!zk::header_meets_own_target(block.header, context.engine));

  const BlockStructureResult result = validate(block, context);
  ZK_CHECK(alternative_is<InsufficientProofOfWorkError>(result) != nullptr);
  ZK_CHECK(zk::block_structure_kind(result) == BlockErrorKind::kInsufficientProofOfWork);
  ZK_CHECK(std::string(zk::block_structure_name(result)) == "InsufficientProofOfWork");
  ZK_CHECK(!zk::block_error_kind_has_payload(BlockErrorKind::kInsufficientProofOfWork));

  // The mirror image: the same block with a nonce that does meet the target is
  // accepted, so the rejection above is about the digest and not about the
  // fixture's shape.
  const ValidationContext easy = default_context(kEasyBits);
  ZK_CHECK(zk::block_structure_accepted(validate(valid_block(easy, 2), easy)));
}

ZK_TEST(the_taxonomy_numbers_names_and_payload_set_are_frozen) {
  // The four values the P4.1A corpus stamped did not move when the other ten were
  // appended, and the ten new ones are the append-only block above them in the
  // order the ordering reaches them. A renumbering here would silently re-map
  // every fixture, so the numbers are asserted at run time as well as in the
  // header's static_asserts.
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kNone) == 0);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kWrongChain) == 1);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kBadHeight) == 2);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kRootMismatch) == 3);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kBadPreviousHash) == 4);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kWrongEngine) == 5);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kBadDifficulty) == 6);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kNoTransactions) == 7);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kTooManyTransactions) == 8);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kFirstNotCoinbase) == 9);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kDuplicateCoinbase) == 10);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kTimestampTooOld) == 11);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kTimestampTooFarFuture) == 12);
  ZK_CHECK(static_cast<std::uint8_t>(BlockErrorKind::kInsufficientProofOfWork) == 13);

  // C-14: the names are the reference's variant spellings, verbatim.
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kNone)) == "None");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kWrongChain)) == "WrongChain");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kBadHeight)) == "BadHeight");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kRootMismatch)) ==
           "RootMismatch");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kBadPreviousHash)) ==
           "BadPreviousHash");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kWrongEngine)) == "WrongEngine");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kBadDifficulty)) ==
           "BadDifficulty");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kNoTransactions)) ==
           "NoTransactions");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kTooManyTransactions)) ==
           "TooManyTransactions");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kFirstNotCoinbase)) ==
           "FirstNotCoinbase");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kDuplicateCoinbase)) ==
           "DuplicateCoinbase");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kTimestampTooOld)) ==
           "TimestampTooOld");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kTimestampTooFarFuture)) ==
           "TimestampTooFarFuture");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kInsufficientProofOfWork)) ==
           "InsufficientProofOfWork");

  // C-12: exactly the seven kinds whose corpus payload object is not null.
  const BlockErrorKind payload_kinds[] = {
      BlockErrorKind::kWrongChain, BlockErrorKind::kBadHeight, BlockErrorKind::kWrongEngine,
      BlockErrorKind::kBadDifficulty, BlockErrorKind::kTooManyTransactions,
      BlockErrorKind::kTimestampTooOld, BlockErrorKind::kTimestampTooFarFuture};
  const BlockErrorKind unit_kinds[] = {
      BlockErrorKind::kNone, BlockErrorKind::kRootMismatch, BlockErrorKind::kBadPreviousHash,
      BlockErrorKind::kNoTransactions, BlockErrorKind::kFirstNotCoinbase,
      BlockErrorKind::kDuplicateCoinbase, BlockErrorKind::kInsufficientProofOfWork};
  for (BlockErrorKind kind : payload_kinds) {
    ZK_CHECK(zk::block_error_kind_has_payload(kind));
  }
  for (BlockErrorKind kind : unit_kinds) {
    ZK_CHECK(!zk::block_error_kind_has_payload(kind));
  }
}

ZK_TEST(the_error_identity_is_the_declared_kind_never_the_variant_position) {
  // `RootMismatchError` is the fourteenth alternative declared in
  // `BlockStructureResult` and carries the numeric kind 3 that P4.1 froze. The two
  // numbers disagree on purpose, which is why `block_structure_kind` visits the
  // alternative and the index is never an error identifier. `index()` is consulted
  // below only to demonstrate that it is the wrong answer, not to produce one.
  const BlockStructureResult root(RootMismatchError{});
  ZK_CHECK(zk::block_structure_kind(root) == BlockErrorKind::kRootMismatch);
  ZK_CHECK(static_cast<std::uint8_t>(zk::block_structure_kind(root)) == 3);
  ZK_CHECK(root.index() == 12);
  ZK_CHECK(root.index() != 3);

  const BlockStructureResult table[] = {
      BlockAccepted{},        WrongChainError{},         BadHeightError{},
      BadPreviousHashError{}, WrongEngineError{},        BadDifficultyError{},
      NoTransactionsError{},  TooManyTransactionsError{}, FirstNotCoinbaseError{},
      DuplicateCoinbaseError{}, TimestampTooOldError{},   TimestampTooFarFutureError{},
      RootMismatchError{},    InsufficientProofOfWorkError{},
  };
  const BlockErrorKind expected[] = {
      BlockErrorKind::kNone, BlockErrorKind::kWrongChain, BlockErrorKind::kBadHeight,
      BlockErrorKind::kBadPreviousHash, BlockErrorKind::kWrongEngine,
      BlockErrorKind::kBadDifficulty, BlockErrorKind::kNoTransactions,
      BlockErrorKind::kTooManyTransactions, BlockErrorKind::kFirstNotCoinbase,
      BlockErrorKind::kDuplicateCoinbase, BlockErrorKind::kTimestampTooOld,
      BlockErrorKind::kTimestampTooFarFuture, BlockErrorKind::kRootMismatch,
      BlockErrorKind::kInsufficientProofOfWork,
  };
  constexpr std::size_t kRows = sizeof(table) / sizeof(table[0]);
  static_assert(kRows == sizeof(expected) / sizeof(expected[0]),
                "one row per alternative, one kind per row");
  static_assert(kRows == std::variant_size_v<BlockStructureResult>,
                "the table covers every alternative in the result type");

  for (std::size_t i = 0; i < kRows; ++i) {
    ZK_CHECK(table[i].index() == i);  // position, i.e. declaration order and nothing more
    ZK_CHECK(zk::block_structure_kind(table[i]) == expected[i]);
    ZK_CHECK(std::string(zk::block_structure_name(table[i])) ==
             std::string(zk::block_error_kind_name(expected[i])));
    ZK_CHECK(zk::block_structure_accepted(table[i]) == (expected[i] == BlockErrorKind::kNone));
  }
}

ZK_TEST(an_api_precondition_failure_is_not_a_consensus_verdict) {
  // `block_structure_verdict_for` is the seam where a reused verb hands its
  // taxonomy over. It is given a kind and not the expected/found values, so a
  // payload-bearing kind cannot be answered honestly: fabricating zeroes would
  // publish a payload the reference never computed, and returning an accept would
  // fail open. Both are contract violations, and both throw instead of becoming a
  // rule. An out-of-range value is the same case with a different reason.
  const BlockErrorKind payload_kinds[] = {
      BlockErrorKind::kWrongChain, BlockErrorKind::kBadHeight, BlockErrorKind::kWrongEngine,
      BlockErrorKind::kBadDifficulty, BlockErrorKind::kTooManyTransactions,
      BlockErrorKind::kTimestampTooOld, BlockErrorKind::kTimestampTooFarFuture};
  for (BlockErrorKind kind : payload_kinds) {
    bool threw = false;
    try {
      (void)zk::block_structure_verdict_for(kind);
    } catch (const std::logic_error&) {
      threw = true;
    }
    ZK_CHECK(threw);
  }

  bool out_of_range_threw = false;
  try {
    (void)zk::block_structure_verdict_for(static_cast<BlockErrorKind>(200));
  } catch (const std::logic_error&) {
    out_of_range_threw = true;
  }
  ZK_CHECK(out_of_range_threw);

  // The kinds it does answer, each answered with its own alternative.
  ZK_CHECK(alternative_is<BlockAccepted>(
               zk::block_structure_verdict_for(BlockErrorKind::kNone)) != nullptr);
  ZK_CHECK(alternative_is<BadPreviousHashError>(
               zk::block_structure_verdict_for(BlockErrorKind::kBadPreviousHash)) != nullptr);
  ZK_CHECK(alternative_is<NoTransactionsError>(
               zk::block_structure_verdict_for(BlockErrorKind::kNoTransactions)) != nullptr);
  ZK_CHECK(alternative_is<FirstNotCoinbaseError>(
               zk::block_structure_verdict_for(BlockErrorKind::kFirstNotCoinbase)) != nullptr);
  ZK_CHECK(alternative_is<DuplicateCoinbaseError>(
               zk::block_structure_verdict_for(BlockErrorKind::kDuplicateCoinbase)) != nullptr);
  ZK_CHECK(alternative_is<RootMismatchError>(
               zk::block_structure_verdict_for(BlockErrorKind::kRootMismatch)) != nullptr);
  ZK_CHECK(alternative_is<InsufficientProofOfWorkError>(
               zk::block_structure_verdict_for(BlockErrorKind::kInsufficientProofOfWork)) !=
           nullptr);

  // And the reason the ordering itself has no pointer precondition: the block
  // owns its transactions, so there is no null-buffer-with-count to hand in and
  // the degenerate block is an ordinary consensus rejection rather than a failure
  // of the call.
  const ValidationContext context = default_context();
  const Block nothing{};
  ZK_CHECK(nothing.transactions.empty());
  ZK_CHECK(alternative_is<WrongChainError>(validate(nothing, context)) != nullptr);
}
