#include "zerocoin/block.h"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "zerocoin/merkle.h"

namespace zk {
namespace {

/// The message for a kind that cannot be answered without payload values this
/// call site does not hold. Kept in one place so every contract violation reads
/// the same way and names the kind it could not map.
std::string unmappable_kind_message(BlockErrorKind kind) {
  return std::string("block structure verdict requested for a kind whose payload this "
                     "call site does not have: ") +
         block_error_kind_name(kind);
}

bool is_unit_or_none(BlockErrorKind kind) noexcept {
  return !block_error_kind_has_payload(kind);
}

}  // namespace

BlockErrorKind block_structure_kind(const BlockStructureResult& result) noexcept {
  // The alternative is asked what it is. `std::variant::index()` is never
  // consulted: it is a property of this header's declaration order, while the
  // taxonomy in header.h is append-only and frozen from P4.1, and the two are
  // deliberately not the same numbering (RootMismatchError is index 12 and kind
  // 3). A generic lambda over the variant reads the `kind` member the alternative
  // itself declares, for every alternative, at compile time, so an alternative
  // that ever forgets to declare its kind fails to compile rather than reporting
  // the wrong rule.
  return std::visit([](const auto& alternative) noexcept -> BlockErrorKind {
            return std::remove_cvref_t<decltype(alternative)>::kind;
          },
          result);
}

const char* block_structure_name(const BlockStructureResult& result) noexcept {
  // The name table belongs to the taxonomy (C-14) and is not duplicated here:
  // one table, so a name cannot disagree with the kind the fixture asserts.
  return block_error_kind_name(block_structure_kind(result));
}

BlockStructureResult block_structure_verdict_for(BlockErrorKind kind) {
  switch (kind) {
    case BlockErrorKind::kNone:
      return BlockAccepted{};
    case BlockErrorKind::kBadPreviousHash:
      return BadPreviousHashError{};
    case BlockErrorKind::kNoTransactions:
      return NoTransactionsError{};
    case BlockErrorKind::kFirstNotCoinbase:
      return FirstNotCoinbaseError{};
    case BlockErrorKind::kDuplicateCoinbase:
      return DuplicateCoinbaseError{};
    case BlockErrorKind::kRootMismatch:
      return RootMismatchError{};
    case BlockErrorKind::kInsufficientProofOfWork:
      return InsufficientProofOfWorkError{};
    case BlockErrorKind::kWrongChain:
    case BlockErrorKind::kBadHeight:
    case BlockErrorKind::kWrongEngine:
    case BlockErrorKind::kBadDifficulty:
    case BlockErrorKind::kTooManyTransactions:
    case BlockErrorKind::kTimestampTooOld:
    case BlockErrorKind::kTimestampTooFarFuture:
      break;
  }
  // Every payload-bearing kind reaches this point, and every kind the switch
  // above does not name is outside the declared range. Neither is a consensus
  // verdict this function is allowed to invent: a payload cannot be fabricated,
  // and a value no rule produces cannot be mapped to a rule. Fail closed — the
  // caller gets an exception, never an accept and never a made-up rejection.
  if (is_unit_or_none(kind)) {
    throw std::logic_error("block structure verdict requested for a kind outside the "
                           "declared taxonomy: " +
                           std::string(block_error_kind_name(kind)));
  }
  throw std::logic_error(unmappable_kind_message(kind));
}

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

BlockStructureResult validate_block_structure(const Block& block,
                                              const ValidationContext& context) {
  const BlockHeader& h = block.header;

  // B-3, B-4. The verb owns both comparisons and their precedence (C-29), so
  // this is a call, not a restatement; the two payload pairs are carried into
  // the alternatives rather than re-derived from the header.
  const BlockIdentityError identity =
      validate_header_identity(h, context.expected_chain, context.expected_height);
  if (!identity.ok()) {
    if (identity.kind == BlockErrorKind::kWrongChain) {
      return WrongChainError{identity.expected_chain, identity.found_chain};
    }
    if (identity.kind == BlockErrorKind::kBadHeight) {
      return BadHeightError{identity.expected_height, identity.found_height};
    }
    // Unreachable through `validate_header_identity`, which produces exactly the
    // three kinds its type documents. A fourth value would be a corrupted result
    // rather than a block verdict, so it is not silently mapped to either of the
    // nearby payload kinds.
    throw std::logic_error("header identity verb returned a kind it does not produce: " +
                           std::string(block_error_kind_name(identity.kind)));
  }

  // B-5. The tip hash is context, never a value read out of the block.
  if (h.previous_hash != context.expected_previous) {
    return BadPreviousHashError{};
  }

  // B-6. `header_engine_matches` is the comparison the reference performs, and
  // the engine it compares against is the context's — this node's configured
  // algorithm. The header's byte is only ever the `found` side of the payload;
  // selecting an engine from it would let a peer choose this node's hash
  // function (pow.h, trust boundary).
  if (!header_engine_matches(h, context.engine)) {
    return WrongEngineError{context.engine.id(), h.engine_id};
  }

  // B-7. Plain equality with the bits the schedule requires, exactly as the
  // reference writes it. `validate_bits` is NOT consulted: the reference never
  // reaches the pow-limit policy on this path, so reusing that verb here would
  // add a rule the ordering does not have and would report the wrong kind for a
  // header whose bits differ from the expectation (C-27 is a different rule).
  if (h.difficulty_bits != context.expected_bits) {
    return BadDifficultyError{context.expected_bits, h.difficulty_bits};
  }

  // B-8. The empty-list rejection, and it returns here — before B-9, before the
  // coinbase checks read element 0, and before any Merkle composition. An empty
  // block is never handed to `compare_claimed_merkle_root` on this path, so the
  // tagged empty-tree digest is not what this verdict depends on.
  if (block.transactions.empty()) {
    return NoTransactionsError{};
  }

  // B-9. Strictly over the limit, so a block with exactly
  // `kMaxBlockTransactions` transactions passes this rule.
  if (block.transactions.size() > kMaxBlockTransactions) {
    return TooManyTransactionsError{block.transactions.size()};
  }

  // B-10, B-11. Exactly one coinbase and it is first. The count is at least one
  // here because B-8 returned, so `front()` and `begin() + 1` are both in
  // range; `transactions[1..].iter().any(...)` is the same iteration.
  if (!block.transactions.front().is_coinbase()) {
    return FirstNotCoinbaseError{};
  }
  if (std::any_of(block.transactions.begin() + 1, block.transactions.end(),
                  [](const Transaction& tx) { return tx.is_coinbase(); })) {
    return DuplicateCoinbaseError{};
  }

  // B-12. `<= median`, so a timestamp equal to the median of the previous eleven
  // blocks is rejected — the reference's own operator, not a `<`.
  if (h.timestamp <= context.median_time_past) {
    return TimestampTooOldError{context.median_time_past, h.timestamp};
  }

  // B-13. `> now.saturating_add(MAX_FUTURE_SECONDS)`. The addition goes through
  // `future_timestamp_limit`, which saturates; a bare `now + 7200` wraps for a
  // clock near `u64::MAX` and then rejects every ordinary timestamp. Equality
  // with the limit is accepted.
  if (h.timestamp > future_timestamp_limit(context.now)) {
    return TimestampTooFarFutureError{context.now, h.timestamp};
  }

  // B-14. P4.1's verb, called rather than restated, and reached only now that
  // the list is known to be non-empty. The mapper translates the taxonomy the
  // verb returns into the alternative this result type carries; it can only ever
  // see kNone or kRootMismatch here.
  const BlockStructureResult root_verdict = block_structure_verdict_for(
      compare_claimed_merkle_root(h, block.transactions.data(), block.transactions.size()));
  if (!std::holds_alternative<BlockAccepted>(root_verdict)) {
    return root_verdict;
  }

  // B-15. Last, after the root comparison, as the reference orders it. The
  // predicate is the header's own `meets_own_target` against the context's
  // engine — the header's own bits, not the schedule's — which is why a header
  // whose work falls short of the target the chain required has already been
  // stopped by B-7 rather than by this rule.
  if (!header_meets_own_target(h, context.engine)) {
    return InsufficientProofOfWorkError{};
  }

  return BlockAccepted{};
}

}  // namespace zk
