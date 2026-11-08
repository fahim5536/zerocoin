// Block structure validation, mirroring zerocoin/src/consensus/block.rs.
//
// Two things live in this file, and they are related exactly the way the
// reference relates them.
//
//   P4.1    `compare_claimed_merkle_root` — rule B-14 as a verdict on its own.
//           The reference site is three lines (block.rs:217-220):
//
//               let root = Self::compute_merkle_root(&self.transactions);
//               if h.merkle_root != root {
//                   return Err(BlockError::RootMismatch);
//               }
//
//           Its behaviour is NOT changed by this slice: the P4.1A corpus replays
//           thirty cases against it, including the two boundary cases whose whole
//           point is that the comparison itself has an answer for an empty list.
//           Widening it — adding a count limit, a coinbase check, a guard — would
//           move an already-verified verdict and would be a second rule.
//           `validate_block_structure` below CALLS it for B-14 rather than
//           restating it.
//
//   P4.2B-1 `Block`, `ValidationContext` and `validate_block_structure` — the
//           ordering. The kernel now has the `Block` type this file once declined
//           to create, because the ordering cannot be ported without the two
//           things it reads. The reference reaches the comparison through
//           `self.header` and `self.transactions`, so `Block` is those two fields
//           and nothing else. Everything else the ordering compares is not block
//           data at all — the engine this NODE runs, the chain id and height this
//           chain expects, the tip hash, the bits the schedule requires, the
//           median of the previous eleven blocks, this node's clock — so those
//           eight inputs are an explicit `ValidationContext`, in the reference's
//           own parameter order (block.rs:165-171), with no defaults.
//
// The order is a compatibility requirement, not a style choice. `validate_structure`
// returns the FIRST failure it reaches, so a block that breaks six rules reports
// one of them, and "which one" is therefore consensus-observable. C-13 is the
// requirement to report it; the sequence below is `block.rs` read top to bottom,
// and CONSENSUS_RULES.md §2.4 numbers the same thirteen rules:
//
//   B-3   WrongChain              header.chain != expected_chain          (payload u32, u32)
//   B-4   BadHeight               header.height != expected_height        (payload u64, u64)
//   B-5   BadPreviousHash         header.previous_hash != tip hash        (unit)
//   B-6   WrongEngine             header.engine_id != engine.id()         (payload u8, u8)
//   B-7   BadDifficulty           header.bits != expected_bits            (payload u32, u32)
//   B-8   NoTransactions          transactions.is_empty()                 (unit)
//   B-9   TooManyTransactions     transactions.len() > 2000               (payload usize)
//   B-10  FirstNotCoinbase        !transactions[0].is_coinbase()          (unit)
//   B-11  DuplicateCoinbase       any of transactions[1..] is a coinbase  (unit)
//   B-12  TimestampTooOld         header.timestamp <= median_time_past    (payload u64, u64)
//   B-13  TimestampTooFarFuture   header.timestamp > now.saturating_add(7200)  (payload u64, u64)
//   B-14  RootMismatch            header.merkle_root != computed root     (unit)
//   B-15  InsufficientProofOfWork !header.meets_own_target(engine)        (unit)
//
// Three facts about that sequence are worth stating where they are decided,
// because the P4.2A corpus (test/p42-vectors/chain/block_structure.json, 36 cases)
// does not demonstrate them and a later reader should not have to rediscover it:
//
//   (8, 9)   mutually exclusive by construction. `is_empty()` and `len() > 2000`
//            cannot both hold, so no fixture can order B-8 against B-9 and none is
//            needed; C-13 exempts the pair for this reason.
//   8 before 14/15   follows from the source order above, but `iso_08` — the
//            corpus's only empty-list case — publishes `roots_match: true` and
//            `proof_of_work_meets_target: true`, so it reports `NoTransactions`
//            while being in no position to show that the Merkle comparison was
//            skipped. tests/test_block_structure.cpp pins the skip directly.
//   B-7    is plain equality with `expected_bits`. It is NOT `validate_bits`: the
//            reference never consults the pow-limit policy on this path, so a bits
//            value the schedule would reject is a `BadDifficulty` here, and a bits
//            value equal to the expected one is accepted however it decodes.
//
// What deliberately stays OUT of this module: `connect_block`, `required_bits` and
// any retargeting (the caller supplies `expected_bits`; computing it would mean
// reading chain history through an untrusted height, which is finding F-1 and is
// not closed here), UTXO and reward validation, signature checking, fork choice,
// and any networking. The P4.2A differential replay of the 36 fixtures and the
// Python verifier registration landed in P4.2B-2/P4.2B-3 and live outside this
// module. Rust remains the oracle; this is not full consensus parity and not
// production readiness.

#ifndef ZEROCOIN_KERNEL_BLOCK_H
#define ZEROCOIN_KERNEL_BLOCK_H

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <variant>
#include <vector>

#include "zerocoin/header.h"
#include "zerocoin/pow.h"
#include "zerocoin/transaction.h"

namespace zk {

/// `MAX_BLOCK_TRANSACTIONS` (block.rs:31). B-9 rejects a list strictly longer than
/// this; a block with exactly this many transactions is valid on this rule.
inline constexpr std::size_t kMaxBlockTransactions = 2000;

/// `MAX_FUTURE_SECONDS` (block.rs:33, declared as `2 * 60 * 60`). B-13's window,
/// added to the clock ONLY through `future_timestamp_limit`, never with a bare `+`.
inline constexpr std::uint64_t kMaxFutureSeconds = 7200;

/// The block, as the reference owns it: the header and the ordered transactions,
/// the first of which must be the coinbase. There is no validation in the type —
/// `Block` is the data `validate_structure` reads, and a default-constructed one
/// (a zero header, an empty list) is a block B-8 rejects, not an error to
/// construct.
///
/// The transactions are owned by value rather than passed as a pointer and a
/// count. That is what makes the null-pointer question disappear at this boundary:
/// there is no `nullptr` with a non-zero count to hand in, so the only verdicts
/// this function can return are the reference's consensus verdicts.
/// `compare_claimed_merkle_root` keeps its own pointer-and-count contract, which
/// is where `merkle_root_from_transactions` gets to answer for an empty list.
struct Block {
  BlockHeader header{};
  std::vector<Transaction> transactions{};

  friend bool operator==(const Block& lhs, const Block& rhs) {
    return lhs.header == rhs.header && lhs.transactions == rhs.transactions;
  }
  friend bool operator!=(const Block& lhs, const Block& rhs) { return !(lhs == rhs); }
};

/// Everything the ordering compares the block against that is not in the block, in
/// the reference's own parameter order (block.rs:165-171).
///
/// No member has a default initialiser and the aggregate is not
/// default-constructible — `PowEngine` has no default constructor, so a context
/// either names the engine this node actually runs or fails to compile. That is
/// deliberate: every field here belongs to the caller's chain state or
/// configuration, and a missing one must never be filled in from the block. B-6 is
/// the clearest case, and it is a consensus rule rather than a style point —
/// `header.engine_id` is a peer's claim about which algorithm mined the block,
/// `context.engine` is this node's policy about which algorithm it accepts, and the
/// whole reason the byte is in the header is that a block must not be able to pick.
/// The same exclusion applies to `expected_bits`: it comes from the schedule at a
/// height the caller has already validated, and this module does not derive it
/// (F-1).
struct ValidationContext {
  /// The configured engine. B-6 compares against its id and B-15 hashes with it.
  PowEngine engine;
  std::uint32_t expected_chain;
  std::uint64_t expected_height;
  Hash256 expected_previous;
  /// The bits the schedule requires. B-7 is equality with this value.
  std::uint32_t expected_bits;
  std::uint64_t median_time_past;
  std::uint64_t now;
};

// ---------------------------------------------------------------------------
// The P4.1 verb, unchanged by this slice: rule B-14 as a verdict on its own.
// `validate_block_structure` calls it instead of restating it, which is the one
// reason this declaration is in this header rather than only in the corpus
// wrapper's vocabulary.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// The error alternatives. One struct per Rust `BlockError` variant, with the
// variant's own payload fields and widths (C-12): `WrongChain` carries two u32s
// and `BadHeight` two u64s, so they are two types and not one type with four
// numbers in it. Each declares which `BlockErrorKind` it IS, which is how the
// mapping below is written out per alternative instead of being derived from the
// variant's index — the index is a memory-layout detail of this header and would
// change the moment an alternative was inserted, while the numeric taxonomy in
// header.h is append-only and frozen from P4.1.
// ---------------------------------------------------------------------------

/// The absence of a rejection. `Block::validate_structure`'s `Ok(())`.
struct BlockAccepted {
  static constexpr BlockErrorKind kind = BlockErrorKind::kNone;
};

/// B-3 `BlockError::WrongChain { expected: u32, found: u32 }`.
struct WrongChainError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kWrongChain;
  std::uint32_t expected = 0;
  std::uint32_t found = 0;
};

/// B-4 `BlockError::BadHeight { expected: u64, found: u64 }`.
struct BadHeightError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kBadHeight;
  std::uint64_t expected = 0;
  std::uint64_t found = 0;
};

/// B-5 `BlockError::BadPreviousHash`. Unit variant: the fixture publishes
/// `error_payload: null` for it, so there is nothing to carry.
struct BadPreviousHashError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kBadPreviousHash;
};

/// B-6 `BlockError::WrongEngine { expected: u8, found: u8 }`. `expected` is the
/// configured engine's id; `found` is the header's byte.
struct WrongEngineError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kWrongEngine;
  std::uint8_t expected = 0;
  std::uint8_t found = 0;
};

/// B-7 `BlockError::BadDifficulty { expected: u32, found: u32 }`. The compact bits,
/// not a decoded target.
struct BadDifficultyError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kBadDifficulty;
  std::uint32_t expected = 0;
  std::uint32_t found = 0;
};

/// B-8 `BlockError::NoTransactions`.
struct NoTransactionsError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kNoTransactions;
};

/// B-9 `BlockError::TooManyTransactions(usize)`. The count is the newtype's field;
/// the corpus publishes it as `count`.
struct TooManyTransactionsError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kTooManyTransactions;
  std::size_t count = 0;
};

/// B-10 `BlockError::FirstNotCoinbase`.
struct FirstNotCoinbaseError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kFirstNotCoinbase;
};

/// B-11 `BlockError::DuplicateCoinbase`.
struct DuplicateCoinbaseError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kDuplicateCoinbase;
};

/// B-12 `BlockError::TimestampTooOld { median: u64, found: u64 }`.
struct TimestampTooOldError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kTimestampTooOld;
  std::uint64_t median = 0;
  std::uint64_t found = 0;
};

/// B-13 `BlockError::TimestampTooFarFuture { now: u64, found: u64 }`. The payload is
/// the clock and the timestamp — the limit is derivable from them by the reader, and
/// the reference does not publish it.
struct TimestampTooFarFutureError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kTimestampTooFarFuture;
  std::uint64_t now = 0;
  std::uint64_t found = 0;
};

/// B-14 `BlockError::RootMismatch`. The unit variant P4.1 ports; `kRootMismatch`
/// keeps the numeric value 3 it has had since P4.1 and is named at the end of the
/// ordering because that is where the reference reaches it.
struct RootMismatchError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kRootMismatch;
};

/// B-15 `BlockError::InsufficientProofOfWork`.
struct InsufficientProofOfWorkError {
  static constexpr BlockErrorKind kind = BlockErrorKind::kInsufficientProofOfWork;
};

/// The typed result of `validate_block_structure`: the accepted signal, or the one
/// rule the reference reached first, with that rule's payload.
///
/// The alternatives are ordered by evaluation (B-3 first, B-15 last) purely so the
/// declaration reads like `block.rs`. Nothing depends on that order and nothing
/// must ever: identity is the `kind` each alternative declares, and
/// `RootMismatchError` is the standing counter-example — it is the twelfth error
/// alternative in this list, it carries the numeric kind 3 frozen by P4.1, and it
/// is Rust discriminant 3 of 12, three numbers that agree with each other only by
/// coincidence of these files' histories. Use `block_structure_kind`.
using BlockStructureResult =
    std::variant<BlockAccepted, WrongChainError, BadHeightError, BadPreviousHashError,
                 WrongEngineError, BadDifficultyError, NoTransactionsError,
                 TooManyTransactionsError, FirstNotCoinbaseError, DuplicateCoinbaseError,
                 TimestampTooOldError, TimestampTooFarFutureError, RootMismatchError,
                 InsufficientProofOfWorkError>;

/// Whether the reference would have returned `Ok(())`.
constexpr bool block_structure_accepted(const BlockStructureResult& result) noexcept {
  return std::holds_alternative<BlockAccepted>(result);
}

/// The taxonomy kind a result carries, asked of the alternative itself. Never the
/// variant index (see `BlockStructureResult`).
///
/// `noexcept` is honest here: every alternative is trivially copyable, so the
/// variant can never be valueless and the visit can never throw.
BlockErrorKind block_structure_kind(const BlockStructureResult& result) noexcept;

/// The stable name of a result's variant, which is the reference's variant name
/// (`block_error_kind_name` owns the table; C-14).
const char* block_structure_name(const BlockStructureResult& result) noexcept;

/// `now.saturating_add(kMaxFutureSeconds)` — the limit B-13 compares the header's
/// timestamp against.
///
/// The saturation is part of the rule, not defensive arithmetic: an unchecked
/// `now + 7200` wraps for a clock near `u64::MAX` to 7199, and every real timestamp
/// then reads as far-future. `bnd_13_near_max_saturating_accept` in the P4.2A corpus
/// is published specifically to catch a port that writes the bare `+`, and
/// `bnd_13_near_max_edge_reject` and `bnd_13_near_max_last_exact_accept` are the two
/// sides of the point where the addition starts to clamp. The guard is
/// divide-free and subtraction-based (`now > MAX - addend`) so the comparison itself
/// cannot overflow, the same shape `DifficultyParams::target_window_seconds` uses.
constexpr std::uint64_t future_timestamp_limit(std::uint64_t now) noexcept {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  if (now > kMax - kMaxFutureSeconds) {
    return kMax;
  }
  return now + kMaxFutureSeconds;
}

/// Maps a `BlockErrorKind` that a kernel verb has already produced into this
/// module's alternative, used by `validate_block_structure` for the two verbs that
/// return the taxonomy directly: `validate_header_identity` (B-3, B-4) and
/// `compare_claimed_merkle_root` (B-14).
///
/// Total over the taxonomy in the direction that needs no data this call site does
/// not have: `kNone` is `BlockAccepted`, and the six unit variants are their own
/// alternatives. A payload-bearing kind arriving here is an API contract violation
/// rather than a consensus result — this function has no expected/found values to
/// put in it, and inventing zeroes would publish a payload the reference never
/// computed, while returning `BlockAccepted` would fail open. It throws instead,
/// which is the same stance this kernel takes for allocation failure inside the
/// Merkle composition: a failure that is not a rule does not become a verdict.
/// Not `noexcept`, for that reason.
BlockStructureResult block_structure_verdict_for(BlockErrorKind kind);

/// Rules B-3 through B-15, in `Block::validate_structure`'s order, returning the
/// first failure the reference would have returned.
///
/// Each rule is one predicate on the block and the context, and the ones the kernel
/// already implements are CALLS rather than restatements: B-3 and B-4 are
/// `validate_header_identity` (whose chain-before-height precedence C-29 pins), B-6
/// and B-15 are `header_engine_matches` and `header_meets_own_target` against the
/// context's engine, and B-14 is P4.1's `compare_claimed_merkle_root`, unchanged.
/// B-5, B-7 and B-8 through B-13 had no ported verb to reuse and are written here
/// from the reference's own comparisons.
///
/// Precondition: none about pointers, because there is nothing to get wrong — the
/// block owns its transactions, so `nullptr` with a non-zero count cannot be
/// handed to this function, and B-8 returns before any buffer is read. The only
/// precondition left is the caller's: `context` must be this node's own state, not
/// anything derived from the block being validated. A violation of the
/// kind-mapping contract inside the two reused verbs propagates as
/// `std::logic_error`; it never appears in the return type.
///
/// Not `noexcept`, for the same reason `compare_claimed_merkle_root` is not: the
/// B-14 call composes `Transaction::serialize()`, which allocates. An exhausted
/// allocator propagates instead of returning a verdict computed from a partial
/// tree.
BlockStructureResult validate_block_structure(const Block& block,
                                              const ValidationContext& context);

/// `Block` is the reference's two fields and has no validation of its own.
static_assert(std::is_default_constructible_v<Block>,
              "a default Block is an empty block, which B-8 rejects, not a bug");
static_assert(std::is_empty_v<BadPreviousHashError> && std::is_empty_v<NoTransactionsError> &&
                  std::is_empty_v<FirstNotCoinbaseError> &&
                  std::is_empty_v<DuplicateCoinbaseError> && std::is_empty_v<RootMismatchError> &&
                  std::is_empty_v<InsufficientProofOfWorkError> && std::is_empty_v<BlockAccepted>,
              "the unit variants carry nothing, as the corpus's null payloads say");

/// The taxonomy values P4.1 published are unchanged, and P4.2B-1 appends the rest
/// above them, in the order the ordering reaches them (header.h: append, never
/// insert). Freezing the numbers here means a renumbering cannot pass unnoticed.
static_assert(static_cast<std::uint8_t>(BlockErrorKind::kNone) == 0, "kNone stays 0");
static_assert(static_cast<std::uint8_t>(BlockErrorKind::kWrongChain) == 1,
              "kWrongChain stays 1");
static_assert(static_cast<std::uint8_t>(BlockErrorKind::kBadHeight) == 2, "kBadHeight stays 2");
static_assert(static_cast<std::uint8_t>(BlockErrorKind::kRootMismatch) == 3,
              "kRootMismatch stays 3, from P4.1");
static_assert(static_cast<std::uint8_t>(BlockErrorKind::kBadPreviousHash) == 4 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kWrongEngine) == 5 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kBadDifficulty) == 6 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kNoTransactions) == 7 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kTooManyTransactions) == 8 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kFirstNotCoinbase) == 9 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kDuplicateCoinbase) == 10 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kTimestampTooOld) == 11 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kTimestampTooFarFuture) == 12 &&
                  static_cast<std::uint8_t>(BlockErrorKind::kInsufficientProofOfWork) == 13,
              "the ten appended kinds are 4 through 13");

/// Each alternative declares the kind the taxonomy gives it. This is the mapping
/// `block_structure_kind` reads, and it is the reason the variant index is never
/// consulted: `RootMismatchError` sits at index 12 and carries kind 3.
static_assert(BlockAccepted::kind == BlockErrorKind::kNone &&
                  WrongChainError::kind == BlockErrorKind::kWrongChain &&
                  BadHeightError::kind == BlockErrorKind::kBadHeight &&
                  BadPreviousHashError::kind == BlockErrorKind::kBadPreviousHash &&
                  WrongEngineError::kind == BlockErrorKind::kWrongEngine &&
                  BadDifficultyError::kind == BlockErrorKind::kBadDifficulty &&
                  NoTransactionsError::kind == BlockErrorKind::kNoTransactions &&
                  TooManyTransactionsError::kind == BlockErrorKind::kTooManyTransactions &&
                  FirstNotCoinbaseError::kind == BlockErrorKind::kFirstNotCoinbase &&
                  DuplicateCoinbaseError::kind == BlockErrorKind::kDuplicateCoinbase &&
                  TimestampTooOldError::kind == BlockErrorKind::kTimestampTooOld &&
                  TimestampTooFarFutureError::kind == BlockErrorKind::kTimestampTooFarFuture &&
                  RootMismatchError::kind == BlockErrorKind::kRootMismatch &&
                  InsufficientProofOfWorkError::kind == BlockErrorKind::kInsufficientProofOfWork,
              "every alternative names its own kind");
static_assert(std::variant_size_v<BlockStructureResult> == 14,
              "the accepted signal plus the reference's thirteen BlockError variants");

/// The two constants are consensus data, and the corpus's 2000/2001 boundary cases
/// and `bnd_13_*` saturation cases are published against these values.
static_assert(kMaxBlockTransactions == 2000, "B-9's limit is MAX_BLOCK_TRANSACTIONS");
static_assert(kMaxFutureSeconds == 2 * 60 * 60, "B-13's window is 7200 seconds");

/// The saturating limit, pinned at the four points the corpus publishes plus the
/// origin, including the witness against a bare `+`: wrapping reaches 7199 where the
/// reference reaches `u64::MAX`.
static_assert(future_timestamp_limit(0) == kMaxFutureSeconds, "the origin adds the window");
static_assert(future_timestamp_limit(std::numeric_limits<std::uint64_t>::max() -
                                     kMaxFutureSeconds - 1) ==
                  std::numeric_limits<std::uint64_t>::max() - 1,
              "MAX - 7201 is the last clock whose addition lands one below MAX");
static_assert(future_timestamp_limit(std::numeric_limits<std::uint64_t>::max() -
                                     kMaxFutureSeconds) == std::numeric_limits<std::uint64_t>::max(),
              "MAX - 7200 is the last exact addition, and it reaches MAX");
static_assert(future_timestamp_limit(std::numeric_limits<std::uint64_t>::max()) ==
                  std::numeric_limits<std::uint64_t>::max(),
              "MAX saturates instead of wrapping");
static_assert(future_timestamp_limit(std::numeric_limits<std::uint64_t>::max()) !=
                  std::numeric_limits<std::uint64_t>::max() + kMaxFutureSeconds,
              "the saturating limit is not what an unchecked `now + 7200` computes");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_BLOCK_H
