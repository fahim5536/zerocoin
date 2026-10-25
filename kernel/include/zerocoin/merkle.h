// Merkle roots. Mirrors zerocoin/src/consensus/block.rs (`merkle_root` and the
// `Block::compute_merkle_root` that feeds it) and the empty-tree tag
// `EMPTY_MERKLE_TAG` beside it.
//
// Two entry points, one tree. `merkle_root` is the leaf-level rule;
// `merkle_root_from_transactions` is the reference's composition, which maps a
// transaction list through each transaction's own id and hands the result to
// that same function. The second calls the first and adds no hashing, no
// ordering and no rule of its own.
//
// The boundary is unchanged by that addition. This module still does NOT encode
// or hash a header, does NOT dispatch a proof-of-work engine, does NOT validate
// a block and does NOT compare a header's claimed root against the transactions
// present (B-1 / B-14): the kernel has no `Block` type, and producing a root
// from a transaction list is not a block-validation path. Nor does it
// re-implement the id rule — it calls `Transaction::txid()`, which owns C-2.
// Both functions are pure: given input, they return a digest, and nothing else.
//
// The contract is CPP_PORT_REQUIREMENTS.md C-5, and each part of it is an
// observable difference from some other Merkle rule, so none of it is a choice:
//
//   empty      `count == 0` returns the double-SHA256 of the 17-byte tag below,
//              not the all-zero digest and not a root of width 0.
//   single     `count == 1` returns that leaf unchanged, with no hash applied to
//              it. A duplicated single leaf is therefore NOT the same root.
//   internal   a parent is `sha256d(left || right)` over exactly 64 raw internal
//              bytes: no node tag, no prefix, no separator, no length, and no
//              lexicographic ordering of the two children.
//   odd        the final node of an odd-width level is duplicated and paired
//              with itself at every level where the width is odd — it is not
//              promoted unchanged to the next level, which is the rule that
//              distinguishes this tree from Bitcoin's.
//   order      leaves are consumed in the order given. [a,b,c] and [c,b,a] have
//              different roots.
//
// Byte order: the pair is the stored internal bytes, in order, exactly as
// `pair[..32].copy_from_slice(&left.0)` does in the reference. Any function
// here that needed the display form would have to ask for it explicitly; this
// module never reverses anything.

#ifndef ZEROCOIN_KERNEL_MERKLE_H
#define ZEROCOIN_KERNEL_MERKLE_H

#include <cstddef>
#include <cstdint>

#include "zerocoin/hash.h"
#include "zerocoin/transaction.h"

namespace zk {

/// Domain tag hashed to produce the root of an empty leaf list, so the empty
/// tree has a fixed, non-zero identity: `ZRO/merkle:empty` plus one NUL byte.
///
/// `block.rs` declares it `pub(crate)`, so the kernel — like the reference's own
/// P3.2B exporter — has to restate it. `kEmptyMerkleTagSize` below is the frozen
/// length; the trailing 0 is part of the tag, not a string terminator, and the
/// assertions at the bottom of this header are what pin that.
inline constexpr std::uint8_t kEmptyMerkleTag[] = {'Z', 'R', 'O', '/', 'm', 'e', 'r',
                                                   'k', 'l', 'e', ':', 'e', 'm', 'p',
                                                   't', 'y', 0};
inline constexpr std::size_t kEmptyMerkleTagSize = sizeof(kEmptyMerkleTag);

/// The exact input width of one internal node: the two child digests, raw.
/// Derived from the digest width, so it moves with it instead of being copied
/// from a document.
inline constexpr std::size_t kMerklePairSize = Hash256::kWidth * 2;

/// The Merkle root of `count` leaf digests.
///
/// Null-pointer contract: `leaves` may be null if and only if `count == 0`,
/// because the empty case returns before the buffer is ever read — that is the
/// order the reference uses (`if leaves.is_empty() { ... }` before
/// `leaves.to_vec()`), and keeping it means an empty tree cannot dereference
/// anything. For any other `count`, `leaves` must point to `count` valid
/// `Hash256` objects. The function reads that range and never writes it.
///
/// There is no leaf-count limit here, deliberately: `MAX_BLOCK_TRANSACTIONS` is
/// a block rule the reference enforces outside `merkle_root`, and a limit baked
/// into this function would be a second, different consensus rule. Callers pass
/// what they have.
///
/// Infallible, like the reference (`merkle_root` returns `Hash256`, not
/// `Result`), so `noexcept` is the honest signature. The work buffers allocate,
/// and an exhausted allocator therefore terminates the process instead of
/// returning a root — the same outcome Rust reaches by aborting on allocation
/// failure, and strictly better than silently returning a wrong digest.
Hash256 merkle_root(const Hash256* leaves, std::size_t count) noexcept;

/// The Merkle root of `count` transactions, each committed to by its own id.
///
/// This is `Block::compute_merkle_root`, which is two lines in the reference:
/// map the list through `Transaction::txid()` in order, pass those digests to
/// `merkle_root`. Everything the root depends on — the encoding the id commits
/// to (C-1, C-2) and the pairing rule (C-5) — belongs to those two callees and
/// is not restated here. Nothing reorders, re-encodes or reinterprets a digest,
/// and no third hash is applied.
///
/// Null-pointer contract, same shape as `merkle_root` above: `txs` may be null
/// if and only if `count == 0`, because a zero count produces an empty leaf list
/// and the leaf rule returns the tagged empty-tree digest before reading any
/// buffer. That is the reference's own public behavior for an empty slice. For
/// any other `count`, `txs` must point to `count` valid `Transaction` objects.
/// The function reads that range and never writes it.
///
/// There is no transaction-count limit, deliberately and for the same reason as
/// the leaf rule: `MAX_BLOCK_TRANSACTIONS` is block rule B-9, enforced by
/// `validate_structure`, and a limit inside this primitive would be a second,
/// different consensus rule.
///
/// Not `noexcept`, unlike `merkle_root`: `Transaction::serialize()` builds the
/// byte string the id hashes and is itself not `noexcept`, so the promise cannot
/// be made here without the callee making it. An exhausted allocator propagates
/// `std::bad_alloc` instead of returning a partially computed root.
Hash256 merkle_root_from_transactions(const Transaction* txs, std::size_t count);

// The tag, its length and the two widths are frozen at compile time.
static_assert(kEmptyMerkleTagSize == 17, "the empty tag is ZRO/merkle:empty plus a NUL");
static_assert(sizeof(kEmptyMerkleTag) == 17, "the tag array has no hidden length");
static_assert(kEmptyMerkleTag[16] == 0, "the seventeenth tag byte is the NUL, not a terminator");
static_assert(Hash256::kWidth == 32, "a Merkle leaf is one 256-bit digest");
static_assert(kMerklePairSize == 64, "an internal node hashes exactly 64 bytes");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_MERKLE_H
