// Leaf-level Merkle root. Mirrors zerocoin/src/consensus/block.rs
// (`merkle_root`) and the empty-tree tag `EMPTY_MERKLE_TAG` beside it.
//
// The scope is exactly that one function. This module does NOT compute
// transaction ids, does NOT aggregate a `Block`'s transactions into leaves
// (`Block::compute_merkle_root` stays in Rust until a block/transaction
// integration milestone), does NOT encode or hash a header, does NOT dispatch a
// proof-of-work engine, does NOT validate a block and does NOT compare a
// header's claimed root against the transactions present (B-1 / B-14). It is
// pure: given leaves, it returns a digest, and nothing else.
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

// The tag, its length and the two widths are frozen at compile time.
static_assert(kEmptyMerkleTagSize == 17, "the empty tag is ZRO/merkle:empty plus a NUL");
static_assert(sizeof(kEmptyMerkleTag) == 17, "the tag array has no hidden length");
static_assert(kEmptyMerkleTag[16] == 0, "the seventeenth tag byte is the NUL, not a terminator");
static_assert(Hash256::kWidth == 32, "a Merkle leaf is one 256-bit digest");
static_assert(kMerklePairSize == 64, "an internal node hashes exactly 64 bytes");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_MERKLE_H
