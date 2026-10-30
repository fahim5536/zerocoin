// Block-header preimage and header identity, mirroring
// zerocoin/src/consensus/block.rs (`BlockHeader::preimage` and
// `Block::validate_header_identity`).
//
// The scope is exactly the two functions the P3.1A corpus pins, and nothing
// else. This module does NOT decode a serialized header, does NOT hash the
// preimage and does NOT dispatch a proof-of-work engine: the block's identity
// is `engine.hash(preimage, nonce)` (CPP_PORT_REQUIREMENTS.md C-4), the kernel
// has no `Block` type or chain state, so `connect_block` and its ordering
// obligation stay in P4. Rust remains the oracle and F-1 is not closed by this
// file. The one block rule ported so far — the claimed-Merkle-root comparison
// of B-14 — is not a header rule and does not live here either; it is in
// block.h, and only the `BlockError` taxonomy below is shared between them.
//
// Two behaviours are compatibility requirements rather than choices:
//
//   C-3   the preimage is exactly 107 bytes: a 14-byte tag, then version,
//         chain, height, the two digests as stored, timestamp, bits and one
//         engine byte. The nonce is NOT in it — the engine appends it, which is
//         why two headers differing only in the nonce share one preimage.
//   C-29  the validator tests the chain id first and the height second, so a
//         header wrong about both is `WrongChain`, never `BadHeight`. The
//         reference runs this before `required_bits`, which is why a height may
//         only be used as an index into stored history once this returns ok.
//
// Endianness and widths follow C-11 and C-12: every integer is written byte by
// byte from an unsigned value, so no host byte order, no struct packing, no
// `memcpy` of a native integer and no sign extension is involved anywhere. The
// fixed 107-byte result is expressed in the return type and frozen below.

#ifndef ZEROCOIN_KERNEL_HEADER_H
#define ZEROCOIN_KERNEL_HEADER_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "zerocoin/hash.h"

namespace zk {

/// Domain tag mixed into every header preimage: `ZRO/header/v1\0`.
/// `block.rs` declares it `pub(crate)`, so the reference's own P3.1A exporter
/// restates it the same way; `kHeaderTagBytes` below is the frozen length.
inline constexpr std::uint8_t kHeaderTag[] = {'Z', 'R', 'O', '/', 'h', 'e', 'a', 'd',
                                              'e', 'r', '/', 'v', '1', 0};
inline constexpr std::size_t kHeaderTagSize = sizeof(kHeaderTag);

/// tag(14) + version(4) + chain(4) + height(8) + previous_hash(32) +
/// merkle_root(32) + timestamp(8) + difficulty_bits(4) + engine_id(1).
/// Derived from the field list, so it moves with the layout instead of being
/// copied from a document.
inline constexpr std::size_t kHeaderPreimageSize =
    kHeaderTagSize + sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint64_t) +
    Hash256::kWidth + Hash256::kWidth + sizeof(std::uint64_t) + sizeof(std::uint32_t) +
    sizeof(std::uint8_t);

/// A block header. The field set, field order and widths are the reference's;
/// `nonce` is carried here because the header owns it, but it is not part of
/// the preimage and nothing in this module reads it.
struct BlockHeader {
  std::uint32_t version = 0;
  std::uint32_t chain = 0;
  std::uint64_t height = 0;
  Hash256 previous_hash{};
  Hash256 merkle_root{};
  std::uint64_t timestamp = 0;
  std::uint32_t difficulty_bits = 0;
  std::uint8_t engine_id = 0;
  std::uint64_t nonce = 0;

  friend constexpr bool operator==(const BlockHeader& lhs, const BlockHeader& rhs) noexcept {
    return lhs.version == rhs.version && lhs.chain == rhs.chain && lhs.height == rhs.height &&
           lhs.previous_hash == rhs.previous_hash && lhs.merkle_root == rhs.merkle_root &&
           lhs.timestamp == rhs.timestamp && lhs.difficulty_bits == rhs.difficulty_bits &&
           lhs.engine_id == rhs.engine_id && lhs.nonce == rhs.nonce;
  }
  friend constexpr bool operator!=(const BlockHeader& lhs, const BlockHeader& rhs) noexcept {
    return !(lhs == rhs);
  }
};

/// The canonical preimage the PoW engine hashes, excluding the nonce.
///
/// The two digests are copied in stored (internal) byte order with no reversal
/// and no length prefix, exactly as `extend_from_slice(&hash.0)` does in the
/// reference. Length is structural, not data-dependent, so it is part of the
/// return type.
std::array<std::uint8_t, kHeaderPreimageSize> header_preimage(const BlockHeader& header) noexcept;

/// The `BlockError` variants the kernel can produce, named exactly as the
/// reference names them (C-14) because the fixture asserts the names.
///
/// The numbering is the kernel's own declaration order, NOT the Rust
/// discriminants (`BlockError::WrongChain` is discriminant 0 there): `kNone`
/// must occupy 0 so a default-constructed result means "accepted", which is the
/// convention `DifficultyError` already sets. A variant is therefore appended,
/// never inserted, so no existing value moves when a rule is ported. The
/// remaining ten `BlockError` variants are not declared here — nothing produces
/// them yet, and declaring them would imply a ported rule that does not exist.
///
/// `kRootMismatch` belongs to this enum because the Rust type is one enum: it is
/// the variant `Block::validate_structure` returns for the B-14 comparison, which
/// block.h ports. It carries no payload (C-12), unlike the two identity
/// variants, which is why the payload question is answered per variant by
/// `block_error_kind_has_payload` rather than per struct.
enum class BlockErrorKind : std::uint8_t {
  kNone = 0,
  kWrongChain = 1,
  kBadHeight = 2,
  kRootMismatch = 3,
};

/// Whether the reference's `BlockError` variant carries a numeric payload
/// (C-12). Answered per variant because the variants differ: `WrongChain` and
/// `BadHeight` do, `RootMismatch` is a unit variant and does not, and `None` is
/// not a rejection at all. Declared before `BlockIdentityError` so the member
/// below can call it — a name declared after the class is not yet visible in an
/// inline member body.
constexpr bool block_error_kind_has_payload(BlockErrorKind kind) noexcept {
  return kind == BlockErrorKind::kWrongChain || kind == BlockErrorKind::kBadHeight;
}

/// The rejection, with the reference's payload widths kept distinct per variant
/// (C-12): `WrongChain` carries two `u32`s, `BadHeight` two `u64`s. Exactly one
/// pair is meaningful for a given `kind`; the other stays zero-initialised, so
/// a caller can never read a chain id out of a height field.
struct BlockIdentityError {
  BlockErrorKind kind = BlockErrorKind::kNone;
  /// WrongChain { expected, found }.
  std::uint32_t expected_chain = 0;
  std::uint32_t found_chain = 0;
  /// BadHeight { expected, found }.
  std::uint64_t expected_height = 0;
  std::uint64_t found_height = 0;

  constexpr bool ok() const noexcept { return kind == BlockErrorKind::kNone; }

  /// Whether the reference's variant carries a numeric payload. `Ok` and
  /// `RootMismatch` carry none, and the fixture publishes `null` for them rather
  /// than a guessed shape.
  constexpr bool has_payload() const noexcept { return block_error_kind_has_payload(kind); }
};

/// The stable name the conformance fixture asserts against.
const char* block_error_kind_name(BlockErrorKind kind) noexcept;

/// The identity checks that do not depend on chain history: the header must
/// name this node's chain and the height this chain expects next.
///
/// In the reference this is a method on `Block`, but it reads only
/// `self.header.chain` and `self.header.height`, so a header parameter is
/// behaviour-identical and the kernel needs no `Block` type to port it.
/// Precedence is observable — it decides which error a caller sees — so the
/// chain test runs first (C-13, C-29) and the heights are compared as unsigned
/// values of their own width.
BlockIdentityError validate_header_identity(const BlockHeader& header,
                                            std::uint32_t expected_chain,
                                            std::uint64_t expected_height) noexcept;

// The layout is frozen at compile time: 14 + 4 + 4 + 8 + 32 + 32 + 8 + 4 + 1.
static_assert(kHeaderTagSize == 14, "the tag is ZRO/header/v1 plus a NUL");
static_assert(sizeof(kHeaderTag) == 14, "the tag array has no hidden length");
static_assert(kHeaderPreimageSize == 107, "the header preimage is 107 bytes");
static_assert(Hash256::kWidth == 32, "a header carries two 32-byte digests");
static_assert(sizeof(std::uint32_t) == 4 && sizeof(std::uint64_t) == 8 &&
                  sizeof(std::uint8_t) == 1,
              "the field widths the preimage layout commits to");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_HEADER_H
