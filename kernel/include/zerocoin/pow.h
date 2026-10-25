// Proof-of-work engines and the header identity they produce, mirroring
// zerocoin/src/consensus/pow.rs (`TrivialEngine`, `ScratchPadEngine`,
// `verify_pow`) and the two `BlockHeader` methods that consume them in
// zerocoin/src/consensus/block.rs (`pow_hash`, `meets_own_target`).
//
// This closes C-4 and nothing else. The module does NOT own a `Block` type, does
// NOT run `validate_structure`, does NOT compare a claimed Merkle root with the
// transactions present (B-14), does NOT reject an insufficient proof inside a
// block-validation ordering (B-15), does NOT touch chain context, `connect_block`
// or fork choice, and does NOT expose mining as a production API — the reference
// says so itself: `mine` is "used by a miner; a validator never calls this", so
// the nonce search lives in the conformance runner instead of here. Rust stays
// the oracle; F-1, C-29 and full consensus parity are not closed by this file.
//
// Five behaviours are compatibility requirements rather than choices:
//
//   C-4   the block's identity is `engine.hash(header_preimage, nonce)`. The
//         nonce is never inserted into the 107-byte preimage: both engines
//         append the same 8 little-endian bytes to a copy of it, which is why
//         two headers that differ only in the nonce share one preimage.
//   C-11  every integer the engine touches — the appended nonce, the scratchpad
//         index word — is read or written byte by byte from an unsigned value,
//         so no host byte order is ever observable.
//   F-11  the hash is compared as a big-endian integer against an inclusive
//         bound. This module reuses `hash_meets_target` rather than restating it,
//         so the engine and the difficulty policy cannot drift apart.
//
// The engine id is asserted, never selected, by the trust boundary. In the
// reference `EngineSpec::build()` instantiates the network's OWN declared engine
// and `Block::validate_structure` merely compares the header's byte against
// `engine.id()`, producing `WrongEngine { expected, found }`. There is no
// id -> engine function on that path at all, and adding one that a peer's byte
// could reach would let a remote value choose the local hash function.
// `engine_for_id` below is therefore the kernel's inverse of `PowEngine::id()`,
// for the network's own declared configuration only, and it has no default: an
// id other than 0 or 1 returns std::nullopt rather than a plausible engine.
//
// ScratchPad memory: the reference folds the final state and then every cell
// into one streaming SHA-256. The kernel has no incremental hasher, so the pad
// lives in a single buffer of `(1 + cells) * 32` bytes whose first 32 bytes are
// reserved for the final state and whose cell `i` starts at `32 + 32 * i`; the
// fold is then one `sha256(buffer)` call over exactly the byte sequence Rust
// feeds to the streamer, in the same order, with no second allocation and no
// copy of the pad. The two layers are separated in `src/pow_internal.h`, which
// is deliberately outside the exported include directory.

#ifndef ZEROCOIN_KERNEL_POW_H
#define ZEROCOIN_KERNEL_POW_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "zerocoin/difficulty.h"
#include "zerocoin/hash.h"
#include "zerocoin/header.h"
#include "zerocoin/uint256.h"

namespace zk {

/// The engine ids the reference commits into the block header
/// (`ENGINE_ID_TRIVIAL`, `ENGINE_ID_SCRATCHPAD`), so a block cannot silently
/// switch algorithms without a consensus-visible change.
inline constexpr std::uint8_t kEngineIdTrivial = 0;
inline constexpr std::uint8_t kEngineIdScratchpad = 1;

/// The reference's `&'static str` names, reproduced verbatim: they reach logs and
/// RPC, and the corpus publishes them as expected values, so they are data.
inline constexpr std::string_view kTrivialEngineName = "sha256d-trivial";
inline constexpr std::string_view kScratchpadEngineName = "scratchpad-memory-hard";

/// Bytes per scratchpad cell (`const CELL: usize = 32`). Cell width is part of
/// the hash, not a tuning knob: a different width addresses a different pad.
inline constexpr std::size_t kScratchpadCellBytes = 32;

/// The two parameters that decide a scratchpad hash. The pad length is an input
/// to the digest, so two nodes with different values here compute different
/// hashes and fork the chain — the reference states this about
/// `MOBILE_SCRATCHPAD_BYTES` and it holds for every profile.
struct ScratchPadParams {
  std::size_t memory_bytes = 0;
  std::size_t rounds = 0;

  friend constexpr bool operator==(const ScratchPadParams& lhs,
                                   const ScratchPadParams& rhs) noexcept {
    return lhs.memory_bytes == rhs.memory_bytes && lhs.rounds == rhs.rounds;
  }
  friend constexpr bool operator!=(const ScratchPadParams& lhs,
                                   const ScratchPadParams& rhs) noexcept {
    return !(lhs == rhs);
  }
};

/// `ScratchPadEngine::balanced()` — the devnet profile: 64 KiB, 1,024 rounds.
inline constexpr ScratchPadParams kScratchpadDevnet{64 * 1024, 1024};

/// `ScratchPadEngine::mainnet()` — 2 MiB, 4,096 rounds.
inline constexpr ScratchPadParams kScratchpadMainnet{2 * 1024 * 1024, 4096};

/// `(memory_bytes / CELL).max(1)`, exactly as `cells()` computes it. The floor
/// matters: a `memory_bytes` below one cell still addresses one cell, so the
/// index arithmetic never sees a zero-width pad.
constexpr std::size_t scratchpad_cell_count(std::size_t memory_bytes) noexcept {
  const std::size_t cells = memory_bytes / kScratchpadCellBytes;
  return cells == 0 ? std::size_t{1} : cells;
}

/// A proof-of-work engine: the reference's `PowEngine` trait object, as a value
/// type. The only ways to hold one are the two factories below — the class is
/// deliberately NOT default-constructible, so an engine always carries an id the
/// code chose, never an uninitialised one that happens to read as trivial.
/// `TrivialEngine` itself still has no state: its `Kind` and empty parameters are
/// set explicitly by `trivial()`.
class PowEngine {
 public:
  /// `TrivialEngine`: plain SHA-256d over `preimage || nonce_le64`. The regtest
  /// engine, and the one every `pow.trivial.*` corpus case pins.
  static PowEngine trivial() noexcept { return PowEngine(Kind::kTrivial, ScratchPadParams{}); }

  /// `ScratchPadEngine::new(memory_bytes, rounds)`. No clamping, no rounding and
  /// no hardware-profile cap is applied here: `capped_to` is a mining-ergonomics
  /// helper that the reference explicitly says "never redefines the network's
  /// consensus engine", so the caller passes the network's own parameters.
  static PowEngine scratchpad(const ScratchPadParams& params) noexcept {
    return PowEngine(Kind::kScratchpad, params);
  }

  /// The byte the header commits to. Inline and `constexpr` because it is a
  /// cast of the kind, and `header_engine_matches` below has to be usable where
  /// the engine is a constant expression.
  constexpr std::uint8_t id() const noexcept { return static_cast<std::uint8_t>(kind_); }

  /// The reference's engine name, for logs and for the corpus to assert against.
  constexpr std::string_view name() const noexcept {
    return kind_ == Kind::kTrivial ? kTrivialEngineName : kScratchpadEngineName;
  }

  /// The declared parameters. `{0, 0}` for the trivial engine, whose hash reads
  /// neither field — exposed so a caller can echo what it was configured with,
  /// not so it can influence the digest.
  constexpr ScratchPadParams scratchpad_params() const noexcept { return params_; }

  /// Hashes `preimage` with a candidate nonce.
  ///
  /// Null-pointer contract: `preimage` may be null if and only if
  /// `preimage_size == 0`, which is the reference's own empty `&[u8]`. The bytes
  /// are read and never written, and the nonce is appended to a copy — the
  /// caller's buffer is never extended in place.
  ///
  /// Not `noexcept`: the scratchpad allocation is the whole point of the
  /// construction. An exhausted allocator propagates instead of returning a
  /// partially computed digest, the same stance `merkle_root_from_transactions`
  /// takes for the same reason.
  Hash256 hash(const std::uint8_t* preimage, std::size_t preimage_size,
               std::uint64_t nonce) const;

 private:
  /// Which engine, chosen by the factory and not by anything downstream. The
  /// discriminants are the two ids, so `id()` is a straight cast and there is
  /// one table of identities rather than two that can disagree.
  enum class Kind : std::uint8_t {
    kTrivial = kEngineIdTrivial,
    kScratchpad = kEngineIdScratchpad,
  };

  constexpr PowEngine(Kind kind, const ScratchPadParams& params) noexcept
      : kind_(kind), params_(params) {}

  Kind kind_ = Kind::kTrivial;
  ScratchPadParams params_{};
};

/// The inverse of `PowEngine::id()`, for the network's OWN declared engine id.
///
/// Returns the engine for ids 0 and 1 and std::nullopt for every other byte: no
/// default, no nearest match, no fallback to the cheaper algorithm. `scratchpad_params`
/// is consulted only for id 1 — the trivial engine ignores it — so a caller that
/// has no scratchpad configuration may pass any value to resolve id 0.
///
/// A caller holding a header is on the other side of the trust boundary and must
/// NOT use this function to honour `header.engine_id`. It must build its own
/// network engine and compare: see `header_engine_matches` below.
std::optional<PowEngine> engine_for_id(std::uint8_t engine_id,
                                       const ScratchPadParams& scratchpad_params) noexcept;

/// The comparison `Block::validate_structure` actually performs with the engine
/// byte (block.rs, `h.engine_id != engine.id() -> WrongEngine { expected, found }`).
/// Provided because the correct use of a peer's engine id is a comparison and this
/// module is the only place the two ids are declared; it runs no hash and produces
/// no error variant, so it stays outside the unported block-validation ordering.
constexpr bool header_engine_matches(const BlockHeader& header, const PowEngine& engine) noexcept {
  return header.engine_id == engine.id();
}

/// `BlockHeader::pow_hash` — the block's identity, `engine.hash(preimage, nonce)`
/// (C-4). The preimage comes from `header_preimage`, so the layout, the widths
/// and the nonce exclusion are owned by header.h and are not restated here.
Hash256 header_pow_hash(const BlockHeader& header, const PowEngine& engine);

/// `BlockHeader::meets_own_target`: the digest against the target THIS HEADER'S
/// OWN `difficulty_bits` denotes — not the target the chain would have required,
/// which is a separate rule (`validate_bits`, B-6) and is deliberately not
/// reachable from here.
bool header_meets_own_target(const BlockHeader& header, const PowEngine& engine);

/// The reference's `PowError` variants this module can produce, named as the
/// reference names them (C-14). `kNone` occupies 0 so a default-constructed
/// result means "accepted", the convention `DifficultyError` sets.
///
/// `NonceExhausted` and `Aborted` are NOT declared: nothing here searches nonces
/// or can be interrupted, and declaring a variant no path produces would imply a
/// ported rule that does not exist.
enum class PowErrorKind : std::uint8_t {
  kNone = 0,
  kInsufficientWork = 1,
};

/// `verify_pow`'s result. The digest is populated on BOTH paths, because the
/// reference's error carries it (`InsufficientWork { hash }`) so a caller can
/// report the hash that fell short; a rejected proof therefore never looks like
/// a missing value.
struct PowVerifyResult {
  PowErrorKind kind = PowErrorKind::kNone;
  Hash256 hash{};

  constexpr bool ok() const noexcept { return kind == PowErrorKind::kNone; }
};

/// The stable name the conformance fixture asserts against.
const char* pow_error_kind_name(PowErrorKind kind) noexcept;

/// The whole of a node's proof-of-work validation: hash the preimage with the
/// candidate nonce and require the digest, read big-endian, to be at or below
/// the target (F-11). The comparison is `hash_meets_target` itself, so the
/// engine cannot disagree with the difficulty policy about the bound.
PowVerifyResult verify_pow(const PowEngine& engine, const std::uint8_t* preimage,
                           std::size_t preimage_size, std::uint64_t nonce,
                           const Uint256& target);

// The identities and the cell arithmetic the reference commits to.
static_assert(kEngineIdTrivial == 0 && kEngineIdScratchpad == 1,
              "the two ids the block header commits to");
static_assert(kScratchpadCellBytes == Hash256::kWidth,
              "one scratchpad cell is one SHA-256 digest");
static_assert(scratchpad_cell_count(0) == 1 && scratchpad_cell_count(31) == 1,
              "a sub-cell budget still addresses one cell");
static_assert(scratchpad_cell_count(kScratchpadDevnet.memory_bytes) == 2048,
              "the devnet pad is 2,048 cells");
static_assert(scratchpad_cell_count(kScratchpadMainnet.memory_bytes) == 65536,
              "the mainnet pad is 65,536 cells");
static_assert(kHeaderPreimageSize == 107, "the engine hashes the frozen 107-byte preimage");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_POW_H
