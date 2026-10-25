#include "zerocoin/pow.h"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "pow_internal.h"

namespace zk {
namespace {

// C-11: every byte is shifted out of, or into, an explicitly unsigned value of
// the same width, so nothing here depends on the host byte order and no native
// integer is ever copied. `u64::from_le_bytes(state[0..8])` in the reference is
// the read; `nonce.to_le_bytes()` is the write.
void write_le64(std::uint64_t value, std::uint8_t* out) noexcept {
  for (unsigned i = 0; i < sizeof(std::uint64_t); ++i) {
    out[i] = static_cast<std::uint8_t>(value >> (8U * i));
  }
}

std::uint64_t read_le64(const std::uint8_t* bytes) noexcept {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < sizeof(std::uint64_t); ++i) {
    value |= static_cast<std::uint64_t>(bytes[i]) << (8U * i);
  }
  return value;
}

/// `TrivialEngine::hash`: `sha256d(preimage || nonce_le64)`. The reference
/// builds one buffer and hashes it twice, so this does too; `sha256d` is the
/// kernel's existing double-hash and is not re-implemented here.
Hash256 trivial_hash(const std::uint8_t* preimage, std::size_t preimage_size,
                     std::uint64_t nonce) {
  constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
  if (preimage_size > kMax - sizeof(std::uint64_t)) {
    throw std::length_error("PowEngine::hash: preimage too large to append a nonce");
  }
  std::vector<std::uint8_t> data(preimage_size + sizeof(std::uint64_t));
  if (preimage_size != 0) {
    std::copy_n(preimage, preimage_size, data.begin());
  }
  write_le64(nonce, data.data() + preimage_size);
  return sha256d(data.data(), data.size());
}

}  // namespace

namespace detail {

void write_scratchpad_image(std::uint8_t* out, std::size_t out_size,
                            const ScratchPadParams& params, const std::uint8_t* preimage,
                            std::size_t preimage_size, std::uint64_t nonce) {
  if (out == nullptr) {
    throw std::invalid_argument("write_scratchpad_image: null output buffer");
  }
  const std::size_t cells = scratchpad_cell_count(params.memory_bytes);
  const std::size_t expected = scratchpad_image_bytes(cells);
  if (out_size != expected) {
    throw std::invalid_argument("write_scratchpad_image: buffer is " + std::to_string(out_size) +
                                " bytes, the pad needs " + std::to_string(expected));
  }
  if (preimage == nullptr && preimage_size != 0) {
    throw std::invalid_argument("write_scratchpad_image: non-zero size with a null preimage");
  }

  // 1. Seed. One SHA-256 — not the doubled one the trivial engine uses — over a
  //    copy of the preimage with the 8 little-endian nonce bytes appended. The
  //    caller's buffer is never extended in place, which is what keeps the
  //    107-byte header preimage nonce-free (C-4).
  constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
  if (preimage_size > kMax - sizeof(std::uint64_t)) {
    throw std::length_error("write_scratchpad_image: preimage too large to append a nonce");
  }
  std::vector<std::uint8_t> seed_input(preimage_size + sizeof(std::uint64_t));
  if (preimage_size != 0) {
    std::copy_n(preimage, preimage_size, seed_input.begin());
  }
  write_le64(nonce, seed_input.data() + preimage_size);
  std::array<std::uint8_t, kScratchpadCellBytes> state =
      sha256(seed_input.data(), seed_input.size());

  // Cell i lives at `kScratchpadCellBytes * (i + 1)`; index 0 of the image is
  // reserved for the final state, which is only known after the rounds. The
  // stride is a multiply on std::size_t, so it cannot narrow, and every i below
  // `cells` keeps the write inside `out_size` by the exact-size check above.
  std::uint8_t* const cells_begin = out + kScratchpadCellBytes;

  // 2. Fill. A hash chain seeded by `state`: cell i is SHA-256 of the state that
  //    cell i-1 left behind, and the state after the loop is the last cell — so
  //    the last cell is folded twice, once as the prefix and once as a cell, and
  //    the port must reproduce that.
  for (std::size_t cell = 0; cell < cells; ++cell) {
    state = sha256(state.data(), state.size());
    std::copy_n(state.begin(), kScratchpadCellBytes, cells_begin + kScratchpadCellBytes * cell);
  }

  // 3. Data-dependent rounds. The address comes from the current state, so the
  //    access pattern is not known ahead of the computation — the property the
  //    whole construction exists for.
  //
  //    A power-of-two pad masks; any other pad takes a remainder. These are NOT
  //    interchangeable: for cells = 2048 they agree, and for a non-power-of-two
  //    cell count a mask would index past the buffer. `cells` is never 0 (the
  //    floor in `scratchpad_cell_count`), so `cells - 1` cannot wrap and the
  //    remainder's divisor is never 0.
  const bool power_of_two = (cells & (cells - 1)) == 0;
  const std::uint64_t mask = static_cast<std::uint64_t>(cells - 1);
  const std::uint64_t cells_u64 = static_cast<std::uint64_t>(cells);
  std::array<std::uint8_t, kScratchpadCellBytes * 2> mixed{};
  for (std::size_t round = 0; round < params.rounds; ++round) {
    const std::uint64_t index_word = read_le64(state.data());
    // Both branches are strictly less than `cells`: a mask by `cells - 1` when
    // `cells` is a power of two, a remainder otherwise. So no bounds check is
    // needed here, and none is silently relied upon either.
    const std::size_t index =
        power_of_two ? static_cast<std::size_t>(index_word & mask)
                     : static_cast<std::size_t>(index_word % cells_u64);
    std::copy_n(state.begin(), kScratchpadCellBytes, mixed.begin());
    std::copy_n(cells_begin + kScratchpadCellBytes * index, kScratchpadCellBytes,
                mixed.begin() + kScratchpadCellBytes);
    state = sha256(mixed.data(), mixed.size());
    std::copy_n(state.begin(), kScratchpadCellBytes, cells_begin + kScratchpadCellBytes * index);
  }

  // 4. The prefix. Folding itself is the caller's `scratchpad_finalize` call.
  std::copy_n(state.begin(), kScratchpadCellBytes, out);
}

Hash256 scratchpad_finalize(const std::uint8_t* image, std::size_t size) {
  if (image == nullptr && size != 0) {
    throw std::invalid_argument("scratchpad_finalize: non-zero size with a null image");
  }
  // `sha256(data, 0)` is the empty-hash and never dereferences, so a zero-size
  // image is well-defined rather than a trap — unreachable from `hash()`, whose
  // smallest image is two cells.
  return Hash256(sha256(image, size));
}

}  // namespace detail

Hash256 PowEngine::hash(const std::uint8_t* preimage, std::size_t preimage_size,
                        std::uint64_t nonce) const {
  switch (kind_) {
    case Kind::kTrivial:
      return trivial_hash(preimage, preimage_size, nonce);
    case Kind::kScratchpad: {
      const std::size_t cells = scratchpad_cell_count(params_.memory_bytes);
      const std::size_t image_size = detail::scratchpad_image_bytes(cells);
      // One allocation holds the whole fold: the reserved prefix and every cell.
      // Value-initialisation is not a correctness requirement — the writer
      // overwrites all of it — but it keeps an arithmetic slip in the writer
      // from turning into a digest over uninitialised memory.
      std::vector<std::uint8_t> image(image_size);
      detail::write_scratchpad_image(image.data(), image.size(), params_, preimage, preimage_size,
                                     nonce);
      return detail::scratchpad_finalize(image.data(), image.size());
    }
  }
  // Unreachable: `kind_` is only ever one of the two enumerators above, and both
  // return. Kept so the function cannot fall off the end, and loud if a third
  // engine is ever added without a hash path.
  throw std::logic_error("PowEngine::hash: engine kind has no hash path");
}

std::optional<PowEngine> engine_for_id(std::uint8_t engine_id,
                                       const ScratchPadParams& scratchpad_params) noexcept {
  switch (engine_id) {
    case kEngineIdTrivial:
      return PowEngine::trivial();
    case kEngineIdScratchpad:
      return PowEngine::scratchpad(scratchpad_params);
    default:
      // No default engine. The reference has no id -> engine path to fall back
      // to, and a silent mapping would let an algorithm the network never
      // declared be reachable from a byte this module did not choose.
      return std::nullopt;
  }
}

Hash256 header_pow_hash(const BlockHeader& header, const PowEngine& engine) {
  // header_preimage owns the layout (C-3) and the nonce exclusion; this is the
  // reference's one-line composition `engine.hash(&self.preimage(), self.nonce)`.
  const std::array<std::uint8_t, kHeaderPreimageSize> preimage = header_preimage(header);
  return engine.hash(preimage.data(), preimage.size(), header.nonce);
}

bool header_meets_own_target(const BlockHeader& header, const PowEngine& engine) {
  // `meets_own_target` reads the header's OWN bits field, not the bits the chain
  // would have required at this height. `block_target` is the existing compact
  // decoder and `hash_meets_target` the existing F-11 comparison, so neither the
  // rounding rule nor the bound is restated here.
  return hash_meets_target(header_pow_hash(header, engine), block_target(header.difficulty_bits));
}

const char* pow_error_kind_name(PowErrorKind kind) noexcept {
  switch (kind) {
    case PowErrorKind::kNone:
      return "None";
    case PowErrorKind::kInsufficientWork:
      return "InsufficientWork";
  }
  return "Unknown";
}

PowVerifyResult verify_pow(const PowEngine& engine, const std::uint8_t* preimage,
                           std::size_t preimage_size, std::uint64_t nonce,
                           const Uint256& target) {
  const Hash256 hash = engine.hash(preimage, preimage_size, nonce);
  if (hash_meets_target(hash, target)) {
    return PowVerifyResult{PowErrorKind::kNone, hash};
  }
  // The reference's `InsufficientWork` carries the hash, so the rejection is
  // reportable and never looks like a missing value.
  return PowVerifyResult{PowErrorKind::kInsufficientWork, hash};
}

// The seam is reachable only from inside the library and from tests/; the width
// it commits to is the one the reference's fold depends on, and the arithmetic
// is checked at compile time on both shipped profiles.
static_assert(detail::scratchpad_image_bytes(2048) == 2049 * kScratchpadCellBytes,
              "the devnet fold is one prefix plus 2,048 cells");
static_assert(detail::scratchpad_image_bytes(65536) == 65537 * kScratchpadCellBytes,
              "the mainnet fold is one prefix plus 65,536 cells");
static_assert(kScratchpadDevnet.memory_bytes == kScratchpadCellBytes * 2048 &&
                  kScratchpadMainnet.memory_bytes == kScratchpadCellBytes * 65536,
              "both shipped profiles are a whole number of cells, so no budget is dropped");

}  // namespace zk
