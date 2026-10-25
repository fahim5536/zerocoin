// The scratchpad engine's internal seams. NOT part of the kernel's production
// interface: this header lives under src/, outside the directory CMake exports
// (kernel/CMakeLists.txt gives `zerocoin_kernel` only `include/` as PUBLIC), so
// no node-side consumer can reach it without an explicit relative path. It
// exists because CPP_PORT_REQUIREMENTS C-4's memory-hard step has one property
// that cannot be observed through `PowEngine::hash` at all — that the final
// digest folds EVERY cell and not just the last one — and the corruption tests
// in tests/test_pow.cpp have to mutate that folded image to prove it.
//
// The image is the exact byte string Rust streams into its finalizer: the state
// after the last round, then cell 0, cell 1, ... cell n-1, each 32 bytes, with
// no separator, length or padding. `PowEngine::hash` for the scratchpad engine is
// `scratchpad_finalize(write_scratchpad_image(...))` and nothing else, so what the
// tests can corrupt is what production hashes.

#ifndef ZEROCOIN_KERNEL_POW_INTERNAL_H
#define ZEROCOIN_KERNEL_POW_INTERNAL_H

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

#include "zerocoin/pow.h"

namespace zk::detail {

/// The width of the folded image: the reserved final-state prefix plus every
/// cell, `(1 + cells) * kScratchpadCellBytes`.
///
/// The multiplication is checked. `cells` is at most `SIZE_MAX / 32`, so only a
/// `memory_bytes` within 32 bytes of `SIZE_MAX` can overflow it — and the
/// product of that one band would wrap to a smaller buffer than the pad, which
/// is the failure mode that produces a plausible digest over a truncated fold.
/// It throws `std::length_error` there instead, the same stance `hash()` takes
/// for an exhausted allocator. Defined here rather than in `pow.cpp` because it
/// is pure arithmetic and both the implementation and the tests freeze it at
/// compile time.
inline constexpr std::size_t scratchpad_image_bytes(std::size_t cells) {
  constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
  if (cells > (kMax / kScratchpadCellBytes) - 1) {
    throw std::length_error("scratchpad cell count too large to size the fold buffer");
  }
  return (1 + cells) * kScratchpadCellBytes;
}

/// Runs the reference's four steps and leaves the folded image in `out`.
///
/// `out` must point to `scratchpad_image_bytes(scratchpad_cell_count(
/// params.memory_bytes))` writable bytes; any other size throws
/// `std::invalid_argument` rather than writing past the buffer or leaving part
/// of it uninitialised. `preimage` may be null if and only if `preimage_size`
/// is 0, and is read but never written.
void write_scratchpad_image(std::uint8_t* out, std::size_t out_size,
                            const ScratchPadParams& params, const std::uint8_t* preimage,
                            std::size_t preimage_size, std::uint64_t nonce);

/// The reference's finalizer: one SHA-256 over the whole folded image.
///
/// Kept separate from the writer so a test can feed it an image it has mutated
/// itself. Every 32-byte unit of `image` must have been written by
/// `write_scratchpad_image`; the function cannot tell and does not try — it
/// hashes whatever it is given, which is exactly why the separation is the point.
Hash256 scratchpad_finalize(const std::uint8_t* image, std::size_t size);

}  // namespace zk::detail

#endif  // ZEROCOIN_KERNEL_POW_INTERNAL_H
