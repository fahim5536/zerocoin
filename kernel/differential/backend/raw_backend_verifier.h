// Test-only raw probe of the pinned libsecp256k1: the backend verdict with no
// ZeroCoin contract gate applied. It exists so the differential report can
// show exactly where the production verifier's compressed-key gate is
// load-bearing instead of claiming parity the library does not have.
//
// The production path is `zk::Secp256k1Verifier`
// (kernel/include/zerocoin/secp256k1_verifier.h), which applies the 33-byte
// gate before making exactly these backend calls. This class ships only in the
// differential experiment and is never linked into `zerocoin_kernel`.

#ifndef ZEROCOIN_KERNEL_DIFFERENTIAL_RAW_BACKEND_VERIFIER_H_
#define ZEROCOIN_KERNEL_DIFFERENTIAL_RAW_BACKEND_VERIFIER_H_

#include <cstddef>
#include <cstdint>

#include "zerocoin/sighash.h"

// Declared by the pinned `<secp256k1.h>`; only used as an opaque handle here so
// this header stays free of third-party includes.
struct secp256k1_context_struct;

namespace zk::differential {

class RawBackendVerifier final {
 public:
  RawBackendVerifier();
  ~RawBackendVerifier();

  RawBackendVerifier(const RawBackendVerifier&) = delete;
  RawBackendVerifier& operator=(const RawBackendVerifier&) = delete;
  RawBackendVerifier(RawBackendVerifier&&) = delete;
  RawBackendVerifier& operator=(RawBackendVerifier&&) = delete;

  // The raw backend verdict: no ZeroCoin length gate. Fail-closed; never throws.
  bool verify(const Hash256& digest, const std::uint8_t* der, std::size_t der_size,
              const std::uint8_t* public_key, std::size_t public_key_size) const;

 private:
  secp256k1_context_struct* ctx_;
};

}  // namespace zk::differential

#endif  // ZEROCOIN_KERNEL_DIFFERENTIAL_RAW_BACKEND_VERIFIER_H_
