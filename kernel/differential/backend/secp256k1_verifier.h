// Test-only adapter from `zk::SigVerifier` to libsecp256k1 v0.8.0.
//
// Scope: P2.6 differential experiment. This class is NOT part of the production
// kernel, is not linked into `zerocoin_kernel`, and must not be reachable from
// `TxSigChecker`. See `kernel/third_party/secp256k1/ORIGIN.md` and
// `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md` §13.
//
// The class exposes two verdicts on purpose:
//
//   `verify`         the verdict the seam must produce: it applies the ZeroCoin
//                    contract gate (33-byte compressed SEC1 only) and then asks
//                    the backend. This is the only method a production caller
//                    would ever use.
//
//   `backend_verify` the raw backend verdict with no ZeroCoin gate applied.
//                    It exists so the differential report can show exactly
//                    where the adapter is load-bearing instead of claiming
//                    parity the library does not have.

#ifndef ZEROCOIN_KERNEL_DIFFERENTIAL_SECP256K1_VERIFIER_H_
#define ZEROCOIN_KERNEL_DIFFERENTIAL_SECP256K1_VERIFIER_H_

#include <cstddef>
#include <cstdint>

#include "zerocoin/sighash.h"

// Declared by the pinned `<secp256k1.h>`; only used as an opaque handle here so
// this header stays free of third-party includes.
struct secp256k1_context_struct;

namespace zk::differential {

class Secp256k1Verifier final : public SigVerifier {
 public:
  Secp256k1Verifier();
  ~Secp256k1Verifier() override;

  Secp256k1Verifier(const Secp256k1Verifier&) = delete;
  Secp256k1Verifier& operator=(const Secp256k1Verifier&) = delete;
  Secp256k1Verifier(Secp256k1Verifier&&) = delete;
  Secp256k1Verifier& operator=(Secp256k1Verifier&&) = delete;

  // Fail-closed. Any parse failure, scalar-range rejection, wrong-length key or
  // backend error yields `false`; nothing here throws and nothing panics.
  bool verify(const Hash256& digest, const std::uint8_t* der, std::size_t der_size,
              const std::uint8_t* public_key,
              std::size_t public_key_size) const override;

  // Raw backend verdict, bypassing the ZeroCoin length gate. Test-only.
  bool backend_verify(const Hash256& digest, const std::uint8_t* der,
                      std::size_t der_size, const std::uint8_t* public_key,
                      std::size_t public_key_size) const;

 private:
  secp256k1_context_struct* ctx_;
};

}  // namespace zk::differential

#endif  // ZEROCOIN_KERNEL_DIFFERENTIAL_SECP256K1_VERIFIER_H_
