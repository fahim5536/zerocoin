// The production curve backend behind `zk::SigVerifier`: the pinned vendored
// libsecp256k1 v0.8.0 (kernel/third_party/secp256k1, ORIGIN.md).
//
// Since P2.10 §7 this class is what `TxSigChecker` calls when the script
// interpreter reaches OP_CHECKSIG. It binds exactly the obligations of
// docs/architecture/INTERFACE_CONTRACTS.md §3:
//
//   B1  only 33-byte compressed SEC1 keys (02/03 tag); the length gate is
//       applied here because libsecp256k1 itself also accepts 65-byte and
//       hybrid encodings, which rule P-1 rejects;
//   B2  strict DER decoding;
//   B3  the 32-byte digest is used exactly as given;
//   B4  high-S signatures are rejected, never normalised (the library rejects
//       them internally, the same rule the Rust reference inherits from k256);
//   B5  every failure — null input, wrong length, parse error, backend error —
//       is `false`; nothing here throws;
//   B6  safe to share across threads: the context is immutable after
//       construction and `secp256k1_ecdsa_verify` is documented re-entrant;
//   B7  no key or signature material is logged or retained.
//
// Verification only: no signing API exists in the kernel (C-52; the RFC 6979
// signing adapter lives under kernel/differential/signing and is never linked
// into `zerocoin_kernel`).

#ifndef ZEROCOIN_KERNEL_SECP256K1_VERIFIER_H
#define ZEROCOIN_KERNEL_SECP256K1_VERIFIER_H

#include <cstddef>
#include <cstdint>

#include "zerocoin/sighash.h"

// Declared by the pinned `<secp256k1.h>`; only used as an opaque handle here so
// this header stays free of third-party includes.
struct secp256k1_context_struct;

namespace zk {

class Secp256k1Verifier final : public SigVerifier {
 public:
  Secp256k1Verifier();
  ~Secp256k1Verifier() override;

  Secp256k1Verifier(const Secp256k1Verifier&) = delete;
  Secp256k1Verifier& operator=(const Secp256k1Verifier&) = delete;
  Secp256k1Verifier(Secp256k1Verifier&&) = delete;
  Secp256k1Verifier& operator=(Secp256k1Verifier&&) = delete;

  // Fail-closed. Any parse failure, scalar-range rejection, wrong-length key or
  // backend error yields `false`; nothing here throws.
  bool verify(const Hash256& digest, const std::uint8_t* der, std::size_t der_size,
              const std::uint8_t* public_key,
              std::size_t public_key_size) const override;

 private:
  secp256k1_context_struct* ctx_;
};

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_SECP256K1_VERIFIER_H
