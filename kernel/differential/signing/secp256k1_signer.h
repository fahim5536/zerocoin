// Test-only signing adapter from ZeroCoin's differential harness to
// libsecp256k1 v0.8.0.
//
// Scope: the P2.10 deterministic DER parity check (blocker CB-1). This class
// is NOT part of the production kernel, is not linked into `zerocoin_kernel`,
// and must not be reachable from `TxSigChecker`, the wallet or any node
// binary. The differential project is a standalone CMake tree; the only
// consumer of this adapter is the `secp256k1_der_signing` test executable next
// to it. See `docs/architecture/CRYPTO_BLOCKER_REGISTER.md` (CB-1) and
// `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md` §19.2.
//
// The adapter is necessary and justified exactly as the audit's §19.2
// prescribes: the `ledger.sighash.signature_der` vector requires *signing*
// (the committed value is a 71-byte DER signature, not a verdict), a
// verifier-only harness cannot produce comparable bytes, every input is a
// fixed published test value, and the expected bytes were committed by the
// pinned Rust reference (k256 0.13.4), never transcribed from this library.
// The adapter exposes the prescribed signing surface and nothing else:
//
//   * `secp256k1_ecdsa_sign` with `noncefp = NULL`, which selects
//     `secp256k1_nonce_function_default` == `secp256k1_nonce_function_rfc6979`
//     (vendored `include/secp256k1.h`): RFC 6979 nonce derivation over
//     HMAC-SHA256 (`src/hash_impl.h`, steps 3.2.b-h), with the 32-byte input
//     taken as the message hash `h1` exactly as the Rust fixture does;
//   * `secp256k1_ecdsa_signature_serialize_der` for the DER encoding.
//
// The library enforces low-S at signing time (`src/ecdsa_impl.h`,
// `secp256k1_ecdsa_sig_sign`: `scalar_cond_negate(sigs, is_high)`), so the
// output is directly comparable with the low-S DER the Rust reference
// committed.
//
// There is no production signing API here: no entropy, no key generation, no
// key storage, no zeroisation policy — only fixed non-secret test scalars in
// and DER bytes out, fail-closed on every invalid input.

#ifndef ZEROCOIN_KERNEL_DIFFERENTIAL_SECP256K1_SIGNER_H_
#define ZEROCOIN_KERNEL_DIFFERENTIAL_SECP256K1_SIGNER_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

// Declared by the pinned `<secp256k1.h>`; only used as an opaque handle here so
// this header stays free of third-party includes.
struct secp256k1_context_struct;

namespace zk::differential {

class Secp256k1Signer final {
 public:
  Secp256k1Signer();
  ~Secp256k1Signer();

  Secp256k1Signer(const Secp256k1Signer&) = delete;
  Secp256k1Signer& operator=(const Secp256k1Signer&) = delete;
  Secp256k1Signer(Secp256k1Signer&&) = delete;
  Secp256k1Signer& operator=(Secp256k1Signer&&) = delete;

  // Deterministic RFC 6979 (SHA-256) low-S DER signature over a 32-byte
  // prehash. Fail-closed: a null pointer, a wrong length, an invalid secret
  // scalar (0 or >= n) or any backend error yields `std::nullopt`; nothing
  // here throws and nothing panics.
  std::optional<std::vector<std::uint8_t>> sign_der(const std::uint8_t* msg32,
                                                    std::size_t msg32_size,
                                                    const std::uint8_t* seckey,
                                                    std::size_t seckey_size) const;

 private:
  secp256k1_context_struct* ctx_;
};

}  // namespace zk::differential

#endif  // ZEROCOIN_KERNEL_DIFFERENTIAL_SECP256K1_SIGNER_H_
