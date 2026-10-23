#include "secp256k1_signer.h"

#include <secp256k1.h>

namespace zk::differential {
namespace {

// The corpus fixture signs a 32-byte prehash (`internal_hex` of
// `ledger.sighash.signature_der`); the secret key is 32 bytes by contract.
constexpr std::size_t kDigestSize = 32;
constexpr std::size_t kSecretKeySize = 32;

// `secp256k1_ecdsa_sig_serialize` writes at most 6 + 33 + 33 bytes
// (`src/ecdsa_impl.h`).
constexpr std::size_t kMaxDerSize = 72;

}  // namespace

// v0.8.0 builds the ecmult_gen context for every created context regardless of
// flags (`src/secp256k1.c`, `secp256k1_context_preallocated_create` calls
// `secp256k1_ecmult_gen_context_build` unconditionally); the deprecated
// SECP256K1_CONTEXT_SIGN is documented as equivalent to NONE, and the only
// context `secp256k1_ecdsa_sign` excludes is `secp256k1_context_static`. The
// verifier adapter uses NONE for the same reason.
Secp256k1Signer::Secp256k1Signer()
    : ctx_(secp256k1_context_create(SECP256K1_CONTEXT_NONE)) {}

Secp256k1Signer::~Secp256k1Signer() {
  if (ctx_ != nullptr) {
    secp256k1_context_destroy(ctx_);
  }
}

std::optional<std::vector<std::uint8_t>> Secp256k1Signer::sign_der(
    const std::uint8_t* msg32, std::size_t msg32_size,
    const std::uint8_t* seckey, std::size_t seckey_size) const {
  if (ctx_ == nullptr) {
    return std::nullopt;
  }
  if (msg32 == nullptr || msg32_size != kDigestSize) {
    return std::nullopt;
  }
  if (seckey == nullptr || seckey_size != kSecretKeySize) {
    return std::nullopt;
  }

  secp256k1_ecdsa_signature signature;
  // `noncefp = NULL` selects the RFC 6979 default (see the header comment). An
  // invalid secret scalar (0 or >= n) makes the call return 0:
  // `secp256k1_ecdsa_sign_inner` computes `ret &= is_sec_valid`
  // (`src/secp256k1.c`), and `secp256k1_ecdsa_sign` saves zeroed scalars in
  // that case.
  if (secp256k1_ecdsa_sign(ctx_, &signature, msg32, seckey, nullptr, nullptr) != 1) {
    return std::nullopt;
  }

  std::uint8_t der[kMaxDerSize];
  std::size_t der_size = sizeof(der);
  if (secp256k1_ecdsa_signature_serialize_der(ctx_, der, &der_size, &signature) != 1) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(der, der + der_size);
}

}  // namespace zk::differential
