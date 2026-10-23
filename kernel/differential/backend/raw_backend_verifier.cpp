#include "raw_backend_verifier.h"

#include <secp256k1.h>

namespace zk::differential {

RawBackendVerifier::RawBackendVerifier()
    : ctx_(secp256k1_context_create(SECP256K1_CONTEXT_NONE)) {}

RawBackendVerifier::~RawBackendVerifier() {
  if (ctx_ != nullptr) {
    secp256k1_context_destroy(ctx_);
  }
}

bool RawBackendVerifier::verify(const Hash256& digest, const std::uint8_t* der,
                                std::size_t der_size, const std::uint8_t* public_key,
                                std::size_t public_key_size) const {
  if (ctx_ == nullptr) {
    return false;
  }
  if (der == nullptr || der_size == 0) {
    return false;
  }
  if (public_key == nullptr || public_key_size == 0) {
    return false;
  }

  secp256k1_ecdsa_signature signature;
  if (secp256k1_ecdsa_signature_parse_der(ctx_, &signature, der, der_size) != 1) {
    return false;
  }

  secp256k1_pubkey parsed_key;
  if (secp256k1_ec_pubkey_parse(ctx_, &parsed_key, public_key, public_key_size) != 1) {
    return false;
  }

  // Rejects high-S internally (`!secp256k1_scalar_is_high` before the equation),
  // which is the same rule the Rust reference inherits from `k256`.
  return secp256k1_ecdsa_verify(ctx_, &signature, digest.bytes.data(), &parsed_key) == 1;
}

}  // namespace zk::differential
