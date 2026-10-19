#include "secp256k1_verifier.h"

#include <secp256k1.h>

namespace zk::differential {
namespace {

// `src/crypto/secp256k1.rs` (`COMPRESSED_PUBKEY_LEN`) accepts exactly this many
// bytes and nothing else. The gate is applied here, not in libsecp256k1, which
// also accepts 65-byte and hybrid encodings.
constexpr std::size_t kCompressedPublicKeySize = 33;

}  // namespace

Secp256k1Verifier::Secp256k1Verifier()
    : ctx_(secp256k1_context_create(SECP256K1_CONTEXT_NONE)) {}

Secp256k1Verifier::~Secp256k1Verifier() {
  if (ctx_ != nullptr) {
    secp256k1_context_destroy(ctx_);
  }
}

bool Secp256k1Verifier::backend_verify(const Hash256& digest, const std::uint8_t* der,
                                       std::size_t der_size,
                                       const std::uint8_t* public_key,
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

bool Secp256k1Verifier::verify(const Hash256& digest, const std::uint8_t* der,
                               std::size_t der_size, const std::uint8_t* public_key,
                               std::size_t public_key_size) const {
  // Seam contract first: `PublicKey::from_sec1` in the Rust reference rejects
  // any length other than 33 before the curve arithmetic is reached.
  if (public_key_size != kCompressedPublicKeySize) {
    return false;
  }
  return backend_verify(digest, der, der_size, public_key, public_key_size);
}

}  // namespace zk::differential
