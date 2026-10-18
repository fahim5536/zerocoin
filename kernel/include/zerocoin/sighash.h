// Signature hashing (sighash) and the transaction signature checker,
// mirroring zerocoin/src/ledger/sighash.rs exactly.
//
// A ZeroCoin signature commits to the transaction being spent, the specific
// input being authorized, the output script of the coin being spent
// (`script_code`), the sighash type, and — as a deviation-hardening measure —
// the chain id. Binding the chain id into every preimage is domain separation:
// a signature valid on devnet can never be replayed on mainnet.
//
// Only SIGHASH_ALL is accepted by the checker. The hasher still folds whatever
// type it is given into the preimage, because that is what the reference does
// (finding F18): the type is a checked rule at the checker and a convention at
// the hasher.

#ifndef ZEROCOIN_KERNEL_SIGHASH_H
#define ZEROCOIN_KERNEL_SIGHASH_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "zerocoin/hash.h"
#include "zerocoin/script.h"
#include "zerocoin/transaction.h"

namespace zk {

/// The only supported sighash type: commit to every input and every output.
inline constexpr std::uint32_t kSigHashAll = 0x01;

/// Domain-separation tag mixed into every signature preimage: `ZRO/sighash/v1\0`.
inline constexpr std::uint8_t kSigHashTag[] = {'Z', 'R', 'O', '/', 's', 'i', 'g', 'h', 'a', 's',
                                               'h', '/', 'v', '1', 0};
inline constexpr std::size_t kSigHashTagSize = sizeof(kSigHashTag);

/// Identifies a network. Mixed into sighash so signatures cannot cross chains.
/// Mainnet is 0x5A524F01, devnet 0x5A524F02, regtest 0x5A524F00.
struct ChainId {
  std::uint32_t value = 0;

  friend constexpr bool operator==(const ChainId& lhs, const ChainId& rhs) noexcept {
    return lhs.value == rhs.value;
  }
  friend constexpr bool operator!=(const ChainId& lhs, const ChainId& rhs) noexcept {
    return !(lhs == rhs);
  }
};

/// A preimage and the digest it hashes to. The reference returns only the
/// digest; both are exposed here so the corpus can pin the bytes that are
/// hashed, not just the result.
struct SigHash {
  std::vector<std::uint8_t> preimage;
  Hash256 digest{};
};

/// Compute the digest a signature over input `input_index` must cover.
///
/// `script_code` is the scriptPubKey of the output being spent. Every input's
/// scriptSig is blanked and the input being signed carries `script_code` in its
/// place, so a signature commits to the exact coin it authorizes without
/// committing to other inputs' unlock data.
///
/// Returns `nullopt` when `input_index` is out of range: the checker treats
/// that as an automatic verification failure rather than a guessable digest.
/// `sighash_type` is folded in verbatim and is not validated here (F18).
std::optional<SigHash> signature_hash(const Transaction& tx, std::size_t input_index,
                                      const std::uint8_t* script_code,
                                      std::size_t script_code_size, ChainId chain_id,
                                      std::uint32_t sighash_type);

/// The curve backend behind `TxSigChecker`.
///
/// It owns DER decoding, SEC1 public-key parsing and point validation, and the
/// ECDSA verification itself. The kernel does not implement any of that: R9 in
/// docs/migration/04-risk-register.md requires a vetted library, and none is
/// linked in this phase, so no implementation of this interface ships here.
class SigVerifier {
 public:
  virtual ~SigVerifier() = default;

  /// `der` is the DER signature without the trailing sighash byte; `public_key`
  /// is compressed SEC1. Return true only if both parse and the signature is
  /// valid over `digest`.
  virtual bool verify(const Hash256& digest, const std::uint8_t* der, std::size_t der_size,
                      const std::uint8_t* public_key,
                      std::size_t public_key_size) const = 0;
};

/// A `SigChecker` bound to one transaction input, used by the script
/// interpreter when it reaches `OP_CHECKSIG` while validating that input.
///
/// `script_code` is not copied: it must outlive the checker. `verifier` may be
/// null, in which case every signature is rejected — the phase has no curve
/// backend, so it fails closed instead of guessing (G2c, docs/migration/08).
class TxSigChecker final : public SigChecker {
 public:
  TxSigChecker(const Transaction& tx, std::size_t input_index, const std::uint8_t* script_code,
               std::size_t script_code_size, ChainId chain_id,
               const SigVerifier* verifier) noexcept;

  bool check_signature(const std::uint8_t* signature, std::size_t signature_size,
                       const std::uint8_t* public_key,
                       std::size_t public_key_size) const override;

 private:
  const Transaction& tx_;
  std::size_t input_index_;
  const std::uint8_t* script_code_;
  std::size_t script_code_size_;
  ChainId chain_id_;
  const SigVerifier* verifier_;
};

static_assert(kSigHashAll == 0x01, "SIGHASH_ALL is the only consensus-valid type");
static_assert(sizeof(kSigHashTag) == 15, "the tag is ZRO/sighash/v1 plus a NUL");
static_assert(kSigHashTagSize == 15, "the tag length is frozen with the preimage");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_SIGHASH_H
