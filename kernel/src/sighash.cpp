#include "zerocoin/sighash.h"

#include <utility>

#include "zerocoin/varint.h"

namespace zk {
namespace {

void append_le32(std::uint32_t value, std::vector<std::uint8_t>& out) {
  out.push_back(static_cast<std::uint8_t>(value));
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value >> 16));
  out.push_back(static_cast<std::uint8_t>(value >> 24));
}

void append_le64(std::uint64_t value, std::vector<std::uint8_t>& out) {
  for (unsigned i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
  }
}

void append_bytes(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out) {
  if (size != 0) {
    out.insert(out.end(), data, data + size);
  }
}

}  // namespace

std::optional<SigHash> signature_hash(const Transaction& tx, std::size_t input_index,
                                      const std::uint8_t* script_code,
                                      std::size_t script_code_size, ChainId chain_id,
                                      std::uint32_t sighash_type) {
  if (input_index >= tx.inputs.size()) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> preimage;
  preimage.reserve(128);
  append_bytes(kSigHashTag, kSigHashTagSize, preimage);
  append_le32(chain_id.value, preimage);

  // Version. Casting the signed value to u32 yields the same bytes as the
  // reference's i32::to_le_bytes.
  append_le32(static_cast<std::uint32_t>(tx.version), preimage);

  // Inputs: blank every scriptSig except the one being signed, which carries
  // the script_code of the coin it spends.
  write_varint(tx.inputs.size(), preimage);
  for (std::size_t index = 0; index < tx.inputs.size(); ++index) {
    const TxIn& input = tx.inputs[index];
    append_bytes(input.previous_output.txid.bytes.data(), Hash256::kWidth, preimage);
    append_le32(input.previous_output.vout, preimage);
    const bool signed_input = index == input_index;
    write_varint(signed_input ? script_code_size : 0, preimage);
    if (signed_input) {
      append_bytes(script_code, script_code_size, preimage);
    }
    append_le32(input.sequence, preimage);
  }

  // Outputs.
  write_varint(tx.outputs.size(), preimage);
  for (const TxOut& output : tx.outputs) {
    append_le64(output.value, preimage);
    write_varint(output.script_pubkey.size(), preimage);
    append_bytes(output.script_pubkey.data(), output.script_pubkey.size(), preimage);
  }

  append_le32(tx.lock_time, preimage);
  append_le32(sighash_type, preimage);

  SigHash result;
  result.digest = sha256d(preimage.data(), preimage.size());
  result.preimage = std::move(preimage);
  return result;
}

TxSigChecker::TxSigChecker(const Transaction& tx, std::size_t input_index,
                           const std::uint8_t* script_code, std::size_t script_code_size,
                           ChainId chain_id, const SigVerifier* verifier) noexcept
    : tx_(tx),
      input_index_(input_index),
      script_code_(script_code),
      script_code_size_(script_code_size),
      chain_id_(chain_id),
      verifier_(verifier) {}

bool TxSigChecker::check_signature(const std::uint8_t* signature, std::size_t signature_size,
                                   const std::uint8_t* public_key,
                                   std::size_t public_key_size) const {
  // A signature on the stack is DER bytes followed by a single sighash byte.
  if (signature == nullptr || signature_size == 0) {
    return false;
  }
  const std::uint32_t sighash_type = signature[signature_size - 1];
  if (sighash_type != kSigHashAll) {
    // Only SIGHASH_ALL is consensus-valid in ZeroCoin.
    return false;
  }
  const std::size_t der_size = signature_size - 1;
  const std::optional<SigHash> sighash =
      signature_hash(tx_, input_index_, script_code_, script_code_size_, chain_id_, sighash_type);
  if (!sighash.has_value()) {
    return false;
  }
  if (verifier_ == nullptr) {
    // No curve backend in this phase: fail closed rather than accept.
    return false;
  }
  return verifier_->verify(sighash->digest, signature, der_size, public_key, public_key_size);
}

}  // namespace zk
