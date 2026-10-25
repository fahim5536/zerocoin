// Replays the conformance corpora. Each fixture is generated from
// test/vectors/*.json by one of the tools/*_conformance.py wrappers, which also
// check the runner's answers: this binary knows nothing about the Rust source
// and nothing about JSON, so a passing run means the C++ kernel reproduced
// bytes that the Rust reference produced. Since P3.1B the header corpus is
// replayed the same way; it lives outside that root, in test/p31-vectors/chain/, and
// tools/p31_conformance.py renders it. Since P3.2B the leaf-level Merkle corpus
// is replayed the same way too, from test/p32-vectors/chain/, rendered by
// tools/p32_conformance.py.
//
// Fixture grammar (one directive per line, `value` is everything after the
// first '=' so empty values are unambiguous):
//
//   META key=value
//   CASE <id>
//   OP <op>
//   IN key=value      (repeatable; `in` and `out` carry one item each)
//   OUT key=value
//   END
//
// One output line per case:   RESULT <id> ok | fail <message>
// Final line:                 SUMMARY cases=<n> failures=<n>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "zerocoin/difficulty.h"
#include "zerocoin/hash.h"
#include "zerocoin/header.h"
#include "zerocoin/hex.h"
#include "zerocoin/merkle.h"
#include "zerocoin/script.h"
#include "zerocoin/secp256k1_verifier.h"
#include "zerocoin/sighash.h"
#include "zerocoin/transaction.h"
#include "zerocoin/uint256.h"
#include "zerocoin/varint.h"

namespace {

using zk::Hash160;
using zk::Hash256;
using zk::Transaction;
using zk::TxDecodeResult;
using zk::TxIn;
using zk::TxOut;
using zk::Uint256;

struct CaseError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

[[noreturn]] void fail(const std::string& message) { throw CaseError(message); }

std::string one_line(std::string text) {
  std::replace(text.begin(), text.end(), '\n', ' ');
  return text;
}

struct Case {
  std::string id;
  std::string op;
  std::vector<std::pair<std::string, std::string>> inputs;
  std::vector<std::pair<std::string, std::string>> outputs;

  std::vector<std::string> all(const std::string& key) const {
    std::vector<std::string> values;
    for (const auto& [name, value] : inputs) {
      if (name == key) {
        values.push_back(value);
      }
    }
    return values;
  }

  std::string one(const std::string& key) const {
    const std::vector<std::string> values = all(key);
    if (values.empty()) {
      fail("fixture has no IN " + key + " for case " + id);
    }
    if (values.size() > 1) {
      fail("fixture has " + std::to_string(values.size()) + " IN " + key + " for case " + id);
    }
    return values.front();
  }
};

std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (true) {
    const std::size_t end = text.find(separator, start);
    if (end == std::string::npos) {
      parts.push_back(text.substr(start));
      return parts;
    }
    parts.push_back(text.substr(start, end - start));
    start = end + 1;
  }
}

std::uint64_t parse_u64(const std::string& text, const std::string& what, int base = 10) {
  if (text.empty()) {
    fail(what + ": empty number");
  }
  errno = 0;
  char* end = nullptr;
  const unsigned long long value = std::strtoull(text.c_str(), &end, base);
  if (errno != 0 || end != text.c_str() + text.size()) {
    fail(what + ": not a number: " + text);
  }
  return static_cast<std::uint64_t>(value);
}

std::uint64_t parse_bits(const std::string& text) {
  if (text.rfind("0x", 0) == 0) {
    return parse_u64(text.substr(2), "bits", 16);
  }
  return parse_u64(text, "bits");
}

std::uint32_t parse_u32(const std::string& text, const std::string& what) {
  const std::uint64_t value = parse_u64(text, what);
  if (value > 0xffff'ffffull) {
    fail(what + ": does not fit in 32 bits: " + text);
  }
  return static_cast<std::uint32_t>(value);
}

std::uint32_t parse_bits_u32(const std::string& text) {
  const std::uint64_t bits = parse_bits(text);
  if (bits > 0xffff'ffffull) {
    fail("bits: does not fit in 32 bits: " + text);
  }
  return static_cast<std::uint32_t>(bits);
}

std::vector<std::uint8_t> bytes_of(const std::string& hex, const std::string& what) {
  auto bytes = zk::from_hex(hex);
  if (!bytes.has_value()) {
    fail(what + ": not a hex string");
  }
  return *bytes;
}

Hash256 hash256_of(const std::string& hex, const std::string& what) {
  const std::vector<std::uint8_t> bytes = bytes_of(hex, what);
  if (bytes.size() != Hash256::kWidth) {
    fail(what + ": expected 32 bytes, got " + std::to_string(bytes.size()));
  }
  Hash256 hash{};
  std::copy(bytes.begin(), bytes.end(), hash.bytes.begin());
  return hash;
}

std::string hex_of(const std::vector<std::uint8_t>& bytes) {
  return zk::to_hex(bytes.data(), bytes.size());
}

Transaction tx_of(const std::string& hex, const std::string& what) {
  const std::vector<std::uint8_t> bytes = bytes_of(hex, what);
  const TxDecodeResult result = zk::deserialize_transaction(bytes.data(), bytes.size());
  if (!result) {
    fail(what + ": decode failed: " + zk::to_string(result.error));
  }
  if (result.consumed != bytes.size()) {
    fail(what + ": " + std::to_string(bytes.size() - result.consumed) +
         " trailing bytes after the transaction");
  }
  return result.tx;
}

std::string bool_text(bool value) { return value ? "true" : "false"; }

std::string value_text(const std::optional<std::uint64_t>& value) {
  return value.has_value() ? std::to_string(*value) : "overflow";
}

std::string txid_internal(const Transaction& tx) { return tx.txid().to_hex().str(); }
std::string txid_display(const Transaction& tx) { return tx.txid().to_display_hex().str(); }

// --- operations -------------------------------------------------------------

using Produced = std::map<std::string, std::string>;

Produced op_sha256_utf8(const Case& c) {
  const std::string text = c.one("text_utf8");
  const auto digest = zk::sha256(text);
  return {{"sha256_hex", zk::to_hex(digest.data(), digest.size())}};
}

Produced op_sha256d_utf8(const Case& c) {
  const std::string text = c.one("text_utf8");
  const Hash256 hash = zk::sha256d(text);
  return {{"internal_hex", hash.to_hex().str()}, {"display_hex", hash.to_display_hex().str()}};
}

Produced op_hash160_sec1(const Case& c) {
  const std::vector<std::uint8_t> pubkey = bytes_of(c.one("pubkey_sec1_hex"), "pubkey");
  const Hash160 hash = zk::hash160(pubkey.data(), pubkey.size());
  return {{"hash160_hex", hash.to_hex().str()}};
}

Produced op_display_reversal(const Case& c) {
  const std::vector<std::uint8_t> bytes = bytes_of(c.one("internal_hex"), "internal_hex");
  if (bytes.size() == 32) {
    std::array<std::uint8_t, 32> raw{};
    std::copy(bytes.begin(), bytes.end(), raw.begin());
    return {{"display_hex", zk::DisplayHex256(raw).str()}};
  }
  if (bytes.size() == 20) {
    std::array<std::uint8_t, 20> raw{};
    std::copy(bytes.begin(), bytes.end(), raw.begin());
    return {{"display_hex", zk::DisplayHex20(raw).str()}};
  }
  fail("internal_hex: expected 20 or 32 bytes, got " + std::to_string(bytes.size()));
}

Produced op_varint_encode(const Case& c) {
  const std::uint64_t value = parse_u64(c.one("value"), "value");
  std::vector<std::uint8_t> encoded;
  zk::write_varint(value, encoded);
  return {{"bytes_hex", hex_of(encoded)}, {"length", std::to_string(encoded.size())}};
}

Produced op_tx_build(const Case& c) {
  Transaction tx;
  tx.version = static_cast<std::int32_t>(parse_u64(c.one("version"), "version"));
  tx.lock_time = static_cast<std::uint32_t>(parse_u64(c.one("lock_time"), "lock_time"));

  for (const std::string& spec : c.all("in")) {
    const std::vector<std::string> parts = split(spec, '|');
    if (parts.size() != 4) {
      fail("IN in: expected txid|vout|script_sig_hex|sequence: " + spec);
    }
    TxIn input;
    input.previous_output.txid = hash256_of(parts[0], "in.txid");
    input.previous_output.vout = static_cast<std::uint32_t>(parse_u64(parts[1], "in.vout"));
    input.script_sig = bytes_of(parts[2], "in.script_sig");
    input.sequence = static_cast<std::uint32_t>(parse_u64(parts[3], "in.sequence"));
    tx.inputs.push_back(std::move(input));
  }

  for (const std::string& spec : c.all("out")) {
    const std::vector<std::string> parts = split(spec, '|');
    if (parts.size() != 2) {
      fail("IN out: expected value|script_pubkey_hex: " + spec);
    }
    TxOut output;
    output.value = parse_u64(parts[0], "out.value");
    output.script_pubkey = bytes_of(parts[1], "out.script_pubkey");
    tx.outputs.push_back(std::move(output));
  }

  const std::vector<std::uint8_t> bytes = tx.serialize();
  const TxDecodeResult replay = zk::deserialize_transaction(bytes.data(), bytes.size());
  const bool roundtrip = static_cast<bool>(replay) && replay.tx == tx &&
                         replay.consumed == bytes.size();
  return {
      {"serialized_hex", hex_of(bytes)},
      {"serialized_len", std::to_string(bytes.size())},
      {"txid_internal_hex", txid_internal(tx)},
      {"txid_display_hex", txid_display(tx)},
      {"is_coinbase", bool_text(tx.is_coinbase())},
      {"output_value", value_text(tx.output_value())},
      {"roundtrip", bool_text(roundtrip)},
  };
}

Produced op_tx_roundtrip(const Case& c) {
  const std::vector<std::uint8_t> bytes = bytes_of(c.one("bytes_hex"), "bytes_hex");
  const TxDecodeResult result = zk::deserialize_transaction(bytes.data(), bytes.size());
  if (!result) {
    fail(std::string("decode failed: ") + zk::to_string(result.error));
  }

  const Transaction& tx = result.tx;
  Produced produced{
      {"serialized_hex", hex_of(tx.serialize())},
      {"txid_internal_hex", txid_internal(tx)},
      {"txid_display_hex", txid_display(tx)},
      {"is_coinbase", bool_text(tx.is_coinbase())},
      {"output_value", value_text(tx.output_value())},
      {"input_count", std::to_string(tx.inputs.size())},
      {"output_count", std::to_string(tx.outputs.size())},
      {"version", std::to_string(tx.version)},
      {"lock_time", std::to_string(tx.lock_time)},
      {"consumed", std::to_string(result.consumed)},
  };
  if (!tx.inputs.empty()) {
    produced["script_sig_hex"] = hex_of(tx.inputs.front().script_sig);
  }
  if (!tx.outputs.empty()) {
    produced["script_pubkey_hex"] = hex_of(tx.outputs.front().script_pubkey);
  }
  return produced;
}

Produced op_tx_decode_error(const Case& c) {
  const std::vector<std::uint8_t> bytes = bytes_of(c.one("bytes_hex"), "bytes_hex");
  const TxDecodeResult result = zk::deserialize_transaction(bytes.data(), bytes.size());
  return {
      {"error", zk::to_string(result.error)},
      {"consumed", std::to_string(result.consumed)},
  };
}

Produced op_compact(const Case& c) {
  const std::uint64_t bits = parse_bits(c.one("bits"));
  if (bits > 0xffff'ffffull) {
    fail("bits: does not fit in 32 bits");
  }
  const Uint256 target = Uint256::from_compact(static_cast<std::uint32_t>(bits));
  const auto be = target.to_be_bytes();
  return {
      {"target_be_hex", zk::to_hex(be.data(), be.size())},
      {"is_zero", bool_text(target.is_zero())},
      {"roundtrip_bits", std::to_string(target.to_compact())},
  };
}

Produced op_script_push_data(const Case& c) {
  const std::vector<std::uint8_t> fill = bytes_of(c.one("fill"), "fill");
  if (fill.size() != 1) {
    fail("fill: expected one byte, got " + std::to_string(fill.size()));
  }
  Produced produced;
  for (const std::string& text : c.all("len")) {
    const std::uint32_t length = parse_u32(text, "len");
    const std::vector<std::uint8_t> data(length, fill.front());
    std::vector<std::uint8_t> script;
    zk::push_data(data.data(), data.size(), script);
    produced["len_" + std::to_string(length)] = hex_of(script);
  }
  if (produced.empty()) {
    fail("script_push_data: no len given");
  }
  return produced;
}

Produced op_p2pkh_script_pubkey(const Case& c) {
  const std::vector<std::uint8_t> raw = bytes_of(c.one("pubkey_hash_hex"), "pubkey_hash_hex");
  if (raw.size() != Hash160::kWidth) {
    fail("pubkey_hash_hex: expected 20 bytes, got " + std::to_string(raw.size()));
  }
  Hash160 pkhash{};
  std::copy(raw.begin(), raw.end(), pkhash.bytes.begin());
  const std::vector<std::uint8_t> script = zk::p2pkh_script_pubkey(pkhash);
  return {{"script_hex", hex_of(script)}, {"length", std::to_string(script.size())}};
}

Produced op_p2pkh_script_sig(const Case& c) {
  const std::vector<std::uint8_t> signature = bytes_of(c.one("signature_hex"), "signature_hex");
  const std::vector<std::uint8_t> pubkey = bytes_of(c.one("pubkey_sec1_hex"), "pubkey_sec1_hex");
  const std::vector<std::uint8_t> script =
      zk::p2pkh_script_sig(signature.data(), signature.size(), pubkey.data(), pubkey.size());
  return {{"script_hex", hex_of(script)}, {"length", std::to_string(script.size())}};
}

// The accept/reject checkers are stubs that pin the interpreter's control flow
// for cases that must not produce a signature verdict. The only corpus case
// that checks a real signature is p2pkh_spend below, which runs the vendored
// backend behind the production seam.
struct AcceptAllChecker final : zk::SigChecker {
  bool check_signature(const std::uint8_t* /*signature*/, std::size_t /*signature_size*/,
                       const std::uint8_t* /*public_key*/,
                       std::size_t /*public_key_size*/) const override {
    return true;
  }
};

struct RejectAllChecker final : zk::SigChecker {
  bool check_signature(const std::uint8_t* /*signature*/, std::size_t /*signature_size*/,
                       const std::uint8_t* /*public_key*/,
                       std::size_t /*public_key_size*/) const override {
    return false;
  }
};

Produced op_script_verify(const Case& c) {
  const std::vector<std::uint8_t> script_sig = bytes_of(c.one("script_sig_hex"), "script_sig_hex");
  const std::vector<std::uint8_t> script_pubkey =
      bytes_of(c.one("script_pubkey_hex"), "script_pubkey_hex");
  const std::string checker = c.one("checker");
  const AcceptAllChecker accept;
  const RejectAllChecker reject;
  const zk::SigChecker* selected = nullptr;
  if (checker == "accept") {
    selected = &accept;
  } else if (checker == "reject") {
    selected = &reject;
  } else {
    fail("checker: expected accept or reject: " + checker);
  }
  const zk::ScriptResult result = zk::verify(
      script_sig.data(), script_sig.size(), script_pubkey.data(), script_pubkey.size(), *selected);
  return {{"accepted", bool_text(static_cast<bool>(result))},
          {"error", zk::to_string(result.error)},
          {"opcode", std::to_string(result.opcode)}};
}

// A real signature verdict: the corpus spend case runs the actual vendored
// backend through `TxSigChecker` — the first accepted signature in the corpus.
Produced op_p2pkh_spend(const Case& c) {
  const Transaction tx = tx_of(c.one("tx_hex"), "tx_hex");
  const std::uint64_t input_index = parse_u64(c.one("input_index"), "input_index");
  const std::vector<std::uint8_t> script_code =
      bytes_of(c.one("script_code_hex"), "script_code_hex");
  const std::vector<std::uint8_t> script_pubkey =
      bytes_of(c.one("script_pubkey_hex"), "script_pubkey_hex");
  const std::uint32_t chain_id = parse_u32(c.one("chain_id"), "chain_id");
  if (input_index >= tx.inputs.size()) {
    fail("input_index: out of range");
  }
  const zk::Secp256k1Verifier verifier;
  const zk::TxSigChecker checker(tx, static_cast<std::size_t>(input_index), script_code.data(),
                                 script_code.size(), zk::ChainId{chain_id}, &verifier);
  const std::vector<std::uint8_t>& script_sig = tx.inputs[input_index].script_sig;
  const zk::ScriptResult result = zk::verify(script_sig.data(), script_sig.size(),
                                             script_pubkey.data(), script_pubkey.size(),
                                             checker);
  return {{"accepted", bool_text(static_cast<bool>(result))},
          {"error", zk::to_string(result.error)}};
}

Produced op_sighash(const Case& c) {
  const Transaction tx = tx_of(c.one("tx_hex"), "tx_hex");
  const std::uint64_t input_index = parse_u64(c.one("input_index"), "input_index");
  const std::vector<std::uint8_t> script_code =
      bytes_of(c.one("script_code_hex"), "script_code_hex");
  const std::uint32_t chain_id = parse_u32(c.one("chain_id"), "chain_id");
  const std::uint32_t sighash_type = parse_u32(c.one("sighash_type"), "sighash_type");
  const std::optional<zk::SigHash> sighash =
      zk::signature_hash(tx, static_cast<std::size_t>(input_index), script_code.data(),
                         script_code.size(), zk::ChainId{chain_id}, sighash_type);
  if (!sighash.has_value()) {
    return {{"digest", "null"}};
  }
  return {{"digest", sighash->digest.to_hex().str()},
          {"digest_display_hex", sighash->digest.to_display_hex().str()},
          {"preimage_hex", hex_of(sighash->preimage)}};
}

Produced op_sighash_distinct(const Case& c) {
  const Transaction tx = tx_of(c.one("tx_hex"), "tx_hex");
  const std::vector<std::uint8_t> script_code =
      bytes_of(c.one("script_code_hex"), "script_code_hex");
  Produced produced;
  for (const std::string& spec : c.all("pair")) {
    const std::vector<std::string> parts = split(spec, '|');
    if (parts.size() != 7) {
      fail("IN pair: expected name|chain_a|index_a|type_a|chain_b|index_b|type_b: " + spec);
    }
    const auto digest_of = [&](const std::string& chain, const std::string& index,
                               const std::string& type) {
      const std::optional<zk::SigHash> sighash = zk::signature_hash(
          tx, static_cast<std::size_t>(parse_u64(index, "pair.index")), script_code.data(),
          script_code.size(), zk::ChainId{parse_u32(chain, "pair.chain")},
          parse_u32(type, "pair.type"));
      if (!sighash.has_value()) {
        fail("pair: index out of range: " + index);
      }
      return sighash->digest;
    };
    const Hash256 left = digest_of(parts[1], parts[2], parts[3]);
    const Hash256 right = digest_of(parts[4], parts[5], parts[6]);
    produced[parts[0]] = bool_text(left == right);
  }
  if (produced.empty()) {
    fail("sighash_distinct: no pair given");
  }
  return produced;
}

// --- P3: difficulty policy ---------------------------------------------------

Produced op_difficulty_params(const Case& /*c*/) {
  const zk::DifficultyParams& params = zk::kDifficultyParams;
  return {
      {"target_spacing_seconds", std::to_string(params.target_spacing_seconds)},
      {"retarget_interval", std::to_string(params.retarget_interval)},
      {"max_adjustment_factor", std::to_string(params.max_adjustment_factor)},
      {"pow_limit_bits", std::to_string(params.pow_limit_bits)},
      {"target_window_seconds", std::to_string(params.target_window_seconds())},
  };
}

Produced op_difficulty_validate_bits(const Case& c) {
  zk::DifficultyParams params = zk::kDifficultyParams;
  params.pow_limit_bits = parse_u32(c.one("pow_limit_bits"), "pow_limit_bits");
  const std::uint32_t bits = parse_bits_u32(c.one("bits"));
  const zk::DifficultyError error = zk::validate_bits(bits, params);
  return {
      {"bits", std::to_string(bits)},
      {"error_kind", zk::difficulty_error_kind_name(error.kind)},
      {"ok", bool_text(error.ok())},
  };
}

Produced op_difficulty_hash_meets_target(const Case& c) {
  const Uint256 target = zk::block_target(parse_bits_u32(c.one("bits")));
  std::array<std::uint8_t, Hash256::kWidth> all_ones{};
  all_ones.fill(0xff);
  return {
      {"all_ones_hash", bool_text(zk::hash_meets_target(Hash256(all_ones), target))},
      {"equal_to_target",
       bool_text(zk::hash_meets_target(Hash256(target.to_be_bytes()), target))},
      {"zero_hash", bool_text(zk::hash_meets_target(Hash256::zero(), target))},
  };
}

Produced op_difficulty_required_work(const Case& c) {
  const std::optional<Uint256> work =
      zk::required_work(zk::block_target(parse_bits_u32(c.one("bits"))));
  if (!work.has_value()) {
    // F-7: the reference divides by zero at Uint256::MAX. No corpus case reaches
    // it; naming the trap keeps the fixture honest if one ever does.
    return {{"work_be_hex", "trap"}};
  }
  const auto be = work->to_be_bytes();
  return {{"work_be_hex", zk::to_hex(be.data(), be.size())}};
}

Produced op_difficulty_next(const Case& c) {
  const std::uint32_t prev_bits = parse_bits_u32(c.one("prev_bits"));
  const std::uint64_t window = parse_u64(c.one("actual_window_seconds"), "actual_window_seconds");
  const zk::RetargetResult result =
      zk::next_difficulty_target(prev_bits, window, zk::kDifficultyParams);
  const auto be = result.target.to_be_bytes();
  return {
      {"next_bits", std::to_string(result.bits)},
      {"next_target_be_hex", zk::to_hex(be.data(), be.size())},
  };
}

// Reads the nine header fields the P3.1A corpus publishes for a header. The
// prefix keeps the two operand shapes honest: `header_preimage` names the
// fields bare, while `header_identity` nests them under `header.` so the
// validator's own `expected_*` inputs can never be confused with the header
// bytes being validated.
zk::BlockHeader header_of(const Case& c, const std::string& prefix) {
  zk::BlockHeader header{};
  header.version = parse_u32(c.one(prefix + "version"), "version");
  header.chain = parse_u32(c.one(prefix + "chain"), "chain");
  header.height = parse_u64(c.one(prefix + "height"), "height");
  header.previous_hash = hash256_of(c.one(prefix + "previous_hash_hex"), "previous_hash_hex");
  header.merkle_root = hash256_of(c.one(prefix + "merkle_root_hex"), "merkle_root_hex");
  header.timestamp = parse_u64(c.one(prefix + "timestamp"), "timestamp");
  header.difficulty_bits = parse_u32(c.one(prefix + "difficulty_bits"), "difficulty_bits");
  const std::string engine_text = c.one(prefix + "engine_id");
  const std::uint64_t engine = parse_u64(engine_text, "engine_id");
  if (engine > 0xffull) {
    fail("engine_id: does not fit in 8 bits: " + engine_text);
  }
  header.engine_id = static_cast<std::uint8_t>(engine);
  // Read, but by nothing that writes a byte: the reference's engine appends the
  // nonce after the preimage, so the fixture can only pin its exclusion by
  // publishing a second header that differs in the nonce alone.
  header.nonce = parse_u64(c.one(prefix + "nonce"), "nonce");
  return header;
}

Produced op_header_preimage(const Case& c) {
  const std::array<std::uint8_t, zk::kHeaderPreimageSize> preimage =
      zk::header_preimage(header_of(c, ""));
  return {
      {"preimage_hex", zk::to_hex(preimage.data(), preimage.size())},
      {"preimage_len", std::to_string(preimage.size())},
      {"tag_hex", zk::to_hex(zk::kHeaderTag, zk::kHeaderTagSize)},
  };
}

Produced op_header_identity(const Case& c) {
  const zk::BlockHeader header = header_of(c, "header.");
  const std::uint32_t expected_chain = parse_u32(c.one("expected_chain"), "expected_chain");
  const std::uint64_t expected_height = parse_u64(c.one("expected_height"), "expected_height");
  const zk::BlockIdentityError error =
      zk::validate_header_identity(header, expected_chain, expected_height);
  Produced produced{
      {"accepted", bool_text(error.ok())},
      {"error_kind", zk::block_error_kind_name(error.kind)},
      {"error_payload_present", bool_text(error.has_payload())},
  };
  // `Ok` carries no payload and the reference publishes null for it, so the
  // runner withholds these keys instead of inventing a zero payload. A fixture
  // that expected one then fails with "produced no value for", not a false
  // equality.
  if (error.kind == zk::BlockErrorKind::kWrongChain) {
    produced["error_payload_expected"] = std::to_string(error.expected_chain);
    produced["error_payload_found"] = std::to_string(error.found_chain);
  } else if (error.kind == zk::BlockErrorKind::kBadHeight) {
    produced["error_payload_expected"] = std::to_string(error.expected_height);
    produced["error_payload_found"] = std::to_string(error.found_height);
  }
  return produced;
}

// The leaf-level Merkle root (C-5). One `IN leaf=<internal hex>` per leaf, in
// corpus order; a case with no leaf lines is the empty tree.
Produced op_merkle_root(const Case& c) {
  const std::vector<std::string> hexes = c.all("leaf");
  std::vector<Hash256> leaves;
  leaves.reserve(hexes.size());
  for (const std::string& hex : hexes) {
    // `hash256_of` insists on exactly 32 bytes, so a short or long leaf fails the
    // case as a malformed fixture instead of being padded or truncated into a
    // plausible-looking root.
    leaves.push_back(hash256_of(hex, "leaf"));
  }
  // For an empty corpus case `data()` is null and `size()` is 0, which is the one
  // combination merkle.h documents as meaningful; the empty branch returns before
  // the buffer is read.
  const Hash256 root = zk::merkle_root(leaves.data(), leaves.size());
  return {
      {"internal_hex", root.to_hex().str()},
      {"display_hex", root.to_display_hex().str()},
      {"root_len", std::to_string(root.bytes.size())},
      // Echoed so the wrapper can prove the runner consumed every leaf line it
      // emitted rather than quietly dropping one.
      {"leaf_count", std::to_string(leaves.size())},
  };
}

// The transaction-level composition, the C++ shape of
// `Block::compute_merkle_root`. One `IN tx_hex=<canonical bytes>` per
// transaction, in corpus order; a case with no tx line is the empty list. Every
// transaction is decoded, so what the kernel hashes is the id of the object its
// own codec produced — the encoding rule C-1 and the id rule C-2 are both on the
// path, not assumed by the fixture.
Produced op_merkle_root_from_txs(const Case& c) {
  const std::vector<std::string> hexes = c.all("tx_hex");
  std::vector<Transaction> txs;
  txs.reserve(hexes.size());
  for (const std::string& hex : hexes) {
    // `tx_of` fails the case on a bad decode or on trailing bytes, so an input
    // that is not exactly one canonical transaction cannot be quietly dropped or
    // padded into a plausible-looking root.
    txs.push_back(tx_of(hex, "tx_hex"));
  }

  // The same call shape as op_merkle_root above: an empty list is a null pointer
  // with a zero count, the one combination merkle.h documents as meaningful.
  const Hash256 root = zk::merkle_root_from_transactions(txs.data(), txs.size());

  // The leaf ids, concatenated in list order. Echoing them lets the wrapper check
  // the id-to-leaf mapping instead of only the digest at the top of the tree, and
  // its width is what proves one leaf per transaction reached the tree.
  std::string leaves;
  for (const Transaction& tx : txs) {
    leaves += txid_internal(tx);
  }

  return {
      {"internal_hex", root.to_hex().str()},
      {"display_hex", root.to_display_hex().str()},
      {"root_len", std::to_string(root.bytes.size())},
      {"tx_count", std::to_string(txs.size())},
      {"leaf_txids_hex", leaves},
  };
}

Produced execute(const Case& c) {
  if (c.op == "sha256_utf8") return op_sha256_utf8(c);
  if (c.op == "sha256d_utf8") return op_sha256d_utf8(c);
  if (c.op == "hash160_sec1") return op_hash160_sec1(c);
  if (c.op == "display_reversal") return op_display_reversal(c);
  if (c.op == "varint_encode") return op_varint_encode(c);
  if (c.op == "tx_build") return op_tx_build(c);
  if (c.op == "tx_roundtrip") return op_tx_roundtrip(c);
  if (c.op == "tx_decode_error") return op_tx_decode_error(c);
  if (c.op == "compact") return op_compact(c);
    if (c.op == "script_push_data") return op_script_push_data(c);
    if (c.op == "p2pkh_script_pubkey") return op_p2pkh_script_pubkey(c);
    if (c.op == "p2pkh_script_sig") return op_p2pkh_script_sig(c);
    if (c.op == "script_verify") return op_script_verify(c);
    if (c.op == "p2pkh_spend") return op_p2pkh_spend(c);
    if (c.op == "sighash") return op_sighash(c);
    if (c.op == "sighash_distinct") return op_sighash_distinct(c);
    if (c.op == "difficulty_params") return op_difficulty_params(c);
    if (c.op == "difficulty_validate_bits") return op_difficulty_validate_bits(c);
    if (c.op == "difficulty_hash_meets_target") return op_difficulty_hash_meets_target(c);
    if (c.op == "difficulty_required_work") return op_difficulty_required_work(c);
    if (c.op == "difficulty_next") return op_difficulty_next(c);
  if (c.op == "header_preimage") return op_header_preimage(c);
  if (c.op == "header_identity") return op_header_identity(c);
  if (c.op == "merkle_root") return op_merkle_root(c);
  if (c.op == "merkle_root_from_txs") return op_merkle_root_from_txs(c);
  fail("unknown OP: " + c.op);
}

void compare(const Case& c, const Produced& produced) {
  if (c.outputs.empty()) {
    fail("fixture declares no expected values");
  }
  for (const auto& [key, expected] : c.outputs) {
    const auto it = produced.find(key);
    if (it == produced.end()) {
      fail("runner produced no value for '" + key + "'");
    }
    if (it->second != expected) {
      fail("'" + key + "': expected " + expected + ", got " + it->second);
    }
  }
}

// --- fixture parsing --------------------------------------------------------

struct FixtureError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

std::vector<Case> parse_fixture(std::istream& in) {
  std::vector<Case> cases;
  std::string line;
  int line_number = 0;
  bool open = false;
  Case current;

  while (std::getline(in, line)) {
    ++line_number;
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto where = "line " + std::to_string(line_number) + ": ";
    const std::size_t space = line.find(' ');
    const std::string tag = line.substr(0, space);
    const std::string rest = (space == std::string::npos) ? "" : line.substr(space + 1);

    if (tag == "META") {
      continue;
    }
    if (tag == "CASE") {
      if (open) {
        throw FixtureError(where + "CASE inside CASE");
      }
      current = Case{};
      current.id = rest;
      if (rest.empty()) {
        throw FixtureError(where + "CASE without an id");
      }
      open = true;
      continue;
    }
    if (!open) {
      throw FixtureError(where + tag + " outside a CASE");
    }
    if (tag == "OP") {
      current.op = rest;
    } else if (tag == "IN" || tag == "OUT") {
      const std::size_t equals = rest.find('=');
      if (equals == std::string::npos) {
        throw FixtureError(where + tag + " without '='");
      }
      const std::string key = rest.substr(0, equals);
      const std::string value = rest.substr(equals + 1);
      if (key.empty()) {
        throw FixtureError(where + tag + " with an empty key");
      }
      if (tag == "IN") {
        current.inputs.emplace_back(key, value);
      } else {
        current.outputs.emplace_back(key, value);
      }
    } else if (tag == "END") {
      if (current.op.empty()) {
        throw FixtureError(where + "CASE without an OP");
      }
      cases.push_back(current);
      open = false;
    } else {
      throw FixtureError(where + "unknown directive: " + tag);
    }
  }

  if (open) {
    throw FixtureError("fixture ends inside a CASE");
  }
  return cases;
}

int run(const std::string& path) {
  std::ifstream input(path);
  if (!input) {
    std::cerr << "cannot open fixture: " << path << '\n';
    return 2;
  }

  std::vector<Case> cases;
  try {
    cases = parse_fixture(input);
  } catch (const FixtureError& error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 2;
  }

  int failures = 0;
  for (const Case& test : cases) {
    try {
      compare(test, execute(test));
      std::cout << "RESULT " << test.id << " ok\n";
    } catch (const CaseError& error) {
      ++failures;
      std::cout << "RESULT " << test.id << " fail " << one_line(error.what()) << '\n';
    }
  }
  std::cout << "SUMMARY cases=" << cases.size() << " failures=" << failures << '\n';
  return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: kernel_conformance <fixture>\n";
    return 2;
  }
  try {
    return run(argv[1]);
  } catch (const std::exception& error) {
    std::cerr << "fatal: " << error.what() << '\n';
    return 2;
  }
}
