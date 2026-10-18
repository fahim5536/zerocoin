#include "test_framework.h"

#include "zerocoin/hex.h"
#include "zerocoin/transaction.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {

using zk::Hash256;
using zk::Outpoint;
using zk::Transaction;
using zk::TxDecodeError;
using zk::TxDecodeResult;
using zk::TxIn;
using zk::TxOut;

// Zeros and arbitrary scripts, straight from test/vectors/encoding/transaction.json.
constexpr const char* kSampleHex =
    "010000000111111111111111111111111111111111111111111111111111111111111111110000000003010203"
    "ffffffff0100f2052a010000000376a91400000000";
constexpr const char* kCoinbase147Hex =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
    "0c029300085a65726f436f696effffffff0100f2052a010000001976a914751e76e8199196d454941c45"
    "d1b3a323f1433bd688ac00000000";

Hash256 hash_of_bytes(std::uint8_t byte) {
  Hash256 hash{};
  for (std::uint8_t& slot : hash.bytes) {
    slot = byte;
  }
  return hash;
}

Transaction sample_transaction() {
  Transaction tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{Outpoint{hash_of_bytes(0x11), 0}, {0x01, 0x02, 0x03}, 0xffff'ffff});
  tx.outputs.push_back(TxOut{5'000'000'000ull, {0x76, 0xa9, 0x14}});
  tx.lock_time = 0;
  return tx;
}

Transaction payment_transaction() {
  Transaction tx;
  tx.version = 1;
  tx.inputs.push_back(TxIn{Outpoint{hash_of_bytes(0x22), 1}, {}, 0xffff'fffe});
  tx.inputs.push_back(TxIn{Outpoint{hash_of_bytes(0x33), 7}, {}, 0});
  tx.outputs.push_back(TxOut{1, {}});
  tx.outputs.push_back(TxOut{2'100'000'000'000'000ull, {0x6a}});
  tx.lock_time = 500'000;
  return tx;
}

std::string serialize_hex(const Transaction& tx) {
  const std::vector<std::uint8_t> bytes = tx.serialize();
  return zk::to_hex(bytes.data(), bytes.size());
}

TxDecodeResult decode_hex(const std::string& text) {
  const auto bytes = zk::from_hex(text);
  ZK_CHECK(bytes.has_value());
  return zk::deserialize_transaction(bytes->data(), bytes->size());
}

std::string bytes_hex(const std::vector<std::uint8_t>& bytes) {
  return zk::to_hex(bytes.data(), bytes.size());
}

}  // namespace

ZK_TEST(transaction_serializes_like_the_corpus) {
  ZK_CHECK(serialize_hex(sample_transaction()) == kSampleHex);
  ZK_CHECK(serialize_hex(payment_transaction()) ==
           "010000000222222222222222222222222222222222222222222222222222222222222222220100000000"
           "feffffff3333333333333333333333333333333333333333333333333333333333333333070000000000"
           "000000020100000000000000000040075af0750700016a20a10700");
  ZK_CHECK(serialize_hex(payment_transaction()).size() == 2 * 111);
}

ZK_TEST(transaction_empty_serializes_to_ten_bytes) {
  Transaction tx;
  tx.version = 2;
  ZK_CHECK(serialize_hex(tx) == "02000000000000000000");
  ZK_CHECK(tx.serialize().size() == 10);
  ZK_CHECK(!tx.is_coinbase());
  ZK_CHECK(tx.output_value() == 0);
}

ZK_TEST(transaction_txid_matches_the_corpus) {
  const Transaction tx = sample_transaction();
  ZK_CHECK(tx.txid().to_hex().str() ==
           "f081567dbebd014d2de472cd9f243eda4e287856b54065644182eaea67befc81");
  ZK_CHECK(tx.txid().to_display_hex().str() ==
           "81fcbe67eaea8241646540b55678284eda3e249fcd72e42d4d01bdbe7d5681f0");
}

ZK_TEST(transaction_txid_commits_to_every_field) {
  const Hash256 baseline = sample_transaction().txid();

  Transaction version = sample_transaction();
  version.version = 3;
  ZK_CHECK(version.txid() != baseline);

  Transaction sequence = sample_transaction();
  sequence.inputs[0].sequence = 0;
  ZK_CHECK(sequence.txid() != baseline);

  Transaction value = sample_transaction();
  value.outputs[0].value = 4'999'999'999ull;
  ZK_CHECK(value.txid() != baseline);

  Transaction lock_time = sample_transaction();
  lock_time.lock_time = 1;
  ZK_CHECK(lock_time.txid() != baseline);
}

ZK_TEST(transaction_round_trips_through_the_decoder) {
  const Transaction original = sample_transaction();
  const TxDecodeResult result = decode_hex(kSampleHex);
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.error == TxDecodeError::None);
  ZK_CHECK(result.tx == original);
  ZK_CHECK(result.consumed == original.serialize().size());
  ZK_CHECK(serialize_hex(result.tx) == kSampleHex);
}

ZK_TEST(transaction_payment_round_trips_with_two_inputs) {
  const Transaction original = payment_transaction();
  const TxDecodeResult result = decode_hex(serialize_hex(original));
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.tx == original);
  ZK_CHECK(result.tx.inputs.size() == 2);
  ZK_CHECK(result.tx.inputs[0].previous_output.vout == 1);
  ZK_CHECK(result.tx.inputs[1].previous_output.vout == 7);
  ZK_CHECK(result.tx.output_value() == 2'100'000'000'000'001ull);
}

ZK_TEST(transaction_coinbase_147_round_trips) {
  const TxDecodeResult result = decode_hex(kCoinbase147Hex);
  ZK_CHECK(static_cast<bool>(result));

  const Transaction& tx = result.tx;
  ZK_CHECK(tx.is_coinbase());
  ZK_CHECK(tx.inputs.size() == 1);
  ZK_CHECK(tx.inputs[0].previous_output.is_null());
  ZK_CHECK(tx.inputs[0].script_sig ==
           std::vector<std::uint8_t>({0x02, 0x93, 0x00, 0x08, 0x5a, 0x65,
                                      0x72, 0x6f, 0x43, 0x6f, 0x69, 0x6e}));
  ZK_CHECK(tx.outputs.size() == 1);
  ZK_CHECK(tx.outputs[0].value == 5'000'000'000ull);
  ZK_CHECK(bytes_hex(tx.outputs[0].script_pubkey) ==
           "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac");
  ZK_CHECK(tx.output_value() == 5'000'000'000ull);
  ZK_CHECK(tx.txid().to_hex().str() ==
           "a903fa7dd9a52d6d76d03818b99314ebcf3dbbada7d89fb5b8e870494a68da94");
  ZK_CHECK(tx.txid().to_display_hex().str() ==
           "94da684a4970e8b8b59fd8a7adbb3dcfeb1493b91838d0766d2da5d97dfa03a9");
  ZK_CHECK(serialize_hex(tx) == kCoinbase147Hex);
}

ZK_TEST(transaction_coinbase_needs_the_null_outpoint) {
  Transaction tx = sample_transaction();
  ZK_CHECK(!tx.is_coinbase());

  tx.inputs[0].previous_output = Outpoint::null();
  ZK_CHECK(tx.is_coinbase());

  tx.inputs[0].previous_output.vout = 0;
  ZK_CHECK(!tx.is_coinbase());

  tx.inputs[0].previous_output = Outpoint::null();
  tx.inputs.push_back(TxIn{Outpoint::null(), {}, 0});
  ZK_CHECK(!tx.is_coinbase());

  Transaction empty;
  ZK_CHECK(!empty.is_coinbase());
}

ZK_TEST(transaction_outpoint_null_is_all_zero_and_all_ones) {
  ZK_CHECK(Outpoint::null().txid.is_zero());
  ZK_CHECK(Outpoint::null().vout == 0xffff'ffff);
  ZK_CHECK(Outpoint::null().is_null());

  Outpoint other = Outpoint::null();
  other.txid = hash_of_bytes(0x01);
  ZK_CHECK(!other.is_null());

  Outpoint zero_vout = Outpoint::null();
  zero_vout.vout = 0;
  ZK_CHECK(!zero_vout.is_null());
}

ZK_TEST(transaction_output_value_adds_up) {
  Transaction tx;
  tx.outputs.push_back(TxOut{1, {}});
  tx.outputs.push_back(TxOut{2, {}});
  tx.outputs.push_back(TxOut{3, {}});
  ZK_CHECK(tx.output_value() == 6);

  Transaction maxed;
  maxed.outputs.push_back(TxOut{UINT64_MAX, {}});
  ZK_CHECK(maxed.output_value() == UINT64_MAX);

  maxed.outputs.push_back(TxOut{1, {}});
  ZK_CHECK(!maxed.output_value().has_value());
}

ZK_TEST(transaction_decoder_refuses_non_minimal_counts) {
  const TxDecodeResult result = decode_hex("01000000fd0100");
  ZK_CHECK(!static_cast<bool>(result));
  ZK_CHECK(result.error == TxDecodeError::NonMinimalVarInt);
  ZK_CHECK(zk::to_string(result.error) == std::string("NonMinimalVarInt"));
}

ZK_TEST(transaction_decoder_reports_truncation) {
  ZK_CHECK(decode_hex("").error == TxDecodeError::Truncated);
  ZK_CHECK(decode_hex("01000000").error == TxDecodeError::Truncated);
  ZK_CHECK(decode_hex("0100000001" + std::string(62, '0')).error == TxDecodeError::Truncated);
  const std::string sample{kSampleHex};
  ZK_CHECK(decode_hex(sample.substr(0, sample.size() - 2)).error == TxDecodeError::Truncated);
}

ZK_TEST(transaction_decoder_bounds_the_input_count) {
  // 0x2711 == 10001 inputs, one past the limit.
  const TxDecodeResult result = decode_hex("01000000fd1127");
  ZK_CHECK(result.error == TxDecodeError::TooManyInputs);
  ZK_CHECK(zk::to_string(result.error) == std::string("TooManyInputs"));
}

ZK_TEST(transaction_decoder_bounds_the_output_count) {
  const TxDecodeResult result = decode_hex("0100000000fd1127");
  ZK_CHECK(result.error == TxDecodeError::TooManyOutputs);
  ZK_CHECK(zk::to_string(result.error) == std::string("TooManyOutputs"));
}

ZK_TEST(transaction_decoder_bounds_the_script_length) {
  const std::string header =
      "01000000" "01" + std::string(64, '0') + "00000000";
  // 0x0f4241 == 1000001 bytes, one past kMaxTxBytes.
  const TxDecodeResult too_large = decode_hex(header + "fe41420f00");
  ZK_CHECK(too_large.error == TxDecodeError::ScriptTooLarge);
  ZK_CHECK(zk::to_string(too_large.error) == std::string("ScriptTooLarge"));

  // Exactly kMaxTxBytes is allowed by the bound, so the decoder runs out of
  // bytes instead of rejecting the length.
  const TxDecodeResult at_bound = decode_hex(header + "fe40420f00");
  ZK_CHECK(at_bound.error == TxDecodeError::Truncated);
}

ZK_TEST(transaction_decoder_leaves_trailing_bytes_alone) {
  // Finding F-2: the reference does not require the input to be exhausted.
  const TxDecodeResult result = decode_hex(std::string(kSampleHex) + "deadbeef");
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.consumed == (std::string(kSampleHex).size() / 2));
  ZK_CHECK(serialize_hex(result.tx) == kSampleHex);
}

ZK_TEST(transaction_uses_minimal_varints_for_scripts) {
  const std::vector<std::uint8_t> bytes = sample_transaction().serialize();
  // version(4) + count(1) + outpoint(36) + script length(1) + script(3) + sequence(4)
  ZK_CHECK(bytes.size() == 66);
  ZK_CHECK(bytes[4] == 0x01);
  ZK_CHECK(bytes[41] == 0x03);
}
