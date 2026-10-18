#include "test_framework.h"

#include "zerocoin/hex.h"
#include "zerocoin/script.h"
#include "zerocoin/sighash.h"
#include "zerocoin/transaction.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

using zk::ChainId;
using zk::Hash256;
using zk::SigHash;
using zk::Transaction;

// The shared transaction pinned by test/vectors/ledger/sighash.json: two inputs
// with empty scriptSigs and two outputs.
constexpr const char* kTxHex =
    "01000000022222222222222222222222222222222222222222222222222222222222222222010000"
    "0000feffffff33333333333333333333333333333333333333333333333333333333333333330700"
    "00000000000000020100000000000000000040075af0750700016a20a10700";

constexpr const char* kScriptCodeHex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";

// Chain ids from zerocoin/src/params.rs: regtest 0x5A524F00, mainnet 0x5A524F01.
constexpr std::uint32_t kRegtest = 1515343616;
constexpr std::uint32_t kMainnet = 1515343617;

// The P2PKH spend pinned by test/vectors/ledger/script.json: 71 DER bytes plus
// the trailing SIGHASH_ALL byte.
constexpr const char* kSignatureHex =
    "304502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "0220199b56aa206063c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f01";
constexpr const char* kPubkeySec1Hex =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
constexpr const char* kScriptSigHex =
    "48304502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "0220199b56aa206063c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f"
    "01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
constexpr const char* kScriptPubkeyHex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";

std::vector<std::uint8_t> bytes_of(const std::string& hex) {
  auto parsed = zk::from_hex(hex);
  ZK_CHECK(parsed.has_value());
  return *parsed;
}

std::string hex_of(const std::vector<std::uint8_t>& bytes) {
  return zk::to_hex(bytes.data(), bytes.size());
}

Transaction corpus_tx() {
  const std::vector<std::uint8_t> bytes = bytes_of(kTxHex);
  ZK_CHECK(bytes.size() == 111);
  const zk::TxDecodeResult result = zk::deserialize_transaction(bytes.data(), bytes.size());
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.consumed == bytes.size());
  ZK_CHECK(result.tx.inputs.size() == 2);
  ZK_CHECK(result.tx.outputs.size() == 2);
  return result.tx;
}

std::vector<std::uint8_t> script_code() { return bytes_of(kScriptCodeHex); }

std::optional<SigHash> hash_at(const Transaction& tx, std::size_t input_index,
                               std::uint32_t chain_id, std::uint32_t sighash_type) {
  const std::vector<std::uint8_t> code = script_code();
  return zk::signature_hash(tx, input_index, code.data(), code.size(), ChainId{chain_id},
                            sighash_type);
}

/// Records every call, so a test can prove the checker's gates run before the
/// curve backend (or that the backend is never reached at all).
struct RecordingVerifier final : zk::SigVerifier {
  mutable std::size_t calls = 0;
  mutable std::vector<std::uint8_t> last_der;
  bool accept = true;

  bool verify(const Hash256& /*digest*/, const std::uint8_t* der, std::size_t der_size,
              const std::uint8_t* /*public_key*/,
              std::size_t /*public_key_size*/) const override {
    ++calls;
    last_der.assign(der, der + der_size);
    return accept;
  }
};

}  // namespace

ZK_TEST(sighash_corpus_vectors_match_the_preimage_and_digest) {
  struct Vector {
    std::size_t input_index;
    std::uint32_t chain_id;
    std::uint32_t sighash_type;
    const char* preimage_hex;
    const char* digest_internal_hex;
  };
  // The four distinct rule/oddity vectors. `regtest_index_repeat` duplicates
  // `regtest_index_0` by design and is replayed by the conformance runner.
  const Vector vectors[] = {
      {0,
       kRegtest,
       1,
       "5a524f2f736967686173682f763100004f525a0100000002222222222222222222222222222222222222222222"
       "2222222222222222222222010000001976a914751e76e8199196d454941c45d1b3a323f1433bd688acfeffffff"
       "333333333333333333333333333333333333333333333333333333333333333307000000000000000002010000"
       "0000000000000040075af0750700016a20a1070001000000",
       "e0e7ce176c2aa8077378299f682baec23e02abc289b51fa1895b7cde9ce6a237"},
      {1,
       kRegtest,
       1,
       "5a524f2f736967686173682f763100004f525a0100000002222222222222222222222222222222222222222222"
       "22222222222222222222220100000000feffffff33333333333333333333333333333333333333333333333333"
       "33333333333333070000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac0000000002010000"
       "0000000000000040075af0750700016a20a1070001000000",
       "c821a960aa95273388ff62bdce33e42eabb791935a402f009a3985423e448361"},
      {0,
       kMainnet,
       1,
       "5a524f2f736967686173682f763100014f525a0100000002222222222222222222222222222222222222222222"
       "2222222222222222222222010000001976a914751e76e8199196d454941c45d1b3a323f1433bd688acfeffffff"
       "333333333333333333333333333333333333333333333333333333333333333307000000000000000002010000"
       "0000000000000040075af0750700016a20a1070001000000",
       "e364172d5128d013b7b2504e886c8977b7241ceb32212280fd1f92b6a9106738"},
      {0,
       kRegtest,
       2,
       "5a524f2f736967686173682f763100004f525a0100000002222222222222222222222222222222222222222222"
       "2222222222222222222222010000001976a914751e76e8199196d454941c45d1b3a323f1433bd688acfeffffff"
       "333333333333333333333333333333333333333333333333333333333333333307000000000000000002010000"
       "0000000000000040075af0750700016a20a1070002000000",
       "845fee9ab714f4103d808378e10173040ebccb527cfe8de0cbdb9cab181efb9d"},
  };

  const Transaction tx = corpus_tx();
  for (const Vector& vector : vectors) {
    const std::optional<SigHash> sighash =
        hash_at(tx, vector.input_index, vector.chain_id, vector.sighash_type);
    ZK_CHECK(sighash.has_value());
    ZK_CHECK(hex_of(sighash->preimage) == vector.preimage_hex);
    ZK_CHECK(sighash->digest.to_hex().str() == vector.digest_internal_hex);
    ZK_CHECK(sighash->preimage.size() == 159);
  }
}

ZK_TEST(sighash_out_of_range_index_has_no_digest) {
  const Transaction tx = corpus_tx();
  ZK_CHECK(!hash_at(tx, 2, kRegtest, 1).has_value());
  ZK_CHECK(!hash_at(tx, static_cast<std::size_t>(-1), kRegtest, 1).has_value());
}

ZK_TEST(sighash_preimage_layout_is_tag_chain_version_then_inputs) {
  const Transaction tx = corpus_tx();
  const std::optional<SigHash> sighash = hash_at(tx, 0, kRegtest, 1);
  ZK_CHECK(sighash.has_value());
  const std::vector<std::uint8_t>& preimage = sighash->preimage;

  // The tag, chain id, version and sighash type sit at fixed offsets.
  const std::vector<std::uint8_t> tag(preimage.begin(), preimage.begin() + 15);
  ZK_CHECK(hex_of(tag) == "5a524f2f736967686173682f763100");
  ZK_CHECK(preimage[15] == 0x00 && preimage[16] == 0x4f && preimage[17] == 0x52 &&
           preimage[18] == 0x5a);
  ZK_CHECK(preimage[19] == 0x01 && preimage[20] == 0x00 && preimage[21] == 0x00 &&
           preimage[22] == 0x00);
  ZK_CHECK(preimage[preimage.size() - 4] == 0x01);
  ZK_CHECK(preimage[preimage.size() - 3] == 0x00 && preimage[preimage.size() - 2] == 0x00 &&
           preimage[preimage.size() - 1] == 0x00);

  // Flipping the trailing type byte changes exactly one byte of the preimage:
  // the hasher folds the type in verbatim and does not validate it (F18).
  const std::optional<SigHash> type_two = hash_at(tx, 0, kRegtest, 2);
  ZK_CHECK(type_two.has_value());
  ZK_CHECK(type_two->preimage.size() == preimage.size());
  ZK_CHECK(type_two->preimage[type_two->preimage.size() - 4] == 0x02);
  ZK_CHECK(type_two->digest != sighash->digest);
}

ZK_TEST(sighash_blanks_every_script_sig) {
  // The digest commits to each coin's script_code, never to the unlock data of
  // any input: overwriting every scriptSig must not move the digest.
  Transaction tx = corpus_tx();
  const std::optional<SigHash> before = hash_at(tx, 1, kRegtest, 1);
  ZK_CHECK(before.has_value());
  tx.inputs[0].script_sig = {0xde, 0xad, 0xbe, 0xef};
  tx.inputs[1].script_sig = {0x00};
  const std::optional<SigHash> after = hash_at(tx, 1, kRegtest, 1);
  ZK_CHECK(after.has_value());
  ZK_CHECK(after->preimage == before->preimage);
  ZK_CHECK(after->digest == before->digest);
}

ZK_TEST(sighash_chain_index_and_type_are_domain_separated) {
  // Mirrors ledger.sighash.digest_stability from the corpus.
  const Transaction tx = corpus_tx();
  const std::optional<SigHash> index_0 = hash_at(tx, 0, kRegtest, 1);
  const std::optional<SigHash> index_1 = hash_at(tx, 1, kRegtest, 1);
  const std::optional<SigHash> mainnet = hash_at(tx, 0, kMainnet, 1);
  const std::optional<SigHash> type_two = hash_at(tx, 0, kRegtest, 2);
  ZK_CHECK(index_0.has_value() && index_1.has_value() && mainnet.has_value() &&
           type_two.has_value());
  ZK_CHECK(index_0->digest != index_1->digest);
  ZK_CHECK(index_0->digest != mainnet->digest);
  ZK_CHECK(index_0->digest != type_two->digest);
}

ZK_TEST(sighash_checker_accepts_sighash_all) {
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  const std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  RecordingVerifier verifier;
  const zk::TxSigChecker checker(tx, 0, code.data(), code.size(), ChainId{kRegtest}, &verifier);

  ZK_CHECK(checker.check_signature(signature.data(), signature.size(), pubkey.data(),
                                   pubkey.size()));
  ZK_CHECK(verifier.calls == 1);
  // The trailing sighash byte is stripped before the DER reaches the backend.
  ZK_CHECK(verifier.last_der.size() == signature.size() - 1);
  ZK_CHECK(hex_of(verifier.last_der) == std::string(kSignatureHex).substr(0, 142));
}

ZK_TEST(sighash_checker_rejects_other_types_before_the_backend) {
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  RecordingVerifier verifier;
  const zk::TxSigChecker checker(tx, 0, code.data(), code.size(), ChainId{kRegtest}, &verifier);

  // SIGHASH_ALL is the only consensus-valid type: the checker must reject 0x02
  // without asking the backend, even though the hasher would fold it in.
  signature.back() = 0x02;
  ZK_CHECK(!checker.check_signature(signature.data(), signature.size(), pubkey.data(),
                                    pubkey.size()));
  ZK_CHECK(verifier.calls == 0);

  signature.back() = 0x00;
  ZK_CHECK(!checker.check_signature(signature.data(), signature.size(), pubkey.data(),
                                    pubkey.size()));
  ZK_CHECK(verifier.calls == 0);
}

ZK_TEST(sighash_checker_rejects_empty_signatures) {
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  const std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  RecordingVerifier verifier;
  const zk::TxSigChecker checker(tx, 0, code.data(), code.size(), ChainId{kRegtest}, &verifier);

  ZK_CHECK(!checker.check_signature(nullptr, 0, pubkey.data(), pubkey.size()));
  ZK_CHECK(!checker.check_signature(signature.data(), 0, pubkey.data(), pubkey.size()));
  ZK_CHECK(verifier.calls == 0);
}

ZK_TEST(sighash_checker_fails_closed_without_a_backend) {
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  const std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  // No curve backend is linked in this phase, so every signature is rejected.
  const zk::TxSigChecker checker(tx, 0, code.data(), code.size(), ChainId{kRegtest}, nullptr);
  ZK_CHECK(!checker.check_signature(signature.data(), signature.size(), pubkey.data(),
                                    pubkey.size()));
}

ZK_TEST(sighash_checker_rejects_out_of_range_index) {
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  const std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  RecordingVerifier verifier;
  const zk::TxSigChecker checker(tx, 2, code.data(), code.size(), ChainId{kRegtest}, &verifier);
  ZK_CHECK(!checker.check_signature(signature.data(), signature.size(), pubkey.data(),
                                    pubkey.size()));
  ZK_CHECK(verifier.calls == 0);
}

ZK_TEST(sighash_checker_honours_a_rejecting_backend) {
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  const std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  RecordingVerifier verifier;
  verifier.accept = false;
  const zk::TxSigChecker checker(tx, 0, code.data(), code.size(), ChainId{kRegtest}, &verifier);
  ZK_CHECK(!checker.check_signature(signature.data(), signature.size(), pubkey.data(),
                                    pubkey.size()));
  ZK_CHECK(verifier.calls == 1);
}

ZK_TEST(sighash_script_spend_reaches_the_backend_once) {
  // End to end through the interpreter: OP_CHECKSIG hands exactly one signature
  // to the checker, which reaches the backend once.
  const Transaction tx = corpus_tx();
  const std::vector<std::uint8_t> code = script_code();
  const std::vector<std::uint8_t> script_sig = bytes_of(kScriptSigHex);
  const std::vector<std::uint8_t> script_pubkey = bytes_of(kScriptPubkeyHex);
  RecordingVerifier verifier;
  const zk::TxSigChecker checker(tx, 0, code.data(), code.size(), ChainId{kRegtest}, &verifier);
  const zk::ScriptResult result = zk::verify(
      script_sig.data(), script_sig.size(), script_pubkey.data(), script_pubkey.size(), checker);
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.error == zk::ScriptError::None);
  ZK_CHECK(verifier.calls == 1);
  ZK_CHECK(verifier.last_der.size() == 71);
}

ZK_TEST(sighash_tag_is_fifteen_bytes) {
  ZK_CHECK(zk::kSigHashTagSize == 15);
  const std::vector<std::uint8_t> tag(zk::kSigHashTag, zk::kSigHashTag + zk::kSigHashTagSize);
  ZK_CHECK(hex_of(tag) == "5a524f2f736967686173682f763100");
}
