#include "test_framework.h"

#include "zerocoin/hex.h"
#include "zerocoin/script.h"
#include "zerocoin/secp256k1_verifier.h"
#include "zerocoin/sighash.h"
#include "zerocoin/transaction.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

using zk::ScriptError;
using zk::ScriptResult;
using zk::Secp256k1Verifier;

// The accepted P2PKH spend pinned by test/vectors/ledger/script.json
// (ledger.script.p2pkh_spend_accepted): a real signature from scalar 1 over
// its own transaction, regtest chain id (0x5A524F00).
constexpr std::uint32_t kChainId = 1515343616;
constexpr const char* kTxHex =
    "01000000022222222222222222222222222222222222222222222222222222222222222222010000006b48304"
    "502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee890220199b56aa20606"
    "3c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f01210279be667ef9dcbbac55a06295ce870b0"
    "7029bfcdb2dce28d959f2815b16f81798feffffff3333333333333333333333333333333333333333333333"
    "333333333333333333070000000000000000020100000000000000000040075af0750700016a20a10700";
constexpr const char* kScriptPubkeyHex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
constexpr const char* kSignatureHex =
    "304502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "0220199b56aa206063c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f01";
constexpr const char* kPubkeySec1Hex =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
constexpr const char* kScriptSigHex =
    "48304502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "0220199b56aa206063c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f"
    "01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// V2.p2_corpus_high_s_twin: (r, n - s) of the corpus signature — same ECDSA
// point, opposite verdict. The half-order gate is load-bearing (contract B4).
constexpr const char* kHighSDigestHex =
    "e0e7ce176c2aa8077378299f682baec23e02abc289b51fa1895b7cde9ce6a237";
constexpr const char* kHighSDerHex =
    "304602210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "022100e664a955df9f9c37ea358ce3de6c3e584da13c872f02c9179e8c82e96a5a06f2";

// V4 rows: the library accepts these key encodings, the ZeroCoin contract
// rejects them (rule P-1). Same digest and DER as V1.p23_scalar7_low_s.
constexpr const char* kV4DigestHex =
    "e6d8533d96866eecea284731dac93bce9978750097c45629228e709fc80b7650";
constexpr const char* kV4DerHex =
    "3045022100b402ba359b4789a03022778f78c50989e635942a6d4079c1fa404358b77177c5"
    "022005029d004a5142f7f496ac7e30de1a6c7a39cd2f61d11dd83b30cec48c0f30e4";
constexpr const char* kV4UncompressedHex =
    "04989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
    "631f4d05b3ae518776ee08755a7703e64b2ebc32547504de0b55a142d4ecdf80";
constexpr const char* kV4Prefix05Hex =
    "05989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";

std::vector<std::uint8_t> bytes_of(const std::string& hex) {
  auto parsed = zk::from_hex(hex);
  ZK_CHECK(parsed.has_value());
  return *parsed;
}

zk::Hash256 digest_of(const std::string& hex) {
  const std::vector<std::uint8_t> raw = bytes_of(hex);
  ZK_CHECK(raw.size() == zk::Hash256::kWidth);
  zk::Hash256 digest{};
  for (std::size_t i = 0; i < raw.size(); ++i) {
    digest.bytes[i] = raw[i];
  }
  return digest;
}

/// The accepted corpus spend, decoded once: its transaction, locking script,
/// signature (DER + the SIGHASH_ALL byte), key, and the digest a signature
/// over input 0 must cover.
struct CorpusSpend {
  zk::Transaction tx;
  std::vector<std::uint8_t> script_code;
  std::vector<std::uint8_t> signature;
  std::vector<std::uint8_t> pubkey;
  zk::SigHash sighash;
};

CorpusSpend corpus_spend() {
  const std::vector<std::uint8_t> tx_bytes = bytes_of(kTxHex);
  const zk::TxDecodeResult decoded = zk::deserialize_transaction(tx_bytes.data(), tx_bytes.size());
  ZK_CHECK(static_cast<bool>(decoded));
  CorpusSpend spend;
  spend.tx = decoded.tx;
  spend.script_code = bytes_of(kScriptPubkeyHex);
  spend.signature = bytes_of(kSignatureHex);
  spend.pubkey = bytes_of(kPubkeySec1Hex);
  const std::optional<zk::SigHash> sighash =
      zk::signature_hash(spend.tx, 0, spend.script_code.data(), spend.script_code.size(),
                         zk::ChainId{kChainId}, zk::kSigHashAll);
  ZK_CHECK(sighash.has_value());
  spend.sighash = *sighash;
  return spend;
}

}  // namespace

ZK_TEST(secp256k1_verifier_accepts_the_corpus_spend_digest) {
  const CorpusSpend spend = corpus_spend();
  ZK_CHECK(spend.signature.back() == zk::kSigHashAll);
  const Secp256k1Verifier verifier;
  ZK_CHECK(verifier.verify(spend.sighash.digest, spend.signature.data(),
                           spend.signature.size() - 1, spend.pubkey.data(),
                           spend.pubkey.size()));
}

ZK_TEST(secp256k1_verifier_rejects_a_corrupted_digest) {
  const CorpusSpend spend = corpus_spend();
  zk::Hash256 corrupted = spend.sighash.digest;
  corrupted.bytes[0] ^= 0x01;
  const Secp256k1Verifier verifier;
  ZK_CHECK(!verifier.verify(corrupted, spend.signature.data(), spend.signature.size() - 1,
                            spend.pubkey.data(), spend.pubkey.size()));
}

ZK_TEST(secp256k1_verifier_rejects_high_s_without_normalising) {
  const Secp256k1Verifier verifier;
  const std::vector<std::uint8_t> der = bytes_of(kHighSDerHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  ZK_CHECK(!verifier.verify(digest_of(kHighSDigestHex), der.data(), der.size(), pubkey.data(),
                            pubkey.size()));
}

ZK_TEST(secp256k1_verifier_enforces_the_compressed_key_gate) {
  const Secp256k1Verifier verifier;
  const std::vector<std::uint8_t> der = bytes_of(kV4DerHex);
  const zk::Hash256 digest = digest_of(kV4DigestHex);

  // V4.uncompressed_65: the library would verify this encoding; the ZeroCoin
  // contract rejects it on length before the curve is touched.
  const std::vector<std::uint8_t> uncompressed = bytes_of(kV4UncompressedHex);
  ZK_CHECK(uncompressed.size() == 65);
  ZK_CHECK(!verifier.verify(digest, der.data(), der.size(), uncompressed.data(),
                            uncompressed.size()));

  // V4.prefix_05: 33 bytes with a tag outside {02, 03} is likewise outside P-1.
  const std::vector<std::uint8_t> prefix05 = bytes_of(kV4Prefix05Hex);
  ZK_CHECK(prefix05.size() == 33);
  ZK_CHECK(!verifier.verify(digest, der.data(), der.size(), prefix05.data(), prefix05.size()));
}

ZK_TEST(secp256k1_verifier_rejects_malformed_der) {
  const CorpusSpend spend = corpus_spend();
  const Secp256k1Verifier verifier;

  // Truncating one byte breaks the DER framing: SEQUENCE still claims 69
  // content bytes and only 68 remain.
  std::vector<std::uint8_t> truncated(spend.signature.begin(), spend.signature.end() - 1);
  truncated.pop_back();
  ZK_CHECK(!verifier.verify(spend.sighash.digest, truncated.data(), truncated.size(),
                            spend.pubkey.data(), spend.pubkey.size()));

  // A bit flip inside s is well-formed DER over a different scalar: rejected
  // by the equation, not by the parser.
  std::vector<std::uint8_t> wrong_scalar = spend.signature;
  wrong_scalar[wrong_scalar.size() - 2] ^= 0x01;
  wrong_scalar.pop_back();
  ZK_CHECK(!verifier.verify(spend.sighash.digest, wrong_scalar.data(), wrong_scalar.size(),
                            spend.pubkey.data(), spend.pubkey.size()));
}

ZK_TEST(script_p2pkh_spend_verifies_with_the_vendored_backend) {
  const CorpusSpend spend = corpus_spend();
  const Secp256k1Verifier verifier;
  const zk::TxSigChecker checker(spend.tx, 0, spend.script_code.data(), spend.script_code.size(),
                                 zk::ChainId{kChainId}, &verifier);
  const std::vector<std::uint8_t> script_sig = bytes_of(kScriptSigHex);
  const std::vector<std::uint8_t> script_pubkey = bytes_of(kScriptPubkeyHex);
  const ScriptResult result = zk::verify(script_sig.data(), script_sig.size(),
                                         script_pubkey.data(), script_pubkey.size(), checker);
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.error == ScriptError::None);
}

ZK_TEST(script_p2pkh_spend_with_a_corrupted_signature_is_evalfalse) {
  const CorpusSpend spend = corpus_spend();
  const Secp256k1Verifier verifier;
  const zk::TxSigChecker checker(spend.tx, 0, spend.script_code.data(), spend.script_code.size(),
                                 zk::ChainId{kChainId}, &verifier);
  std::vector<std::uint8_t> script_sig = bytes_of(kScriptSigHex);
  script_sig[2] ^= 0x01;  // first byte inside the DER payload; the pushes stay intact
  const std::vector<std::uint8_t> script_pubkey = bytes_of(kScriptPubkeyHex);
  const ScriptResult result = zk::verify(script_sig.data(), script_sig.size(),
                                         script_pubkey.data(), script_pubkey.size(), checker);
  ZK_CHECK(!static_cast<bool>(result));
  ZK_CHECK(result.error == ScriptError::EvalFalse);
}
