#include "test_framework.h"

#include "zerocoin/hex.h"
#include "zerocoin/script.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

using zk::ScriptError;
using zk::ScriptResult;

// The P2PKH pair pinned by test/vectors/ledger/script.json.
constexpr const char* kPubkeyHashHex = "751e76e8199196d454941c45d1b3a323f1433bd6";
constexpr const char* kPubkeySec1Hex =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
constexpr const char* kSignatureHex =
    "304502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "0220199b56aa206063c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f01";
constexpr const char* kScriptPubkeyHex = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
constexpr const char* kScriptSigHex =
    "48304502210096b22dddb2b93b4eb6a4a649ee126c4493a81855257b03758c5735a052ffee89"
    "0220199b56aa206063c815ca731c2193c1a66d0da05f8045d7242145dba365dc3a4f"
    "01210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct AlwaysAccept final : zk::SigChecker {
  bool check_signature(const std::uint8_t* /*signature*/, std::size_t /*signature_size*/,
                       const std::uint8_t* /*public_key*/,
                       std::size_t /*public_key_size*/) const override {
    return true;
  }
};

struct RejectAll final : zk::SigChecker {
  bool check_signature(const std::uint8_t* /*signature*/, std::size_t /*signature_size*/,
                       const std::uint8_t* /*public_key*/,
                       std::size_t /*public_key_size*/) const override {
    return false;
  }
};

std::vector<std::uint8_t> bytes_of(const std::string& hex) {
  auto parsed = zk::from_hex(hex);
  ZK_CHECK(parsed.has_value());
  return *parsed;
}

std::string hex_of(const std::vector<std::uint8_t>& bytes) {
  return zk::to_hex(bytes.data(), bytes.size());
}

ScriptResult run_hex(const std::string& script_sig_hex, const std::string& script_pubkey_hex,
                     const zk::SigChecker& checker) {
  const std::vector<std::uint8_t> script_sig = bytes_of(script_sig_hex);
  const std::vector<std::uint8_t> script_pubkey = bytes_of(script_pubkey_hex);
  return zk::verify(script_sig.data(), script_sig.size(), script_pubkey.data(),
                    script_pubkey.size(), checker);
}

/// `count` copies of one two-byte push whose payload is `value`.
std::string repeated_push(std::size_t count, std::uint8_t value) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string script;
  script.reserve(count * 4);
  for (std::size_t i = 0; i < count; ++i) {
    script += "01";
    script.push_back(kDigits[value >> 4]);
    script.push_back(kDigits[value & 0x0f]);
  }
  return script;
}

/// `count` copies of a one-byte opcode.
std::string repeated_opcode(std::size_t count, std::uint8_t opcode) {
  constexpr char kDigits[] = "0123456789abcdef";
  std::string script;
  script.reserve(count * 2);
  for (std::size_t i = 0; i < count; ++i) {
    script.push_back(kDigits[opcode >> 4]);
    script.push_back(kDigits[opcode & 0x0f]);
  }
  return script;
}

}  // namespace

ZK_TEST(script_p2pkh_pubkey_matches_the_corpus) {
  zk::Hash160 pkhash{};
  const std::vector<std::uint8_t> raw = bytes_of(kPubkeyHashHex);
  ZK_CHECK(raw.size() == 20);
  for (std::size_t i = 0; i < raw.size(); ++i) {
    pkhash.bytes[i] = raw[i];
  }
  const std::vector<std::uint8_t> script = zk::p2pkh_script_pubkey(pkhash);
  ZK_CHECK(script.size() == 25);
  ZK_CHECK(hex_of(script) == kScriptPubkeyHex);
  ZK_CHECK(script.front() == zk::kOpDup);
  ZK_CHECK(script.back() == zk::kOpCheckSig);
}

ZK_TEST(script_p2pkh_sig_matches_the_corpus) {
  const std::vector<std::uint8_t> signature = bytes_of(kSignatureHex);
  const std::vector<std::uint8_t> pubkey = bytes_of(kPubkeySec1Hex);
  ZK_CHECK(signature.size() == 72);
  ZK_CHECK(pubkey.size() == 33);
  const std::vector<std::uint8_t> script =
      zk::p2pkh_script_sig(signature.data(), signature.size(), pubkey.data(), pubkey.size());
  ZK_CHECK(script.size() == 107);
  ZK_CHECK(hex_of(script) == kScriptSigHex);
}

ZK_TEST(script_push_data_uses_the_minimal_prefix) {
  // The boundaries the corpus pins: 0, 1, 75, 76, 255, 256, 520.
  struct Sample {
    std::size_t length;
    std::size_t prefix;
    std::uint8_t first;
    std::uint8_t second;
  };
  const Sample samples[] = {{0, 1, 0x00, 0x00},
                            {1, 1, 0x01, 0x00},
                            {75, 1, 0x4b, 0x00},
                            {76, 2, zk::kOpPushData1, 0x4c},
                            {255, 2, zk::kOpPushData1, 0xff},
                            {256, 3, zk::kOpPushData2, 0x00},
                            {520, 3, zk::kOpPushData2, 0x08}};
  for (const Sample& sample : samples) {
    const std::vector<std::uint8_t> data(sample.length, 0xab);
    std::vector<std::uint8_t> script;
    zk::push_data(data.data(), data.size(), script);
    ZK_CHECK(script.size() == sample.prefix + sample.length);
    ZK_CHECK(script[0] == sample.first);
    if (sample.second != 0) {
      ZK_CHECK(script[1] == sample.second);
    }
    if (sample.length != 0) {
      ZK_CHECK(script[sample.prefix] == 0xab);
    }
  }

  std::vector<std::uint8_t> empty;
  zk::push_data(nullptr, 0, empty);
  ZK_CHECK(empty.size() == 1);
  ZK_CHECK(empty[0] == 0x00);
}

ZK_TEST(script_valid_p2pkh_spend_runs) {
  const ScriptResult result = run_hex(kScriptSigHex, kScriptPubkeyHex, AlwaysAccept{});
  ZK_CHECK(static_cast<bool>(result));
  ZK_CHECK(result.error == ScriptError::None);
}

ZK_TEST(script_p2pkh_with_rejecting_checker_is_evalfalse) {
  const ScriptResult result = run_hex(kScriptSigHex, kScriptPubkeyHex, RejectAll{});
  ZK_CHECK(!static_cast<bool>(result));
  ZK_CHECK(result.error == ScriptError::EvalFalse);
}

ZK_TEST(script_wrong_pubkey_hash_fails_equalverify) {
  // Lock to a different key's hash, then spend with the pinned pubkey.
  const zk::Hash160 other = zk::hash160(std::string_view("not the pinned key"));
  const std::vector<std::uint8_t> script_pubkey = zk::p2pkh_script_pubkey(other);
  ZK_CHECK(script_pubkey != bytes_of(kScriptPubkeyHex));
  const ScriptResult result = run_hex(kScriptSigHex, hex_of(script_pubkey), AlwaysAccept{});
  ZK_CHECK(result.error == ScriptError::EqualVerifyFailed);
}

ZK_TEST(script_reject_matrix_matches_the_corpus) {
  struct Reject {
    const char* script_sig;
    const char* script_pubkey;
    ScriptError error;
  };
  // The first seven reject vectors from test/vectors/ledger/script.json; the
  // four limit vectors are generated by the tests below.
  const Reject rejects[] = {
      {"", "6a", ScriptError::UnsupportedOpcode},
      {"", "0180", ScriptError::EvalFalse},
      {"", "00", ScriptError::EvalFalse},
      {"", "69", ScriptError::StackUnderflow},
      {"01010102", "88", ScriptError::EqualVerifyFailed},
      {"", "87", ScriptError::StackUnderflow},
      {"", "0201", ScriptError::Truncated},
  };
  for (const Reject& reject : rejects) {
    const ScriptResult result = run_hex(reject.script_sig, reject.script_pubkey, AlwaysAccept{});
    ZK_CHECK(!static_cast<bool>(result));
    ZK_CHECK(result.error == reject.error);
    if (result.error == ScriptError::UnsupportedOpcode) {
      ZK_CHECK(result.opcode == 0x6a);
    }
  }
}

ZK_TEST(script_element_limit_is_520_bytes) {
  // 0x0208 == 520 bytes: allowed, and the payload starts non-zero so the top
  // of the stack is true.
  std::string at_bound = "4d0802";
  for (std::size_t i = 0; i < 520; ++i) {
    at_bound += "cd";
  }
  ZK_CHECK(static_cast<bool>(run_hex("", at_bound, AlwaysAccept{})));

  // 0x0209 == 521 bytes: one past the element limit.
  std::string too_large = "4d0902";
  for (std::size_t i = 0; i < 521; ++i) {
    too_large += "cd";
  }
  ZK_CHECK(run_hex("", too_large, AlwaysAccept{}).error == ScriptError::ElementTooLarge);
}

ZK_TEST(script_stack_limit_is_1000_items) {
  ZK_CHECK(static_cast<bool>(run_hex("", repeated_push(1'000, 0x01), AlwaysAccept{})));
  const ScriptResult overflow = run_hex("", repeated_push(1'001, 0x01), AlwaysAccept{});
  ZK_CHECK(overflow.error == ScriptError::StackOverflow);
}

ZK_TEST(script_op_limit_is_201_ops_and_pushes_are_free) {
  // A one-byte push leaves 0x01 on the stack; each OP_DUP is one op.
  ZK_CHECK(static_cast<bool>(
      run_hex("", "0101" + repeated_opcode(201, zk::kOpDup), AlwaysAccept{})));
  ZK_CHECK(run_hex("", "0101" + repeated_opcode(202, zk::kOpDup), AlwaysAccept{}).error ==
           ScriptError::TooManyOps);

  // 300 zero-length pushes are free ops; the stack ends with an empty top, so
  // the script fails on truthiness, not on the op budget.
  ZK_CHECK(run_hex("", repeated_opcode(300, zk::kOp0), AlwaysAccept{}).error ==
           ScriptError::EvalFalse);

  // 300 one-byte pushes likewise stay under the op budget and leave true.
  ZK_CHECK(static_cast<bool>(run_hex("", repeated_push(300, 0x01), AlwaysAccept{})));
}

ZK_TEST(script_size_limit_is_10000_bytes) {
  // Exactly 10_000 bytes: the size check passes and the stack bound fires.
  const std::string at_bound = repeated_opcode(10'000, zk::kOp0);
  ZK_CHECK(at_bound.size() == 20'000);
  ZK_CHECK(run_hex("", at_bound, AlwaysAccept{}).error == ScriptError::StackOverflow);

  // 10_001 bytes: rejected before execution.
  const ScriptResult too_large = run_hex("", repeated_opcode(10'001, zk::kOp0), AlwaysAccept{});
  ZK_CHECK(too_large.error == ScriptError::ScriptTooLarge);
}

ZK_TEST(script_truthiness_rejects_negative_zero) {
  // 0x80 alone is negative zero; 0x00 is zero; both are false.
  ZK_CHECK(run_hex("", "0180", AlwaysAccept{}).error == ScriptError::EvalFalse);
  ZK_CHECK(run_hex("", "0100", AlwaysAccept{}).error == ScriptError::EvalFalse);
  ZK_CHECK(run_hex("", "00", AlwaysAccept{}).error == ScriptError::EvalFalse);

  // Any other non-zero byte is true, including 0x80 that is not the last byte.
  ZK_CHECK(static_cast<bool>(run_hex("", "0101", AlwaysAccept{})));
  ZK_CHECK(static_cast<bool>(run_hex("", "028080", AlwaysAccept{})));

  // Two pushes: 0x00 then 0x01, so the top is true.
  ZK_CHECK(static_cast<bool>(run_hex("", "0100" "0101", AlwaysAccept{})));

  // An empty script leaves nothing on the stack.
  ZK_CHECK(run_hex("", "", AlwaysAccept{}).error == ScriptError::EvalFalse);
}

ZK_TEST(script_error_names_are_stable) {
  ZK_CHECK(std::string(zk::to_string(ScriptError::None)) == "None");
  ZK_CHECK(std::string(zk::to_string(ScriptError::ScriptTooLarge)) == "ScriptTooLarge");
  ZK_CHECK(std::string(zk::to_string(ScriptError::TooManyOps)) == "TooManyOps");
  ZK_CHECK(std::string(zk::to_string(ScriptError::StackOverflow)) == "StackOverflow");
  ZK_CHECK(std::string(zk::to_string(ScriptError::StackUnderflow)) == "StackUnderflow");
  ZK_CHECK(std::string(zk::to_string(ScriptError::ElementTooLarge)) == "ElementTooLarge");
  ZK_CHECK(std::string(zk::to_string(ScriptError::EvalFalse)) == "EvalFalse");
  ZK_CHECK(std::string(zk::to_string(ScriptError::VerifyFailed)) == "VerifyFailed");
  ZK_CHECK(std::string(zk::to_string(ScriptError::EqualVerifyFailed)) == "EqualVerifyFailed");
  ZK_CHECK(std::string(zk::to_string(ScriptError::Truncated)) == "Truncated");
  ZK_CHECK(std::string(zk::to_string(ScriptError::UnsupportedOpcode)) == "UnsupportedOpcode");
}
