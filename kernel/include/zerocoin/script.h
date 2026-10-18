// A Forth-like, stack-based script interpreter for P2PKH validation,
// mirroring zerocoin/src/ledger/script.rs exactly.
//
// ZeroCoin runs Bitcoin's script model: the unlocking script (scriptSig) is
// executed first, then the locking script (scriptPubKey) runs against the stack
// it left behind, and the spend is valid only if a true value is on top.
// Signature checking is delegated to a SigChecker so the interpreter never
// needs to know about sighash construction or keys.
//
// Only the ten opcodes a P2PKH spend needs are implemented. Everything else is
// rejected, which keeps the interpreter free of the disabled and flow-control
// opcodes that have historically produced consensus bugs.

#ifndef ZEROCOIN_KERNEL_SCRIPT_H
#define ZEROCOIN_KERNEL_SCRIPT_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "zerocoin/hash.h"

namespace zk {

// Opcodes. `OP_0` is a zero-length push, not a number opcode.
inline constexpr std::uint8_t kOp0 = 0x00;
inline constexpr std::uint8_t kOpPushData1 = 0x4c;
inline constexpr std::uint8_t kOpPushData2 = 0x4d;
inline constexpr std::uint8_t kOpVerify = 0x69;
inline constexpr std::uint8_t kOpDrop = 0x75;
inline constexpr std::uint8_t kOpDup = 0x76;
inline constexpr std::uint8_t kOpEqual = 0x87;
inline constexpr std::uint8_t kOpEqualVerify = 0x88;
inline constexpr std::uint8_t kOpHash160 = 0xa9;
inline constexpr std::uint8_t kOpCheckSig = 0xac;

// Limits mirroring the reference (which mirrors Bitcoin's) so a hostile script
// cannot exhaust memory or spin. They are part of consensus.
inline constexpr std::size_t kMaxStackItems = 1'000;
inline constexpr std::size_t kMaxScriptElement = 520;
inline constexpr std::size_t kMaxOpsPerScript = 201;
inline constexpr std::size_t kMaxScriptSize = 10'000;

enum class ScriptError : std::uint8_t {
  None = 0,
  ScriptTooLarge,
  TooManyOps,
  StackOverflow,
  StackUnderflow,
  ElementTooLarge,
  EvalFalse,
  VerifyFailed,
  EqualVerifyFailed,
  Truncated,
  UnsupportedOpcode,
};

/// Stable spelling used by the conformance runner and the corpus.
const char* to_string(ScriptError error) noexcept;

/// The result of a script run. `opcode` is set only for
/// `ScriptError::UnsupportedOpcode`, matching the payload the reference's
/// `Result<(), ScriptError>` carries in that variant.
struct ScriptResult {
  ScriptError error = ScriptError::None;
  std::uint8_t opcode = 0;

  explicit operator bool() const noexcept { return error == ScriptError::None; }
};

/// A signature checker the interpreter calls for `OP_CHECKSIG`. The ledger
/// supplies one bound to the transaction, input and chain being validated.
///
/// `signature` is DER followed by one sighash byte; `public_key` is compressed
/// SEC1. Implementations must not be hand-written curve code: see R9 in
/// docs/migration/04-risk-register.md.
class SigChecker {
 public:
  virtual ~SigChecker() = default;

  virtual bool check_signature(const std::uint8_t* signature, std::size_t signature_size,
                               const std::uint8_t* public_key,
                               std::size_t public_key_size) const = 0;
};

/// Execute `script_sig` then `script_pubkey` on one stack and require a true
/// value on top. This is the whole of ZeroCoin's spend authorization.
ScriptResult verify(const std::uint8_t* script_sig, std::size_t script_sig_size,
                    const std::uint8_t* script_pubkey, std::size_t script_pubkey_size,
                    const SigChecker& checker);

/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG` (25 bytes).
std::vector<std::uint8_t> p2pkh_script_pubkey(const Hash160& pkhash);

/// The unlocking script for a P2PKH spend: `<sig> <pubkey>`, both minimal pushes.
std::vector<std::uint8_t> p2pkh_script_sig(const std::uint8_t* signature,
                                           std::size_t signature_size,
                                           const std::uint8_t* public_key,
                                           std::size_t public_key_size);

/// Appends a minimal data push for `data[0..size)` to `out`.
///
/// Below 0x4c the length is the opcode; up to 0xff `OP_PUSHDATA1` and one
/// length byte; otherwise `OP_PUSHDATA2` and a little-endian 16-bit length.
/// The reference masks the length above 0xffff, and so does this port: the
/// builder is only reachable with tiny inputs today (finding F20 tracks the
/// latent truncation rather than changing behaviour).
void push_data(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out);

static_assert(kOp0 == 0x00, "OP_0 is the zero-length push");
static_assert(kOpPushData1 == 0x4c, "OP_PUSHDATA1 is 0x4c");
static_assert(kOpPushData2 == 0x4d, "OP_PUSHDATA2 is 0x4d");
static_assert(kOpVerify == 0x69, "OP_VERIFY is 0x69");
static_assert(kOpDrop == 0x75, "OP_DROP is 0x75");
static_assert(kOpDup == 0x76, "OP_DUP is 0x76");
static_assert(kOpEqual == 0x87, "OP_EQUAL is 0x87");
static_assert(kOpEqualVerify == 0x88, "OP_EQUALVERIFY is 0x88");
static_assert(kOpHash160 == 0xa9, "OP_HASH160 is 0xa9");
static_assert(kOpCheckSig == 0xac, "OP_CHECKSIG is 0xac");

static_assert(kMaxStackItems == 1'000, "the stack bound is frozen with the interpreter");
static_assert(kMaxScriptElement == 520, "the element bound is frozen with the interpreter");
static_assert(kMaxOpsPerScript == 201, "the op budget is frozen with the interpreter");
static_assert(kMaxScriptSize == 10'000, "the script size bound is frozen with the interpreter");
static_assert(static_cast<std::uint8_t>(ScriptError::UnsupportedOpcode) ==
                  static_cast<std::uint8_t>(ScriptError::Truncated) + 1,
              "ScriptError values are contiguous for the corpus spelling");

}  // namespace zk

#endif  // ZEROCOIN_KERNEL_SCRIPT_H
