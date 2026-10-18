#include "zerocoin/script.h"

#include <utility>

namespace zk {
namespace {

using Stack = std::vector<std::vector<std::uint8_t>>;

/// Bitcoin's rule for interpreting a stack item as a boolean: empty and every
/// encoding of zero (including negative zero) are false.
bool is_true(const std::vector<std::uint8_t>& item) noexcept {
  if (item.empty()) {
    return false;
  }
  for (std::size_t index = 0; index < item.size(); ++index) {
    const std::uint8_t byte = item[index];
    if (byte != 0) {
      // A lone 0x80 in the final position is negative zero, which is false.
      if (index + 1 == item.size() && byte == 0x80) {
        return false;
      }
      return true;
    }
  }
  return false;
}

ScriptResult push(Stack& stack, std::vector<std::uint8_t> item) {
  if (item.size() > kMaxScriptElement) {
    return {ScriptError::ElementTooLarge, 0};
  }
  if (stack.size() >= kMaxStackItems) {
    return {ScriptError::StackOverflow, 0};
  }
  stack.push_back(std::move(item));
  return {};
}

ScriptResult pop(Stack& stack, std::vector<std::uint8_t>& out) {
  if (stack.empty()) {
    return {ScriptError::StackUnderflow, 0};
  }
  out = std::move(stack.back());
  stack.pop_back();
  return {};
}

ScriptResult read_u8(const std::uint8_t* script, std::size_t size, std::size_t& offset,
                     std::uint8_t& out) {
  if (offset >= size) {
    return {ScriptError::Truncated, 0};
  }
  out = script[offset];
  ++offset;
  return {};
}

ScriptResult read_push(const std::uint8_t* script, std::size_t size, std::size_t& offset,
                       std::size_t length, std::vector<std::uint8_t>& out) {
  // `offset <= size` holds at every call, so the subtraction cannot wrap.
  if (length > size - offset) {
    return {ScriptError::Truncated, 0};
  }
  out.assign(script + offset, script + offset + length);
  offset += length;
  return {};
}

ScriptResult run_script(const std::uint8_t* script, std::size_t size, Stack& stack,
                        const SigChecker& checker) {
  if (size > kMaxScriptSize) {
    return {ScriptError::ScriptTooLarge, 0};
  }
  std::size_t ops = 0;
  std::size_t offset = 0;
  while (offset < size) {
    const std::uint8_t opcode = script[offset];
    ++offset;
    // Every opcode past the push range counts against the operation budget.
    if (opcode > kOpPushData2) {
      ++ops;
      if (ops > kMaxOpsPerScript) {
        return {ScriptError::TooManyOps, 0};
      }
    }

    // Data pushes: 0x01..0x4b carry their length in the opcode.
    if (opcode >= 0x01 && opcode <= 0x4b) {
      std::vector<std::uint8_t> data;
      if (ScriptResult result = read_push(script, size, offset, opcode, data); !result) {
        return result;
      }
      if (ScriptResult result = push(stack, std::move(data)); !result) {
        return result;
      }
      continue;
    }

    switch (opcode) {
      case kOp0: {
        if (ScriptResult result = push(stack, std::vector<std::uint8_t>{}); !result) {
          return result;
        }
        break;
      }
      case kOpPushData1: {
        std::uint8_t length = 0;
        if (ScriptResult result = read_u8(script, size, offset, length); !result) {
          return result;
        }
        std::vector<std::uint8_t> data;
        if (ScriptResult result = read_push(script, size, offset, length, data); !result) {
          return result;
        }
        if (ScriptResult result = push(stack, std::move(data)); !result) {
          return result;
        }
        break;
      }
      case kOpPushData2: {
        std::uint8_t lo = 0;
        std::uint8_t hi = 0;
        if (ScriptResult result = read_u8(script, size, offset, lo); !result) {
          return result;
        }
        if (ScriptResult result = read_u8(script, size, offset, hi); !result) {
          return result;
        }
        const std::size_t length =
            static_cast<std::size_t>(lo) | (static_cast<std::size_t>(hi) << 8);
        std::vector<std::uint8_t> data;
        if (ScriptResult result = read_push(script, size, offset, length, data); !result) {
          return result;
        }
        if (ScriptResult result = push(stack, std::move(data)); !result) {
          return result;
        }
        break;
      }

      case kOpDrop: {
        std::vector<std::uint8_t> dropped;
        if (ScriptResult result = pop(stack, dropped); !result) {
          return result;
        }
        break;
      }
      case kOpDup: {
        if (stack.empty()) {
          return {ScriptError::StackUnderflow, 0};
        }
        if (ScriptResult result = push(stack, stack.back()); !result) {
          return result;
        }
        break;
      }

      case kOpHash160: {
        std::vector<std::uint8_t> top;
        if (ScriptResult result = pop(stack, top); !result) {
          return result;
        }
        const Hash160 digest = hash160(top.data(), top.size());
        if (ScriptResult result =
                push(stack, std::vector<std::uint8_t>(digest.bytes.begin(), digest.bytes.end()));
            !result) {
          return result;
        }
        break;
      }
      case kOpEqual: {
        std::vector<std::uint8_t> b;
        std::vector<std::uint8_t> a;
        if (ScriptResult result = pop(stack, b); !result) {
          return result;
        }
        if (ScriptResult result = pop(stack, a); !result) {
          return result;
        }
        const bool equal = a == b;
        if (ScriptResult result = push(stack, equal ? std::vector<std::uint8_t>{1}
                                                    : std::vector<std::uint8_t>{});
            !result) {
          return result;
        }
        break;
      }
      case kOpVerify: {
        std::vector<std::uint8_t> top;
        if (ScriptResult result = pop(stack, top); !result) {
          return result;
        }
        if (!is_true(top)) {
          return {ScriptError::VerifyFailed, 0};
        }
        break;
      }
      case kOpEqualVerify: {
        std::vector<std::uint8_t> b;
        std::vector<std::uint8_t> a;
        if (ScriptResult result = pop(stack, b); !result) {
          return result;
        }
        if (ScriptResult result = pop(stack, a); !result) {
          return result;
        }
        if (a != b) {
          return {ScriptError::EqualVerifyFailed, 0};
        }
        break;
      }
      case kOpCheckSig: {
        // After a P2PKH scriptSig the stack ends [.., sig, pubkey], so the
        // public key is on top.
        std::vector<std::uint8_t> public_key;
        std::vector<std::uint8_t> signature;
        if (ScriptResult result = pop(stack, public_key); !result) {
          return result;
        }
        if (ScriptResult result = pop(stack, signature); !result) {
          return result;
        }
        const bool ok = checker.check_signature(signature.data(), signature.size(),
                                                public_key.data(), public_key.size());
        if (ScriptResult result = push(stack, ok ? std::vector<std::uint8_t>{1}
                                                 : std::vector<std::uint8_t>{});
            !result) {
          return result;
        }
        break;
      }

      default:
        return {ScriptError::UnsupportedOpcode, opcode};
    }
  }
  return {};
}

}  // namespace

const char* to_string(ScriptError error) noexcept {
  switch (error) {
    case ScriptError::None:
      return "None";
    case ScriptError::ScriptTooLarge:
      return "ScriptTooLarge";
    case ScriptError::TooManyOps:
      return "TooManyOps";
    case ScriptError::StackOverflow:
      return "StackOverflow";
    case ScriptError::StackUnderflow:
      return "StackUnderflow";
    case ScriptError::ElementTooLarge:
      return "ElementTooLarge";
    case ScriptError::EvalFalse:
      return "EvalFalse";
    case ScriptError::VerifyFailed:
      return "VerifyFailed";
    case ScriptError::EqualVerifyFailed:
      return "EqualVerifyFailed";
    case ScriptError::Truncated:
      return "Truncated";
    case ScriptError::UnsupportedOpcode:
      return "UnsupportedOpcode";
  }
  return "Unknown";
}

ScriptResult verify(const std::uint8_t* script_sig, std::size_t script_sig_size,
                    const std::uint8_t* script_pubkey, std::size_t script_pubkey_size,
                    const SigChecker& checker) {
  Stack stack;
  if (ScriptResult result = run_script(script_sig, script_sig_size, stack, checker); !result) {
    return result;
  }
  if (ScriptResult result = run_script(script_pubkey, script_pubkey_size, stack, checker);
      !result) {
    return result;
  }
  if (stack.empty() || !is_true(stack.back())) {
    return {ScriptError::EvalFalse, 0};
  }
  return {};
}

std::vector<std::uint8_t> p2pkh_script_pubkey(const Hash160& pkhash) {
  std::vector<std::uint8_t> script;
  script.reserve(25);
  script.push_back(kOpDup);
  script.push_back(kOpHash160);
  push_data(pkhash.bytes.data(), pkhash.bytes.size(), script);
  script.push_back(kOpEqualVerify);
  script.push_back(kOpCheckSig);
  return script;
}

std::vector<std::uint8_t> p2pkh_script_sig(const std::uint8_t* signature,
                                           std::size_t signature_size,
                                           const std::uint8_t* public_key,
                                           std::size_t public_key_size) {
  std::vector<std::uint8_t> script;
  script.reserve(signature_size + public_key_size + 2);
  push_data(signature, signature_size, script);
  push_data(public_key, public_key_size, script);
  return script;
}

void push_data(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out) {
  if (size < kOpPushData1) {
    out.push_back(static_cast<std::uint8_t>(size));
  } else if (size <= 0xff) {
    out.push_back(kOpPushData1);
    out.push_back(static_cast<std::uint8_t>(size));
  } else {
    // Byte-identical to the reference, which masks above 0xffff; see F20.
    out.push_back(kOpPushData2);
    out.push_back(static_cast<std::uint8_t>(size & 0xff));
    out.push_back(static_cast<std::uint8_t>((size >> 8) & 0xff));
  }
  if (size != 0) {
    out.insert(out.end(), data, data + size);
  }
}

}  // namespace zk
