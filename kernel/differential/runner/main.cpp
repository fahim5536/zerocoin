// Test-only differential runner: pinned libsecp256k1 v0.8.0 vs the Rust reference.
//
// Reads a vector file, computes two verdicts per case with the backend adapter,
// and prints one line per case. The recorded Rust verdict comes from the fixture
// (produced by `zerocoin/tests/differential_vectors.rs`); this program never
// invents an expected value, it only reports whether the backend reproduced it.
//
// Usage: secp256k1_differential <vectors.txt>
//
// Exit codes: 0 all cases matched, 1 at least one mismatch, 2 malformed input.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "secp256k1_verifier.h"

namespace {

constexpr std::size_t kDigestSize = 32;

struct Case {
  std::string id;
  std::string group;
  bool rust_accept = false;
  std::vector<std::uint8_t> digest;
  std::vector<std::uint8_t> der;
  std::vector<std::uint8_t> public_key;
  std::string note;
};

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::optional<std::vector<std::uint8_t>> decode_hex(std::string_view text) {
  std::vector<std::uint8_t> bytes;
  if (text.size() % 2 != 0) {
    return std::nullopt;
  }
  bytes.reserve(text.size() / 2);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int high = hex_value(text[i]);
    const int low = hex_value(text[i + 1]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return bytes;
}

std::string_view trim(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
    text.remove_suffix(1);
  }
  return text;
}

/// Splits `key=value` on the first '=' and trims both sides.
std::optional<std::pair<std::string_view, std::string_view>> split_pair(std::string_view line) {
  const std::size_t at = line.find('=');
  if (at == std::string_view::npos) {
    return std::nullopt;
  }
  return std::make_pair(trim(line.substr(0, at)), trim(line.substr(at + 1)));
}

bool parse_verdict(std::string_view text, bool* accept) {
  if (text == "accept") {
    *accept = true;
    return true;
  }
  if (text == "reject") {
    *accept = false;
    return true;
  }
  return false;
}

bool decode_bytes_field(std::string_view value, std::vector<std::uint8_t>* out) {
  if (value == "-") {
    out->clear();
    return true;
  }
  const auto decoded = decode_hex(value);
  if (!decoded.has_value()) {
    return false;
  }
  *out = *decoded;
  return true;
}

class FixtureError {
 public:
  FixtureError(std::size_t line, std::string message)
      : line_(line), message_(std::move(message)) {}

  friend std::ostream& operator<<(std::ostream& os, const FixtureError& err) {
    return os << "line " << err.line_ << ": " << err.message_;
  }

 private:
  std::size_t line_;
  std::string message_;
};

std::vector<Case> load_fixture(const std::string& path, std::size_t* declared_cases) {
  std::ifstream stream(path);
  if (!stream) {
    throw FixtureError(0, "cannot open " + path);
  }

  std::vector<Case> cases;
  std::optional<Case> current;
  std::size_t line_number = 0;
  std::size_t declared = 0;
  bool has_declared = false;

  std::string raw;
  while (std::getline(stream, raw)) {
    ++line_number;
    const std::string_view line = trim(raw);
    if (line.empty() || line.front() == '#') {
      continue;
    }

    const std::size_t space = line.find(' ');
    const std::string_view keyword = line.substr(0, space);
    const std::string_view rest =
        space == std::string_view::npos ? std::string_view{} : trim(line.substr(space + 1));

    if (keyword == "META") {
      const auto pair = split_pair(rest);
      if (!pair.has_value()) {
        throw FixtureError(line_number, "META expects key=value");
      }
      if (pair->first == "cases") {
        try {
          declared = std::stoul(std::string(pair->second));
        } catch (const std::exception&) {
          throw FixtureError(line_number, "META cases is not a number");
        }
        has_declared = true;
      }
      continue;
    }

    if (keyword == "CASE") {
      if (current.has_value()) {
        throw FixtureError(line_number, "CASE before previous END");
      }
      if (rest.empty()) {
        throw FixtureError(line_number, "CASE expects an identifier");
      }
      current.emplace();
      current->id = std::string(rest);
      continue;
    }

    if (keyword == "END") {
      if (!current.has_value()) {
        throw FixtureError(line_number, "END without CASE");
      }
      if (current->group.empty()) {
        throw FixtureError(line_number, "case " + current->id + " has no GROUP");
      }
      if (current->digest.size() != kDigestSize) {
        throw FixtureError(line_number, "case " + current->id + " digest is not 32 bytes");
      }
      cases.push_back(std::move(*current));
      current.reset();
      continue;
    }

    // Every remaining keyword is a per-case field.
    if (!current.has_value()) {
      throw FixtureError(line_number, std::string(keyword) + " outside CASE");
    }

    if (keyword == "GROUP") {
      current->group = std::string(rest);
    } else if (keyword == "RUST") {
      if (!parse_verdict(rest, &current->rust_accept)) {
        throw FixtureError(line_number, "RUST expects accept or reject");
      }
    } else if (keyword == "DER") {
      if (!decode_bytes_field(rest, &current->der)) {
        throw FixtureError(line_number, "DER is not valid hex");
      }
    } else if (keyword == "PUBKEY") {
      if (!decode_bytes_field(rest, &current->public_key)) {
        throw FixtureError(line_number, "PUBKEY is not valid hex");
      }
    } else if (keyword == "DIGEST") {
      if (!decode_bytes_field(rest, &current->digest)) {
        throw FixtureError(line_number, "DIGEST is not valid hex");
      }
    } else if (keyword == "NOTE") {
      current->note = std::string(rest);
    } else {
      throw FixtureError(line_number, "unknown keyword " + std::string(keyword));
    }
  }

  if (current.has_value()) {
    throw FixtureError(line_number, "unterminated case " + current->id);
  }
  if (!has_declared) {
    throw FixtureError(line_number, "fixture does not declare META cases=<n>");
  }

  *declared_cases = declared;
  return cases;
}

const char* verdict(bool accept) { return accept ? "accept" : "reject"; }

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: secp256k1_differential <vectors.txt>\n";
    return 2;
  }

  std::vector<Case> cases;
  std::size_t declared_cases = 0;
  try {
    cases = load_fixture(argv[1], &declared_cases);
  } catch (const FixtureError& error) {
    std::cerr << argv[1] << ": " << error << "\n";
    return 2;
  }

  if (cases.size() != declared_cases) {
    std::cerr << argv[1] << ": META cases=" << declared_cases << " but " << cases.size()
              << " cases were parsed\n";
    return 2;
  }

  zk::differential::Secp256k1Verifier verifier;

  std::size_t failures = 0;
  std::size_t adapter_divergences = 0;

  for (const Case& test : cases) {
    zk::Hash256 digest{};
    std::copy(test.digest.begin(), test.digest.end(), digest.bytes.begin());

    const std::uint8_t* der = test.der.empty() ? nullptr : test.der.data();
    const std::uint8_t* public_key =
        test.public_key.empty() ? nullptr : test.public_key.data();

    const bool seam = verifier.verify(digest, der, test.der.size(), public_key,
                                      test.public_key.size());
    const bool backend = verifier.backend_verify(digest, der, test.der.size(), public_key,
                                                 test.public_key.size());

    const bool matched = seam == test.rust_accept;
    if (!matched) {
      ++failures;
    }
    if (backend != seam) {
      ++adapter_divergences;
    }

    std::cout << "CASE " << test.id << " group=" << test.group
              << " rust=" << verdict(test.rust_accept) << " seam=" << verdict(seam)
              << " backend=" << verdict(backend) << " match=" << (matched ? "yes" : "no")
              << " adapter=" << (backend == seam ? "faithful" : "load-bearing") << "\n";
  }

  std::cout << "SUMMARY cases=" << cases.size() << " failures=" << failures
            << " adapter_divergences=" << adapter_divergences << "\n";

  return failures == 0 ? 0 : 1;
}
