// Test-only runner for the P2.10 deterministic DER parity check (blocker CB-1).
//
// It signs the committed `ledger.sighash.signature_der` inputs with the vendored
// libsecp256k1 v0.8.0 through `Secp256k1Signer` — exactly the RFC 6979 + DER
// surface `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md` §19.2
// prescribes — and compares the output byte for byte with the corpus bytes the
// pinned Rust reference committed (k256 0.13.4; corpus provenance
// `source_commit 7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c`). The expected value
// below is transcribed from `test/vectors/ledger/sighash.json`, never from this
// library: if the two implementations disagree, the first differing byte is
// reported and the run fails. The reference vector is never edited to make the
// implementations appear equivalent.
//
// Beyond the parity check itself:
//   * repeatability — the same inputs are signed three times, the third through
//     a fresh signer instance (a fresh context), and every run must produce
//     identical bytes; the `SIGNATURE der_hex=` line makes two process runs
//     comparable byte for byte as well;
//   * equation and low-S anchors — the produced bytes and the committed bytes
//     both parse as strict DER, verify against the generator (the public key of
//     scalar 1) over the corpus digest, and are already in low-S form;
//   * malformed inputs — through the adapter, null pointers, wrong lengths and
//     invalid secret scalars (0 and the group order) all fail closed; through
//     the underlying API, invalid secret scalars and an undersized serializer
//     buffer fail closed too. Null arguments are exercised only through the
//     adapter: the vendored header declares the raw API's pointer parameters
//     `SECP256K1_ARG_NONNULL` for consumers, so a null call there would be
//     outside the declared contract, not a negative control of it.
//
// Usage: secp256k1_der_signing
// Exit codes: 0 every check passed, 1 at least one check failed.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <secp256k1.h>

#include "secp256k1_signer.h"

namespace {

// The committed `ledger.sighash.signature_der` digest (`internal_hex` in
// `test/vectors/ledger/sighash.json`): the production sighash of the corpus
// regtest transaction. It is below the group order, so both libraries use it
// as the ECDSA `z` unchanged.
constexpr std::uint8_t kCorpusDigest[32] = {
    0xe0, 0xe7, 0xce, 0x17, 0x6c, 0x2a, 0xa8, 0x07,
    0x73, 0x78, 0x29, 0x9f, 0x68, 0x2b, 0xae, 0xc2,
    0x3e, 0x02, 0xab, 0xc2, 0x89, 0xb5, 0x1f, 0xa1,
    0x89, 0x5b, 0x7c, 0xde, 0x9c, 0xe6, 0xa2, 0x37,
};

// The corpus key convention: `scalar: 1` is a 32-byte big-endian secret with
// the scalar in the least-significant position. Public, fixed, never secret.
constexpr std::uint8_t kScalarOne[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

// The compressed encoding of the generator G — the public key of scalar 1, and
// the anchor `zerocoin/tests/s5_boundary_probes.rs` pins.
constexpr std::uint8_t kGeneratorCompressed[33] = {
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
    0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
    0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
};

// The committed expected output (`expected.der_hex`): 71 bytes, low-S, produced
// by the pinned Rust reference. Not transcribed from any C++ output.
constexpr std::size_t kExpectedDerSize = 71;
constexpr std::uint8_t kExpectedDer[kExpectedDerSize] = {
    0x30, 0x45,
    0x02, 0x21, 0x00, 0x96, 0xb2, 0x2d, 0xdd, 0xb2, 0xb9, 0x3b, 0x4e, 0xb6,
    0xa4, 0xa6, 0x49, 0xee, 0x12, 0x6c, 0x44, 0x93, 0xa8, 0x18, 0x55, 0x25,
    0x7b, 0x03, 0x75, 0x8c, 0x57, 0x35, 0xa0, 0x52, 0xff, 0xee, 0x89,
    0x02, 0x20, 0x19, 0x9b, 0x56, 0xaa, 0x20, 0x60, 0x63, 0xc8, 0x15, 0xca,
    0x73, 0x1c, 0x21, 0x93, 0xc1, 0xa6, 0x6d, 0x0d, 0xa0, 0x5f, 0x80, 0x45,
    0xd7, 0x24, 0x21, 0x45, 0xdb, 0xa3, 0x65, 0xdc, 0x3a, 0x4f,
};

// The two secret scalars the library must reject: 0, and the group order n
// (`scalar_set_b32_seckey` fails for both, so `secp256k1_ecdsa_sign` returns 0).
constexpr std::uint8_t kZeroKey[32] = {};
constexpr std::uint8_t kOrderKey[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

std::string hex(const std::uint8_t* bytes, std::size_t size) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(digits[bytes[i] >> 4]);
    out.push_back(digits[bytes[i] & 0x0f]);
  }
  return out;
}

class Checks {
 public:
  void add(bool ok, const std::string& name, const std::string& detail = {}) {
    ++total_;
    if (!ok) {
      ++failures_;
    }
    std::cout << (ok ? "[ok]   " : "[FAIL] ") << name;
    if (!ok && !detail.empty()) {
      std::cout << " — " << detail;
    }
    std::cout << "\n";
  }

  int total() const { return total_; }
  int failures() const { return failures_; }

 private:
  int total_ = 0;
  int failures_ = 0;
};

/// Points at the first differing byte, or at the length difference, so a parity
/// failure is diagnosable without a debugger.
std::string first_difference(const std::vector<std::uint8_t>& produced,
                             const std::uint8_t* expected, std::size_t size) {
  const std::size_t common = std::min(produced.size(), size);
  for (std::size_t i = 0; i < common; ++i) {
    if (produced[i] != expected[i]) {
      return "first difference at byte " + std::to_string(i) + ": produced 0x" +
             hex(&produced[i], 1) + ", expected 0x" + hex(&expected[i], 1);
    }
  }
  if (produced.size() != size) {
    return "length differs: produced " + std::to_string(produced.size()) +
           " bytes, expected " + std::to_string(size);
  }
  return "identical";
}

/// Strict-parse, low-S and equation anchors for one DER blob (produced or
/// committed). Every verdict comes from the library itself, so a byte-equal
/// result can never be an artifact of this runner's own parsing.
void anchor_checks(Checks& checks, const std::string& label,
                   const std::uint8_t* der, std::size_t der_size) {
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  secp256k1_ecdsa_signature signature;
  const bool parsed = ctx != nullptr &&
      secp256k1_ecdsa_signature_parse_der(ctx, &signature, der, der_size) == 1;
  checks.add(parsed, label + "_der_parses_strictly");
  if (!parsed) {
    secp256k1_context_destroy(ctx);
    return;
  }
  // `secp256k1_ecdsa_signature_normalize` returns whether the *input* was
  // high-S; zero means the signature is already in low-S form.
  checks.add(secp256k1_ecdsa_signature_normalize(ctx, nullptr, &signature) == 0,
             label + "_der_is_already_low_s");
  secp256k1_pubkey generator;
  const bool key_parsed = secp256k1_ec_pubkey_parse(
                              ctx, &generator, kGeneratorCompressed,
                              sizeof(kGeneratorCompressed)) == 1;
  checks.add(key_parsed, label + "_generator_pubkey_parses");
  checks.add(key_parsed &&
                 secp256k1_ecdsa_verify(ctx, &signature, kCorpusDigest,
                                        &generator) == 1,
             label + "_der_verifies_against_the_generator_over_the_corpus_digest");
  secp256k1_context_destroy(ctx);
}

}  // namespace

int main() {
  Checks checks;
  const zk::differential::Secp256k1Signer signer;

  // 1. Byte-for-byte parity with the committed corpus value.
  const auto produced = signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest),
                                        kScalarOne, sizeof(kScalarOne));
  checks.add(produced.has_value(), "adapter_signs_corpus_inputs",
             "sign_der returned nullopt");
  const std::vector<std::uint8_t> expected(kExpectedDer,
                                           kExpectedDer + kExpectedDerSize);
  if (produced.has_value()) {
    std::cout << "SIGNATURE der_hex=" << hex(produced->data(), produced->size())
              << "\n";
    checks.add(produced->size() == kExpectedDerSize, "der_length_is_71",
               "produced " + std::to_string(produced->size()) + " bytes");
    checks.add(*produced == expected,
               "der_bytes_match_the_committed_corpus_value",
               first_difference(*produced, kExpectedDer, kExpectedDerSize));

    // 2. Deterministic repeatability: same inputs, same bytes, every run.
    for (int run = 2; run <= 3; ++run) {
      const auto again = signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest),
                                         kScalarOne, sizeof(kScalarOne));
      checks.add(again.has_value() && *again == *produced,
                 "repeat_run_" + std::to_string(run) + "_is_identical",
                 again ? first_difference(*again, produced->data(),
                                          produced->size())
                       : "sign_der returned nullopt");
    }
    const zk::differential::Secp256k1Signer second;  // a fresh context
    const auto independent = second.sign_der(kCorpusDigest, sizeof(kCorpusDigest),
                                             kScalarOne, sizeof(kScalarOne));
    checks.add(independent.has_value() && *independent == *produced,
               "fresh_context_run_is_identical",
               independent ? first_difference(*independent, produced->data(),
                                              produced->size())
                           : "sign_der returned nullopt");

    // 3. Anchors for the produced bytes.
    anchor_checks(checks, "produced", produced->data(), produced->size());
  }

  // The committed bytes are anchored independently of the adapter: if the
  // fixture itself stopped parsing, verifying or being low-S, parity with it
  // would be meaningless.
  anchor_checks(checks, "committed", kExpectedDer, kExpectedDerSize);

  // 4. The library's public key for scalar 1 is the generator, so the anchor
  // key and the corpus key are the same key.
  {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey public_key;
    std::uint8_t serialized[33] = {};
    std::size_t serialized_size = sizeof(serialized);
    const bool ok = ctx != nullptr &&
        secp256k1_ec_pubkey_create(ctx, &public_key, kScalarOne) == 1 &&
        secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_size,
                                      &public_key, SECP256K1_EC_COMPRESSED) == 1 &&
        serialized_size == sizeof(kGeneratorCompressed) &&
        std::equal(serialized, serialized + serialized_size, kGeneratorCompressed);
    checks.add(ok, "scalar_one_public_key_is_the_generator");
    secp256k1_context_destroy(ctx);
  }

  // 5. Malformed inputs fail closed through the adapter.
  checks.add(!signer.sign_der(nullptr, sizeof(kCorpusDigest), kScalarOne,
                              sizeof(kScalarOne))
                  .has_value(),
             "adapter_rejects_null_digest");
  checks.add(!signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest) - 1,
                              kScalarOne, sizeof(kScalarOne))
                  .has_value(),
             "adapter_rejects_short_digest");
  checks.add(!signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest), nullptr,
                              sizeof(kScalarOne))
                  .has_value(),
             "adapter_rejects_null_seckey");
  checks.add(!signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest), kScalarOne,
                              sizeof(kScalarOne) - 1)
                  .has_value(),
             "adapter_rejects_short_seckey");
  checks.add(!signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest), kZeroKey,
                              sizeof(kZeroKey))
                  .has_value(),
             "adapter_rejects_zero_seckey");
  checks.add(!signer.sign_der(kCorpusDigest, sizeof(kCorpusDigest), kOrderKey,
                              sizeof(kOrderKey))
                  .has_value(),
             "adapter_rejects_overflow_seckey");

  // 6. The library contract the adapter relies on, restricted to inputs the
  // vendored header allows: invalid secret scalars fail signing, and the
  // serializer reports its required size on an undersized buffer. NULL
  // arguments are deliberately NOT fed to the raw API — the header marks its
  // pointer parameters `SECP256K1_ARG_NONNULL` for consumers — so null
  // rejection is the adapter's own responsibility, proven by the checks above.
  // A local context, not the adapter's private one.
  {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    checks.add(ctx != nullptr, "raw_api_context_created");
    if (ctx != nullptr) {
      secp256k1_ecdsa_signature signature;
      const bool signed_ok =
          secp256k1_ecdsa_sign(ctx, &signature, kCorpusDigest, kScalarOne,
                               nullptr, nullptr) == 1;
      checks.add(signed_ok, "raw_api_signs_corpus_inputs");
      checks.add(secp256k1_ecdsa_sign(ctx, &signature, kCorpusDigest, kZeroKey,
                                      nullptr, nullptr) == 0,
                 "raw_api_rejects_zero_seckey");
      checks.add(secp256k1_ecdsa_sign(ctx, &signature, kCorpusDigest, kOrderKey,
                                      nullptr, nullptr) == 0,
                 "raw_api_rejects_overflow_seckey");
      if (signed_ok) {
        // The two negative controls above deliberately left `signature`
        // holding the zeroed object the library writes when signing fails
        // (observed: it serializes to the 8-byte R=S=0 form, so it can never
        // verify). The serialization checks need the corpus signature, so it
        // is signed fresh here.
        secp256k1_ecdsa_signature corpus_signature;
        checks.add(
            secp256k1_ecdsa_sign(ctx, &corpus_signature, kCorpusDigest,
                                 kScalarOne, nullptr, nullptr) == 1,
            "raw_api_re_signs_corpus_inputs");
        std::uint8_t der[72];
        std::size_t der_size = kExpectedDerSize - 1;  // one byte too small
        const int fit = secp256k1_ecdsa_signature_serialize_der(
            ctx, der, &der_size, &corpus_signature);
        // `secp256k1_ecdsa_sig_serialize` reports the required size on failure.
        checks.add(fit == 0 && der_size == kExpectedDerSize,
                   "serializer_reports_required_size_on_undersized_output",
                   "returned " + std::to_string(fit) + ", size " +
                       std::to_string(der_size));
        der_size = sizeof(der);
        checks.add(secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_size,
                                                           &corpus_signature) == 1 &&
                       der_size == kExpectedDerSize &&
                       std::equal(der, der + der_size, kExpectedDer),
                   "raw_api_serializes_the_committed_bytes");
      }
      secp256k1_context_destroy(ctx);
    }
  }

  std::cout << "SUMMARY checks=" << checks.total()
            << " failures=" << checks.failures() << "\n";
  return checks.failures() == 0 ? 0 : 1;
}
