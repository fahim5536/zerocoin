#include "test_framework.h"

#include "zerocoin/hash.h"
#include "zerocoin/hex.h"

#include <cstdint>
#include <string>
#include <vector>

namespace {

std::string internal_hex(const zk::Hash256& hash) { return hash.to_hex().str(); }
std::string display_hex(const zk::Hash256& hash) { return hash.to_display_hex().str(); }
std::string internal_hex(const zk::Hash160& hash) { return hash.to_hex().str(); }

zk::Hash160 hash160_of_hex(const std::string& text) {
  const auto bytes = zk::from_hex(text);
  ZK_CHECK(bytes.has_value());
  return zk::hash160(bytes->data(), bytes->size());
}

}  // namespace

// FIPS 180-4 / NIST CAVP published vectors. These are checked independently of
// the port: if SHA-256 is wrong here, every hash in the node is wrong.

ZK_TEST(sha256_of_empty_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::sha256("").data(), 32) ==
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

ZK_TEST(sha256_of_abc_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::sha256("abc").data(), 32) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

ZK_TEST(sha256_of_the_56_byte_vector_crosses_into_two_blocks) {
  const std::string text =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  ZK_CHECK(text.size() == 56);
  ZK_CHECK(zk::to_hex(zk::sha256(text).data(), 32) ==
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

ZK_TEST(sha256_of_the_112_byte_vector_crosses_into_three_blocks) {
  const std::string text =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
      "klmnopqrlmnopqrsmnopqrstnopqrstu";
  ZK_CHECK(text.size() == 112);
  ZK_CHECK(zk::to_hex(zk::sha256(text).data(), 32) ==
           "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

ZK_TEST(sha256_of_a_million_a) {
  const std::string text(1'000'000, 'a');
  ZK_CHECK(zk::to_hex(zk::sha256(text).data(), 32) ==
           "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// The RIPEMD-160 reference vectors from the algorithm's specification.

ZK_TEST(ripemd160_of_empty_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::ripemd160("").data(), 20) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
}

ZK_TEST(ripemd160_of_a_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::ripemd160("a").data(), 20) == "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
}

ZK_TEST(ripemd160_of_abc_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::ripemd160("abc").data(), 20) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

ZK_TEST(ripemd160_of_message_digest_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::ripemd160("message digest").data(), 20) ==
           "5d0689ef49d2fae572b881b123a85ffa21595f36");
}

ZK_TEST(ripemd160_of_the_alphabet_is_the_published_vector) {
  ZK_CHECK(zk::to_hex(zk::ripemd160("abcdefghijklmnopqrstuvwxyz").data(), 20) ==
           "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
}

ZK_TEST(ripemd160_of_the_56_byte_vector_crosses_into_two_blocks) {
  const std::string text =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  ZK_CHECK(zk::to_hex(zk::ripemd160(text).data(), 20) ==
           "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
}

ZK_TEST(ripemd160_of_the_80_byte_vector_crosses_into_two_blocks) {
  const std::string text =
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
  ZK_CHECK(text.size() == 80);
  ZK_CHECK(zk::to_hex(zk::ripemd160(text).data(), 20) ==
           "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
}

ZK_TEST(ripemd160_of_a_million_a) {
  const std::string text(1'000'000, 'a');
  ZK_CHECK(zk::to_hex(zk::ripemd160(text).data(), 20) ==
           "52783243c1697bdbe16d37f97f68f08325dc1528");
}

// Composite primitives: the two the ledger actually uses.

ZK_TEST(sha256d_of_empty_is_the_published_vector) {
  const zk::Hash256 hash = zk::sha256d("");
  ZK_CHECK(internal_hex(hash) ==
           "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
  ZK_CHECK(display_hex(hash) ==
           "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d");
}

ZK_TEST(sha256d_reverses_for_display_only) {
  const zk::Hash256 hash = zk::sha256d("zerocoin");
  ZK_CHECK(internal_hex(hash) ==
           "67adc27c1d4348d0d1db35a04c1f9e8dceb7629a772617c18d614b9e86fec5f4");
  ZK_CHECK(display_hex(hash) ==
           "f4c5fe869e4b618dc11726779a62b7ce8d9e1f4ca035dbd1d048431d7cc2ad67");
  ZK_CHECK(hash.to_display_hex().internal_bytes() == hash.bytes);
}

ZK_TEST(hash160_of_the_privkey_one_pubkey) {
  const zk::Hash160 hash =
      hash160_of_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  ZK_CHECK(internal_hex(hash) == "751e76e8199196d454941c45d1b3a323f1433bd6");
}

ZK_TEST(hash160_of_empty_is_ripemd160_of_sha256_of_empty) {
  const zk::Hash160 hash = zk::hash160("");
  ZK_CHECK(internal_hex(hash) == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
}

ZK_TEST(hash160_is_not_truncated_sha256) {
  const zk::Hash160 hash = zk::hash160("zerocoin");
  const auto sha = zk::sha256("zerocoin");
  const std::vector<std::uint8_t> first20(sha.begin(), sha.begin() + 20);
  ZK_CHECK(zk::to_hex(first20.data(), first20.size()) != internal_hex(hash));
}

ZK_TEST(hash_types_reject_the_all_zero_sentinel) {
  ZK_CHECK(zk::Hash256::zero().is_zero());
  ZK_CHECK(!zk::sha256d("").is_zero());
  ZK_CHECK(zk::Hash160::zero().is_zero());
  ZK_CHECK(!zk::hash160("").is_zero());
}

ZK_TEST(hash_string_view_and_pointer_overloads_agree) {
  const std::string text = "zerocoin";
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(text.data());
  ZK_CHECK(zk::sha256(text) == zk::sha256(bytes, text.size()));
  ZK_CHECK(zk::ripemd160(text) == zk::ripemd160(bytes, text.size()));
  ZK_CHECK(zk::sha256d(text) == zk::sha256d(bytes, text.size()));
  ZK_CHECK(zk::hash160(text) == zk::hash160(bytes, text.size()));
}
