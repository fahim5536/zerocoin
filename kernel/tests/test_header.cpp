// Block-header preimage and identity tests. The corpus in
// test/p31-vectors/chain/ is the value oracle (kernel/tools/p31_conformance.py
// replays it byte for byte); these tests pin the structure the corpus cannot
// express on its own: the exact offset of each field, the direction of each
// byte order, the non-appendable nonce, and which side of the precedence the
// validator takes. Nothing here copies an expected preimage from a fixture —
// the values are chosen locally and their little-endian encodings written out
// by hand, so an offset or endianness mistake shows up as a disagreement
// between this file and header.cpp rather than in both at once.

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <string>

#include "test_framework.h"
#include "zerocoin/header.h"

namespace {

using zk::BlockErrorKind;
using zk::BlockHeader;
using zk::Hash256;
using Preimage = std::array<std::uint8_t, zk::kHeaderPreimageSize>;

// The contract positions, written out from the layout in
// CPP_PORT_REQUIREMENTS.md C-3 rather than derived from the implementation.
constexpr std::size_t kTag = 0;
constexpr std::size_t kVersion = 14;
constexpr std::size_t kChain = 18;
constexpr std::size_t kHeight = 22;
constexpr std::size_t kPreviousHash = 30;
constexpr std::size_t kMerkleRoot = 62;
constexpr std::size_t kTimestamp = 94;
constexpr std::size_t kBits = 102;
constexpr std::size_t kEngineId = 106;

// A header whose fields are pairwise distinct and whose bytes are all
// different from one another, so a value written at the wrong offset or in the
// wrong order cannot accidentally match the assertion. The nonce is deliberately
// built from bytes no field uses.
BlockHeader probe_header() {
  BlockHeader header{};
  header.version = 0x0403'0201u;
  header.chain = 0x0807'0605u;
  header.height = 0x100f'0e0d'0c0b'0a09ull;
  for (std::size_t i = 0; i < Hash256::kWidth; ++i) {
    header.previous_hash.bytes[i] = static_cast<std::uint8_t>(i + 1);
    header.merkle_root.bytes[i] = static_cast<std::uint8_t>(Hash256::kWidth - i);
  }
  header.timestamp = 0x201f'1e1d'1c1b'1a19ull;
  header.difficulty_bits = 0x2827'2625u;
  header.engine_id = 0x29;
  header.nonce = 0xfefd'fcfb'faf9'f8f7ull;
  return header;
}

void expect_bytes(const Preimage& preimage, std::size_t offset,
                  std::initializer_list<std::uint8_t> expected) {
  ZK_CHECK(offset + expected.size() <= preimage.size());
  std::size_t index = 0;
  for (const std::uint8_t byte : expected) {
    ZK_CHECK(preimage[offset + index] == byte);
    ++index;
  }
}

Hash256 digest_with_corners() {
  // Set by index rather than as a 32-byte literal: a miscounted list would
  // silently change the byte the assertion is about.
  Hash256 hash = Hash256::zero();
  hash.bytes[0] = 0xff;
  hash.bytes[2] = 0x80;
  hash.bytes[Hash256::kWidth - 1] = 0x01;
  return hash;
}

}  // namespace

ZK_TEST(header_preimage_is_107_bytes_behind_the_frozen_tag) {
  const Preimage preimage = zk::header_preimage(probe_header());
  ZK_CHECK(preimage.size() == 107);
  expect_bytes(preimage, kTag,
               {'Z', 'R', 'O', '/', 'h', 'e', 'a', 'd', 'e', 'r', '/', 'v', '1', 0});
  // The NUL is part of the tag, not a separator that the version overwrites.
  ZK_CHECK(preimage[13] == 0);
  ZK_CHECK(preimage[kVersion] == 0x01);
}

ZK_TEST(header_preimage_orders_every_integer_little_endian) {
  const Preimage preimage = zk::header_preimage(probe_header());
  expect_bytes(preimage, kVersion, {0x01, 0x02, 0x03, 0x04});
  expect_bytes(preimage, kChain, {0x05, 0x06, 0x07, 0x08});
  expect_bytes(preimage, kHeight, {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10});
  expect_bytes(preimage, kTimestamp, {0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20});
  expect_bytes(preimage, kBits, {0x25, 0x26, 0x27, 0x28});
  expect_bytes(preimage, kEngineId, {0x29});
}

ZK_TEST(header_preimage_copies_the_digests_in_stored_order) {
  const Preimage preimage = zk::header_preimage(probe_header());
  // Ascending in, ascending out: no reversal into the display form, no length
  // prefix, no padding between the two 32-byte fields.
  std::array<std::uint8_t, Hash256::kWidth> ascending{};
  std::array<std::uint8_t, Hash256::kWidth> descending{};
  for (std::size_t i = 0; i < Hash256::kWidth; ++i) {
    ascending[i] = static_cast<std::uint8_t>(i + 1);
    descending[i] = static_cast<std::uint8_t>(Hash256::kWidth - i);
    ZK_CHECK(preimage[kPreviousHash + i] == ascending[i]);
    ZK_CHECK(preimage[kMerkleRoot + i] == descending[i]);
  }
  // The first digest byte is 0x01 and its last is 0x20; a reversed copy would
  // put 0x20 first. Same for the root, in the other direction.
  ZK_CHECK(preimage[kPreviousHash] == 0x01 && preimage[kPreviousHash + 31] == 0x20);
  ZK_CHECK(preimage[kMerkleRoot] == 0x20 && preimage[kMerkleRoot + 31] == 0x01);
}

ZK_TEST(header_preimage_high_bit_and_maxima_stay_unsigned) {
  BlockHeader header = probe_header();
  header.version = 0x8000'0001u;
  header.chain = 0x8000'0002u;
  header.height = 0x8000'0000'0000'0003ull;
  header.timestamp = 0x8000'0000'0000'0004ull;
  header.difficulty_bits = 0x8000'0005u;
  const Preimage set = zk::header_preimage(header);
  // C-12: the top bit lands in the most significant byte of its own field and
  // nothing above it, which a sign-extended or narrowed write would break.
  expect_bytes(set, kVersion, {0x01, 0x00, 0x00, 0x80});
  expect_bytes(set, kChain, {0x02, 0x00, 0x00, 0x80});
  expect_bytes(set, kHeight, {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80});
  expect_bytes(set, kTimestamp, {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80});
  expect_bytes(set, kBits, {0x05, 0x00, 0x00, 0x80});

  header.version = 0xffff'ffffu;
  header.chain = 0xffff'ffffu;
  header.height = UINT64_MAX;
  header.timestamp = UINT64_MAX;
  header.difficulty_bits = 0xffff'ffffu;
  const Preimage maxed = zk::header_preimage(header);
  expect_bytes(maxed, kVersion, {0xff, 0xff, 0xff, 0xff});
  expect_bytes(maxed, kChain, {0xff, 0xff, 0xff, 0xff});
  expect_bytes(maxed, kHeight, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  expect_bytes(maxed, kTimestamp, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  expect_bytes(maxed, kBits, {0xff, 0xff, 0xff, 0xff});
  expect_bytes(maxed, kEngineId, {0x29});
  ZK_CHECK(maxed.size() == 107);

  // All-zero is a distinct encoding, not the empty one.
  const BlockHeader zero{};
  const Preimage zeroed = zk::header_preimage(zero);
  ZK_CHECK(zeroed.size() == 107);
  expect_bytes(zeroed, kVersion, {0, 0, 0, 0});
  expect_bytes(zeroed, kHeight, {0, 0, 0, 0, 0, 0, 0, 0});
  ZK_CHECK(zeroed[kEngineId] == 0);
}

ZK_TEST(header_preimage_engine_id_spans_its_whole_range) {
  BlockHeader header = probe_header();
  header.engine_id = 0;
  const Preimage low = zk::header_preimage(header);
  header.engine_id = 1;
  const Preimage one = zk::header_preimage(header);
  header.engine_id = 255;
  const Preimage high = zk::header_preimage(header);
  ZK_CHECK(low[kEngineId] == 0x00 && low.size() == 107);
  ZK_CHECK(one[kEngineId] == 0x01 && one.size() == 107);
  // The last field, so 0xff here must not spill into a 108th byte.
  ZK_CHECK(high[kEngineId] == 0xff && high.size() == 107);
  // Only that one byte differs across the range.
  for (std::size_t i = 0; i < 106; ++i) {
    ZK_CHECK(low[i] == high[i]);
  }
}

ZK_TEST(header_preimage_excludes_the_nonce) {
  const std::uint64_t nonces[] = {0ull, 1ull, 42ull, 0x0102'0304'0506'0708ull, UINT64_MAX};
  BlockHeader base = probe_header();
  base.nonce = 0;
  const Preimage reference = zk::header_preimage(base);
  for (const std::uint64_t nonce : nonces) {
    base.nonce = nonce;
    const Preimage varied = zk::header_preimage(base);
    ZK_CHECK(varied == reference);
    ZK_CHECK(varied.size() == 107);
  }
  // The encoder must not merely ignore the size: the nonce bytes themselves
  // appear nowhere in the output, so nothing appended them. The canary nonce is
  // built from bytes no other field uses, which is what makes this unambiguous —
  // a nonce of 0x0102...08 would be found in the ascending previous hash.
  const std::array<std::uint8_t, 8> pattern = {0xf7, 0xf8, 0xf9, 0xfa,
                                               0xfb, 0xfc, 0xfd, 0xfe};
  const Preimage probed = zk::header_preimage(probe_header());
  ZK_CHECK(std::search(probed.begin(), probed.end(), pattern.begin(), pattern.end()) ==
           probed.end());
  // Two headers differing only in the nonce share one identity preimage; the
  // engine is what separates them, and it is not ported here (C-4).
  BlockHeader left = probe_header();
  BlockHeader right = probe_header();
  left.nonce = 0;
  right.nonce = UINT64_MAX;
  ZK_CHECK(left != right);
  ZK_CHECK(zk::header_preimage(left) == zk::header_preimage(right));
}

ZK_TEST(header_preimage_hashes_keep_their_high_bit_position) {
  BlockHeader header = probe_header();
  header.previous_hash = digest_with_corners();
  header.merkle_root = Hash256::zero();
  const Preimage preimage = zk::header_preimage(header);
  ZK_CHECK(preimage[kPreviousHash] == 0xff);
  ZK_CHECK(preimage[kPreviousHash + 2] == 0x80);
  ZK_CHECK(preimage[kPreviousHash + 31] == 0x01);
  // The zero root stays 32 zero bytes; 0x00 elsewhere is not a terminator.
  for (std::size_t i = 0; i < Hash256::kWidth; ++i) {
    ZK_CHECK(preimage[kMerkleRoot + i] == 0);
  }
}

ZK_TEST(header_identity_accepts_a_matching_chain_and_height) {
  BlockHeader header = probe_header();
  header.chain = 1'515'343'616u;  // regtest
  header.height = 1;
  const zk::BlockIdentityError ok = zk::validate_header_identity(header, 1'515'343'616u, 1);
  ZK_CHECK(ok.ok());
  ZK_CHECK(!ok.has_payload());
  ZK_CHECK(ok.kind == BlockErrorKind::kNone);
  ZK_CHECK(std::string(zk::block_error_kind_name(ok.kind)) == "None");
  // Height zero is a real height, and it must match an expected zero rather
  // than being mistaken for an unset field.
  BlockHeader genesis = probe_header();
  genesis.chain = 1'515'343'616u;
  genesis.height = 0;
  ZK_CHECK(zk::validate_header_identity(genesis, 1'515'343'616u, 0).ok());
}

ZK_TEST(header_identity_chain_is_tested_before_height) {
  BlockHeader header = probe_header();
  header.chain = 1'515'343'617u;  // mainnet
  header.height = 7;
  // C-29: a header wrong about both is `WrongChain`. Reaching `BadHeight` here
  // would mean the kernel computed a schedule from an unvalidated height.
  const zk::BlockIdentityError both = zk::validate_header_identity(header, 1'515'343'616u, 9);
  ZK_CHECK(both.kind == BlockErrorKind::kWrongChain);
  ZK_CHECK(!both.ok());
  ZK_CHECK(both.has_payload());
  ZK_CHECK(std::string(zk::block_error_kind_name(both.kind)) == "WrongChain");
  ZK_CHECK(both.expected_chain == 1'515'343'616u);
  ZK_CHECK(both.found_chain == 1'515'343'617u);
  // The height is never read once the chain disagrees, so the height pair stays
  // at its initialised value rather than leaking the rejected one.
  ZK_CHECK(both.expected_height == 0 && both.found_height == 0);
}

ZK_TEST(header_identity_reports_bad_height_with_unsigned_payloads) {
  BlockHeader header = probe_header();
  header.chain = 1'515'343'616u;
  header.height = 1;
  const zk::BlockIdentityError low = zk::validate_header_identity(header, 1'515'343'616u, 2);
  ZK_CHECK(low.kind == BlockErrorKind::kBadHeight);
  ZK_CHECK(low.has_payload());
  ZK_CHECK(std::string(zk::block_error_kind_name(low.kind)) == "BadHeight");
  ZK_CHECK(low.expected_height == 2 && low.found_height == 1);
  ZK_CHECK(low.expected_chain == 0 && low.found_chain == 0);

  // A found height above the expected one is the same variant, not a special
  // case, and both payloads stay unsigned.
  const zk::BlockIdentityError high = zk::validate_header_identity(header, 1'515'343'616u, 0);
  ZK_CHECK(high.kind == BlockErrorKind::kBadHeight);
  ZK_CHECK(high.expected_height == 0 && high.found_height == 1);
  ZK_CHECK(std::to_string(high.found_height) == "1");
}

ZK_TEST(header_identity_height_zero_and_maximum_boundaries) {
  BlockHeader header = probe_header();
  header.chain = 1'515'343'616u;
  header.height = 0;
  ZK_CHECK(zk::validate_header_identity(header, 1'515'343'616u, 0).ok());
  const zk::BlockIdentityError from_zero = zk::validate_header_identity(header, 1'515'343'616u, 1);
  ZK_CHECK(from_zero.kind == BlockErrorKind::kBadHeight);
  ZK_CHECK(from_zero.expected_height == 1 && from_zero.found_height == 0);
  ZK_CHECK(std::to_string(from_zero.found_height) == "0");

  header.height = UINT64_MAX;
  ZK_CHECK(zk::validate_header_identity(header, 1'515'343'616u, UINT64_MAX).ok());
  const zk::BlockIdentityError at_max = zk::validate_header_identity(header, 1'515'343'616u, 1);
  ZK_CHECK(at_max.kind == BlockErrorKind::kBadHeight);
  ZK_CHECK(at_max.found_height == UINT64_MAX);
  // C-12: rendered as the reference renders it, not as a signed value.
  ZK_CHECK(std::to_string(at_max.found_height) == "18446744073709551615");
}

ZK_TEST(header_identity_chain_payloads_span_the_unsigned_range) {
  BlockHeader header = probe_header();
  header.chain = 4'294'967'295u;
  header.height = 1;
  const zk::BlockIdentityError max_found = zk::validate_header_identity(header, 1'515'343'616u, 1);
  ZK_CHECK(max_found.kind == BlockErrorKind::kWrongChain);
  ZK_CHECK(max_found.expected_chain == 1'515'343'616u);
  ZK_CHECK(max_found.found_chain == 0xffff'ffffu);
  ZK_CHECK(std::to_string(max_found.found_chain) == "4294967295");

  header.chain = 0;
  const zk::BlockIdentityError zero_found = zk::validate_header_identity(header, 1'515'343'616u, 1);
  ZK_CHECK(zero_found.kind == BlockErrorKind::kWrongChain);
  ZK_CHECK(zero_found.found_chain == 0);
  ZK_CHECK(std::to_string(zero_found.found_chain) == "0");
}

ZK_TEST(header_error_kind_names_are_the_reference_variant_names) {
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kNone)) == "None");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kWrongChain)) == "WrongChain");
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kBadHeight)) == "BadHeight");
  // The name B-14's fixture asserts. It is the reference's variant name, so a
  // rename in block.rs is a disagreement here rather than a silent pass.
  ZK_CHECK(std::string(zk::block_error_kind_name(BlockErrorKind::kRootMismatch)) == "RootMismatch");

  // The kernel's own numbering, frozen: 0 means accepted and every existing
  // value keeps its slot, so a newly ported variant is appended and never
  // inserted. These are declaration order, NOT the Rust discriminants.
  static_assert(static_cast<std::uint8_t>(BlockErrorKind::kNone) == 0);
  static_assert(static_cast<std::uint8_t>(BlockErrorKind::kWrongChain) == 1);
  static_assert(static_cast<std::uint8_t>(BlockErrorKind::kBadHeight) == 2);
  static_assert(static_cast<std::uint8_t>(BlockErrorKind::kRootMismatch) == 3);

  // The payload question is per variant (C-12). The two identity variants carry
  // numbers; `RootMismatch` is a unit variant in the reference and `None` is not
  // a rejection at all, so answering it from the struct's shape would let the
  // runner publish a payload that the reference publishes as null.
  ZK_CHECK(!zk::block_error_kind_has_payload(BlockErrorKind::kNone));
  ZK_CHECK(zk::block_error_kind_has_payload(BlockErrorKind::kWrongChain));
  ZK_CHECK(zk::block_error_kind_has_payload(BlockErrorKind::kBadHeight));
  ZK_CHECK(!zk::block_error_kind_has_payload(BlockErrorKind::kRootMismatch));

  // And the member agrees with the free function for every variant, including a
  // default-constructed one.
  const zk::BlockIdentityError default_error{};
  ZK_CHECK(default_error.has_payload() == zk::block_error_kind_has_payload(default_error.kind));
  zk::BlockIdentityError mismatch{};
  mismatch.kind = BlockErrorKind::kRootMismatch;
  ZK_CHECK(!mismatch.has_payload());
}
