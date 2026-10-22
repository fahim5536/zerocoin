//! P2.7 — the `0x05` public-key encoding, pinned from parser to block.
//!
//! **THIS FILE RECORDS AN UNRESOLVED DIVERGENCE. IT DOES NOT DEFINE A CONTRACT.**
//!
//! `PublicKey::from_sec1` (`src/crypto/secp256k1.rs:112`) gates on length only and
//! delegates the tag decision to `k256`/`sec1`. `sec1` gives `0x05` the meaning
//! `Tag::Compact`, whose message length is one field element, so a 33-byte
//! `0x05 || x` parses and `k256` decompacts it as the point with **even** y — the
//! same point as `0x02 || x`. libsecp256k1 v0.8.0 accepts only `0x02`/`0x03` at
//! 33 bytes, so the two implementations disagree (the `V4.prefix_05` row in
//! `kernel/differential/vectors/ledger.sighash.differential.txt`).
//!
//! These tests exist to answer one question with evidence rather than inference:
//! can a `0x05` key reach the consensus decision, and if so, what exactly does it
//! let an attacker do? The answer they pin is:
//!
//! * it parses, and it verifies signatures as the `0x02` point (alias);
//! * it does **not** unlock a coin locked to `hash160(0x02 || x)`, because
//!   `key_hash` hashes the stored bytes and `OP_EQUALVERIFY` runs before
//!   `OP_CHECKSIG`;
//! * it *does* satisfy a coin locked to `hash160(0x05 || x)`, end to end.
//!
//! So the impact is "non-canonical encodings are accepted for coins that were
//! already locked with them", not "a signature forgery or a theft primitive".
//!
//! Such a coin does not have to be hand-built: a pool share carries its payout key
//! over the wire as a `PublicKey`, and the pool pays `payout.key_hash()` in the
//! split coinbase. A peer that submits a `0x05` payout therefore causes a
//! compact-locked output to exist on-chain without editing any local state. Spending
//! it still needs a hand-built scriptSig, because the wallet signs with the
//! canonical spelling derived from the secret.
//!
//! If a `divergence_pin_*` test fails, production parsing has changed. That is a
//! consensus decision, not a test fix: see the P2.7 addendum in
//! `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md` before touching either
//! side.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, EncodedPoint};
use zerocoin::chain::{Chain, ChainError};
use zerocoin::crypto::hash::Hash256;
use zerocoin::crypto::secp256k1::{CryptoError, PrivateKey, PublicKey, COMPRESSED_PUBKEY_LEN, SECRET_LEN};
use zerocoin::ledger::script::{
    p2pkh_script_pubkey, p2pkh_script_sig, verify, ScriptError,
};
use zerocoin::ledger::sighash::{signature_hash, ChainId, SIGHASH_ALL, TxSigChecker};
use zerocoin::ledger::transaction::{Outpoint, Transaction, TxIn, TxOut};
use zerocoin::ledger::utxo::UtxoError;
use zerocoin::params::{ChainParams, GENESIS_TIMESTAMP};

/// The chain id the fixtures sign against. Taken from the params rather than
/// restated, so a fixture can never disagree with the network it models.
fn chain_id() -> ChainId {
    ChainParams::regtest().chain_id
}

/// Deterministic fixture: one secret, its canonical compressed key, and the
/// disputed `0x05 || x` spelling of the same point.
struct Fixture {
    key: PrivateKey,
    canonical: PublicKey,
    compact_bytes: [u8; COMPRESSED_PUBKEY_LEN],
    compact: PublicKey,
}

fn fixture() -> Fixture {
    let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("seed 7 is a valid scalar");
    let canonical = key.public_key();
    let canonical_bytes = canonical.to_sec1();
    assert!(matches!(canonical_bytes[0], 0x02 | 0x03));

    let mut compact_bytes = [0u8; COMPRESSED_PUBKEY_LEN];
    compact_bytes[0] = 0x05;
    compact_bytes[1..].copy_from_slice(&canonical_bytes[1..]);
    let compact = PublicKey::from_sec1(&compact_bytes).expect("P2.7: accepted today, unresolved");

    Fixture {
        key,
        canonical,
        compact_bytes,
        compact,
    }
}

/// A one-input transaction whose `script_pubkey` doubles as the `script_code`.
fn locked_tx(script_code: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint {
                txid: Hash256([0x22; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: 1_000,
            script_pubkey: script_code.to_vec(),
        }],
        lock_time: 0,
    }
}

/// `<sig || SIGHASH_ALL> <pubkey_bytes>`, signed over `script_code`.
fn signed_script_sig(
    key: &PrivateKey,
    tx: &Transaction,
    script_code: &[u8],
    pubkey_bytes: &[u8],
    chain_id: ChainId,
) -> Vec<u8> {
    let digest = signature_hash(tx, 0, script_code, chain_id, SIGHASH_ALL)
        .expect("input 0 is in range");
    let mut sig = key.sign(&digest).expect("signs the sighash").to_der().to_vec();
    sig.push(SIGHASH_ALL as u8);
    p2pkh_script_sig(&sig, pubkey_bytes)
}

// ---------------------------------------------------------------------------
// Stage 1: input parsing acceptance
// ---------------------------------------------------------------------------

#[test]
fn divergence_pin_parser_accepts_the_compact_tag_verbatim() {
    let fx = fixture();

    // `from_sec1` stores the bytes it was given; it does not re-encode.
    assert_eq!(fx.compact.to_sec1(), fx.compact_bytes);
    assert_eq!(fx.compact.to_sec1()[0], 0x05);

    // The same curve point under two encodings is two distinct `PublicKey`
    // values, because equality is over the stored bytes.
    assert_ne!(fx.compact, fx.canonical);
    assert_ne!(fx.compact.key_hash(), fx.canonical.key_hash());
}

#[test]
fn compressed_prefix_03_is_accepted_like_prefix_02() {
    // A canonical key with odd parity, found deterministically rather than assumed.
    let (key, bytes) = (1u8..=64)
        .find_map(|seed| {
            let key = PrivateKey::from_bytes([seed; SECRET_LEN]).expect("valid scalar");
            let bytes = key.public_key().to_sec1();
            (bytes[0] == 0x03).then_some((key, bytes))
        })
        .expect("some small seed yields an odd-y public key");

    let parsed = PublicKey::from_sec1(&bytes).expect("0x03 is a canonical compressed tag");
    assert_eq!(parsed.to_sec1(), bytes);

    let digest = Hash256([0x5c; 32]);
    let signature = key.sign(&digest).expect("signs");
    assert!(parsed.verify(&digest, &signature).is_ok());
}

#[test]
fn parser_still_rejects_every_other_non_canonical_encoding() {
    let fx = fixture();
    let canonical = fx.canonical.to_sec1();
    let x_only = &canonical[1..];

    // A genuinely valid 65-byte uncompressed encoding of the *same point*.
    // Rejected only because of the 33-byte length gate, never because of maths.
    let uncompressed = uncompressed_spelling(&fx.canonical);
    let uncompressed_bytes = uncompressed.as_bytes();
    assert_eq!(uncompressed_bytes.len(), 65);
    assert_eq!(uncompressed_bytes[0], 0x04);
    assert_eq!(
        PublicKey::from_sec1(uncompressed_bytes),
        Err(CryptoError::InvalidPublicKey)
    );

    let mut hybrid_even = uncompressed_bytes.to_vec();
    hybrid_even[0] = 0x06;
    let mut hybrid_odd = uncompressed_bytes.to_vec();
    hybrid_odd[0] = 0x07;
    assert_eq!(
        PublicKey::from_sec1(&hybrid_even),
        Err(CryptoError::InvalidPublicKey)
    );
    assert_eq!(
        PublicKey::from_sec1(&hybrid_odd),
        Err(CryptoError::InvalidPublicKey)
    );

    // 33-byte inputs with a tag that is neither 0x02/0x03 nor the compact 0x05.
    for prefix in [0x00u8, 0x04, 0x06, 0x07, 0x01, 0xff] {
        let mut candidate = vec![prefix];
        candidate.extend_from_slice(x_only);
        assert_eq!(
            PublicKey::from_sec1(&candidate),
            Err(CryptoError::InvalidPublicKey),
            "prefix {prefix:#04x} must not parse"
        );
    }

    // Length gate.
    for length in [0usize, 32, 34, 65] {
        let mut candidate = vec![0x02u8];
        candidate.resize(length, 0x11);
        assert_eq!(
            PublicKey::from_sec1(&candidate),
            Err(CryptoError::InvalidPublicKey),
            "length {length} must not parse"
        );
    }

    // 33 zero bytes, and an x that is not a field element.
    assert_eq!(
        PublicKey::from_sec1(&[0u8; COMPRESSED_PUBKEY_LEN]),
        Err(CryptoError::InvalidPublicKey)
    );
    let mut x_equals_p = vec![0x02u8];
    x_equals_p.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xfc, 0x2f,
    ]);
    assert_eq!(x_equals_p.len(), COMPRESSED_PUBKEY_LEN);
    assert_eq!(
        PublicKey::from_sec1(&x_equals_p),
        Err(CryptoError::InvalidPublicKey)
    );
}

/// The valid 65-byte uncompressed spelling of the same curve point, so the test
/// does not have to re-derive the curve arithmetic by hand.
fn uncompressed_spelling(key: &PublicKey) -> EncodedPoint {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let encoded = EncodedPoint::from_bytes(key.to_sec1()).expect("33-byte encoded point");
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .expect("the fixture key is on the curve");
    point.to_encoded_point(false)
}

// ---------------------------------------------------------------------------
// Stage 2 and 3: point interpretation and the signature equation
// ---------------------------------------------------------------------------

#[test]
fn divergence_pin_compact_tag_verifies_as_the_same_curve_point() {
    let fx = fixture();
    let digest = Hash256([0x5a; 32]);
    let signature = fx.key.sign(&digest).expect("signs");

    // The very same signature validates under both spellings: `0x05 || x` is a
    // silent alias for the even-y point, i.e. for `0x02 || x`.
    assert!(fx.canonical.verify(&digest, &signature).is_ok());
    assert!(fx.compact.verify(&digest, &signature).is_ok());

    // The equation is still a real equation: a different digest fails.
    let other = Hash256([0x5b; 32]);
    assert_eq!(
        fx.compact.verify(&other, &signature),
        Err(CryptoError::VerificationFailed)
    );
}

// ---------------------------------------------------------------------------
// Stage 4: script execution
// ---------------------------------------------------------------------------

#[test]
fn divergence_pin_key_hash_commits_to_the_encoding_not_the_point() {
    let fx = fixture();

    // Lock to the compact spelling, try to unlock with the canonical spelling.
    let compact_script = p2pkh_script_pubkey(&fx.compact.key_hash());
    let tx = locked_tx(&compact_script);
    let canonical_sig = signed_script_sig(
        &fx.key,
        &tx,
        &compact_script,
        &fx.canonical.to_sec1(),
        chain_id(),
    );
    let checker = TxSigChecker::new(&tx, 0, &compact_script, chain_id());
    assert_eq!(
        verify(&canonical_sig, &compact_script, &checker),
        Err(ScriptError::EqualVerifyFailed),
        "a 0x02 scriptSig must not satisfy a 0x05-locked script"
    );

    // And the mirror image: lock to the canonical spelling, unlock with compact.
    let canonical_script = p2pkh_script_pubkey(&fx.canonical.key_hash());
    let tx = locked_tx(&canonical_script);
    let compact_sig = signed_script_sig(
        &fx.key,
        &tx,
        &canonical_script,
        &fx.compact_bytes,
        chain_id(),
    );
    let checker = TxSigChecker::new(&tx, 0, &canonical_script, chain_id());
    assert_eq!(
        verify(&compact_sig, &canonical_script, &checker),
        Err(ScriptError::EqualVerifyFailed),
        "a 0x05 scriptSig must not satisfy an 0x02-locked script"
    );

    // Positive control on the same bytes: matched spellings execute cleanly.
    let tx = locked_tx(&compact_script);
    let matched = signed_script_sig(
        &fx.key,
        &tx,
        &compact_script,
        &fx.compact_bytes,
        chain_id(),
    );
    let checker = TxSigChecker::new(&tx, 0, &compact_script, chain_id());
    assert!(verify(&matched, &compact_script, &checker).is_ok());
}

// ---------------------------------------------------------------------------
// Stage 5: transaction and block acceptance
// ---------------------------------------------------------------------------

#[test]
fn divergence_pin_end_to_end_p2pkh_spend_from_a_compact_locked_coin_is_accepted() {
    let fx = fixture();
    let compact_hash = fx.compact.key_hash();
    let mut chain = Chain::in_memory(ChainParams::regtest()).expect("opens at genesis");
    let chain_id = chain.chain_id();
    let mut now = GENESIS_TIMESTAMP + 1_000;

    // Height 1 pays the compact public key, i.e. locks to hash160(0x05 || x).
    // This is a real coinbase: `mine_block` accepts the parsed key as a payout.
    for _ in 0..100 {
        chain.mine_block(&fx.compact, vec![], now).expect("mines");
        now += 1;
    }
    assert_eq!(chain.height(), 100);

    let coins = chain.coins_for_pubkey_hash(&compact_hash);
    let funding = coins
        .iter()
        .find(|coin| coin.spendable)
        .expect("the height-1 coinbase is mature at height 101")
        .clone();

    let script_code = p2pkh_script_pubkey(&compact_hash);
    let recipient = PrivateKey::from_bytes([9u8; SECRET_LEN]).expect("valid scalar");
    let recipient_hash = recipient.public_key().key_hash();
    let fee = 1_000u64;

    let build_tx = || Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: funding.outpoint,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: funding.value - fee,
            script_pubkey: p2pkh_script_pubkey(&recipient_hash),
        }],
        lock_time: 0,
    };

    // Negative control: the canonical spelling cannot spend the compact coin.
    let mut wrong = build_tx();
    wrong.inputs[0].script_sig = signed_script_sig(
        &fx.key,
        &wrong,
        &script_code,
        &fx.canonical.to_sec1(),
        chain_id,
    );
    assert!(matches!(
        chain.validate_transaction(&wrong),
        Err(ChainError::Utxo(UtxoError::ScriptInvalid { .. }))
    ));

    // The complete path: mempool admission, then block acceptance.
    let mut tx = build_tx();
    tx.inputs[0].script_sig = signed_script_sig(
        &fx.key,
        &tx,
        &script_code,
        &fx.compact_bytes,
        chain_id,
    );

    let paid = chain
        .validate_transaction(&tx)
        .expect("P2.7: mempool admission accepts the 0x05 spend");
    assert_eq!(paid, fee);

    let height = chain.next_height();
    chain
        .mine_block(&fx.compact, vec![tx], now)
        .expect("P2.7: block acceptance accepts the 0x05 spend");
    assert_eq!(chain.height(), height);
    assert_eq!(
        chain.balance_of_pubkey_hash(&recipient_hash),
        funding.value - fee
    );

    // The wallet still holds the other compact-locked coinbases.
    assert!(chain.balance_of_pubkey_hash(&compact_hash) > 0);
}

// ---------------------------------------------------------------------------
// Reachability: how a compact-locked output arises without hand-built state
// ---------------------------------------------------------------------------

#[test]
fn divergence_pin_wire_share_payout_accepts_the_compact_tag() {
    use zerocoin::consensus::block::{BlockHeader, BLOCK_VERSION};
    use zerocoin::network::message::{Message, SharePayload};

    let fx = fixture();
    let params = ChainParams::regtest();
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain: params.chain_id.0,
        height: 1,
        previous_hash: Hash256([0x11; 32]),
        merkle_root: Hash256([0x22; 32]),
        timestamp: GENESIS_TIMESTAMP,
        difficulty_bits: params.genesis_bits,
        engine_id: params.engine.id(),
        nonce: 0,
    };

    // A share's payout key is a `PublicKey` on the wire, decoded through the same
    // length-only gate. Nothing in the message layer asks for a canonical tag.
    let share = Message::Share(Box::new(SharePayload {
        header,
        payout: fx.compact,
    }));
    let encoded = share.encode().expect("share encodes");
    let Message::Share(decoded) = Message::decode(&encoded).expect("a 0x05 payout decodes")
    else {
        panic!("decode returned a different variant");
    };
    assert_eq!(decoded.payout.to_sec1(), fx.compact_bytes);

    // The pool keeps only the hash, so from here on the encoding is invisible: the
    // split coinbase pays `p2pkh_script_pubkey(hash160(0x05 || x))`.
    assert_eq!(decoded.payout.key_hash(), fx.compact.key_hash());
    assert_ne!(decoded.payout.key_hash(), fx.canonical.key_hash());
}
