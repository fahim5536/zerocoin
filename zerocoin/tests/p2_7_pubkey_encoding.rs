//! P2.8 — the public-key encoding contract, pinned from parser to block.
//!
//! P2.7 recorded an unresolved divergence in this file: `PublicKey::from_sec1`
//! used to gate on length only, so `k256`/`sec1` also
//! decoded SEC1 tag `0x05` ("compact") as the even-`y` spelling of the point
//! `0x02 || x`, while libsecp256k1 admits only `0x02`/`0x03` at 33 bytes. That
//! was the `V4.prefix_05` row in the differential fixture.
//!
//! P2.8 resolved it. `docs/consensus/PUBLIC_KEY_ENCODING_CONTRACT.md` rule
//! **P-1** admits exactly two tags at 33 bytes — `0x02` and `0x03` — and
//! `from_sec1` now enforces that before the curve is touched. These tests pin the
//! resolved contract:
//!
//! * both canonical tags parse, verify and spend;
//! * `0x05` and every other tag are rejected at the parser, so no code path can
//!   construct a `PublicKey` holding a non-canonical encoding;
//! * a coin locked to `hash160(0x05 || x)` — constructible now only by writing the
//!   UTXO set by hand — can no longer be spent;
//! * a wire `Share` whose payout key is tagged `0x05` no longer decodes.
//!
//! `historical_regression_the_former_0x05_alias_is_rejected` is the P2.7 pin
//! inverted: it asserts that the alias P2.7 measured working is now refused, and
//! it must not be deleted. If a test here fails, production parsing has changed —
//! which is a consensus decision, not a test fix. See the P2.8 addendum in
//! `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md`.

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use zerocoin::chain::{Chain, ChainError};
use zerocoin::crypto::hash::{hash160, Hash256};
use zerocoin::crypto::secp256k1::{CryptoError, PrivateKey, PublicKey, COMPRESSED_PUBKEY_LEN, SECRET_LEN};
use zerocoin::ledger::script::{
    p2pkh_script_pubkey, p2pkh_script_sig, verify, ScriptError,
};
use zerocoin::ledger::sighash::{signature_hash, ChainId, SIGHASH_ALL, TxSigChecker};
use zerocoin::ledger::transaction::{Outpoint, Transaction, TxIn, TxOut};
use zerocoin::ledger::utxo::{UtxoError, UtxoSet};
use zerocoin::params::{ChainParams, GENESIS_TIMESTAMP};

/// The chain id the fixtures sign against. Taken from the params rather than
/// restated, so a fixture can never disagree with the network it models.
fn chain_id() -> ChainId {
    ChainParams::regtest().chain_id
}

/// Deterministic fixture: one secret, its canonical compressed key, and the
/// `0x05 || x` spelling that P2.7 measured and P2.8 removed from the parser.
struct Fixture {
    key: PrivateKey,
    canonical: PublicKey,
    compact_bytes: [u8; COMPRESSED_PUBKEY_LEN],
}

fn fixture() -> Fixture {
    let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("seed 7 is a valid scalar");
    let canonical = key.public_key();
    let canonical_bytes = canonical.to_sec1();
    assert!(matches!(canonical_bytes[0], 0x02 | 0x03));

    let mut compact_bytes = [0u8; COMPRESSED_PUBKEY_LEN];
    compact_bytes[0] = 0x05;
    compact_bytes[1..].copy_from_slice(&canonical_bytes[1..]);

    Fixture {
        key,
        canonical,
        compact_bytes,
    }
}

/// A deterministic key whose canonical encoding uses `tag`, found by search
/// rather than assumed.
fn key_with_tag(tag: u8) -> (PrivateKey, [u8; COMPRESSED_PUBKEY_LEN]) {
    (1u8..=64)
        .find_map(|seed| {
            let key = PrivateKey::from_bytes([seed; SECRET_LEN]).expect("valid scalar");
            let bytes = key.public_key().to_sec1();
            (bytes[0] == tag).then_some((key, bytes))
        })
        .expect("some small seed yields each compressed tag")
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
// Stage 1: input parsing — the contract boundary
// ---------------------------------------------------------------------------

#[test]
fn compact_prefix_05_is_rejected_at_the_parser() {
    let fx = fixture();

    // The disputed encoding: 33 bytes, SEC1 tag 0x05 ("compact"), the same `x`
    // as the canonical key. P-1 rejects the tag before the curve is consulted.
    assert_eq!(
        PublicKey::from_sec1(&fx.compact_bytes),
        Err(CryptoError::InvalidPublicKey)
    );

    // The same `x` under either allowed tag still parses, so the refusal above is
    // about the tag and not about the point: the point itself is valid.
    for tag in [0x02u8, 0x03] {
        let mut candidate = fx.compact_bytes;
        candidate[0] = tag;
        assert!(
            PublicKey::from_sec1(&candidate).is_ok(),
            "tag {tag:#04x} over the same x must parse"
        );
    }
}

#[test]
fn historical_regression_the_former_0x05_alias_is_rejected() {
    // Before P2.8 this exact byte string parsed, verified as the `0x02` point and
    // satisfied a `hash160(0x05 || x)` lock — the three `divergence_pin_*` tests
    // of the P2.7 version of this file. It is now refused at the parser, and with
    // it every consequence those pins recorded.
    let fx = fixture();
    assert_eq!(
        PublicKey::from_sec1(&fx.compact_bytes),
        Err(CryptoError::InvalidPublicKey),
        "the former 0x05 alias must stay rejected"
    );

    // The canonical spelling of the same point is untouched, so this test cannot
    // pass by rejecting everything.
    let canonical_bytes = fx.canonical.to_sec1();
    assert!(PublicKey::from_sec1(&canonical_bytes).is_ok());
    assert_eq!(canonical_bytes[1..], fx.compact_bytes[1..]);
    assert_ne!(canonical_bytes[0], fx.compact_bytes[0]);
}

#[test]
fn canonical_prefix_02_is_accepted() {
    let (key, bytes) = key_with_tag(0x02);
    assert_eq!(bytes[0], 0x02);

    let parsed = PublicKey::from_sec1(&bytes).expect("0x02 is a canonical compressed tag");
    assert_eq!(parsed.to_sec1(), bytes, "the encoding is stored unchanged");
    assert_eq!(parsed.key_hash(), key.public_key().key_hash());

    let digest = Hash256([0x5c; 32]);
    let signature = key.sign(&digest).expect("signs");
    assert!(parsed.verify(&digest, &signature).is_ok());
}

#[test]
fn canonical_prefix_03_is_accepted() {
    let (key, bytes) = key_with_tag(0x03);
    assert_eq!(bytes[0], 0x03);

    let parsed = PublicKey::from_sec1(&bytes).expect("0x03 is a canonical compressed tag");
    assert_eq!(parsed.to_sec1(), bytes, "the encoding is stored unchanged");
    assert_eq!(parsed.key_hash(), key.public_key().key_hash());

    let digest = Hash256([0x5d; 32]);
    let signature = key.sign(&digest).expect("signs");
    assert!(parsed.verify(&digest, &signature).is_ok());
}

#[test]
fn every_other_unsupported_prefix_is_rejected() {
    let fx = fixture();
    let canonical = fx.canonical.to_sec1();
    let x_only = &canonical[1..];

    // 33-byte inputs whose tag is neither 0x02 nor 0x03. 0x05 is listed here as
    // well as in its own test so that trimming this list cannot silently re-admit
    // the disputed tag.
    for prefix in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0xff] {
        let mut candidate = vec![prefix];
        candidate.extend_from_slice(x_only);
        assert_eq!(
            PublicKey::from_sec1(&candidate),
            Err(CryptoError::InvalidPublicKey),
            "prefix {prefix:#04x} must not parse"
        );
    }

    // A genuinely valid 65-byte uncompressed encoding of the *same point*: the
    // length gate rejects it, never the curve maths.
    let uncompressed = uncompressed_spelling(&fx.canonical);
    let uncompressed_bytes = uncompressed.as_bytes();
    assert_eq!(uncompressed_bytes.len(), 65);
    assert_eq!(uncompressed_bytes[0], 0x04);
    assert_eq!(
        PublicKey::from_sec1(uncompressed_bytes),
        Err(CryptoError::InvalidPublicKey)
    );

    // Hybrid tags carrying a valid point are refused as well.
    for tag in [0x06u8, 0x07] {
        let mut hybrid = uncompressed_bytes.to_vec();
        hybrid[0] = tag;
        assert_eq!(
            PublicKey::from_sec1(&hybrid),
            Err(CryptoError::InvalidPublicKey),
            "hybrid prefix {tag:#04x} must not parse"
        );
    }
}

#[test]
fn invalid_lengths_and_invalid_curve_points_are_rejected() {
    // The length gate runs before the tag gate.
    for length in [0usize, 1, 32, 34, 64, 65] {
        let mut candidate = vec![0x02u8];
        candidate.resize(length, 0x11);
        assert_eq!(
            PublicKey::from_sec1(&candidate),
            Err(CryptoError::InvalidPublicKey),
            "length {length} must not parse"
        );
    }

    // 33 zero bytes: a correct length with a forbidden tag.
    assert_eq!(
        PublicKey::from_sec1(&[0u8; COMPRESSED_PUBKEY_LEN]),
        Err(CryptoError::InvalidPublicKey)
    );

    // An `x` that is not a field element.
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

    // A field element with no matching curve point, found by perturbation rather
    // than hard-coded, under both allowed tags.
    let (_, canonical) = key_with_tag(0x02);
    let off_curve = (1u8..=64)
        .find_map(|delta| {
            let mut candidate = canonical;
            candidate[COMPRESSED_PUBKEY_LEN - 1] =
                candidate[COMPRESSED_PUBKEY_LEN - 1].wrapping_add(delta);
            let encoded = EncodedPoint::from_bytes(candidate).expect("33 bytes");
            bool::from(AffinePoint::from_encoded_point(&encoded).is_none())
                .then_some(candidate)
        })
        .expect("some perturbation has no curve point");
    for tag in [0x02u8, 0x03] {
        let mut candidate = off_curve;
        candidate[0] = tag;
        assert_eq!(
            PublicKey::from_sec1(&candidate),
            Err(CryptoError::InvalidPublicKey),
            "off-curve x under tag {tag:#04x}"
        );
    }
}

/// The valid 65-byte uncompressed spelling of the same curve point, so the test
/// does not have to re-derive the curve arithmetic by hand.
fn uncompressed_spelling(key: &PublicKey) -> EncodedPoint {
    let encoded = EncodedPoint::from_bytes(key.to_sec1()).expect("33-byte encoded point");
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .expect("the fixture key is on the curve");
    point.to_encoded_point(false)
}

// ---------------------------------------------------------------------------
// Stage 2 and 3: point interpretation and the signature equation
// ---------------------------------------------------------------------------

#[test]
fn valid_signature_verification_is_unchanged() {
    let fx = fixture();
    let digest = Hash256([0x5a; 32]);
    let signature = fx.key.sign(&digest).expect("signs");

    // The canonical key verifies the signature its owner made. P2.8 changed only
    // which encodings may reach this equation, never the equation itself.
    assert!(fx.canonical.verify(&digest, &signature).is_ok());

    // It is still a real equation: a different digest fails...
    let other = Hash256([0x5b; 32]);
    assert_eq!(
        fx.canonical.verify(&other, &signature),
        Err(CryptoError::VerificationFailed)
    );

    // ...and so does the same signature under an unrelated key.
    let stranger = PrivateKey::from_bytes([0x0b; SECRET_LEN]).expect("valid scalar");
    assert_eq!(
        stranger.public_key().verify(&digest, &signature),
        Err(CryptoError::VerificationFailed)
    );
}

// ---------------------------------------------------------------------------
// Stage 4: script execution
// ---------------------------------------------------------------------------

/// A P2PKH lock is `OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY
/// OP_CHECKSIG`, so a lock and a scriptSig have to agree on the *encoding*, not
/// merely on the point.
#[test]
fn p2pkh_script_validation_uses_canonical_and_noncanonical_encodings() {
    let fx = fixture();

    // Canonical lock, canonical scriptSig: the one combination that works.
    let canonical_script = p2pkh_script_pubkey(&fx.canonical.key_hash());
    let canonical_tx = locked_tx(&canonical_script);
    let canonical_sig = signed_script_sig(
        &fx.key,
        &canonical_tx,
        &canonical_script,
        &fx.canonical.to_sec1(),
        chain_id(),
    );
    let checker = TxSigChecker::new(&canonical_tx, 0, &canonical_script, chain_id());
    assert!(verify(&canonical_sig, &canonical_script, &checker).is_ok());

    // Canonical lock, 0x05 scriptSig: refused at OP_EQUALVERIFY, before any
    // signature work, because `key_hash` commits to the encoding.
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

    // The mirror case is the one P2.8 changed. A lock on `hash160(0x05 || x)` with
    // a *matching* 0x05 scriptSig clears OP_EQUALVERIFY — the hashes do agree —
    // and then dies at OP_CHECKSIG, because the parser refuses the tag and pushes
    // an empty value; `verify` sees no true top and reports `EvalFalse`.
    let compact_script = p2pkh_script_pubkey(&hash160(&fx.compact_bytes));
    let tx = locked_tx(&compact_script);
    let matching = signed_script_sig(
        &fx.key,
        &tx,
        &compact_script,
        &fx.compact_bytes,
        chain_id(),
    );
    let checker = TxSigChecker::new(&tx, 0, &compact_script, chain_id());
    assert_eq!(
        verify(&matching, &compact_script, &checker),
        Err(ScriptError::EvalFalse),
        "a matching 0x05 scriptSig must now fail at OP_CHECKSIG"
    );

    // And a canonical scriptSig never matched that lock in the first place.
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
        "a 0x02 scriptSig cannot match a 0x05 lock either"
    );
}

// ---------------------------------------------------------------------------
// Stage 5: transaction and block acceptance
// ---------------------------------------------------------------------------

#[test]
fn canonical_p2pkh_spend_is_still_accepted() {
    let fx = fixture();
    let mut chain = Chain::in_memory(ChainParams::regtest()).expect("opens at genesis");
    let chain_id = chain.chain_id();
    let mut now = GENESIS_TIMESTAMP + 1_000;

    // Height 1 pays the canonical public key.
    for _ in 0..100 {
        chain.mine_block(&fx.canonical, vec![], now).expect("mines");
        now += 1;
    }
    assert_eq!(chain.height(), 100);

    let coins = chain.coins_for_pubkey_hash(&fx.canonical.key_hash());
    let funding = coins
        .iter()
        .find(|coin| coin.spendable)
        .expect("the height-1 coinbase is mature at height 101")
        .clone();

    let script_code = p2pkh_script_pubkey(&fx.canonical.key_hash());
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

    // Negative control on the same coin: the 0x05 spelling can no longer spend.
    let mut wrong = build_tx();
    wrong.inputs[0].script_sig = signed_script_sig(
        &fx.key,
        &wrong,
        &script_code,
        &fx.compact_bytes,
        chain_id,
    );
    assert!(matches!(
        chain.validate_transaction(&wrong),
        Err(ChainError::Utxo(UtxoError::ScriptInvalid { .. }))
    ));

    // The complete path is unchanged for the canonical encoding: mempool
    // admission, then block acceptance, then a balance for the payee.
    let mut tx = build_tx();
    tx.inputs[0].script_sig = signed_script_sig(
        &fx.key,
        &tx,
        &script_code,
        &fx.canonical.to_sec1(),
        chain_id,
    );

    let paid = chain
        .validate_transaction(&tx)
        .expect("a canonical P2PKH spend is admitted");
    assert_eq!(paid, fee);

    let height = chain.next_height();
    chain
        .mine_block(&fx.canonical, vec![tx], now)
        .expect("block acceptance agrees with mempool admission");
    assert_eq!(chain.height(), height);
    assert_eq!(
        chain.balance_of_pubkey_hash(&recipient_hash),
        funding.value - fee
    );
}

/// The coin the P2.7 pin spent can no longer be spent. It cannot even be created
/// through a `PublicKey` any more, so the UTXO set is seeded directly: creating an
/// output needs no key, only spending it does.
#[test]
fn compact_locked_coin_can_no_longer_be_spent() {
    let fx = fixture();
    let compact_hash = hash160(&fx.compact_bytes);
    let script_code = p2pkh_script_pubkey(&compact_hash);
    let funding = TxOut {
        value: 5_000,
        script_pubkey: script_code.clone(),
    };
    let txid = Hash256([0x33; 32]);
    let outpoint = Outpoint { txid, vout: 0 };

    let mut set = UtxoSet::new();
    set.insert_output(txid, 0, funding.clone(), 1);
    let before = set.state_root();
    assert!(set.contains(&outpoint));

    let recipient = PrivateKey::from_bytes([9u8; SECRET_LEN]).expect("valid scalar");
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: funding.value - 1_000,
            script_pubkey: p2pkh_script_pubkey(&recipient.public_key().key_hash()),
        }],
        lock_time: 0,
    };
    // The scriptSig that satisfied this lock before P2.8.
    tx.inputs[0].script_sig =
        signed_script_sig(&fx.key, &tx, &script_code, &fx.compact_bytes, chain_id());

    assert!(matches!(
        set.apply_transaction(&tx, chain_id(), 2, 2),
        Err(UtxoError::ScriptInvalid {
            index: 0,
            source: ScriptError::EvalFalse,
        })
    ));

    // Unspendable, not consumed: `apply_transaction` validates before it mutates.
    assert_eq!(set.state_root(), before);
    assert!(set.contains(&outpoint));
    assert_eq!(set.balance_of_script(&script_code), funding.value);
}

// ---------------------------------------------------------------------------
// Reachability: a wire-supplied pool payout key
// ---------------------------------------------------------------------------

#[test]
fn wire_share_with_a_compact_payout_key_is_rejected() {
    use zerocoin::consensus::block::{BlockHeader, BLOCK_VERSION};
    use zerocoin::network::message::{Message, SharePayload};

    let fx = fixture();
    let params = ChainParams::regtest();
    let header = || BlockHeader {
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

    // A canonical share round-trips, so the refusal below cannot be blamed on the
    // message shape or on the header.
    let canonical = Message::Share(Box::new(SharePayload {
        header: header(),
        payout: fx.canonical,
    }));
    let encoded = canonical.encode().expect("share encodes");
    let Message::Share(decoded) = Message::decode(&encoded).expect("a canonical payout decodes")
    else {
        panic!("decode returned a different variant");
    };
    assert_eq!(decoded.payout.to_sec1(), fx.canonical.to_sec1());

    // Rewrite `payout` with the 0x05 spelling, exactly as a hostile peer would.
    // `PublicKey::deserialize` funnels straight into `from_sec1`, so the share is
    // refused at the codec and never reaches the pool.
    let mut value = serde_json::to_value(&canonical).expect("share to JSON");
    value["Share"]["payout"] = serde_json::Value::String(hex::encode(fx.compact_bytes));
    let patched = serde_json::to_vec(&value).expect("patched share to bytes");
    assert!(
        Message::decode(&patched).is_err(),
        "a 0x05 payout key must not decode off the wire"
    );
}
