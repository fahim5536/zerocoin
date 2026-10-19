//! P2.3 regression pins for the high-S rejection inherited from `k256`.
//!
//! `docs/architecture/CRYPTO_BACKEND_READINESS.md` §2 H1 records that the Rust
//! reference rejects a signature whose `s` is greater than `floor(n/2)`. The
//! rejection is not written in ZeroCoin: `PublicKey::verify`
//! (`src/crypto/secp256k1.rs:137-143`) forwards the parsed DER and the 32-byte
//! prehash to `VerifyingKey::verify_prehash`, which reaches
//! `k256-0.13.4/src/ecdsa.rs:201-209`:
//!
//! ```text
//! if sig.s().is_high().into() {
//!     return Err(Error::new());
//! }
//! ```
//!
//! These tests pin that behaviour at the surface a node observes —
//! `PublicKey::verify` and `ECDSA::verify` — so a dependency update that
//! changed the verdict would fail here instead of silently changing consensus
//! (readiness document §7 R1/R2). No production code is changed.
//!
//! # The twin
//!
//! The secp256k1 group order is
//!
//! ```text
//! n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
//! ```
//!
//! For a signature `(r, s)` that verifies under `Q` over digest `z`, write
//! `w = s^-1`, `u1 = z*w`, `u2 = r*w`, so the verifier computes
//! `R = u1*G + u2*Q` and accepts when `x(R) = r`. The pair `(r, n - s)` is also
//! a valid signature because
//!
//! ```text
//! w' = (n - s)^-1 = -s^-1 = -w
//! u1' = z*w' = -u1,   u2' = r*w' = -u2
//! R'  = u1'*G + u2'*Q = -(u1*G + u2*Q) = -R
//! x(R') = x(-R) = x(R) = r
//! ```
//!
//! So both encodings commit to the same ECDSA point; they differ only in the
//! sign of `s`. `n` is odd, so exactly one of `s`, `n - s` is greater than
//! `floor(n/2)`: the original is low-S (k256 normalises while signing,
//! `k256-0.13.4/src/ecdsa.rs:194`) and the twin is high-S. The subtraction is
//! performed by `k256`'s `Scalar::negate` (`n - s mod n`), not by this test.
//!
//! Run with `cargo test --test high_s_signature`.

use k256::ecdsa::Signature as K256Signature;
use k256::elliptic_curve::scalar::IsHigh;
use k256::Scalar;

use zerocoin::crypto::hash::Hash256;
use zerocoin::crypto::secp256k1::{
    CryptoError, PrivateKey, PublicKey, Signature, COMPRESSED_PUBKEY_LEN, ECDSA, SECRET_LEN,
};
use zerocoin::ledger::script::p2pkh_script_pubkey;
use zerocoin::ledger::sighash::{signature_hash, SIGHASH_ALL};
use zerocoin::ledger::transaction::{Outpoint, Transaction, TxIn, TxOut};
use zerocoin::params::ChainParams;

/// A transaction signed under the production sighash conventions: the
/// `ZRO/sighash/v1` preimage over a regtest chain id, producing a single
/// 32-byte digest that is passed to ECDSA unchanged.
struct Fixture {
    public: PublicKey,
    digest: Hash256,
    low_s_der: Vec<u8>,
}

fn fixture() -> Fixture {
    // A fixed scalar, so every run signs the same digest with the same key.
    let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("fixed seed is a valid scalar");
    let public = key.public_key();
    let script_code = p2pkh_script_pubkey(&public.key_hash());

    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint {
                txid: Hash256([0x11; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: 50_000_000,
            script_pubkey: script_code.clone(),
        }],
        lock_time: 0,
    };

    let digest = signature_hash(
        &tx,
        0,
        &script_code,
        ChainParams::regtest().chain_id,
        SIGHASH_ALL,
    )
    .expect("input 0 is in range");

    let low_s_der = key
        .sign(&digest)
        .expect("signs the sighash")
        .to_der()
        .to_vec();

    Fixture {
        public,
        digest,
        low_s_der,
    }
}

/// `(r, s) -> (r, n - s)`: the malleated twin of a low-S DER signature.
///
/// `s` is read with `split_scalars`, negated with `k256`'s group arithmetic
/// (`Scalar::negate`, i.e. `n - s mod n`), and re-encoded. No curve arithmetic
/// is implemented here.
fn high_s_twin(der: &[u8]) -> Vec<u8> {
    let parsed = K256Signature::from_der(der).expect("the fixture is valid DER");
    let (r, s) = parsed.split_scalars();
    let s_high: Scalar = -*s;

    K256Signature::from_scalars(r.to_bytes(), s_high.to_bytes())
        .expect("n - s is a non-zero scalar below n")
        .to_der()
        .as_bytes()
        .to_vec()
}

// ---------------------------------------------------------------------------
// p2.3_1: the valid low-S original is accepted
// ---------------------------------------------------------------------------

/// The signature produced by `PrivateKey::sign` is low-S and verifies over the
/// exact sighash and compressed SEC1 key that were used to produce it.
#[test]
fn valid_low_s_sighash_signature_is_accepted() {
    let fx = fixture();

    let parsed = K256Signature::from_der(&fx.low_s_der).expect("the reference emits valid DER");
    assert!(
        !bool::from(parsed.s().is_high()),
        "k256 normalises s while signing, so the original must be low-S"
    );

    // The conventions under test: a 33-byte compressed SEC1 key, re-imported
    // through the same gate a node uses, and a 32-byte prehash passed as-is.
    let sec1 = fx.public.to_sec1();
    assert_eq!(sec1.len(), COMPRESSED_PUBKEY_LEN);
    assert!(matches!(sec1[0], 0x02 | 0x03), "compressed parity prefix");
    assert_eq!(
        PublicKey::from_sec1(&sec1).expect("round-trips through SEC1"),
        fx.public
    );

    let signature = Signature::from_der(&fx.low_s_der).expect("parses");
    assert_eq!(fx.public.verify(&fx.digest, &signature), Ok(()));
    assert!(ECDSA::verify(&fx.public, &fx.digest, &signature));
}

// ---------------------------------------------------------------------------
// p2.3_2: the mathematically equivalent high-S twin is rejected
// ---------------------------------------------------------------------------

/// `(r, n - s)` is a second encoding of the same ECDSA point. The reference
/// accepts it at DER parse time and rejects it at verification time, before
/// curve arithmetic, which is the rule H1 describes.
#[test]
fn high_s_twin_is_rejected_at_verification() {
    let fx = fixture();

    let low = K256Signature::from_der(&fx.low_s_der).expect("the fixture is valid DER");
    let twin_der = high_s_twin(&fx.low_s_der);
    let twin = K256Signature::from_der(&twin_der).expect("the twin is valid DER");

    // What makes this the twin and not an unrelated corruption: r is identical,
    // s is negated mod n, and normalising the twin returns the original byte
    // for byte. That is the equivalence `(r, s) ~ (r, n - s)`.
    let (low_r, low_s) = low.split_bytes();
    let (twin_r, twin_s) = twin.split_bytes();
    assert_eq!(twin_r, low_r, "the twin keeps r unchanged");
    assert_eq!(
        twin.normalize_s(),
        Some(low),
        "BIP-62 normalisation maps the twin back to the original"
    );
    assert!(!bool::from(low.s().is_high()), "the original is low-S");
    assert!(bool::from(twin.s().is_high()), "the twin is high-S");
    assert_ne!(twin_s, low_s);
    assert_ne!(twin_der, fx.low_s_der);

    // The twin is not rejected as malformed: `Signature::from_der` accepts it,
    // so the verdict below is decided by verification, not by parsing.
    let signature = Signature::from_der(&twin_der).expect("high-S is well-formed DER");
    assert_eq!(
        fx.public.verify(&fx.digest, &signature),
        Err(CryptoError::VerificationFailed)
    );
    assert!(!ECDSA::verify(&fx.public, &fx.digest, &signature));
}

// ---------------------------------------------------------------------------
// p2.3_3: invalid signatures remain rejected
// ---------------------------------------------------------------------------

/// Corruption of either scalar, a different prehash, a different key, and
/// malformed DER all stay rejected. The `s` corruption is chosen so the result
/// is still low-S, proving that rejection comes from the ECDSA equation and not
/// from the high-S rule.
#[test]
fn invalid_signatures_are_still_rejected() {
    let fx = fixture();
    let parsed = K256Signature::from_der(&fx.low_s_der).expect("the fixture is valid DER");
    let (r, s) = parsed.split_bytes();

    let verify = |der: &[u8]| {
        let signature = Signature::from_der(der).expect("the corruption is valid DER");
        fx.public.verify(&fx.digest, &signature)
    };

    // One bit flipped in r.
    let mut r_bad = r;
    r_bad[31] ^= 0x01;
    let corrupt_r = K256Signature::from_scalars(r_bad, s).expect("below n and non-zero");
    assert_eq!(
        verify(corrupt_r.to_der().as_bytes()),
        Err(CryptoError::VerificationFailed)
    );

    // One bit flipped in s, kept low-S so the verdict isolates the equation.
    let mut s_bad = s;
    s_bad[31] ^= 0x01;
    let corrupt_s = K256Signature::from_scalars(r, s_bad).expect("below n and non-zero");
    assert!(
        !bool::from(corrupt_s.s().is_high()),
        "the corrupted s must stay low-S for this probe to mean what it says"
    );
    assert_eq!(
        verify(corrupt_s.to_der().as_bytes()),
        Err(CryptoError::VerificationFailed)
    );

    // The original signature over a different 32-byte prehash.
    let other_digest = Hash256(zerocoin::crypto::hash::sha256(b"another sighash"));
    let signature = Signature::from_der(&fx.low_s_der).expect("parses");
    assert_eq!(
        fx.public.verify(&other_digest, &signature),
        Err(CryptoError::VerificationFailed)
    );

    // The original signature under a different compressed SEC1 key.
    let other_public = PrivateKey::from_bytes([9u8; SECRET_LEN])
        .expect("valid scalar")
        .public_key();
    assert_eq!(
        other_public.verify(&fx.digest, &signature),
        Err(CryptoError::VerificationFailed)
    );

    // Malformed DER never reaches the curve: empty, empty sequence, trailing
    // byte, and truncation all fail at the parser.
    for malformed in [
        Vec::new(),
        vec![0x30, 0x00],
        {
            let mut bytes = fx.low_s_der.clone();
            bytes.push(0x00);
            bytes
        },
        {
            let mut bytes = fx.low_s_der.clone();
            bytes.pop();
            bytes
        },
    ] {
        assert_eq!(
            Signature::from_der(&malformed).err(),
            Some(CryptoError::InvalidSignature),
            "malformed DER must fail before verification: {malformed:02x?}"
        );
    }
}

// ---------------------------------------------------------------------------
// p2.3_4: the signing conventions are pinned
// ---------------------------------------------------------------------------

/// Signing the same prehash twice must yield identical bytes (RFC 6979), and
/// the sighash must be a 32-byte value that is not re-hashed by verification.
#[test]
fn signing_conventions_are_pinned() {
    let fx = fixture();
    let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("valid scalar");

    let first = key.sign(&fx.digest).expect("signs").to_der().to_vec();
    let second = key.sign(&fx.digest).expect("signs").to_der().to_vec();
    assert_eq!(first, second, "signing is deterministic (RFC 6979)");
    assert_eq!(first, fx.low_s_der);

    assert_eq!(fx.digest.0.len(), 32, "the prehash is 32 bytes");
    assert!(
        (70..=72).contains(&first.len()),
        "DER ECDSA over secp256k1 is 70-72 bytes, got {}",
        first.len()
    );

    // Signing and verification consume the same 32-byte digest unchanged. If
    // either side re-hashed it, this round-trip would fail.
    let signature = Signature::from_der(&first).expect("parses");
    assert_eq!(fx.public.verify(&fx.digest, &signature), Ok(()));
}
