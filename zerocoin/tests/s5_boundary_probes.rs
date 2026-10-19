//! S5 boundary probes: what the existing public surface can and cannot pin.
//!
//! S5 asks for six high-S verdicts. Two are already pinned end-to-end in
//! `tests/high_s_signature.rs`. The four scalar-boundary probes (`s = 1`,
//! `s = n - 1`, `s = floor(n/2)`, `s = floor(n/2) + 1`) are *not* pinned here
//! and are not claimed: a boundary probe must present a signature that is
//! valid for the intended verdict, and changing `s` alone breaks the ECDSA
//! equation. Producing a valid signature with a chosen `s` needs nonce
//! control — `PrivateKey::sign` uses RFC 6979 and accepts no nonce, and
//! `k256`'s `SignPrimitive` normalises to low-S — so it would require adding a
//! test-only signer. P2.4 is not authorised to add one.
//!
//! These tests pin the two facts that make that verdict auditable, using only
//! public APIs and no new signing facility:
//!
//! 1. the half-order predicate is strict (`s > floor(n/2)`), so each of the
//!    four values sits on a known side of the gate, and
//! 2. the high-S twin is equation-valid under the library's own equation-only
//!    primitive, so its rejection by `PublicKey::verify` can only be the gate.

use k256::ecdsa::{hazmat, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::{ff::Field, scalar::IsHigh};
use k256::{FieldBytes, ProjectivePoint, Scalar};
use zerocoin::crypto::hash::Hash256;
use zerocoin::crypto::secp256k1::{CryptoError, PrivateKey, Signature, SECRET_LEN};

/// The half-order predicate decides every S5 verdict, so its boundary is
/// pinned exactly: `floor(n/2)` is low-S, `floor(n/2) + 1` is high-S.
#[test]
fn high_s_predicate_boundary_is_strictly_above_half_the_group_order() {
    // `n - 1` is the largest representable scalar; it is also `-1` mod n.
    let n_minus_one = -Scalar::ONE;
    assert_eq!(
        hex::encode(n_minus_one.to_bytes()),
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "anchor the arithmetic to the secp256k1 group order"
    );

    // n is odd, so floor(n/2) = (n - 1) / 2 = -1 * 2^-1 in the scalar field.
    let two_inv = Option::<Scalar>::from(Scalar::ONE.double().invert())
        .expect("two is invertible modulo an odd prime order");
    let half: Scalar = -two_inv;
    assert_eq!(half.double(), n_minus_one, "2 * floor(n/2) == n - 1");
    assert_ne!(half, half + Scalar::ONE);

    assert!(!bool::from(Scalar::ONE.is_high()), "s = 1 is low-S");
    assert!(bool::from(n_minus_one.is_high()), "s = n - 1 is high-S");
    assert!(!bool::from(half.is_high()), "s = floor(n/2) is low-S");
    assert!(
        bool::from((half + Scalar::ONE).is_high()),
        "s = floor(n/2) + 1 is the smallest high-S scalar"
    );
}

/// The P2.3 twin satisfies the ECDSA equation. This is what separates it from
/// the four blocked probes: those have no valid signature at all, whereas the
/// twin is valid and still rejected, which is the high-S rule in action.
#[test]
fn high_s_twin_is_equation_valid_but_the_public_api_rejects_it() {
    let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("fixed seed is a valid scalar");
    let public = key.public_key();
    let digest = Hash256([0x5a; 32]);

    let low_s = key.sign(&digest).expect("signs the fixed prehash");
    let parsed = K256Signature::from_der(low_s.to_der()).expect("the fixture is valid DER");
    let (r, s) = parsed.split_scalars();
    assert!(!bool::from((*s).is_high()), "the signer normalises to low-S");

    let s_high: Scalar = -*s;
    let twin = K256Signature::from_scalars(r.to_bytes(), s_high.to_bytes())
        .expect("n - s is a non-zero scalar below n");
    let (_, twin_s) = twin.split_scalars();
    assert!(bool::from((*twin_s).is_high()), "the twin is high-S");

    // The equation-only primitive has no half-order rule: it accepts the twin.
    let verifying = VerifyingKey::from_sec1_bytes(&public.to_sec1()).expect("SEC1 round-trip");
    let q = ProjectivePoint::from(*verifying.as_affine());
    let z = FieldBytes::clone_from_slice(&digest.0);
    assert!(
        hazmat::verify_prehashed(&q, &z, &twin).is_ok(),
        "the twin satisfies the ECDSA equation, so rejection cannot be blamed on the equation"
    );

    // The public API rejects the very same signature.
    let twin_signature =
        Signature::from_der(twin.to_der().as_bytes()).expect("the twin re-encodes as DER");
    assert_eq!(
        public.verify(&digest, &twin_signature),
        Err(CryptoError::VerificationFailed)
    );
}

/// The only sanctioned signer accepts no nonce and emits low-S, so it cannot
/// produce any of the four boundary scalars. The sweep is a fixed corpus, not
/// a random sample: the deterministic result is the assertion.
#[test]
fn the_public_signing_api_cannot_emit_a_chosen_scalar() {
    let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("fixed seed is a valid scalar");
    for seed in 0u8..32 {
        let mut preimage = [0u8; 32];
        preimage[0] = seed;
        let digest = Hash256(preimage);
        let signature = key.sign(&digest).expect("signs the fixed prehash");
        let parsed = K256Signature::from_der(signature.to_der()).expect("valid DER");
        let (_, s) = parsed.split_scalars();
        assert!(
            !bool::from((*s).is_high()),
            "RFC 6979 output is normalised; the caller cannot choose s"
        );
    }
}
