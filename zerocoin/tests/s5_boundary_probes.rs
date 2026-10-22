//! S5 boundary probes: the six verdicts at the half-order boundary.
//!
//! S5 asks for six verdicts. Two are pinned end-to-end in
//! `tests/high_s_signature.rs`: a valid low-S signature is accepted, and its
//! high-S twin `(r, n - s)` is rejected. The four scalar-boundary probes —
//! `s = 1`, `s = n - 1`, `s = floor(n/2)`, `s = floor(n/2) + 1` — were blocked
//! from P2.4 through P2.8: a boundary probe must present a signature that is
//! valid for the intended verdict, changing `s` alone breaks the ECDSA
//! equation, and producing a valid signature with a chosen `s` needs nonce
//! control. `PrivateKey::sign` uses RFC 6979 and accepts no nonce, and
//! `k256`'s `SignPrimitive` normalises to low-S.
//!
//! P2.9 resolves the strategy with the test-only signer that
//! `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md` §10 sanctions:
//! `ecdsa::hazmat::sign_prehashed` (the dependency's own equation-only signer,
//! re-exported as `k256::ecdsa::hazmat`), driven by fixed public constants —
//! `d = 1` (the corpus `signature_der` key) and nonce `k = 3`. It lives only
//! in this integration-test target, so it cannot be linked into a node, and
//! it emits only fixtures, so it is never a production signing path. Fixing
//! `k` yields `r = x(k*G) mod n` and `s = k^-1 * (z + r*d) mod n`; choosing
//! `z' = z + k*(s_target - s) mod n` makes the equation yield `s_target`, so
//! every probe below presents a signature that is genuinely ECDSA-valid for
//! its intended verdict.
//!
//! The first three tests are the P2.4 pins, kept with their logic unchanged
//! (the third's comment was clarified, not its assertions). They pin the two
//! facts that made the verdict auditable before a signer existed —
//!
//! 1. the half-order predicate is strict (`s > floor(n/2)`), so each of the
//!    four values sits on a known side of the gate, and
//! 2. the high-S twin is equation-valid under the library's own equation-only
//!    primitive, so its rejection by `PublicKey::verify` can only be the gate.
//!
//! The four tests after them are the P2.9 probes. Each asserts the exact
//! `s_target`, proves equation validity over `z'` through the equation-only
//! primitive (so a rejection cannot be blamed on the equation), and records
//! the production `PublicKey::verify` verdict. The two low-S probes also run
//! the negative control: the same signature over the original corpus digest
//! fails the equation, which is what separates a real boundary probe from a
//! mere mutation of `s`.

use k256::ecdsa::{hazmat, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::{ff::Field, ops::Reduce, scalar::IsHigh, ScalarPrimitive};
use k256::{FieldBytes, ProjectivePoint, Scalar, Secp256k1, U256};
use zerocoin::crypto::hash::Hash256;
use zerocoin::crypto::secp256k1::{CryptoError, PrivateKey, PublicKey, Signature, SECRET_LEN};

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

/// The production signer accepts no nonce and emits low-S, so it cannot
/// produce any of the four boundary scalars; the P2.9 probes below therefore
/// use a test-only signer instead. The sweep is a fixed corpus, not a random
/// sample: the deterministic result is the assertion.
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

// ---------------------------------------------------------------------------
// P2.9: the four scalar-boundary probes, via the §10 test-only signer
// ---------------------------------------------------------------------------

/// The exact 32-byte digest the committed `ledger.sighash.signature_der`
/// fixture signs over (`internal_hex` in `test/vectors/ledger/sighash.json`),
/// produced by the production `signature_hash` over the corpus regtest
/// transaction. It is below the group order, so the verifier's modular
/// reduction of the digest is the identity.
const CORPUS_DIGEST: [u8; 32] = [
    0xe0, 0xe7, 0xce, 0x17, 0x6c, 0x2a, 0xa8, 0x07, 0x73, 0x78, 0x29, 0x9f, 0x68, 0x2b, 0xae, 0xc2,
    0x3e, 0x02, 0xab, 0xc2, 0x89, 0xb5, 0x1f, 0xa1, 0x89, 0x5b, 0x7c, 0xde, 0x9c, 0xe6, 0xa2, 0x37,
];

/// A private key whose scalar is `byte` in the least-significant position —
/// the corpus convention (`export_baseline_vectors.rs`), where `scalar: 1` is
/// the published `signature_der` key.
fn scalar_key(byte: u8) -> PrivateKey {
    let mut bytes = [0u8; SECRET_LEN];
    bytes[31] = byte;
    PrivateKey::from_bytes(bytes).expect("1..=255 are valid secp256k1 scalars")
}

/// `floor(n/2) = (n - 1) / 2 = -1 * 2^-1` in the scalar field (n is odd).
fn half_order() -> Scalar {
    let two_inv = Option::<Scalar>::from(Scalar::ONE.double().invert())
        .expect("two is invertible modulo an odd prime order");
    -two_inv
}

/// The P2.9 test-only signer, exactly as §10 of
/// `docs/architecture/CRYPTO_BACKEND_SELECTION_AUDIT.md` requires.
///
/// Scope and isolation:
/// - It lives only in this integration-test target. Test binaries are never
///   linked into a node, so no production build can reach it.
/// - Every constant is public and fixed: `d = 1` (the corpus `signature_der`
///   key), `k = 3` (the nonce) and the corpus digest. Nothing is drawn from
///   entropy, so there is no secret material to generate, store or zeroise.
/// - The primitive is `ecdsa::hazmat::sign_prehashed` (`ecdsa-0.16.9`, the
///   dependency pinned by `Cargo.lock`), which takes the nonce explicitly and
///   performs no RFC 6979 derivation and no low-S normalisation.
/// - It emits only test fixtures and is never counted as a production signing
///   path.
///
/// Given a target scalar `s_target`, it returns the signature `(r, s_target)`
/// and the digest `z'` that makes it ECDSA-valid. Fixing `k` yields
/// `r = x(k*G) mod n` and `s = k^-1 * (z + r*d) mod n`; choosing
/// `z' = z + k*(s_target - s) mod n` makes the equation yield `s_target`.
/// The verifier reduces the digest mod n before use, and `z < n`, so both
/// sides agree on `z`.
fn chosen_s_signature(s_target: &Scalar) -> (K256Signature, FieldBytes) {
    let d = Scalar::ONE; // the corpus key: `signature_der` uses `scalar: 1`
    let k = Scalar::ONE.double() + Scalar::ONE; // the fixed nonce k = 3

    let z_bytes = FieldBytes::clone_from_slice(&CORPUS_DIGEST);
    // `Scalar` is the curve's scalar type, a projection the compiler treats as
    // non-injective, so the curve parameter cannot be inferred from `d` alone;
    // pin both generics explicitly.
    let (sig, _recovery) = hazmat::sign_prehashed::<Secp256k1, Scalar>(&d, k, &z_bytes)
        .expect("k = 3 is invertible");
    let (r, s) = sig.split_scalars();
    let s = Scalar::from(ScalarPrimitive::from(&s));

    let z = <Scalar as Reduce<U256>>::reduce_bytes(&z_bytes);
    let z_prime = z + k * (*s_target - s);
    let z_prime_bytes = FieldBytes::clone_from_slice(&z_prime.to_bytes());

    // `from_scalars` is generic over the curve and a bare byte array cannot
    // pin it (many curves use 32-byte field elements); bind both sides to the
    // concrete `FieldBytes<Secp256k1>` via `From<&NonZeroScalar>`.
    let r_bytes = FieldBytes::from(&r);
    let s_bytes = FieldBytes::clone_from_slice(&s_target.to_bytes());
    let target_sig = K256Signature::from_scalars(r_bytes, s_bytes)
        .expect("the four targets are non-zero scalars below n");
    (target_sig, z_prime_bytes)
}

/// Run one probe through the production surfaces a node uses: the corpus key
/// `d = 1` (whose public key is the generator `G`), the strict-DER parser and
/// the public verifier.
fn probe_fixture(s_target: &Scalar) -> (PublicKey, K256Signature, Hash256, Signature) {
    let (target_sig, z_prime_bytes) = chosen_s_signature(s_target);

    let public = scalar_key(1).public_key();
    let generator = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("even-length hex");
    assert_eq!(
        public.as_bytes(),
        &generator[..],
        "d = 1 has the generator G as its public key, the anchor of the corpus fixture"
    );

    let der = target_sig.to_der();
    let signature = Signature::from_der(der.as_bytes()).expect("the target is valid DER");
    let z_prime = Hash256(z_prime_bytes.into());
    (public, target_sig, z_prime, signature)
}

/// The equation-only primitive has no half-order rule and no public API: it
/// computes `R = u1*G + u2*Q` and compares `x(R)` with `r`. Accepting a
/// signature here proves ECDSA-validity independently of the gate under test.
fn equation_valid(target_sig: &K256Signature, z_prime: &Hash256) {
    let q = ProjectivePoint::GENERATOR; // d = 1, asserted in `probe_fixture`
    let z_field = FieldBytes::clone_from_slice(&z_prime.0);
    assert!(
        hazmat::verify_prehashed(&q, &z_field, target_sig).is_ok(),
        "the signature must be ECDSA-valid over z' before any verdict means anything"
    );
}

/// `s = 1` is the smallest representable scalar. The §10 construction yields
/// a signature the production verifier accepts, and the equation check
/// confirms it is ECDSA-valid, so the acceptance is decided by the equation
/// and the low-S position, not by an artifact of the test.
#[test]
fn s_equals_one_is_equation_valid_and_accepted() {
    let target = Scalar::ONE;
    assert!(!bool::from(target.is_high()), "s = 1 is low-S");

    let (public, sig_target, z_prime, signature) = probe_fixture(&target);
    let (_, s) = sig_target.split_scalars();
    assert_eq!(s.to_bytes(), target.to_bytes(), "the construction yields exactly s = 1");

    equation_valid(&sig_target, &z_prime);
    assert_eq!(public.verify(&z_prime, &signature), Ok(()));

    // Negative control: the same signature over the original corpus digest
    // fails the equation — mutating s alone is not a boundary probe.
    assert_ne!(z_prime.0, CORPUS_DIGEST, "the shifted digest differs from the corpus digest");
    assert_eq!(
        public.verify(&Hash256(CORPUS_DIGEST), &signature),
        Err(CryptoError::VerificationFailed)
    );
}

/// `s = n - 1` is the largest representable scalar (`-1` mod n). It verifies
/// false through the public verifier even though the equation holds, which
/// proves the only failing condition is the half-order gate.
#[test]
fn s_equals_n_minus_one_is_equation_valid_but_rejected() {
    let target = -Scalar::ONE;
    assert!(bool::from(target.is_high()), "s = n - 1 is high-S");

    let (public, sig_target, z_prime, signature) = probe_fixture(&target);
    let (_, s) = sig_target.split_scalars();
    assert_eq!(s.to_bytes(), target.to_bytes(), "the construction yields exactly s = n - 1");

    // ECDSA-valid over z' and still rejected: the half-order gate is the only
    // rule that differs between the two primitives.
    equation_valid(&sig_target, &z_prime);
    assert_eq!(
        public.verify(&z_prime, &signature),
        Err(CryptoError::VerificationFailed),
        "the Rust reference rejects s = n - 1"
    );
}

/// `floor(n/2)` is the largest low-S scalar. The construction yields a
/// signature the production verifier accepts, with the same equation and
/// negative-control evidence as the `s = 1` probe.
#[test]
fn s_equals_half_the_group_order_is_equation_valid_and_accepted() {
    let target = half_order();
    assert!(!bool::from(target.is_high()), "s = floor(n/2) is low-S");

    let (public, sig_target, z_prime, signature) = probe_fixture(&target);
    let (_, s) = sig_target.split_scalars();
    assert_eq!(s.to_bytes(), target.to_bytes(), "the construction yields exactly s = floor(n/2)");

    equation_valid(&sig_target, &z_prime);
    assert_eq!(public.verify(&z_prime, &signature), Ok(()));

    assert_ne!(z_prime.0, CORPUS_DIGEST, "the shifted digest differs from the corpus digest");
    assert_eq!(
        public.verify(&Hash256(CORPUS_DIGEST), &signature),
        Err(CryptoError::VerificationFailed)
    );
}

/// `floor(n/2) + 1` is the smallest high-S scalar. Equation-valid and still
/// rejected: the gate fires exactly here.
#[test]
fn s_equals_half_plus_one_is_equation_valid_but_rejected() {
    let target = half_order() + Scalar::ONE;
    assert!(
        bool::from(target.is_high()),
        "s = floor(n/2) + 1 is the smallest high-S scalar"
    );

    let (public, sig_target, z_prime, signature) = probe_fixture(&target);
    let (_, s) = sig_target.split_scalars();
    assert_eq!(
        s.to_bytes(),
        target.to_bytes(),
        "the construction yields exactly s = floor(n/2) + 1"
    );

    equation_valid(&sig_target, &z_prime);
    assert_eq!(
        public.verify(&z_prime, &signature),
        Err(CryptoError::VerificationFailed),
        "the Rust reference rejects s = floor(n/2) + 1"
    );
}
