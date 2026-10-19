//! P2.6 differential vectors: generator and oracle for the libsecp256k1 experiment.
//!
//! Two tests live here, and they point in opposite directions on purpose.
//!
//! * [`emit_differential_vectors`] is `#[ignore]`d. Run explicitly, it writes
//!   `kernel/differential/vectors/ledger.sighash.differential.txt`, recording one
//!   row per case together with the verdict the **Rust reference** produces for
//!   it. No verdict in that file is written by hand.
//!
//! * [`differential_vectors_match_rust_reference`] runs in the normal suite. It
//!   re-reads the committed fixture, recomputes every verdict through the same
//!   fail-closed seam a node uses, and fails if the recorded value differs. That
//!   is the anti-fabrication control: the C++ runner is only meaningful if the
//!   column it is compared against is still what Rust says.
//!
//! The seam under comparison is exactly
//! [`zerocoin::crypto::secp256k1::PublicKey::verify`] behind the same parse gates
//! a node applies (`from_sec1` then `from_der`), collapsed to `bool`:
//!
//! ```text
//! PublicKey::from_sec1(sec1).ok()
//!     .zip(Signature::from_der(der).ok())
//!     .map(|(key, sig)| key.verify(&digest, &sig).is_ok())
//!     .unwrap_or(false)
//! ```
//!
//! That is the contract `zk::SigVerifier` has to reproduce. It is *not* the
//! libsecp256k1 API surface: the library parses 65-byte and hybrid public keys
//! that this seam rejects, so rows where the two differ are recorded rather than
//! assumed away.
//!
//! No production code, consensus rule or signing path is touched by this file.

use std::path::{Path, PathBuf};

use k256::ecdsa::Signature as K256Signature;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, Scalar};
use zerocoin::crypto::hash::Hash256;
use zerocoin::crypto::secp256k1::{
    PrivateKey, PublicKey, Signature, COMPRESSED_PUBKEY_LEN, SECRET_LEN,
};
use zerocoin::ledger::script::p2pkh_script_pubkey;
use zerocoin::ledger::sighash::{signature_hash, SIGHASH_ALL};
use zerocoin::ledger::transaction::{Outpoint, Transaction, TxIn, TxOut};
use zerocoin::params::ChainParams;

// ---------------------------------------------------------------------------
// Curve constants
// ---------------------------------------------------------------------------

/// The secp256k1 group order.
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
    0x41, 0x41,
];

/// The field prime, used as "an `x` that is not a field element".
const FIELD_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
    0xfc, 0x2f,
];

const ALL_ONES: [u8; 32] = [0xff; 32];

// ---------------------------------------------------------------------------
// Fixtures the vectors are anchored to
// ---------------------------------------------------------------------------

struct Base {
    digest: [u8; 32],
    der: Vec<u8>,
    pubkey: Vec<u8>,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("vectors")
        .join("ledger")
}

fn load_json(name: &str) -> serde_json::Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn find_case<'a>(document: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    document["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .find(|case| case["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("case {id} not present"))
}

fn hex_field(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid hex")
}

/// The P2 corpus triple, reconstructed from the committed vector files rather
/// than retyped, so the differential fixture cannot drift from the corpus.
///
/// `ledger.sighash.signature_der` publishes the digest and the DER;
/// `ledger.script.p2pkh_spend_accepted` publishes the same DER inside a
/// `scriptSig` push together with the compressed key. Both are asserted below:
/// if the two files ever disagree, this panics instead of producing vectors.
fn p2_corpus_fixture() -> Base {
    let sighash = load_json("sighash.json");
    let script = load_json("script.json");

    let derived = find_case(&sighash, "ledger.sighash.signature_der");
    let spend = find_case(&script, "ledger.script.p2pkh_spend_accepted");

    let digest = hex_field(&derived["input"]["digest"]["internal_hex"]);
    let der = hex_field(&derived["expected"]["der_hex"]);
    let script_sig = hex_field(&spend["input"]["script_sig_hex"]);
    let sighash_type = spend["input"]["sighash_type"].as_u64().expect("sighash_type");

    assert_eq!(digest.len(), 32, "digest is 32 bytes");
    assert_eq!(
        script_sig[0] as usize,
        der.len() + 1,
        "the scriptSig push covers the DER plus the sighash byte"
    );
    assert_eq!(
        &script_sig[1..1 + der.len()],
        der.as_slice(),
        "scriptSig embeds the same DER as ledger.sighash.signature_der"
    );
    assert_eq!(
        script_sig[1 + der.len()],
        u8::try_from(sighash_type).expect("fits a byte"),
        "trailing sighash byte"
    );
    assert_eq!(script_sig[2 + der.len()], 33, "compressed pubkey push length");

    let pubkey = script_sig[3 + der.len()..].to_vec();
    assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_LEN);

    Base {
        digest: digest.as_slice().try_into().expect("32 bytes"),
        der,
        pubkey,
    }
}

/// The P2.3 fixture, byte for byte the same construction as
/// `tests/high_s_signature.rs`: a fixed scalar `[7u8; 32]`, its own P2PKH
/// script code, a one-input transaction, and the production sighash.
fn p23_fixture() -> Base {
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

    let der = key.sign(&digest).expect("signs the sighash").to_der().to_vec();

    Base {
        digest: digest.0,
        der,
        pubkey: public.to_sec1().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// The seam under comparison
// ---------------------------------------------------------------------------

/// Exactly the fail-closed composition a node applies, collapsed to a verdict.
fn seam_verdict(digest: &[u8; 32], der: &[u8], sec1: &[u8]) -> bool {
    let Ok(key) = PublicKey::from_sec1(sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(der) else {
        return false;
    };
    key.verify(&Hash256(*digest), &signature).is_ok()
}

// ---------------------------------------------------------------------------
// Deterministic encoders
// ---------------------------------------------------------------------------

fn split(der: &[u8]) -> ([u8; 32], [u8; 32]) {
    let parsed = K256Signature::from_der(der).expect("fixture DER parses");
    let (r, s) = parsed.split_bytes();
    (
        r.as_slice().try_into().expect("r is 32 bytes"),
        s.as_slice().try_into().expect("s is 32 bytes"),
    )
}

/// `(r, s) -> (r, n - s)`: the malleated twin of a low-S signature.
fn high_s_twin(der: &[u8]) -> Vec<u8> {
    let parsed = K256Signature::from_der(der).expect("fixture DER parses");
    let (r, s) = parsed.split_scalars();
    let s_high: Scalar = -*s;
    K256Signature::from_scalars(r.to_bytes(), s_high.to_bytes())
        .expect("n - s is a non-zero scalar below n")
        .to_der()
        .as_bytes()
        .to_vec()
}

/// DER `INTEGER` body: minimal, with a `0x00` pad when the sign bit is set.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut bytes = value.to_vec();
    while bytes.len() > 1 && bytes[0] == 0x00 {
        bytes.remove(0);
    }
    assert!(!bytes.is_empty(), "an integer needs at least one byte");
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    bytes
}

fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x30);
    if body.len() < 0x80 {
        out.push(u8::try_from(body.len()).expect("short form fits"));
    } else {
        out.push(0x81);
        out.push(u8::try_from(body.len()).expect("one length byte"));
    }
    out.extend_from_slice(body);
    out
}

fn der_pair(r_integer: &[u8], s_integer: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x02);
    body.push(u8::try_from(r_integer.len()).expect("fits"));
    body.extend_from_slice(r_integer);
    body.push(0x02);
    body.push(u8::try_from(s_integer.len()).expect("fits"));
    body.extend_from_slice(s_integer);
    der_sequence(&body)
}

fn der_signed(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    der_pair(&der_integer(r), &der_integer(s))
}

/// `value mod n` for a 32-byte big-endian value. One subtraction suffices
/// because `2^256 < 2n`.
fn reduce_mod_n(value: &[u8; 32]) -> [u8; 32] {
    if value < &GROUP_ORDER {
        return *value;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let difference =
            i16::from(value[index]) - i16::from(GROUP_ORDER[index]) - borrow;
        if difference < 0 {
            out[index] = u8::try_from(difference + 256).expect("in range");
            borrow = 1;
        } else {
            out[index] = u8::try_from(difference).expect("in range");
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "value must be >= n for the reduction to apply");
    out
}

// ---------------------------------------------------------------------------
// Case model and rendering
// ---------------------------------------------------------------------------

struct Case {
    id: String,
    group: &'static str,
    digest: [u8; 32],
    der: Vec<u8>,
    pubkey: Vec<u8>,
    note: String,
}

impl Case {
    fn new(
        group: &'static str,
        id: impl Into<String>,
        digest: &[u8; 32],
        der: &[u8],
        pubkey: &[u8],
        note: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            group,
            digest: *digest,
            der: der.to_vec(),
            pubkey: pubkey.to_vec(),
            note: note.into(),
        }
    }

    fn verdict(&self) -> bool {
        seam_verdict(&self.digest, &self.der, &self.pubkey)
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn render(cases: &[Case]) -> String {
    let mut out = String::new();
    out.push_str("# ZeroCoin P2.6 differential vectors.\n");
    out.push_str("#\n");
    out.push_str("# GENERATED by zerocoin/tests/differential_vectors.rs. Do not hand-edit.\n");
    out.push_str("# Every RUST line is the verdict of the Rust reference for that row, and\n");
    out.push_str("# differential_vectors_match_rust_reference re-derives it on every test run.\n");
    out.push_str("#\n");
    out.push_str("# '-' means an empty byte string. DER and PUBKEY are compared as raw bytes.\n");
    out.push_str("META format=zerocoin-differential-v1\n");
    out.push_str("META backend=libsecp256k1-0.8.0\n");
    out.push_str("META reference=zerocoin/src/crypto/secp256k1.rs\n");
    out.push_str("META seam=zk::SigVerifier (33-byte compressed SEC1, strict DER)\n");
    out.push_str(&format!("META cases={}\n", cases.len()));

    for case in cases {
        out.push('\n');
        out.push_str(&format!("CASE {}\n", case.id));
        out.push_str(&format!("GROUP {}\n", case.group));
        out.push_str(&format!(
            "RUST {}\n",
            if case.verdict() { "accept" } else { "reject" }
        ));
        out.push_str(&format!("DIGEST {}\n", hex_bytes(&case.digest)));
        out.push_str(&format!(
            "DER {}\n",
            if case.der.is_empty() {
                "-".to_string()
            } else {
                hex_bytes(&case.der)
            }
        ));
        out.push_str(&format!(
            "PUBKEY {}\n",
            if case.pubkey.is_empty() {
                "-".to_string()
            } else {
                hex_bytes(&case.pubkey)
            }
        ));
        out.push_str(&format!("NOTE {}\n", case.note));
        out.push_str("END\n");
    }

    out
}

// ---------------------------------------------------------------------------
// Vector construction
// ---------------------------------------------------------------------------

fn build_cases() -> Vec<Case> {
    let corpus = p2_corpus_fixture();
    let p23 = p23_fixture();
    let (r, s) = split(&p23.der);

    let mut cases = Vec::new();

    // -- V1: valid low-S -----------------------------------------------------
    cases.push(Case::new(
        "V1",
        "V1.p2_corpus_low_s",
        &corpus.digest,
        &corpus.der,
        &corpus.pubkey,
        "ledger.sighash.signature_der / ledger.script.p2pkh_spend_accepted triple: \
         scalar 1 over the regtest P2PKH sighash. Accepted by both.",
    ));
    cases.push(Case::new(
        "V1",
        "V1.p23_scalar7_low_s",
        &p23.digest,
        &p23.der,
        &p23.pubkey,
        "tests/high_s_signature.rs fixture: seed [7u8; 32], RFC 6979, low-S.",
    ));

    // -- V2: high-S twins ----------------------------------------------------
    cases.push(Case::new(
        "V2",
        "V2.p2_corpus_high_s_twin",
        &corpus.digest,
        &high_s_twin(&corpus.der),
        &corpus.pubkey,
        "(r, n - s) of V1.p2_corpus_low_s. Same ECDSA point; only the half-order \
         gate separates accept from reject.",
    ));
    cases.push(Case::new(
        "V2",
        "V2.p23_scalar7_high_s_twin",
        &p23.digest,
        &high_s_twin(&p23.der),
        &p23.pubkey,
        "(r, n - s) of V1.p23_scalar7_low_s.",
    ));

    {
        // The P2.4 probe shape: a digest of repeated 0x5a and the scalar 7 key,
        // so the twin is not tied to a sighash preimage.
        let key = PrivateKey::from_bytes(scalar_bytes(7)).expect("scalar 7");
        let digest = Hash256([0x5a; 32]);
        let low = key.sign(&digest).expect("signs").to_der().to_vec();
        cases.push(Case::new(
            "V2",
            "V2.s5_probe_digest_5a_high_s_twin",
            &digest.0,
            &high_s_twin(&low),
            &key.public_key().to_sec1(),
            "tests/s5_boundary_probes.rs twin shape: digest 0x5a repeated, scalar 7.",
        ));
    }

    // -- V3: DER structure ---------------------------------------------------
    let der_structural: Vec<(&str, Vec<u8>, &str)> = vec![
        ("V3.der_empty", Vec::new(), "zero-length input"),
        ("V3.der_sequence_only", vec![0x30, 0x00], "sequence with an empty body"),
        (
            "V3.der_truncated",
            p23.der[..p23.der.len() - 1].to_vec(),
            "last byte of s removed; length no longer matches",
        ),
        (
            "V3.der_trailing_byte",
            {
                let mut v = p23.der.clone();
                v.push(0x00);
                v
            },
            "one byte after the sequence",
        ),
        (
            "V3.der_trailing_inside_sequence",
            {
                let mut body = p23.der[2..].to_vec();
                body.push(0x00);
                der_sequence(&body)
            },
            "extra byte inside the sequence, after s; the length is consistent",
        ),
        (
            "V3.der_long_form_length",
            {
                let body = p23.der[2..].to_vec();
                let mut out = vec![0x30, 0x81, u8::try_from(body.len()).expect("fits")];
                out.extend_from_slice(&body);
                out
            },
            "length encoded in long form although it is below 0x80 (non-minimal)",
        ),
        (
            "V3.der_r_redundant_zero",
            {
                let mut integer = vec![0x00];
                integer.extend_from_slice(&der_integer(&r));
                der_pair(&integer, &der_integer(&s))
            },
            "r carries a 0x00 pad that minimality forbids",
        ),
        (
            "V3.der_s_redundant_zero",
            {
                let mut integer = vec![0x00];
                integer.extend_from_slice(&der_integer(&s));
                der_pair(&der_integer(&r), &integer)
            },
            "s carries a 0x00 pad that minimality forbids",
        ),
        (
            "V3.der_r_negative",
            {
                let mut negative = r;
                negative[0] |= 0x80;
                der_pair(&negative, &der_integer(&s))
            },
            "r has the sign bit set and no 0x00 pad, so it encodes a negative integer",
        ),
        (
            "V3.der_s_negative",
            {
                let mut negative = s;
                negative[0] |= 0x80;
                der_pair(&der_integer(&r), &negative)
            },
            "s has the sign bit set and no 0x00 pad",
        ),
        (
            "V3.der_wrong_integer_tag",
            {
                let mut malformed = p23.der.clone();
                malformed[2] = 0x03;
                malformed
            },
            "first INTEGER tag changed from 0x02 to 0x03",
        ),
        (
            "V3.der_indefinite_length",
            {
                let mut out = vec![0x30, 0x80];
                out.extend_from_slice(&p23.der[2..]);
                out.extend_from_slice(&[0x00, 0x00]);
                out
            },
            "indefinite length 0x80 (BER, not DER)",
        ),
        (
            "V3.der_r_zero",
            der_signed(&[0u8; 32], &s),
            "r = 0 is not a valid signature scalar",
        ),
        (
            "V3.der_s_zero",
            der_signed(&r, &[0u8; 32]),
            "s = 0 is not a valid signature scalar",
        ),
        (
            "V3.der_s_zero_length",
            {
                let r_integer = der_integer(&r);
                let mut body = vec![0x02, u8::try_from(r_integer.len()).expect("fits")];
                body.extend_from_slice(&r_integer);
                body.extend_from_slice(&[0x02, 0x00]);
                der_sequence(&body)
            },
            "s encoded as a zero-length INTEGER",
        ),
        (
            "V3.der_r_equals_n",
            der_signed(&GROUP_ORDER, &s),
            "r = n; the scalar must be strictly below the group order",
        ),
        (
            "V3.der_s_equals_n",
            der_signed(&r, &GROUP_ORDER),
            "s = n; the scalar must be strictly below the group order",
        ),
        (
            "V3.der_extra_integer",
            {
                let mut body = p23.der[2..].to_vec();
                body.extend_from_slice(&[0x02, 0x01, 0x01]);
                der_sequence(&body)
            },
            "a third INTEGER after s",
        ),
    ];
    for (id, der, note) in der_structural {
        cases.push(Case::new("V3", id, &p23.digest, &der, &p23.pubkey, note));
    }

    // -- V4: public-key encodings -------------------------------------------
    {
        let point = AffinePoint::from_encoded_point(
            &EncodedPoint::from_bytes(&p23.pubkey).expect("33-byte encoded point"),
        )
        .expect("the fixture key is a curve point");
        let uncompressed = point.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);

        let x_only = uncompressed[1..33].to_vec();
        let y_only = uncompressed[33..].to_vec();

        let mut hybrid_even = vec![0x06];
        hybrid_even.extend_from_slice(&x_only);
        hybrid_even.extend_from_slice(&y_only);

        let mut hybrid_odd = vec![0x07];
        hybrid_odd.extend_from_slice(&x_only);
        hybrid_odd.extend_from_slice(&y_only);

        let mut prefix_zero = vec![0x00];
        prefix_zero.extend_from_slice(&x_only);

        let mut prefix_five = vec![0x05];
        prefix_five.extend_from_slice(&x_only);

        let mut field_prime = vec![0x02];
        field_prime.extend_from_slice(&FIELD_PRIME);

        let mut length_34 = vec![0x02];
        length_34.extend_from_slice(&x_only);
        length_34.push(0x00);

        // A compressed encoding whose x has no solution on the curve. The
        // predicate is `AffinePoint::from_encoded_point`, i.e. the curve itself,
        // not the reference gate.
        let off_curve = {
            let mut found = None;
            for candidate in 1u32..1024 {
                let mut x = [0u8; 32];
                x[28..].copy_from_slice(&candidate.to_be_bytes());
                let mut sec1 = vec![0x02];
                sec1.extend_from_slice(&x);
                let encoded = EncodedPoint::from_bytes(&sec1).expect("33 bytes");
                if bool::from(AffinePoint::from_encoded_point(&encoded).is_none()) {
                    found = Some(sec1);
                    break;
                }
            }
            found.expect("some small x is off the curve")
        };

        let variants: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "V4.uncompressed_65",
                uncompressed,
                "SEQUENCE 04||x||y. libsecp256k1 accepts this encoding; the Rust seam rejects the length.",
            ),
            (
                "V4.hybrid_prefix_06",
                hybrid_even,
                "hybrid 0x06||x||y, 65 bytes. Same length gate.",
            ),
            (
                "V4.hybrid_prefix_07",
                hybrid_odd,
                "hybrid 0x07||x||y, 65 bytes. Same length gate.",
            ),
            ("V4.length_32", x_only, "x coordinate only, 32 bytes"),
            ("V4.length_34", length_34, "33-byte key plus a trailing byte"),
            ("V4.prefix_00", prefix_zero, "prefix 0x00 is not a SEC1 tag"),
            ("V4.prefix_05", prefix_five, "prefix 0x05 is not a SEC1 tag"),
            ("V4.all_zero_33", vec![0u8; 33], "33 zero bytes"),
            ("V4.empty", Vec::new(), "zero-length key"),
            (
                "V4.x_equals_field_prime",
                field_prime,
                "x = p is not a field element, so no point can decompress",
            ),
            (
                "V4.x_without_curve_point",
                off_curve,
                "x has no square root of x^3 + 7; the smallest such x is used",
            ),
        ];
        for (id, key, note) in variants {
            cases.push(Case::new("V4", id, &p23.digest, &p23.der, &key, note));
        }
    }

    // -- V5: digest handling -------------------------------------------------
    {
        let mut flipped = p23.digest;
        flipped[31] ^= 0x01;
        cases.push(Case::new(
            "V5",
            "V5.wrong_digest",
            &flipped,
            &p23.der,
            &p23.pubkey,
            "one bit of the digest flipped; the equation no longer holds",
        ));
        cases.push(Case::new(
            "V5",
            "V5.zero_digest",
            &[0u8; 32],
            &p23.der,
            &p23.pubkey,
            "all-zero digest for a signature made over a different prehash",
        ));

        // Reduction probes: both libraries reduce a 32-byte prehash mod n
        // (libsecp in `secp256k1_scalar_set_b32`, Rust in `verify_prehashed` ->
        // `Scalar::reduce_bytes`). Signing over the reduced value and then
        // presenting the unreduced 32 bytes separates "reduces" from "rejects".
        for (id, digest, note) in [
            (
                "V5.digest_equals_n_reduces_to_zero",
                GROUP_ORDER,
                "digest = n reduces to 0; the signature is made over z = 0",
            ),
            (
                "V5.digest_equals_n_plus_one_reduces_to_one",
                {
                    // n ends in 0x41, so incrementing the last byte is n + 1.
                    let mut value = GROUP_ORDER;
                    value[31] = 0x42;
                    value
                },
                "digest = n + 1 reduces to 1; the signature is made over z = 1",
            ),
            (
                "V5.digest_all_ones_reduces",
                ALL_ONES,
                "digest = 2^256 - 1 reduces to (2^256 - 1) - n",
            ),
        ] {
            let reduced = reduce_mod_n(&digest);
            let signer = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("scalar");
            let der = signer
                .sign(&Hash256(reduced))
                .expect("signs")
                .to_der()
                .to_vec();
            cases.push(Case::new("V5", id, &digest, &der, &p23.pubkey, note));
        }
    }

    // -- V6: P2 corpus replay ------------------------------------------------
    cases.push(Case::new(
        "V6",
        "V6.p2pkh_spend_accepted",
        &corpus.digest,
        &corpus.der,
        &corpus.pubkey,
        "The corpus triple replayed through the seam; identical bytes to \
         V1.p2_corpus_low_s, kept separate so the corpus anchor is visible.",
    ));
    cases.push(Case::new(
        "V6",
        "V6.script_sig_push_including_sighash_byte",
        &corpus.digest,
        &{
            let mut with_type = corpus.der.clone();
            with_type.push(0x01);
            with_type
        },
        &corpus.pubkey,
        "the 72-byte scriptSig push, i.e. DER plus the SIGHASH_ALL byte, fed as DER",
    ));

    // -- V7: corruption sweep ------------------------------------------------
    for index in 0..corpus.der.len() {
        let mut corrupted = corpus.der.clone();
        corrupted[index] ^= 0x01;
        cases.push(Case::new(
            "V7",
            format!("V7.corrupt_der_{index:02}"),
            &corpus.digest,
            &corrupted,
            &corpus.pubkey,
            format!("single-bit flip 0x01 at DER byte {index}"),
        ));
    }

    let key_corruptions: Vec<(String, Vec<u8>, String)> = vec![
        (
            "V7.corrupt_pubkey_prefix".to_string(),
            {
                let mut key = corpus.pubkey.clone();
                key[0] ^= 0x01;
                key
            },
            "prefix 0x02 -> 0x03: the negated point, a valid key that is not the signer"
                .to_string(),
        ),
        (
            "V7.corrupt_pubkey_x_first_byte".to_string(),
            {
                let mut key = corpus.pubkey.clone();
                key[1] ^= 0x01;
                key
            },
            "one bit of the x coordinate flipped".to_string(),
        ),
        (
            "V7.corrupt_pubkey_x_last_byte".to_string(),
            {
                let mut key = corpus.pubkey.clone();
                key[32] ^= 0x01;
                key
            },
            "the last x byte flipped".to_string(),
        ),
        (
            "V7.corrupt_pubkey_truncated".to_string(),
            corpus.pubkey[..32].to_vec(),
            "33-byte key truncated to 32".to_string(),
        ),
    ];
    for (id, key, note) in key_corruptions {
        cases.push(Case::new("V7", id, &corpus.digest, &corpus.der, &key, note));
    }

    cases.push(Case::new(
        "V7",
        "V7.corrupt_digest_last_byte",
        &{
            let mut digest = corpus.digest;
            digest[31] ^= 0x01;
            digest
        },
        &corpus.der,
        &corpus.pubkey,
        "single-bit flip of the digest",
    ));

    cases
}

fn scalar_bytes(value: u8) -> [u8; SECRET_LEN] {
    let mut bytes = [0u8; SECRET_LEN];
    bytes[SECRET_LEN - 1] = value;
    bytes
}

// ---------------------------------------------------------------------------
// Parsing (used by the oracle)
// ---------------------------------------------------------------------------

struct Recorded {
    id: String,
    group: String,
    rust_accept: bool,
    digest: [u8; 32],
    der: Vec<u8>,
    pubkey: Vec<u8>,
}

fn parse_field(value: &str) -> Vec<u8> {
    if value == "-" {
        Vec::new()
    } else {
        hex::decode(value).expect("fixture hex")
    }
}

fn parse_fixture(text: &str) -> (usize, Vec<Recorded>) {
    let mut declared = None;
    let mut cases = Vec::new();
    let mut open: Option<Recorded> = None;
    let mut pending_digest: Option<Vec<u8>> = None;
    let mut pending_group: Option<String> = None;

    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, rest) = match line.split_once(' ') {
            Some((keyword, rest)) => (keyword, rest.trim()),
            None => (line, ""),
        };

        match keyword {
            "META" => {
                let (key, value) = rest.split_once('=').expect("META key=value");
                if key == "cases" {
                    declared = Some(value.parse::<usize>().expect("META cases"));
                }
            }
            "CASE" => {
                assert!(open.is_none(), "line {}: CASE inside CASE", number + 1);
                pending_digest = None;
                pending_group = None;
                open = Some(Recorded {
                    id: rest.to_string(),
                    group: String::new(),
                    rust_accept: false,
                    digest: [0u8; 32],
                    der: Vec::new(),
                    pubkey: Vec::new(),
                });
            }
            "END" => {
                let mut case = open.take().expect("END without CASE");
                case.group = pending_group.take().expect("GROUP");
                let digest = pending_digest.take().expect("DIGEST");
                case.digest = digest.as_slice().try_into().expect("32-byte digest");
                cases.push(case);
            }
            _ => {
                let case = open.as_mut().expect("field outside CASE");
                match keyword {
                    "GROUP" => pending_group = Some(rest.to_string()),
                    "RUST" => {
                        case.rust_accept = match rest {
                            "accept" => true,
                            "reject" => false,
                            other => panic!("bad verdict {other}"),
                        }
                    }
                    "DIGEST" => pending_digest = Some(parse_field(rest)),
                    "DER" => case.der = parse_field(rest),
                    "PUBKEY" => case.pubkey = parse_field(rest),
                    "NOTE" => {}
                    other => panic!("unknown keyword {other}"),
                }
            }
        }
    }

    assert!(open.is_none(), "unterminated case");
    (declared.expect("META cases"), cases)
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("kernel")
        .join("differential")
        .join("vectors")
        .join("ledger.sighash.differential.txt")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Writes the committed fixture. Deliberately ignored: a normal `cargo test`
/// must not rewrite the evidence it is checking.
#[test]
#[ignore = "regenerates kernel/differential/vectors/ledger.sighash.differential.txt"]
fn emit_differential_vectors() {
    let cases = build_cases();
    let path = fixture_path();
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create vectors dir");
    std::fs::write(&path, render(&cases)).expect("write fixture");
    println!("wrote {} cases to {}", cases.len(), path.display());
}

/// The anti-fabrication control: every recorded verdict must still be the
/// verdict of the Rust reference, and the corpus anchor must be the corpus.
#[test]
fn differential_vectors_match_rust_reference() {
    let text = std::fs::read_to_string(fixture_path()).expect("read the committed fixture");
    let (declared, recorded) = parse_fixture(&text);

    assert_eq!(declared, recorded.len(), "META cases matches the row count");
    assert!(recorded.len() >= 100, "the fixture covers more than a token set");

    let mut seen = std::collections::BTreeSet::new();
    for case in &recorded {
        assert!(seen.insert(case.id.clone()), "duplicate case id {}", case.id);
        let verdict = seam_verdict(&case.digest, &case.der, &case.pubkey);
        assert_eq!(
            verdict, case.rust_accept,
            "recorded verdict for {} is stale",
            case.id
        );
    }

    for group in ["V1", "V2", "V3", "V4", "V5", "V6", "V7"] {
        assert!(
            recorded.iter().any(|case| case.group == group),
            "group {group} has no cases"
        );
    }

    // The corpus rows must carry the bytes the P2 corpus publishes.
    let corpus = p2_corpus_fixture();
    for id in ["V1.p2_corpus_low_s", "V6.p2pkh_spend_accepted"] {
        let case = recorded
            .iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("{id} missing"));
        assert_eq!(case.digest, corpus.digest, "{id} digest");
        assert_eq!(case.der, corpus.der, "{id} DER");
        assert_eq!(case.pubkey, corpus.pubkey, "{id} pubkey");
        assert!(case.rust_accept, "{id} must be accepted by the reference");
    }

    // And the high-S twin of the corpus row must be the recorded twin.
    let twin = recorded
        .iter()
        .find(|case| case.id == "V2.p2_corpus_high_s_twin")
        .expect("twin row");
    assert_eq!(twin.der, high_s_twin(&corpus.der));
    assert!(!twin.rust_accept, "high-S is rejected by the reference");
}
