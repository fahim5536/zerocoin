//! secp256k1 ECDSA keys and signatures.
//!
//! ZeroCoin uses Bitcoin's curve. A [`PrivateKey`] wraps a 32-byte scalar that is
//! zeroized on drop; a [`PublicKey`] is the compressed SEC1 encoding (33 bytes) of
//! the matching curve point; a [`Signature`] is a DER-encoded ECDSA signature.
//!
//! Signing operates on a *precomputed* 32-byte digest (`sign_prehash`) rather than
//! hashing the message again, which is exactly how Bitcoin signs a sighash. All
//! arithmetic comes from `k256`; nothing here re-implements the curve.

use std::fmt;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::ecdsa::Signature as K256Signature;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use super::hash::{hash160, Hash160, Hash256};

/// Length of a compressed SEC1 public key.
pub const COMPRESSED_PUBKEY_LEN: usize = 33;
/// Length of a private-key scalar.
pub const SECRET_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("secret key is not a valid secp256k1 scalar")]
    InvalidSecret,
    #[error("public key is not a valid compressed secp256k1 point")]
    InvalidPublicKey,
    #[error("signature is not valid DER encoding")]
    InvalidSignature,
    #[error("signature does not verify against this key and digest")]
    VerificationFailed,
}

/// A secret scalar. The bytes are wiped when the key is dropped.
pub struct PrivateKey {
    bytes: Zeroizing<[u8; SECRET_LEN]>,
}

impl PrivateKey {
    /// Generate a fresh key from the operating-system CSPRNG.
    pub fn random() -> Self {
        let signing = SigningKey::random(&mut OsRng);
        let mut bytes = [0u8; SECRET_LEN];
        bytes.copy_from_slice(&signing.to_bytes());
        PrivateKey {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Reconstruct a key from a 32-byte scalar, rejecting zero and out-of-range
    /// values that are not valid secp256k1 private keys.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Result<Self, CryptoError> {
        // `SigningKey::from_slice` enforces 0 < scalar < group order.
        SigningKey::from_slice(&bytes).map_err(|_| CryptoError::InvalidSecret)?;
        Ok(PrivateKey {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// The 32-byte scalar. Callers should treat the result as secret.
    pub fn to_bytes(&self) -> [u8; SECRET_LEN] {
        *self.bytes
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        let signing = SigningKey::from_slice(&self.bytes[..]).expect("validated at construction");
        let verifying = signing.verifying_key();
        let point = verifying.to_encoded_point(true);
        let mut bytes = [0u8; COMPRESSED_PUBKEY_LEN];
        bytes.copy_from_slice(point.as_bytes());
        PublicKey { bytes }
    }

    /// Sign a 32-byte digest (a sighash). Deterministic per RFC 6979.
    pub fn sign(&self, digest: &Hash256) -> Result<Signature, CryptoError> {
        let signing = SigningKey::from_slice(&self.bytes[..]).map_err(|_| CryptoError::InvalidSecret)?;
        let signature = signing
            .sign_prehash(&digest.0)
            .map_err(|_| CryptoError::InvalidSecret)?;
        Ok(Signature::from_k256(signature))
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey {
            bytes: Zeroizing::new(*self.bytes),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never leak the scalar, even to logs.
        write!(f, "PrivateKey(<redacted>)")
    }
}

/// A compressed SEC1 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    bytes: [u8; COMPRESSED_PUBKEY_LEN],
}

impl PublicKey {
    /// Parse a 33-byte compressed SEC1 public key.
    ///
    /// Only the tags `0x02` and `0x03` are in contract; every other encoding is
    /// rejected before the curve is touched. See
    /// `docs/consensus/PUBLIC_KEY_ENCODING_CONTRACT.md` (P-1).
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != COMPRESSED_PUBKEY_LEN {
            return Err(CryptoError::InvalidPublicKey);
        }
        // `k256` also decodes SEC1 tag 0x05 ("compact"), which names the same
        // point with an even `y`. Accepting it would give one point two key
        // hashes, because `key_hash` commits to the encoding, not the point.
        if !matches!(bytes[0], 0x02 | 0x03) {
            return Err(CryptoError::InvalidPublicKey);
        }
        // Validate that the bytes are a real point on the curve.
        VerifyingKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
        out.copy_from_slice(bytes);
        Ok(PublicKey { bytes: out })
    }

    pub fn to_sec1(&self) -> [u8; COMPRESSED_PUBKEY_LEN] {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The P2PKH public-key hash: RIPEMD-160(SHA-256(pubkey)).
    pub fn key_hash(&self) -> Hash160 {
        hash160(&self.bytes)
    }

    /// Verify a signature over a 32-byte digest.
    pub fn verify(&self, digest: &Hash256, signature: &Signature) -> Result<(), CryptoError> {
        let verifying = self.verifying_key()?;
        let sig = signature.to_k256()?;
        verifying
            .verify_prehash(&digest.0, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_sec1_bytes(&self.bytes).map_err(|_| CryptoError::InvalidPublicKey)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.bytes))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

/// A DER-encoded ECDSA signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    der: Vec<u8>,
}

impl Signature {
    /// Wrap an already-produced `k256` signature in its DER encoding.
    fn from_k256(signature: K256Signature) -> Signature {
        Signature {
            der: signature.to_der().as_bytes().to_vec(),
        }
    }

    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        // Parse to reject malleable / malformed encodings before we ever store them.
        K256Signature::from_der(der).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Signature {
            der: der.to_vec(),
        })
    }

    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    fn to_k256(&self) -> Result<K256Signature, CryptoError> {
        K256Signature::from_der(&self.der).map_err(|_| CryptoError::InvalidSignature)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(&self.der))
    }
}

/// A stateless marker mirroring the reference prototype's `SignatureScheme`, so
/// generic validation code can name the algorithm it expects.
pub struct ECDSA;

impl ECDSA {
    pub fn verify(
        public_key: &PublicKey,
        digest: &Hash256,
        signature: &Signature,
    ) -> bool {
        public_key.verify(digest, signature).is_ok()
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.bytes))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        PublicKey::from_sec1(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.der))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        Signature::from_der(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = PrivateKey::random();
        let digest = Hash256(crate::crypto::hash::sha256(b"zerocoin message"));
        let signature = key.sign(&digest).expect("signs");
        assert!(key.public_key().verify(&digest, &signature).is_ok());
    }

    #[test]
    fn wrong_digest_fails_verification() {
        let key = PrivateKey::random();
        let digest = Hash256(crate::crypto::hash::sha256(b"one"));
        let other = Hash256(crate::crypto::hash::sha256(b"two"));
        let signature = key.sign(&digest).expect("signs");
        assert_eq!(
            key.public_key().verify(&other, &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let a = PrivateKey::random();
        let b = PrivateKey::random();
        let digest = Hash256(crate::crypto::hash::sha256(b"payload"));
        let signature = a.sign(&digest).expect("signs");
        assert!(b.public_key().verify(&digest, &signature).is_err());
    }

    #[test]
    fn public_key_is_compressed_and_stable() {
        let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("valid scalar");
        let pubkey = key.public_key();
        assert_eq!(pubkey.to_sec1().len(), COMPRESSED_PUBKEY_LEN);
        // The first byte of a compressed key is the parity prefix 0x02 or 0x03.
        assert!(matches!(pubkey.to_sec1()[0], 0x02 | 0x03));
        // Round-trips through SEC1.
        assert_eq!(PublicKey::from_sec1(&pubkey.to_sec1()).unwrap(), pubkey);
    }

    #[test]
    fn accepts_only_the_two_compressed_tags() {
        let key = PrivateKey::from_bytes([7u8; SECRET_LEN]).expect("valid scalar");
        let canonical = key.public_key().to_sec1();

        // Both parities of the same `x` are in contract: `y` and `-y` are on curve.
        for tag in [0x02u8, 0x03] {
            let mut bytes = canonical;
            bytes[0] = tag;
            let parsed = PublicKey::from_sec1(&bytes).expect("compressed tag is accepted");
            assert_eq!(parsed.to_sec1(), bytes, "the encoding is stored unchanged");
        }

        // Every other tag is out of contract, including SEC1 "compact" 0x05.
        for tag in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff] {
            let mut bytes = canonical;
            bytes[0] = tag;
            assert_eq!(
                PublicKey::from_sec1(&bytes).err(),
                Some(CryptoError::InvalidPublicKey),
                "tag {tag:#04x}"
            );
        }

        // The length gate still runs first.
        assert!(PublicKey::from_sec1(&canonical[..32]).is_err());
        assert!(PublicKey::from_sec1(&[canonical.as_slice(), &[0u8]].concat()).is_err());
    }

    #[test]
    fn rejects_invalid_secret() {
        // Zero is not a valid private key.
        assert_eq!(
            PrivateKey::from_bytes([0u8; SECRET_LEN]).err(),
            Some(CryptoError::InvalidSecret)
        );
    }

    #[test]
    fn key_hash_is_twenty_bytes() {
        let key = PrivateKey::random();
        assert_eq!(key.public_key().key_hash().0.len(), 20);
    }
}
