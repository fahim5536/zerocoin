//! Hash functions and the digest newtypes used across the ledger.
//!
//! ZeroCoin uses Bitcoin's hash conventions: `sha256d` (double SHA-256) for
//! transaction and block identifiers, and `hash160` (RIPEMD-160 over SHA-256) for
//! public-key hashes inside P2PKH outputs.

use std::fmt;

use ripemd::Ripemd160;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// A 32-byte double-SHA-256 digest: the shape of every txid and block hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

/// A 20-byte RIPEMD-160(SHA-256) digest: the shape of a P2PKH public-key hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash160(pub [u8; 20]);

impl Hash256 {
    /// The all-zero digest, used as the null outpoint of a coinbase input.
    pub const ZERO: Hash256 = Hash256([0u8; 32]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Some(Hash256(out))
    }

    /// Bitcoin prints block hashes byte-reversed; the ledger stores them big-endian
    /// internally. This is the display form a user recognizes from an explorer.
    pub fn to_display_hex(&self) -> String {
        let mut reversed = self.0;
        reversed.reverse();
        hex::encode(reversed)
    }
}

impl Hash160 {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 20 {
            return None;
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(bytes);
        Some(Hash160(out))
    }
}

/// Single SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Double SHA-256, the transaction/block identifier hash.
pub fn sha256d(data: &[u8]) -> Hash256 {
    Hash256(sha256(&sha256(data)))
}

/// RIPEMD-160 over SHA-256, the P2PKH public-key hash.
pub fn hash160(data: &[u8]) -> Hash160 {
    let sha = sha256(data);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    Hash160(out)
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash160({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// Serde stores digests as fixed-length hex so snapshots stay human-readable and
// canonical regardless of the serializer's binary support.
impl Serialize for Hash256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected a 32-byte hex digest"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Hash256(out))
    }
}

impl Serialize for Hash160 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Hash160 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom("expected a 20-byte hex digest"));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Hash160(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc") — a published test vector.
        let digest = sha256(b"abc");
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256d_is_double_application() {
        let once = sha256(b"zerocoin");
        assert_eq!(sha256d(b"zerocoin").0, sha256(&once));
    }

    #[test]
    fn hash160_is_twenty_bytes() {
        assert_eq!(hash160(b"pubkey").0.len(), 20);
    }

    #[test]
    fn display_hex_reverses_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        let hash = Hash256(bytes);
        // Big-endian internal storage prints reversed, so 0xab lands last.
        assert!(hash.to_display_hex().ends_with("ab"));
    }
}
