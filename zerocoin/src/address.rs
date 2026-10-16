//! Base58Check addresses for P2PKH.
//!
//! A ZeroCoin address is the human-facing form of a public-key hash: the 20-byte
//! `HASH160` of a compressed public key, prefixed by a network version byte and
//! suffixed by a 4-byte checksum, all encoded in Base58. This is Bitcoin's
//! Base58Check exactly — same alphabet, same double-SHA-256 checksum — so an address
//! is short, copy-pasteable, and self-validating: a single mistyped character changes
//! the checksum and the address is refused rather than silently sending coins into a
//! hole.
//!
//! Base58 omits `0OIl` so addresses are unambiguous by eye. The version byte ties an
//! address to a network, so a mainnet address (`0x00`, leading `1`) is rejected on
//! devnet (`0x6f`, leading `m`/`n`) and vice versa.
//!
//! The checksum is computed with the crate's own [`sha256d`] rather than a Base58
//! library's built-in check feature, so the construction is explicit and matches the
//! rest of ZeroCoin's hashing.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::{sha256d, Hash160};
use crate::crypto::secp256k1::PublicKey;

/// Number of checksum bytes appended before Base58 encoding.
pub const CHECKSUM_LEN: usize = 4;
/// Length of the versioned payload: 1 version byte + 20 hash bytes.
pub const PAYLOAD_LEN: usize = 21;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("address is not valid Base58: {0}")]
    BadEncoding(String),
    #[error("address payload is {0} bytes, expected at least {PAYLOAD_LEN} plus a checksum")]
    BadLength(usize),
    #[error("address checksum does not match: the address was corrupted or mistyped")]
    BadChecksum,
    #[error("address version byte {found:#04x} does not match this network's {expected:#04x}")]
    WrongNetwork { expected: u8, found: u8 },
}

/// A decoded address: the network version byte and the public-key hash it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub version: u8,
    pub pubkey_hash: Hash160,
}

impl Address {
    /// Derive the address for a public key on a network identified by `version`.
    pub fn from_public_key(version: u8, public_key: &PublicKey) -> Address {
        Address {
            version,
            pubkey_hash: public_key.key_hash(),
        }
    }

    /// From a raw public-key hash and version byte.
    pub fn from_hash(version: u8, pubkey_hash: Hash160) -> Address {
        Address { version, pubkey_hash }
    }

    /// The versioned payload (before checksum): `version || pubkey_hash`.
    pub fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.pubkey_hash.0);
        payload
    }

    /// Encode to a Base58Check string.
    pub fn encode(&self) -> String {
        let mut data = self.payload();
        let checksum = sha256d(&data);
        data.extend_from_slice(&checksum.0[..CHECKSUM_LEN]);
        bs58::encode(data).into_string()
    }

    /// Decode a Base58Check string, verifying the checksum. The version byte is
    /// returned but not checked here, so a caller can report *which* network an
    /// address belongs to; use [`Address::decode_for_network`] to enforce one.
    pub fn decode(text: &str) -> Result<Address, AddressError> {
        let data = bs58::decode(text)
            .into_vec()
            .map_err(|e| AddressError::BadEncoding(e.to_string()))?;
        if data.len() < PAYLOAD_LEN + CHECKSUM_LEN {
            return Err(AddressError::BadLength(data.len()));
        }
        let (payload, checksum) = data.split_at(data.len() - CHECKSUM_LEN);
        let expected = sha256d(payload);
        if &expected.0[..CHECKSUM_LEN] != checksum {
            return Err(AddressError::BadChecksum);
        }
        // Only the canonical 21-byte payload is accepted; a longer one with a valid
        // trailing checksum is not an address this network knows how to spend.
        if payload.len() != PAYLOAD_LEN {
            return Err(AddressError::BadLength(payload.len()));
        }
        let version = payload[0];
        let pubkey_hash = Hash160::from_slice(&payload[1..PAYLOAD_LEN])
            .ok_or(AddressError::BadLength(payload.len()))?;
        Ok(Address {
            version,
            pubkey_hash,
        })
    }

    /// Decode and require the address to belong to the network with this version
    /// byte. This is what a wallet or node calls before paying an address.
    pub fn decode_for_network(text: &str, expected_version: u8) -> Result<Address, AddressError> {
        let address = Address::decode(text)?;
        if address.version != expected_version {
            return Err(AddressError::WrongNetwork {
                expected: expected_version,
                found: address.version,
            });
        }
        Ok(address)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl std::str::FromStr for Address {
    type Err = AddressError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Address::decode(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::PrivateKey;

    #[test]
    fn roundtrip_preserves_version_and_hash() {
        let key = PrivateKey::random().public_key();
        let address = Address::from_public_key(0x6f, &key);
        let text = address.encode();
        let decoded = Address::decode(&text).expect("decodes");
        assert_eq!(decoded, address);
        assert_eq!(decoded.pubkey_hash, key.key_hash());
    }

    #[test]
    fn mainnet_address_starts_with_one() {
        // A version byte of 0x00 yields the familiar leading '1' of a Bitcoin-style
        // mainnet P2PKH address.
        let key = PrivateKey::random().public_key();
        let text = Address::from_public_key(0x00, &key).encode();
        assert!(text.starts_with('1'), "mainnet address was {text}");
    }

    #[test]
    fn testnet_prefix_differs_from_mainnet() {
        let key = PrivateKey::random().public_key();
        let mainnet = Address::from_public_key(0x00, &key).encode();
        let devnet = Address::from_public_key(0x6f, &key).encode();
        assert_ne!(mainnet, devnet);
        assert!(devnet.starts_with('m') || devnet.starts_with('n'));
    }

    #[test]
    fn single_character_typo_is_rejected() {
        let key = PrivateKey::random().public_key();
        let text = Address::from_public_key(0x6f, &key).encode();
        // Corrupt one character; the checksum must catch it.
        let mut chars: Vec<char> = text.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let corrupted: String = chars.into_iter().collect();
        assert!(matches!(
            Address::decode(&corrupted),
            Err(AddressError::BadChecksum) | Err(AddressError::BadEncoding(_))
        ));
    }

    #[test]
    fn wrong_network_rejected() {
        let key = PrivateKey::random().public_key();
        let text = Address::from_public_key(0x6f, &key).encode();
        assert!(matches!(
            Address::decode_for_network(&text, 0x00),
            Err(AddressError::WrongNetwork { .. })
        ));
        assert!(Address::decode_for_network(&text, 0x6f).is_ok());
    }

    #[test]
    fn truncated_input_rejected() {
        assert!(matches!(
            Address::decode("2"),
            Err(AddressError::BadLength(_)) | Err(AddressError::BadEncoding(_))
        ));
    }

    #[test]
    fn display_and_fromstr_agree() {
        let key = PrivateKey::random().public_key();
        let address = Address::from_public_key(0x6f, &key);
        let parsed: Address = address.to_string().parse().expect("parses");
        assert_eq!(parsed, address);
    }
}
