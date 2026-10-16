//! Application-level P2P messages.
//!
//! These are the payloads carried inside [`crate::network::frame`] frames once a
//! session is established. They mirror Bitcoin's gossip protocol, grouped by the
//! job each does:
//!
//! - **Handshake / liveness**: [`Message::Version`], [`Message::Verack`],
//!   [`Message::Ping`], [`Message::Pong`].
//! - **Peer discovery**: [`Message::GetAddr`], [`Message::Addr`].
//! - **Mempool and block propagation**: [`Message::Inv`], [`Message::GetData`],
//!   [`Message::Tx`], [`Message::Block`].
//! - **Header sync**: [`Message::GetHeaders`], [`Message::Headers`].
//! - **Pool shares**: [`Message::Share`], a partial proof of work a low-end device
//!   submits to earn a proportional micro-reward (see [`crate::pool`]).
//!
//! The encoding is JSON. That is a deliberate trade: the frame layer already
//! guarantees confidentiality, integrity and freshness, so the codec's only job is
//! to be unambiguous and easy to evolve. Consensus identity is *not* taken from
//! this encoding — a transaction's `txid` and a block's proof-of-work hash are
//! computed from their own canonical serializers in the `ledger` and `consensus`
//! layers — so a JSON wire format can never change what the network agrees on.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::consensus::block::{Block, BlockHeader};
use crate::crypto::hash::Hash256;
use crate::crypto::secp256k1::PublicKey;
use crate::ledger::transaction::Transaction;

/// Bumped whenever the message set changes incompatibly. Peers that disagree on
/// this refuse to talk rather than misparse each other. Version 2 added
/// [`Message::Share`] for the in-built pool's partial-proof-of-work submissions.
pub const PROTOCOL_VERSION: u32 = 2;

/// Bounds on list-carrying messages, so one peer cannot bury another in work.
/// These mirror the limits Bitcoin places on `inv`, `addr` and `getheaders`.
pub const MAX_INV_ENTRIES: usize = 500;
pub const MAX_ADDR_ENTRIES: usize = 1_000;
pub const MAX_HEADERS: usize = 2_000;
pub const MAX_LOCATOR_ENTRIES: usize = 101;

/// What kind of object an inventory vector names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvKind {
    /// A transaction, sought for the mempool.
    Tx = 1,
    /// A block, sought for the chain.
    Block = 2,
}

/// An inventory vector: a typed object hash, as in Bitcoin's `inv`/`getdata`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub kind: InvKind,
    pub hash: Hash256,
}

impl Inventory {
    pub fn tx(hash: Hash256) -> Self {
        Inventory {
            kind: InvKind::Tx,
            hash,
        }
    }

    pub fn block(hash: Hash256) -> Self {
        Inventory {
            kind: InvKind::Block,
            hash,
        }
    }
}

/// The opening message of an application session, exchanged right after the
/// cryptographic handshake so each side learns the other's version, chain, height
/// and dial-back address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionPayload {
    pub version: u32,
    /// The chain id the peer serves; a mismatch means the peers are on different
    /// networks and must disconnect.
    pub chain: u32,
    /// The peer's best known block height, used to decide whether to sync.
    pub height: u64,
    /// The address the peer can be dialed back on (its source port is ephemeral
    /// and useless for redialing).
    pub listen: Option<SocketAddr>,
    /// A random nonce; if it comes back in the peer's `Version`, the connection is
    /// to ourselves and is dropped.
    pub nonce: u64,
}

/// A **partial proof of work** a low-end device submits to the pool. It carries the
/// block header the miner worked on — including the winning `nonce`, so a coordinator
/// can re-hash it and check it against the (easier) share target — and the miner's
/// payout key, which decides where the micro-reward is credited.
///
/// A share mints nothing and touches no consensus state: it is a pool-layer promise
/// to include `payout` in a future block's split coinbase. Only that coinbase, whose
/// total never exceeds `subsidy + fees`, reaches the chain, so the 21,000,000 ZRO
/// cap is unaffected by however many shares circulate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePayload {
    /// The header the miner solved against the share target; its `nonce` is the proof.
    pub header: BlockHeader,
    /// Where to credit this miner's micro-reward.
    pub payout: PublicKey,
}

/// A protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Opening handshake.
    Version(VersionPayload),
    /// Handshake acknowledged; carries the responder's version and height.
    Verack { version: u32, height: u64 },
    /// Liveness probe.
    Ping { nonce: u64 },
    /// Liveness reply, echoing the probe's nonce.
    Pong { nonce: u64 },
    /// "Which peers do you know?" (Bitcoin `getaddr`.)
    GetAddr,
    /// Dial-back addresses a peer offers. (Bitcoin `addr`.)
    Addr { addresses: Vec<SocketAddr> },
    /// "I have these objects." A hash list, never the objects themselves. (Bitcoin `inv`.)
    Inv { items: Vec<Inventory> },
    /// "Send me these specific objects." (Bitcoin `getdata`.)
    GetData { items: Vec<Inventory> },
    /// A transaction, relayed because it was announced and requested.
    Tx { transaction: Box<Transaction> },
    /// "Give me headers above the fork point my locator names." (Bitcoin `getheaders`.)
    GetHeaders { locator: Vec<Hash256>, stop: Hash256 },
    /// Header chain returned for a `GetHeaders`, newest-last.
    Headers { headers: Vec<BlockHeader> },
    /// A full block body, sent only in answer to a `GetData` that named its hash.
    Block { block: Box<Block> },
    /// A partial proof of work submitted to the in-built pool for a micro-reward.
    Share(Box<SharePayload>),
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("message is not valid protocol data: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("message list has {found} entries, over the {limit} limit")]
    TooManyEntries { limit: usize, found: usize },
    #[error("protocol version {0} is not supported")]
    UnsupportedVersion(u32),
}

impl Message {
    /// Serialize to the bytes carried in a frame's plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse from a frame's plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Message, MessageError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Enforce the per-message list bounds. A node calls this right after decoding
    /// so an oversized announcement is rejected before it is ever acted on.
    pub fn validate_limits(&self) -> Result<(), MessageError> {
        match self {
            Message::Inv { items } | Message::GetData { items } => {
                bounded(MAX_INV_ENTRIES, items.len())?;
            }
            Message::Addr { addresses } => {
                bounded(MAX_ADDR_ENTRIES, addresses.len())?;
            }
            Message::Headers { headers } => {
                bounded(MAX_HEADERS, headers.len())?;
            }
            Message::GetHeaders { locator, .. } => {
                bounded(MAX_LOCATOR_ENTRIES, locator.len())?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether this message belongs to the initial handshake, before the peers
    /// exchange any chain data. A node drops anything else that arrives first.
    pub fn is_handshake(&self) -> bool {
        matches!(self, Message::Version(_) | Message::Verack { .. })
    }
}

fn bounded(limit: usize, found: usize) -> Result<(), MessageError> {
    if found > limit {
        return Err(MessageError::TooManyEntries { limit, found });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_roundtrip() {
        let msg = Message::Version(VersionPayload {
            version: PROTOCOL_VERSION,
            chain: 0x2E01_0001,
            height: 1234,
            listen: Some("127.0.0.1:8333".parse().unwrap()),
            nonce: 0xdead_beef,
        });
        let bytes = msg.encode().expect("encodes");
        let back = Message::decode(&bytes).expect("decodes");
        assert_eq!(msg, back);
        assert!(back.is_handshake());
    }

    #[test]
    fn inventory_roundtrip() {
        let msg = Message::Inv {
            items: vec![
                Inventory::tx(Hash256([1u8; 32])),
                Inventory::block(Hash256([2u8; 32])),
            ],
        };
        let back = Message::decode(&msg.encode().unwrap()).unwrap();
        assert_eq!(msg, back);
        assert!(back.validate_limits().is_ok());
    }

    #[test]
    fn ping_pong_nonce_preserved() {
        let ping = Message::Ping { nonce: 42 };
        assert_eq!(Message::decode(&ping.encode().unwrap()).unwrap(), ping);
    }

    #[test]
    fn oversized_inv_rejected() {
        let items = vec![Inventory::tx(Hash256([0u8; 32])); MAX_INV_ENTRIES + 1];
        let msg = Message::Inv { items };
        assert!(matches!(
            msg.validate_limits(),
            Err(MessageError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn addr_roundtrip_and_bound() {
        let addresses = vec!["10.0.0.1:8333".parse().unwrap(), "[::1]:8333".parse().unwrap()];
        let msg = Message::Addr { addresses };
        assert_eq!(Message::decode(&msg.encode().unwrap()).unwrap(), msg);
        assert!(msg.validate_limits().is_ok());
    }

    #[test]
    fn garbage_bytes_rejected() {
        assert!(matches!(
            Message::decode(b"not json at all"),
            Err(MessageError::Codec(_))
        ));
    }

    #[test]
    fn share_roundtrip() {
        use crate::crypto::secp256k1::PrivateKey;
        let payout = PrivateKey::from_bytes([7u8; 32]).unwrap().public_key();
        let header = BlockHeader {
            version: crate::consensus::block::BLOCK_VERSION,
            chain: 0x2E01_0001,
            height: 42,
            previous_hash: Hash256([1u8; 32]),
            merkle_root: Hash256([2u8; 32]),
            timestamp: 1_700_000_000,
            difficulty_bits: 0x207f_ffff,
            engine_id: 1,
            nonce: 12_345,
        };
        let msg = Message::Share(Box::new(SharePayload { header, payout }));
        let back = Message::decode(&msg.encode().unwrap()).unwrap();
        assert_eq!(msg, back);
        // A share carries no list, so it is within bounds, and it is not a handshake.
        assert!(back.validate_limits().is_ok());
        assert!(!back.is_handshake());
    }

    #[test]
    fn protocol_version_is_two_with_shares() {
        assert_eq!(PROTOCOL_VERSION, 2);
    }
}
