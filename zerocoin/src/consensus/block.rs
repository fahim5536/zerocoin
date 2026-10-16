//! Block and block-header structures, Merkle commitment, and structural validation.
//!
//! A block's identity *is* its proof-of-work hash: the header preimage (everything
//! but the nonce) is hashed by the configured [`PowEngine`] together with the nonce,
//! and the result must be at or below the header's difficulty target. Because the
//! engine is named in the header, a block cannot silently switch algorithms.
//!
//! Validation here is purely structural and consensus-critical: correct chain,
//! height, previous hash, Merkle root, timestamp bounds, engine, difficulty and
//! proof of work. Transaction-level validation (inputs exist, signatures, maturity,
//! no double-spend) lives in [`crate::ledger::utxo`] and is applied by the node when
//! it connects a block.

use serde::{Deserialize, Serialize};

use crate::consensus::difficulty::{compact_to_target, hash_meets_target};
use crate::consensus::pow::PowEngine;
use crate::consensus::reward;
use crate::crypto::hash::{sha256d, Hash256};
use crate::ledger::transaction::Transaction;

/// Domain tag mixed into the header preimage so a header hash can never collide
/// with a transaction hash or another structure's hash. Frozen by
/// [`crate::consensus::immutability`]: changing one byte changes every header hash.
pub(crate) const HEADER_TAG: &[u8] = b"ZRO/header/v1\0";
/// Tag for the empty Merkle root, so an empty list has a fixed, non-zero identity.
/// Frozen like [`HEADER_TAG`].
pub(crate) const EMPTY_MERKLE_TAG: &[u8] = b"ZRO/merkle:empty\0";

pub const BLOCK_VERSION: u32 = 1;
pub const MAX_BLOCK_TRANSACTIONS: usize = 2_000;
/// How far ahead of the local clock a block timestamp may be (2 hours), as Bitcoin.
pub const MAX_FUTURE_SECONDS: u64 = 2 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("block commits to chain {found:#x} but this node serves {expected:#x}")]
    WrongChain { expected: u32, found: u32 },
    #[error("block height {found} does not follow tip height {expected}")]
    BadHeight { expected: u64, found: u64 },
    #[error("block's previous hash does not match the tip")]
    BadPreviousHash,
    #[error("Merkle root does not match the block's transactions")]
    RootMismatch,
    #[error("block uses engine id {found} but this network requires {expected}")]
    WrongEngine { expected: u8, found: u8 },
    #[error("block difficulty {found:#x} does not match the required {expected:#x}")]
    BadDifficulty { expected: u32, found: u32 },
    #[error("proof of work does not meet the block's own target")]
    InsufficientProofOfWork,
    #[error("block timestamp {found} is not after the median of the previous blocks ({median})")]
    TimestampTooOld { median: u64, found: u64 },
    #[error("block timestamp {found} is more than {MAX_FUTURE_SECONDS}s ahead of the clock ({now})")]
    TimestampTooFarFuture { now: u64, found: u64 },
    #[error("block has no transactions; the coinbase is mandatory")]
    NoTransactions,
    #[error("the first transaction of a block must be a coinbase")]
    FirstNotCoinbase,
    #[error("block contains more than one coinbase")]
    DuplicateCoinbase,
    #[error("block has {0} transactions, over the {MAX_BLOCK_TRANSACTIONS} limit")]
    TooManyTransactions(usize),
}

/// A block header. Every field feeds the proof-of-work hash except the nonce, which
/// is the value a miner varies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub chain: u32,
    pub height: u64,
    pub previous_hash: Hash256,
    pub merkle_root: Hash256,
    pub timestamp: u64,
    pub difficulty_bits: u32,
    /// Which [`PowEngine`] this block was mined with.
    pub engine_id: u8,
    pub nonce: u64,
}

impl BlockHeader {
    /// The canonical preimage the PoW engine hashes, excluding the nonce (which the
    /// engine appends itself).
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + HEADER_TAG.len());
        out.extend_from_slice(HEADER_TAG);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.chain.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.previous_hash.0);
        out.extend_from_slice(&self.merkle_root.0);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.difficulty_bits.to_le_bytes());
        out.push(self.engine_id);
        out
    }

    /// The block's proof-of-work hash, which is also its identity.
    pub fn pow_hash(&self, engine: &dyn PowEngine) -> Hash256 {
        engine.hash(&self.preimage(), self.nonce)
    }

    /// Whether this header's own hash meets its own advertised target.
    pub fn meets_own_target(&self, engine: &dyn PowEngine) -> bool {
        hash_meets_target(&self.pow_hash(engine), &compact_to_target(self.difficulty_bits))
    }
}

/// A full block: a header and its ordered transactions, the first of which is the
/// coinbase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Bitcoin-style Merkle root over the transaction ids: pair and hash up the
    /// tree, duplicating an odd trailing element.
    pub fn compute_merkle_root(transactions: &[Transaction]) -> Hash256 {
        let leaves: Vec<Hash256> = transactions.iter().map(|tx| tx.txid()).collect();
        merkle_root(&leaves)
    }

    /// The block's identity (its proof-of-work hash).
    pub fn id(&self, engine: &dyn PowEngine) -> Hash256 {
        self.header.pow_hash(engine)
    }

    /// Structural and proof-of-work validation of an untrusted block.
    ///
    /// `median_time_past` is the median timestamp of the previous 11 blocks and
    /// `now` is this node's clock; together they bound the timestamp so a miner
    /// cannot rewrite history or claim a far-future time to game retargeting.
    pub fn validate_structure(
        &self,
        engine: &dyn PowEngine,
        expected_chain: u32,
        expected_height: u64,
        expected_previous: &Hash256,
        expected_bits: u32,
        median_time_past: u64,
        now: u64,
    ) -> Result<(), BlockError> {
        let h = &self.header;

        if h.chain != expected_chain {
            return Err(BlockError::WrongChain {
                expected: expected_chain,
                found: h.chain,
            });
        }
        if h.height != expected_height {
            return Err(BlockError::BadHeight {
                expected: expected_height,
                found: h.height,
            });
        }
        if &h.previous_hash != expected_previous {
            return Err(BlockError::BadPreviousHash);
        }
        if h.engine_id != engine.id() {
            return Err(BlockError::WrongEngine {
                expected: engine.id(),
                found: h.engine_id,
            });
        }
        if h.difficulty_bits != expected_bits {
            return Err(BlockError::BadDifficulty {
                expected: expected_bits,
                found: h.difficulty_bits,
            });
        }
        if self.transactions.is_empty() {
            return Err(BlockError::NoTransactions);
        }
        if self.transactions.len() > MAX_BLOCK_TRANSACTIONS {
            return Err(BlockError::TooManyTransactions(self.transactions.len()));
        }
        // Exactly one coinbase, and it is first.
        if !self.transactions[0].is_coinbase() {
            return Err(BlockError::FirstNotCoinbase);
        }
        if self.transactions[1..].iter().any(Transaction::is_coinbase) {
            return Err(BlockError::DuplicateCoinbase);
        }
        if h.timestamp <= median_time_past {
            return Err(BlockError::TimestampTooOld {
                median: median_time_past,
                found: h.timestamp,
            });
        }
        if h.timestamp > now.saturating_add(MAX_FUTURE_SECONDS) {
            return Err(BlockError::TimestampTooFarFuture {
                now,
                found: h.timestamp,
            });
        }
        // The committed Merkle root must match the transactions actually present.
        let root = Self::compute_merkle_root(&self.transactions);
        if h.merkle_root != root {
            return Err(BlockError::RootMismatch);
        }
        // Finally, the proof of work must meet the header's own target.
        if !h.meets_own_target(engine) {
            return Err(BlockError::InsufficientProofOfWork);
        }
        Ok(())
    }

    /// Total fees the block's non-coinbase transactions pay, given the value of the
    /// inputs they spend. The node computes this while connecting the block; it is
    /// needed before the coinbase reward can be validated.
    pub fn subsidy_for_height(height: u64) -> u64 {
        reward::block_subsidy(height)
    }
}

/// Compute a Merkle root from 32-byte leaves.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return sha256d(EMPTY_MERKLE_TAG);
    }
    let mut level: Vec<Hash256> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&left.0);
            pair[32..].copy_from_slice(&right.0);
            next.push(sha256d(&pair));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::pow::TrivialEngine;
    use crate::crypto::secp256k1::PrivateKey;
    use crate::ledger::transaction::TxOut;

    fn sample_coinbase(height: u64) -> Transaction {
        let key = PrivateKey::from_bytes([5u8; 32]).unwrap().public_key();
        reward::coinbase_transaction(height, &key, reward::block_subsidy(height))
    }

    fn header_at(height: u64, prev: Hash256, root: Hash256) -> BlockHeader {
        BlockHeader {
            version: BLOCK_VERSION,
            chain: 1,
            height,
            previous_hash: prev,
            merkle_root: root,
            timestamp: 1_700_000_000 + height,
            difficulty_bits: 0x207f_ffff, // trivial target so mining is instant
            engine_id: 0,
            nonce: 0,
        }
    }

    #[test]
    fn merkle_root_is_stable_and_order_sensitive() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        assert_eq!(merkle_root(&[a, b]), merkle_root(&[a, b]));
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
        // Single leaf is its own root.
        assert_eq!(merkle_root(&[a]), a);
        // Empty has a fixed non-zero identity.
        assert_ne!(merkle_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn block_validates_with_correct_merkle_and_pow() {
        let engine = TrivialEngine::new();
        let txs = vec![sample_coinbase(1)];
        let root = Block::compute_merkle_root(&txs);
        let mut header = header_at(1, Hash256::ZERO, root);
        // Solve the trivial PoW.
        let preimage = header.preimage();
        let (nonce, _) =
            crate::consensus::pow::mine(&engine, &preimage, &compact_to_target(header.difficulty_bits), 0)
                .unwrap();
        header.nonce = nonce;
        header.engine_id = engine.id();

        let block = Block {
            header,
            transactions: txs,
        };
        assert!(block
            .validate_structure(&engine, 1, 1, &Hash256::ZERO, 0x207f_ffff, 0, u64::MAX)
            .is_ok());
    }

    #[test]
    fn tampered_merkle_root_rejected() {
        let engine = TrivialEngine::new();
        let txs = vec![sample_coinbase(1)];
        let root = Block::compute_merkle_root(&txs);
        let header = header_at(1, Hash256::ZERO, root);
        let mut block = Block {
            header,
            transactions: txs,
        };
        // Change an output value so the Merkle root no longer matches.
        block.transactions[0].outputs.push(TxOut {
            value: 1,
            script_pubkey: vec![],
        });
        assert!(matches!(
            block.validate_structure(&engine, 1, 1, &Hash256::ZERO, 0x207f_ffff, 0, u64::MAX),
            Err(BlockError::RootMismatch) | Err(BlockError::InsufficientProofOfWork)
        ));
    }

    #[test]
    fn missing_coinbase_rejected() {
        let engine = TrivialEngine::new();
        let root = Block::compute_merkle_root(&[]);
        let header = header_at(1, Hash256::ZERO, root);
        let block = Block {
            header,
            transactions: vec![],
        };
        assert!(matches!(
            block.validate_structure(&engine, 1, 1, &Hash256::ZERO, 0x207f_ffff, 0, u64::MAX),
            Err(BlockError::NoTransactions)
        ));
    }

    #[test]
    fn timestamp_must_advance_past_median() {
        let engine = TrivialEngine::new();
        let txs = vec![sample_coinbase(1)];
        let root = Block::compute_merkle_root(&txs);
        let mut header = header_at(1, Hash256::ZERO, root);
        header.timestamp = 100;
        let block = Block {
            header,
            transactions: txs,
        };
        // median_time_past above the timestamp => too old.
        assert!(matches!(
            block.validate_structure(&engine, 1, 1, &Hash256::ZERO, 0x207f_ffff, 200, u64::MAX),
            Err(BlockError::TimestampTooOld { .. })
        ));
    }
}
