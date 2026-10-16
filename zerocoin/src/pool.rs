//! The in-built mining pool: partial proofs of work ("shares") and micro-rewards.
//!
//! ZeroCoin's third deviation from Bitcoin, and the one that opens mining to a phone.
//! A low-end device will essentially never win a full block race against a rig, so on
//! its own it would earn nothing. The pool lets such a device submit **shares** —
//! valid proofs of work against a deliberately *easier* target — to a coordinating
//! full node. The node credits each contributor's share weight, and when it next
//! finds a block it splits that block's reward across everyone by weight in a single
//! multi-output coinbase (see [`crate::consensus::reward::split_reward`]).
//!
//! ## Why this cannot break the 21,000,000 ZRO cap
//!
//! A share is *pool-layer* state: it lives only in a coordinator's memory and never
//! enters a block. Shares mint nothing. The only thing that reaches the chain is the
//! split coinbase, whose total is bounded by `subsidy + fees` and re-checked by
//! [`crate::consensus::reward::validate_coinbase`] at connect time exactly as a solo
//! coinbase is. So the pool *redistributes* the one subsidy a block already earns;
//! it can never enlarge it. However many shares circulate, issuance is unchanged.
//!
//! ## Finder weight
//!
//! Whoever finds the actual block did `DEFAULT_SHARE_EASINESS` times the work of one
//! share, so it is credited [`FINDER_SHARE_WEIGHT`] — the share-equivalent of a whole
//! block. That keeps the economics honest: the finder takes the bulk of the reward,
//! and mobile share-miners earn a fair, stable, but smaller slice proportional to the
//! shares they actually produced.

use std::collections::BTreeMap;

use crate::consensus::block::BlockHeader;
use crate::consensus::difficulty::compact_to_target;
use crate::consensus::pow::{share_target, verify_pow, PowEngine, DEFAULT_SHARE_EASINESS};
use crate::consensus::reward::PoolPayout;
use crate::consensus::uint256::Uint256;
use crate::crypto::hash::{Hash160, Hash256};
use crate::ledger::sighash::ChainId;
use crate::params::ChainParams;

/// The weight one accepted share contributes. Share difficulty is fixed, so every
/// share is worth the same and a contributor's weight is simply its share count.
pub const SHARE_WEIGHT: u64 = 1;

/// The weight credited to whoever finds the actual block: one block is
/// `DEFAULT_SHARE_EASINESS` shares' worth of work, so the finder is paid as if it had
/// submitted that many shares. This is what makes the split fair between a rig that
/// wins the block and the phones that contributed shares toward it.
pub const FINDER_SHARE_WEIGHT: u64 = DEFAULT_SHARE_EASINESS;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    #[error("share is for chain {found} but this node serves {expected}")]
    WrongChain { expected: u32, found: u32 },
    #[error("share is for height {found} but the pool is mining height {expected}")]
    StaleWork { expected: u64, found: u64 },
    #[error("share does not meet the required share target")]
    InsufficientWork,
}

/// The pool's off-chain accounting of who contributed share work toward the next
/// block: each contributor's P2PKH public-key hash mapped to the total share weight
/// they have earned.
///
/// This is deliberately *not* consensus state. It is a plain in-memory map that a
/// coordinator drains when it mines; the chain only ever sees the resulting coinbase.
/// A `BTreeMap` gives a deterministic iteration order, so the payout list — and thus
/// the coinbase and its txid — is reproducible for a given set of contributions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolLedger {
    contributions: BTreeMap<Hash160, u64>,
    total_weight: u64,
}

impl PoolLedger {
    pub fn new() -> Self {
        PoolLedger::default()
    }

    /// Credit `weight` share-weight to a contributor. Addition saturates rather than
    /// overflowing, so a flood of shares can never wrap the accounting into a smaller
    /// total (which would let a contributor claim more than they earned).
    pub fn record(&mut self, beneficiary: Hash160, weight: u64) {
        if weight == 0 {
            return;
        }
        let entry = self.contributions.entry(beneficiary).or_insert(0);
        *entry = entry.saturating_add(weight);
        self.total_weight = self.total_weight.saturating_add(weight);
    }

    /// Record a single accepted share (weight [`SHARE_WEIGHT`]) for a contributor.
    pub fn record_share(&mut self, beneficiary: Hash160) {
        self.record(beneficiary, SHARE_WEIGHT);
    }

    /// Total weight accumulated across all contributors.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// How many distinct contributors have earned weight.
    pub fn contributor_count(&self) -> usize {
        self.contributions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contributions.is_empty()
    }

    /// The weight credited to one contributor, or 0 if they have none.
    pub fn weight_of(&self, beneficiary: &Hash160) -> u64 {
        self.contributions.get(beneficiary).copied().unwrap_or(0)
    }

    /// A snapshot of the contributions as a payout weight list, without clearing
    /// them. Deterministically ordered by public-key hash.
    pub fn payouts(&self) -> Vec<PoolPayout> {
        self.contributions.iter().map(|(h, w)| (*h, *w)).collect()
    }

    /// Take every contribution out, resetting the ledger, and return them as the
    /// payout weight list for the next block's split coinbase. A coordinator calls
    /// this immediately before mining, so each block pays out exactly the shares
    /// accumulated since the last one.
    pub fn drain(&mut self) -> Vec<PoolPayout> {
        let payouts = self.payouts();
        self.contributions.clear();
        self.total_weight = 0;
        payouts
    }
}

/// Validate a submitted share: it must be for this network, for the height the pool
/// is currently mining, and its proof must meet the (easier) share target. Returns
/// the share hash on success.
///
/// This is the *entire* cost a coordinator pays per submission — one hash compared to
/// a target — and it touches no consensus state, so a flood of bogus shares costs an
/// attacker a peer only a single hash each and can never inflate the supply or corrupt
/// the chain. The share's `nonce` is carried in `header`, so validation re-hashes the
/// very preimage the miner worked on.
pub fn validate_share_submission(
    engine: &dyn PowEngine,
    header: &BlockHeader,
    expected_chain: ChainId,
    expected_height: u64,
    share_target: &Uint256,
) -> Result<Hash256, ShareError> {
    if header.chain != expected_chain.0 {
        return Err(ShareError::WrongChain {
            expected: expected_chain.0,
            found: header.chain,
        });
    }
    if header.height != expected_height {
        return Err(ShareError::StaleWork {
            expected: expected_height,
            found: header.height,
        });
    }
    verify_pow(engine, &header.preimage(), header.nonce, share_target)
        .map_err(|_| ShareError::InsufficientWork)
}

/// The share target a low-end miner must meet to have a share accepted for a block
/// whose target is `block_target`, under `params`' difficulty floor. Bounded by the
/// network `pow_limit`, so a share is never easier than the easiest legal block and a
/// coordinator cannot be tricked into accepting trivially-cheap shares.
pub fn share_target_for(params: &ChainParams, block_target: &Uint256) -> Uint256 {
    let pow_limit = compact_to_target(params.difficulty.pow_limit_bits);
    share_target(block_target, DEFAULT_SHARE_EASINESS, &pow_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::block::BLOCK_VERSION;
    use crate::consensus::pow::{mine, TrivialEngine, ENGINE_ID_TRIVIAL};
    use crate::consensus::reward::{block_subsidy, split_reward};
    use crate::params::DEVNET_CHAIN;

    fn test_header(chain: u32, height: u64) -> BlockHeader {
        BlockHeader {
            version: BLOCK_VERSION,
            chain,
            height,
            previous_hash: Hash256::ZERO,
            merkle_root: Hash256::ZERO,
            timestamp: crate::params::GENESIS_TIMESTAMP,
            difficulty_bits: 0x207f_ffff,
            engine_id: ENGINE_ID_TRIVIAL,
            nonce: 0,
        }
    }

    #[test]
    fn ledger_accumulates_weight_per_contributor() {
        let mut ledger = PoolLedger::new();
        let a = Hash160([1u8; 20]);
        let b = Hash160([2u8; 20]);
        assert!(ledger.is_empty());

        ledger.record_share(a);
        ledger.record_share(a);
        ledger.record_share(b);

        assert_eq!(ledger.contributor_count(), 2);
        assert_eq!(ledger.total_weight(), 3);
        assert_eq!(ledger.weight_of(&a), 2);
        assert_eq!(ledger.weight_of(&b), 1);
        assert_eq!(ledger.weight_of(&Hash160([3u8; 20])), 0);
    }

    #[test]
    fn drain_returns_payouts_and_resets_the_ledger() {
        let mut ledger = PoolLedger::new();
        ledger.record_share(Hash160([1u8; 20]));
        ledger.record(Hash160([2u8; 20]), 5);

        let payouts = ledger.drain();
        assert_eq!(payouts.iter().map(|(_, w)| *w).sum::<u64>(), 6);
        assert!(ledger.is_empty(), "draining clears contributions");
        assert_eq!(ledger.total_weight(), 0);
        assert_eq!(ledger.contributor_count(), 0);
    }

    #[test]
    fn zero_weight_is_ignored() {
        let mut ledger = PoolLedger::new();
        ledger.record(Hash160([1u8; 20]), 0);
        assert!(ledger.is_empty());
        assert_eq!(ledger.total_weight(), 0);
    }

    #[test]
    fn validate_share_submission_accepts_a_mined_share() {
        let engine = TrivialEngine::new();
        let params = ChainParams::regtest();
        let block_target = compact_to_target(params.genesis_bits);
        let share_tgt = share_target_for(&params, &block_target);

        let mut header = test_header(params.chain_id.0, 5);
        let (nonce, _hash) =
            mine(&engine, &header.preimage(), &share_tgt, 0).expect("a share is easy to find");
        header.nonce = nonce;

        assert!(validate_share_submission(&engine, &header, params.chain_id, 5, &share_tgt).is_ok());
    }

    #[test]
    fn validate_share_submission_rejects_the_wrong_chain() {
        let engine = TrivialEngine::new();
        let params = ChainParams::regtest();
        let pow_limit = compact_to_target(params.difficulty.pow_limit_bits);
        let header = test_header(params.chain_id.0, 5);
        // The share is for regtest but the pool serves devnet.
        let result = validate_share_submission(&engine, &header, DEVNET_CHAIN, 5, &pow_limit);
        assert!(matches!(result, Err(ShareError::WrongChain { .. })));
    }

    #[test]
    fn validate_share_submission_rejects_stale_height() {
        let engine = TrivialEngine::new();
        let params = ChainParams::regtest();
        let pow_limit = compact_to_target(params.difficulty.pow_limit_bits);
        let header = test_header(params.chain_id.0, 5);
        // The pool has moved on to height 6; a height-5 share is stale.
        let result = validate_share_submission(&engine, &header, params.chain_id, 6, &pow_limit);
        assert!(matches!(result, Err(ShareError::StaleWork { .. })));
    }

    #[test]
    fn validate_share_submission_rejects_insufficient_work() {
        let engine = TrivialEngine::new();
        let params = ChainParams::regtest();
        let header = test_header(params.chain_id.0, 5);
        // An impossible target: nonce 0's hash will not meet it.
        let impossible = Uint256::from_u64(1);
        let result = validate_share_submission(&engine, &header, params.chain_id, 5, &impossible);
        assert!(matches!(result, Err(ShareError::InsufficientWork)));
    }

    #[test]
    fn share_target_is_bounded_by_the_pow_limit() {
        let params = ChainParams::regtest();
        let block_target = compact_to_target(params.genesis_bits);
        let share_tgt = share_target_for(&params, &block_target);
        let pow_limit = compact_to_target(params.difficulty.pow_limit_bits);
        assert!(share_tgt >= block_target, "a share is easier than a block");
        assert!(share_tgt <= pow_limit, "but never easier than the network floor");
    }

    #[test]
    fn finder_weight_dwarfs_a_handful_of_mobile_shares() {
        // Ten mobile shares beside the block finder: the finder keeps the bulk of the
        // reward, yet the mobiles still earn a real, proportional micro-reward, and
        // the split sums to exactly one subsidy.
        let mut ledger = PoolLedger::new();
        let finder = Hash160([9u8; 20]);
        for i in 0..10u8 {
            ledger.record_share(Hash160([i; 20]));
        }
        ledger.record(finder, FINDER_SHARE_WEIGHT);

        let reward = block_subsidy(1);
        let payouts = split_reward(reward, &ledger.payouts());
        let finder_share = payouts.iter().find(|(h, _)| *h == finder).unwrap().1;
        assert!(finder_share > reward / 2, "the finder keeps the bulk of the reward");

        let mobile_total: u64 = payouts
            .iter()
            .filter(|(h, _)| *h != finder)
            .map(|(_, v)| *v)
            .sum();
        assert!(mobile_total > 0, "mobiles earn a micro-reward");
        assert_eq!(
            payouts.iter().map(|(_, v)| *v).sum::<u64>(),
            reward,
            "the split never inflates the reward, so the cap holds"
        );
    }
}
