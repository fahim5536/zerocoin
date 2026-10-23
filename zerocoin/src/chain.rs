//! The chain: an ordered, validated history of blocks and the state they produce.
//!
//! [`Chain`] is the node's authoritative view of the ledger. It owns the active
//! branch (a `Vec<Block>` from genesis to tip), the block identities (the
//! proof-of-work hashes, cached so they are computed once), the [`UtxoSet`] those
//! blocks produce, and the running subsidy counter that enforces the 21,000,000 ZRO
//! cap. It is the single place where *all* consensus rules meet: structural block
//! validation, difficulty retargeting, transaction validation, coinbase reward and
//! maturity, and persistence.
//!
//! ## Connecting a block
//!
//! [`Chain::connect_block`] is all-or-nothing. It validates the header against the
//! tip (chain id, height, previous hash, engine, difficulty, Merkle root, timestamp
//! bounds, proof of work), then replays every transaction against a **clone** of the
//! UTXO set, collecting fees, then validates the coinbase against exactly
//! `subsidy + fees`. Only if every step succeeds is the clone committed and the block
//! appended, so a half-applied block can never corrupt state. This costs one state
//! clone per block — fine for a devnet; a production node swaps in an undo log or a
//! database transaction behind the same [`Store`] trait.
//!
//! ## Difficulty
//!
//! [`Chain::required_bits`] reproduces the network's difficulty schedule. Height 0 is
//! pinned at the genesis floor. On regtest (`allow_pow_retarget == false`) difficulty
//! never moves, so a single process can mine instantly and predictably. Otherwise, at
//! every 1,440-block boundary the target is recomputed from how long the previous
//! window actually took, via Bitcoin's simple-moving-average rule
//! ([`crate::consensus::difficulty::next_difficulty`]); between boundaries it is
//! inherited unchanged.
//!
//! ## Mining
//!
//! [`Chain::mine_block`] builds a block template from a payout key and a list of
//! memory-pool transactions, computes the exact reward (`subsidy + fees`), searches
//! for a nonce, and connects the result. The timestamp is `max(now, median_time_past
//! + 1)` because consensus requires it strictly greater than the median of the last
//! 11 blocks — without this, mining several blocks within the same wall-clock second
//! would be rejected as "too old". The drift this introduces is bounded well under
//! the 2-hour future limit.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::consensus::block::{Block, BlockHeader, BLOCK_VERSION};
use crate::consensus::difficulty::{compact_to_target, next_difficulty, validate_bits};
use crate::consensus::pow::{mine, PowEngine};
use crate::consensus::reward::{self, block_reward};
use crate::crypto::hash::{Hash160, Hash256};
use crate::crypto::secp256k1::PublicKey;
use crate::genesis::{genesis_block, genesis_hash};
use crate::ledger::script::p2pkh_script_pubkey;
use crate::ledger::transaction::{Outpoint, Transaction};
use crate::ledger::utxo::{UtxoError, UtxoSet};
use crate::params::ChainParams;
use crate::storage::{ChainData, Store, StorageError};

/// Number of previous blocks whose median timestamp bounds a new block's time.
pub const MEDIAN_TIME_SPAN: usize = 11;

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("block failed structural validation: {0}")]
    Structure(#[from] crate::consensus::block::BlockError),
    #[error("transaction failed validation: {0}")]
    Utxo(#[from] UtxoError),
    #[error("coinbase reward is invalid: {0}")]
    Reward(#[from] reward::RewardError),
    #[error("difficulty is invalid: {0}")]
    Difficulty(#[from] crate::consensus::difficulty::DifficultyError),
    #[error("proof of work failed: {0}")]
    Pow(#[from] crate::consensus::pow::PowError),
    #[error("consensus immutability violation: {0}")]
    Immutability(#[from] crate::consensus::immutability::ImmutabilityError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("the persisted chain has no genesis block")]
    NoGenesis,
    #[error("stored genesis {found} does not match this network's {expected}")]
    GenesisMismatch { expected: Hash256, found: Hash256 },
    #[error("coinbase reward overflows the value range")]
    RewardOverflow,
}

/// A snapshot of the chain's identity and progress, for RPC and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStatus {
    pub network: &'static str,
    pub chain_id: u32,
    pub height: u64,
    pub tip: Hash256,
    pub difficulty_bits: u32,
    pub engine: &'static str,
    pub utxo_count: usize,
    pub subsidy_issued: u64,
    pub state_root: Hash256,
}

/// One unspent output paying a given key, with its maturity state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinInfo {
    pub outpoint: Outpoint,
    pub value: u64,
    pub height: u64,
    pub is_coinbase: bool,
    /// The height at which this coin first becomes spendable.
    pub mature_at: u64,
    /// Whether it is spendable by a transaction in the *next* block.
    pub spendable: bool,
}

/// Current UNIX time in seconds, saturating to 0 on a clock before the epoch.
pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The consensus state machine.
pub struct Chain {
    params: ChainParams,
    engine: Box<dyn PowEngine>,
    store: Box<dyn Store>,
    /// Active branch, ordered by height; `blocks[0]` is genesis.
    blocks: Vec<Block>,
    /// `hashes[i]` is the proof-of-work identity of `blocks[i]`.
    hashes: Vec<Hash256>,
    utxo: UtxoSet,
    subsidy_issued: u64,
}

impl Chain {
    /// Open a chain backed by `store`, creating and persisting genesis if the store
    /// is empty. The stored genesis is checked against the one this network defines,
    /// so a data directory from another network (or a hand-edited one) is refused
    /// rather than silently followed onto a private chain.
    pub fn open(params: ChainParams, store: Box<dyn Store>) -> Result<Self, ChainError> {
        // Frozen fair-launch commitments first: if the genesis data or the
        // state-root layout has drifted by even one bit from its pinned constant,
        // the node refuses to boot rather than follow a forked specification (see
        // [`crate::consensus::immutability`]).
        crate::consensus::immutability::verify_boot_invariants()?;
        let engine = params.build_engine();
        let expected = genesis_hash(&params, engine.as_ref());

        let data = match store.load()? {
            Some(data) => data,
            None => {
                let genesis = genesis_block(&params, engine.as_ref());
                ChainData {
                    blocks: vec![genesis],
                    utxo: UtxoSet::new(),
                    subsidy_issued: 0,
                }
            }
        };

        let genesis = data.blocks.first().ok_or(ChainError::NoGenesis)?;
        let found = genesis.id(engine.as_ref());
        if found != expected {
            return Err(ChainError::GenesisMismatch { expected, found });
        }

        let hashes = data
            .blocks
            .iter()
            .map(|b| b.id(engine.as_ref()))
            .collect::<Vec<_>>();

        let chain = Chain {
            params,
            engine,
            store,
            blocks: data.blocks,
            hashes,
            utxo: data.utxo,
            subsidy_issued: data.subsidy_issued,
        };
        // Persist so a freshly-created genesis is on disk before any block builds on it.
        chain.store.save(&chain.chain_data())?;
        Ok(chain)
    }

    /// Build an ephemeral, in-memory chain — a convenience for tests and tools.
    pub fn in_memory(params: ChainParams) -> Result<Self, ChainError> {
        Chain::open(params, Box::new(crate::storage::MemoryStore::new()))
    }

    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    pub fn chain_id(&self) -> crate::ledger::sighash::ChainId {
        self.params.chain_id
    }

    /// Height of the tip. A chain always has genesis, so this is never negative.
    pub fn height(&self) -> u64 {
        self.blocks.last().map(|b| b.header.height).unwrap_or(0)
    }

    /// The height the next connected block must claim.
    pub fn next_height(&self) -> u64 {
        self.height().saturating_add(1)
    }

    /// Identity of the tip block (zero only for an empty chain, which cannot happen).
    pub fn tip_hash(&self) -> Hash256 {
        self.hashes.last().copied().unwrap_or(Hash256::ZERO)
    }

    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    pub fn subsidy_issued(&self) -> u64 {
        self.subsidy_issued
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// The block at `height`, if this chain has it.
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        self.blocks.get(height as usize)
    }

    /// The identity of the block at `height`.
    pub fn hash_at(&self, height: u64) -> Option<Hash256> {
        self.hashes.get(height as usize).copied()
    }

    /// Whether this chain holds a block with the given proof-of-work identity.
    pub fn holds_block(&self, hash: &Hash256) -> bool {
        self.hashes.contains(hash)
    }

    /// The median timestamp of the last [`MEDIAN_TIME_SPAN`] blocks. A new block's
    /// timestamp must exceed this, which is what stops a miner from rewriting history.
    pub fn median_time_past(&self) -> u64 {
        let n = self.blocks.len().min(MEDIAN_TIME_SPAN);
        if n == 0 {
            return 0;
        }
        let mut ts: Vec<u64> = self.blocks[self.blocks.len() - n..]
            .iter()
            .map(|b| b.header.timestamp)
            .collect();
        ts.sort_unstable();
        ts[ts.len() / 2]
    }

    /// The compact difficulty a block at `height` must carry.
    ///
    /// # Panics
    ///
    /// On a retargeting network (`allow_pow_retarget == true`) with
    /// `height > self.next_height()`, the schedule is read from
    /// `self.blocks[height - 1]`, which is out of bounds. [`Chain::connect_block`]
    /// validates the height first, so only a direct caller that skips that check
    /// can reach this (finding F-1).
    pub fn required_bits(&self, height: u64) -> u32 {
        if height == 0 || !self.params.allow_pow_retarget {
            return self.params.genesis_bits;
        }
        let interval = self.params.difficulty.retarget_interval;
        let prev = &self.blocks[(height - 1) as usize];
        if height % interval == 0 {
            // Retarget boundary: measure the window that just finished.
            let first = &self.blocks[(height - interval) as usize];
            let actual = prev.header.timestamp.saturating_sub(first.header.timestamp);
            next_difficulty(prev.header.difficulty_bits, actual, &self.params.difficulty)
        } else {
            prev.header.difficulty_bits
        }
    }

    /// Validate and connect a block at the tip. `now` is this node's clock, used for
    /// the future-timestamp bound. On success the block is committed to state and
    /// persisted; on any failure nothing changes.
    pub fn connect_block(&mut self, block: Block, now: u64) -> Result<Hash256, ChainError> {
        let height = block.header.height;

        // The height comes from the untrusted header, and `required_bits` indexes
        // the stored history by it (`blocks[height - 1]`), so the identity checks
        // run before the schedule is computed. Without this ordering a height past
        // the tip panicked on a retargeting network instead of returning
        // `BadHeight` (finding F-1). `validate_structure` applies the same checks
        // below; sharing one implementation is what keeps the order from drifting.
        block.validate_header_identity(self.params.chain_id.0, self.next_height())?;

        let expected_previous = self.tip_hash();
        let expected_bits = self.required_bits(height);

        // 1. Header and proof of work, against the tip and the schedule.
        block.validate_structure(
            self.engine.as_ref(),
            self.params.chain_id.0,
            self.next_height(),
            &expected_previous,
            expected_bits,
            self.median_time_past(),
            now,
        )?;
        validate_bits(block.header.difficulty_bits, &self.params.difficulty)?;

        // 2. Replay every transaction against a clone, so failure leaves state intact.
        let mut candidate = self.utxo.clone();
        let mut fees: u64 = 0;
        for tx in &block.transactions[1..] {
            let fee = candidate.apply_transaction(tx, self.chain_id(), height, height)?;
            fees = fees.saturating_add(fee);
        }

        // 3. The coinbase may claim exactly `subsidy + fees`, and must respect the cap.
        let coinbase = &block.transactions[0];
        let claimed = reward::validate_coinbase(coinbase, height, fees, self.subsidy_issued)?;

        // 4. Commit: apply the coinbase outputs, then swap in the new state.
        candidate.apply_coinbase(coinbase, height);
        self.utxo = candidate;

        // Track only the subsidy actually minted (claimed minus fees). Genesis claims
        // nothing, so this counter stays at zero through block 0 — the anti-premine
        // rule reflected in the running supply.
        let new_subsidy = claimed.saturating_sub(fees);
        self.subsidy_issued = self.subsidy_issued.saturating_add(new_subsidy);

        let id = block.id(self.engine.as_ref());
        self.blocks.push(block);
        self.hashes.push(id);
        self.store.save(&self.chain_data())?;
        Ok(id)
    }

    /// Build, solve and connect a new block paying `payout`, including `txs` from the
    /// memory pool. Returns the connected block. A solo-mining convenience over
    /// [`Chain::mine_block_with_coinbase`]: it computes the exact reward and wraps it
    /// in a single-output coinbase.
    pub fn mine_block(
        &mut self,
        payout: &PublicKey,
        txs: Vec<Transaction>,
        now: u64,
    ) -> Result<Block, ChainError> {
        let height = self.next_height();
        let reward = self.projected_reward(&txs)?;
        let coinbase = reward::coinbase_transaction(height, payout, reward);
        self.mine_block_with_coinbase(coinbase, txs, now)
    }

    /// The exact reward (`subsidy + fees`) a block built on the current tip from
    /// `txs` may claim. This dry-runs the transactions against a clone of the UTXO
    /// set to learn their fees without committing anything, so a pool coordinator can
    /// compute the reward to split *before* it assembles a multi-output coinbase.
    pub fn projected_reward(&self, txs: &[Transaction]) -> Result<u64, ChainError> {
        let height = self.next_height();
        let mut candidate = self.utxo.clone();
        let mut fees: u64 = 0;
        for tx in txs {
            let fee = candidate.apply_transaction(tx, self.chain_id(), height, height)?;
            fees = fees.saturating_add(fee);
        }
        block_reward(height, fees).ok_or(ChainError::RewardOverflow)
    }

    /// Build, solve and connect a new block whose coinbase is supplied by the caller,
    /// including `txs` from the memory pool. This is the shared mining engine behind
    /// both solo mining ([`Chain::mine_block`], a single-output coinbase) and pool
    /// mining (a multi-output coinbase from [`reward::pool_coinbase_transaction`]).
    ///
    /// The caller owns the coinbase's outputs, but `connect_block` still validates
    /// that it claims no more than `subsidy + fees` and respects the 21,000,000 ZRO
    /// cap, so a malformed or inflated coinbase is rejected exactly as before. The
    /// coinbase must commit to [`Chain::next_height`].
    pub fn mine_block_with_coinbase(
        &mut self,
        coinbase: Transaction,
        txs: Vec<Transaction>,
        now: u64,
    ) -> Result<Block, ChainError> {
        let height = self.next_height();
        let bits = self.required_bits(height);

        // Assemble the block: coinbase first, then the accepted transactions.
        let mut transactions = Vec::with_capacity(txs.len() + 1);
        transactions.push(coinbase);
        transactions.extend(txs);
        let merkle_root = Block::compute_merkle_root(&transactions);

        // The timestamp must clear the median-time-past bound even when several blocks
        // are mined within the same wall-clock second.
        let timestamp = now.max(self.median_time_past().saturating_add(1));

        let mut header = BlockHeader {
            version: BLOCK_VERSION,
            chain: self.params.chain_id.0,
            height,
            previous_hash: self.tip_hash(),
            merkle_root,
            timestamp,
            difficulty_bits: bits,
            engine_id: self.engine.id(),
            nonce: 0,
        };
        let target = compact_to_target(bits);
        let (nonce, _hash) = mine(self.engine.as_ref(), &header.preimage(), &target, 0)?;
        header.nonce = nonce;

        let block = Block {
            header,
            transactions,
        };
        self.connect_block(block.clone(), now)?;
        Ok(block)
    }

    /// Validate a transaction as if it were included in the next block, without
    /// committing anything. This is the memory pool's admission check: it confirms
    /// inputs exist and are mature, signatures verify, and the fee is non-negative,
    /// returning that fee.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<u64, ChainError> {
        let height = self.next_height();
        let mut candidate = self.utxo.clone();
        let fee = candidate.apply_transaction(tx, self.chain_id(), height, height)?;
        Ok(fee)
    }

    /// Total spendable value (mature or not) paying `pubkey_hash`.
    pub fn balance_of_pubkey_hash(&self, pubkey_hash: &Hash160) -> u64 {
        self.utxo
            .balance_of_script(&p2pkh_script_pubkey(pubkey_hash))
    }

    /// Every unspent output paying `pubkey_hash`, annotated with maturity so a wallet
    /// can distinguish a confirmed balance from a spendable one.
    pub fn coins_for_pubkey_hash(&self, pubkey_hash: &Hash160) -> Vec<CoinInfo> {
        let script = p2pkh_script_pubkey(pubkey_hash);
        let spend_height = self.next_height();
        self.utxo
            .iter()
            .filter(|(_, entry)| entry.output.script_pubkey == script)
            .map(|(outpoint, entry)| CoinInfo {
                outpoint: *outpoint,
                value: entry.output.value,
                height: entry.height,
                is_coinbase: entry.is_coinbase,
                mature_at: entry.spendable_at(),
                spendable: entry.is_mature(spend_height),
            })
            .collect()
    }

    /// The value paying `pubkey_hash` that is mature enough to spend in the next block.
    pub fn spendable_balance(&self, pubkey_hash: &Hash160) -> u64 {
        self.coins_for_pubkey_hash(pubkey_hash)
            .into_iter()
            .filter(|c| c.spendable)
            .map(|c| c.value)
            .sum()
    }

    /// A getheaders-style locator: block identities at exponentially increasing
    /// distances from the tip, so a peer can find our fork point cheaply.
    pub fn locator(&self) -> Vec<Hash256> {
        let mut out = Vec::new();
        let mut height = self.height();
        let mut step = 1u64;
        loop {
            if let Some(hash) = self.hash_at(height) {
                out.push(hash);
            }
            if height == 0 {
                break;
            }
            height = height.saturating_sub(step);
            if out.len() > 10 {
                step = step.saturating_mul(2);
            }
        }
        out
    }

    /// Headers above `start` (exclusive), up to `limit`, for serving a sync request.
    pub fn headers_above(&self, start: u64, limit: usize) -> Vec<BlockHeader> {
        self.blocks
            .iter()
            .skip((start.saturating_add(1)) as usize)
            .take(limit)
            .map(|b| b.header.clone())
            .collect()
    }

    /// A snapshot of this chain's identity and progress.
    pub fn describe(&self) -> ChainStatus {
        ChainStatus {
            network: self.params.name,
            chain_id: self.params.chain_id.0,
            height: self.height(),
            tip: self.tip_hash(),
            difficulty_bits: self
                .blocks
                .last()
                .map(|b| b.header.difficulty_bits)
                .unwrap_or(self.params.genesis_bits),
            engine: self.params.engine.name(),
            utxo_count: self.utxo.len(),
            subsidy_issued: self.subsidy_issued,
            state_root: self.utxo.state_root(),
        }
    }

    fn chain_data(&self) -> ChainData {
        ChainData {
            blocks: self.blocks.clone(),
            utxo: self.utxo.clone(),
            subsidy_issued: self.subsidy_issued,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::reward::block_subsidy;
    use crate::crypto::secp256k1::PrivateKey;
    use crate::ledger::script::{p2pkh_script_pubkey, p2pkh_script_sig};
    use crate::ledger::sighash::{signature_hash, SIGHASH_ALL};
    use crate::ledger::transaction::{TxIn, TxOut};

    fn regtest_chain() -> Chain {
        Chain::in_memory(ChainParams::regtest()).expect("opens")
    }

    fn keypair(seed: u8) -> (PrivateKey, PublicKey) {
        let sk = PrivateKey::from_bytes([seed; 32]).unwrap();
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn opens_at_genesis_with_zero_premine() {
        let chain = regtest_chain();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.next_height(), 1);
        assert_eq!(chain.subsidy_issued(), 0, "genesis mints nothing");
        assert!(chain.utxo().is_empty(), "no coins exist at launch");
    }

    #[test]
    fn genesis_is_persisted_and_reopened_identically() {
        let store = Box::new(crate::storage::MemoryStore::new());
        let params = ChainParams::regtest();
        let first = Chain::open(params, store).expect("opens");
        let tip = first.tip_hash();
        let status = first.describe();
        drop(first);

        // Reopening a fresh in-memory chain derives the same genesis identity.
        let again = regtest_chain();
        assert_eq!(again.tip_hash(), tip);
        assert_eq!(again.describe().state_root, status.state_root);
    }

    #[test]
    fn mining_advances_the_tip_and_pays_the_subsidy() {
        let mut chain = regtest_chain();
        let (_sk, miner) = keypair(1);
        let now = crate::params::GENESIS_TIMESTAMP + 1_000;
        let block = chain.mine_block(&miner, vec![], now).expect("mines");
        assert_eq!(block.header.height, 1);
        assert_eq!(chain.height(), 1);
        // The coinbase pays exactly the height-1 subsidy.
        let pkhash = miner.key_hash();
        assert_eq!(chain.balance_of_pubkey_hash(&pkhash), block_subsidy(1));
        assert_eq!(chain.subsidy_issued(), block_subsidy(1));
    }

    #[test]
    fn coinbase_is_immature_then_matures_at_one_hundred() {
        let mut chain = regtest_chain();
        let (_sk, miner) = keypair(2);
        let mut now = crate::params::GENESIS_TIMESTAMP + 1_000;
        // Mine the funding block at height 1.
        chain.mine_block(&miner, vec![], now).expect("mines");
        let pkhash = miner.key_hash();

        // Right after mining, the coin is confirmed but not spendable.
        let coins = chain.coins_for_pubkey_hash(&pkhash);
        assert_eq!(coins.len(), 1);
        assert!(coins[0].is_coinbase);
        assert!(!coins[0].spendable, "immature: needs 100 confirmations");
        assert_eq!(coins[0].mature_at, 101);
        assert_eq!(chain.spendable_balance(&pkhash), 0);

        // Mine 98 more blocks to reach height 99. The next block would be height 100,
        // still short of the height-1 coinbase's maturity at 101, so it stays locked.
        for _ in 0..98 {
            now += 1;
            chain.mine_block(&miner, vec![], now).expect("mines");
        }
        assert_eq!(chain.height(), 99);
        assert_eq!(chain.spendable_balance(&pkhash), 0);

        // One more block reaches height 100, so the next block is height 101 — the
        // height-1 coinbase now has its 100th confirmation and becomes spendable.
        now += 1;
        chain.mine_block(&miner, vec![], now).expect("mines");
        assert_eq!(chain.height(), 100);
        assert!(chain.spendable_balance(&pkhash) >= block_subsidy(1));
    }

    #[test]
    fn a_valid_payment_moves_value_between_keys() {
        let mut chain = regtest_chain();
        let (miner_sk, miner) = keypair(3);
        let (_sk, recipient) = keypair(4);
        let mut now = crate::params::GENESIS_TIMESTAMP + 1_000;

        // Fund and mature the miner's coinbase at height 1.
        chain.mine_block(&miner, vec![], now).expect("mines");
        for _ in 0..100 {
            now += 1;
            chain.mine_block(&miner, vec![], now).expect("mines");
        }
        let miner_hash = miner.key_hash();
        let coins = chain.coins_for_pubkey_hash(&miner_hash);
        let funding = coins
            .iter()
            .find(|c| c.spendable)
            .expect("a mature coin exists");

        // Build a P2PKH payment of 1 ZRO with a 1000 Fah fee, change back to miner.
        let script_code = p2pkh_script_pubkey(&miner_hash);
        let amount = 100_000_000;
        let fee = 1_000;
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: funding.outpoint,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![
                TxOut {
                    value: amount,
                    script_pubkey: p2pkh_script_pubkey(&recipient.key_hash()),
                },
                TxOut {
                    value: funding.value - amount - fee,
                    script_pubkey: script_code.clone(),
                },
            ],
            lock_time: 0,
        };
        let digest = signature_hash(&tx, 0, &script_code, chain.chain_id(), SIGHASH_ALL).unwrap();
        let mut sig = miner_sk.sign(&digest).unwrap().to_der().to_vec();
        sig.push(SIGHASH_ALL as u8);
        tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &miner.to_sec1());

        // The mempool admission check accepts it and reports the fee.
        assert_eq!(chain.validate_transaction(&tx).expect("valid"), fee);

        // Mine it into a block.
        let height = chain.next_height();
        chain.mine_block(&miner, vec![tx], now + 1).expect("mines");
        assert_eq!(chain.height(), height);
        assert_eq!(chain.balance_of_pubkey_hash(&recipient.key_hash()), amount);
    }

    #[test]
    fn rejects_a_block_with_the_wrong_height() {
        let mut chain = regtest_chain();
        let (_sk, miner) = keypair(5);
        let now = crate::params::GENESIS_TIMESTAMP + 1_000;
        let mut block = chain.mine_block(&miner, vec![], now).expect("mines");
        // Tamper with a connected block's copy and try to reconnect it: the height no
        // longer follows the tip.
        block.header.height = 99;
        assert!(chain.connect_block(block, now + 1).is_err());
    }

    #[test]
    fn rejects_a_block_from_another_network() {
        let mut regtest = regtest_chain();
        let (_sk, miner) = keypair(6);
        let now = crate::params::GENESIS_TIMESTAMP + 1_000;
        // Re-stamp a valid regtest block with the devnet chain id. Structural
        // validation checks the chain first, so it is refused as a foreign block.
        let mut block = regtest.mine_block(&miner, vec![], now).expect("mines");
        block.header.chain = ChainParams::devnet().chain_id.0;
        assert!(matches!(
            regtest.connect_block(block, now + 1),
            Err(ChainError::Structure(
                crate::consensus::block::BlockError::WrongChain { .. }
            ))
        ));
    }

    #[test]
    fn difficulty_is_pinned_on_regtest() {
        let chain = regtest_chain();
        // Regtest never retargets, so every height uses the genesis bits.
        for h in [0u64, 1, 1_440, 1_441, 100_000] {
            assert_eq!(chain.required_bits(h), chain.params().genesis_bits);
        }
    }

    #[test]
    fn locator_starts_at_the_tip_and_ends_at_genesis() {
        let mut chain = regtest_chain();
        let (_sk, miner) = keypair(7);
        let mut now = crate::params::GENESIS_TIMESTAMP + 1_000;
        for _ in 0..5 {
            now += 1;
            chain.mine_block(&miner, vec![], now).expect("mines");
        }
        let locator = chain.locator();
        assert_eq!(locator[0], chain.tip_hash());
        assert_eq!(*locator.last().unwrap(), chain.hash_at(0).unwrap());
    }

    #[test]
    fn median_time_past_tracks_recent_blocks() {
        let mut chain = regtest_chain();
        let (_sk, miner) = keypair(8);
        let mut now = crate::params::GENESIS_TIMESTAMP + 1_000;
        for _ in 0..3 {
            now += 10;
            chain.mine_block(&miner, vec![], now).expect("mines");
        }
        // The median of the recent timestamps is at least the genesis timestamp and at
        // most the tip's.
        let mtp = chain.median_time_past();
        assert!(mtp >= crate::params::GENESIS_TIMESTAMP);
        assert!(mtp <= chain.block_at(chain.height()).unwrap().header.timestamp);
    }

    #[test]
    fn a_pool_coinbase_splits_one_subsidy_across_many_miners() {
        use crate::consensus::reward::{pool_coinbase_transaction, split_reward};
        let mut chain = regtest_chain();
        let (_sk, finder) = keypair(11);
        let now = crate::params::GENESIS_TIMESTAMP + 1_000;

        // Two mobile share-miners paid alongside the block finder.
        let mobile_a = Hash160([0xAA; 20]);
        let mobile_b = Hash160([0xBB; 20]);
        let finder_hash = finder.key_hash();

        let height = chain.next_height();
        let reward = chain.projected_reward(&[]).expect("reward");
        assert_eq!(reward, block_subsidy(height), "an empty block earns the subsidy");
        let payouts = split_reward(
            reward,
            &[(finder_hash, 1_000_000), (mobile_a, 300), (mobile_b, 200)],
        );
        let coinbase = pool_coinbase_transaction(height, reward, &payouts);
        let block = chain
            .mine_block_with_coinbase(coinbase, vec![], now)
            .expect("mines a pool block");

        assert_eq!(block.header.height, 1);
        // The block minted exactly one subsidy: the split redistributed it, never
        // enlarged it, so the running supply and the 21,000,000 ZRO cap hold.
        assert_eq!(chain.subsidy_issued(), block_subsidy(1));
        let total: u64 = block.transactions[0].outputs.iter().map(|o| o.value).sum();
        assert_eq!(total, reward, "the split never inflates the reward");
        // Every contributor is paid, and the finder's slice dwarfs a mobile's.
        assert!(chain.balance_of_pubkey_hash(&mobile_a) > 0, "a mobile earns a micro-reward");
        assert!(chain.balance_of_pubkey_hash(&mobile_b) > 0);
        assert!(chain.balance_of_pubkey_hash(&finder_hash) > chain.balance_of_pubkey_hash(&mobile_a));
    }
}
