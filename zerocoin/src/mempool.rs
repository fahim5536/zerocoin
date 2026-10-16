//! The memory pool: unconfirmed transactions waiting to be mined.
//!
//! A node keeps every transaction it has validated but not yet seen in a block. The
//! pool is the buffer between the network (which gossips transactions) and the miner
//! (which packs them into blocks). Admission is gated by the chain's own validation
//! ([`crate::chain::Chain::validate_transaction`]), so the pool never holds a
//! transaction that spends a non-existent, immature or unauthorized coin.
//!
//! Two rules keep the pool honest beyond state validation:
//! - **No conflicting spends.** Once a transaction is pooled, its inputs are
//!   reserved; a second transaction spending the same output is refused rather than
//!   allowed to race, so the pool can never contain a double-spend pair.
//! - **Fee-priority selection.** [`Mempool::take_for_block`] returns the
//!   highest fee-rate transactions that do not conflict, the way a rational miner
//!   fills limited block space with the most valuable work first.
//!
//! The pool is deliberately dependency-free and single-threaded; the node wraps it in
//! a mutex and shares it between the gossip and mining threads.

use std::collections::{BTreeMap, BTreeSet};

use crate::chain::Chain;
use crate::crypto::hash::Hash256;
use crate::ledger::transaction::{Outpoint, Transaction};

/// A pooled transaction with the metadata the miner and RPC need.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    /// Fee in Fah, established at admission time.
    pub fee: u64,
    /// Serialized size in bytes, used for the fee rate.
    pub size: usize,
    /// Fee rate in Fah per byte; the miner's priority key.
    pub fee_rate: f64,
}

/// Reasons a transaction may be refused entry to the pool.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("transaction failed chain validation: {0}")]
    Invalid(#[from] crate::chain::ChainError),
    #[error("transaction {0} is already in the pool")]
    Duplicate(Hash256),
    #[error("input {0:?} is already claimed by a transaction in the pool")]
    ConflictsWithPooled(Outpoint),
    #[error("coinbase transactions are not accepted into the memory pool")]
    CoinbaseNotAllowed,
}

/// The set of unconfirmed transactions.
#[derive(Debug, Default)]
pub struct Mempool {
    entries: BTreeMap<Hash256, MempoolEntry>,
    /// Every outpoint spent by a pooled transaction, for O(1) conflict detection.
    claimed: BTreeSet<Outpoint>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, txid: &Hash256) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn get(&self, txid: &Hash256) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// The identities of every pooled transaction, in canonical (lexicographic) order.
    pub fn txids(&self) -> Vec<Hash256> {
        self.entries.keys().copied().collect()
    }

    /// Validate a transaction against the chain and, if it passes and does not
    /// conflict with anything already pooled, admit it. Returns the fee it pays.
    pub fn admit(&mut self, tx: Transaction, chain: &Chain) -> Result<u64, MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::Duplicate(txid));
        }
        // Refuse a transaction that races one already pooled for the same coin.
        for input in &tx.inputs {
            if self.claimed.contains(&input.previous_output) {
                return Err(MempoolError::ConflictsWithPooled(input.previous_output));
            }
        }
        // Full state validation (existence, maturity, signatures, non-negative fee).
        let fee = chain.validate_transaction(&tx)?;

        let size = tx.serialize().len();
        let fee_rate = if size == 0 { 0.0 } else { fee as f64 / size as f64 };
        for input in &tx.inputs {
            self.claimed.insert(input.previous_output);
        }
        self.entries.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                size,
                fee_rate,
            },
        );
        Ok(fee)
    }

    /// Remove a transaction from the pool, releasing the coins it claimed.
    pub fn remove(&mut self, txid: &Hash256) -> Option<Transaction> {
        let entry = self.entries.remove(txid)?;
        for input in &entry.tx.inputs {
            self.claimed.remove(&input.previous_output);
        }
        Some(entry.tx)
    }

    /// Select transactions for a new block: highest fee-rate first, skipping any that
    /// would conflict with an already-chosen spend, up to `limit` transactions.
    pub fn take_for_block(&self, limit: usize) -> Vec<Transaction> {
        let mut ordered: Vec<&MempoolEntry> = self.entries.values().collect();
        // Sort by fee rate descending; break ties deterministically by txid so every
        // miner sees the same order for equal-value transactions.
        ordered.sort_by(|a, b| {
            b.fee_rate
                .partial_cmp(&a.fee_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.tx.txid().0.cmp(&b.tx.txid().0))
        });

        let mut chosen = Vec::new();
        let mut used: BTreeSet<Outpoint> = BTreeSet::new();
        for entry in ordered {
            if chosen.len() >= limit {
                break;
            }
            // Skip a transaction that spends a coin an already-chosen one also spends.
            if entry
                .tx
                .inputs
                .iter()
                .any(|i| used.contains(&i.previous_output))
            {
                continue;
            }
            for input in &entry.tx.inputs {
                used.insert(input.previous_output);
            }
            chosen.push(entry.tx.clone());
        }
        chosen
    }

    /// Drop every transaction that a newly connected block made irrelevant: those
    /// included in it, and those that now spend an output the block consumed.
    pub fn prune_confirmed(&mut self, block_transactions: &[Transaction]) {
        let included: BTreeSet<Hash256> =
            block_transactions.iter().map(|tx| tx.txid()).collect();
        let mut spent: BTreeSet<Outpoint> = BTreeSet::new();
        for tx in block_transactions {
            for input in &tx.inputs {
                spent.insert(input.previous_output);
            }
        }

        let stale: Vec<Hash256> = self
            .entries
            .iter()
            .filter(|(txid, entry)| {
                included.contains(*txid)
                    || entry
                        .tx
                        .inputs
                        .iter()
                        .any(|i| spent.contains(&i.previous_output))
            })
            .map(|(txid, _)| *txid)
            .collect();
        for txid in stale {
            self.remove(&txid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::reward::block_subsidy;
    use crate::crypto::secp256k1::{PrivateKey, PublicKey};
    use crate::ledger::script::{p2pkh_script_pubkey, p2pkh_script_sig};
    use crate::ledger::sighash::{signature_hash, SIGHASH_ALL};
    use crate::ledger::transaction::{TxIn, TxOut};
    use crate::params::ChainParams;

    fn keypair(seed: u8) -> (PrivateKey, PublicKey) {
        let sk = PrivateKey::from_bytes([seed; 32]).unwrap();
        let pk = sk.public_key();
        (sk, pk)
    }

    /// A chain with a mature coinbase paying `miner`, ready to fund payments.
    fn mature_chain(miner: &PublicKey) -> Chain {
        let mut chain = Chain::in_memory(ChainParams::regtest()).unwrap();
        let mut now = crate::params::GENESIS_TIMESTAMP + 1_000;
        chain.mine_block(miner, vec![], now).unwrap();
        for _ in 0..100 {
            now += 1;
            chain.mine_block(miner, vec![], now).unwrap();
        }
        chain
    }

    fn payment(
        sk: &PrivateKey,
        pk: &PublicKey,
        coin: &Outpoint,
        coin_value: u64,
        to: &PublicKey,
        amount: u64,
        fee: u64,
        chain_id: crate::ledger::sighash::ChainId,
    ) -> Transaction {
        let script_code = p2pkh_script_pubkey(&pk.key_hash());
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: *coin,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![
                TxOut {
                    value: amount,
                    script_pubkey: p2pkh_script_pubkey(&to.key_hash()),
                },
                TxOut {
                    value: coin_value - amount - fee,
                    script_pubkey: script_code.clone(),
                },
            ],
            lock_time: 0,
        };
        let digest = signature_hash(&tx, 0, &script_code, chain_id, SIGHASH_ALL).unwrap();
        let mut sig = sk.sign(&digest).unwrap().to_der().to_vec();
        sig.push(SIGHASH_ALL as u8);
        tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &pk.to_sec1());
        tx
    }

    fn first_mature_coin(chain: &Chain, pk: &PublicKey) -> (Outpoint, u64) {
        let coin = chain
            .coins_for_pubkey_hash(&pk.key_hash())
            .into_iter()
            .find(|c| c.spendable)
            .expect("a mature coin exists");
        (coin.outpoint, coin.value)
    }

    #[test]
    fn admits_a_valid_payment() {
        let (sk, miner) = keypair(20);
        let (_rsk, recipient) = keypair(21);
        let chain = mature_chain(&miner);
        let (coin, value) = first_mature_coin(&chain, &miner);
        let tx = payment(&sk, &miner, &coin, value, &recipient, 100_000_000, 500, chain.chain_id());

        let mut pool = Mempool::new();
        let fee = pool.admit(tx.clone(), &chain).expect("admitted");
        assert_eq!(fee, 500);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx.txid()));
    }

    #[test]
    fn rejects_a_conflicting_double_spend() {
        let (sk, miner) = keypair(22);
        let (_a, alice) = keypair(23);
        let (_b, bob) = keypair(24);
        let chain = mature_chain(&miner);
        let (coin, value) = first_mature_coin(&chain, &miner);

        let mut pool = Mempool::new();
        let to_alice = payment(&sk, &miner, &coin, value, &alice, 50_000_000, 500, chain.chain_id());
        pool.admit(to_alice, &chain).expect("first admitted");

        // A second transaction spending the *same* coin must be refused.
        let to_bob = payment(&sk, &miner, &coin, value, &bob, 50_000_000, 500, chain.chain_id());
        assert!(matches!(
            pool.admit(to_bob, &chain),
            Err(MempoolError::ConflictsWithPooled(_))
        ));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_a_duplicate() {
        let (sk, miner) = keypair(25);
        let (_r, recipient) = keypair(26);
        let chain = mature_chain(&miner);
        let (coin, value) = first_mature_coin(&chain, &miner);
        let tx = payment(&sk, &miner, &coin, value, &recipient, 10_000_000, 500, chain.chain_id());

        let mut pool = Mempool::new();
        pool.admit(tx.clone(), &chain).expect("admitted");
        assert!(matches!(
            pool.admit(tx, &chain),
            Err(MempoolError::Duplicate(_))
        ));
    }

    #[test]
    fn rejects_a_coinbase() {
        let chain = Chain::in_memory(ChainParams::regtest()).unwrap();
        let cb = crate::consensus::reward::coinbase_transaction(
            1,
            &keypair(27).1,
            block_subsidy(1),
        );
        let mut pool = Mempool::new();
        assert!(matches!(
            pool.admit(cb, &chain),
            Err(MempoolError::CoinbaseNotAllowed)
        ));
    }

    #[test]
    fn selection_prefers_the_higher_fee_rate() {
        let (sk, miner) = keypair(28);
        let (_a, alice) = keypair(29);
        let (_b, bob) = keypair(30);
        let chain = mature_chain(&miner);
        // Two independent mature coins fund two independent payments.
        let coins: Vec<_> = chain
            .coins_for_pubkey_hash(&miner.key_hash())
            .into_iter()
            .filter(|c| c.spendable)
            .collect();
        assert!(coins.len() >= 2, "need two mature coins");

        let cheap = payment(
            &sk, &miner, &coins[0].outpoint, coins[0].value, &alice,
            10_000_000, 100, chain.chain_id(),
        );
        let rich = payment(
            &sk, &miner, &coins[1].outpoint, coins[1].value, &bob,
            10_000_000, 100_000, chain.chain_id(),
        );

        let mut pool = Mempool::new();
        pool.admit(cheap.clone(), &chain).unwrap();
        pool.admit(rich.clone(), &chain).unwrap();

        let chosen = pool.take_for_block(2);
        assert_eq!(chosen.len(), 2);
        // The higher-fee transaction comes first.
        assert_eq!(chosen[0].txid(), rich.txid());
        assert_eq!(chosen[1].txid(), cheap.txid());
    }

    #[test]
    fn prune_removes_confirmed_transactions() {
        let (sk, miner) = keypair(31);
        let (_r, recipient) = keypair(32);
        let chain = mature_chain(&miner);
        let (coin, value) = first_mature_coin(&chain, &miner);
        let tx = payment(&sk, &miner, &coin, value, &recipient, 10_000_000, 500, chain.chain_id());

        let mut pool = Mempool::new();
        pool.admit(tx.clone(), &chain).unwrap();
        assert_eq!(pool.len(), 1);
        // Once the transaction appears in a block, it leaves the pool.
        pool.prune_confirmed(std::slice::from_ref(&tx));
        assert!(pool.is_empty());
        assert!(!pool.contains(&tx.txid()));
    }

    #[test]
    fn remove_releases_claimed_coins() {
        let (sk, miner) = keypair(33);
        let (_a, alice) = keypair(34);
        let (_b, bob) = keypair(35);
        let chain = mature_chain(&miner);
        let (coin, value) = first_mature_coin(&chain, &miner);

        let mut pool = Mempool::new();
        let first = payment(&sk, &miner, &coin, value, &alice, 10_000_000, 500, chain.chain_id());
        pool.admit(first.clone(), &chain).unwrap();
        // Removing it frees the coin, so a different spend of the same coin is allowed.
        assert!(pool.remove(&first.txid()).is_some());
        let second = payment(&sk, &miner, &coin, value, &bob, 10_000_000, 500, chain.chain_id());
        assert!(pool.admit(second, &chain).is_ok());
    }
}
