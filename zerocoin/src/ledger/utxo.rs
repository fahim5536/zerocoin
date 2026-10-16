//! The UTXO set: state management and transaction validation.
//!
//! ZeroCoin has no account balances. State is the set of unspent transaction
//! outputs; every output records the height it was created at and whether it came
//! from a coinbase, which is what enforces the 100-block maturity rule. Spending a
//! transaction is validated entirely against this set:
//!
//! 1. every input references an output that is present (exists, not already spent),
//! 2. coinbase inputs have matured (100 confirmations),
//! 3. no input is spent twice within the transaction,
//! 4. each input's unlocking script satisfies the referenced output's locking script
//!    under a chain-bound sighash,
//! 5. inputs sum to at least outputs (the surplus is the miner fee), with no overflow.
//!
//! The set is a `BTreeMap` so iteration — and therefore the state commitment root —
//! is deterministic across nodes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::consensus::reward::COINBASE_MATURITY;
use crate::crypto::hash::{sha256d, Hash256};
use crate::ledger::script::{self, ScriptError};
use crate::ledger::sighash::{ChainId, TxSigChecker};
use crate::ledger::transaction::{Outpoint, Transaction, TxOut};

// Rule 2 (coinbase maturity guard): the 100-block delay is a frozen consensus
// invariant. The full anchor set lives in [`crate::consensus::immutability`];
// this duplicate fails the build even if only this module is touched.
const _: () = assert!(
    COINBASE_MATURITY == 100,
    "the coinbase maturity guard is frozen at exactly 100 blocks"
);

/// A single unspent output plus the metadata consensus needs to judge spendability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub output: TxOut,
    /// Height of the block that created this output.
    pub height: u64,
    /// Coinbase outputs are subject to the maturity delay; ordinary outputs are not.
    pub is_coinbase: bool,
}

impl UtxoEntry {
    pub fn new(output: TxOut, height: u64, is_coinbase: bool) -> Self {
        UtxoEntry {
            output,
            height,
            is_coinbase,
        }
    }

    /// The height at which this output first becomes spendable.
    pub fn spendable_at(&self) -> u64 {
        if self.is_coinbase {
            self.height.saturating_add(COINBASE_MATURITY)
        } else {
            self.height
        }
    }

    /// Whether this output may be spent by a transaction included at `spend_height`.
    ///
    /// Frozen: a coinbase output becomes spendable at exactly `height + 100`
    /// confirmations. An earlier spend is [`UtxoError::ImmatureCoinbase`]; the node
    /// drops the whole block and isolates the peer that served it
    /// (see [`crate::consensus::immutability::isolates_peer`]).
    pub fn is_mature(&self, spend_height: u64) -> bool {
        self.spendable_at() <= spend_height
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UtxoError {
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("input {0:?} references an output that does not exist or is already spent")]
    MissingInput(Outpoint),
    #[error("input {outpoint:?} spends a coinbase that matures at height {matures} but is spent at {spent}")]
    ImmatureCoinbase {
        outpoint: Outpoint,
        matures: u64,
        spent: u64,
    },
    #[error("input {0:?} is spent more than once in the same transaction")]
    DoubleSpend(Outpoint),
    #[error("input {index} failed script validation: {source}")]
    ScriptInvalid {
        index: usize,
        #[source]
        source: ScriptError,
    },
    #[error("input value total overflows")]
    InputOverflow,
    #[error("output value total overflows")]
    OutputOverflow,
    #[error("transaction spends {inputs} Fah but creates {outputs} Fah: negative fee")]
    NegativeFee { inputs: u64, outputs: u64 },
}

/// The set of unspent outputs, the whole of ZeroCoin's spendable state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UtxoSet {
    entries: BTreeMap<Outpoint, UtxoEntry>,
}

// Serde cannot use a struct as a JSON object key ("key must be a string"), so the
// set is persisted as an ordered list of `(outpoint, entry)` pairs. This affects
// only the storage encoding: `state_root` and every transaction id are computed
// from explicit canonical byte serializers, never from this representation.
impl Serialize for UtxoSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&Outpoint, &UtxoEntry)> = self.entries.iter().collect();
        pairs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UtxoSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pairs = Vec::<(Outpoint, UtxoEntry)>::deserialize(deserializer)?;
        Ok(UtxoSet {
            entries: pairs.into_iter().collect(),
        })
    }
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, outpoint: &Outpoint) -> Option<&UtxoEntry> {
        self.entries.get(outpoint)
    }

    pub fn contains(&self, outpoint: &Outpoint) -> bool {
        self.entries.contains_key(outpoint)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Outpoint, &UtxoEntry)> {
        self.entries.iter()
    }

    /// Insert an output created by a coinbase at `height`.
    pub fn insert_coinbase(&mut self, txid: Hash256, index: u32, output: TxOut, height: u64) {
        self.entries.insert(
            Outpoint { txid, vout: index },
            UtxoEntry::new(output, height, true),
        );
    }

    /// Insert an output created by an ordinary transaction at `height`.
    pub fn insert_output(&mut self, txid: Hash256, index: u32, output: TxOut, height: u64) {
        self.entries.insert(
            Outpoint { txid, vout: index },
            UtxoEntry::new(output, height, false),
        );
    }

    /// Remove a spent output, returning it (used to build undo records for reorgs).
    pub fn spend(&mut self, outpoint: &Outpoint) -> Option<UtxoEntry> {
        self.entries.remove(outpoint)
    }

    /// Total value of all outputs paying `script_pubkey`.
    pub fn balance_of_script(&self, script_pubkey: &[u8]) -> u64 {
        self.entries
            .values()
            .filter(|e| e.output.script_pubkey == script_pubkey)
            .map(|e| e.output.value)
            .sum()
    }

    /// Validate and apply a non-coinbase transaction, returning the fee it pays.
    ///
    /// `spend_height` is the height of the block that will include this transaction
    /// (used for the maturity check); `height` is where its outputs are recorded as
    /// created. On any validation failure the set is left unchanged.
    pub fn apply_transaction(
        &mut self,
        tx: &Transaction,
        chain_id: ChainId,
        height: u64,
        spend_height: u64,
    ) -> Result<u64, UtxoError> {
        if tx.inputs.is_empty() {
            return Err(UtxoError::NoInputs);
        }

        // Phase 0: reject duplicate inputs up front, before any signature work, so a
        // double-spend is reported as such rather than as a sighash mismatch on the
        // second copy of the same outpoint.
        let mut seen: BTreeSet<Outpoint> = BTreeSet::new();
        for input in &tx.inputs {
            if !seen.insert(input.previous_output) {
                return Err(UtxoError::DoubleSpend(input.previous_output));
            }
        }

        // Phase 1: validate every input against the current set without mutating it,
        // so a partially-applied transaction can never corrupt state.
        let mut input_total: u64 = 0;
        for (index, input) in tx.inputs.iter().enumerate() {
            let outpoint = input.previous_output;
            let entry = self
                .entries
                .get(&outpoint)
                .ok_or(UtxoError::MissingInput(outpoint))?;
            if !entry.is_mature(spend_height) {
                return Err(UtxoError::ImmatureCoinbase {
                    outpoint,
                    matures: entry.spendable_at(),
                    spent: spend_height,
                });
            }
            // Authorize the spend: run scriptSig then the referenced scriptPubKey,
            // with a checker bound to this transaction, input and chain.
            let checker = TxSigChecker::new(tx, index, &entry.output.script_pubkey, chain_id);
            script::verify(&input.script_sig, &entry.output.script_pubkey, &checker).map_err(
                |source| UtxoError::ScriptInvalid { index, source },
            )?;
            input_total = input_total
                .checked_add(entry.output.value)
                .ok_or(UtxoError::InputOverflow)?;
        }

        let output_total = tx.output_value().ok_or(UtxoError::OutputOverflow)?;
        if output_total > input_total {
            return Err(UtxoError::NegativeFee {
                inputs: input_total,
                outputs: output_total,
            });
        }
        let fee = input_total - output_total;

        // Phase 2: commit — remove spent outputs, then add the new ones.
        for input in &tx.inputs {
            self.entries.remove(&input.previous_output);
        }
        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            self.insert_output(txid, index as u32, output.clone(), height);
        }
        Ok(fee)
    }

    /// Apply a block's coinbase: record each output as a coinbase entry created at
    /// `height`, so it cannot be spent until `height + COINBASE_MATURITY`.
    pub fn apply_coinbase(&mut self, tx: &Transaction, height: u64) -> Hash256 {
        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            self.insert_coinbase(txid, index as u32, output.clone(), height);
        }
        txid
    }

    /// A deterministic commitment to the whole UTXO set: a Merkle root over every
    /// entry keyed by outpoint. Two nodes with identical state compute an identical
    /// root, which is how a light client or a peer can check state agreement.
    pub fn state_root(&self) -> Hash256 {
        let mut hasher_input = Vec::new();
        for (outpoint, entry) in &self.entries {
            hasher_input.extend_from_slice(&outpoint.txid.0);
            hasher_input.extend_from_slice(&outpoint.vout.to_le_bytes());
            hasher_input.extend_from_slice(&entry.output.value.to_le_bytes());
            hasher_input.extend_from_slice(&(entry.output.script_pubkey.len() as u64).to_le_bytes());
            hasher_input.extend_from_slice(&entry.output.script_pubkey);
            hasher_input.extend_from_slice(&entry.height.to_le_bytes());
            hasher_input.push(entry.is_coinbase as u8);
        }
        sha256d(&hasher_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::reward::{block_subsidy, coinbase_transaction};
    use crate::crypto::secp256k1::PrivateKey;
    use crate::ledger::script::{p2pkh_script_pubkey, p2pkh_script_sig};
    use crate::ledger::sighash::{signature_hash, SIGHASH_ALL};
    use crate::ledger::transaction::{TxIn, TxOut};

    const CHAIN: ChainId = ChainId(0x2E01_0001);

    /// Fund a set with a mature coinbase output paying `key`, returning the outpoint.
    fn funded_set(key: &PrivateKey, height: u64, value: u64) -> (UtxoSet, Outpoint) {
        let mut set = UtxoSet::new();
        let cb = coinbase_transaction(height, &key.public_key(), value);
        let txid = set.apply_coinbase(&cb, height);
        (
            set,
            Outpoint {
                txid,
                vout: 0,
            },
        )
    }

    fn signed_payment(
        key: &PrivateKey,
        input: Outpoint,
        amount: u64,
        fee: u64,
        to: &PrivateKey,
        set: &UtxoSet,
        _height: u64,
    ) -> Transaction {
        let prev = set.get(&input).unwrap();
        let script_code = prev.output.script_pubkey.clone();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: input,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![
                TxOut {
                    value: amount,
                    script_pubkey: p2pkh_script_pubkey(&to.public_key().key_hash()),
                },
                TxOut {
                    value: prev.output.value - amount - fee,
                    script_pubkey: p2pkh_script_pubkey(&key.public_key().key_hash()),
                },
            ],
            lock_time: 0,
        };
        let digest = signature_hash(&tx, 0, &script_code, CHAIN, SIGHASH_ALL).unwrap();
        let mut sig = key.sign(&digest).unwrap().to_der().to_vec();
        sig.push(SIGHASH_ALL as u8);
        tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &key.public_key().to_sec1());
        tx
    }

    #[test]
    fn coinbase_is_immature_until_100_blocks() {
        let key = PrivateKey::from_bytes([1u8; 32]).unwrap();
        let (mut set, outpoint) = funded_set(&key, 1, block_subsidy(1));

        // A payment spending the coinbase at height 50 must fail: immature.
        let to = PrivateKey::from_bytes([2u8; 32]).unwrap();
        let tx = signed_payment(&key, outpoint, 1_000, 100, &to, &set, 50);
        assert!(matches!(
            set.apply_transaction(&tx, CHAIN, 50, 50),
            Err(UtxoError::ImmatureCoinbase { .. })
        ));

        // At height 101 (= 1 + 100 maturity) the same coin is spendable.
        let tx = signed_payment(&key, outpoint, 1_000, 100, &to, &set, 101);
        let fee = set
            .apply_transaction(&tx, CHAIN, 101, 101)
            .expect("mature spend succeeds");
        assert_eq!(fee, 100);
    }

    #[test]
    fn maturity_boundary_is_exact() {
        let key = PrivateKey::from_bytes([3u8; 32]).unwrap();
        let (mut set, outpoint) = funded_set(&key, 10, 50_000);
        let to = PrivateKey::from_bytes([4u8; 32]).unwrap();

        // Height 109 is one short of 10 + 100 = 110.
        let tx = signed_payment(&key, outpoint, 1_000, 0, &to, &set, 109);
        assert!(matches!(
            set.apply_transaction(&tx, CHAIN, 109, 109),
            Err(UtxoError::ImmatureCoinbase { .. })
        ));
        // Height 110 is exactly mature.
        let tx = signed_payment(&key, outpoint, 1_000, 0, &to, &set, 110);
        assert!(set.apply_transaction(&tx, CHAIN, 110, 110).is_ok());
    }

    #[test]
    fn missing_input_rejected() {
        let key = PrivateKey::from_bytes([5u8; 32]).unwrap();
        let mut set = UtxoSet::new();
        let bogus = Outpoint {
            txid: Hash256([0xaa; 32]),
            vout: 0,
        };
        let to = PrivateKey::from_bytes([6u8; 32]).unwrap();
        // Sign against a script we fabricate; the input simply is not in the set.
        let script_code = p2pkh_script_pubkey(&key.public_key().key_hash());
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: bogus,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: p2pkh_script_pubkey(&to.public_key().key_hash()),
            }],
            lock_time: 0,
        };
        let digest = signature_hash(&tx, 0, &script_code, CHAIN, SIGHASH_ALL).unwrap();
        let mut sig = key.sign(&digest).unwrap().to_der().to_vec();
        sig.push(SIGHASH_ALL as u8);
        tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &key.public_key().to_sec1());
        assert_eq!(
            set.apply_transaction(&tx, CHAIN, 200, 200),
            Err(UtxoError::MissingInput(bogus))
        );
    }

    #[test]
    fn double_spend_within_tx_rejected() {
        let key = PrivateKey::from_bytes([7u8; 32]).unwrap();
        let (mut set, outpoint) = funded_set(&key, 1, 100_000);
        let to = PrivateKey::from_bytes([8u8; 32]).unwrap();
        let tx = signed_payment(&key, outpoint, 1_000, 0, &to, &set, 101);
        // Duplicate the single input.
        let mut doubled = tx.clone();
        doubled.inputs.push(tx.inputs[0].clone());
        assert!(matches!(
            set.apply_transaction(&doubled, CHAIN, 101, 101),
            Err(UtxoError::DoubleSpend(_))
        ));
    }

    #[test]
    fn bad_signature_rejected() {
        let key = PrivateKey::from_bytes([9u8; 32]).unwrap();
        let thief = PrivateKey::from_bytes([10u8; 32]).unwrap();
        let (mut set, outpoint) = funded_set(&key, 1, 100_000);
        // The thief tries to spend the victim's coin with their own key.
        let tx = signed_payment(&thief, outpoint, 1_000, 0, &thief, &set, 101);
        assert!(matches!(
            set.apply_transaction(&tx, CHAIN, 101, 101),
            Err(UtxoError::ScriptInvalid { .. })
        ));
    }

    #[test]
    fn negative_fee_rejected() {
        let key = PrivateKey::from_bytes([11u8; 32]).unwrap();
        let (mut set, outpoint) = funded_set(&key, 1, 1_000);
        let to = PrivateKey::from_bytes([12u8; 32]).unwrap();
        // Try to create more value than the input holds.
        let prev = set.get(&outpoint).unwrap();
        let script_code = prev.output.script_pubkey.clone();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOut {
                value: 5_000, // more than the 1_000 input
                script_pubkey: p2pkh_script_pubkey(&to.public_key().key_hash()),
            }],
            lock_time: 0,
        };
        let digest = signature_hash(&tx, 0, &script_code, CHAIN, SIGHASH_ALL).unwrap();
        let mut sig = key.sign(&digest).unwrap().to_der().to_vec();
        sig.push(SIGHASH_ALL as u8);
        tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &key.public_key().to_sec1());
        assert!(matches!(
            set.apply_transaction(&tx, CHAIN, 101, 101),
            Err(UtxoError::NegativeFee { .. })
        ));
    }

    #[test]
    fn spent_output_is_removed() {
        let key = PrivateKey::from_bytes([13u8; 32]).unwrap();
        let (mut set, outpoint) = funded_set(&key, 1, 100_000);
        let to = PrivateKey::from_bytes([14u8; 32]).unwrap();
        assert!(set.contains(&outpoint));
        let tx = signed_payment(&key, outpoint, 40_000, 1_000, &to, &set, 101);
        set.apply_transaction(&tx, CHAIN, 101, 101).unwrap();
        // The funded coin is gone; two new outputs exist (payment + change).
        assert!(!set.contains(&outpoint));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn state_root_is_deterministic() {
        let key = PrivateKey::from_bytes([15u8; 32]).unwrap();
        let (set_a, _) = funded_set(&key, 1, 5_000);
        let (set_b, _) = funded_set(&key, 1, 5_000);
        assert_eq!(set_a.state_root(), set_b.state_root());
    }
}
