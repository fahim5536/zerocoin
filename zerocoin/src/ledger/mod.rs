//! The ledger: transaction format, the P2PKH script machine, signature hashing,
//! and the UTXO set with its validation rules.
//!
//! ZeroCoin uses Bitcoin's UTXO model. There are no account balances: value lives
//! in unspent transaction outputs, and every transaction must reference previous
//! outputs that still exist and are spendable, prove ownership of them with a
//! signature, and create new outputs whose total does not exceed its inputs. The
//! difference between input and output value is the miner fee.

pub mod transaction;
pub mod script;
pub mod sighash;
pub mod utxo;

pub use script::{p2pkh_script_pubkey, p2pkh_script_sig, SigChecker, ScriptError};
pub use sighash::{signature_hash, txid, ChainId, SIGHASH_ALL};
pub use transaction::{Outpoint, Transaction, TxIn, TxOut};
pub use utxo::{UtxoEntry, UtxoSet, UtxoError};
