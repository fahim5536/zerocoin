//! Signature hashing (sighash) and the transaction signature checker.
//!
//! A ZeroCoin signature commits to the transaction being spent, the specific input
//! being authorized, the output script of the coin being spent (`script_code`), the
//! sighash type, and — as a deviation-hardening measure — the **chain id**. Binding
//! the chain id into every signature preimage is domain separation: a signature
//! valid on ZeroCoin devnet can never be replayed on testnet or mainnet, even
//! though the transaction bytes would be identical.
//!
//! Only `SIGHASH_ALL` is supported. That is the mode Bitcoin uses for essentially
//! every real payment: it commits to all inputs and all outputs, so no part of the
//! transaction can be changed after signing without invalidating the signature.

use crate::crypto::hash::{sha256d, Hash256};
use crate::crypto::secp256k1::{PublicKey, Signature};
use crate::ledger::script::SigChecker;
use crate::ledger::transaction::Transaction;

/// The only supported sighash type: commit to every input and every output.
pub const SIGHASH_ALL: u32 = 0x01;

/// Domain-separation tag mixed into every signature preimage.
const SIGHASH_TAG: &[u8] = b"ZRO/sighash/v1\0";

/// Identifies a network. Mixed into sighash so signatures cannot cross chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChainId(pub u32);

/// The transaction identifier: double-SHA-256 of its canonical serialization.
/// This is chain-independent — the same bytes always have the same txid — which is
/// what lets a block's Merkle root be checked by any node.
pub fn txid(tx: &Transaction) -> Hash256 {
    tx.txid()
}

/// Compute the digest a signature over input `input_index` must cover.
///
/// `script_code` is the `scriptPubKey` of the output being spent. Following
/// Bitcoin's legacy sighash algorithm, every input's `scriptSig` is blanked and the
/// input being signed carries `script_code` in its place, so a signature commits to
/// the exact coin it authorizes without committing to other inputs' unlock data.
///
/// Returns `None` if `input_index` is out of range, which the checker treats as an
/// automatic verification failure rather than a guessable digest.
pub fn signature_hash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    chain_id: ChainId,
    sighash_type: u32,
) -> Option<Hash256> {
    if input_index >= tx.inputs.len() {
        return None;
    }
    let mut preimage = Vec::with_capacity(128);
    preimage.extend_from_slice(SIGHASH_TAG);
    preimage.extend_from_slice(&chain_id.0.to_le_bytes());

    // Version.
    preimage.extend_from_slice(&tx.version.to_le_bytes());

    // Inputs: blank every scriptSig except the one being signed, which carries the
    // script_code of the coin it spends.
    super::transaction::write_varint(tx.inputs.len() as u64, &mut preimage);
    for (index, input) in tx.inputs.iter().enumerate() {
        preimage.extend_from_slice(&input.previous_output.txid.0);
        preimage.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        let script: &[u8] = if index == input_index { script_code } else { &[] };
        super::transaction::write_varint(script.len() as u64, &mut preimage);
        preimage.extend_from_slice(script);
        preimage.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Outputs.
    super::transaction::write_varint(tx.outputs.len() as u64, &mut preimage);
    for output in &tx.outputs {
        preimage.extend_from_slice(&output.value.to_le_bytes());
        super::transaction::write_varint(output.script_pubkey.len() as u64, &mut preimage);
        preimage.extend_from_slice(&output.script_pubkey);
    }

    preimage.extend_from_slice(&tx.lock_time.to_le_bytes());
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    Some(sha256d(&preimage))
}

/// A [`SigChecker`] bound to one transaction input, used by the script interpreter
/// when it reaches `OP_CHECKSIG` while validating that input.
pub struct TxSigChecker<'a> {
    tx: &'a Transaction,
    input_index: usize,
    script_code: &'a [u8],
    chain_id: ChainId,
}

impl<'a> TxSigChecker<'a> {
    pub fn new(
        tx: &'a Transaction,
        input_index: usize,
        script_code: &'a [u8],
        chain_id: ChainId,
    ) -> Self {
        TxSigChecker {
            tx,
            input_index,
            script_code,
            chain_id,
        }
    }
}

impl<'a> SigChecker for TxSigChecker<'a> {
    fn check_signature(&self, signature: &[u8], public_key: &[u8]) -> bool {
        // A signature on the stack is DER bytes followed by a single sighash byte.
        let Some((&sighash_byte, der)) = signature.split_last() else {
            return false;
        };
        if sighash_byte as u32 != SIGHASH_ALL {
            // Only SIGHASH_ALL is consensus-valid in ZeroCoin.
            return false;
        }
        let Ok(sig) = Signature::from_der(der) else {
            return false;
        };
        let Ok(pubkey) = PublicKey::from_sec1(public_key) else {
            return false;
        };
        let Some(digest) = signature_hash(
            self.tx,
            self.input_index,
            self.script_code,
            self.chain_id,
            sighash_byte as u32,
        ) else {
            return false;
        };
        pubkey.verify(&digest, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::PrivateKey;
    use crate::ledger::script::p2pkh_script_pubkey;
    use crate::ledger::transaction::{Outpoint, TxIn, TxOut};

    const CHAIN: ChainId = ChainId(0x2E01_0001);

    fn build_tx(script_code: &[u8]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: Outpoint {
                    txid: Hash256([0x22; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: script_code.to_vec(),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn sighash_is_chain_bound() {
        let tx = build_tx(&[0x76]);
        let code = tx.outputs[0].script_pubkey.clone();
        let a = signature_hash(&tx, 0, &code, ChainId(1), SIGHASH_ALL).unwrap();
        let b = signature_hash(&tx, 0, &code, ChainId(2), SIGHASH_ALL).unwrap();
        // Same transaction, different chain id => different digest => no replay.
        assert_ne!(a, b);
    }

    #[test]
    fn out_of_range_input_yields_none() {
        let tx = build_tx(&[0x76]);
        assert!(signature_hash(&tx, 5, &[], CHAIN, SIGHASH_ALL).is_none());
    }

    #[test]
    fn checker_accepts_a_real_signature() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let pkhash = pubkey.key_hash();
        let script_code = p2pkh_script_pubkey(&pkhash);

        let mut tx = build_tx(&script_code);
        let digest = signature_hash(&tx, 0, &script_code, CHAIN, SIGHASH_ALL).unwrap();
        let sig = key.sign(&digest).unwrap();
        // scriptSig = <sig || sighash_byte> <pubkey>
        let mut sig_with_type = sig.to_der().to_vec();
        sig_with_type.push(SIGHASH_ALL as u8);
        tx.inputs[0].script_sig =
            crate::ledger::script::p2pkh_script_sig(&sig_with_type, &pubkey.to_sec1());

        let checker = TxSigChecker::new(&tx, 0, &script_code, CHAIN);
        assert!(checker.check_signature(&sig_with_type, &pubkey.to_sec1()));
    }

    #[test]
    fn checker_rejects_wrong_chain() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let script_code = p2pkh_script_pubkey(&pubkey.key_hash());
        let tx = build_tx(&script_code);
        let digest = signature_hash(&tx, 0, &script_code, CHAIN, SIGHASH_ALL).unwrap();
        let sig = key.sign(&digest).unwrap();
        let mut sig_with_type = sig.to_der().to_vec();
        sig_with_type.push(SIGHASH_ALL as u8);

        // Verify against a different chain id's checker: must fail.
        let checker = TxSigChecker::new(&tx, 0, &script_code, ChainId(0xdead));
        assert!(!checker.check_signature(&sig_with_type, &pubkey.to_sec1()));
    }

    #[test]
    fn checker_rejects_unsupported_sighash_type() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let script_code = p2pkh_script_pubkey(&pubkey.key_hash());
        let tx = build_tx(&script_code);
        let digest = signature_hash(&tx, 0, &script_code, CHAIN, SIGHASH_ALL).unwrap();
        let sig = key.sign(&digest).unwrap();
        let mut sig_with_type = sig.to_der().to_vec();
        sig_with_type.push(0x02); // SIGHASH_NONE: not supported.

        let checker = TxSigChecker::new(&tx, 0, &script_code, CHAIN);
        assert!(!checker.check_signature(&sig_with_type, &pubkey.to_sec1()));
    }
}
