//! Transaction format and canonical serialization.
//!
//! A ZeroCoin transaction is structurally Bitcoin's legacy (pre-segwit)
//! transaction: a version, a list of inputs that each name a previous output and
//! carry an unlocking script, a list of outputs that each carry a value and a
//! locking script, and a lock time.
//!
//! The [`Transaction::txid`] is the double-SHA-256 of a *canonical* byte encoding
//! ([`Transaction::serialize`]). Every node must produce the identical encoding or
//! the same transaction would have different identifiers on different machines and
//! the Merkle tree would never agree, so the encoding is fixed here and covered by
//! a round-trip test.

use serde::{Deserialize, Serialize};

use crate::crypto::hash::{sha256d, Hash256};

/// Maximum transaction size we will deserialize, mirroring Bitcoin's standardness
/// bound so a peer cannot hand us an unbounded frame to allocate.
pub const MAX_TX_BYTES: usize = 1_000_000;
/// Maximum number of signature-operations we will count in one transaction.
pub const MAX_TX_INPUTS: usize = 10_000;
pub const MAX_TX_OUTPUTS: usize = 10_000;

/// A reference to a specific output of a previous transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Outpoint {
    pub txid: Hash256,
    pub vout: u32,
}

impl Outpoint {
    /// The null outpoint that only a coinbase input may spend.
    pub fn null() -> Self {
        Outpoint {
            txid: Hash256::ZERO,
            vout: u32::MAX,
        }
    }

    pub fn is_null(&self) -> bool {
        self.txid.is_zero() && self.vout == u32::MAX
    }
}

/// A transaction input: the output it spends plus the script that unlocks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    pub previous_output: Outpoint,
    /// The unlocking script (`scriptSig`). For P2PKH this is `<sig> <pubkey>`.
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// A transaction output: a value in Fah plus the script that locks it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    /// Value in the smallest unit (Fah). 1 ZRO = 100_000_000 Fah.
    pub value: u64,
    /// The locking script (`scriptPubKey`). For P2PKH this is the standard
    /// `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` template.
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    /// A output that creates nothing and is unspendable, used only inside the
    /// zero-premine genesis coinbase.
    pub fn null() -> Self {
        TxOut {
            value: 0,
            script_pubkey: Vec::new(),
        }
    }
}

/// A complete transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

/// Errors that can occur while decoding a transaction from the wire.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxDecodeError {
    #[error("transaction ended unexpectedly: {0}")]
    Truncated(&'static str),
    #[error("varint is not minimally encoded")]
    NonMinimalVarInt,
    #[error("transaction has {0} inputs, over the {max} limit", max = MAX_TX_INPUTS)]
    TooManyInputs(usize),
    #[error("transaction has {0} outputs, over the {max} limit", max = MAX_TX_OUTPUTS)]
    TooManyOutputs(usize),
    #[error("script of {0} bytes exceeds the transaction size limit")]
    ScriptTooLarge(usize),
}

impl Transaction {
    /// A coinbase spends exactly the null outpoint and is the only transaction
    /// allowed to create value from nothing.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
    }

    /// Canonical encoding. This byte string is what the txid commits to, so it must
    /// never change without a consensus fork.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(self.inputs.len() as u64, &mut out);
        for input in &self.inputs {
            out.extend_from_slice(&input.previous_output.txid.0);
            out.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            write_varint(input.script_sig.len() as u64, &mut out);
            out.extend_from_slice(&input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(self.outputs.len() as u64, &mut out);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_varint(output.script_pubkey.len() as u64, &mut out);
            out.extend_from_slice(&output.script_pubkey);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Decode the canonical encoding produced by [`Transaction::serialize`].
    pub fn deserialize(data: &[u8]) -> Result<Self, TxDecodeError> {
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u32_le()? as i32;
        let input_count = cursor.read_varint()? as usize;
        if input_count > MAX_TX_INPUTS {
            return Err(TxDecodeError::TooManyInputs(input_count));
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let mut txid_bytes = [0u8; 32];
            txid_bytes.copy_from_slice(cursor.read_exact(32)?);
            let txid = Hash256(txid_bytes);
            let vout = cursor.read_u32_le()?;
            let script_len = cursor.read_varint()? as usize;
            if script_len > MAX_TX_BYTES {
                return Err(TxDecodeError::ScriptTooLarge(script_len));
            }
            let script_sig = cursor.read_exact(script_len)?.to_vec();
            let sequence = cursor.read_u32_le()?;
            inputs.push(TxIn {
                previous_output: Outpoint { txid, vout },
                script_sig,
                sequence,
            });
        }
        let output_count = cursor.read_varint()? as usize;
        if output_count > MAX_TX_OUTPUTS {
            return Err(TxDecodeError::TooManyOutputs(output_count));
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let value = cursor.read_u64_le()?;
            let script_len = cursor.read_varint()? as usize;
            if script_len > MAX_TX_BYTES {
                return Err(TxDecodeError::ScriptTooLarge(script_len));
            }
            let script_pubkey = cursor.read_exact(script_len)?.to_vec();
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }
        let lock_time = cursor.read_u32_le()?;
        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// The transaction identifier: double-SHA-256 of the canonical encoding.
    pub fn txid(&self) -> Hash256 {
        sha256d(&self.serialize())
    }

    /// Total value this transaction creates. Used to compute fees and to reject
    /// outputs that overflow the money supply.
    pub fn output_value(&self) -> Option<u64> {
        self.outputs.iter().try_fold(0u64, |acc, o| acc.checked_add(o.value))
    }
}

/// Bitcoin's CompactSize unsigned integer encoding.
pub fn write_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// A bounded reader over a byte slice that refuses to run off the end.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], TxDecodeError> {
        let end = self.pos.checked_add(len).ok_or(TxDecodeError::Truncated("length overflow"))?;
        if end > self.data.len() {
            return Err(TxDecodeError::Truncated("byte range"));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u32_le(&mut self) -> Result<u32, TxDecodeError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, TxDecodeError> {
        let bytes = self.read_exact(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(arr))
    }

    fn read_varint(&mut self) -> Result<u64, TxDecodeError> {
        let first = self.read_exact(1)?[0];
        let (value, len) = match first {
            0..=0xfc => (first as u64, 1usize),
            0xfd => {
                let b = self.read_exact(2)?;
                let v = u16::from_le_bytes([b[0], b[1]]) as u64;
                // Reject non-minimal encodings so a txid has one canonical form.
                if v < 0xfd {
                    return Err(TxDecodeError::NonMinimalVarInt);
                }
                (v, 3)
            }
            0xfe => {
                let b = self.read_exact(4)?;
                let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v < 0x1_0000 {
                    return Err(TxDecodeError::NonMinimalVarInt);
                }
                (v, 5)
            }
            _ => {
                let v = self.read_u64_le()?;
                if v < 0x1_0000_0000 {
                    return Err(TxDecodeError::NonMinimalVarInt);
                }
                (v, 9)
            }
        };
        let _ = len;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: Outpoint {
                    txid: Hash256([0x11; 32]),
                    vout: 0,
                },
                script_sig: vec![1, 2, 3],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let tx = sample_tx();
        let bytes = tx.serialize();
        let decoded = Transaction::deserialize(&bytes).expect("decodes");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn txid_is_stable_under_roundtrip() {
        let tx = sample_tx();
        let decoded = Transaction::deserialize(&tx.serialize()).unwrap();
        assert_eq!(tx.txid(), decoded.txid());
    }

    #[test]
    fn varint_encodes_minimally() {
        for value in [0u64, 1, 252, 253, 65535, 65536, 4_294_967_295, 4_294_967_296] {
            let mut buf = Vec::new();
            write_varint(value, &mut buf);
            let decoded = Cursor::new(&buf).read_varint().unwrap();
            assert_eq!(value, decoded, "varint {value} roundtrip");
        }
    }

    #[test]
    fn non_minimal_varint_rejected() {
        // 0xfd prefix claims a 2-byte value, but 5 fits in one byte: non-minimal.
        let bad = [0xfdu8, 0x05, 0x00];
        assert_eq!(
            Cursor::new(&bad).read_varint(),
            Err(TxDecodeError::NonMinimalVarInt)
        );
    }

    #[test]
    fn truncated_input_rejected() {
        let tx = sample_tx();
        let mut bytes = tx.serialize();
        bytes.truncate(bytes.len() - 3);
        assert!(Transaction::deserialize(&bytes).is_err());
    }

    #[test]
    fn coinbase_detected_by_null_outpoint() {
        let mut tx = sample_tx();
        tx.inputs[0].previous_output = Outpoint::null();
        assert!(tx.is_coinbase());
    }

    #[test]
    fn output_value_sums() {
        let mut tx = sample_tx();
        tx.outputs.push(TxOut {
            value: 1,
            script_pubkey: vec![],
        });
        assert_eq!(tx.output_value(), Some(5_000_000_001));
    }
}
