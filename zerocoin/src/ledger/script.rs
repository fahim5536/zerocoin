//! A Forth-like, stack-based script interpreter for P2PKH validation.
//!
//! ZeroCoin runs Bitcoin's script model: an unlocking script (`scriptSig`) is
//! executed first, then the locking script (`scriptPubKey`) is executed against the
//! stack it left behind, and the output is spendable only if a single `true`
//! remains on top. Signature checking is delegated to a [`SigChecker`] so the
//! interpreter never needs to know about sighash construction or keys — the ledger
//! supplies a checker bound to the transaction, input and chain being validated.
//!
//! Only the opcodes a standard P2PKH spend needs are implemented. Anything else is
//! rejected, which keeps the interpreter small, auditable and free of the
//! disabled / flow-control opcodes that have historically been the source of
//! consensus bugs.

use crate::crypto::hash::{hash160, Hash160};

// Opcodes
pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CHECKSIG: u8 = 0xac;

/// Limits mirroring Bitcoin's, so a hostile script cannot exhaust memory or spin.
pub const MAX_STACK_ITEMS: usize = 1_000;
pub const MAX_SCRIPT_ELEMENT: usize = 520;
pub const MAX_OPS_PER_SCRIPT: usize = 201;
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// A signature checker the interpreter calls for `OP_CHECKSIG`. The ledger
/// implements this over the transaction sighash; the interpreter stays agnostic.
pub trait SigChecker {
    /// Verify `signature` (DER plus a trailing sighash byte) against `public_key`
    /// (compressed SEC1) for the input currently being spent.
    fn check_signature(&self, signature: &[u8], public_key: &[u8]) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScriptError {
    #[error("script exceeds the {MAX_SCRIPT_SIZE}-byte size limit")]
    ScriptTooLarge,
    #[error("script executed more than {MAX_OPS_PER_SCRIPT} operations")]
    TooManyOps,
    #[error("stack exceeded {MAX_STACK_ITEMS} items")]
    StackOverflow,
    #[error("stack underflow: an opcode needed more items than were present")]
    StackUnderflow,
    #[error("pushed element exceeds {MAX_SCRIPT_ELEMENT} bytes")]
    ElementTooLarge,
    #[error("script ended with a non-true value on top of the stack")]
    EvalFalse,
    #[error("OP_VERIFY failed on a false value")]
    VerifyFailed,
    #[error("OP_EQUALVERIFY compared unequal values")]
    EqualVerifyFailed,
    #[error("script ran off the end while reading a push")]
    Truncated,
    #[error("unsupported opcode 0x{0:02x}")]
    UnsupportedOpcode(u8),
}

/// Execute `script_sig` then `script_pubkey` on a shared stack, and require a
/// single true value on top. This is the whole of ZeroCoin's spend authorization.
pub fn verify(
    script_sig: &[u8],
    script_pubkey: &[u8],
    checker: &dyn SigChecker,
) -> Result<(), ScriptError> {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    run_script(script_sig, &mut stack, checker, false)?;
    run_script(script_pubkey, &mut stack, checker, false)?;
    match stack.last() {
        Some(top) if is_true(top) => Ok(()),
        _ => Err(ScriptError::EvalFalse),
    }
}

fn run_script(
    script: &[u8],
    stack: &mut Vec<Vec<u8>>,
    checker: &dyn SigChecker,
    _count_ops_flag: bool,
) -> Result<(), ScriptError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptTooLarge);
    }
    let mut ops = 0usize;
    let mut i = 0usize;
    while i < script.len() {
        let opcode = script[i];
        i += 1;
        // Every opcode past the push range counts against the operation budget.
        if opcode > OP_PUSHDATA2 {
            ops += 1;
            if ops > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::TooManyOps);
            }
        }
        match opcode {
            // Data pushes.
            OP_0 => push(stack, Vec::new())?,
            0x01..=0x4b => {
                let len = opcode as usize;
                let data = read_push(script, &mut i, len)?;
                push(stack, data.to_vec())?;
            }
            OP_PUSHDATA1 => {
                let len = read_u8(script, &mut i)? as usize;
                let data = read_push(script, &mut i, len)?;
                push(stack, data.to_vec())?;
            }
            OP_PUSHDATA2 => {
                let lo = read_u8(script, &mut i)? as usize;
                let hi = read_u8(script, &mut i)? as usize;
                let len = lo | (hi << 8);
                let data = read_push(script, &mut i, len)?;
                push(stack, data.to_vec())?;
            }

            // Stack manipulation.
            OP_DROP => {
                pop(stack)?;
            }
            OP_DUP => {
                let top = stack.last().ok_or(ScriptError::StackUnderflow)?.clone();
                push(stack, top)?;
            }

            // Crypto / comparison.
            OP_HASH160 => {
                let top = pop(stack)?;
                push(stack, hash160(&top).0.to_vec())?;
            }
            OP_EQUAL => {
                let b = pop(stack)?;
                let a = pop(stack)?;
                push(stack, if a == b { vec![1] } else { vec![] })?;
            }
            OP_VERIFY => {
                let top = pop(stack)?;
                if !is_true(&top) {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            OP_EQUALVERIFY => {
                let b = pop(stack)?;
                let a = pop(stack)?;
                if a != b {
                    return Err(ScriptError::EqualVerifyFailed);
                }
            }
            OP_CHECKSIG => {
                // Stack order after a P2PKH scriptSig is [.., sig, pubkey]; the
                // public key is on top.
                let pubkey = pop(stack)?;
                let signature = pop(stack)?;
                let ok = checker.check_signature(&signature, &pubkey);
                push(stack, if ok { vec![1] } else { vec![] })?;
            }

            other => return Err(ScriptError::UnsupportedOpcode(other)),
        }
    }
    Ok(())
}

fn push(stack: &mut Vec<Vec<u8>>, item: Vec<u8>) -> Result<(), ScriptError> {
    if item.len() > MAX_SCRIPT_ELEMENT {
        return Err(ScriptError::ElementTooLarge);
    }
    if stack.len() >= MAX_STACK_ITEMS {
        return Err(ScriptError::StackOverflow);
    }
    stack.push(item);
    Ok(())
}

fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ScriptError> {
    stack.pop().ok_or(ScriptError::StackUnderflow)
}

fn read_u8(script: &[u8], i: &mut usize) -> Result<u8, ScriptError> {
    if *i >= script.len() {
        return Err(ScriptError::Truncated);
    }
    let byte = script[*i];
    *i += 1;
    Ok(byte)
}

fn read_push<'a>(script: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8], ScriptError> {
    let end = i.checked_add(len).ok_or(ScriptError::Truncated)?;
    if end > script.len() {
        return Err(ScriptError::Truncated);
    }
    let data = &script[*i..end];
    *i = end;
    Ok(data)
}

/// Bitcoin's rule for interpreting a stack item as a boolean: empty and every
/// encoding of zero (including negative zero) are false, everything else is true.
fn is_true(item: &[u8]) -> bool {
    if item.is_empty() {
        return false;
    }
    for (index, &byte) in item.iter().enumerate() {
        if byte != 0 {
            // The last byte 0x80 alone is negative zero, which is false.
            if index == item.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Build the standard P2PKH locking script for a public-key hash:
/// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script_pubkey(pkhash: &Hash160) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(OP_DUP);
    script.push(OP_HASH160);
    push_data(&pkhash.0, &mut script);
    script.push(OP_EQUALVERIFY);
    script.push(OP_CHECKSIG);
    script
}

/// Build the unlocking script for a P2PKH spend: `<sig> <pubkey>`.
pub fn p2pkh_script_sig(signature: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(signature.len() + public_key.len() + 2);
    push_data(signature, &mut script);
    push_data(public_key, &mut script);
    script
}

/// Append a minimal data push for `data` to `script`.
pub fn push_data(data: &[u8], script: &mut Vec<u8>) {
    let len = data.len();
    if len < OP_PUSHDATA1 as usize {
        script.push(len as u8);
    } else if len <= 0xff {
        script.push(OP_PUSHDATA1);
        script.push(len as u8);
    } else {
        script.push(OP_PUSHDATA2);
        script.push((len & 0xff) as u8);
        script.push(((len >> 8) & 0xff) as u8);
    }
    script.extend_from_slice(data);
}

/// A checker that always accepts, for unit-testing script flow without a
/// transaction. Never used by consensus code.
#[cfg(test)]
pub struct AlwaysAccept;

#[cfg(test)]
impl SigChecker for AlwaysAccept {
    fn check_signature(&self, _signature: &[u8], _public_key: &[u8]) -> bool {
        true
    }
}

#[cfg(test)]
pub struct RejectAll;

#[cfg(test)]
impl SigChecker for RejectAll {
    fn check_signature(&self, _signature: &[u8], _public_key: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2pkh_pair() -> (Vec<u8>, Vec<u8>) {
        let pubkey = vec![0x02; 33];
        let pkhash = hash160(&pubkey);
        let script_pubkey = p2pkh_script_pubkey(&pkhash);
        let script_sig = p2pkh_script_sig(&vec![0x30; 71], &pubkey);
        (script_sig, script_pubkey)
    }

    #[test]
    fn valid_p2pkh_script_passes() {
        let (script_sig, script_pubkey) = p2pkh_pair();
        assert!(verify(&script_sig, &script_pubkey, &AlwaysAccept).is_ok());
    }

    #[test]
    fn bad_signature_fails() {
        let (script_sig, script_pubkey) = p2pkh_pair();
        assert_eq!(
            verify(&script_sig, &script_pubkey, &RejectAll),
            Err(ScriptError::EvalFalse)
        );
    }

    #[test]
    fn wrong_pubkey_hash_fails_equalverify() {
        let pubkey = vec![0x02; 33];
        // Lock to a different key's hash, then try to spend with the wrong pubkey.
        let other = hash160(&vec![0x03; 33]);
        let script_pubkey = p2pkh_script_pubkey(&other);
        let script_sig = p2pkh_script_sig(&vec![0x30; 71], &pubkey);
        assert_eq!(
            verify(&script_sig, &script_pubkey, &AlwaysAccept),
            Err(ScriptError::EqualVerifyFailed)
        );
    }

    #[test]
    fn unsupported_opcode_rejected() {
        // OP_RETURN (0x6a) is not part of the P2PKH subset.
        let script_pubkey = vec![0x6a];
        let script_sig = vec![OP_0 + 1, 0xaa];
        assert!(matches!(
            verify(&script_sig, &script_pubkey, &AlwaysAccept),
            Err(ScriptError::UnsupportedOpcode(0x6a))
        ));
    }

    #[test]
    fn stack_underflow_rejected() {
        // OP_DUP with an empty stack.
        assert_eq!(
            verify(&[], &[OP_DUP], &AlwaysAccept),
            Err(ScriptError::StackUnderflow)
        );
    }

    #[test]
    fn push_data_uses_minimal_prefix() {
        let mut s = Vec::new();
        push_data(&[0u8; 20], &mut s);
        assert_eq!(s[0], 20);
        let mut big = Vec::new();
        push_data(&[0u8; 200], &mut big);
        assert_eq!(big[0], OP_PUSHDATA1);
        assert_eq!(big[1], 200);
    }
}
