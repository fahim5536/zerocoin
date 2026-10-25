//! Phase P0 — golden-vector emitter for the ZeroCoin Rust baseline.
//!
//! The corpus under `../test/vectors` is *produced by the shipping Rust code*, not
//! by a reimplementation: every case below calls the same public functions the node
//! calls. The Python harness in `../test/harness` then re-derives the same bytes
//! independently, so a vector carries both a Rust origin and a second opinion.
//!
//! Two tests:
//!
//! * `baseline_vectors_match_the_committed_corpus` — the corpus on disk is exactly
//!   what this code produces today. Set `ZRO_VECTOR_WRITE=1` to regenerate in place.
//! * `corpus_generation_is_deterministic` — two generations are byte-identical, which
//!   is gate G0's determinism half.
//!
//! Nothing here uses the wall clock, an RNG, a wallet, a data directory, or the
//! network. Every input is a literal: fixed scalars, fixed timestamps, fixed nonces.
//! No environment variable other than `ZRO_VECTOR_WRITE` is consulted, and that one
//! only selects write-versus-compare, so the corpus never depends on git state. The
//! provenance commit recorded in every file is the pinned literal `SOURCE_COMMIT`,
//! not a `git rev-parse` call, for the same reason.
//!
//! Run:
//! ```text
//! cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors
//! $env:ZRO_VECTOR_WRITE = "1"; cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use zerocoin::address::{Address, AddressError};
use zerocoin::consensus::block::{merkle_root, Block, BlockError, BlockHeader, BLOCK_VERSION};
use zerocoin::consensus::difficulty::{
    compact_from_target, compact_to_target, hash_meets_target, next_difficulty, required_work,
    validate_bits, DifficultyError, DIFFICULTY_PARAMS,
};
use zerocoin::consensus::immutability::{
    verify_boot_invariants, EMPTY_STATE_ROOT, GENESIS_COINBASE_TXID, GENESIS_HASH_DEVNET,
    GENESIS_HASH_REGTEST, GENESIS_MERKLE_ROOT, GENESIS_PREIMAGE_DIGEST_MAINNET,
    STATE_ROOT_LAYOUT_PROBE,
};
use zerocoin::consensus::pow::{PowEngine, ScratchPadEngine, TrivialEngine};
use zerocoin::consensus::reward::{
    block_reward, block_subsidy, coinbase_height, coinbase_transaction, maturity_height,
    split_reward, total_supply_ceiling, validate_coinbase, RewardError, COINBASE_MATURITY,
    FAH_PER_ZRO, HALVING_INTERVAL, INITIAL_SUBSIDY, MAX_HALVINGS, MAX_SUPPLY,
};
use zerocoin::consensus::uint256::Uint256;
use zerocoin::crypto::hash::{sha256, sha256d, Hash160, Hash256};
use zerocoin::crypto::secp256k1::{CryptoError, PrivateKey};
use zerocoin::genesis::{genesis_block, genesis_coinbase, GENESIS_MESSAGE};
use zerocoin::ledger::script::{
    p2pkh_script_pubkey, p2pkh_script_sig, push_data, verify, ScriptError,
    MAX_SCRIPT_ELEMENT, MAX_SCRIPT_SIZE, MAX_STACK_ITEMS, MAX_OPS_PER_SCRIPT,
};
use zerocoin::ledger::sighash::{signature_hash, ChainId, TxSigChecker, SIGHASH_ALL};
use zerocoin::ledger::transaction::{
    write_varint, Outpoint, Transaction, TxDecodeError, TxIn, TxOut,
};
use zerocoin::ledger::utxo::{UtxoError, UtxoSet};
use zerocoin::params::{ChainParams, DEVNET_CHAIN, MAINNET_CHAIN, REGTEST_CHAIN};

/// The commit whose build inputs (`src/`, `Cargo.toml`, `Cargo.lock`, `build.rs`)
/// produced every expected value in this corpus.
///
/// This is a literal like every other input: querying `git` here would make the
/// corpus depend on the checkout and break the determinism gate. When an intended
/// change to a build input lands, regenerate the corpus and set this to the output
/// of `git log -1 --format=%H -- zerocoin/src zerocoin/Cargo.toml zerocoin/Cargo.lock
/// zerocoin/build.rs` in the same commit. `test/harness/run_vectors.py` rejects a
/// word that is not 40 lowercase hex digits, and rejects a file whose value differs
/// from the manifest's.
const SOURCE_COMMIT: &str = "7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c";

// ---------------------------------------------------------------------------
// Fixtures — every one is a literal so the corpus cannot drift with the clock
// ---------------------------------------------------------------------------

/// A small secp256k1 scalar (`0x00..01`), the published private key "1".
fn scalar(byte: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    PrivateKey::from_bytes(bytes).expect("1..=255 are valid secp256k1 scalars")
}

/// The repeated-byte keys the crate's own tests use (`[9u8; 32]` and friends).
fn repeated(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes([byte; 32]).expect("repeated-byte scalars are valid")
}

fn hx(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn hash256_json(hash: &Hash256) -> Value {
    json!({
        "internal_hex": hex::encode(hash.0),
        "display_hex": hash.to_display_hex(),
    })
}

fn target_json(target: &Uint256) -> String {
    hx(&target.to_be_bytes())
}

fn case(id: &str, intent: &str, input: Value, expected: Value, independent_check: &str) -> Value {
    json!({
        "id": id,
        "intent": intent,
        "input": input,
        "expected": expected,
        "independent_check": independent_check,
    })
}

fn envelope(group: &str, intent: &str, note: &str, cases: Vec<Value>) -> String {
    let doc = json!({
        "schema": "zro-baseline-vectors/1",
        "group": group,
        "intent": intent,
        "note": note,
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": SOURCE_COMMIT,
        "provenance": "every expected value was produced by the shipping `zerocoin/` Rust code at `source_commit`; no value is transcribed from another implementation",
        "case_count": cases.len(),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("vector document serialises");
    text.push('\n');
    text
}

// ---------------------------------------------------------------------------
// Error-class helpers: the C++ port must reproduce the *kind*, not just a bool
// ---------------------------------------------------------------------------

fn script_error(error: &ScriptError) -> &'static str {
    match error {
        ScriptError::ScriptTooLarge => "ScriptTooLarge",
        ScriptError::TooManyOps => "TooManyOps",
        ScriptError::StackOverflow => "StackOverflow",
        ScriptError::StackUnderflow => "StackUnderflow",
        ScriptError::ElementTooLarge => "ElementTooLarge",
        ScriptError::EvalFalse => "EvalFalse",
        ScriptError::VerifyFailed => "VerifyFailed",
        ScriptError::EqualVerifyFailed => "EqualVerifyFailed",
        ScriptError::Truncated => "Truncated",
        ScriptError::UnsupportedOpcode(_) => "UnsupportedOpcode",
    }
}

fn reward_error(error: &RewardError) -> &'static str {
    match error {
        RewardError::NotCoinbase => "NotCoinbase",
        RewardError::BadCoinbaseHeight { .. } => "BadCoinbaseHeight",
        RewardError::MissingHeightCommitment => "MissingHeightCommitment",
        RewardError::GenesisPremine { .. } => "GenesisPremine",
        RewardError::TooMuchReward { .. } => "TooMuchReward",
        RewardError::BelowFees { .. } => "BelowFees",
        RewardError::SupplyCapExceeded { .. } => "SupplyCapExceeded",
        RewardError::RewardOverflow => "RewardOverflow",
    }
}

fn difficulty_error(error: &DifficultyError) -> &'static str {
    match error {
        DifficultyError::TargetAbovePowLimit { .. } => "TargetAbovePowLimit",
        DifficultyError::UnexpectedBits { .. } => "UnexpectedBits",
        DifficultyError::ZeroTarget(_) => "ZeroTarget",
    }
}

fn utxo_error(error: &UtxoError) -> &'static str {
    match error {
        UtxoError::NoInputs => "NoInputs",
        UtxoError::MissingInput(_) => "MissingInput",
        UtxoError::ImmatureCoinbase { .. } => "ImmatureCoinbase",
        UtxoError::DoubleSpend(_) => "DoubleSpend",
        UtxoError::ScriptInvalid { .. } => "ScriptInvalid",
        UtxoError::InputOverflow => "InputOverflow",
        UtxoError::OutputOverflow => "OutputOverflow",
        UtxoError::NegativeFee { .. } => "NegativeFee",
    }
}

fn address_error(error: &AddressError) -> &'static str {
    match error {
        AddressError::BadEncoding(_) => "BadEncoding",
        AddressError::BadLength(_) => "BadLength",
        AddressError::BadChecksum => "BadChecksum",
        AddressError::WrongNetwork { .. } => "WrongNetwork",
    }
}

fn crypto_error(error: &CryptoError) -> &'static str {
    match error {
        CryptoError::InvalidSecret => "InvalidSecret",
        CryptoError::InvalidPublicKey => "InvalidPublicKey",
        CryptoError::InvalidSignature => "InvalidSignature",
        CryptoError::VerificationFailed => "VerificationFailed",
    }
}

fn tx_decode_error(error: &TxDecodeError) -> &'static str {
    match error {
        TxDecodeError::Truncated(_) => "Truncated",
        TxDecodeError::NonMinimalVarInt => "NonMinimalVarInt",
        TxDecodeError::TooManyInputs(_) => "TooManyInputs",
        TxDecodeError::TooManyOutputs(_) => "TooManyOutputs",
        TxDecodeError::ScriptTooLarge(_) => "ScriptTooLarge",
    }
}

// ---------------------------------------------------------------------------
// Fixture transactions
// ---------------------------------------------------------------------------

/// The `sample_tx` fixture from `ledger/transaction.rs`'s own tests.
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

/// A two-in, two-out payment with a non-zero lock time, used for sighash vectors.
fn payment_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                previous_output: Outpoint {
                    txid: Hash256([0x22; 32]),
                    vout: 1,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
            },
            TxIn {
                previous_output: Outpoint {
                    txid: Hash256([0x33; 32]),
                    vout: 7,
                },
                script_sig: Vec::new(),
                sequence: 0,
            },
        ],
        outputs: vec![
            TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            },
            TxOut {
                value: 2_100_000_000_000_000,
                script_pubkey: vec![0x6a],
            },
        ],
        lock_time: 500_000,
    }
}

fn signed_payment() -> (Transaction, Hash256, Hash160) {
    let key = scalar(1);
    let script_code = p2pkh_script_pubkey(&key.public_key().key_hash());
    let mut tx = payment_tx();
    let digest = signature_hash(&tx, 0, &script_code, REGTEST_CHAIN, SIGHASH_ALL)
        .expect("input 0 exists");
    let signature = key.sign(&digest).expect("signing succeeds");
    let mut with_type = signature.to_der().to_vec();
    with_type.push(SIGHASH_ALL as u8);
    tx.inputs[0].script_sig = p2pkh_script_sig(&with_type, &key.public_key().to_sec1());
    (tx, digest, key.public_key().key_hash())
}

fn header_at(height: u64, nonce: u64) -> BlockHeader {
    BlockHeader {
        version: BLOCK_VERSION,
        chain: REGTEST_CHAIN.0,
        height,
        previous_hash: Hash256([0x33; 32]),
        merkle_root: Hash256([0x44; 32]),
        timestamp: 1_700_000_000 + height,
        difficulty_bits: 0x207f_ffff,
        engine_id: 0,
        nonce,
    }
}

// ---------------------------------------------------------------------------
// Group: hash
// ---------------------------------------------------------------------------

fn hash_cases() -> Vec<Value> {
    let pubkey = scalar(1).public_key();
    let mut reversed = [0u8; 32];
    reversed[0] = 0xab;
    vec![
        case(
            "hash.sha256.abc",
            "rule",
            json!({"data_utf8": "abc"}),
            json!({"sha256_hex": hx(&sha256(b"abc"))}),
            "NIST FIPS 180-4 published vector",
        ),
        case(
            "hash.sha256.empty",
            "rule",
            json!({"data_utf8": ""}),
            json!({"sha256_hex": hx(&sha256(b""))}),
            "NIST FIPS 180-4 published vector",
        ),
        case(
            "hash.sha256d.zerocoin",
            "rule",
            json!({"data_utf8": "zerocoin"}),
            json!({"hash256": hash256_json(&sha256d(b"zerocoin"))}),
            "sha256d(x) == sha256(sha256(x))",
        ),
        case(
            "hash.hash160.pubkey_scalar_1",
            "rule",
            json!({"pubkey_sec1_hex": hx(&pubkey.to_sec1())}),
            json!({"hash160_hex": hx(&pubkey.key_hash().0)}),
            "RIPEMD160(SHA256(pubkey)) — Bitcoin's privkey-1 P2PKH vector",
        ),
        case(
            "hash.display_reversal",
            "oddity",
            json!({"internal_hex": hx(&reversed)}),
            json!({"display_hex": Hash256(reversed).to_display_hex()}),
            "F3: Display/explorer form reverses the internal big-endian bytes",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: encoding (varint, transaction)
// ---------------------------------------------------------------------------

fn varint_cases() -> Vec<Value> {
    [0u64, 1, 252, 253, 65_535, 65_536, 4_294_967_295, 4_294_967_296, u64::MAX]
        .iter()
        .map(|value| {
            let mut out = Vec::new();
            write_varint(*value, &mut out);
            case(
                &format!("encoding.varint.{value}"),
                "rule",
                json!({"value": value}),
                json!({"bytes_hex": hx(&out), "length": out.len()}),
                "Bitcoin CompactSize: 0xfd/0xfe/0xff prefixes with little-endian payloads",
            )
        })
        .collect()
}

fn transaction_cases() -> Vec<Value> {
    let sample = sample_tx();
    let key = scalar(1);
    let coinbase = coinbase_transaction(147, &key.public_key(), block_subsidy(147));
    let payment = payment_tx();
    let empty = Transaction {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
    };
    let non_minimal = Transaction::deserialize(&[1, 0, 0, 0, 0xfd, 0x01, 0x00])
        .expect_err("a non-minimal input count must be rejected");
    let total = sample.output_value().expect("no overflow");

    // The fixtures are published field by field instead of as a pointer at Rust
    // source, so an implementation in another language can rebuild them without
    // reading this repository.
    let tx_json = |tx: &Transaction| {
        json!({
            "version": tx.version,
            "inputs": tx
                .inputs
                .iter()
                .map(|input| json!({
                    "txid_hex": hx(&input.previous_output.txid.0),
                    "vout": input.previous_output.vout,
                    "script_sig_hex": hx(&input.script_sig),
                    "sequence": input.sequence,
                }))
                .collect::<Vec<_>>(),
            "outputs": tx
                .outputs
                .iter()
                .map(|output| json!({
                    "value": output.value,
                    "script_pubkey_hex": hx(&output.script_pubkey),
                }))
                .collect::<Vec<_>>(),
            "lock_time": tx.lock_time,
        })
    };

    vec![
        case(
            "encoding.transaction.sample",
            "rule",
            tx_json(&sample),
            json!({
                "serialized_hex": hx(&sample.serialize()),
                "serialized_len": sample.serialize().len(),
                "txid": hash256_json(&sample.txid()),
                "output_value": total,
                "is_coinbase": sample.is_coinbase(),
                "roundtrip": Transaction::deserialize(&sample.serialize()).map(|t| t == sample).unwrap_or(false),
            }),
            "version LE || varint(in) || inputs || varint(out) || outputs || lock_time LE",
        ),
        case(
            "encoding.transaction.empty",
            "rule",
            json!({"version": 2, "inputs": 0, "outputs": 0, "lock_time": 0}),
            json!({
                "serialized_hex": hx(&empty.serialize()),
                "txid": hash256_json(&empty.txid()),
            }),
            "degenerate encoding: no inputs, no outputs, lock time only",
        ),
        case(
            "encoding.transaction.payment",
            "rule",
            tx_json(&payment),
            json!({
                "serialized_hex": hx(&payment.serialize()),
                "txid": hash256_json(&payment.txid()),
                "output_value": payment.output_value(),
            }),
            "multi-input ordering and the 0x6a single-byte output script",
        ),
        case(
            "encoding.transaction.coinbase_147",
            "rule",
            json!({"height": 147, "payout_scalar": 1}),
            json!({
                "serialized_hex": hx(&coinbase.serialize()),
                "txid": hash256_json(&coinbase.txid()),
                "script_sig_hex": hx(&coinbase.inputs[0].script_sig),
                "script_pubkey_hex": hx(&coinbase.outputs[0].script_pubkey),
                "output_value": coinbase.outputs[0].value,
                "committed_height": coinbase_height(&coinbase),
                "is_coinbase": coinbase.is_coinbase(),
            }),
            "BIP-34 height push + \"ZeroCoin\" tag in the scriptSig",
        ),
        case(
            "encoding.transaction.decode_nonminimal_varint",
            "rule",
            json!({"bytes_hex": "01000000fd0100"}),
            json!({"kind": tx_decode_error(&non_minimal)}),
            "0xfd 0x01 0x00 encodes 1 non-minimally and must be refused",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: ledger.script
// ---------------------------------------------------------------------------

fn script_cases() -> Vec<Value> {
    let key = scalar(1);
    let pkhash = key.public_key().key_hash();
    let script_pubkey = p2pkh_script_pubkey(&pkhash);
    let (signed, digest, _pkh) = signed_payment();
    let dummy = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint::null(),
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: Vec::new(),
        lock_time: 0,
    };
    let checker = TxSigChecker::new(&dummy, 0, &script_pubkey, REGTEST_CHAIN);

    let push = |len: usize| {
        let mut script = Vec::new();
        push_data(&vec![0xab; len], &mut script);
        hx(&script)
    };

    let mut overflow_script = Vec::new();
    for _ in 0..=MAX_STACK_ITEMS {
        overflow_script.push(0x01);
        overflow_script.push(0x00);
    }

    let mut oversized_element = Vec::new();
    push_data(&vec![0xcd; MAX_SCRIPT_ELEMENT + 1], &mut oversized_element);

    // An unsupported opcode is rejected the moment it is reached, so the op budget
    // must be exhausted with opcodes the interpreter actually executes: seed one
    // stack item, then duplicate it MAX_OPS_PER_SCRIPT + 1 times.
    let mut too_many_ops = vec![0x01u8, 0x01];
    too_many_ops.extend(std::iter::repeat(0x76u8).take(MAX_OPS_PER_SCRIPT + 1));

    let accept_checker = TxSigChecker::new(&signed, 0, &script_pubkey, REGTEST_CHAIN);
    let accepted = verify(&signed.inputs[0].script_sig, &script_pubkey, &accept_checker);

    // Re-derive the exact bytes the scriptSig pushes, so the case publishes both its
    // input and its output: RFC 6979 makes the signature over `digest` reproducible.
    let (sig_with_type, sig_script) = {
        let mut with_type = key
            .sign(&digest)
            .expect("signing succeeds")
            .to_der()
            .to_vec();
        with_type.push(SIGHASH_ALL as u8);
        let script = p2pkh_script_sig(&with_type, &key.public_key().to_sec1());
        (with_type, script)
    };

    let reject_case = |id: &str, sig: &[u8], pubkey: &[u8]| {
        let outcome = verify(sig, pubkey, &checker);
        case(
            id,
            "rule",
            json!({"script_sig_hex": hx(sig), "script_pubkey_hex": hx(pubkey)}),
            json!({
                "accepted": outcome.is_ok(),
                "error_kind": outcome.as_ref().err().map(script_error),
            }),
            "scriptSig then scriptPubKey on one stack; top of stack must be true",
        )
    };

    vec![
        case(
            "ledger.script.push_data.lengths",
            "rule",
            json!({"lengths": [0, 1, 75, 76, 255, 256, 520]}),
            json!({
                "len_0": push(0),
                "len_1": push(1),
                "len_75": push(75),
                "len_76": push(76),
                "len_255": push(255),
                "len_256": push(256),
                "len_520": push(520),
            }),
            "length < 0x4c inline, <= 0xff uses OP_PUSHDATA1, else OP_PUSHDATA2 LE",
        ),
        case(
            "ledger.script.p2pkh_script_pubkey",
            "rule",
            json!({"pubkey_hash_hex": hx(&pkhash.0)}),
            json!({"script_hex": hx(&script_pubkey), "length": script_pubkey.len()}),
            "OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG",
        ),
        case(
            "ledger.script.p2pkh_script_sig",
            "rule",
            json!({
                "signature_with_sighash_hex": hx(&sig_with_type),
                "pubkey_sec1_hex": hx(&key.public_key().to_sec1()),
            }),
            json!({"script_hex": hx(&sig_script), "length": sig_script.len()}),
            "<push sig> <push pubkey>, both minimal pushes",
        ),
        case(
            "ledger.script.p2pkh_spend_accepted",
            "rule",
            json!({
                "tx_hex": hx(&signed.serialize()),
                "input_index": 0,
                "script_code_hex": hx(&script_pubkey),
                "chain_id": REGTEST_CHAIN.0,
                "sighash_type": SIGHASH_ALL,
                "script_sig_hex": hx(&signed.inputs[0].script_sig),
                "script_pubkey_hex": hx(&script_pubkey),
            }),
            json!({
                "accepted": accepted.is_ok(),
                "error_kind": accepted.as_ref().err().map(script_error),
                "txid": hx(&signed.txid().0),
            }),
            "a real signature from scalar 1 satisfies its own P2PKH script",
        ),
        reject_case("ledger.script.reject_unsupported_opcode", &[], &[0x6a]),
        reject_case("ledger.script.reject_false_push", &[], &[0x01, 0x80]),
        reject_case("ledger.script.reject_empty_push", &[], &[0x00]),
        reject_case("ledger.script.reject_op_verify_empty_stack", &[], &[0x69]),
        reject_case(
            "ledger.script.reject_equalverify_unequal",
            &[0x01, 0x01, 0x01, 0x02],
            &[0x88],
        ),
        reject_case("ledger.script.reject_stack_underflow", &[], &[0x87]),
        reject_case("ledger.script.reject_truncated_push", &[], &[0x02, 0x01]),
        reject_case(
            "ledger.script.reject_element_too_large",
            &[],
            &oversized_element,
        ),
        reject_case(
            "ledger.script.reject_stack_overflow",
            &[],
            &overflow_script,
        ),
        reject_case("ledger.script.reject_too_many_ops", &[], &too_many_ops),
        reject_case(
            "ledger.script.reject_script_too_large",
            &[],
            &vec![0x61u8; MAX_SCRIPT_SIZE + 1],
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: ledger.sighash
// ---------------------------------------------------------------------------

fn sighash_cases() -> Vec<Value> {
    let tx = payment_tx();
    let key = scalar(1);
    let script_code = p2pkh_script_pubkey(&key.public_key().key_hash());
    let regtest = signature_hash(&tx, 0, &script_code, REGTEST_CHAIN, SIGHASH_ALL)
        .expect("input 0 exists");
    let second = signature_hash(&tx, 1, &script_code, REGTEST_CHAIN, SIGHASH_ALL)
        .expect("input 1 exists");
    let mainnet = signature_hash(&tx, 0, &script_code, ChainId(0x5A52_4F01), SIGHASH_ALL)
        .expect("input 0 exists");
    let other_type = signature_hash(&tx, 0, &script_code, REGTEST_CHAIN, 0x02)
        .expect("input 0 exists");
    let out_of_range = signature_hash(&tx, 2, &script_code, REGTEST_CHAIN, SIGHASH_ALL);

    let signature = key.sign(&regtest).expect("signing succeeds");
    let verified = key.public_key().verify(&regtest, &signature).is_ok();
    let cross_key = repeated(9);
    let cross_verified = cross_key.public_key().verify(&regtest, &signature).is_ok();

    let digest_case = |id: &str, index: usize, chain: ChainId, kind: u32, tag: &str| {
        let mut preimage = Vec::new();
        let digest = signature_hash(&tx, index, &script_code, chain, kind);
        // Rebuild the preimage here only to publish it; the digest is the output of
        // `signature_hash` itself, never of this reconstruction.
        preimage.extend_from_slice(b"ZRO/sighash/v1\0");
        preimage.extend_from_slice(&chain.0.to_le_bytes());
        preimage.extend_from_slice(&tx.version.to_le_bytes());
        write_varint(tx.inputs.len() as u64, &mut preimage);
        for (i, input) in tx.inputs.iter().enumerate() {
            preimage.extend_from_slice(&input.previous_output.txid.0);
            preimage.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            let script: &[u8] = if i == index { &script_code } else { &[] };
            write_varint(script.len() as u64, &mut preimage);
            preimage.extend_from_slice(script);
            preimage.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(tx.outputs.len() as u64, &mut preimage);
        for output in &tx.outputs {
            preimage.extend_from_slice(&output.value.to_le_bytes());
            write_varint(output.script_pubkey.len() as u64, &mut preimage);
            preimage.extend_from_slice(&output.script_pubkey);
        }
        preimage.extend_from_slice(&tx.lock_time.to_le_bytes());
        preimage.extend_from_slice(&kind.to_le_bytes());
        case(
            id,
            tag,
            json!({
                "tx_hex": hx(&tx.serialize()),
                "txid": hx(&tx.txid().0),
                "input_index": index,
                "chain_id": chain.0,
                "sighash_type": kind,
                "script_code_hex": hx(&script_code),
            }),
            json!({
                "preimage_hex": hx(&preimage),
                "digest": digest.map(|d| hash256_json(&d)),
            }),
            "SIGHASH_TAG || chain || version || ins || outs || lock_time || type",
        )
    };

    vec![
        digest_case("ledger.sighash.regtest_index_0", 0, REGTEST_CHAIN, SIGHASH_ALL, "rule"),
        digest_case("ledger.sighash.regtest_index_1", 1, REGTEST_CHAIN, SIGHASH_ALL, "rule"),
        digest_case(
            "ledger.sighash.mainnet_chain_binding",
            0,
            ChainId(0x5A52_4F01),
            SIGHASH_ALL,
            "rule",
        ),
        digest_case(
            "ledger.sighash.type_02_is_folded_in",
            0,
            REGTEST_CHAIN,
            0x02,
            "oddity",
        ),
        digest_case("ledger.sighash.regtest_index_repeat", 0, REGTEST_CHAIN, SIGHASH_ALL, "rule"),
        case(
            "ledger.sighash.out_of_range_index",
            "rule",
            json!({"input_index": 2, "input_count": 2}),
            json!({"digest": out_of_range.map(|d| hash256_json(&d))}),
            "an index past the end yields None rather than a digest",
        ),
        case(
            "ledger.sighash.digest_stability",
            "rule",
            json!({"note": "the three cases above must be pairwise distinct"}),
            json!({
                "index_0_equals_index_1": regtest == second,
                "regtest_equals_mainnet": regtest == mainnet,
                "type_all_equals_type_02": regtest == other_type,
            }),
            "chain and index are domain-separated; the type byte is not validated",
        ),
        case(
            "ledger.sighash.signature_der",
            "rule",
            json!({"scalar": 1, "digest": hash256_json(&regtest)}),
            json!({
                "der_hex": hx(signature.to_der()),
                "der_len": signature.to_der().len(),
                "verified": verified,
                "verified_under_other_key": cross_verified,
            }),
            "RFC 6979 deterministic ECDSA over secp256k1; DER, low-S",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: chain.header
// ---------------------------------------------------------------------------

fn header_cases() -> Vec<Value> {
    let engine = TrivialEngine::new();
    let h1 = header_at(1, 0);
    let h1_nonce = header_at(1, 42);
    let leaves_one = [Hash256([0x11; 32])];
    let leaves_two = [Hash256([0x11; 32]), Hash256([0x22; 32])];
    let leaves_three = [
        Hash256([0x11; 32]),
        Hash256([0x22; 32]),
        Hash256([0x33; 32]),
    ];
    let leaves_five = [
        Hash256([0x11; 32]),
        Hash256([0x22; 32]),
        Hash256([0x33; 32]),
        Hash256([0x44; 32]),
        Hash256([0x55; 32]),
    ];

    let header_json = |header: &BlockHeader| {
        json!({
            "version": header.version,
            "chain": header.chain,
            "height": header.height,
            "previous_hash_hex": hx(&header.previous_hash.0),
            "merkle_root_hex": hx(&header.merkle_root.0),
            "timestamp": header.timestamp,
            "difficulty_bits": header.difficulty_bits,
            "engine_id": header.engine_id,
            "nonce": header.nonce,
        })
    };

    let mainnet = ChainParams::mainnet();
    let mainnet_genesis_header = BlockHeader {
        version: BLOCK_VERSION,
        chain: mainnet.chain_id.0,
        height: 0,
        previous_hash: Hash256::ZERO,
        merkle_root: GENESIS_MERKLE_ROOT,
        timestamp: zerocoin::params::GENESIS_TIMESTAMP,
        difficulty_bits: mainnet.genesis_bits,
        engine_id: mainnet.engine.id(),
        nonce: 0,
    };

    vec![
        case(
            "chain.header.preimage_regtest_h1",
            "rule",
            header_json(&h1),
            json!({
                "preimage_hex": hx(&h1.preimage()),
                "preimage_len": h1.preimage().len(),
                "pow_hash": hash256_json(&h1.pow_hash(&engine)),
            }),
            "ZRO/header/v1\\0 || version || chain || height || prev || merkle || time || bits || engine",
        ),
        case(
            "chain.header.preimage_regtest_h1_nonce_42",
            "rule",
            header_json(&h1_nonce),
            json!({
                "preimage_hex": hx(&h1_nonce.preimage()),
                "pow_hash": hash256_json(&h1_nonce.pow_hash(&engine)),
            }),
            "the nonce is outside the preimage and is appended by the engine",
        ),
        case(
            "chain.header.mainnet_genesis_preimage_digest",
            "rule",
            header_json(&mainnet_genesis_header),
            json!({
                "preimage_hex": hx(&mainnet_genesis_header.preimage()),
                "preimage_digest": hash256_json(&sha256d(&mainnet_genesis_header.preimage())),
                "pinned_anchor": hash256_json(&GENESIS_PREIMAGE_DIGEST_MAINNET),
            }),
            "cross-check against immutability::GENESIS_PREIMAGE_DIGEST_MAINNET",
        ),
        case(
            "chain.merkle.empty",
            "rule",
            json!({"leaves": 0}),
            json!({"root": hash256_json(&merkle_root(&[]))}),
            "sha256d(\"ZRO/merkle:empty\\0\") — a domain tag, not sha256d(\"\")",
        ),
        case(
            "chain.merkle.single",
            "rule",
            json!({"leaves_hex": [hx(&leaves_one[0].0)]}),
            json!({"root": hash256_json(&merkle_root(&leaves_one))}),
            "one leaf is its own root",
        ),
        case(
            "chain.merkle.two",
            "rule",
            json!({"leaves_hex": [hx(&leaves_two[0].0), hx(&leaves_two[1].0)]}),
            json!({"root": hash256_json(&merkle_root(&leaves_two))}),
            "sha256d(left || right)",
        ),
        case(
            "chain.merkle.three",
            "rule",
            json!({"leaves_hex": [hx(&leaves_three[0].0), hx(&leaves_three[1].0), hx(&leaves_three[2].0)]}),
            json!({"root": hash256_json(&merkle_root(&leaves_three))}),
            "odd trailing leaf is duplicated, never promoted",
        ),
        case(
            "chain.merkle.five",
            "rule",
            json!({"leaves_hex": [
                hx(&leaves_five[0].0), hx(&leaves_five[1].0), hx(&leaves_five[2].0),
                hx(&leaves_five[3].0), hx(&leaves_five[4].0)
            ]}),
            json!({"root": hash256_json(&merkle_root(&leaves_five))}),
            "two duplication rounds: 5 -> 3 -> 2 -> 1",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Groups: chain.header_preimage and chain.header_identity (P3.1A)
//
// A different question from `chain.header` above. That group pins what the
// shipped P0 corpus already said; these two record what the *current* encoder
// and the *current* identity validator produce across a deliberate boundary
// grid. They live in their own corpus root (`test/p31-vectors`) because the P0
// manifest carries a single `source_commit` - 7cb9017 - that predates
// `Block::validate_header_identity`. Stamping identity verdicts with it would
// claim provenance that commit does not have, and re-stamping the manifest
// would rewrite every historical fixture. The P0 corpus is left untouched.
// ---------------------------------------------------------------------------

/// `block::HEADER_TAG` is crate-private, so this integration test restates it.
/// `preimage_case` proves the restatement still matches the reference: every
/// emitted preimage must begin with these bytes and be `P31_PREIMAGE_LEN` long.
const P31_HEADER_TAG: &[u8] = b"ZRO/header/v1\0";

/// tag || version(4) || chain(4) || height(8) || prev(32) || merkle(32) ||
/// timestamp(8) || bits(4) || engine(1). Derived from the field list, so the
/// expected length moves with the layout instead of being copied from a doc.
const P31_PREIMAGE_LEN: usize = P31_HEADER_TAG.len() + 4 + 4 + 8 + 32 + 32 + 8 + 4 + 1;

/// The commit whose `zerocoin/` production code produced every value in this
/// corpus. It is the P3.1 baseline and it contains both functions under test.
const P31_SOURCE_COMMIT: &str = "2ea27f4a2f10f51a42814dfdfd312df94829500f";
/// Where `BlockHeader::preimage` last changed. Between this commit and
/// `P31_SOURCE_COMMIT` the only edit to `block.rs` extracts
/// `validate_header_identity`, so the preimage bytes are the same at both.
const P31_ENCODER_COMMIT: &str = "7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c";
/// Where `Block::validate_header_identity` entered `zerocoin/src`. It did not
/// exist at `P31_ENCODER_COMMIT`, so no fixture may cite that commit for it.
const P31_VALIDATOR_COMMIT: &str = "b71d769be8357bcf10d768d915770125cf7f7c24";

/// The header fields published as a case input. The same shape `chain.header`
/// uses, so one reader can consume both corpora.
fn header_input(header: &BlockHeader) -> Value {
    json!({
        "version": header.version,
        "chain": header.chain,
        "height": header.height,
        "previous_hash_hex": hx(&header.previous_hash.0),
        "merkle_root_hex": hx(&header.merkle_root.0),
        "timestamp": header.timestamp,
        "difficulty_bits": header.difficulty_bits,
        "engine_id": header.engine_id,
        "nonce": header.nonce,
    })
}

/// The exhaustive `BlockError` variant name. A port must reproduce the variant,
/// not merely "rejected".
fn block_error_kind(error: &BlockError) -> &'static str {
    match error {
        BlockError::WrongChain { .. } => "WrongChain",
        BlockError::BadHeight { .. } => "BadHeight",
        BlockError::BadPreviousHash => "BadPreviousHash",
        BlockError::RootMismatch => "RootMismatch",
        BlockError::WrongEngine { .. } => "WrongEngine",
        BlockError::BadDifficulty { .. } => "BadDifficulty",
        BlockError::InsufficientProofOfWork => "InsufficientProofOfWork",
        BlockError::TimestampTooOld { .. } => "TimestampTooOld",
        BlockError::TimestampTooFarFuture { .. } => "TimestampTooFarFuture",
        BlockError::NoTransactions => "NoTransactions",
        BlockError::FirstNotCoinbase => "FirstNotCoinbase",
        BlockError::DuplicateCoinbase => "DuplicateCoinbase",
        BlockError::TooManyTransactions(_) => "TooManyTransactions",
    }
}

/// The numeric payload of the two variants this validator can produce. Every
/// other variant publishes `null` rather than a guessed shape.
fn block_error_payload(error: &BlockError) -> Value {
    match error {
        BlockError::WrongChain { expected, found } => {
            json!({"expected": expected, "found": found})
        }
        BlockError::BadHeight { expected, found } => {
            json!({"expected": expected, "found": found})
        }
        _ => Value::Null,
    }
}

/// The P3.1A envelope: the P0 envelope plus the two reference commits, so one
/// file answers "which code produced this" without consulting the manifest.
fn p31_envelope(group: &str, intent: &str, note: &str, cases: Vec<Value>) -> String {
    let doc = json!({
        "schema": "zro-baseline-vectors/1",
        "group": group,
        "intent": intent,
        "note": note,
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P31_SOURCE_COMMIT,
        "provenance": "every expected value was produced by the shipping `zerocoin/` Rust code at `source_commit`; no value is transcribed from another implementation or written by hand",
        "reference_commits": {
            "encoder": P31_ENCODER_COMMIT,
            "validator_introduced": P31_VALIDATOR_COMMIT,
        },
        "generator": "zerocoin/tests/export_baseline_vectors.rs (`p31_*` functions), added by the P3.1A commit that lands immediately after the baseline; a fixture cannot record the hash of the commit that contains it",
        "case_count": cases.len(),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("reference document serialises");
    text.push('\n');
    text
}

/// One preimage case: the header goes in, the reference's own bytes come out.
/// The length and tag assertions make the exporter fail loudly if the layout
/// ever moves, so a stale expectation cannot be published silently.
fn preimage_case(
    id: &str,
    intent: &str,
    header: &BlockHeader,
    with_tag: bool,
    independent_check: &str,
) -> Value {
    let preimage = header.preimage();
    assert_eq!(
        preimage.len(),
        P31_PREIMAGE_LEN,
        "{id}: the reference preimage is no longer the frozen length"
    );
    assert!(
        preimage.starts_with(P31_HEADER_TAG),
        "{id}: the reference preimage no longer starts with the frozen tag"
    );

    let mut expected = json!({
        "preimage_hex": hx(&preimage),
        "preimage_len": preimage.len(),
        "preimage_digest": hash256_json(&sha256d(&preimage)),
    });
    if with_tag {
        // A slice of the real output, not a restated constant.
        let tag = hx(&preimage[..P31_HEADER_TAG.len()]);
        expected["tag_hex"] = Value::String(tag);
    }

    case(id, intent, header_input(header), expected, independent_check)
}

fn header_preimage_cases() -> Vec<Value> {
    let canonical = header_at(1, 0);
    let variant = |apply: &dyn Fn(&mut BlockHeader)| {
        let mut header = canonical.clone();
        apply(&mut header);
        header
    };
    // Ascending then descending byte runs: a display-order reversal of either
    // hash field reorders these bytes and the case fails.
    let ascending: [u8; 32] = std::array::from_fn(|index| index as u8 + 1);
    let descending: [u8; 32] = std::array::from_fn(|index| 32 - index as u8);
    let mainnet = ChainParams::mainnet();
    let devnet = ChainParams::devnet();

    vec![
        preimage_case(
            "chain.header_preimage.regtest_h1",
            "rule",
            &canonical,
            true,
            "tag || version || chain || height || prev || merkle || time || bits || engine, 107 bytes",
        ),
        preimage_case(
            "chain.header_preimage.nonce_excluded",
            "rule",
            &variant(&|header: &mut BlockHeader| header.nonce = 42),
            false,
            "the nonce is outside the preimage, so this hex must equal chain.header_preimage.regtest_h1 byte for byte",
        ),
        preimage_case(
            "chain.header_preimage.u32_top_bit",
            "oddity",
            &variant(&|header: &mut BlockHeader| {
                header.version = 0x8000_0000;
                header.chain = 0x8000_0001;
                header.difficulty_bits = 0x8000_0002;
            }),
            false,
            "top bit set in all three u32 fields: a signed encoding turns these negative and changes the bytes",
        ),
        preimage_case(
            "chain.header_preimage.u32_max",
            "oddity",
            &variant(&|header: &mut BlockHeader| {
                header.version = u32::MAX;
                header.chain = u32::MAX;
                header.difficulty_bits = u32::MAX;
            }),
            false,
            "u32::MAX in every u32 field: all four bytes are 0xff, little-endian",
        ),
        preimage_case(
            "chain.header_preimage.u64_top_bit",
            "oddity",
            &variant(&|header: &mut BlockHeader| {
                header.height = 0x8000_0000_0000_0000;
                header.timestamp = 0x8000_0000_0000_0001;
                header.nonce = 0x8000_0000_0000_0002;
            }),
            false,
            "top bit set in the u64 fields: little-endian puts 0x00 at byte 7, not 0x80",
        ),
        preimage_case(
            "chain.header_preimage.u64_max",
            "oddity",
            &variant(&|header: &mut BlockHeader| {
                header.height = u64::MAX;
                header.timestamp = u64::MAX;
                header.nonce = u64::MAX;
            }),
            false,
            "u64::MAX in every u64 field: eight 0xff bytes each",
        ),
        preimage_case(
            "chain.header_preimage.engine_id_max",
            "oddity",
            &variant(&|header: &mut BlockHeader| header.engine_id = u8::MAX),
            false,
            "the engine id is one raw byte; 0xff must not widen or sign-extend",
        ),
        preimage_case(
            "chain.header_preimage.mainnet_chain",
            "rule",
            &variant(&|header: &mut BlockHeader| {
                header.chain = MAINNET_CHAIN.0;
                header.height = 0;
                header.previous_hash = Hash256::ZERO;
                header.merkle_root = Hash256([0x55; 32]);
                header.timestamp = zerocoin::params::GENESIS_TIMESTAMP;
                header.difficulty_bits = mainnet.genesis_bits;
                header.engine_id = mainnet.engine.id();
            }),
            false,
            "a second configured chain id (mainnet) with its own engine id",
        ),
        preimage_case(
            "chain.header_preimage.devnet_chain",
            "rule",
            &variant(&|header: &mut BlockHeader| {
                header.chain = DEVNET_CHAIN.0;
                header.height = 0;
                header.previous_hash = Hash256::ZERO;
                header.merkle_root = Hash256([0x66; 32]);
                header.timestamp = zerocoin::params::GENESIS_TIMESTAMP;
                header.difficulty_bits = devnet.genesis_bits;
                header.engine_id = devnet.engine.id();
            }),
            false,
            "a third configured chain id (devnet); the chain field is never normalised",
        ),
        preimage_case(
            "chain.header_preimage.hash_bytes_raw_order",
            "rule",
            &variant(&|header: &mut BlockHeader| {
                header.previous_hash = Hash256(ascending);
                header.merkle_root = Hash256(descending);
            }),
            false,
            "both hashes are copied in stored byte order; there is no display-order reversal and no length prefix",
        ),
    ]
}

/// One identity case: the verdict comes from the real
/// `Block::validate_header_identity`, with an empty transaction list because the
/// validator reads only the header.
fn identity_case(
    id: &str,
    header: &BlockHeader,
    expected_chain: u32,
    expected_height: u64,
    independent_check: &str,
) -> Value {
    let outcome = Block {
        header: header.clone(),
        transactions: Vec::new(),
    }
    .validate_header_identity(expected_chain, expected_height);

    let expected = match &outcome {
        Ok(()) => json!({"accepted": true, "error_kind": null, "error_payload": null}),
        Err(error) => json!({
            "accepted": false,
            "error_kind": block_error_kind(error),
            "error_payload": block_error_payload(error),
        }),
    };

    case(
        id,
        "rule",
        json!({
            "header": header_input(header),
            "expected_chain": expected_chain,
            "expected_height": expected_height,
        }),
        expected,
        independent_check,
    )
}

fn header_identity_cases() -> Vec<Value> {
    let at = |height: u64| header_at(height, 0);
    let at_chain = |chain: u32, height: u64| {
        let mut header = header_at(height, 0);
        header.chain = chain;
        header
    };
    // `header_at` derives the timestamp as `1_700_000_000 + height`, which
    // overflows at u64::MAX, so the boundary header is built field by field.
    let max_height = {
        let mut header = header_at(0, 0);
        header.height = u64::MAX;
        header
    };

    vec![
        identity_case(
            "chain.header_identity.correct_chain_and_height",
            &at(1),
            REGTEST_CHAIN.0,
            1,
            "identity holds: the header names this chain and the height the caller expects next",
        ),
        identity_case(
            "chain.header_identity.chain_mismatch_only",
            &at_chain(MAINNET_CHAIN.0, 1),
            REGTEST_CHAIN.0,
            1,
            "height agrees, chain does not: WrongChain carrying both u32 payloads",
        ),
        identity_case(
            "chain.header_identity.height_mismatch_only",
            &at(1),
            REGTEST_CHAIN.0,
            2,
            "chain agrees, height does not: BadHeight carrying both u64 payloads",
        ),
        identity_case(
            "chain.header_identity.both_wrong_precedence",
            &at_chain(MAINNET_CHAIN.0, 1),
            REGTEST_CHAIN.0,
            2,
            "both fields wrong: the chain test runs first, so WrongChain wins; this is the F-1 evidence at this layer",
        ),
        identity_case(
            "chain.header_identity.height_zero_matches_zero",
            &at(0),
            REGTEST_CHAIN.0,
            0,
            "height 0 matches expected 0: this validator compares, it does not infer a valid height",
        ),
        identity_case(
            "chain.header_identity.height_zero_versus_expected_one",
            &at(0),
            REGTEST_CHAIN.0,
            1,
            "genesis cannot stand in for height 1: BadHeight, not WrongChain",
        ),
        identity_case(
            "chain.header_identity.height_above_expected",
            &at(5),
            REGTEST_CHAIN.0,
            1,
            "a height above the supplied expectation is BadHeight here; chain-tip and schedule behaviour is P4",
        ),
        identity_case(
            "chain.header_identity.height_max_payload",
            &max_height,
            REGTEST_CHAIN.0,
            1,
            "the found payload keeps all 64 bits of u64::MAX",
        ),
        identity_case(
            "chain.header_identity.chain_max_payload",
            &at_chain(u32::MAX, 1),
            REGTEST_CHAIN.0,
            1,
            "the found payload keeps all 32 bits of u32::MAX",
        ),
    ]
}

/// The P3.1A corpus, mirroring `corpus()` above: same `add!` shape, same
/// manifest, same write-versus-compare protocol, different root.
fn p31_corpus() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();

    macro_rules! add {
        ($path:expr, $group:expr, $intent:expr, $note:expr, $cases:expr) => {{
            let cases: Vec<Value> = $cases;
            counts.push(json!({"path": $path, "group": $group, "cases": cases.len()}));
            files.push(($path.to_string(), p31_envelope($group, $intent, $note, cases)));
        }};
    }

    add!(
        "chain/header_preimage.json",
        "chain.header_preimage",
        "rule",
        "The 107-byte header preimage: tag, field order, little-endian integers, \
         raw hash bytes, nonce exclusion and the u32/u64/engine_id boundaries.",
        header_preimage_cases()
    );
    add!(
        "chain/header_identity.json",
        "chain.header_identity",
        "rule",
        "Block::validate_header_identity: chain-before-height precedence, the \
         structured payloads of WrongChain and BadHeight, and heights that only \
         look invalid outside their caller.",
        header_identity_cases()
    );

    let manifest = json!({
        "schema": "zro-baseline-vectors/1",
        "phase": "P3.1A",
        "description": "Rust reference vectors for the P3.1 header preimage encoder and the P3.1 header identity validator.",
        "provenance": "every expected value was produced by the shipping `zerocoin/` Rust code at `source_commit`: `BlockHeader::preimage` (unchanged since `reference_commits.encoder`) and `Block::validate_header_identity` (`reference_commits.validator_introduced`); no value is transcribed from another implementation or written by hand",
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P31_SOURCE_COMMIT,
        "source_commit_rule": "the commit whose `zerocoin/` production code produced every value here; unlike the P0 corpus this is not the commit that introduced the exporter, so `generator` names the exporter separately",
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p31_*` functions, added by the P3.1A commit that lands immediately after 2ea27f4a2f10f51a42814dfdfd312df94829500f; no fixture can record the hash of the commit that contains it",
        "reference_commits": {
            "encoder": P31_ENCODER_COMMIT,
            "validator_introduced": P31_VALIDATOR_COMMIT,
        },
        "regenerate": "ZRO_VECTOR_WRITE=1 with the same command, then review the diff",
        "independent_verifier": "none: test/harness/run_vectors.py dispatches by case-id namespace and registers no verifier for these groups, so the Rust exporter is the sole origin of every value",
        "determinism": [
            "no wall clock, RNG, wallet, data directory or network is used",
            "every header is a literal field set; the only non-literal bytes are the two 32-byte hash fills",
            "JSON object keys are emitted in sorted order by serde_json",
        ],
        "files": counts,
        "total_cases": counts
            .iter()
            .map(|entry| entry["cases"].as_u64().unwrap_or(0))
            .sum::<u64>(),
        "notes": [
            "Separate from test/vectors on purpose: the P0 manifest carries one `source_commit` (7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c) that predates `Block::validate_header_identity`, so re-stamping it for these cases would rewrite every historical fixture.",
            "Only `BlockHeader::preimage` and `Block::validate_header_identity` are exercised. No decoder, no PoW engine, no Merkle tree and no chain state is involved.",
            "`chain.header_identity.*` compares against the supplied expected height. It does not decide whether a height is valid for a chain tip, and it does not read the difficulty schedule; that ordering obligation belongs to `connect_block` in P4.",
        ],
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("reference manifest serialises");
    text.push('\n');
    files.push(("manifest.json".to_string(), text));

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn p31_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p31-vectors")
}

#[test]
fn p31_vectors_match_the_committed_reference_corpus() {
    let write = std::env::var("ZRO_VECTOR_WRITE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let root = p31_root();
    let mut drift: Vec<String> = Vec::new();
    let mut written = 0usize;

    for (relative, text) in p31_corpus() {
        let path = root.join(&relative);
        if write {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("reference directory is creatable");
            }
            fs::write(&path, text.as_bytes()).expect("reference vector is writable");
            written += 1;
        } else {
            let committed = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "missing reference vector {}: {error}\nrun with ZRO_VECTOR_WRITE=1 to regenerate",
                    path.display()
                )
            });
            if committed != text {
                drift.push(relative);
            }
        }
    }

    if write {
        println!("wrote {written} reference vector files under {}", root.display());
    } else {
        assert!(
            drift.is_empty(),
            "these reference vectors differ from the committed corpus: {drift:?}\n\
             run with ZRO_VECTOR_WRITE=1 to regenerate, then review the diff"
        );
    }
}

#[test]
fn p31_reference_fixtures_are_reproducible_and_pinned() {
    let first = p31_corpus();
    let second = p31_corpus();
    assert_eq!(first, second, "two generations must be byte-identical");
    assert_eq!(first.len(), 3, "two groups plus the manifest");

    // Nonce exclusion: the same header mined with a different nonce emits the
    // same preimage bytes, because the engine appends the nonce itself.
    assert_eq!(
        header_at(1, 0).preimage(),
        header_at(1, 42).preimage(),
        "the nonce must not enter the preimage"
    );

    // Precedence: a header wrong in both fields must report the chain first.
    let both_wrong = Block {
        header: header_at(1, 0),
        transactions: Vec::new(),
    };
    assert!(
        matches!(
            both_wrong.validate_header_identity(MAINNET_CHAIN.0, 2),
            Err(BlockError::WrongChain { expected, found })
                if expected == MAINNET_CHAIN.0 && found == REGTEST_CHAIN.0
        ),
        "a header wrong in chain and height must report WrongChain"
    );

    // A top-bit u32 must survive as unsigned little-endian bytes.
    let mut top_bit = header_at(0, 0);
    top_bit.version = 0x8000_0000;
    let bytes = top_bit.preimage();
    assert_eq!(
        &bytes[P31_HEADER_TAG.len()..P31_HEADER_TAG.len() + 4],
        &0x8000_0000u32.to_le_bytes(),
        "the version field must be unsigned little-endian"
    );

    // Every published preimage is the frozen length and carries the frozen tag.
    for value in header_preimage_cases() {
        let expected = &value["expected"];
        let hex = expected["preimage_hex"].as_str().expect("preimage_hex");
        assert_eq!(hex.len(), P31_PREIMAGE_LEN * 2, "{}", value["id"]);
        assert!(hex.starts_with(&hx(P31_HEADER_TAG)), "{}", value["id"]);
        assert_eq!(
            expected["preimage_len"].as_u64(),
            Some(P31_PREIMAGE_LEN as u64),
            "{}",
            value["id"]
        );
    }
}

// ---------------------------------------------------------------------------
// Groups: chain.merkle_root (P3.2B)
//
// A different question from the five historical `chain.merkle.*` cases above.
// Those pin what the shipped P0 corpus already said and are left byte-for-byte
// unchanged. This group asks what the *current* `merkle_root` produces for every
// leaf count and leaf shape the C++ port has to survive: 0 through 9 leaves,
// repeated leaves, an all-zero leaf, an all-`0xff` leaf, high-bit first bytes, a
// leaf whose bytes *are* the empty-tree root, and an explicit ordering pair.
//
// It is a leaf-level function only. No transaction id, no header encoding, no
// block validation and no comparison against a header's claimed root.
//
// It lives in its own corpus root (`test/p32-vectors`) for the same reason the
// P3.1A groups do: the P0 manifest stamps one `source_commit` on all 117
// historical cases, so adding cases there would either re-state a commit that did
// not produce them or rewrite every historical file.
// ---------------------------------------------------------------------------

/// `block::EMPTY_MERKLE_TAG` is crate-private, so this integration test restates
/// it. `p32_reference_fixtures_are_reproducible_and_pinned` proves the restatement
/// still matches the reference: the published empty root must equal `sha256d` of
/// exactly these bytes.
const P32_EMPTY_MERKLE_TAG: &[u8] = b"ZRO/merkle:empty\0";

/// Every leaf and every internal node is one sha256d digest.
const P32_DIGEST_LEN: usize = 32;

/// The exact width of the buffer an internal node hashes: the two child digests
/// back to back, with no node tag, length prefix or separator between them.
const P32_PAIR_LEN: usize = P32_DIGEST_LEN * 2;

/// The commit whose `zerocoin/` production code produced every value in this
/// corpus: the newest commit that touches a Rust build input. `zerocoin/src` is
/// byte-identical here and at the P3.2B baseline, so no value depends on a later
/// test-only or documentation-only commit.
const P32_SOURCE_COMMIT: &str = "b71d769be8357bcf10d768d915770125cf7f7c24";

/// Where `merkle_root` and `EMPTY_MERKLE_TAG` entered `zerocoin/src`. Neither has
/// been edited since, so the values here are the values that commit produced.
const P32_MERKLE_INTRODUCED_COMMIT: &str = "e464695f92f6884e6d25c6947d452d5fb24229a6";

/// A uniform-byte leaf, in the same vocabulary the historical Merkle cases use.
fn p32_leaf(byte: u8) -> Hash256 {
    Hash256([byte; P32_DIGEST_LEN])
}

/// A leaf with a high first byte and a different last byte, so neither a signed
/// cast nor an accidental byte-order swap can hide behind a uniform value.
fn p32_edge_leaf(first: u8, last: u8) -> Hash256 {
    let mut bytes = [0u8; P32_DIGEST_LEN];
    bytes[0] = first;
    bytes[P32_DIGEST_LEN - 1] = last;
    Hash256(bytes)
}

/// One internal node as the contract describes it: two raw digests in exactly
/// `P32_PAIR_LEN` bytes. Used only to cross-check the published roots — every
/// value in the corpus itself still comes from `merkle_root`.
fn p32_internal(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut pair = [0u8; P32_PAIR_LEN];
    pair[..P32_DIGEST_LEN].copy_from_slice(&left.0);
    pair[P32_DIGEST_LEN..].copy_from_slice(&right.0);
    sha256d(&pair)
}

/// One leaf-level case: the leaves go in, the reference's own root comes out. The
/// width assertion makes the exporter fail loudly if the digest ever stops being
/// one sha256d, so a stale expectation cannot be published silently.
fn p32_case(id: &str, intent: &str, leaves: &[Hash256], independent_check: &str) -> Value {
    let root = merkle_root(leaves);
    let internal = hex::encode(root.0);
    assert_eq!(
        internal.len(),
        P32_DIGEST_LEN * 2,
        "{id}: the reference root is no longer one digest wide"
    );

    case(
        id,
        intent,
        json!({
            "leaf_count": leaves.len(),
            "leaves": leaves.iter().map(hash256_json).collect::<Vec<Value>>(),
        }),
        json!({
            "root": hash256_json(&root),
            "root_len": internal.len() / 2,
        }),
        independent_check,
    )
}

fn merkle_root_cases() -> Vec<Value> {
    let empty_root = merkle_root(&[]);
    // A run of distinct leaves, so each slice below is a different tree.
    let nine: Vec<Hash256> = (0u8..9).map(|i| p32_leaf(0xa0 + i)).collect();
    let (a, b, c) = (p32_leaf(0x11), p32_leaf(0x22), p32_leaf(0x33));
    let x = p32_leaf(0x5a);
    let zero = Hash256::ZERO;

    vec![
        // One case per leaf count the port has to handle.
        p32_case(
            "chain.merkle_root.empty",
            "rule",
            &[],
            "sha256d of the 17-byte `ZRO/merkle:empty\\0` tag, not sha256d of an empty message",
        ),
        p32_case(
            "chain.merkle_root.one_leaf",
            "rule",
            &[a],
            "a single leaf is its own root; no hash is computed and the tag never enters",
        ),
        p32_case(
            "chain.merkle_root.two_leaves",
            "rule",
            &[a, b],
            "exactly one internal node: sha256d over the 64 raw bytes a || b",
        ),
        p32_case(
            "chain.merkle_root.three_leaves",
            "rule",
            &[a, b, c],
            "the odd trailing leaf is duplicated, never promoted to the next level",
        ),
        p32_case(
            "chain.merkle_root.four_leaves",
            "rule",
            &nine[..4],
            "a full balanced tree with no duplication: 4 -> 2 -> 1",
        ),
        p32_case(
            "chain.merkle_root.five_leaves",
            "rule",
            &nine[..5],
            "two duplication rounds: 5 -> 3 -> 2 -> 1",
        ),
        p32_case(
            "chain.merkle_root.six_leaves",
            "rule",
            &nine[..6],
            "duplication at the second level only: 6 -> 3 -> 2 -> 1",
        ),
        p32_case(
            "chain.merkle_root.seven_leaves",
            "rule",
            &nine[..7],
            "duplication at the first level only: 7 -> 4 -> 2 -> 1",
        ),
        p32_case(
            "chain.merkle_root.eight_leaves",
            "rule",
            &nine[..8],
            "the power-of-two case with no duplication at any level: 8 -> 4 -> 2 -> 1",
        ),
        p32_case(
            "chain.merkle_root.nine_leaves",
            "rule",
            &nine[..9],
            "duplicate-when-odd at three successive levels: 9 -> 5 -> 3 -> 2 -> 1",
        ),
        // Repeated leaves: the function neither deduplicates nor collapses.
        p32_case(
            "chain.merkle_root.repeated_pair",
            "rule",
            &[x, x],
            "two identical leaves still hash as one pair; nothing is deduplicated",
        ),
        p32_case(
            "chain.merkle_root.repeated_triple",
            "rule",
            &[x, x, x],
            "three identical leaves are not collapsed to one: 3 -> 2 -> 1",
        ),
        // Digest byte shapes a port can get wrong.
        p32_case(
            "chain.merkle_root.high_bit_first_bytes",
            "oddity",
            &[
                p32_edge_leaf(0x80, 0x01),
                p32_edge_leaf(0xff, 0x80),
                p32_edge_leaf(0x81, 0xfe),
            ],
            "top-bit first bytes stay unsigned raw bytes in the 64-byte pair",
        ),
        p32_case(
            "chain.merkle_root.all_ff_leaf",
            "oddity",
            &[p32_leaf(0xff), p32_leaf(0x01)],
            "an all-`0xff` leaf is a digest like any other, not a sentinel",
        ),
        p32_case(
            "chain.merkle_root.zero_leaf_only",
            "oddity",
            &[zero],
            "an all-zero leaf is returned unchanged and is not confused with the empty tree",
        ),
        p32_case(
            "chain.merkle_root.zero_then_nonzero",
            "oddity",
            &[zero, p32_leaf(0x01)],
            "a zero digest is a child, not an absent child; no leading zero is stripped",
        ),
        // The empty-tree root as a value, to prove nothing special-cases it.
        p32_case(
            "chain.merkle_root.empty_root_as_single_leaf",
            "oddity",
            &[empty_root],
            "the empty-tree root used as a leaf is still just a leaf",
        ),
        p32_case(
            "chain.merkle_root.empty_root_paired",
            "oddity",
            &[empty_root, p32_leaf(0x6b)],
            "the empty-tree root gets no special case as the left child of an internal node",
        ),
        // Order, stated twice so the disagreement is visible in the file itself.
        p32_case(
            "chain.merkle_root.order_abc",
            "rule",
            &[a, b, c],
            "the same three leaves as the historical `chain.merkle.three` case",
        ),
        p32_case(
            "chain.merkle_root.order_cba",
            "rule",
            &[c, b, a],
            "the reverse of order_abc: a different root, because the tree is positional",
        ),
    ]
}

/// The P3.2B envelope: the P0 envelope plus the reference commit, so one file
/// answers "which code produced this" without consulting the manifest.
fn p32_envelope(group: &str, intent: &str, note: &str, cases: Vec<Value>) -> String {
    let doc = json!({
        "schema": "zro-baseline-vectors/1",
        "group": group,
        "intent": intent,
        "note": note,
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P32_SOURCE_COMMIT,
        "provenance": "every expected value was produced by a direct call to the shipping `zerocoin/` Rust function `consensus::block::merkle_root` at `source_commit`; no root is transcribed from another implementation, computed by hand, or typed from a document",
        "reference_commits": {
            "merkle_introduced": P32_MERKLE_INTRODUCED_COMMIT,
        },
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p32_*` functions, added by the P3.2B commit that lands immediately after the baseline; a fixture cannot truthfully record the hash of the commit that contains it, so `source_commit` names the code and this field names the exporter separately",
        "case_count": cases.len(),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("reference document serialises");
    text.push('\n');
    text
}

/// The P3.2B corpus, mirroring `p31_corpus()` above: same `add!` shape, same
/// manifest, same write-versus-compare protocol, different root.
fn p32_corpus() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();

    macro_rules! add {
        ($path:expr, $group:expr, $intent:expr, $note:expr, $cases:expr) => {{
            let cases: Vec<Value> = $cases;
            counts.push(json!({"path": $path, "group": $group, "cases": cases.len()}));
            files.push(($path.to_string(), p32_envelope($group, $intent, $note, cases)));
        }};
    }

    add!(
        "chain/merkle_root.json",
        "chain.merkle_root",
        "rule",
        "Leaf-level `merkle_root`: the 17-byte empty-tree tag, the single-leaf \
         identity, the untagged 64-byte internal node over raw internal bytes, \
         duplicate-when-odd at every level, positional leaf order, and the digest \
         byte shapes a port can get wrong.",
        merkle_root_cases()
    );

    let manifest = json!({
        "schema": "zro-baseline-vectors/1",
        "phase": "P3.2B",
        "description": "Rust reference vectors for the leaf-level Merkle root function `zerocoin::consensus::block::merkle_root`, generated for the C++ kernel's `zk::merkle_root`.",
        "provenance": "every expected value was produced by a direct call to `consensus::block::merkle_root` in the shipping `zerocoin/` Rust code at `source_commit`; no root is transcribed from another implementation, computed by hand, or typed from a document. `merkle_root` and `EMPTY_MERKLE_TAG` entered `zerocoin/src` at `reference_commits.merkle_introduced` and have not been edited since, so the roots published here are the roots that commit already produced.",
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P32_SOURCE_COMMIT,
        "source_commit_rule": "the newest commit that touches a Rust build input (`zerocoin/src`, `zerocoin/Cargo.toml`, `zerocoin/Cargo.lock`, `zerocoin/build.rs`) and therefore the production code that produced every value here; `zerocoin/src` is byte-identical between it and the baseline this corpus is committed on. Unlike the P0 corpus this is not the commit that introduced the exporter, so `generator` names the exporter separately.",
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p32_*` functions, added by the P3.2B commit that lands immediately after the baseline; no fixture can record the hash of the commit that contains it, and none here claims to have existed before this exporter did",
        "reference_commits": {
            "merkle_introduced": P32_MERKLE_INTRODUCED_COMMIT,
        },
        "regenerate": "ZRO_VECTOR_WRITE=1 with the same command, then review the diff",
        "independent_verifier": "test/harness/zro_vectors.py::merkle_root is a pre-existing dependency-free Python re-implementation of this contract, already wired to the five historical `chain.merkle.*` cases; this corpus does not wire it to these cases, so the Rust exporter remains the origin of every value published here",
        "determinism": [
            "no wall clock, RNG, wallet, data directory or network is used",
            "every leaf is a literal 32-byte array; the only derived leaf is the empty-tree root, which the reference computes from the frozen tag",
            "inputs are ordered leaf lists, so a change in leaf order changes the file",
            "JSON object keys are emitted in sorted order by serde_json",
        ],
        "contract": {
            "empty_input": "sha256d over the 17-byte `ZRO/merkle:empty\\0` tag, not sha256d of an empty message",
            "single_leaf": "the leaf is returned unchanged; no hash is computed",
            "internal_node": "sha256d(left_internal_bytes || right_internal_bytes) over exactly 64 bytes, with no node tag, prefix or separator",
            "odd_level": "the final node is duplicated at every affected level, never promoted unchanged",
            "leaf_order": "positional; the function does not sort, deduplicate, reverse or reinterpret digest bytes",
            "byte_order": "digests stay in internal byte order; `display_hex` is a separate printing-only representation and is the reverse of `internal_hex`",
            "leaf_count_limit": "none: `merkle_root` is defined on any number of leaves. `MAX_BLOCK_TRANSACTIONS` is a block rule checked outside this function",
            "leaf_width_bytes": P32_DIGEST_LEN,
            "internal_node_input_bytes": P32_PAIR_LEN,
            "empty_tree_tag_bytes": P32_EMPTY_MERKLE_TAG.len(),
            "empty_tree_tag_hex": hx(P32_EMPTY_MERKLE_TAG),
            "empty_tree_tag_hex_note": "a restatement of the crate-private tag, pinned by an assertion in `p32_reference_fixtures_are_reproducible_and_pinned` that the published empty root equals sha256d of exactly these bytes",
        },
        "files": counts,
        "total_cases": counts
            .iter()
            .map(|entry| entry["cases"].as_u64().unwrap_or(0))
            .sum::<u64>(),
        "notes": [
            "Separate from test/vectors on purpose: the P0 manifest carries one `source_commit` (7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c) for all 117 historical cases, so adding these cases there would either re-state that commit for values it did not generate or rewrite every historical file. Nothing under test/vectors was touched.",
            "Leaf-level only. `Block::compute_merkle_root` — the transaction list to root path — is deliberately not exercised here: the kernel has no block type and no transaction-id aggregation yet, so that wiring belongs to a later block/transaction integration milestone.",
            "No header is encoded, hashed or validated by any case in this corpus, and no case compares a root against a header's claimed root.",
            "`chain.merkle_root.empty_root_as_single_leaf` and `chain.merkle_root.empty_root_paired` feed the empty-tree root back in as a leaf value to prove nothing special-cases it.",
            "`chain.merkle_root.order_abc` uses the same three leaves as the historical `chain.merkle.three` case, so the two corpora can be cross-read; `order_cba` is its reverse and must disagree.",
            "These 20 cases are new with the `p32_*` exporter. `reference_commits` names the commit whose code is under test, not the commit that introduced these cases, because a fixture cannot truthfully claim to predate its own generator.",
        ],
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("reference manifest serialises");
    text.push('\n');
    files.push(("manifest.json".to_string(), text));

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn p32_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p32-vectors")
}

#[test]
fn p32_vectors_match_the_committed_reference_corpus() {
    let write = std::env::var("ZRO_VECTOR_WRITE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let root = p32_root();
    let mut drift: Vec<String> = Vec::new();
    let mut written = 0usize;

    for (relative, text) in p32_corpus() {
        let path = root.join(&relative);
        if write {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("reference directory is creatable");
            }
            fs::write(&path, text.as_bytes()).expect("reference vector is writable");
            written += 1;
        } else {
            let committed = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "missing reference vector {}: {error}\nrun with ZRO_VECTOR_WRITE=1 to regenerate",
                    path.display()
                )
            });
            if committed != text {
                drift.push(relative);
            }
        }
    }

    if write {
        println!("wrote {written} reference vector files under {}", root.display());
    } else {
        assert!(
            drift.is_empty(),
            "these reference vectors differ from the committed corpus: {drift:?}\n\
             run with ZRO_VECTOR_WRITE=1 to regenerate, then review the diff"
        );
    }
}

#[test]
fn p32_reference_fixtures_are_reproducible_and_pinned() {
    let first = p32_corpus();
    let second = p32_corpus();
    assert_eq!(first, second, "two generations must be byte-identical");
    assert_eq!(first.len(), 2, "one group plus the manifest");

    let cases = merkle_root_cases();
    assert_eq!(cases.len(), 20, "the pinned case count; p32_conformance.py pins the same number");

    // The restated crate-private tag is still the tag the reference uses, and it
    // is still the frozen 17 bytes. Both halves fail if the tag ever moves.
    assert_eq!(
        P32_EMPTY_MERKLE_TAG.len(),
        17,
        "the empty-tree tag is a frozen 17 bytes"
    );
    assert_eq!(
        merkle_root(&[]),
        sha256d(P32_EMPTY_MERKLE_TAG),
        "the restated empty-tree tag no longer matches the reference"
    );

    // count == 1: the leaf is returned unchanged, so no hash and no tag.
    let (a, b, c, d) = (p32_leaf(0x11), p32_leaf(0x22), p32_leaf(0x33), p32_leaf(0x44));
    assert_eq!(merkle_root(&[a]), a, "a single leaf must be returned unchanged");

    // count == 2: one internal node over the raw 64-byte pair.
    assert_eq!(
        merkle_root(&[a, b]),
        p32_internal(&a, &b),
        "two leaves must hash as one untagged raw pair"
    );

    // Duplicate-when-odd, expressed as an identity: appending a copy of the final
    // node cannot change the root. Bitcoin's promotion rule fails both of these.
    assert_eq!(
        merkle_root(&[a, b, c]),
        merkle_root(&[a, b, c, c]),
        "an odd final node is duplicated, not promoted"
    );
    assert_eq!(
        merkle_root(&[a, b, c, d, a]),
        merkle_root(&[a, b, c, d, a, a]),
        "the duplication rule repeats at every odd level"
    );

    // Positional order, and no deduplication.
    assert_ne!(
        merkle_root(&[a, b]),
        merkle_root(&[b, a]),
        "the tree is positional, so swapping children must change the root"
    );
    let x = p32_leaf(0x5a);
    assert_eq!(
        merkle_root(&[x, x]),
        p32_internal(&x, &x),
        "identical leaves must not be deduplicated"
    );
    assert_ne!(
        merkle_root(&[x, x, x]),
        merkle_root(&[x]),
        "three identical leaves must not collapse to one"
    );

    // Every published case: the root is exactly one digest wide, its display form
    // is the internal form reversed and nothing else, and the leaf array agrees
    // with the count the file claims.
    let published: std::collections::HashMap<String, String> = cases
        .iter()
        .map(|value| {
            let id = value["id"].as_str().expect("case id").to_string();
            let root = value["expected"]["root"]["internal_hex"]
                .as_str()
                .expect("internal_hex")
                .to_string();
            (id, root)
        })
        .collect();

    for value in &cases {
        let id = value["id"].as_str().expect("case id").to_string();
        let expected = &value["expected"];
        let internal = expected["root"]["internal_hex"]
            .as_str()
            .expect("internal_hex")
            .to_string();
        let display = expected["root"]["display_hex"]
            .as_str()
            .expect("display_hex")
            .to_string();

        assert_eq!(internal.len(), P32_DIGEST_LEN * 2, "{id}: internal_hex width");
        assert_eq!(display.len(), P32_DIGEST_LEN * 2, "{id}: display_hex width");
        assert_eq!(
            expected["root_len"].as_u64(),
            Some(P32_DIGEST_LEN as u64),
            "{id}: root_len must be the digest width"
        );

        let mut reversed = hex::decode(&internal).expect("{id}: internal_hex decodes");
        reversed.reverse();
        assert_eq!(
            display,
            hex::encode(&reversed),
            "{id}: display_hex is not the internal bytes reversed"
        );

        let leaves = value["input"]["leaves"].as_array().expect("leaves array");
        assert_eq!(
            leaves.len() as u64,
            value["input"]["leaf_count"].as_u64().expect("leaf_count"),
            "{id}: the published leaf count disagrees with the leaf array"
        );
        for leaf in leaves {
            assert_eq!(
                leaf["internal_hex"].as_str().expect("leaf internal_hex").len(),
                P32_DIGEST_LEN * 2,
                "{id}: a leaf is not one digest wide"
            );
        }
    }

    // The two ordering cases must disagree in the file itself, or the corpus
    // stopped proving positionality, and the empty case must be the tag digest.
    assert_eq!(
        published.get("chain.merkle_root.empty").expect("empty case"),
        &hx(&sha256d(P32_EMPTY_MERKLE_TAG).0),
        "the published empty root is not sha256d of the frozen tag"
    );
    assert_ne!(
        published
            .get("chain.merkle_root.order_abc")
            .expect("order_abc case"),
        published
            .get("chain.merkle_root.order_cba")
            .expect("order_cba case"),
        "reversing the published leaf order must change the published root"
    );
}

// ---------------------------------------------------------------------------
// Group: chain.merkle_root_from_txs (P3.3B)
//
// The composition half the P3.2B corpus names as a later milestone: an ordered
// transaction list in, one Merkle root out, produced by the shipping
// `Block::compute_merkle_root`. Every expected root is that function's return
// value, and every published leaf is the transaction's own `txid()` together with
// the bytes it hashed, so the txid-to-leaf mapping can be checked independently of
// the final digest — not just the root.
//
// Scope is the composition only. No case assembles a `Block` value, encodes or
// hashes a header, compares a root against a claimed one, dispatches a proof-of-work
// engine, or validates a block: `Block::compute_merkle_root` is an inherent method
// used here as the public reference path for the two lines it contains.
//
// Its own corpus root (`test/p33-vectors`) for the same reason the P3.1A and P3.2B
// groups have one: the P0 manifest stamps a single `source_commit` on all 117
// historical cases, so adding cases there would either re-state a commit that did
// not produce them or rewrite every historical file.
// ---------------------------------------------------------------------------

/// Every transaction id and every Merkle node in this corpus is one sha256d digest.
const P33_DIGEST_LEN: usize = 32;

/// `block::EMPTY_MERKLE_TAG` is crate-private, so this section restates it the way
/// the P3.2B section does. `p33_reference_fixtures_are_reproducible_and_pinned`
/// proves the restatement still matches the reference: the published empty root
/// must equal `sha256d` of exactly these bytes.
const P33_EMPTY_MERKLE_TAG: &[u8] = b"ZRO/merkle:empty\0";

/// The commit whose `zerocoin/` production code produced every value in this
/// corpus: the newest commit that touches a Rust build input. `zerocoin/src` is
/// byte-identical here and at the P3.3B baseline, so no value depends on a later
/// test-only or documentation-only commit.
const P33_SOURCE_COMMIT: &str = "b71d769be8357bcf10d768d915770125cf7f7c24";

/// Where `Block::compute_merkle_root` (`src/consensus/block.rs`) and
/// `Transaction::txid` (`src/ledger/transaction.rs`) both entered `zerocoin/src`.
/// Neither has been edited since, so the roots published here are the roots that
/// commit already produced.
const P33_REFERENCE_COMMIT: &str = "e464695f92f6884e6d25c6947d452d5fb24229a6";

/// A transaction whose every byte is a function of one seed byte, so a list of them
/// is a list of distinct serialisations that needs no lookup table. The transaction
/// analogue of the repeated-byte leaves the P3.2B corpus uses.
fn p33_tx(seed: u8) -> Transaction {
    let mut previous = [0u8; P33_DIGEST_LEN];
    for (index, byte) in previous.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint {
                txid: Hash256(previous),
                vout: seed as u32,
            },
            script_sig: vec![seed, seed.wrapping_add(1)],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOut {
            value: (seed as u64 + 1) * 1_000,
            script_pubkey: vec![0x76, 0xa9, 0x14, seed],
        }],
        lock_time: seed as u32,
    }
}

/// `count` transactions built from consecutive seeds, so a permutation of a slice
/// of this list is the same set of transactions in a different order.
fn p33_txs(count: usize, first_seed: u8) -> Vec<Transaction> {
    (0..count)
        .map(|index| p33_tx(first_seed.wrapping_add(index as u8)))
        .collect()
}

/// The coinbase the P0 `encoding.transaction` group already uses: a fixed height,
/// the published private key `1`, and the subsidy that height entitles.
fn p33_coinbase(height: u64) -> Transaction {
    coinbase_transaction(height, &scalar(1).public_key(), block_subsidy(height))
}

/// A transaction that differs from `sample_tx()` in exactly one output value byte,
/// so a root can be shown to depend on transaction *content* and not only on the
/// number or the order of the entries.
fn p33_bumped_sample() -> Transaction {
    let mut tx = sample_tx();
    tx.outputs[0].value += 1;
    tx
}

/// Publish a transaction field by field, exactly as the P0 `tx_json` closure in
/// `transaction_cases` does. That closure is local to its own function, and moving
/// it would rewrite historical exporter code for no change in output, so this
/// section restates it instead — and the pinned test below proves the restatement
/// is byte-identical to what the P0 corpus publishes for the same fixture.
fn p33_tx_json(tx: &Transaction) -> Value {
    json!({
        "version": tx.version,
        "inputs": tx
            .inputs
            .iter()
            .map(|input| json!({
                "txid_hex": hx(&input.previous_output.txid.0),
                "vout": input.previous_output.vout,
                "script_sig_hex": hx(&input.script_sig),
                "sequence": input.sequence,
            }))
            .collect::<Vec<_>>(),
        "outputs": tx
            .outputs
            .iter()
            .map(|output| json!({
                "value": output.value,
                "script_pubkey_hex": hx(&output.script_pubkey),
            }))
            .collect::<Vec<_>>(),
        "lock_time": tx.lock_time,
    })
}

/// One composition case: the ordered transactions go in, the reference's own root
/// comes out, and each leaf is published as the id the reference derived for that
/// transaction plus the exact bytes that id commits to. The width assertion makes
/// the exporter fail loudly if a digest ever stops being one sha256d wide, so a
/// stale expectation cannot be published silently.
fn p33_case(
    id: &str,
    intent: &str,
    transactions: &[Transaction],
    independent_check: &str,
) -> Value {
    let root = Block::compute_merkle_root(transactions);
    let internal = hex::encode(root.0);
    assert_eq!(
        internal.len(),
        P33_DIGEST_LEN * 2,
        "{id}: the reference root is no longer one digest wide"
    );

    let leaves: Vec<Value> = transactions
        .iter()
        .map(|tx| {
            let bytes = tx.serialize();
            json!({
                "txid": hash256_json(&tx.txid()),
                "serialized_hex": hx(&bytes),
                "serialized_len": bytes.len(),
            })
        })
        .collect();

    case(
        id,
        intent,
        json!({
            "tx_count": transactions.len(),
            "transactions": transactions.iter().map(p33_tx_json).collect::<Vec<Value>>(),
        }),
        json!({
            "leaves": leaves,
            "root": hash256_json(&root),
            "root_len": internal.len() / 2,
        }),
        independent_check,
    )
}

fn merkle_root_from_txs_cases() -> Vec<Value> {
    // The three P0 fixture transactions, in the order the encoding corpus names
    // them: a sample, a two-in/two-out payment, and the signed spend.
    let sample = sample_tx();
    let payment = payment_tx();
    let signed = signed_payment().0;
    let genesis = genesis_coinbase();
    let coinbase = p33_coinbase(147);
    let degenerate = Transaction {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
    };
    // Seeds 0x90.. are chosen so this triple never overlaps the seed ranges the
    // width cases below already occupy (0x10.. through 0x60..0x70).
    let (x, y, z) = (p33_tx(0x90), p33_tx(0x91), p33_tx(0x92));

    vec![
        // The empty list: the public reference path supports it and the pinned
        // test below proves it is the tag digest, not an assumed value.
        p33_case(
            "chain.merkle_root_from_txs.empty",
            "rule",
            &[],
            "sha256d of the 17-byte `ZRO/merkle:empty\\0` tag; no transaction is serialised or hashed",
        ),
        // One transaction per case, so the single-leaf passthrough is visible three
        // different ways: an ordinary tx, a coinbase, and the frozen genesis coinbase.
        p33_case(
            "chain.merkle_root_from_txs.single_transaction",
            "rule",
            &[sample.clone()],
            "one leaf is returned unchanged, so the root is exactly this transaction's own txid",
        ),
        p33_case(
            "chain.merkle_root_from_txs.single_coinbase",
            "rule",
            &[coinbase.clone()],
            "a coinbase is an ordinary transaction here: the root is its txid, with no block rule applied",
        ),
        p33_case(
            "chain.merkle_root_from_txs.single_genesis_coinbase",
            "rule",
            &[genesis],
            "the crate's own `genesis_coinbase()` under the single-leaf rule, i.e. the shape `GENESIS_MERKLE_ROOT` has",
        ),
        // Two, and the same two reversed: the pair is the only internal node, so the
        // two published roots must disagree.
        p33_case(
            "chain.merkle_root_from_txs.two_transactions",
            "rule",
            &[sample.clone(), payment.clone()],
            "sha256d over the 64 raw bytes of txid(sample) || txid(payment), with no tag between them",
        ),
        p33_case(
            "chain.merkle_root_from_txs.two_swapped",
            "rule",
            &[payment.clone(), sample.clone()],
            "the same two transactions in the opposite order, so the tree is positional and not a set",
        ),
        p33_case(
            "chain.merkle_root_from_txs.two_identical_transactions",
            "oddity",
            &[sample.clone(), sample.clone()],
            "a repeated transaction is two leaves, not one: the pair is txid || txid with the digest twice",
        ),
        // Three through seven, then nine and seventeen: even widths, odd widths, and
        // a list deep enough to reduce through five levels (17, 9, 5, 3, 2, 1).
        p33_case(
            "chain.merkle_root_from_txs.three_transactions",
            "rule",
            &[sample.clone(), payment.clone(), signed.clone()],
            "an odd level duplicates the final txid rather than promoting it: root([a,b,c]) == root([a,b,c,c])",
        ),
        p33_case(
            "chain.merkle_root_from_txs.four_transactions",
            "rule",
            &p33_txs(4, 0x10),
            "two pairs fold to one level and then to the root",
        ),
        p33_case(
            "chain.merkle_root_from_txs.five_transactions",
            "rule",
            &p33_txs(5, 0x20),
            "the fifth txid is duplicated at the first level and the resulting width 3 is odd again",
        ),
        p33_case(
            "chain.merkle_root_from_txs.six_transactions",
            "rule",
            &p33_txs(6, 0x30),
            "width 6 reduces to 3, which is odd, so the duplication applies on the second level too",
        ),
        p33_case(
            "chain.merkle_root_from_txs.seven_transactions",
            "rule",
            &p33_txs(7, 0x40),
            "width 7 duplicates its final node twice in a row: 7 to 4 to 2 to 1",
        ),
        p33_case(
            "chain.merkle_root_from_txs.nine_transactions",
            "rule",
            &p33_txs(9, 0x50),
            "four levels deep, the widths the P3.2B reduction arithmetic was pinned against",
        ),
        p33_case(
            "chain.merkle_root_from_txs.seventeen_transactions",
            "rule",
            &p33_txs(17, 0x60),
            "five levels: 17 to 9 to 5 to 3 to 2 to 1, odd at every level but the last",
        ),
        // The duplicate-last rule stated as an equality over transactions.
        p33_case(
            "chain.merkle_root_from_txs.odd_tail_duplicated",
            "oddity",
            &[
                sample.clone(),
                payment.clone(),
                signed.clone(),
                signed.clone(),
            ],
            "appending a copy of the final transaction cannot change the root; a Bitcoin promotion rule changes it",
        ),
        p33_case(
            "chain.merkle_root_from_txs.three_copies_of_one_transaction",
            "oddity",
            &[sample.clone(), sample.clone(), sample.clone()],
            "three identical leaves must not collapse to one, and must not equal the single-leaf root",
        ),
        p33_case(
            "chain.merkle_root_from_txs.near_identical_pair",
            "oddity",
            &[sample.clone(), p33_bumped_sample()],
            "two transactions one output-value byte apart must not share a root with two identical ones",
        ),
        p33_case(
            "chain.merkle_root_from_txs.degenerate_transaction_only",
            "oddity",
            &[degenerate],
            "a transaction with no inputs and no outputs still has an id, and one id is the whole root",
        ),
        // An explicit ordering triple over one fixed set of transactions.
        p33_case(
            "chain.merkle_root_from_txs.order_abc",
            "rule",
            &[x.clone(), y.clone(), z.clone()],
            "the same three transactions in list order a, b, c",
        ),
        p33_case(
            "chain.merkle_root_from_txs.order_cba",
            "rule",
            &[z.clone(), y.clone(), x.clone()],
            "the reverse order of `order_abc`, and it must disagree with it",
        ),
        // Block-shaped lists, without any block rule being applied here: B-9, B-12,
        // B-13 and B-14 belong to `validate_structure`, not to this composition.
        p33_case(
            "chain.merkle_root_from_txs.coinbase_then_two_spends",
            "rule",
            &[coinbase, sample.clone(), signed.clone()],
            "a coinbase followed by two spends, committed positionally; nothing checks the order is legal",
        ),
        p33_case(
            "chain.merkle_root_from_txs.three_coinbases",
            "rule",
            &[
                p33_coinbase(1),
                p33_coinbase(2),
                p33_coinbase(3),
            ],
            "a coinbase-only list of three heights, so the ids differ and the tree is not degenerate",
        ),
    ]
}

/// The P3.3B envelope: the P0 envelope plus the reference commits, so one file
/// answers "which code produced this" without consulting the manifest.
fn p33_envelope(group: &str, intent: &str, note: &str, cases: Vec<Value>) -> String {
    let doc = json!({
        "schema": "zro-baseline-vectors/1",
        "group": group,
        "intent": intent,
        "note": note,
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P33_SOURCE_COMMIT,
        "provenance": "every expected root was produced by a direct call to the shipping `zerocoin/` Rust function `consensus::block::Block::compute_merkle_root` at `source_commit`, and every expected leaf id by that transaction's own `Transaction::txid`; no root is transcribed from another implementation, computed by hand, typed from a document, or re-derived by this exporter",
        "reference_commits": {
            "compute_merkle_root_introduced": P33_REFERENCE_COMMIT,
            "txid_introduced": P33_REFERENCE_COMMIT,
        },
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p33_*` functions, added by the P3.3B commit that lands immediately after the baseline; a fixture cannot truthfully record the hash of the commit that contains it, so `source_commit` names the code and this field names the exporter separately",
        "case_count": cases.len(),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("reference document serialises");
    text.push('\n');
    text
}

/// The P3.3B corpus, mirroring `p32_corpus()` above: same `add!` shape, same
/// manifest, same write-versus-compare protocol, different root.
fn p33_corpus() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();

    macro_rules! add {
        ($path:expr, $group:expr, $intent:expr, $note:expr, $cases:expr) => {{
            let cases: Vec<Value> = $cases;
            counts.push(json!({"path": $path, "group": $group, "cases": cases.len()}));
            files.push(($path.to_string(), p33_envelope($group, $intent, $note, cases)));
        }};
    }

    add!(
        "chain/merkle_root_from_txs.json",
        "chain.merkle_root_from_txs",
        "rule",
        "Transaction-level Merkle composition: `Block::compute_merkle_root` derives each leaf as \
         that transaction's `txid()` and hands the ordered ids to `merkle_root`. Each case publishes \
         the transactions field by field, the exact bytes each id commits to, the resulting leaf \
         list and the root, in internal and display form.",
        merkle_root_from_txs_cases()
    );

    let manifest = json!({
        "schema": "zro-baseline-vectors/1",
        "phase": "P3.3B",
        "description": "Rust reference vectors for the transaction-level Merkle composition `zerocoin::consensus::block::Block::compute_merkle_root` (ordered `Transaction::txid` leaves fed to `merkle_root`), generated for the C++ kernel's `zk::merkle_root_from_transactions`.",
        "provenance": "every expected root was produced by a direct call to `consensus::block::Block::compute_merkle_root` in the shipping `zerocoin/` Rust code at `source_commit`, and every expected leaf by `Transaction::txid` on the same published transaction. `Block::compute_merkle_root` and `Transaction::txid` both entered `zerocoin/src` at `reference_commits` and have not been edited since, so the roots published here are the roots that commit already produced. Nothing in this corpus is computed by hand, transcribed from documentation, or generated by the C++ kernel.",
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P33_SOURCE_COMMIT,
        "source_commit_rule": "the newest commit that touches a Rust build input (`zerocoin/src`, `zerocoin/Cargo.toml`, `zerocoin/Cargo.lock`, `zerocoin/build.rs`) and therefore the production code that produced every value here; `zerocoin/src` is byte-identical between it and the baseline this corpus is committed on. Unlike the P0 corpus this is not the commit that introduced the exporter, so `generator` names the exporter separately.",
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p33_*` functions, added by the P3.3B commit that lands immediately after the baseline; no fixture can record the hash of the commit that contains it, and none here claims to have existed before this exporter did",
        "reference_commits": {
            "compute_merkle_root_introduced": P33_REFERENCE_COMMIT,
            "txid_introduced": P33_REFERENCE_COMMIT,
        },
        "regenerate": "ZRO_VECTOR_WRITE=1 with the same command, then review the diff",
        "independent_verifier": "test/harness/zro_vectors.py already provides `tx_from_json`, `tx_serialize`, `tx_txid` and `merkle_root`, which compose into this same rule with no new primitive; `run_vectors.py` registers no verifier for this group and this corpus does not wire it in, so the Rust exporter remains the origin of every value published here",
        "determinism": [
            "no wall clock, RNG, wallet, data directory or network is used",
            "every transaction is a literal: one of the three P0 fixture transactions, the crate's own `genesis_coinbase()`, `coinbase_transaction` at a fixed height paying the published key `1`, or a function of one seed byte",
            "the signed transaction is the same `signed_payment()` fixture the P0 corpus already publishes, whose DER signature is deterministic",
            "inputs are ordered transaction lists, so a change in transaction order or content changes the file",
            "JSON object keys are emitted in sorted order by serde_json",
        ],
        "contract": {
            "leaf_source": "the ordered `Transaction::txid()` of every transaction in the list; the composition adds nothing between the id and the leaf",
            "txid": "sha256d over the canonical re-serialisation of the published fields (C-1, C-2), never over bytes taken as already-encoded input",
            "internal_node": "sha256d(left_internal_bytes || right_internal_bytes) over exactly 64 bytes, with no node tag, prefix or separator",
            "empty_input": "an empty transaction list is supported by the public reference path and yields sha256d over the 17-byte `ZRO/merkle:empty\\0` tag, not sha256d of an empty message and not the all-zero digest",
            "single_transaction": "the only transaction id is returned unchanged: no hash is applied to a single leaf",
            "odd_level": "the final node is duplicated at every affected level, never promoted unchanged",
            "transaction_order": "positional; list order is leaf order, and nothing sorts, deduplicates, reverses or reinterprets digest bytes",
            "byte_order": "digests stay in internal byte order; `display_hex` is a separate printing-only representation and is the reverse of `internal_hex`",
            "transaction_count_limit": "none: the composition is defined on any number of transactions. `MAX_BLOCK_TRANSACTIONS` (2000) is block rule B-9, checked in `validate_structure` and deliberately not exercised or implied here",
            "claimed_root_comparison": "none: no case builds a header or compares a root against a claimed one; B-1 and B-14 stay with the Rust `validate_structure`",
            "digest_width_bytes": P33_DIGEST_LEN,
            "internal_node_input_bytes": P33_DIGEST_LEN * 2,
            "empty_tree_tag_bytes": P33_EMPTY_MERKLE_TAG.len(),
            "empty_tree_tag_hex": hx(P33_EMPTY_MERKLE_TAG),
            "empty_tree_tag_hex_note": "a restatement of the crate-private tag, pinned by an assertion in `p33_reference_fixtures_are_reproducible_and_pinned` that the published empty root equals sha256d of exactly these bytes",
        },
        "files": counts,
        "total_cases": counts
            .iter()
            .map(|entry| entry["cases"].as_u64().unwrap_or(0))
            .sum::<u64>(),
        "notes": [
            "Separate from test/vectors on purpose: the P0 manifest carries one `source_commit` (7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c) for all 117 historical cases, so adding these cases there would either re-state that commit for values it did not generate or rewrite every historical file. Nothing under test/vectors, test/p31-vectors or test/p32-vectors was touched.",
            "Composition only. The kernel has no `Block` type and this corpus gives it none: no case encodes a header, hashes one, dispatches a proof-of-work engine, compares a root against a claimed root, or validates and accepts a block. Producing a root from transactions is not a block-validation path.",
            "`chain.merkle_root_from_txs.empty` records the reference's own public behavior for an empty slice — `Block::compute_merkle_root(&[])` returns the tagged empty-tree digest, which `src/chain.rs` and the `block.rs` tests already rely on — rather than an assumed value.",
            "`odd_tail_duplicated` must agree with `three_transactions` and `three_copies_of_one_transaction` must disagree with `single_transaction`: those equalities are the transaction-level statement of the duplicate-last rule and of the absence of any deduplication.",
            "`two_swapped` against `two_transactions`, and `order_cba` against `order_abc`, are the ordering pairs; `near_identical_pair` is the content pair, one output-value byte wide.",
            "List lengths 4, 5, 6, 7, 9 and 17 are chosen for tree shape — even and odd widths at successive levels — and `seventeen_transactions` reduces 17 to 9 to 5 to 3 to 2 to 1, five levels deep. They are not a claim about any permitted block size.",
            "`coinbase_then_two_spends` and `three_coinbases` are block-shaped lists, not block validation: the coinbase-position, duplicate-coinbase and count rules (B-12, B-13, B-9) are enforced in `validate_structure` and are out of scope for this milestone.",
            "These 22 cases are new with the `p33_*` exporter. `reference_commits` names the commit whose code is under test, not the commit that introduced these cases, because a fixture cannot truthfully claim to predate its own generator.",
        ],
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("reference manifest serialises");
    text.push('\n');
    files.push(("manifest.json".to_string(), text));

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn p33_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p33-vectors")
}

#[test]
fn p33_vectors_match_the_committed_reference_corpus() {
    let write = std::env::var("ZRO_VECTOR_WRITE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let root = p33_root();
    let mut drift: Vec<String> = Vec::new();
    let mut written = 0usize;

    for (relative, text) in p33_corpus() {
        let path = root.join(&relative);
        if write {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("reference directory is creatable");
            }
            fs::write(&path, text.as_bytes()).expect("reference vector is writable");
            written += 1;
        } else {
            let committed = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "missing reference vector {}: {error}\nrun with ZRO_VECTOR_WRITE=1 to regenerate",
                    path.display()
                )
            });
            if committed != text {
                drift.push(relative);
            }
        }
    }

    if write {
        println!("wrote {written} reference vector files under {}", root.display());
    } else {
        assert!(
            drift.is_empty(),
            "these reference vectors differ from the committed corpus: {drift:?}\n\
             run with ZRO_VECTOR_WRITE=1 to regenerate, then review the diff"
        );
    }
}

#[test]
fn p33_reference_fixtures_are_reproducible_and_pinned() {
    let first = p33_corpus();
    let second = p33_corpus();
    assert_eq!(first, second, "two generations must be byte-identical");
    assert_eq!(first.len(), 2, "one group plus the manifest");

    let cases = merkle_root_from_txs_cases();
    assert_eq!(cases.len(), 22, "the pinned case count; p33_conformance.py pins the same number");

    // The restated crate-private tag is still the tag the reference uses, still 17
    // bytes, and the composition agrees with the leaf rule on the empty input.
    assert_eq!(P33_EMPTY_MERKLE_TAG.len(), 17, "the empty-tree tag is a frozen 17 bytes");
    assert_eq!(
        merkle_root(&[]),
        sha256d(P33_EMPTY_MERKLE_TAG),
        "the restated empty-tree tag no longer matches the leaf-level reference"
    );
    assert_eq!(
        Block::compute_merkle_root(&[]),
        sha256d(P33_EMPTY_MERKLE_TAG),
        "the public composition no longer maps an empty list onto the tagged empty-tree digest"
    );

    // One transaction: the root is that transaction's id, unchanged. Two: one
    // untagged internal node over the two ids as stored.
    let sample = sample_tx();
    let payment = payment_tx();
    assert_eq!(
        Block::compute_merkle_root(&[sample.clone()]),
        sample.txid(),
        "a single transaction must yield its own txid"
    );
    assert_eq!(
        Block::compute_merkle_root(&[sample.clone(), payment.clone()]),
        p32_internal(&sample.txid(), &payment.txid()),
        "two transactions must hash as one untagged raw pair of ids"
    );

    // Positional order, and no deduplication of repeated transactions.
    assert_ne!(
        Block::compute_merkle_root(&[sample.clone(), payment.clone()]),
        Block::compute_merkle_root(&[payment.clone(), sample.clone()]),
        "the tree is positional, so swapping the two transactions must change the root"
    );
    assert_eq!(
        Block::compute_merkle_root(&[sample.clone(), sample.clone()]),
        p32_internal(&sample.txid(), &sample.txid()),
        "a repeated transaction must not be deduplicated"
    );
    assert_ne!(
        Block::compute_merkle_root(&[sample.clone(), sample.clone(), sample.clone()]),
        sample.txid(),
        "three identical transactions must not collapse to one leaf"
    );

    // Duplicate-when-odd, expressed over transactions.
    let signed = signed_payment().0;
    assert_eq!(
        Block::compute_merkle_root(&[sample.clone(), payment.clone(), signed.clone()]),
        Block::compute_merkle_root(&[
            sample.clone(),
            payment.clone(),
            signed.clone(),
            signed.clone()
        ]),
        "an odd final node is duplicated, not promoted"
    );

    // Content, not only order, reaches the root: one output-value byte is enough.
    assert_ne!(
        Block::compute_merkle_root(&[sample.clone(), p33_bumped_sample()]),
        Block::compute_merkle_root(&[sample.clone(), sample.clone()]),
        "two transactions one value byte apart must not share a root with two identical ones"
    );

    // The restated transaction publisher must still agree with the P0 corpus's own
    // field-by-field form, byte for byte, or the two corpora have drifted apart.
    let p0_sample = &transaction_cases()[0];
    assert_eq!(
        p0_sample["id"].as_str(),
        Some("encoding.transaction.sample"),
        "the P0 encoding group no longer starts with the sample transaction"
    );
    assert_eq!(
        p0_sample["input"],
        p33_tx_json(&sample),
        "p33_tx_json no longer publishes exactly what the P0 corpus publishes for the same fixture"
    );

    // Every published case: the leaf list has one entry per transaction, each leaf
    // id is sha256d of the bytes the file says it hashed, those bytes decode back to
    // the fixture transaction, the display form is the internal form reversed and
    // nothing else, and the whole published input reproduces the published root.
    for value in &cases {
        let id = value["id"].as_str().expect("case id").to_string();
        let expected = &value["expected"];
        let internal = expected["root"]["internal_hex"]
            .as_str()
            .expect("internal_hex")
            .to_string();
        let display = expected["root"]["display_hex"]
            .as_str()
            .expect("display_hex")
            .to_string();

        assert_eq!(internal.len(), P33_DIGEST_LEN * 2, "{id}: internal_hex width");
        assert_eq!(display.len(), P33_DIGEST_LEN * 2, "{id}: display_hex width");
        assert_eq!(
            expected["root_len"].as_u64(),
            Some(P33_DIGEST_LEN as u64),
            "{id}: root_len must be the digest width"
        );

        let mut reversed = hex::decode(&internal).expect("internal_hex decodes");
        reversed.reverse();
        assert_eq!(
            display,
            hex::encode(&reversed),
            "{id}: display_hex is not the internal bytes reversed"
        );

        let declared = value["input"]["tx_count"].as_u64().expect("tx_count");
        let published = value["input"]["transactions"]
            .as_array()
            .expect("transactions array");
        let leaves = expected["leaves"].as_array().expect("leaves array");
        assert_eq!(published.len() as u64, declared, "{id}: the published tx_count is wrong");
        assert_eq!(leaves.len() as u64, declared, "{id}: the leaf list is not one id per transaction");

        let mut rebuilt: Vec<Transaction> = Vec::new();
        for (index, leaf) in leaves.iter().enumerate() {
            let bytes = hex::decode(
                leaf["serialized_hex"].as_str().expect("serialized_hex"),
            )
            .expect("serialized_hex decodes");
            assert_eq!(
                leaf["serialized_len"].as_u64(),
                Some(bytes.len() as u64),
                "{id}: leaf {index} publishes a length that disagrees with its own bytes"
            );
            assert_eq!(
                leaf["txid"]["internal_hex"].as_str().expect("leaf internal_hex").len(),
                P33_DIGEST_LEN * 2,
                "{id}: leaf {index} is not one digest wide"
            );

            // The id must be sha256d of exactly the published bytes: that is the
            // txid-to-leaf mapping, checked without calling the composition at all.
            let digest = sha256d(&bytes);
            assert_eq!(
                hash256_json(&digest),
                leaf["txid"].clone(),
                "{id}: leaf {index} is not sha256d of the bytes this file publishes"
            );

            let tx = Transaction::deserialize(&bytes)
                .unwrap_or_else(|error| panic!("{id}: leaf {index} does not decode: {error:?}"));
            assert_eq!(
                tx.serialize(),
                bytes,
                "{id}: leaf {index} does not re-serialize to the bytes this file publishes"
            );
            assert_eq!(
                tx,
                Transaction::deserialize(&tx.serialize()).expect("re-decode agrees"),
                "{id}: leaf {index} does not round-trip"
            );
            assert_eq!(
                p33_tx_json(&tx),
                published[index],
                "{id}: leaf {index} disagrees with the transaction published as this case's input"
            );
            rebuilt.push(tx);
        }

        assert_eq!(
            Block::compute_merkle_root(&rebuilt),
            Hash256::from_slice(&hex::decode(&internal).expect("internal hex decodes"))
                .expect("the published root is one digest"),
            "{id}: the published root does not reproduce from this case's own published input"
        );
    }

    // The pairs that exist to prove positionality and content sensitivity must
    // disagree in the file itself, or the corpus stopped proving anything.
    let published: std::collections::HashMap<String, String> = cases
        .iter()
        .map(|value| {
            let id = value["id"].as_str().expect("case id").to_string();
            let root = value["expected"]["root"]["internal_hex"]
                .as_str()
                .expect("internal_hex")
                .to_string();
            (id, root)
        })
        .collect();

    assert_eq!(
        published
            .get("chain.merkle_root_from_txs.empty")
            .expect("empty case"),
        &hx(&sha256d(P33_EMPTY_MERKLE_TAG).0),
        "the published empty root is not sha256d of the frozen tag"
    );
    assert_eq!(
        published
            .get("chain.merkle_root_from_txs.three_transactions")
            .expect("three_transactions case"),
        published
            .get("chain.merkle_root_from_txs.odd_tail_duplicated")
            .expect("odd_tail_duplicated case"),
        "duplicating the final transaction must not change the published root"
    );
    for (left, right) in [
        ("two_transactions", "two_swapped"),
        ("order_abc", "order_cba"),
        ("single_transaction", "three_copies_of_one_transaction"),
        ("two_identical_transactions", "near_identical_pair"),
    ] {
        assert_ne!(
            published
                .get(&format!("chain.merkle_root_from_txs.{left}"))
                .unwrap_or_else(|| panic!("{left}: case is missing")),
            published
                .get(&format!("chain.merkle_root_from_txs.{right}"))
                .unwrap_or_else(|| panic!("{right}: case is missing")),
            "{left} and {right} must publish different roots"
        );
    }

    // The single-transaction cases must publish their own transaction's id as the
    // root, which is the one identity a reader can check without a tree at all.
    for id in [
        "single_transaction",
        "single_coinbase",
        "single_genesis_coinbase",
        "degenerate_transaction_only",
    ] {
        let case_id = format!("chain.merkle_root_from_txs.{id}");
        let value = cases
            .iter()
            .find(|candidate| candidate["id"].as_str() == Some(case_id.as_str()))
            .unwrap_or_else(|| panic!("{case_id}: case is missing"));
        assert_eq!(
            value["expected"]["root"],
            value["expected"]["leaves"][0]["txid"],
            "{case_id}: a one-transaction root must be that transaction's own published id"
        );
    }
}

// ---------------------------------------------------------------------------
// Group: pow
// ---------------------------------------------------------------------------

fn pow_cases() -> Vec<Value> {
    let trivial = TrivialEngine::new();
    let preimage = header_at(1, 0).preimage();
    let devnet = ScratchPadEngine::new(64 * 1024, 1_024);
    let mainnet = ScratchPadEngine::new(2 * 1024 * 1024, 4_096);
    let raw = b"zerocoin-pow";

    let trivial_case = |id: &str, data: &[u8], nonce: u64| {
        case(
            id,
            "rule",
            json!({"preimage_hex": hx(data), "nonce": nonce}),
            json!({"hash": hash256_json(&trivial.hash(data, nonce))}),
            "sha256d(preimage || nonce_le64)",
        )
    };

    let scratch_case = |id: &str, engine: &ScratchPadEngine, nonce: u64| {
        case(
            id,
            "rule",
            json!({
                "preimage_hex": hx(raw),
                "nonce": nonce,
                "engine_id": engine.id(),
                "engine_name": engine.name(),
                // The cost parameters are consensus-visible: the same nonce over
                // the same preimage hashes differently at another scratchpad size.
                "memory_bytes": engine.memory_bytes,
                "rounds": engine.rounds,
            }),
            json!({"hash": hash256_json(&engine.hash(raw, nonce))}),
            "Rust-produced anchor: the C++ engine must reproduce this byte for byte",
        )
    };

    vec![
        case(
            "pow.engine_ids",
            "rule",
            json!({"engines": ["trivial", "scratchpad"]}),
            json!({
                "trivial_id": trivial.id(),
                "trivial_name": trivial.name(),
                "scratchpad_id": devnet.id(),
                "scratchpad_name": devnet.name(),
            }),
            "engine_id is committed in the header and is consensus-visible",
        ),
        trivial_case("pow.trivial.raw_nonce_0", raw, 0),
        trivial_case("pow.trivial.raw_nonce_1", raw, 1),
        trivial_case("pow.trivial.header_nonce_0", &preimage, 0),
        trivial_case("pow.trivial.header_nonce_42", &preimage, 42),
        scratch_case("pow.scratchpad.devnet_nonce_0", &devnet, 0),
        scratch_case("pow.scratchpad.devnet_nonce_1", &devnet, 1),
        scratch_case("pow.scratchpad.devnet_nonce_42", &devnet, 42),
        scratch_case("pow.scratchpad.mainnet_nonce_0", &mainnet, 0),
        scratch_case("pow.scratchpad.mainnet_nonce_1", &mainnet, 1),
        case(
            "pow.trivial.mine_from_zero",
            "rule",
            json!({"preimage_hex": hx(&preimage), "target_bits": 0x207f_ffff}),
            json!({
                "nonce": zerocoin::consensus::pow::mine(
                    &trivial,
                    &preimage,
                    &compact_to_target(0x207f_ffff),
                    0,
                )
                .expect("the trivial floor is solvable")
                .0,
            }),
            "mining searches nonces upward from the given start, deterministically",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: difficulty
// ---------------------------------------------------------------------------

fn difficulty_cases() -> Vec<Value> {
    let compact_cases: Vec<Value> = [
        0u32,
        0x0300_0001,
        0x0100_3456,
        0x1c00_ffff,
        0x1d00_ffff,
        0x1e00_ffff,
        0x207f_ffff,
        0x2100_ffff,
        0x1d80_0000,
    ]
    .iter()
    .map(|bits| {
        let target = compact_to_target(*bits);
        case(
            &format!("difficulty.compact.{bits:08x}"),
            "rule",
            json!({"bits": bits}),
            json!({
                "target_be_hex": target_json(&target),
                "roundtrip_bits": compact_from_target(&target),
                "is_zero": target.is_zero(),
            }),
            "target = mantissa * 256^(exponent-3); a set sign bit means zero",
        )
    })
    .collect();

    let validate = |bits: u32| {
        let outcome = validate_bits(bits, &DIFFICULTY_PARAMS);
        json!({
            "bits": bits,
            "ok": outcome.is_ok(),
            "error_kind": outcome.as_ref().err().map(difficulty_error),
        })
    };

    let retarget = |prev_bits: u32, seconds: u64| {
        let next = next_difficulty(prev_bits, seconds, &DIFFICULTY_PARAMS);
        json!({
            "prev_bits": prev_bits,
            "actual_window_seconds": seconds,
            "next_bits": next,
            "next_target_be_hex": target_json(&compact_to_target(next)),
        })
    };

    let boundary_target = compact_to_target(0x1d00_ffff);
    let boundary_hash = Hash256(boundary_target.to_be_bytes());

    let mut cases: Vec<Value> = vec![
        case(
            "difficulty.params",
            "rule",
            json!({"network": "all three share one schedule"}),
            json!({
                "target_spacing_seconds": DIFFICULTY_PARAMS.target_spacing_seconds,
                "retarget_interval": DIFFICULTY_PARAMS.retarget_interval,
                "max_adjustment_factor": DIFFICULTY_PARAMS.max_adjustment_factor,
                "pow_limit_bits": DIFFICULTY_PARAMS.pow_limit_bits,
                "target_window_seconds": DIFFICULTY_PARAMS.target_window_seconds(),
            }),
            "1,440 blocks x 60 s = 86,400 s = 24 h",
        ),
        case(
            "difficulty.validate_bits",
            "rule",
            json!({
                "pow_limit_bits": DIFFICULTY_PARAMS.pow_limit_bits,
                "bits": {
                    "zero": 0,
                    "above_floor": 0x2100_ffff,
                    "difficulty_one": 0x1d00_ffff,
                    "at_floor": 0x1e00_ffff,
                },
            }),
            json!({
                "zero": validate(0),
                "above_floor": validate(0x2100_ffff),
                "difficulty_one": validate(0x1d00_ffff),
                "at_floor": validate(0x1e00_ffff),
            }),
            "a block's own bits must be non-zero and no easier than the floor",
        ),
        case(
            "difficulty.hash_meets_target",
            "rule",
            json!({"bits": 0x1d00_ffff}),
            json!({
                "zero_hash": hash_meets_target(&Hash256::ZERO, &boundary_target),
                "all_ones_hash": hash_meets_target(&Hash256([0xff; 32]), &boundary_target),
                "equal_to_target": hash_meets_target(&boundary_hash, &boundary_target),
            }),
            "comparison is on the big-endian byte value and is inclusive",
        ),
        case(
            "difficulty.required_work",
            "rule",
            json!({"bits": {
                "difficulty_one": 0x1d00_ffff,
                "floor": 0x1e00_ffff,
                "trivial": 0x207f_ffff,
                "zero_target": 0,
            }}),
            json!({
                "difficulty_one": target_json(&required_work(&compact_to_target(0x1d00_ffff))),
                "floor": target_json(&required_work(&compact_to_target(0x1e00_ffff))),
                "trivial": target_json(&required_work(&compact_to_target(0x207f_ffff))),
                "zero_target": target_json(&required_work(&Uint256::ZERO)),
            }),
            "(~target) / (target + 1) + 1",
        ),
        case(
            "difficulty.retarget.clamps",
            "rule",
            json!({"prev_bits": 0x1c00_ffff}),
            json!({
                "one_second": retarget(0x1c00_ffff, 1),
                "quarter_window": retarget(0x1c00_ffff, 21_600),
                "half_window": retarget(0x1c00_ffff, 43_200),
                "on_schedule": retarget(0x1c00_ffff, 86_400),
                "double_window": retarget(0x1c00_ffff, 172_800),
                "quadruple_window": retarget(0x1c00_ffff, 345_600),
                "max_u64": retarget(0x1c00_ffff, u64::MAX),
            }),
            "actual clamped to [expected/4, expected*4]; target capped at pow_limit",
        ),
        case(
            "difficulty.retarget.at_floor",
            "rule",
            json!({"prev_bits": DIFFICULTY_PARAMS.pow_limit_bits, "actual_window_seconds": u64::MAX}),
            json!({"next_bits": next_difficulty(DIFFICULTY_PARAMS.pow_limit_bits, u64::MAX, &DIFFICULTY_PARAMS)}),
            "difficulty can never fall below the network floor",
        ),
    ];

    // The nine compact encodings ride along as top-level vectors, so every id in the
    // corpus is individually addressable and `total_cases` counts truthful cases.
    cases.extend(compact_cases);
    cases
}

// ---------------------------------------------------------------------------
// Group: reward
// ---------------------------------------------------------------------------

fn subsidy_cases() -> Vec<Value> {
    let heights = [
        0u64,
        1,
        209_999,
        210_000,
        419_999,
        420_000,
        629_999,
        630_000,
        HALVING_INTERVAL * 10,
        HALVING_INTERVAL * 63,
        HALVING_INTERVAL * 64,
        HALVING_INTERVAL * 64 + 1,
        u64::MAX,
    ];
    let table: Vec<Value> = heights
        .iter()
        .map(|height| {
            json!({
                "height": height,
                "subsidy_fah": block_subsidy(*height),
            })
        })
        .collect();

    let maturity: Vec<Value> = [0u64, 1, 99, 100, 101, u64::MAX]
        .iter()
        .map(|height| json!({"height": height, "maturity_height": maturity_height(*height)}))
        .collect();

    let split = |reward: u64, weights: &[u64]| {
        let payouts: Vec<(Hash160, u64)> = weights
            .iter()
            .enumerate()
            .map(|(index, weight)| (Hash160([(index as u8) + 1; 20]), *weight))
            .collect();
        let result = split_reward(reward, &payouts);
        json!({
            "reward": reward,
            "weights": weights,
            "payouts": result
                .iter()
                .map(|(hash, value)| json!({"hash160_hex": hx(&hash.0), "value": value}))
                .collect::<Vec<_>>(),
            "total": result.iter().map(|(_, value)| *value).sum::<u64>(),
        })
    };

    vec![
        case(
            "reward.constants",
            "rule",
            json!({"source": "consensus/reward.rs"}),
            json!({
                "fah_per_zro": FAH_PER_ZRO,
                "initial_subsidy_fah": INITIAL_SUBSIDY,
                "halving_interval": HALVING_INTERVAL,
                "max_halvings": MAX_HALVINGS,
                "max_supply_fah": MAX_SUPPLY,
                "coinbase_maturity": COINBASE_MATURITY,
                "total_supply_ceiling_fah": total_supply_ceiling(),
            }),
            "frozen economics, also pinned by compile-time asserts",
        ),
        case(
            "reward.subsidy.table",
            "rule",
            json!({"heights": heights}),
            json!({"rows": table}),
            "INITIAL_SUBSIDY >> (height / 210000), zero at height 0 and past 64 halvings",
        ),
        case(
            "reward.maturity.table",
            "rule",
            json!({"heights": [0, 1, 99, 100, 101, u64::MAX]}),
            json!({"rows": maturity}),
            "height + 100, saturating",
        ),
        case(
            "reward.block_reward",
            "rule",
            json!({"rows": [
                {"key": "height_1", "height": 1, "fees": 0},
                {"key": "height_1_with_fees", "height": 1, "fees": 1000},
                {"key": "max_height_max_fees", "height": u64::MAX, "fees": u64::MAX},
                {"key": "overflow_is_none", "height": 1, "fees": u64::MAX},
            ]}),
            json!({
                "height_1": block_reward(1, 0),
                "height_1_with_fees": block_reward(1, 1_000),
                // At height u64::MAX the subsidy has already halved to zero, so maximum
                // fees still fit: this row pins the tail of the schedule, not overflow.
                "max_height_max_fees": block_reward(u64::MAX, u64::MAX),
                // Height 1 does issue a subsidy, so this sum must overflow and be None.
                "overflow_is_none": block_reward(1, u64::MAX),
            }),
            "subsidy + fees; None when the sum overflows, encoded as JSON null",
        ),
        case(
            "reward.split_reward.remainder",
            "rule",
            json!({"cases": [[11, [1, 1]], [100, [1, 2, 3]], [1, [1, 1, 1]]]}),
            json!({
                "eleven_two_ways": split(11, &[1, 1]),
                "hundred_by_weights": split(100, &[1, 2, 3]),
                "one_three_ways": split(1, &[1, 1, 1]),
            }),
            "floor each share, credit the remainder to the first contributor",
        ),
        case(
            "reward.split_reward.edge_cases",
            "rule",
            json!({"cases": [[0, [1, 1]], [10, [0, 0]], [10, [0, 3]]]}),
            json!({
                "zero_reward": split(0, &[1, 1]),
                "zero_weights": split(10, &[0, 0]),
                "one_zero_weight": split(10, &[0, 3]),
            }),
            "zero reward or zero total weight yields no payouts; zero shares are dropped",
        ),
    ]
}

fn coinbase_cases() -> Vec<Value> {
    let key = scalar(1);
    let payout = key.public_key();
    let heights = [0u64, 1, 16, 127, 128, 255, 256, 65_535, 1_000_000, u32::MAX as u64];
    let scripts: Vec<Value> = heights
        .iter()
        .map(|height| {
            let tx = coinbase_transaction(*height, &payout, block_subsidy(*height));
            json!({
                "height": height,
                "script_sig_hex": hx(&tx.inputs[0].script_sig),
                "txid_internal_hex": hx(&tx.txid().0),
                "committed_height": coinbase_height(&tx),
            })
        })
        .collect();

    let at_147 = coinbase_transaction(147, &payout, block_subsidy(147));
    let underclaim = coinbase_transaction(147, &payout, block_subsidy(147) - 1);
    let wrong_height = coinbase_transaction(148, &payout, block_subsidy(147));
    let genesis_premine = coinbase_transaction(0, &payout, 1);
    let overclaim = coinbase_transaction(147, &payout, block_subsidy(147) + 1);
    let below_fees = coinbase_transaction(147, &payout, 0);
    // The supply check runs last, so it can only be reached by a coinbase that
    // already commits to the right height and claims no more than the subsidy.
    let at_one = coinbase_transaction(1, &payout, block_subsidy(1));
    let not_coinbase = payment_tx();

    let verdict = |tx: &Transaction, height: u64, fees: u64, issued: u64| {
        let outcome = validate_coinbase(tx, height, fees, issued);
        json!({
            "ok": outcome.is_ok(),
            "error_kind": outcome.as_ref().err().map(reward_error),
            "claimed": outcome.ok(),
        })
    };

    vec![
        case(
            "reward.coinbase.height_commitment",
            "rule",
            json!({
                "payout_scalar": 1,
                "rows": heights
                    .iter()
                    .map(|height| json!({
                        "height": height,
                        "reward_fah": block_subsidy(*height),
                    }))
                    .collect::<Vec<_>>(),
            }),
            json!({"rows": scripts}),
            "script_num(height) pushed minimally, then the \"ZeroCoin\" tag",
        ),
        case(
            "reward.coinbase.valid_at_147",
            "rule",
            json!({"height": 147, "fees": 0, "subsidy_issued": 0, "claimed": block_subsidy(147)}),
            verdict(&at_147, 147, 0, 0),
            "a coinbase claiming exactly the subsidy is accepted",
        ),
        case(
            "reward.coinbase.accepts_fees_and_underclaim",
            "rule",
            json!({
                "subsidy_issued": 0,
                "rows": [
                    {"key": "exact", "height": 147, "fees": 0, "claimed": block_subsidy(147)},
                    {"key": "underclaim", "height": 147, "fees": 0, "claimed": block_subsidy(147) - 1},
                    {"key": "with_fee_expectation", "height": 147, "fees": 250, "claimed": block_subsidy(147)},
                ],
            }),
            json!({
                "exact": verdict(&at_147, 147, 0, 0),
                "underclaim": verdict(&underclaim, 147, 0, 0),
                "with_fee_expectation": verdict(&at_147, 147, 250, 0),
            }),
            "claiming less than subsidy+fees is legal; claiming less than fees is not",
        ),
        case(
            "reward.coinbase.reject_genesis_premine",
            "rule",
            json!({"height": 0, "fees": 0, "claimed": 1}),
            verdict(&genesis_premine, 0, 0, 0),
            "frozen rule: the height-0 coinbase may claim exactly zero",
        ),
        case(
            "reward.coinbase.reject_wrong_height",
            "rule",
            json!({"block_height": 147, "committed_height": 148, "claimed": block_subsidy(147)}),
            verdict(&wrong_height, 147, 0, 0),
            "BIP-34 height commitment must match the block being validated",
        ),
        case(
            "reward.coinbase.reject_overclaim",
            "rule",
            json!({"height": 147, "claimed": block_subsidy(147) + 1}),
            verdict(&overclaim, 147, 0, 0),
            "one Fah above subsidy+fees is inflation",
        ),
        case(
            "reward.coinbase.reject_below_fees",
            "rule",
            json!({"height": 147, "fees": 1, "claimed": 0}),
            verdict(&below_fees, 147, 1, 0),
            "a coinbase must carry at least the fees it collects",
        ),
        case(
            "reward.coinbase.reject_supply_cap",
            "rule",
            json!({"height": 1, "fees": 0, "subsidy_issued": MAX_SUPPLY, "claimed": block_subsidy(1)}),
            verdict(&at_one, 1, 0, MAX_SUPPLY),
            "the running subsidy may never pass 21,000,000 ZRO",
        ),
        case(
            "reward.coinbase.reject_not_coinbase",
            "rule",
            json!({"tx_hex": hx(&not_coinbase.serialize())}),
            verdict(&not_coinbase, 147, 0, 0),
            "the first transaction of a block must spend the null outpoint",
        ),
        case(
            "reward.coinbase.pool_invariance",
            "rule",
            json!({
                "height": 147,
                "weights": [block_subsidy(147) / 2, block_subsidy(147) - block_subsidy(147) / 2],
            }),
            json!({
                "solo_total": at_147.output_value(),
                "pool_total": zerocoin::consensus::reward::pool_coinbase_transaction(
                    147,
                    block_subsidy(147),
                    &[
                        (Hash160([1u8; 20]), block_subsidy(147) / 2),
                        (Hash160([2u8; 20]), block_subsidy(147) - block_subsidy(147) / 2),
                    ],
                )
                .output_value(),
            }),
            "a pool coinbase redistributes the same total, never enlarges it",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: ledger.state_root
// ---------------------------------------------------------------------------

fn state_root_cases() -> Vec<Value> {
    let key = scalar(1);
    let other = scalar(2);
    let coinbase = coinbase_transaction(1, &key.public_key(), block_subsidy(1));
    let script_a = p2pkh_script_pubkey(&key.public_key().key_hash());
    let script_b = p2pkh_script_pubkey(&other.public_key().key_hash());

    // Sign one input of `tx` against `script_a`. Every signature here commits to the
    // transaction it actually signs, so a vector cannot go stale against its inputs.
    let sign_input = |tx: &mut Transaction, index: usize, secret: &PrivateKey| {
        let digest = signature_hash(tx, index, &script_a, REGTEST_CHAIN, SIGHASH_ALL)
            .expect("input exists");
        let signature = secret.sign(&digest).expect("signing succeeds");
        let mut with_type = signature.to_der().to_vec();
        with_type.push(SIGHASH_ALL as u8);
        tx.inputs[index].script_sig =
            p2pkh_script_sig(&with_type, &secret.public_key().to_sec1());
    };

    // 1. The empty set.
    let empty = UtxoSet::new().state_root();

    // 2. The exact two-entry layout probe from `consensus/immutability.rs`.
    let mut probe = UtxoSet::new();
    probe.insert_coinbase(
        Hash256([0x11; 32]),
        0x0201,
        TxOut {
            value: 1_234_567_890_123,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0xab, 0xcd, 0x88, 0xac],
        },
        3,
    );
    probe.insert_output(
        Hash256([0x22; 32]),
        7,
        TxOut {
            value: 1,
            script_pubkey: Vec::new(),
        },
        42,
    );

    // 3. Order independence: same three entries, opposite insertion order.
    let three = |reverse: bool| {
        let mut set = UtxoSet::new();
        let insert = |set: &mut UtxoSet, txid: u8, vout: u32, value: u64| {
            set.insert_output(
                Hash256([txid; 32]),
                vout,
                TxOut {
                    value,
                    script_pubkey: script_a.clone(),
                },
                7,
            );
        };
        if reverse {
            insert(&mut set, 0x33, 1, 3);
            insert(&mut set, 0x22, 0, 2);
            insert(&mut set, 0x11, 9, 1);
        } else {
            insert(&mut set, 0x11, 9, 1);
            insert(&mut set, 0x22, 0, 2);
            insert(&mut set, 0x33, 1, 3);
        }
        set
    };
    let forward = three(false).state_root();
    let backward = three(true).state_root();

    // 4. A funded set, then a real signed spend at the exact maturity boundary.
    let mut pre_spend = UtxoSet::new();
    let coinbase_txid = pre_spend.apply_coinbase(&coinbase, 1);
    let funded_root = pre_spend.state_root();
    let funded_balance = pre_spend.balance_of_script(&script_a);

    let mut spend = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint {
                txid: coinbase_txid,
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: block_subsidy(1) - 1_000,
            script_pubkey: script_b.clone(),
        }],
        lock_time: 0,
    };
    sign_input(&mut spend, 0, &key);

    let immature = pre_spend
        .clone()
        .apply_transaction(&spend, REGTEST_CHAIN, 101, 100)
        .expect_err("a coinbase mined at 1 is not spendable at 100");
    let mut spent = pre_spend.clone();
    let fee = spent
        .apply_transaction(&spend, REGTEST_CHAIN, 101, 101)
        .expect("mature at exactly height 101");
    let spent_root = spent.state_root();
    let spent_len = spent.len();
    let receiver_balance = spent.balance_of_script(&script_b);

    // A genuine double spend: the same outpoint twice inside one transaction, each
    // input carrying a valid signature. Phase 0 rejects it before any script work.
    let mut double_spend = Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                previous_output: Outpoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            },
            TxIn {
                previous_output: Outpoint {
                    txid: coinbase_txid,
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            },
        ],
        outputs: vec![TxOut {
            value: block_subsidy(1) - 1_000,
            script_pubkey: script_b.clone(),
        }],
        lock_time: 0,
    };
    for index in 0..double_spend.inputs.len() {
        sign_input(&mut double_spend, index, &key);
    }
    let double = pre_spend
        .clone()
        .apply_transaction(&double_spend, REGTEST_CHAIN, 101, 101)
        .expect_err("the same outpoint twice in one transaction is a double spend");
    let already_spent = spent
        .clone()
        .apply_transaction(&spend, REGTEST_CHAIN, 102, 102)
        .expect_err("the outpoint was removed by the earlier spend");

    let negative = {
        let mut set = pre_spend.clone();
        let mut greedy = spend.clone();
        greedy.outputs[0].value = block_subsidy(1) + 1;
        // The signature commits to the outputs, so it must be rebuilt before the fee
        // check can be the reason the transaction is rejected.
        sign_input(&mut greedy, 0, &key);
        set.apply_transaction(&greedy, REGTEST_CHAIN, 101, 101)
            .expect_err("outputs exceed inputs")
    };

    // 5. The four UtxoError variants the cases above do not reach. Each is pushed
    //    through `apply_transaction`, so the variant is the interpreter's own.
    let no_inputs = UtxoSet::new()
        .apply_transaction(
            &Transaction {
                version: 1,
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: 0,
            },
            REGTEST_CHAIN,
            101,
            101,
        )
        .expect_err("a transaction with no inputs is rejected before any lookup");

    let mut wrong_key = spend.clone();
    {
        let wrong_key_signature = {
            let digest = signature_hash(&wrong_key, 0, &script_a, REGTEST_CHAIN, SIGHASH_ALL)
                .expect("input exists");
            let signature = other.sign(&digest).expect("signing succeeds");
            let mut with_type = signature.to_der().to_vec();
            with_type.push(SIGHASH_ALL as u8);
            with_type
        };
        wrong_key.inputs[0].script_sig =
            p2pkh_script_sig(&wrong_key_signature, &other.public_key().to_sec1());
    }
    let script_invalid = pre_spend
        .clone()
        .apply_transaction(&wrong_key, REGTEST_CHAIN, 101, 101)
        .expect_err("a signature from another key fails the P2PKH script");

    // Two ordinary outputs of u64::MAX each: both scripts pass, then the input sum
    // overflows.
    let mut huge = UtxoSet::new();
    huge.insert_output(
        Hash256([0x77; 32]),
        0,
        TxOut {
            value: u64::MAX,
            script_pubkey: script_a.clone(),
        },
        1,
    );
    huge.insert_output(
        Hash256([0x77; 32]),
        1,
        TxOut {
            value: u64::MAX,
            script_pubkey: script_a.clone(),
        },
        1,
    );
    let mut overflow_inputs = Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                previous_output: Outpoint {
                    txid: Hash256([0x77; 32]),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            },
            TxIn {
                previous_output: Outpoint {
                    txid: Hash256([0x77; 32]),
                    vout: 1,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
            },
        ],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: script_b.clone(),
        }],
        lock_time: 0,
    };
    for index in 0..overflow_inputs.inputs.len() {
        sign_input(&mut overflow_inputs, index, &key);
    }
    let input_overflow = huge
        .apply_transaction(&overflow_inputs, REGTEST_CHAIN, 101, 101)
        .expect_err("u64::MAX + u64::MAX overflows the input sum");

    let mut overflowing_outputs = spend.clone();
    overflowing_outputs.outputs = vec![
        TxOut {
            value: u64::MAX,
            script_pubkey: Vec::new(),
        },
        TxOut {
            value: 2,
            script_pubkey: Vec::new(),
        },
    ];
    // Same reason as `negative`: the signature must cover the new outputs, otherwise
    // ScriptInvalid fires before the overflow check.
    sign_input(&mut overflowing_outputs, 0, &key);
    let output_overflow = pre_spend
        .clone()
        .apply_transaction(&overflowing_outputs, REGTEST_CHAIN, 101, 101)
        .expect_err("the output sum overflows");

    vec![
        case(
            "ledger.state_root.empty",
            "rule",
            json!({"entries": 0}),
            json!({
                "root": hash256_json(&empty),
                "pinned_anchor": hash256_json(&EMPTY_STATE_ROOT),
            }),
            "cross-check against immutability::EMPTY_STATE_ROOT",
        ),
        case(
            "ledger.state_root.layout_probe",
            "rule",
            json!({
                "entry_0": {
                    "txid_hex": hx(&[0x11u8; 32]),
                    "vout": 0x0201,
                    "value": 1_234_567_890_123u64,
                    "script_hex": "76a914abcd88ac",
                    "height": 3,
                    "is_coinbase": true,
                },
                "entry_1": {
                    "txid_hex": hx(&[0x22u8; 32]),
                    "vout": 7,
                    "value": 1,
                    "script_hex": "",
                    "height": 42,
                    "is_coinbase": false,
                },
            }),
            json!({
                "root": hash256_json(&probe.state_root()),
                "pinned_anchor": hash256_json(&STATE_ROOT_LAYOUT_PROBE),
            }),
            "cross-check against immutability::STATE_ROOT_LAYOUT_PROBE",
        ),
        case(
            "ledger.state_root.order_independence",
            "rule",
            json!({
                "entries": [
                    {"txid_hex": hx(&[0x11u8; 32]), "vout": 9, "value": 1, "script_hex": hx(&script_a), "height": 7, "is_coinbase": false},
                    {"txid_hex": hx(&[0x22u8; 32]), "vout": 0, "value": 2, "script_hex": hx(&script_a), "height": 7, "is_coinbase": false},
                    {"txid_hex": hx(&[0x33u8; 32]), "vout": 1, "value": 3, "script_hex": hx(&script_a), "height": 7, "is_coinbase": false},
                ],
                "insertion_orders": ["ascending", "descending"],
            }),
            json!({
                "ascending": hash256_json(&forward),
                "descending": hash256_json(&backward),
                "equal": forward == backward,
            }),
            "entries iterate in outpoint order (BTreeMap), so insertion order cannot leak",
        ),
        case(
            "ledger.state_root.funded_coinbase",
            "rule",
            json!({ "height": 1, "subsidy_fah": block_subsidy(1), "payout_scalar": 1 }),
            json!({
                "txid": hash256_json(&coinbase_txid),
                "root": hash256_json(&funded_root),
                "entries": 1,
                "balance_of_payout_script": funded_balance,
            }),
            "a coinbase output is inserted with is_coinbase = 1",
        ),
        case(
            "ledger.state_root.after_signed_spend",
            "rule",
            json!({
                "spend_height": 101,
                "fee_fah": 1000,
                "funded_height": 1,
                "payout_scalar": 1,
                "receiver_scalar": 2,
            }),
            json!({
                "fee": fee,
                "root": hash256_json(&spent_root),
                "entries": spent_len,
                "receiver_balance": receiver_balance,
                "payout_balance": spent.balance_of_script(&script_a),
                "txid": hash256_json(&spend.txid()),
            }),
            "spend at exactly height+100 succeeds; the set then holds one ordinary output",
        ),
        case(
            "ledger.state_root.immature_coinbase",
            "rule",
            json!({"mined_at": 1, "spend_height": 100, "matures_at": 101}),
            json!({"kind": utxo_error(&immature)}),
            "off-by-one at the maturity boundary must reject, not clamp",
        ),
        case(
            "ledger.state_root.double_spend",
            "rule",
            json!({"outpoint": "coinbase:0", "occurrences": 2}),
            json!({"kind": utxo_error(&double)}),
            "phase 0 detects the duplicate before any script work",
        ),
        case(
            "ledger.state_root.missing_input",
            "rule",
            json!({"outpoint": "coinbase:0", "spent_at": 101, "retried_at": 102}),
            json!({"kind": utxo_error(&already_spent)}),
            "a removed outpoint surfaces as MissingInput, not as a second spend",
        ),
        case(
            "ledger.state_root.negative_fee",
            "rule",
            json!({"inputs": block_subsidy(1), "outputs": block_subsidy(1) + 1}),
            json!({"kind": utxo_error(&negative)}),
            "outputs may never exceed inputs",
        ),
        case(
            "ledger.state_root.no_inputs",
            "rule",
            json!({"inputs": 0}),
            json!({"kind": utxo_error(&no_inputs)}),
            "checked before any outpoint lookup",
        ),
        case(
            "ledger.state_root.script_invalid",
            "rule",
            json!({"signer": 2, "payout_script_from": 1}),
            json!({"kind": utxo_error(&script_invalid)}),
            "a well-formed signature by the wrong key is a ScriptInvalid",
        ),
        case(
            "ledger.state_root.input_overflow",
            "rule",
            json!({"entry_values": [u64::MAX, u64::MAX]}),
            json!({"kind": utxo_error(&input_overflow)}),
            "the input sum is checked, not wrapping",
        ),
        case(
            "ledger.state_root.output_overflow",
            "rule",
            json!({"output_values": [u64::MAX, 2]}),
            json!({"kind": utxo_error(&output_overflow)}),
            "the output sum is checked before the fee comparison",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: chain.anchors
// ---------------------------------------------------------------------------

fn anchor_cases() -> Vec<Value> {
    let coinbase = genesis_coinbase();
    let merkle = merkle_root(&[coinbase.txid()]);
    let regtest = ChainParams::regtest();
    let regtest_engine = regtest.build_engine();
    let regtest_block = genesis_block(&regtest, regtest_engine.as_ref());
    let devnet = ChainParams::devnet();
    let devnet_engine = devnet.build_engine();
    let devnet_block = genesis_block(&devnet, devnet_engine.as_ref());

    let params = |params: &ChainParams| {
        json!({
            "name": params.name,
            "chain_id": params.chain_id.0,
            "engine_id": params.engine.id(),
            "engine_name": params.engine.name(),
            "genesis_bits": params.genesis_bits,
            "allow_pow_retarget": params.allow_pow_retarget,
            "base58_pubkey_prefix": params.base58_pubkey_prefix,
            "default_p2p_port": params.default_p2p_port,
            "default_rpc_port": params.default_rpc_port,
        })
    };

    vec![
        case(
            "chain.anchors.pinned_constants",
            "rule",
            json!({"source": "consensus/immutability.rs"}),
            json!({
                "genesis_coinbase_txid": hash256_json(&GENESIS_COINBASE_TXID),
                "genesis_merkle_root": hash256_json(&GENESIS_MERKLE_ROOT),
                "genesis_hash_regtest": hash256_json(&GENESIS_HASH_REGTEST),
                "genesis_hash_devnet": hash256_json(&GENESIS_HASH_DEVNET),
                "genesis_preimage_digest_mainnet": hash256_json(&GENESIS_PREIMAGE_DIGEST_MAINNET),
                "empty_state_root": hash256_json(&EMPTY_STATE_ROOT),
                "state_root_layout_probe": hash256_json(&STATE_ROOT_LAYOUT_PROBE),
            }),
            "the seven boot-time anchors; a C++ node must boot on exactly these",
        ),
        case(
            "chain.anchors.genesis_coinbase",
            "rule",
            json!({"message_utf8": String::from_utf8_lossy(GENESIS_MESSAGE)}),
            json!({
                "serialized_hex": hx(&coinbase.serialize()),
                "txid": hash256_json(&coinbase.txid()),
                "merkle_root": hash256_json(&merkle),
                "outputs": coinbase.outputs.len(),
                "output_value": coinbase.output_value(),
                "script_sig_hex": hx(&coinbase.inputs[0].script_sig),
                "committed_height": coinbase_height(&coinbase),
                "is_coinbase": coinbase.is_coinbase(),
            }),
            "block 0 mints nothing: the anti-premine rule as one empty output vector",
        ),
        case(
            "chain.anchors.regtest_genesis",
            "rule",
            params(&regtest),
            json!({
                "nonce": regtest_block.header.nonce,
                "preimage_hex": hx(&regtest_block.header.preimage()),
                "hash": hash256_json(&regtest_block.id(regtest_engine.as_ref())),
                "pinned_anchor": hash256_json(&GENESIS_HASH_REGTEST),
                "transactions": regtest_block.transactions.len(),
            }),
            "mining searches nonces upward from zero, so the nonce is reproducible",
        ),
        case(
            "chain.anchors.devnet_genesis",
            "rule",
            params(&devnet),
            json!({
                "nonce": devnet_block.header.nonce,
                "hash": hash256_json(&devnet_block.id(devnet_engine.as_ref())),
                "pinned_anchor": hash256_json(&GENESIS_HASH_DEVNET),
            }),
            "the devnet engine is scratchpad-based, so this also pins its genesis path",
        ),
        case(
            "chain.anchors.boot_invariants",
            "rule",
            json!({"call": "verify_boot_invariants()"}),
            json!({"ok": verify_boot_invariants().is_ok()}),
            "every anchor re-derived at boot; a mismatch refuses to start",
        ),
        case(
            "chain.anchors.network_params",
            "rule",
            json!({"networks": ["mainnet", "devnet", "regtest"]}),
            json!({
                "mainnet": params(&ChainParams::mainnet()),
                "devnet": params(&devnet),
                "regtest": params(&regtest),
                "genesis_timestamp": zerocoin::params::GENESIS_TIMESTAMP,
            }),
            "chain ids, ports, address prefixes and engine ids per network",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Group: crypto.addresses
// ---------------------------------------------------------------------------

fn address_cases() -> Vec<Value> {
    let key_one = scalar(1);
    let key_two = scalar(2);
    let key_nine = repeated(9);

    let describe = |key: &PrivateKey, label: &str| {
        let public = key.public_key();
        let hash = public.key_hash();
        let mainnet = Address::from_hash(0x00, hash);
        let regtest = Address::from_hash(0x6f, hash);
        json!({
            "label": label,
            "pubkey_sec1_hex": hx(&public.to_sec1()),
            "hash160_hex": hx(&hash.0),
            "address_mainnet": mainnet.encode(),
            "address_regtest": regtest.encode(),
            "roundtrip": Address::decode(&regtest.encode()).map(|a| a == regtest).unwrap_or(false),
        })
    };

    let hash_one = key_one.public_key().key_hash();
    let mainnet_one = Address::from_hash(0x00, hash_one).encode();
    let regtest_one = Address::from_hash(0x6f, hash_one).encode();
    let wrong_network = Address::decode_for_network(&mainnet_one, 0x6f)
        .expect_err("a mainnet address is not a regtest address");
    let corrupted = {
        let mut text = regtest_one.clone();
        let last = text.pop().expect("non-empty");
        text.push(if last == '1' { '2' } else { '1' });
        text
    };
    let bad_checksum = Address::decode(&corrupted).expect_err("the checksum must catch a typo");
    let bad_secret = PrivateKey::from_bytes([0u8; 32]).expect_err("zero is not a scalar");

    vec![
        case(
            "crypto.address.published_scalar_1",
            "rule",
            json!({"scalar_hex": "0000000000000000000000000000000000000000000000000000000000000001"}),
            describe(&key_one, "secp256k1 scalar 1"),
            "Bitcoin's privkey-1 vector: 0279be66... / hash160 751e76e8...",
        ),
        case(
            "crypto.address.published_scalar_2",
            "rule",
            json!({"scalar_hex": "0000000000000000000000000000000000000000000000000000000000000002"}),
            describe(&key_two, "secp256k1 scalar 2"),
            "hash160 06afd46b... is the published privkey-2 vector",
        ),
        case(
            "crypto.address.repo_key_09",
            "rule",
            json!({"scalar_hex": "0909090909090909090909090909090909090909090909090909090909090909"}),
            describe(&key_nine, "the [9u8; 32] key used by the crate's own tests"),
            "present only to mirror in-repo fixtures; no external anchor",
        ),
        case(
            "crypto.address.reject_wrong_network",
            "rule",
            json!({"address": mainnet_one, "expected_version": 0x6f}),
            json!({"kind": address_error(&wrong_network)}),
            "the version byte ties an address to one network",
        ),
        case(
            "crypto.address.reject_typo",
            "rule",
            json!({"address": regtest_one, "corrupted": corrupted}),
            json!({"kind": address_error(&bad_checksum)}),
            "a single mistyped character must fail the 4-byte checksum",
        ),
        case(
            "crypto.address.reject_zero_scalar",
            "rule",
            json!({"scalar_hex": hx(&[0u8; 32])}),
            json!({"kind": crypto_error(&bad_secret)}),
            "0 is not a valid secp256k1 scalar",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Corpus assembly, manifest, and the two tests
// ---------------------------------------------------------------------------

fn corpus() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();

    macro_rules! add {
        ($path:expr, $group:expr, $intent:expr, $note:expr, $cases:expr) => {{
            let cases: Vec<Value> = $cases;
            counts.push(json!({"path": $path, "group": $group, "cases": cases.len()}));
            files.push(($path.to_string(), envelope($group, $intent, $note, cases)));
        }};
    }

    add!(
        "hash/primitives.json",
        "hash",
        "rule",
        "SHA-256, SHA-256d, HASH160 and the display byte-order rule.",
        hash_cases()
    );
    add!(
        "encoding/varint.json",
        "encoding.varint",
        "rule",
        "Bitcoin CompactSize encoding at every width boundary.",
        varint_cases()
    );
    add!(
        "encoding/transaction.json",
        "encoding.transaction",
        "rule",
        "Canonical transaction serialization, txid derivation and minimal-varint rejection.",
        transaction_cases()
    );
    add!(
        "ledger/script.json",
        "ledger.script",
        "rule",
        "The ten-opcode interpreter, its four limits, and the accept/reject matrix.",
        script_cases()
    );
    add!(
        "ledger/sighash.json",
        "ledger.sighash",
        "rule",
        "Chain-bound signature digest, preimage bytes, and one deterministic DER signature.",
        sighash_cases()
    );
    add!(
        "ledger/state_root.json",
        "ledger.state_root",
        "rule",
        "UTXO state commitment: the empty set, the layout probe, and a funded spend.",
        state_root_cases()
    );
    add!(
        "chain/header.json",
        "chain.header",
        "rule",
        "Block-header preimage (107 bytes) and the Merkle folding rule.",
        header_cases()
    );
    add!(
        "chain/anchors.json",
        "chain.anchors",
        "rule",
        "The pinned consensus anchors, the genesis block, and per-network parameters.",
        anchor_cases()
    );
    add!(
        "pow/engines.json",
        "pow",
        "rule",
        "Trivial SHA-256d and both scratchpad profiles; the scratchpad rows are Rust anchors.",
        pow_cases()
    );
    add!(
        "difficulty/retarget.json",
        "difficulty",
        "rule",
        "Compact target encoding, the 4x clamp, the pow floor, and required work.",
        difficulty_cases()
    );
    add!(
        "reward/subsidy.json",
        "reward.subsidy",
        "rule",
        "The halving schedule, maturity, block reward and exact pool splitting.",
        subsidy_cases()
    );
    add!(
        "reward/coinbase.json",
        "reward.coinbase",
        "rule",
        "BIP-34 height commitment and every coinbase acceptance rule.",
        coinbase_cases()
    );
    add!(
        "crypto/addresses.json",
        "crypto.address",
        "rule",
        "Base58Check P2PKH addresses built from published secp256k1 test scalars.",
        address_cases()
    );

    let manifest = json!({
        "schema": "zro-baseline-vectors/1",
        "phase": "P0",
        "description": "Deterministic baseline vectors for the ZeroCoin Rust implementation.",
        "provenance": "every expected value was produced by the shipping `zerocoin/` Rust code at `source_commit`; no value is transcribed from another implementation",
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": SOURCE_COMMIT,
        "regenerate": "ZRO_VECTOR_WRITE=1 with the same command, then review the diff",
        "source_commit_rule": "newest commit touching zerocoin/src, Cargo.toml, Cargo.lock or build.rs; update it in the same commit that regenerates the corpus",
        "independent_verifier": "python test/harness/run_vectors.py",
        "determinism": [
            "no wall clock, RNG, wallet, data directory or network is used",
            "keys are the published scalars 1 and 2, plus the crate's repeated-byte [9u8; 32]",
            "block timestamps are the literals 1700000000 + height and GENESIS_TIMESTAMP",
            "ECDSA signatures are RFC 6979 deterministic",
            "JSON object keys are emitted in sorted order by serde_json",
        ],
        "files": counts,
        "total_cases": counts
            .iter()
            .map(|entry| entry["cases"].as_u64().unwrap_or(0))
            .sum::<u64>(),
        "notes": [
            "Every case except the pinned constants in chain/anchors.json and the \
             `difficulty.params`, `pow.engine_ids` and `reward.constants` cases is \
             recomputed from its inputs by test/harness/zro_vectors.py; those five \
             cannot be recomputed from an input and are reported as ANCHOR, not PASS.",
            "Private values in crypto/addresses.json are published test scalars, never wallet keys.",
        ],
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("manifest serialises");
    text.push('\n');
    files.push(("manifest.json".to_string(), text));

    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("vectors")
}

#[test]
fn baseline_vectors_match_the_committed_corpus() {
    let write = std::env::var("ZRO_VECTOR_WRITE").map(|v| v == "1").unwrap_or(false);
    let root = corpus_root();
    let mut drift: Vec<String> = Vec::new();
    let mut written = 0usize;

    for (relative, text) in corpus() {
        let path = root.join(&relative);
        if write {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("vector directory is creatable");
            }
            fs::write(&path, text.as_bytes()).expect("vector is writable");
            written += 1;
        } else {
            let committed = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "missing vector {}: {error}\nrun with ZRO_VECTOR_WRITE=1 to regenerate",
                    path.display()
                )
            });
            if committed != text {
                drift.push(relative);
            }
        }
    }

    if write {
        println!("wrote {written} vector files under {}", root.display());
    } else {
        assert!(
            drift.is_empty(),
            "these vectors differ from the committed corpus: {drift:?}\n\
             run with ZRO_VECTOR_WRITE=1 to regenerate, then review the diff"
        );
    }
}

#[test]
fn corpus_generation_is_deterministic() {
    let first = corpus();
    let second = corpus();
    assert_eq!(first, second, "two generations must be byte-identical");
    assert!(!first.is_empty(), "the corpus must not be empty");
}
