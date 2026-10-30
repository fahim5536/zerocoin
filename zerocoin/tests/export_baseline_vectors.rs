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
use zerocoin::consensus::block::{
    merkle_root, Block, BlockError, BlockHeader, BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS,
    MAX_FUTURE_SECONDS,
};
use zerocoin::consensus::difficulty::{
    compact_from_target, compact_to_target, hash_meets_target, next_difficulty, required_work,
    validate_bits, DifficultyError, DIFFICULTY_PARAMS,
};
use zerocoin::consensus::immutability::{
    verify_boot_invariants, EMPTY_STATE_ROOT, GENESIS_COINBASE_TXID, GENESIS_HASH_DEVNET,
    GENESIS_HASH_REGTEST, GENESIS_MERKLE_ROOT, GENESIS_PREIMAGE_DIGEST_MAINNET,
    STATE_ROOT_LAYOUT_PROBE,
};
use zerocoin::consensus::pow::{mine, PowEngine, ScratchPadEngine, TrivialEngine};
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

/// The numeric payload of every `BlockError` variant that carries one, read out of the
/// variant the reference actually returned. Before the P4.2A exporter this function knew
/// only the two variants the P3.1B identity cases could produce; the five added here are
/// the remaining payload-bearing variants of `Block::validate_structure`, so one mapping
/// serves both corpora. Unit variants keep publishing `null` rather than a guessed shape,
/// which is why adding these arms rewrites no already-published byte: the only variant
/// name carrying a payload anywhere in the committed corpora besides `WrongChain` and
/// `BadHeight` is `NoTransactions`, and that one is a unit variant.
fn block_error_payload(error: &BlockError) -> Value {
    match error {
        BlockError::WrongChain { expected, found } => {
            json!({"expected": expected, "found": found})
        }
        BlockError::BadHeight { expected, found } => {
            json!({"expected": expected, "found": found})
        }
        BlockError::WrongEngine { expected, found } => {
            json!({"expected": expected, "found": found})
        }
        BlockError::BadDifficulty { expected, found } => {
            json!({"expected": expected, "found": found})
        }
        BlockError::TimestampTooOld { median, found } => {
            json!({"median": median, "found": found})
        }
        BlockError::TimestampTooFarFuture { now, found } => {
            json!({"now": now, "found": found})
        }
        BlockError::TooManyTransactions(count) => json!({"count": count}),
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
// Group: chain.claimed_merkle_root (P4.1A)
//
// The comparison between the two halves P3.3B already made available separately: the
// root a block's transactions actually compute, against the root its header claims. In
// `src/consensus/block.rs` that is rule B-14 — `let root =
// Self::compute_merkle_root(&self.transactions); if h.merkle_root != root { return
// Err(BlockError::RootMismatch); }` — three lines sitting between the timestamp guards
// (B-12, B-13) and the proof-of-work check (B-15).
//
// Every verdict in this corpus is the shipping validator's own return value: `p41_case`
// calls `Block::validate_structure` and panics on any outcome but `Ok` and
// `RootMismatch`. Because B-1 .. B-13 all run *before* the comparison, an outcome of
// `Ok` or `RootMismatch` proves that none of them rejected — the chain id, height,
// previous hash, engine, bits, transaction count, coinbase position and timestamps are
// satisfied by construction, and the panic is what proves it rather than a sentence
// claiming it.
//
// B-15 runs *after* the comparison, so a rejection alone would not show that the
// header's hash was any good. Two things close that gap: every header here is mined with
// the reference's own `consensus::pow::mine` at the trivial difficulty floor, and
// `p41_case` publishes `BlockHeader::meets_own_target` alongside an invariant assertion
// — accepted if and only if the two roots match *and* the proof of work meets the
// target. The two `intent: "ordering"` cases take that further: each carries a
// deliberately failing nonce *and* a stale claimed root, and the reference still returns
// `RootMismatch`. That is the evidence that B-14 precedes B-15.
//
// The evidence matters, because mutating a transaction does not invalidate a block's
// proof of work at all: a header commits to the root it *claims*, not to the root its
// transactions happen to produce, so a transaction change leaves the preimage and the
// nonce untouched. The existing `consensus_rules.rs` test
// `merkle_mismatch_is_reported_before_proof_of_work` states in its comment that a
// mutated transaction invalidates both, and its assertion passes only because B-14 is
// reached first; the precedence it claims to demonstrate is never actually put to the
// test. This milestone records that instead of editing that test, and the two ordering
// cases below are the version of it that does prove something.
//
// Its own corpus root (`test/p41-vectors`) for the same reason the P3.1A, P3.2B and
// P3.3B groups have one: the P0 manifest stamps a single `source_commit` on all 117
// historical cases, so adding cases there would either re-state a commit that did not
// produce them or rewrite every historical file.
// ---------------------------------------------------------------------------

/// The commit whose `zerocoin/` production code produced every value in this corpus: the
/// newest commit that touches a Rust build input. `zerocoin/src` is byte-identical here
/// and at the P4.1 baseline, so no value depends on a later test-only or
/// documentation-only commit.
const P41_SOURCE_COMMIT: &str = "b71d769be8357bcf10d768d915770125cf7f7c24";

/// Where the claimed-root comparison, the `BlockError::RootMismatch` variant and
/// `Block::validate_structure` itself all entered `zerocoin/src` (`src/consensus/block.rs
///`): `git log -S` names this one commit for each of the three, and the comparison lines
/// have not been edited since, so the verdicts published here are the verdicts that
/// commit already produced.
const P41_REFERENCE_COMMIT: &str = "e464695f92f6884e6d25c6947d452d5fb24229a6";

/// The difficulty every case advertises: the trivial engine's frozen floor, the same one
/// `header_at` already uses. A 2^255 target is met by roughly half of all nonces, so
/// mining an honest proof of work costs nothing here and the corpus can still claim one.
const P41_BITS: u32 = 0x207f_ffff;

/// The width of every digest in this corpus. One root is exactly one sha256d wide, so a
/// bit flip, a reversal or a re-encoding can be described as a fact about 32 bytes instead
/// of a hope about a string.
const P41_DIGEST_LEN: usize = 32;

/// The context a case hands `validate_structure` beside the block. Both time fields are
/// literals, never a clock: zero sits below every timestamp `header_at` and `genesis_block`
/// produce, and `u64::MAX` saturates B-13's `now + 7200` so no timestamp can exceed it. The
/// two timestamp guards therefore pass for the whole corpus by construction, which is what
/// keeps a wall clock out of a consensus fixture even though B-13 reads one in production.
struct P41Context {
    expected_chain: u32,
    expected_height: u64,
    expected_previous: Hash256,
    expected_bits: u32,
    median_time_past: u64,
    now: u64,
}

impl P41Context {
    /// Names the header's own chain, height, previous hash and bits, so the four guards
    /// that read them cannot fire. This is not a way to make an illegal block legal:
    /// `p41_case` panics if *any* guard other than the comparison rejects, which is how a
    /// reader knows the construction actually held.
    fn from_header(header: &BlockHeader) -> Self {
        P41Context {
            expected_chain: header.chain,
            expected_height: header.height,
            expected_previous: header.previous_hash,
            expected_bits: header.difficulty_bits,
            median_time_past: 0,
            now: u64::MAX,
        }
    }

    fn json(&self) -> Value {
        json!({
            "expected_chain": self.expected_chain,
            "expected_height": self.expected_height,
            "expected_previous_hex": hx(&self.expected_previous.0),
            "expected_bits": self.expected_bits,
            "median_time_past": self.median_time_past,
            "now": self.now,
            "engine": "sha256d-trivial",
        })
    }
}

/// A header at `height` claiming `claimed` as its Merkle root, with a nonce searched from
/// zero by the reference's own `pow::mine`. Mining here is a fixture convenience, never a
/// consensus claim: `validate_structure` only asks whether the header's hash meets the
/// header's own target, and this is how a case obtains a hash that does.
fn p41_mined_header(height: u64, claimed: Hash256) -> BlockHeader {
    let mut header = header_at(height, 0);
    header.merkle_root = claimed;
    let engine = TrivialEngine::new();
    let target = compact_to_target(P41_BITS);
    let (nonce, _hash) = mine(&engine, &header.preimage(), &target, 0)
        .expect("the trivial difficulty floor is always solvable from nonce zero");
    header.nonce = nonce;
    header
}

/// The same, with a nonce searched to *miss* the target — deterministically, the way
/// `consensus_rules.rs` already does it, because a 2^255 target fails on roughly half of
/// all nonces. Only the two `intent: "ordering"` cases use this, and they are the corpus's
/// proof that the comparison is reached before the proof-of-work check.
fn p41_failing_nonce_header(height: u64, claimed: Hash256) -> BlockHeader {
    let mut header = header_at(height, 0);
    header.merkle_root = claimed;
    let engine = TrivialEngine::new();
    let failing = (0u64..512)
        .find(|nonce| {
            header.nonce = *nonce;
            !header.meets_own_target(&engine)
        })
        .expect("a 2^255 target yields a failing nonce within 512 tries");
    header.nonce = failing;
    header
}

/// The same digest with one bit of its internal bytes flipped, so a port that compares
/// digests byte for byte must still reject it.
fn p41_flip_bit(digest: &Hash256, index: usize, bit: u8) -> Hash256 {
    assert!(index < P41_DIGEST_LEN, "digest index out of range");
    assert!(bit < 8, "digest bit index out of range");
    let mut bytes = digest.0;
    bytes[index] ^= 1u8 << bit;
    Hash256(bytes)
}

/// The digest's internal bytes in display order: exactly what a port that re-encodes a
/// hash before comparing it would be holding, and a value the reference itself produced.
fn p41_display_order(digest: &Hash256) -> Hash256 {
    let mut bytes = digest.0;
    bytes.reverse();
    Hash256(bytes)
}

/// One published transaction: the P0 field-by-field form, plus the exact bytes the leaf
/// id commits to and whether the reference considers it a coinbase. The bytes belong in
/// the input because they are what a node receives; the derived id stays in the expected.
fn p41_tx_input(tx: &Transaction) -> Value {
    let mut value = p33_tx_json(tx);
    let bytes = tx.serialize();
    value["serialized_hex"] = json!(hx(&bytes));
    value["serialized_len"] = json!(bytes.len());
    value["is_coinbase"] = json!(tx.is_coinbase());
    value
}

/// The two digests the comparison is between, whether they are byte-identical, and the
/// verdict the caller decided to publish.
fn p41_expected(
    computed: &Hash256,
    claimed: &Hash256,
    transactions: &[Transaction],
    accepted: bool,
    error_kind: Option<&'static str>,
) -> Value {
    json!({
        "accepted": accepted,
        "error_kind": error_kind,
        "error_payload": Value::Null,
        "roots_match": computed.0 == claimed.0,
        "computed_root": hash256_json(computed),
        "claimed_root": hash256_json(claimed),
        "computed_root_len": computed.0.len(),
        "leaves": transactions
            .iter()
            .map(|tx| json!({"txid": hash256_json(&tx.txid())}))
            .collect::<Vec<Value>>(),
        "leaf_count": transactions.len(),
    })
}

fn p41_input(header: &BlockHeader, transactions: &[Transaction], context: &P41Context) -> Value {
    json!({
        "header": header_input(header),
        "tx_count": transactions.len(),
        "transactions": transactions
            .iter()
            .map(p41_tx_input)
            .collect::<Vec<Value>>(),
        "validation_context": context.json(),
    })
}

/// The one emitter every case in this group goes through. `header` decides the claimed
/// root and the nonce; `transactions` decide the computed root. An outcome other than
/// `Ok` or `RootMismatch` means the fixture failed to satisfy a guard that runs before
/// the comparison, which would make the published verdict a statement about a different
/// rule — so the exporter stops instead of publishing it.
fn p41_emit(
    id: &str,
    intent: &str,
    header: &BlockHeader,
    transactions: &[Transaction],
    independent_check: &str,
) -> Value {
    let engine = TrivialEngine::new();
    let block = Block {
        header: header.clone(),
        transactions: transactions.to_vec(),
    };
    let context = P41Context::from_header(header);
    let computed = Block::compute_merkle_root(transactions);
    let claimed = header.merkle_root;
    let roots_match = computed.0 == claimed.0;
    let proof_of_work = header.meets_own_target(&engine);

    let outcome = block.validate_structure(
        &engine,
        context.expected_chain,
        context.expected_height,
        &context.expected_previous,
        context.expected_bits,
        context.median_time_past,
        context.now,
    );
    let accepted = match &outcome {
        Ok(()) => true,
        Err(BlockError::RootMismatch) => false,
        Err(error) => panic!(
            "{id}: validate_structure returned `{}`, which is not the claimed-root comparison",
            block_error_kind(error)
        ),
    };

    // The invariant that makes a rejection mean one thing: with every earlier guard
    // proven to have passed (the panic above) and the proof of work published as an
    // explicit field, the validator can only accept when both roots match *and* the
    // header's hash meets its target.
    assert_eq!(
        accepted,
        roots_match && proof_of_work,
        "{id}: the validator's verdict no longer equals roots_match && meets_own_target"
    );

    let mut expected = p41_expected(
        &computed,
        &claimed,
        transactions,
        accepted,
        if accepted {
            None
        } else {
            Some("RootMismatch")
        },
    );
    expected["proof_of_work_meets_target"] = json!(proof_of_work);
    case(
        id,
        intent,
        p41_input(header, transactions, &context),
        expected,
        independent_check,
    )
}

/// A case whose header claims the root its own transactions compute. The validator must
/// accept it, and the accept is the reference's answer, not this exporter's guess.
fn p41_accepted_case(
    id: &str,
    height: u64,
    transactions: &[Transaction],
    independent_check: &str,
) -> Value {
    let claimed = Block::compute_merkle_root(transactions);
    p41_emit(
        id,
        "rule",
        &p41_mined_header(height, claimed),
        transactions,
        independent_check,
    )
}

/// A case whose header claims `claimed`, whatever that turns out to be: the root of a
/// different list, one flipped bit, the bytes in display order, the all-zero digest. Every
/// value here still comes from a call into the reference, so a mismatch is something the
/// port has to detect rather than a digest this file invented.
fn p41_claim_case(
    id: &str,
    height: u64,
    claimed: Hash256,
    transactions: &[Transaction],
    independent_check: &str,
) -> Value {
    p41_emit(
        id,
        "rule",
        &p41_mined_header(height, claimed),
        transactions,
        independent_check,
    )
}

/// The ordering cases: a stale claimed root *and* a nonce that misses the target, so the
/// reference has two rules it could report and reports B-14. These are the cases the
/// existing `consensus_rules.rs` precedence test never actually exercised.
fn p41_ordering_case(
    id: &str,
    height: u64,
    claimed: Hash256,
    transactions: &[Transaction],
    independent_check: &str,
) -> Value {
    p41_emit(
        id,
        "ordering",
        &p41_failing_nonce_header(height, claimed),
        transactions,
        independent_check,
    )
}

/// The two cases an empty transaction list produces, and the only two that do not go
/// through `p41_emit`. Production rejects an empty list with B-8 `NoTransactions` *before*
/// the comparison, so there is no validator verdict to publish for the comparison itself;
/// what the extracted comparison layer does accept is the empty slice, because
/// `Block::compute_merkle_root(&[])` returns the tagged empty-tree digest the P3.3B corpus
/// already publishes. These cases therefore state the comparison layer's verdict and record
/// the guard production really returned, so the exclusion is a published fact pinned by an
/// assertion below rather than a sentence in the manifest.
fn p41_boundary_case(
    id: &str,
    height: u64,
    claimed: Hash256,
    independent_check: &str,
) -> Value {
    let engine = TrivialEngine::new();
    let header = p41_mined_header(height, claimed);
    let context = P41Context::from_header(&header);
    let computed = Block::compute_merkle_root(&[]);

    let guard = Block {
        header: header.clone(),
        transactions: Vec::new(),
    }
    .validate_structure(
        &engine,
        context.expected_chain,
        context.expected_height,
        &context.expected_previous,
        context.expected_bits,
        context.median_time_past,
        context.now,
    )
    .expect_err("an empty transaction list must be rejected before the comparison is reached");
    assert_eq!(
        block_error_kind(&guard),
        "NoTransactions",
        "{id}: production no longer rejects an empty list with B-8, so the exclusion \n\
         documented in this corpus is stale and the case above must be rethought"
    );

    let roots_match = computed.0 == claimed.0;
    let mut expected = p41_expected(
        &computed,
        &claimed,
        &[],
        roots_match,
        if roots_match {
            None
        } else {
            Some("RootMismatch")
        },
    );
    expected["proof_of_work_meets_target"] = json!(header.meets_own_target(&engine));
    expected["guard_before_comparison"] = json!({
        "accepted": false,
        "error_kind": block_error_kind(&guard),
        "error_payload": block_error_payload(&guard),
        "note": "the verdict `Block::validate_structure` actually returns for this input; it \
                 belongs to B-8, which runs before B-14, so no claimed-root comparison verb in \
                 C++ or Python may be expected to reproduce it",
    });
    case(
        id,
        "boundary",
        p41_input(&header, &[], &context),
        expected,
        independent_check,
    )
}

/// The corpus. Cases are independent blocks in independent validator contexts, so heights
/// repeat: nothing here chains one case to the next, and a family of cases deliberately
/// shares one coinbase so that the pair under test differs in exactly one thing — the
/// order of the list, its length, or the content of one transaction.
fn claimed_merkle_root_cases() -> Vec<Value> {
    let degenerate = Transaction {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
    };
    let (sample, payment, signed, bumped) = (
        sample_tx(),
        payment_tx(),
        signed_payment().0,
        p33_bumped_sample(),
    );
    let (a, b, c) = (p33_tx(0x10), p33_tx(0x11), p33_tx(0x12));
    let genesis = genesis_block(&ChainParams::regtest(), &TrivialEngine::new());

    // The family every controlled pair below draws from: one coinbase, three distinct
    // spends, permuted and extended. Sharing the coinbase is what makes a swap or an
    // appended transaction the *only* difference between two published roots.
    let cb = p33_coinbase(20);
    let fam_a = vec![cb.clone(), a.clone()];
    let fam_ab = vec![cb.clone(), a.clone(), b.clone()];
    let fam_ba = vec![cb.clone(), b.clone(), a.clone()];
    let fam_aa = vec![cb.clone(), a.clone(), a.clone()];
    let fam_abc = vec![cb.clone(), a.clone(), b.clone(), c.clone()];
    let other_block = vec![p33_coinbase(60), p33_tx(0xC0), p33_tx(0xC1)];

    let mut seven = vec![p33_coinbase(6)];
    seven.extend(p33_txs(6, 0x30));
    let mut eight = vec![p33_coinbase(7)];
    eight.extend(p33_txs(7, 0x38));
    let mut seventeen = vec![p33_coinbase(12)];
    seventeen.extend(p33_txs(16, 0x40));

    let single = vec![p33_coinbase(1)];
    // The duplicated-tail pair, built from one coinbase at the height both cases use, so the
    // repeated final transaction is the only difference between the two published lists. An odd
    // leaf count duplicates its last leaf into a pair, so three leaves and those same three with
    // the last one repeated reduce to the same root — and four is the count a deduplicating port
    // would silently collapse.
    let three = vec![p33_coinbase(8), a.clone(), b.clone()];
    let odd_tails = vec![p33_coinbase(8), a.clone(), b.clone(), b.clone()];
    let spend_pair = vec![p33_coinbase(21), sample.clone()];
    let mutate_pair = vec![p33_coinbase(21), bumped.clone()];
    let pay_pair = vec![p33_coinbase(22), payment.clone()];
    let sign_pair = vec![p33_coinbase(22), signed.clone()];

    // Roots the reference itself computed, reused as *claims*. Only the all-zero digest
    // below is a value no function produced, and that is the case being made by it.
    let root = |txs: &[Transaction]| Block::compute_merkle_root(txs);
    let empty_root = root(&[]);
    let fam_ab_root = root(&fam_ab);
    let fam_abc_root = root(&fam_abc);
    let fam_a_root = root(&fam_a);
    let fam_aa_root = root(&fam_aa);
    let spend_pair_root = root(&spend_pair);
    let pay_pair_root = root(&pay_pair);
    let other_block_root = root(&other_block);
    let single_root = root(&single);
    let genesis_root = root(&genesis.transactions);

    vec![
        // ---- accepted: the header claims the root its own transactions compute ----
        p41_accepted_case(
            "chain.claimed_merkle_root.single_coinbase_block",
            1,
            &single,
            "one coinbase, so the claimed root is that transaction's own id and B-14 holds unchanged",
        ),
        p41_emit(
            "chain.claimed_merkle_root.genesis_block_accepted",
            "rule",
            &genesis.header,
            &genesis.transactions,
            "the block production assembles for regtest: `genesis_block` sets the header's root \
             with `Block::compute_merkle_root` and mines the nonce, so this is a genuinely \
             accepted block rather than one this exporter constructed",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.coinbase_then_two_spends",
            3,
            &[p33_coinbase(3), sample.clone(), payment.clone()],
            "three transactions, an odd count, with the two P0 encoding fixtures after the coinbase",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.coinbase_then_signed_spend",
            4,
            &[p33_coinbase(4), signed.clone()],
            "two transactions, so the root is one untagged node over two ids; the spend carries a \
             real DER signature so its id depends on signature bytes",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.five_transaction_block",
            5,
            &[
                p33_coinbase(5),
                p33_tx(0x20),
                p33_tx(0x21),
                p33_tx(0x22),
                p33_tx(0x23),
            ],
            "five transactions: the second level is odd as well, so the duplicate reaches a level \
             above the leaves",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.seven_transaction_block",
            6,
            &seven,
            "seven transactions reduce 7 to 4 to 2 to 1",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.eight_transaction_block",
            7,
            &eight,
            "eight transactions reduce 8 to 4 to 2 to 1, the one width in this corpus that is a \
             complete tree with no odd level at all",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.three_transaction_block",
            8,
            &three,
            "three transactions, so the third leaf is odd and gets a duplicated partner: the base \
             of the duplicate-tail case below, with the same coinbase and the first two of the \
             three spends",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.odd_tail_duplicate_accepted",
            8,
            &odd_tails,
            "four transactions whose last repeats the third: the reference duplicates rather than \
             deduplicates, so this list shares its root with the three-transaction block above and \
             both are accepted",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.repeated_transaction_block",
            9,
            &[p33_coinbase(9), a.clone(), a.clone()],
            "the same non-coinbase transaction twice: repeated leaves, never a collapsed one",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.degenerate_tail_transaction",
            10,
            &[p33_coinbase(10), degenerate.clone()],
            "a tail transaction with no inputs and no outputs still has an id and still reaches \
             the root; only position zero is required to be a coinbase",
        ),
        p41_accepted_case(
            "chain.claimed_merkle_root.seventeen_transaction_block",
            12,
            &seventeen,
            "seventeen transactions reduce 17 to 9 to 5 to 3 to 2 to 1, five levels deep",
        ),
        // ---- rejected: the header claims something other than its own root ----
        p41_claim_case(
            "chain.claimed_merkle_root.zero_claim",
            20,
            Hash256::ZERO,
            &fam_ab,
            "a header claiming the all-zero digest for a block of three transactions: the only \
             published claim that is not itself a computed root, and the case that proves the \
             comparison is a real equality rather than a null check",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.one_bit_low_byte",
            20,
            p41_flip_bit(&fam_abc_root, 31, 0),
            &fam_abc,
            "the correct root of this exact list with the final bit of the final internal byte \
             flipped: one byte differs, everything else is identical",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.one_bit_high_byte",
            20,
            p41_flip_bit(&fam_abc_root, 0, 7),
            &fam_abc,
            "the same digest with one bit flipped in the first internal byte instead, so a port \
             that compares only a prefix or a suffix of the digest cannot pass both bit cases",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.display_order_claim",
            20,
            p41_display_order(&fam_abc_root),
            &fam_abc,
            "the correct root's bytes in display order: the value a port that re-encodes a digest \
             before comparing it would be holding, and the case that keeps byte order visible",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.stale_after_extra_transaction",
            20,
            fam_ab_root,
            &fam_abc,
            "the root of the first three transactions of this very block, claimed after a fourth \
             was appended: a stale claim from a shorter version of the same list",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.stale_after_dropped_tail",
            20,
            fam_abc_root,
            &fam_ab,
            "the inverse pair: the root of four transactions claimed by the three-transaction \
             block that is its own prefix",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.stale_after_swap",
            20,
            fam_ab_root,
            &fam_ba,
            "the same coinbase and the same two spends in the opposite order, claimed under the \
             original order: the tree is positional, so the claim is stale",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.stale_after_content_mutation",
            21,
            spend_pair_root,
            &mutate_pair,
            "the coinbase of `chain.claimed_merkle_root.stale_after_...` cases above plus the P0 \
             sample transaction with one output-value byte increased: the transaction-level \
             mutation `consensus_rules.rs` performs, with the header rebuilt to claim the old root",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.repeated_claim_vs_single_transaction",
            20,
            fam_aa_root,
            &fam_a,
            "the root of two identical spends claimed by a block holding only one of them: no \
             duplication, so no match",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.single_claim_vs_repeated_transactions",
            20,
            fam_a_root,
            &fam_aa,
            "the inverse pair: the root of one spend claimed by a block that repeats it, so a port \
             that deduplicates leaves would call this a match and be wrong",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.same_count_different_content",
            22,
            pay_pair_root,
            &sign_pair,
            "two transactions in both lists and the same coinbase, but the second is a signed \
             spend rather than the unsigned payment: equal length tells the comparison nothing",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.root_from_another_block",
            20,
            other_block_root,
            &fam_ab,
            "a root computed from an entirely different transaction list, at a height no case here \
             uses for its own header: a copied claim",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.empty_tree_claim_by_nonempty_block",
            20,
            empty_root,
            &fam_ab,
            "the tagged empty-list digest claimed by a block of three transactions, so the two \
             halves of B-14 are both reference values and the case is a genuine mismatch",
        ),
        p41_claim_case(
            "chain.claimed_merkle_root.genesis_root_claim_by_later_block",
            23,
            genesis_root,
            &[p33_coinbase(23), sample.clone()],
            "the root the production genesis block claims, claimed instead by a block whose own \
             transactions are a different coinbase and the P0 sample",
        ),
        // ---- ordering: the comparison fires even when the proof of work would also fail ----
        p41_ordering_case(
            "chain.claimed_merkle_root.stale_root_with_failing_proof_of_work",
            25,
            fam_ab_root,
            &fam_abc,
            "a stale claim and a nonce searched to miss the header's own target: B-14 and B-15 \
             both apply, and the reference reports RootMismatch, which is the precedence the \
             existing consensus_rules comment only assumes",
        ),
        p41_ordering_case(
            "chain.claimed_merkle_root.zero_claim_with_failing_proof_of_work",
            26,
            Hash256::ZERO,
            &fam_ab,
            "the same with the all-zero claim, so the ordering holds for two different ways the \
             roots can disagree",
        ),
        // ---- boundary: the empty list, which production rejects before the comparison ----
        p41_boundary_case(
            "chain.claimed_merkle_root.empty_list_matching_claim",
            50,
            empty_root,
            "the comparison layer alone, on the input only it can take: an empty list against the \
             tagged digest it computes. Production returns B-8 NoTransactions for this block, \
             published beside the verdict as `guard_before_comparison`",
        ),
        p41_boundary_case(
            "chain.claimed_merkle_root.empty_list_mismatching_claim",
            51,
            single_root,
            "an empty list against the root of a one-transaction block: the comparison layer's \
             own rejection, with the same B-8 guard published beside it",
        ),
    ]
}

/// The P4.1A envelope: the P0 envelope plus the reference commits, so one file answers
/// "which code produced this verdict" without consulting the manifest.
fn p41_envelope(group: &str, intent: &str, note: &str, cases: Vec<Value>) -> String {
    let doc = json!({
        "schema": "zro-baseline-vectors/1",
        "group": group,
        "intent": intent,
        "note": note,
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P41_SOURCE_COMMIT,
        "provenance": "every verdict was produced by a direct call to the shipping `zerocoin/` \
Rust function `consensus::block::Block::validate_structure` at `source_commit`, which is \
where rule B-14 lives; every computed root by `Block::compute_merkle_root` on that call's \
own transaction list, every leaf id by `Transaction::txid`, and every header nonce by \
`consensus::pow::mine`. No claim, root or verdict here is taken from another implementation, \
computed by hand, or re-derived by this exporter",
        "reference_commits": {
            "claimed_root_comparison_introduced": P41_REFERENCE_COMMIT,
            "validate_structure_introduced": P41_REFERENCE_COMMIT,
            "compute_merkle_root_introduced": P41_REFERENCE_COMMIT,
        },
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p41_*` functions, added by the \
P4.1A commit that lands immediately after the baseline; a fixture cannot truthfully record the \
hash of the commit that contains it, so `source_commit` names the code and this field names \
the exporter separately",
        "case_count": cases.len(),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("reference document serialises");
    text.push('\n');
    text
}

/// The P4.1A corpus, mirroring `p33_corpus()` above: same `add!` shape, same manifest, same
/// write-versus-compare protocol, different root.
fn p41_corpus() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();

    macro_rules! add {
        ($path:expr, $group:expr, $intent:expr, $note:expr, $cases:expr) => {{
            let cases: Vec<Value> = $cases;
            counts.push(json!({"path": $path, "group": $group, "cases": cases.len()}));
            files.push(($path.to_string(), p41_envelope($group, $intent, $note, cases)));
        }};
    }

    add!(
        "chain/claimed_merkle_root.json",
        "chain.claimed_merkle_root",
        "rule",
        "The claimed-root comparison (B-14): the root a block's transactions compute against the \
root its header claims, with the verdict `Block::validate_structure` itself returned. Each case \
publishes the header, the exact serialized transactions, the validator context, both digests in \
internal and display form, the leaf ids, and whether the header's proof of work meets its own \
target.",
        claimed_merkle_root_cases()
    );

    let manifest = json!({
        "schema": "zro-baseline-vectors/1",
        "phase": "P4.1A",
        "description": "Rust reference vectors for the claimed-Merkle-root comparison in \
`zerocoin::consensus::block::Block::validate_structure` (rule B-14, the `RootMismatch` verdict), \
generated for the C++ kernel's `zk::compare_claimed_merkle_root`.",
        "provenance": "every verdict was produced by a direct call to \
`consensus::block::Block::validate_structure` in the shipping `zerocoin/` Rust code at \
`source_commit`; every computed root by `Block::compute_merkle_root`; every leaf id by \
`Transaction::txid`; every nonce by `consensus::pow::mine`. `git log -S` names \
`reference_commits.claimed_root_comparison_introduced` for the comparison, the `RootMismatch` \
variant and `validate_structure` alike, and none of the three has been edited since, so the \
verdicts published here are the verdicts that commit already produced. Nothing here is computed \
by the C++ kernel, transcribed from documentation, or typed by hand.",
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P41_SOURCE_COMMIT,
        "source_commit_rule": "the newest commit that touches a Rust build input (`zerocoin/src`, \
`zerocoin/Cargo.toml`, `zerocoin/Cargo.lock`, `zerocoin/build.rs`) and therefore the production \
code that produced every value here; `zerocoin/src` is byte-identical between it and the baseline \
this corpus is committed on. Unlike the P0 corpus this is not the commit that introduced the \
exporter, so `generator` names the exporter separately.",
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p41_*` functions, added by the \
P4.1A commit that lands immediately after the baseline; no fixture can record the hash of the \
commit that contains it, and none here claims to have existed before this exporter did",
        "reference_commits": {
            "claimed_root_comparison_introduced": P41_REFERENCE_COMMIT,
            "validate_structure_introduced": P41_REFERENCE_COMMIT,
            "compute_merkle_root_introduced": P41_REFERENCE_COMMIT,
        },
        "regenerate": "ZRO_VECTOR_WRITE=1 with the same command, then review the diff",
        "independent_verifier": "test/harness/zro_vectors.py already provides `tx_from_json`, \
`tx_serialize`, `tx_txid` and `merkle_root`, which compose the root a case claims against; the \
comparison itself is one byte-for-byte equality over two published digests, so it needs no new \
primitive. `run_vectors.py` registers no verifier for this group and this corpus does not wire it \
in, so the Rust exporter remains the origin of every value published here",
        "determinism": [
            "no wall clock, RNG, wallet, data directory or network is used: `median_time_past` is \
the literal 0 and `now`, which B-13 reads from a node clock in production, is the literal \
u64::MAX, where `now + 7200` saturates",
            "every header nonce comes from `consensus::pow::mine` searching upward from zero, or \
from the same deterministic failing-nonce search `consensus_rules.rs` uses, so a nonce is a \
function of the header alone and never of a thread count or a clock",
            "every transaction is a literal: the crate's own `genesis_coinbase()` inside \
`genesis_block`, `coinbase_transaction` at a fixed height paying the published key 1, one of the \
three P0 fixture transactions, or a function of one seed byte",
            "every claimed root is either a root the reference computed for some list or one \
bit, or one byte reversal, away from the root it computed for this list; the only published claim \
that is not a computed digest at all is the all-zero digest, and `chain.claimed_merkle_root.zero_claim` \
is named for exactly that",
            "JSON object keys are emitted in sorted order by serde_json",
        ],
        "contract": {
            "comparison_site": "rule B-14 in `Block::validate_structure` \
(`src/consensus/block.rs`): compute the root from the block's own transactions and compare it \
with the header's `merkle_root`. A port implements this equality and the `RootMismatch` outcome, \
nothing else",
            "verdict": "the validator's own `Result`. `Ok(())` publishes `accepted` true with \
`error_kind` null; `Err(BlockError::RootMismatch)` publishes `accepted` false with `error_kind` \
`RootMismatch` and `error_payload` null, because that variant carries no data",
            "guard_order": "B-1 through B-13 run before B-14 and B-15 runs after it. Every \
`rule` and `ordering` case is either `Ok` or `RootMismatch` — the exporter panics on any other \
variant — which is what proves the earlier guards passed rather than asserting it in prose. The \
`ordering` cases carry a nonce that misses the header's own target, so B-14 is shown to be \
reached before B-15 instead of assumed.",
            "invariant": "accepted == (roots_match && proof_of_work_meets_target) for every case. \
`p41_reference_fixtures_are_reproducible_and_pinned` checks it from the published fields alone, \
so a reader can use it as a consistency test of its own",
            "byte_order": "the two digests compare in internal byte order. `display_hex` is a \
printing-only reversal of `internal_hex` and is never what the comparison sees; \
`chain.claimed_merkle_root.display_order_claim` is the case that rejects a port which re-encodes \
before comparing",
            "empty_input": "excluded from the validator verdict, not from the corpus. B-8 \
`NoTransactions` rejects an empty transaction list before B-14, so `validate_structure` has no \
comparison verdict to publish for it. The two `boundary` cases instead publish the extracted \
comparison layer's own verdict on the empty slice — which the reference does support, returning \
the tagged empty-tree digest the P3.3B corpus documents — beside the B-8 guard production \
actually returned. The exporter asserts that guard's name, so the exclusion is a fact about \
`source_commit` rather than a claim in this file.",
            "transaction_count_limit": "none: the comparison is defined on any list length. \
`MAX_BLOCK_TRANSACTIONS` (2000) is B-9, checked in `validate_structure` before B-14, and is \
deliberately not exercised or implied here",
            "coinbase_position": "B-10 and B-11 are not part of the comparison. Every case puts \
the coinbase at position zero and nowhere else so that the comparison is reached; \
`is_coinbase` is published per transaction as the evidence, and the `degenerate_tail_transaction` \
case shows a tail transaction with no inputs and no outputs is legal at the comparison",
            "proof_of_work": "`proof_of_work_meets_target` is \
`BlockHeader::meets_own_target` for the published header, at the trivial difficulty floor \
`0x207fffff`. It is published, not assumed: the accepted cases have it true, the two ordering \
cases have it false and are still `RootMismatch`",
            "scope": "the comparison only. This corpus gives the kernel no `Block` type, no chain, \
no `connect_block`, no acceptance path and no UTXO effect. It publishes the two digests, the \
verdict between them, and the validator context needed to reach that verdict honestly",
            "digest_width_bytes": P41_DIGEST_LEN,
            "header_preimage_len_bytes": P31_PREIMAGE_LEN,
        },
        "files": counts,
        "total_cases": counts
            .iter()
            .map(|entry| entry["cases"].as_u64().unwrap_or(0))
            .sum::<u64>(),
        "notes": [
            "Separate from test/vectors on purpose: the P0 manifest carries one `source_commit` \
(7cb9017c21e01df30b70b63c8ef3aa8dcbd35b6c) for all 117 historical cases, so adding these cases \
there would either re-state that commit for values it did not generate or rewrite every \
historical file. Nothing under test/vectors, test/p31-vectors, test/p32-vectors or \
test/p33-vectors was touched.",
            "30 cases: 26 `rule`, 2 `ordering`, 2 `boundary`. By verdict, 13 accepted and 17 \
rejected, and every one of the 17 rejections is the `RootMismatch` variant — no other block error \
appears in this file.",
            "Transaction lists are independent blocks, not a chain, so heights repeat. The \
controlled pairs deliberately share one coinbase so that the order of the list, its length, or \
the content of one transaction is the only difference between the two published roots.",
            "`three_transaction_block` and `odd_tail_duplicate_accepted` must publish the same \
computed root while being different transaction lists: that identity is the block-level statement \
of the duplicate-odd-tail rule and it fails a port that deduplicates or promotes the final leaf. \
`repeated_claim_vs_single_transaction` and `single_claim_vs_repeated_transactions` are its two \
directions, both rejected.",
            "`stale_after_extra_transaction` against `stale_after_dropped_tail`, and \
`stale_after_swap`, are the length-and-order pair; `stale_after_content_mutation` and \
`same_count_different_content` are the content pair, one output-value byte and one whole \
signature apart. `one_bit_low_byte` and `one_bit_high_byte` are one bit apart at opposite ends of \
the digest.",
            "Recorded, not fixed: `zerocoin/tests/consensus_rules.rs::\
merkle_mismatch_is_reported_before_proof_of_work` states in its comment that mutating a \
transaction invalidates both the Merkle root and the proof of work, because the root is in the \
preimage. That is not true of the transactions a node receives — a header commits to the root it \
claims, so changing the block's transactions leaves the header, its preimage and its nonce \
untouched. The test's assertion passes because B-14 is reached, not because both rules fire, and \
the precedence it cites is therefore untested. The two `ordering` cases here carry a stale claim \
*and* a failing nonce, which is the same experiment with the second condition actually present. \
`docs/consensus/CONSENSUS_RULES.md` states the same assumption in its B-14 boundary note.",
            "The header's `version` is published and never validated (F-2), so no case here \
depends on it; `BLOCK_VERSION` is written by `header_at` and read by nothing in the path under \
test.",
            "These 30 cases are new with the `p41_*` exporter. `reference_commits` names the \
commit whose code is under test, not the commit that introduced these cases, because a fixture \
cannot truthfully claim to predate its own generator.",
        ],
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("reference manifest serialises");
    text.push('\n');
    files.push(("manifest.json".to_string(), text));

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn p41_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p41-vectors")
}

#[test]
fn p41_vectors_match_the_committed_reference_corpus() {
    let write = std::env::var("ZRO_VECTOR_WRITE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let root = p41_root();
    let mut drift: Vec<String> = Vec::new();
    let mut written = 0usize;

    for (relative, text) in p41_corpus() {
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

/// The P4.1A half of the determinism gate, and the corpus's own consistency test. Every
/// assertion below reads only what the cases publish — the emitters are not consulted — and
/// rebuilds each case's header, transactions and validator context from those published fields
/// to confirm that the reference still returns the verdict written beside them. The invariant
/// the manifest contract promises, `accepted == roots_match && proof_of_work_meets_target`, is
/// recomputed here from published fields alone, so a reader outside this file can use it as a
/// check of its own — which is exactly what `p41_conformance.py` will do with the committed
/// JSON instead of with these in-memory values.
#[test]
fn p41_reference_fixtures_are_reproducible_and_pinned() {
    let first = p41_corpus();
    let second = p41_corpus();
    assert_eq!(first, second, "two generations must be byte-identical");
    assert_eq!(first.len(), 2, "one group plus the manifest");

    let cases = claimed_merkle_root_cases();
    assert_eq!(
        cases.len(),
        30,
        "the pinned case count; p41_conformance.py pins the same number"
    );

    let prefix = "chain.claimed_merkle_root.";
    let engine = TrivialEngine::new();
    let raw_digest = |text: &str| -> Hash256 {
        Hash256::from_slice(&hex::decode(text).expect("published hex decodes"))
            .expect("a published digest is one sha256d wide")
    };
    let internal = |value: &Value| -> String {
        value["internal_hex"]
            .as_str()
            .expect("a published digest carries internal_hex")
            .to_string()
    };
    let digest = |value: &Value| -> Hash256 { raw_digest(&internal(value)) };
    let header_from = |value: &Value| -> BlockHeader {
        BlockHeader {
            version: value["version"].as_u64().expect("header version") as u32,
            chain: value["chain"].as_u64().expect("header chain") as u32,
            height: value["height"].as_u64().expect("header height"),
            previous_hash: raw_digest(
                value["previous_hash_hex"]
                    .as_str()
                    .expect("previous_hash_hex"),
            ),
            merkle_root: raw_digest(
                value["merkle_root_hex"]
                    .as_str()
                    .expect("merkle_root_hex"),
            ),
            timestamp: value["timestamp"].as_u64().expect("header timestamp"),
            difficulty_bits: value["difficulty_bits"].as_u64().expect("difficulty_bits") as u32,
            engine_id: value["engine_id"].as_u64().expect("engine_id") as u8,
            nonce: value["nonce"].as_u64().expect("header nonce"),
        }
    };
    let case_by_id = |name: &str| -> Value {
        let id = format!("{prefix}{name}");
        cases
            .iter()
            .find(|candidate| candidate["id"].as_str() == Some(id.as_str()))
            .cloned()
            .unwrap_or_else(|| panic!("{id}: case is missing"))
    };
    let bit_diff = |left: &Value, right: &Value| -> u32 {
        let left = hex::decode(internal(left)).expect("left internal_hex decodes");
        let right = hex::decode(internal(right)).expect("right internal_hex decodes");
        let mut differing = 0u32;
        for (l, r) in left.iter().zip(right.iter()) {
            differing += (l ^ r).count_ones();
        }
        differing
    };

    // The published mix must be the mix the manifest note claims, or the manifest describes a
    // corpus that no longer exists.
    let (mut rule, mut ordering, mut boundary) = (0usize, 0usize, 0usize);
    let (mut accepted_count, mut rejected_count) = (0usize, 0usize);
    for value in &cases {
        match value["intent"].as_str().expect("intent") {
            "rule" => rule += 1,
            "ordering" => ordering += 1,
            "boundary" => boundary += 1,
            other => panic!(
                "{}: intent `{other}` is not one of rule, ordering, boundary",
                value["id"]
            ),
        }
        if value["expected"]["accepted"].as_bool().expect("accepted") {
            accepted_count += 1
        } else {
            rejected_count += 1
        }
    }
    assert_eq!(
        (rule, ordering, boundary),
        (26, 2, 2),
        "the published intent mix is no longer what the manifest note claims"
    );
    assert_eq!(
        (accepted_count, rejected_count),
        (13, 17),
        "the published verdict mix is no longer what the manifest note claims"
    );

    // The digest width is a fact about the reference, not about this file: a root that stopped
    // being one sha256d wide would make every bit and byte claim below meaningless.
    assert_eq!(P41_DIGEST_LEN, 32, "a sha256d digest is 32 bytes");

    for value in &cases {
        let id = value["id"].as_str().expect("case id").to_string();
        assert!(
            id.strip_prefix(prefix).is_some(),
            "{id}: case id outside the group namespace"
        );
        let intent = value["intent"].as_str().expect("intent").to_string();
        let input = &value["input"];
        let expected = &value["expected"];

        // ---- the two digests: width, and the printing-only relation between the two forms ----
        for key in ["computed_root", "claimed_root"] {
            let published = &expected[key];
            assert_eq!(
                published.as_object().expect("digest object").len(),
                2,
                "{id}: {key} publishes more than the two byte orders"
            );
            let both = ["internal_hex", "display_hex"];
            for field in both {
                assert_eq!(
                    published[field].as_str().expect(field).len(),
                    P41_DIGEST_LEN * 2,
                    "{id}: {key}.{field} is not one digest of hex"
                );
            }
            let mut reversed =
                hex::decode(internal(published)).expect("internal_hex decodes");
            reversed.reverse();
            assert_eq!(
                published["display_hex"].as_str().expect("display_hex"),
                hex::encode(&reversed),
                "{id}: {key}.display_hex is not the internal bytes reversed"
            );
        }
        assert_eq!(
            expected["computed_root_len"].as_u64(),
            Some(P41_DIGEST_LEN as u64),
            "{id}: computed_root_len must be the digest width"
        );
        assert_eq!(
            input["header"]["merkle_root_hex"].as_str().expect("header merkle_root_hex"),
            internal(&expected["claimed_root"]),
            "{id}: the header field and the claimed root disagree in internal order"
        );

        // ---- the validator context: the frozen literals that keep a clock out of B-12/B-13 ----
        let context = &input["validation_context"];
        assert_eq!(
            context["expected_chain"].as_u64(),
            input["header"]["chain"].as_u64(),
            "{id}: the context must name the chain the header names, or an earlier guard fires"
        );
        assert_eq!(
            context["expected_height"].as_u64(),
            input["header"]["height"].as_u64(),
            "{id}: the context must expect the height the header carries"
        );
        assert_eq!(
            context["expected_previous_hex"].as_str().expect("expected_previous_hex"),
            input["header"]["previous_hash_hex"]
                .as_str()
                .expect("header previous_hash_hex"),
            "{id}: B-5 needs the context to repeat the header's own previous hash"
        );
        assert_eq!(
            context["median_time_past"].as_u64(),
            Some(0),
            "{id}: the frozen median time past"
        );
        assert_eq!(
            context["now"].as_u64(),
            Some(u64::MAX),
            "{id}: the frozen `now`, where `now + 7200` saturates"
        );
        assert_eq!(
            context["engine"].as_str(),
            Some("sha256d-trivial"),
            "{id}: the corpus is mined with the trivial engine and must say so"
        );
        assert_eq!(
            input["header"]["difficulty_bits"].as_u64(),
            Some(P41_BITS as u64),
            "{id}: every case advertises the frozen trivial difficulty floor"
        );
        assert_eq!(
            context["expected_bits"].as_u64(),
            Some(P41_BITS as u64),
            "{id}: B-7 needs the context to expect the bits the header advertises"
        );
        assert_eq!(
            input["header"]["engine_id"].as_u64(),
            Some(0),
            "{id}: ENGINE_ID_TRIVIAL is zero"
        );

        // ---- transactions and leaves: the published bytes are what the ids commit to ----
        let declared = input["tx_count"].as_u64().expect("tx_count");
        let published_txs = input["transactions"].as_array().expect("transactions array");
        let leaves = expected["leaves"].as_array().expect("leaves array");
        assert_eq!(
            published_txs.len() as u64,
            declared,
            "{id}: the published tx_count is wrong"
        );
        assert_eq!(
            expected["leaf_count"].as_u64(),
            Some(declared),
            "{id}: the leaf count is not the transaction count"
        );
        assert_eq!(
            leaves.len() as u64,
            declared,
            "{id}: the leaf list is not one id per transaction"
        );
        assert_eq!(
            (declared == 0) as usize,
            (intent == "boundary") as usize,
            "{id}: only the two boundary cases may carry an empty transaction list"
        );

        let mut rebuilt: Vec<Transaction> = Vec::new();
        for (index, leaf) in leaves.iter().enumerate() {
            assert_eq!(
                leaf.as_object().expect("leaf object").len(),
                1,
                "{id}: leaf {index} publishes more than its txid"
            );
            let entry = &published_txs[index];
            let bytes = hex::decode(
                entry["serialized_hex"]
                    .as_str()
                    .expect("serialized_hex"),
            )
            .expect("serialized_hex decodes");
            assert_eq!(
                entry["serialized_len"].as_u64(),
                Some(bytes.len() as u64),
                "{id}: transaction {index} publishes a length that disagrees with its own bytes"
            );

            let digest_of_bytes = sha256d(&bytes);
            assert_eq!(
                hash256_json(&digest_of_bytes),
                leaf["txid"].clone(),
                "{id}: leaf {index} is not sha256d of the bytes this file publishes"
            );

            let tx = Transaction::deserialize(&bytes)
                .unwrap_or_else(|error| panic!("{id}: transaction {index} does not decode: {error:?}"));
            assert_eq!(
                tx.serialize(),
                bytes,
                "{id}: transaction {index} does not re-serialize to the bytes this file publishes"
            );
            assert_eq!(
                tx.txid(),
                digest_of_bytes,
                "{id}: transaction {index} does not have the id published for its bytes"
            );
            // Only position zero is a coinbase anywhere in this corpus — the evidence that the
            // cases reach the comparison instead of tripping B-10 or B-11 on the way.
            assert_eq!(
                entry["is_coinbase"].as_bool(),
                Some(index == 0),
                "{id}: transaction {index} disagrees about coinbase status"
            );
            assert_eq!(
                tx.is_coinbase(),
                index == 0,
                "{id}: the published coinbase flag is not what the reference returns"
            );

            let mut restated = entry.clone();
            let object = restated.as_object_mut().expect("transaction object");
            for key in ["serialized_hex", "serialized_len", "is_coinbase"] {
                assert!(
                    object.remove(key).is_some(),
                    "{id}: transaction {index} does not publish {key}"
                );
            }
            assert_eq!(
                restated,
                p33_tx_json(&tx),
                "{id}: transaction {index} disagrees with the P0 field-by-field form for the same bytes"
            );
            rebuilt.push(tx);
        }

        // ---- reproduce the reference verdict from the published input alone ----
        let header = header_from(&input["header"]);
        assert_eq!(
            header.preimage().len(),
            P31_PREIMAGE_LEN,
            "{id}: the header preimage is no longer the frozen length"
        );
        let proof_of_work = header.meets_own_target(&engine);
        assert_eq!(
            expected["proof_of_work_meets_target"].as_bool(),
            Some(proof_of_work),
            "{id}: proof_of_work_meets_target does not reproduce from the published header"
        );

        let computed = Block::compute_merkle_root(&rebuilt);
        assert_eq!(
            computed,
            digest(&expected["computed_root"]),
            "{id}: the published computed root does not reproduce from this case's own published transactions"
        );
        assert_eq!(
            header.merkle_root,
            digest(&expected["claimed_root"]),
            "{id}: the published claimed root is not the header's merkle_root"
        );
        assert_eq!(
            expected["roots_match"].as_bool(),
            Some(computed == header.merkle_root),
            "{id}: roots_match does not agree with the two digests published beside it"
        );
        assert_eq!(
            expected["accepted"].as_bool(),
            Some(computed == header.merkle_root && proof_of_work),
            "{id}: accepted is not roots_match && proof_of_work_meets_target, the invariant the corpus contract promises"
        );
        if expected["accepted"].as_bool().expect("accepted") {
            assert_eq!(
                expected["claimed_root"], expected["computed_root"],
                "{id}: an accepted case must claim the root it computes"
            );
        } else {
            assert_ne!(
                expected["claimed_root"], expected["computed_root"],
                "{id}: a rejected case must claim something other than the root it computes"
            );
        }

        let outcome = Block {
            header,
            transactions: rebuilt,
        }
        .validate_structure(
            &engine,
            context["expected_chain"].as_u64().expect("expected_chain") as u32,
            context["expected_height"].as_u64().expect("expected_height"),
            &raw_digest(
                context["expected_previous_hex"]
                    .as_str()
                    .expect("expected_previous_hex"),
            ),
            context["expected_bits"].as_u64().expect("expected_bits") as u32,
            context["median_time_past"].as_u64().expect("median_time_past"),
            context["now"].as_u64().expect("now"),
        );

        if intent == "boundary" {
            // The published verdict belongs to the extracted comparison layer; production stops
            // at B-8 first, and that guard is published beside it as a fact, not a footnote.
            let Err(guard) = outcome else {
                panic!("{id}: production no longer rejects an empty list before the comparison")
            };
            let published_guard = &expected["guard_before_comparison"];
            assert_eq!(
                block_error_kind(&guard),
                published_guard["error_kind"].as_str().expect("guard error_kind"),
                "{id}: the published guard is not the error production returned"
            );
            assert_eq!(
                block_error_payload(&guard),
                published_guard["error_payload"].clone(),
                "{id}: the published guard payload is not the reference's"
            );
            assert_eq!(
                published_guard["accepted"].as_bool(),
                Some(false),
                "{id}: B-8 rejects, so the published guard cannot claim an accept"
            );
            assert_eq!(
                block_error_kind(&guard),
                "NoTransactions",
                "{id}: B-8 is no longer the guard that precedes the comparison"
            );
        } else {
            match outcome {
                Ok(()) => {
                    assert_eq!(
                        expected["accepted"].as_bool(),
                        Some(true),
                        "{id}: the reference accepted but the file says rejected"
                    );
                    assert!(
                        expected["error_kind"].is_null(),
                        "{id}: an accepted case must publish a null error_kind"
                    );
                    assert!(
                        expected["error_payload"].is_null(),
                        "{id}: an accepted case must publish a null error_payload"
                    );
                    assert!(
                        expected["guard_before_comparison"].is_null(),
                        "{id}: only a boundary case publishes a guard"
                    );
                }
                Err(error) => {
                    assert_eq!(
                        expected["accepted"].as_bool(),
                        Some(false),
                        "{id}: the reference rejected but the file says accepted"
                    );
                    assert_eq!(
                        expected["error_kind"].as_str(),
                        Some(block_error_kind(&error)),
                        "{id}: the published error kind is not the reference's variant"
                    );
                    assert_eq!(
                        block_error_kind(&error),
                        "RootMismatch",
                        "{id}: a case about a rule other than the comparison is in this corpus"
                    );
                    assert!(
                        expected["error_payload"].is_null(),
                        "{id}: RootMismatch carries no payload"
                    );
                }
            }
        }
    }

    // ---- the duplicate-odd-tail pair: the accepted identity a deduplicating port fails ----
    let base = case_by_id("three_transaction_block");
    let odd_tail = case_by_id("odd_tail_duplicate_accepted");
    assert_eq!(
        base["input"]["tx_count"].as_u64(),
        Some(3),
        "three_transaction_block must be three wide"
    );
    assert_eq!(
        odd_tail["input"]["tx_count"].as_u64(),
        Some(4),
        "odd_tail_duplicate_accepted must be four wide"
    );
    assert_eq!(
        base["expected"]["computed_root"], odd_tail["expected"]["computed_root"],
        "duplicating the odd final leaf must not change the root, so the three- and \
         four-transaction blocks must publish the same one"
    );
    assert_eq!(
        base["expected"]["claimed_root"], odd_tail["expected"]["claimed_root"],
        "both halves of the duplicate-tail pair are accepted, so each claims that shared root"
    );
    assert_eq!(
        odd_tail["input"]["transactions"][3], odd_tail["input"]["transactions"][2],
        "the fourth transaction must be a repeat of the third"
    );
    let base_txs = base["input"]["transactions"]
        .as_array()
        .expect("three-transaction list");
    let odd_txs = odd_tail["input"]["transactions"]
        .as_array()
        .expect("four-transaction list");
    assert_eq!(
        &base_txs[..],
        &odd_txs[..3],
        "the three-transaction list must be the four-transaction list without its duplicated tail"
    );

    // ---- the stale-claim pair: the same two roots published in opposite directions ----
    let grew = case_by_id("stale_after_extra_transaction");
    let shrank = case_by_id("stale_after_dropped_tail");
    assert_eq!(
        grew["expected"]["claimed_root"], shrank["expected"]["computed_root"],
        "the three-transaction root claimed by the four-transaction block must be that \
         shorter block's own computed root"
    );
    assert_eq!(
        shrank["expected"]["claimed_root"], grew["expected"]["computed_root"],
        "the four-transaction root claimed by the three-transaction block must be that \
         longer block's own computed root"
    );
    let grew_txs = grew["input"]["transactions"]
        .as_array()
        .expect("appended list");
    let shrank_txs = shrank["input"]["transactions"]
        .as_array()
        .expect("prefix list");
    assert_eq!(
        &grew_txs[..3],
        &shrank_txs[..],
        "the longer list must be the shorter one with one transaction appended"
    );

    // Position is the only difference the swap pair is allowed to have.
    let swapped = case_by_id("stale_after_swap");
    assert_eq!(
        swapped["expected"]["claimed_root"], grew["expected"]["claimed_root"],
        "stale_after_swap claims the same three-transaction root"
    );
    assert_ne!(
        swapped["expected"]["computed_root"], grew["expected"]["computed_root"],
        "yet its own list is the permuted one, so the two computed roots must differ"
    );
    assert_eq!(
        swapped["input"]["transactions"][0], grew["input"]["transactions"][0],
        "the swap keeps the coinbase in place"
    );
    assert_eq!(
        swapped["input"]["transactions"][1], grew["input"]["transactions"][2],
        "the swap exchanges the two spends"
    );

    // ---- the one-bit and byte-order claims ----
    for (name, index) in [("one_bit_low_byte", 31usize), ("one_bit_high_byte", 0usize)] {
        let value = case_by_id(name);
        assert_eq!(
            bit_diff(&value["expected"]["claimed_root"], &value["expected"]["computed_root"]),
            1,
            "{prefix}{name}: the claim must be exactly one bit away from the computed root"
        );
        let mut expected_bytes =
            hex::decode(internal(&value["expected"]["computed_root"])).expect("decodes");
        expected_bytes[index] ^= 1u8 << if index == 31 { 0 } else { 7 };
        assert_eq!(
            internal(&value["expected"]["claimed_root"]),
            hex::encode(&expected_bytes),
            "{prefix}{name}: the flipped bit is not the one this case is named for"
        );
    }
    assert_eq!(
        bit_diff(
            &case_by_id("one_bit_low_byte")["expected"]["claimed_root"],
            &case_by_id("one_bit_high_byte")["expected"]["claimed_root"],
        ),
        2,
        "the two bit claims differ from each other in the two opposite ends of the digest"
    );
    let display_case = case_by_id("display_order_claim");
    let mut reversed =
        hex::decode(internal(&display_case["expected"]["computed_root"])).expect("decodes");
    reversed.reverse();
    assert_eq!(
        internal(&display_case["expected"]["claimed_root"]),
        hex::encode(&reversed),
        "display_order_claim must claim exactly its own computed root in display order"
    );
    assert_eq!(
        internal(&case_by_id("zero_claim")["expected"]["claimed_root"]),
        "0".repeat(P41_DIGEST_LEN * 2),
        "zero_claim is the one claim in the corpus that no function computed"
    );

    // ---- the deduplication trap, both directions, both rejected ----
    assert_ne!(
        case_by_id("repeated_claim_vs_single_transaction")["expected"]["claimed_root"],
        case_by_id("single_claim_vs_repeated_transactions")["expected"]["claimed_root"],
        "the two directions of the deduplication trap claim two different roots"
    );
    assert_eq!(
        case_by_id("single_claim_vs_repeated_transactions")["input"]["transactions"][1],
        case_by_id("single_claim_vs_repeated_transactions")["input"]["transactions"][2],
        "the repeated block must really repeat its spend"
    );

    // ---- the empty digest, tied to the frozen P3.3B tag ----
    let empty_digest = hash256_json(&sha256d(P33_EMPTY_MERKLE_TAG));
    assert_eq!(
        case_by_id("empty_list_matching_claim")["expected"]["computed_root"],
        empty_digest,
        "the boundary case's empty-list root is no longer the tagged digest the P3.3B corpus publishes"
    );
    assert_eq!(
        case_by_id("empty_tree_claim_by_nonempty_block")["expected"]["claimed_root"],
        empty_digest,
        "the non-empty block claiming the empty digest must be claiming that same digest"
    );
    assert_eq!(
        case_by_id("empty_list_matching_claim")["expected"]["roots_match"].as_bool(),
        Some(true),
        "an empty list against its own digest matches at the comparison layer"
    );
    assert_eq!(
        case_by_id("empty_list_mismatching_claim")["expected"]["roots_match"].as_bool(),
        Some(false),
        "an empty list against a one-transaction root does not"
    );

    // ---- the ordering pair: the same two digests, one with a failing proof of work ----
    for (rule_name, ordering_name) in [
        ("stale_after_extra_transaction", "stale_root_with_failing_proof_of_work"),
        ("zero_claim", "zero_claim_with_failing_proof_of_work"),
    ] {
        let honest = case_by_id(rule_name);
        let failing = case_by_id(ordering_name);
        assert_eq!(
            honest["expected"]["computed_root"], failing["expected"]["computed_root"],
            "the {ordering_name} case must reuse {rule_name}'s transaction list"
        );
        assert_eq!(
            honest["expected"]["claimed_root"], failing["expected"]["claimed_root"],
            "the {ordering_name} case must reuse {rule_name}'s stale claim"
        );
        assert_eq!(
            honest["expected"]["error_kind"], failing["expected"]["error_kind"],
            "{ordering_name}: the comparison must report the same variant either way"
        );
        assert_eq!(
            failing["expected"]["error_kind"].as_str(),
            Some("RootMismatch"),
            "{ordering_name}: B-14 is what must be reported while B-15 would also fail"
        );
        assert_eq!(
            honest["expected"]["proof_of_work_meets_target"].as_bool(),
            Some(true),
            "{rule_name}: the mined header must meet its own target"
        );
        assert_eq!(
            failing["expected"]["proof_of_work_meets_target"].as_bool(),
            Some(false),
            "{ordering_name}: the ordering evidence depends on the nonce really missing the target"
        );
    }

    // ---- the production genesis block ----
    let genesis = genesis_block(&ChainParams::regtest(), &TrivialEngine::new());
    let accepted_genesis = case_by_id("genesis_block_accepted");
    assert_eq!(
        header_input(&genesis.header),
        accepted_genesis["input"]["header"].clone(),
        "the genesis case is no longer the header production assembles for regtest"
    );
    assert_eq!(
        genesis.transactions.len() as u64,
        accepted_genesis["input"]["tx_count"].as_u64().expect("tx_count"),
        "the genesis case is no longer the transaction list production assembles"
    );
    assert_eq!(
        hash256_json(&Block::compute_merkle_root(&genesis.transactions)),
        accepted_genesis["expected"]["computed_root"].clone(),
        "the genesis case's root is not the root of the production block"
    );
    assert_eq!(
        accepted_genesis["expected"]["claimed_root"],
        case_by_id("genesis_root_claim_by_later_block")["expected"]["claimed_root"],
        "the later block must claim exactly the root the genesis block claims"
    );
}

// ---------------------------------------------------------------------------
// Group: chain.block_structure (P4.2A)
//
// The structural validator as a whole: rules B-3 through B-15, in the order
// `src/consensus/block.rs` actually evaluates them, with the verdict `Block::
// validate_structure` itself returned. P4.1 asked one question (B-14) and was
// allowed one answer (`Ok` or `RootMismatch`); this corpus asks thirteen and
// publishes whichever of the thirteen variants the reference produced, so a C++
// port of the whole function has a fixed target for every guard and for every
// pair of adjacent guards.
//
// Rust is the sole authority for `expected`, and the authority is exercised, not
// claimed: `p42_emit` builds the block, calls `validate_structure` directly (the
// seven-argument form the reference uses in its own in-source tests, never
// `Chain::connect_block`, which additionally runs `difficulty::validate_bits` and
// the reward and UTXO checks a structural fixture does not need), and takes
// `error_kind`, `error_payload`, `reported_rule` and every digest from that call.
// The design contract predicted outcomes for these cases; not one of those
// predictions is written into `expected`. Each instead appears as a *declared
// construction intent* beside the fixture, and the emitter panics naming the case
// if the returned variant, the payload inside that variant, or the independently
// re-evaluated set of violated rules disagrees with the declaration. A fixture
// whose expectation had become unreachable could not be committed, because
// generating it is what fails.
//
// The third assertion is the one that makes precedence a fact rather than a
// sentence. `p42_violated_rules` re-evaluates all thirteen predicates against the
// same input — every one is a pure function of the published header, transaction
// list and context — and the emitter asserts that the validator's rule row is the
// *smallest* number in that set. So "B-7 dominates B-8" for `pair_07_08` means the
// published fixture violates both, measurably, and the reference reported the
// earlier one; and `chaos_all_later_guards_broken` is a dominance witness because
// eleven rules are violated at once and row 3 is what came back.
//
// Two orderings in `BlockError` must not be conflated, and both are published
// rather than implied. The *declaration* order (3, 4, 5, 14, 6, 7, 15, 12, 13, 8,
// 10, 11, 9) is the enum's; the *evaluation* order is B-3 to B-15 and lives in the
// body of `validate_structure`; and the kernel's `BlockErrorKind` numbering is a
// third, C++-side sequence. `rule_row` is the evaluation row, `error_kind` is the
// variant name, and nothing here assigns a numeric code to a port's enum.
//
// Two facts this corpus deliberately does not claim. B-8 and B-9 cannot both hold
// — `transactions.is_empty()` and `transactions.len() > MAX_BLOCK_TRANSACTIONS`
// are mutually exclusive — so the pair (B-8, B-9) has no fixture, no fake
// `.pair_08_09` identifier, and no experimental support: the relative order of
// those two guards is observationally vacuous and the manifest defers the pair
// with that reason. The emitter records the exclusivity as data: for every case it
// asserts the derived violated set never contains 8 and 9 together. And B-15 is
// only reachable when B-14 passed, which is why `iso_15_insufficient_pow` (root
// matching, nonce failing) is structurally impossible in the P4.1 corpus, whose
// emitter panics on any variant but `Ok` and `RootMismatch`.
//
// Reuse is explicit and byte-exact. Five cases replay a committed P4.1 block
// unchanged — the published header, the serialized transactions and the seven-key
// validation context are the same bytes — and add a validator-level claim, which
// P4.1 could not make: which guard the reference actually reported, and which
// rules were simultaneously violated. `p42_reference_fixtures_are_reproducible_and_pinned`
// compares those five against `test/p41-vectors/chain/claimed_merkle_root.json` on
// disk, so the identity is checked against the published corpus and not against a
// second copy of the same emitter call.
//
// No C++ code is involved, referenced as an authority, or claimed to agree; the
// differential belongs to P4.2B. The wall clock appears nowhere: `now` is a
// literal in every case, including the three that deliberately put it next to
// `u64::MAX` to separate saturating from wrapping addition.
// ---------------------------------------------------------------------------

/// The commit whose `zerocoin/` production code produced every value in this corpus: the
/// newest commit that touches a Rust build input. `zerocoin/src` is byte-identical here and
/// at the P4.2A baseline, so no value depends on a later test-only or documentation-only
/// commit. Same commit `chain.claimed_merkle_root` records, for the same reason.
const P42_SOURCE_COMMIT: &str = "b71d769be8357bcf10d768d915770125cf7f7c24";

/// Where `Block::validate_structure`, `Transaction::is_coinbase`, the
/// `BlockError::TooManyTransactions` variant and `MAX_BLOCK_TRANSACTIONS` each entered
/// `zerocoin/src` — `git log -S` names this one commit for all four. Between it and
/// `P42_SOURCE_COMMIT` the only edit to `block.rs` extracts B-3 and B-4 into
/// `validate_header_identity` (finding F-1), which changes the call graph but no verdict; so
/// unlike P4.1 this corpus cannot say the guarded lines "have not been edited since", and
/// does not.
const P42_REFERENCE_COMMIT: &str = "e464695f92f6884e6d25c6947d452d5fb24229a6";

/// The difficulty every honest fixture advertises: the trivial engine's frozen floor, a
/// 2^255 target that about half of all nonces meet, so mining costs nothing.
const P42_BITS: u32 = 0x207f_ffff;
/// One mantissa step below it. A B-7 fault has to be a value the reference itself can mine
/// against, so that the *only* undeclared-looking difference from a clean header is the
/// mismatch with `expected_bits`.
const P42_WRONG_BITS: u32 = 0x207f_fffe;

/// The anchor block height, and the four anchor context numbers the corrected P4.2 design
/// contract froze. `header_at(h).timestamp` is `1_700_000_000 + h`, so the natural heights
/// 4, 5, 7210 and 7211 below produce exactly the contract's timestamps without an override —
/// which is why `iso_12` and `iso_13` are isolation cases rather than hand-written numbers.
const P42_HEIGHT: u64 = 5;
const P42_MEDIAN: u64 = 1_700_000_004;
const P42_NOW: u64 = 1_700_000_010;
/// `P42_NOW + MAX_FUTURE_SECONDS`: the largest timestamp B-13 admits at the anchor clock.
/// The equality is asserted in the pinned test rather than trusted here.
const P42_LIMIT: u64 = 1_700_007_210;
/// One second past that limit — the timestamp `iso_13` and `bnd_13_one_above_reject` carry.
const P42_OVER_LIMIT: u64 = 1_700_007_211;

/// The previous hash a well-formed fixture header already carries, so "the tip this block
/// points at" and "the digest this block names" are the same value until a B-5 fault says
/// otherwise.
const P42_TIP: Hash256 = Hash256([0x33; 32]);

/// `now` one second short of the point where `now + 7200` starts to clamp: the limit is
/// `M - 1`, so a timestamp of `M` is rejected.
const P42_EDGE_NOW: u64 = u64::MAX - MAX_FUTURE_SECONDS - 1;
/// `now` at the last value whose limit is still `M` exactly: a timestamp of `M` fits, with
/// nothing to spare. `now = M` is the first value that clamps, and that is the case
/// `bnd_13_near_max_saturating_accept` reuses from P4.1 — the corpus's only witness against a
/// port that writes `now + 7200` without saturating, because a wrapping limit there is 7199.
const P42_LAST_EXACT_NOW: u64 = u64::MAX - MAX_FUTURE_SECONDS;

/// Lists no longer than this publish the P4.1 field-by-field transaction form and a leaf
/// array; longer ones publish canonical hex only, because a 2001-transaction block written
/// field by field would be most of a megabyte of JSON and the root already commits to every
/// byte of it.
const P42_VERBOSE_LIMIT: usize = 8;

/// Which proof-of-work engine the validator is running. The header's `engine_id` field is a
/// separate thing — every fixture writes the trivial id 0, which is exactly what makes B-6 a
/// statement about the *selected* engine rather than about a byte in the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum P42Engine {
    Trivial,
    ScratchPad,
}

impl P42Engine {
    /// Builds the engine the reference itself would build. Every published engine id, engine
    /// name and nonce search goes through the value returned here, so this section never
    /// restates `PowEngine::id` or `PowEngine::name` as a literal.
    fn build(&self) -> Box<dyn PowEngine> {
        match self {
            P42Engine::Trivial => Box::new(TrivialEngine::new()),
            // The devnet preset: the same `ScratchPadEngine::balanced()` the production
            // parameters select, and the only scratchpad fixture cost is a couple of hashes.
            P42Engine::ScratchPad => Box::new(ScratchPadEngine::balanced()),
        }
    }

    /// The engine identity as the reference reports it, published beside the context so a
    /// reader can see which engine a `WrongEngine` payload's `expected` came from. The
    /// scratchpad's memory size and round count are deliberately absent: they belong to the
    /// engine, not to the seven-key validation context P4.1 froze, and putting them there
    /// would change bytes the reuse cases must replay exactly.
    fn describe(&self) -> Value {
        let engine = self.build();
        match self {
            P42Engine::Trivial => json!(null),
            P42Engine::ScratchPad => json!({
                "engine_id": engine.id(),
                "engine_name": engine.name(),
                "preset": "ScratchPadEngine::balanced()",
            }),
        }
    }
}

/// The context a case hands `validate_structure` beside the block, in the seven published key
/// names `chain.claimed_merkle_root` already uses — plus which engine is selected, published
/// under `engine` as the reference's own `PowEngine::name()`.
struct P42Context {
    expected_chain: u32,
    expected_height: u64,
    expected_previous: Hash256,
    expected_bits: u32,
    median_time_past: u64,
    now: u64,
    engine: P42Engine,
}

impl P42Context {
    fn json(&self) -> Value {
        json!({
            "expected_chain": self.expected_chain,
            "expected_height": self.expected_height,
            "expected_previous_hex": hx(&self.expected_previous.0),
            "expected_bits": self.expected_bits,
            "median_time_past": self.median_time_past,
            "now": self.now,
            "engine": self.engine.build().name(),
        })
    }
}

/// A one-transaction block: the coinbase shape the P0 and P4.1 corpora already publish, at
/// the height the case names. `is_coinbase` reads only the input count and the null prevout,
/// so this is a coinbase wherever it is placed — and `coinbase_transaction` is the production
/// builder, not a fixture imitation of one.
fn p42_single(height: u64) -> Vec<Transaction> {
    vec![p33_coinbase(height)]
}

/// A fixture spend, distinct seed per case, so two cases that share a height still share no
/// transaction id.
fn p42_spend(seed: u8) -> Transaction {
    p33_tx(seed)
}

/// The coinbase pair every duplicate-coinbase fixture is built from: two production coinbase
/// transactions at two different heights.
fn p42_two_coinbases() -> Vec<Transaction> {
    vec![p33_coinbase(5), p33_coinbase(6)]
}

/// A tail transaction whose `is_coinbase()` is false for the *input* reason: exactly one
/// input, and its prevout is not null (`txid` non-zero, `vout` not `u32::MAX`).
fn p42_fill_spends(index: usize) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint {
                txid: Hash256([0x11; 32]),
                vout: index as u32,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOut {
            value: index as u64,
            script_pubkey: vec![0x51],
        }],
        lock_time: index as u32,
    }
}

/// A tail transaction whose `is_coinbase()` is false for the *count* reason: no inputs at
/// all. Zero outputs is structurally legal — P4.1 publishes a transaction with neither and the
/// reference accepts the block — so this shape isolates the input-count half of the predicate.
fn p42_fill_empty(index: usize) -> Transaction {
    Transaction {
        version: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: index as u32,
    }
}

/// The filler at `index`: the two shapes alternate, and `lock_time` carries the index, so no
/// two leaves in a large list can collide and the published root commits to the order as well
/// as the set.
fn p42_fill(index: usize) -> Transaction {
    if index % 2 == 0 {
        p42_fill_spends(index)
    } else {
        p42_fill_empty(index)
    }
}

/// `count` transactions: exactly one coinbase at index 0 and `count - 1` alternating
/// non-coinbases above it. The 2000 and 2001 fixtures are the same list at two lengths, so
/// the accepted and rejected pair differs by one transaction and nothing else.
fn p42_large(count: usize) -> Vec<Transaction> {
    let mut txs = vec![p33_coinbase(P42_HEIGHT)];
    txs.extend((1..count).map(p42_fill));
    txs
}

/// `count` transactions with no coinbase anywhere: index 0 is a zero-input transaction, so
/// B-10 is violated as well as B-9, and the `TooManyTransactions` verdict cannot be attributed
/// to the coinbase scan that follows it.
fn p42_large_without_coinbase(count: usize) -> Vec<Transaction> {
    let mut txs = vec![p42_fill_empty(0)];
    txs.extend((1..count).map(p42_fill));
    txs
}

/// What the emitter is being asked to build, and what it is being asked to prove about the
/// result. The three `declare_*` fields are the design contract's prediction written down as a
/// *check on the fixture*, never as the published value: `p42_emit` compares them with what the
/// reference returned and panics on any difference.
struct P42Spec {
    id: &'static str,
    group: &'static str,
    intent: &'static str,
    height: u64,
    timestamp: Option<u64>,
    chain: Option<u32>,
    previous: Option<Hash256>,
    bits: Option<u32>,
    engine: P42Engine,
    expected_chain: u32,
    expected_height: u64,
    expected_previous: Option<Hash256>,
    expected_bits: u32,
    median_time_past: u64,
    now: u64,
    transactions: Vec<Transaction>,
    /// The root the header claims. `None` means the root this list actually computes, which
    /// is what makes a case's B-14 status a construction fact rather than a coincidence.
    claim: Option<Hash256>,
    /// Whether the header claims the root this list actually computes (`false`) or that root
    /// with one bit of its first internal byte flipped (`true`). A stale claim that is still a
    /// digest, which is what makes B-14 a comparison rather than a parse failure.
    stale_claim: bool,
    /// Whether the nonce is searched to meet the header's own target (`true`, the reference's
    /// `pow::mine`) or to miss it (`false`, the deterministic scan `consensus_rules.rs` uses).
    /// Either way it is searched with the *selected* engine, because publishing a proof of work
    /// verified against a different engine than the validator ran would be an undeclared fault.
    honest_pow: bool,
    declare_variant: &'static str,
    declare_payload: Value,
    declare_rules: Vec<u8>,
    /// How many transactions of the list `Transaction::is_coinbase` reports as coinbases, and
    /// whether index zero is one. Both are checked against the built list before anything is
    /// published, so a large fixture cannot quietly lose the coinbase it was designed around.
    declare_coinbase_count: usize,
    declare_first_is_coinbase: bool,
    synthetic: bool,
    reuse_of: Option<&'static str>,
    check: &'static str,
}

impl P42Spec {
    /// Writes down the design contract's prediction as a *check on the construction*. The three
    /// declared values never reach the corpus: `p42_emit` publishes what the reference returned
    /// and panics naming the case if the declaration does not match it.
    fn declare(&mut self, variant: &'static str, payload: Value, rules: &[u8]) {
        self.declare_variant = variant;
        self.declare_payload = payload;
        self.declare_rules = rules.to_vec();
    }
}

impl P42Spec {
    /// The anchor construction: a well-formed header at height 5 with the anchor context, the
    /// trivial engine selected, an honest proof of work, and a claim equal to its own root —
    /// that is, a block with no rule violation at all until a case adds one.
    fn anchor(id: &'static str, group: &'static str, intent: &'static str) -> Self {
        P42Spec {
            id,
            group,
            intent,
            height: P42_HEIGHT,
            timestamp: None,
            chain: None,
            previous: None,
            bits: None,
            engine: P42Engine::Trivial,
            expected_chain: REGTEST_CHAIN.0,
            expected_height: P42_HEIGHT,
            expected_previous: None,
            expected_bits: P42_BITS,
            median_time_past: P42_MEDIAN,
            now: P42_NOW,
            transactions: p42_single(P42_HEIGHT),
            claim: None,
            stale_claim: false,
            honest_pow: true,
            declare_variant: "Ok",
            declare_payload: Value::Null,
            declare_rules: Vec::new(),
            declare_coinbase_count: 1,
            declare_first_is_coinbase: true,
            synthetic: false,
            reuse_of: None,
            check: "",
        }
    }
}

/// A case with nothing overridden but its own name, group, intent and independent check.
fn p42_case(id: &'static str, group: &'static str, intent: &'static str, check: &'static str) -> P42Spec {
    P42Spec { check, ..P42Spec::anchor(id, group, intent) }
}

/// The evaluation row a variant belongs to. Declaration order and evaluation order differ in
/// `BlockError`, so this is a property of `validate_structure`'s body, not of the enum.
fn block_error_rule(error: &BlockError) -> u8 {
    match error {
        BlockError::WrongChain { .. } => 3,
        BlockError::BadHeight { .. } => 4,
        BlockError::BadPreviousHash => 5,
        BlockError::WrongEngine { .. } => 6,
        BlockError::BadDifficulty { .. } => 7,
        BlockError::NoTransactions => 8,
        BlockError::TooManyTransactions(_) => 9,
        BlockError::FirstNotCoinbase => 10,
        BlockError::DuplicateCoinbase => 11,
        BlockError::TimestampTooOld { .. } => 12,
        BlockError::TimestampTooFarFuture { .. } => 13,
        BlockError::RootMismatch => 14,
        BlockError::InsufficientProofOfWork => 15,
    }
}

/// Every guard that the published input really fails, re-evaluated here as thirteen pure
/// predicates over that input. This is not a second validator: it returns no verdict, only the
/// set of rows whose condition holds, and the emitter's assertion that the reference reported
/// the smallest member of that set is what turns a rejection into precedence evidence.
///
/// For an empty list, rows 10 and 11 are *absent* rather than present-and-satisfied:
/// production returns at B-8 before it reads `transactions[0]` or `transactions[1..]`, and
/// pretending otherwise would publish an evaluation that never happened. That is also why
/// rows 8 and 9 can never appear together, which the emitter asserts per case.
fn p42_violated_rules(
    header: &BlockHeader,
    transactions: &[Transaction],
    context: &P42Context,
    engine: &dyn PowEngine,
    computed: &Hash256,
) -> Vec<u8> {
    let mut rules: Vec<u8> = Vec::new();
    if header.chain != context.expected_chain {
        rules.push(3);
    }
    if header.height != context.expected_height {
        rules.push(4);
    }
    if header.previous_hash != context.expected_previous {
        rules.push(5);
    }
    if header.engine_id != engine.id() {
        rules.push(6);
    }
    if header.difficulty_bits != context.expected_bits {
        rules.push(7);
    }
    let empty = transactions.is_empty();
    if empty {
        rules.push(8);
    }
    if transactions.len() > MAX_BLOCK_TRANSACTIONS {
        rules.push(9);
    }
    if !empty {
        if !transactions[0].is_coinbase() {
            rules.push(10);
        }
        if transactions[1..].iter().any(Transaction::is_coinbase) {
            rules.push(11);
        }
    }
    if header.timestamp <= context.median_time_past {
        rules.push(12);
    }
    if header.timestamp > context.now.saturating_add(MAX_FUTURE_SECONDS) {
        rules.push(13);
    }
    if header.merkle_root != *computed {
        rules.push(14);
    }
    if !header.meets_own_target(engine) {
        rules.push(15);
    }
    rules
}

fn p42_canonical(value: &Value) -> String {
    serde_json::to_string(value).expect("a published payload serialises")
}

/// The committed P4.1 case this fixture replays, rebuilt from the bytes that case publishes:
/// the header field by field, every transaction from its own `serialized_hex`, and all seven
/// validation-context values. Reuse is therefore byte-exact by construction and not by
/// transcription — the rebuilt header and context are compared with the published JSON before
/// anything is derived from them, and every transaction is re-serialised and compared.
///
/// The fourth half of the tuple is the proof-of-work status P4.1 recorded, which `p42_emit`
/// re-checks against the reference so a reused header cannot silently stop solving.
fn p42_reuse(name: &str) -> (BlockHeader, Vec<Transaction>, P42Context, bool) {
    let path = p41_root().join("chain").join("claimed_merkle_root.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "P4.2A reuse reads the committed P4.1 corpus at {}: {error}",
            path.display()
        )
    });
    let document: Value =
        serde_json::from_str(&text).expect("the committed P4.1 corpus is valid JSON");
    let id = format!("chain.claimed_merkle_root.{name}");
    let published = document["cases"]
        .as_array()
        .expect("the P4.1 corpus has a cases array")
        .iter()
        .find(|candidate| candidate["id"].as_str() == Some(id.as_str()))
        .unwrap_or_else(|| panic!("{id}: the committed P4.1 corpus has no such case"))
        .clone();
    let header_json = &published["input"]["header"];
    let field = |key: &str| -> u64 {
        header_json[key]
            .as_u64()
            .unwrap_or_else(|| panic!("{id}: header field `{key}` is missing"))
    };
    let digest = |object: &Value, key: &str| -> Hash256 {
        let text = object[key]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: field `{key}` is missing"));
        Hash256::from_slice(&hex::decode(text).expect("a published digest is hex"))
            .expect("a published digest is one sha256d wide")
    };
    let context_json = &published["input"]["validation_context"];
    let header = BlockHeader {
        version: field("version") as u32,
        chain: field("chain") as u32,
        height: field("height"),
        previous_hash: digest(header_json, "previous_hash_hex"),
        merkle_root: digest(header_json, "merkle_root_hex"),
        timestamp: field("timestamp"),
        difficulty_bits: field("difficulty_bits") as u32,
        engine_id: field("engine_id") as u8,
        nonce: field("nonce"),
    };
    let entries = published["input"]["transactions"]
        .as_array()
        .expect("a P4.1 case publishes its transactions as an array");
    let transactions: Vec<Transaction> = entries
        .iter()
        .map(|entry| {
            let text = entry["serialized_hex"]
                .as_str()
                .expect("a published P4.1 transaction carries serialized_hex");
            let bytes = hex::decode(text).expect("a published serialization is hex");
            let tx = Transaction::deserialize(&bytes)
                .unwrap_or_else(|error| panic!("{id}: a published transaction: {error}"));
            assert_eq!(
                hx(&tx.serialize()),
                text,
                "{id}: a P4.1 transaction does not re-serialise to its published bytes"
            );
            tx
        })
        .collect();
    let context = P42Context {
        expected_chain: context_json["expected_chain"]
            .as_u64()
            .expect("expected_chain") as u32,
        expected_height: context_json["expected_height"].as_u64().expect("expected_height"),
        expected_previous: digest(context_json, "expected_previous_hex"),
        expected_bits: context_json["expected_bits"]
            .as_u64()
            .expect("expected_bits") as u32,
        median_time_past: context_json["median_time_past"]
            .as_u64()
            .expect("median_time_past"),
        now: context_json["now"].as_u64().expect("now"),
        engine: P42Engine::Trivial,
    };
    assert_eq!(
        header_input(&header),
        header_json.clone(),
        "{id}: the rebuilt header is not the header P4.1 published"
    );
    assert_eq!(
        context.json(),
        context_json.clone(),
        "{id}: the rebuilt validation context is not the seven keys P4.1 published"
    );
    let proof_of_work = published["expected"]["proof_of_work_meets_target"]
        .as_bool()
        .expect("P4.1 publishes proof_of_work_meets_target");
    (header, transactions, context, proof_of_work)
}

/// The construction path: a header from the spec's own overrides, a claimed root taken from
/// the root the reference computes for this exact transaction list, and a nonce searched with
/// the *selected* engine — mined when the case wants a passing proof of work, scanned for a
/// failing one when it does not. Both searches are deterministic upward scans from zero, so a
/// nonce is a function of the header alone and never of a thread count, a clock or an RNG.
///
/// `header.engine_id` is pinned to the trivial id for every constructed case: a B-6 fault is a
/// property of the engine the validator is *running*, not of a byte in the header, which is
/// exactly what the `WrongEngine{expected, found}` pair is able to say about it.
fn p42_construct(
    spec: &P42Spec,
    engine: &dyn PowEngine,
) -> (BlockHeader, Vec<Transaction>, P42Context) {
    let mut header = header_at(spec.height, 0);
    header.chain = spec.chain.unwrap_or(header.chain);
    header.previous_hash = spec.previous.unwrap_or(P42_TIP);
    header.difficulty_bits = spec.bits.unwrap_or(P42_BITS);
    header.timestamp = spec.timestamp.unwrap_or(header.timestamp);
    header.engine_id = TrivialEngine::new().id();
    let transactions = spec.transactions.clone();
    let computed = Block::compute_merkle_root(&transactions);
    let claimed = spec.claim.unwrap_or(computed);
    header.merkle_root = if spec.stale_claim {
        p41_flip_bit(&claimed, 0, 0)
    } else {
        claimed
    };
    header.nonce = if spec.honest_pow {
        mine(
            engine,
            &header.preimage(),
            &compact_to_target(header.difficulty_bits),
            0,
        )
        .expect("the difficulty every P4.2A fixture advertises is solvable from nonce zero")
        .0
    } else {
        (0u64..512)
            .find(|nonce| {
                header.nonce = *nonce;
                !header.meets_own_target(engine)
            })
            .expect("a 2^255-class target yields a failing nonce within 512 tries")
    };
    let context = P42Context {
        expected_chain: spec.expected_chain,
        expected_height: spec.expected_height,
        expected_previous: spec.expected_previous.unwrap_or(P42_TIP),
        expected_bits: spec.expected_bits,
        median_time_past: spec.median_time_past,
        now: spec.now,
        engine: spec.engine,
    };
    (header, transactions, context)
}

/// The one emitter every case in this group goes through, and the place the oracle doctrine is
/// enforced. It calls `Block::validate_structure` directly with the seven arguments the
/// reference's own in-source test uses, then publishes *that* call's verdict: the variant name,
/// the payload read out of the variant it actually returned, the evaluation row that variant
/// belongs to, and the set of rules the published input independently re-evaluates as violated.
///
/// Five things are asserted before anything is returned, and each one names the case when it
/// fails, so a fixture whose expectation had become unreachable stops the export instead of
/// publishing a wrong `expected`:
///
/// 1. every transaction round-trips `deserialize(serialize(tx)) == tx` at its published width;
/// 2. no two transactions share a leaf id, so the published root commits to the list uniquely;
/// 3. the coinbase count and the status of index 0 equal what the case was designed around;
/// 4. the returned variant and its payload equal the *declared construction intent*, which is
///    the design contract's prediction recorded as a check on the fixture and nowhere else;
/// 5. the reported row is the smallest member of the derived violated set, and an accept
///    happens only when that set is empty — the assertion that turns a rejection into evidence
///    about precedence rather than about a single guard.
///
/// The derived set is additionally asserted never to hold 8 and 9 together, which is the
/// computed backing for the manifest's deferral of that pair.
fn p42_emit(spec: &P42Spec) -> Value {
    let engine = spec.engine.build();
    let label = format!("chain.block_structure.{}", spec.id);
    let (header, transactions, context) = match spec.reuse_of {
        None => p42_construct(spec, engine.as_ref()),
        Some(name) => {
            let (header, transactions, context, published_pow) = p42_reuse(name);
            assert_eq!(
                context.engine, spec.engine,
                "{label}: {name} replays a P4.1 context whose engine is not the one this case declares"
            );
            assert_eq!(context.median_time_past, spec.median_time_past, "{label}: the reused P4.1 `median_time_past` is not the one this case declares");
            assert_eq!(context.now, spec.now, "{label}: the reused P4.1 `now` is not the one this case declares");
            assert_eq!(context.expected_chain, spec.expected_chain, "{label}: the reused P4.1 `expected_chain` is not the one this case declares");
            assert_eq!(context.expected_height, spec.expected_height, "{label}: the reused P4.1 `expected_height` is not the one this case declares");
            assert_eq!(context.expected_bits, spec.expected_bits, "{label}: the reused P4.1 `expected_bits` is not the one this case declares");
            assert_eq!(
                header.engine_id,
                engine.id(),
                "{label}: a reused P4.1 header no longer advertises the engine this case selects"
            );
            assert_eq!(
                header.meets_own_target(engine.as_ref()),
                published_pow,
                "{label}: the reused P4.1 header no longer solves the target it advertises"
            );
            (header, transactions, context)
        }
    };

    for (index, tx) in transactions.iter().enumerate() {
        let bytes = tx.serialize();
        let rebuilt = Transaction::deserialize(&bytes)
            .unwrap_or_else(|error| panic!("{label}: transaction {index} does not deserialise: {error}"));
        assert_eq!(rebuilt, *tx, "{label}: the canonical round-trip is not the identity at index {index}");
        assert_eq!(hx(&bytes).len(), bytes.len() * 2, "{label}: serialization width moved at index {index}");
    }

    let leaves: Vec<Hash256> = transactions.iter().map(Transaction::txid).collect();
    let mut unique: Vec<[u8; 32]> = leaves.iter().map(|leaf| leaf.0).collect();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        leaves.len(),
        "{label}: two transactions share a leaf id, so the published root would not commit to this list uniquely"
    );

    let flags: String = transactions
        .iter()
        .map(|tx| if tx.is_coinbase() { '1' } else { '0' })
        .collect();
    let coinbase_count = flags.matches('1').count();
    let first_is_coinbase = transactions.first().map_or(false, Transaction::is_coinbase);
    assert_eq!(
        coinbase_count, spec.declare_coinbase_count,
        "{label}: the list holds {coinbase_count} coinbases, not the {} this case was built around",
        spec.declare_coinbase_count
    );
    assert_eq!(
        first_is_coinbase, spec.declare_first_is_coinbase,
        "{label}: index 0 is {} a coinbase, contrary to how this case was built",
        if spec.declare_first_is_coinbase { "" } else { "not" }
    );

    let computed = Block::compute_merkle_root(&transactions);
    let claimed = header.merkle_root;
    let roots_match = computed.0 == claimed.0;
    let proof_of_work = header.meets_own_target(engine.as_ref());

    let outcome = Block {
        header: header.clone(),
        transactions: transactions.clone(),
    }
    .validate_structure(
        engine.as_ref(),
        context.expected_chain,
        context.expected_height,
        &context.expected_previous,
        context.expected_bits,
        context.median_time_past,
        context.now,
    );
    let violated = p42_violated_rules(&header, &transactions, &context, engine.as_ref(), &computed);
    assert!(
        !(violated.contains(&8) && violated.contains(&9)),
        "{label}: the derived violated set holds B-8 and B-9 together, which `is_empty()` and \
         `len() > MAX_BLOCK_TRANSACTIONS` make impossible"
    );

    let returned = match &outcome {
        Ok(()) => "Ok",
        Err(error) => block_error_kind(error),
    };
    assert_eq!(
        returned, spec.declare_variant,
        "{label}: this fixture was constructed as `{}`, but `validate_structure` returned `{}`",
        spec.declare_variant,
        returned
    );
    let error_payload = match &outcome {
        Ok(()) => Value::Null,
        Err(error) => block_error_payload(error),
    };
    assert_eq!(
        p42_canonical(&error_payload),
        p42_canonical(&spec.declare_payload),
        "{label}: the reference returned the payload `{}`, not the `{}` this case was built to carry",
        p42_canonical(&error_payload),
        p42_canonical(&spec.declare_payload)
    );
    assert_eq!(
        violated,
        spec.declare_rules,
        "{label}: the published input violates rules {violated:?}, not {rules:?} as constructed",
        rules = spec.declare_rules
    );

    let reported_rule = match &outcome {
        Ok(()) => None,
        Err(error) => Some(block_error_rule(error)),
    };
    match (reported_rule, violated.first()) {
        (None, None) => {}
        (None, Some(row)) => panic!(
            "{label}: the reference accepted a block whose published input violates rule B-{row}"
        ),
        (Some(row), None) => panic!(
            "{label}: the reference reported rule B-{row} while no guard of the published input fails"
        ),
        (Some(row), Some(&first)) => assert_eq!(
            row, first,
            "{label}: the reference reported B-{row}, but B-{first} is the earliest guard the \
             published input fails — precedence evidence, not a verdict, is what this corpus \
             publishes, so this must not be papered over"
        ),
    }

    let verbose = transactions.len() <= P42_VERBOSE_LIMIT;
    let mut input = json!({
        "group": spec.group,
        "header": header_input(&header),
        "tx_count": transactions.len(),
        "validation_context": context.json(),
        "engine_config": spec.engine.describe(),
        "synthetic_context": spec.synthetic,
        "reused_from": spec.reuse_of.map(|name| format!("chain.claimed_merkle_root.{name}")),
    });
    if verbose {
        input["transactions"] = json!(transactions.iter().map(p41_tx_input).collect::<Vec<Value>>());
    } else {
        input["transactions_hex"] = json!(
            transactions
                .iter()
                .map(|tx| hx(&tx.serialize()))
                .collect::<Vec<String>>()
        );
    }

    let mut expected = json!({
        "accepted": outcome.is_ok(),
        "error_kind": match &outcome {
            Ok(()) => Value::Null,
            Err(error) => json!(block_error_kind(error)),
        },
        "error_payload": error_payload,
        "reported_rule": reported_rule,
        "violated_rules": violated,
        "is_first_violation": match reported_rule {
            Some(row) => json!(violated.first() == Some(&row)),
            None => Value::Null,
        },
        "roots_match": roots_match,
        "computed_root": hash256_json(&computed),
        "claimed_root": hash256_json(&claimed),
        "computed_root_len": computed.0.len(),
        "proof_of_work_meets_target": proof_of_work,
        "coinbase_flags": flags,
        "coinbase_count": coinbase_count,
        "first_is_coinbase": first_is_coinbase,
        "leaf_count": transactions.len(),
    });
    if verbose {
        expected["leaves"] = json!(
            leaves
                .iter()
                .map(|leaf| json!({ "txid": hash256_json(leaf) }))
                .collect::<Vec<Value>>()
        );
    }
    case(&label, spec.intent, input, expected, spec.check)
}

/// The timestamp `header_at(5).timestamp` produces, written once so the two B-12 and two B-13
/// boundary pairs can be read as the one-second steps they are.
const P42_ANCHOR_TS: u64 = 1_700_000_005;

/// A case built from the anchor by a closure that applies its own faults and writes down its
/// own declaration. Every field the closure does not touch stays exactly as `P42Spec::anchor`
/// set it, so a reader comparing two cases in this list can see the whole difference between
/// them in the lines that differ.
fn p42_spec(
    id: &'static str,
    group: &'static str,
    intent: &'static str,
    check: &'static str,
    configure: impl FnOnce(&mut P42Spec),
) -> P42Spec {
    let mut spec = p42_case(id, group, intent, check);
    configure(&mut spec);
    spec
}

/// The frozen matrix: 14 isolation cases, 8 boundary cases, 11 representable adjacent-pair
/// cases and 1 dominance witness. 34, with the pair (B-8, B-9) deliberately absent because the
/// two predicates are mutually exclusive, and the pair (B-13, B-14) absent because the corrected
/// design contract does not list it — neither gap is presented as proven by a fixture here.
fn p42_specs() -> Vec<P42Spec> {
    let specs = vec![
        // ---- Group A: one guard per case, every earlier guard demonstrably satisfied ----
        p42_spec(
            "iso_03_wrong_chain",
            "A",
            "rule",
            "`input.header.chain` differs from `input.validation_context.expected_chain` and no other published field differs from its expected value",
            |s| {
                s.chain = Some(0);
                s.declare(
                    "WrongChain",
                    json!({"expected": REGTEST_CHAIN.0, "found": 0}),
                    &[3],
                );
            },
        ),
        p42_spec(
            "iso_04_bad_height",
            "A",
            "rule",
            "`input.header.height` is 6 while the context expects 5; the chain, previous hash, bits, engine and clock all match",
            |s| {
                s.height = 6;
                s.transactions = p42_single(6);
                s.declare(
                    "BadHeight",
                    json!({"expected": P42_HEIGHT, "found": 6}),
                    &[4],
                );
            },
        ),
        p42_spec(
            "iso_05_bad_previous_hash",
            "A",
            "rule",
            "`input.header.previous_hash_hex` is all zero while the context names the 0x33 tip; a unit variant carries no payload",
            |s| {
                s.previous = Some(Hash256([0u8; 32]));
                s.declare("BadPreviousHash", Value::Null, &[5]);
            },
        ),
        p42_spec(
            "iso_06_wrong_engine",
            "A",
            "rule",
            "the header advertises `TrivialEngine::id()` while `input.validation_context.engine` is the scratchpad's own `PowEngine::name()`; the payload is the reference's two ids, not literals",
            |s| {
                s.engine = P42Engine::ScratchPad;
                s.declare(
                    "WrongEngine",
                    json!({
                        "expected": ScratchPadEngine::balanced().id(),
                        "found": TrivialEngine::new().id(),
                    }),
                    &[6],
                );
            },
        ),
        p42_spec(
            "iso_07_bad_difficulty",
            "A",
            "rule",
            "`input.header.difficulty_bits` is one mantissa step below the context's `expected_bits`, and the header is mined against its own advertised bits so B-15 cannot be what fired",
            |s| {
                s.bits = Some(P42_WRONG_BITS);
                s.declare(
                    "BadDifficulty",
                    json!({"expected": P42_BITS, "found": P42_WRONG_BITS}),
                    &[7],
                );
            },
        ),
        p42_spec(
            "iso_08_no_transactions",
            "A",
            "rule",
            "the committed P4.1 block whose list is empty, whose claimed root matches and whose proof of work passes: `NoTransactions` is the only verdict the published input can produce",
            |s| {
                s.expected_height = 50;
                s.median_time_past = 0;
                s.now = u64::MAX;
                s.declare("NoTransactions", Value::Null, &[8]);
                s.declare_coinbase_count = 0;
                s.declare_first_is_coinbase = false;
                s.reuse_of = Some("empty_list_matching_claim");
            },
        ),
        p42_spec(
            "iso_09_too_many_transactions",
            "A",
            "rule",
            "`tx_count` is 2001, index 0 is the only coinbase, and `expected.count` is the length the variant itself carried out of `validate_structure`",
            |s| {
                s.transactions = p42_large(2_001);
                s.declare(
                    "TooManyTransactions",
                    json!({"count": 2_001}),
                    &[9],
                );
            },
        ),
        p42_spec(
            "iso_10_first_not_coinbase",
            "A",
            "rule",
            "`coinbase_flags` is `00`: two ordinary spends, so B-10 fires on a list of legal length",
            |s| {
                s.transactions = vec![p42_spend(20), p42_spend(21)];
                s.declare("FirstNotCoinbase", Value::Null, &[10]);
                s.declare_coinbase_count = 0;
                s.declare_first_is_coinbase = false;
            },
        ),
        p42_spec(
            "iso_11_duplicate_coinbase",
            "A",
            "rule",
            "`coinbase_flags` is `11`: two production coinbases at two heights, so the second is at index 1",
            |s| {
                s.transactions = p42_two_coinbases();
                s.declare("DuplicateCoinbase", Value::Null, &[11]);
                s.declare_coinbase_count = 2;
            },
        ),
        p42_spec(
            "iso_11_duplicate_coinbase_at_last_index",
            "A",
            "rule",
            "`coinbase_flags` is `100001`: the scan of `transactions[1..]` has to reach the sixth element, so a port that stops at index 1 is caught by this case alone",
            |s| {
                s.transactions = vec![
                    p33_coinbase(5),
                    p42_spend(30),
                    p42_spend(31),
                    p42_spend(32),
                    p42_spend(33),
                    p33_coinbase(6),
                ];
                s.declare("DuplicateCoinbase", Value::Null, &[11]);
                s.declare_coinbase_count = 2;
            },
        ),
        p42_spec(
            "iso_12_timestamp_too_old",
            "A",
            "rule",
            "height 4 makes `header_at` produce `timestamp == median_time_past` without an override, so the equality is a construction fact",
            |s| {
                s.height = 4;
                s.expected_height = 4;
                s.transactions = p42_single(4);
                s.declare(
                    "TimestampTooOld",
                    json!({"median": P42_MEDIAN, "found": P42_MEDIAN}),
                    &[12],
                );
            },
        ),
        p42_spec(
            "iso_13_timestamp_too_far_future",
            "A",
            "rule",
            "height 7211 makes `header_at` produce `timestamp == now + 7201` without an override, one second past the anchor limit",
            |s| {
                s.height = 7_211;
                s.expected_height = 7_211;
                s.transactions = p42_single(7_211);
                s.declare(
                    "TimestampTooFarFuture",
                    json!({"now": P42_NOW, "found": P42_OVER_LIMIT}),
                    &[13],
                );
            },
        ),
        p42_spec(
            "iso_14_root_mismatch",
            "A",
            "rule",
            "the committed P4.1 block whose fourth transaction made the claim stale: `roots_match` false, `proof_of_work_meets_target` true, `coinbase_flags` `1000`",
            |s| {
                s.reuse_of = Some("stale_after_extra_transaction");
                s.expected_height = 20;
                s.median_time_past = 0;
                s.now = u64::MAX;
                s.declare("RootMismatch", Value::Null, &[14]);
            },
        ),
        p42_spec(
            "iso_15_insufficient_pow",
            "A",
            "rule",
            "`roots_match` true with `proof_of_work_meets_target` false — a pairing the P4.1 corpus cannot contain, because its invariant is `accepted == roots_match && pow`",
            |s| {
                s.honest_pow = false;
                s.declare("InsufficientProofOfWork", Value::Null, &[15]);
            },
        ),
        // ---- Group B: the boundary itself, one step either side where a step exists ----
        p42_spec(
            "bnd_09_count_at_limit_accept",
            "B",
            "boundary",
            "`tx_count` 2000 with `coinbase_flags` `1` followed by 1999 `0`s: the limit is inclusive, and the accept is the reference's own verdict on a list that spends UTXOs nobody has",
            |s| {
                s.transactions = p42_large(2_000);
                s.declare("Ok", Value::Null, &[]);
            },
        ),
        p42_spec(
            "bnd_12_equal_median_reject",
            "B",
            "boundary",
            "the same header as `.bnd_12_one_above_median_accept` with `median_time_past` one second later, so `timestamp == median` rejects",
            |s| {
                s.median_time_past = P42_ANCHOR_TS;
                s.declare(
                    "TimestampTooOld",
                    json!({"median": P42_ANCHOR_TS, "found": P42_ANCHOR_TS}),
                    &[12],
                );
            },
        ),
        p42_spec(
            "bnd_12_one_above_median_accept",
            "B",
            "boundary",
            "`timestamp == median_time_past + 1`: the one-second difference from the case above is the only thing that changes the verdict",
            |s| s.declare("Ok", Value::Null, &[]),
        ),
        p42_spec(
            "bnd_13_equal_limit_accept",
            "B",
            "boundary",
            "`now` is `timestamp - 7200`, so the limit equals the timestamp exactly and B-13's comparison is strict",
            |s| {
                s.median_time_past = 0;
                s.now = P42_ANCHOR_TS - MAX_FUTURE_SECONDS;
                s.declare("Ok", Value::Null, &[]);
            },
        ),
        p42_spec(
            "bnd_13_one_above_reject",
            "B",
            "boundary",
            "`now` one second below the case above, with every other published byte identical: the reject is one clock second away from the accept",
            |s| {
                s.median_time_past = 0;
                s.now = P42_ANCHOR_TS - MAX_FUTURE_SECONDS - 1;
                s.declare(
                    "TimestampTooFarFuture",
                    json!({"now": P42_ANCHOR_TS - MAX_FUTURE_SECONDS - 1, "found": P42_ANCHOR_TS}),
                    &[13],
                );
            },
        ),
        p42_spec(
            "bnd_13_near_max_edge_reject",
            "B",
            "boundary",
            "`now = u64::MAX - 7201` with `timestamp = u64::MAX`: the saturating limit is `MAX - 1`, so the timestamp is one past it and nothing has clamped",
            |s| {
                s.median_time_past = 0;
                s.now = P42_EDGE_NOW;
                s.timestamp = Some(u64::MAX);
                s.declare(
                    "TimestampTooFarFuture",
                    json!({"now": P42_EDGE_NOW, "found": u64::MAX}),
                    &[13],
                );
            },
        ),
        p42_spec(
            "bnd_13_near_max_last_exact_accept",
            "B",
            "boundary",
            "`now = u64::MAX - 7200` with `timestamp = u64::MAX`: the limit is `MAX` exactly, the last value before the addition starts to clamp",
            |s| {
                s.median_time_past = 0;
                s.now = P42_LAST_EXACT_NOW;
                s.timestamp = Some(u64::MAX);
                s.declare("Ok", Value::Null, &[]);
            },
        ),
        p42_spec(
            "bnd_13_near_max_saturating_accept",
            "B",
            "boundary",
            "`now = u64::MAX` with a realistic timestamp: the corpus's only witness against a port that writes `now + 7200` without saturating, because the wrapping limit there is 7199. The block is the committed P4.1 five-transaction accept, which already carries this context",
            |s| {
                s.median_time_past = 0;
                s.now = u64::MAX;
                s.declare("Ok", Value::Null, &[]);
                s.reuse_of = Some("five_transaction_block");
            },
        ),
        // ---- Group C: both faults of an adjacent pair present at once, the earlier row wins ----
        p42_spec(
            "pair_03_04_chain_and_height",
            "C",
            "ordering",
            "`violated_rules` is `[3, 4]` and `reported_rule` is 3: the chain and the height are both wrong, and the chain is what the reference named",
            |s| {
                s.chain = Some(0);
                s.height = 6;
                s.transactions = p42_single(6);
                s.declare(
                    "WrongChain",
                    json!({"expected": REGTEST_CHAIN.0, "found": 0}),
                    &[3, 4],
                );
            },
        ),
        p42_spec(
            "pair_04_05_height_and_previous",
            "C",
            "ordering",
            "`violated_rules` is `[4, 5]` and `reported_rule` is 4: a wrong height masks a wrong previous hash",
            |s| {
                s.height = 6;
                s.previous = Some(Hash256([0u8; 32]));
                s.transactions = p42_single(6);
                s.declare(
                    "BadHeight",
                    json!({"expected": P42_HEIGHT, "found": 6}),
                    &[4, 5],
                );
            },
        ),
        p42_spec(
            "pair_05_06_previous_and_engine",
            "C",
            "ordering",
            "`violated_rules` is `[5, 6]` and `reported_rule` is 5: a bad previous hash masks the scratchpad being selected while the header advertises the trivial id",
            |s| {
                s.previous = Some(Hash256([0u8; 32]));
                s.engine = P42Engine::ScratchPad;
                s.declare("BadPreviousHash", Value::Null, &[5, 6]);
            },
        ),
        p42_spec(
            "pair_06_07_engine_and_bits",
            "C",
            "ordering",
            "`violated_rules` is `[6, 7]` and `reported_rule` is 6: the engine mismatch masks the one-mantissa-step bits mismatch",
            |s| {
                s.engine = P42Engine::ScratchPad;
                s.bits = Some(P42_WRONG_BITS);
                s.declare(
                    "WrongEngine",
                    json!({
                        "expected": ScratchPadEngine::balanced().id(),
                        "found": TrivialEngine::new().id(),
                    }),
                    &[6, 7],
                );
            },
        ),
        p42_spec(
            "pair_07_08_bits_and_empty",
            "C",
            "ordering",
            "`violated_rules` is `[7, 8]` and `reported_rule` is 7: the bits mismatch is returned without ever reaching the empty-list check, so `transactions` is published as `[]` next to a `BadDifficulty`",
            |s| {
                s.bits = Some(P42_WRONG_BITS);
                s.transactions = Vec::new();
                s.declare(
                    "BadDifficulty",
                    json!({"expected": P42_BITS, "found": P42_WRONG_BITS}),
                    &[7, 8],
                );
                s.declare_coinbase_count = 0;
                s.declare_first_is_coinbase = false;
            },
        ),
        p42_spec(
            "pair_09_10_over_limit_and_first_not_coinbase",
            "C",
            "ordering",
            "`violated_rules` is `[9, 10]` and `reported_rule` is 9: the list is over the limit *and* carries no coinbase at index 0, so the `TooManyTransactions` verdict cannot be attributed to the coinbase scan that follows it",
            |s| {
                s.transactions = p42_large_without_coinbase(2_001);
                s.declare(
                    "TooManyTransactions",
                    json!({"count": 2_001}),
                    &[9, 10],
                );
                s.declare_coinbase_count = 0;
                s.declare_first_is_coinbase = false;
            },
        ),
        p42_spec(
            "pair_10_11_first_not_coinbase_and_duplicate",
            "C",
            "ordering",
            "`coinbase_flags` is `01` and `violated_rules` is `[10, 11]`: B-10 fires on the missing first coinbase before the scan that would report the duplicate",
            |s| {
                s.transactions = vec![p42_spend(40), p33_coinbase(6)];
                s.declare("FirstNotCoinbase", Value::Null, &[10, 11]);
                s.declare_coinbase_count = 1;
                s.declare_first_is_coinbase = false;
            },
        ),
        p42_spec(
            "pair_11_12_duplicate_and_old_timestamp",
            "C",
            "ordering",
            "`violated_rules` is `[11, 12]`: two coinbases and a timestamp equal to the median, and the duplicate is what the reference reported",
            |s| {
                s.transactions = p42_two_coinbases();
                s.timestamp = Some(P42_MEDIAN);
                s.declare("DuplicateCoinbase", Value::Null, &[11, 12]);
                s.declare_coinbase_count = 2;
            },
        ),
        p42_spec(
            "pair_12_13_old_and_future",
            "C",
            "ordering",
            "`violated_rules` is `[12, 13]` with `median_time_past` above `now + 7200` — a clock pair no node can produce, which is why this case is labelled synthetic; the stale check runs first and reports the old timestamp",
            |s| {
                s.timestamp = Some(P42_OVER_LIMIT);
                s.median_time_past = P42_OVER_LIMIT + 1;
                s.synthetic = true;
                s.declare(
                    "TimestampTooOld",
                    json!({"median": P42_OVER_LIMIT + 1, "found": P42_OVER_LIMIT}),
                    &[12, 13],
                );
            },
        ),
        p42_spec(
            "pair_14_15_root_mismatch_and_failing_pow",
            "C",
            "ordering",
            "the committed P4.1 block with a stale root *and* a failing nonce, re-asserted through the validator's verdict: `violated_rules` is `[14, 15]`, `reported_rule` is 14",
            |s| {
                s.expected_height = 25;
                s.median_time_past = 0;
                s.now = u64::MAX;
                s.declare("RootMismatch", Value::Null, &[14, 15]);
                s.reuse_of = Some("stale_root_with_failing_proof_of_work");
            },
        ),
        p42_spec(
            "pair_14_15_zero_root_claim_and_failing_pow",
            "C",
            "ordering",
            "the committed P4.1 block whose claim is the all-zero digest and whose nonce fails, so the pair is witnessed a second time from a different claim shape: `violated_rules` `[14, 15]`, `reported_rule` 14",
            |s| {
                s.expected_height = 26;
                s.median_time_past = 0;
                s.now = u64::MAX;
                s.declare("RootMismatch", Value::Null, &[14, 15]);
                s.reuse_of = Some("zero_claim_with_failing_proof_of_work");
            },
        ),
        // ---- Group D: one block, every jointly satisfiable later guard broken at once ----
        p42_spec(
            "chaos_all_later_guards_broken",
            "D",
            "ordering",
            "`violated_rules` holds ten of the twelve later conditions — 4, 5, 6, 7, 10, 11, 12, 13, 14, 15 — and `reported_rule` is 3, so B-3 dominates all of them at once. B-8 and B-9 are absent by construction: the list has two transactions, and the empty list that B-8 needs excludes B-9, B-10 and B-11",
            |s| {
                s.height = 6;
                s.chain = Some(0);
                s.previous = Some(Hash256([0u8; 32]));
                s.bits = Some(P42_WRONG_BITS);
                s.engine = P42Engine::ScratchPad;
                s.timestamp = Some(P42_OVER_LIMIT);
                s.median_time_past = P42_OVER_LIMIT + 1;
                s.transactions = vec![p42_spend(50), p33_coinbase(6)];
                s.stale_claim = true;
                s.honest_pow = false;
                s.synthetic = true;
                s.declare(
                    "WrongChain",
                    json!({"expected": REGTEST_CHAIN.0, "found": 0}),
                    &[3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15],
                );
                s.declare_coinbase_count = 1;
                s.declare_first_is_coinbase = false;
            },
        ),
    ];
    specs
}

/// The corpus's 34 cases, each one produced by `p42_emit` and therefore by a direct call into
/// `Block::validate_structure`.
fn block_structure_cases() -> Vec<Value> {
    p42_specs().iter().map(p42_emit).collect()
}

/// The P4.2A envelope: the P4.1 envelope shape with this corpus's own source revision, so one
/// file answers "which Rust code produced these verdicts" without consulting the manifest.
fn p42_envelope(group: &str, intent: &str, note: &str, cases: Vec<Value>) -> String {
    let doc = json!({
        "schema": "zro-baseline-vectors/1",
        "group": group,
        "intent": intent,
        "note": note,
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P42_SOURCE_COMMIT,
        "provenance": "every `expected` value was produced by a direct call to the shipping \
`zerocoin/` Rust function `consensus::block::Block::validate_structure` at `source_commit`, \
which is where rules B-3 through B-15 live; every computed root by `Block::compute_merkle_root` \
on that call's own transaction list, every leaf id by `Transaction::txid`, every coinbase flag \
by `Transaction::is_coinbase`, every payload field by matching on the variant that call \
actually returned, and every header nonce by `consensus::pow::mine` or by the deterministic \
failing-nonce scan `consensus_rules.rs` uses. No verdict, payload, rule row or digest here is \
taken from another implementation, predicted by a design document, computed by hand, or \
derived by a Python or C++ program",
        "reference_commits": {
            "validate_structure_introduced": P42_REFERENCE_COMMIT,
            "block_error_variants_introduced": P42_REFERENCE_COMMIT,
            "coinbase_rule_introduced": P42_REFERENCE_COMMIT,
            "max_block_transactions_introduced": P42_REFERENCE_COMMIT,
        },
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p42_*` functions, added by the \
P4.2A commit that lands immediately after the baseline; a fixture cannot truthfully record the \
hash of the commit that contains it, so `source_commit` names the code and this field names the \
exporter separately",
        "case_count": cases.len(),
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("reference document serialises");
    text.push('\n');
    text
}

/// The P4.2A corpus and its manifest, mirroring `p41_corpus()` above: same `add!` shape, same
/// write-versus-compare protocol, different root. Every count, id list, rule-coverage array and
/// synthetic label in the manifest is computed from the cases that were just emitted, so the
/// manifest cannot describe a corpus that no longer exists.
fn p42_corpus() -> Vec<(String, String)> {
    let cases = block_structure_cases();
    let ids: Vec<String> = cases
        .iter()
        .map(|case| {
            case["id"]
                .as_str()
                .expect("every case publishes an id")
                .to_string()
        })
        .collect();
    let by_group = |letter: &str| -> usize {
        cases
            .iter()
            .filter(|case| case["input"]["group"].as_str() == Some(letter))
            .count()
    };
    let by_intent = |name: &str| -> usize {
        cases
            .iter()
            .filter(|case| case["intent"].as_str() == Some(name))
            .count()
    };
    let accepted_ids: Vec<&str> = cases
        .iter()
        .filter(|case| case["expected"]["accepted"].as_bool() == Some(true))
        .map(|case| case["id"].as_str().expect("id"))
        .collect();
    let synthetic_ids: Vec<&str> = cases
        .iter()
        .filter(|case| case["input"]["synthetic_context"].as_bool() == Some(true))
        .map(|case| case["id"].as_str().expect("id"))
        .collect();
    let reused_ids: Vec<&str> = cases
        .iter()
        .filter(|case| case["input"]["reused_from"].is_string())
        .map(|case| case["id"].as_str().expect("id"))
        .collect();
    let mut reported_rows: Vec<u8> = cases
        .iter()
        .filter_map(|case| case["expected"]["reported_rule"].as_u64().map(|row| row as u8))
        .collect();
    reported_rows.sort_unstable();
    reported_rows.dedup();
    let mut violated_rows: Vec<u8> = cases
        .iter()
        .flat_map(|case| {
            case["expected"]["violated_rules"]
                .as_array()
                .expect("every case publishes violated_rules")
                .iter()
                .map(|row| row.as_u64().expect("a rule row") as u8)
        })
        .collect();
    violated_rows.sort_unstable();
    violated_rows.dedup();
    let precedence: Vec<Value> = cases
        .iter()
        .filter(|case| case["intent"].as_str() == Some("ordering"))
        .map(|case| {
            json!({
                "id": case["id"],
                "violated_rules": case["expected"]["violated_rules"],
                "reported_rule": case["expected"]["reported_rule"],
            })
        })
        .collect();

    let mut files: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();

    macro_rules! add {
        ($path:expr, $group:expr, $intent:expr, $note:expr, $cases:expr) => {{
            let cases: Vec<Value> = $cases;
            counts.push(json!({"path": $path, "group": $group, "cases": cases.len()}));
            files.push(($path.to_string(), p42_envelope($group, $intent, $note, cases)));
        }};
    }

    add!(
        "chain/block_structure.json",
        "chain.block_structure",
        "rule",
        "The whole structural validator, B-3 through B-15: thirteen guards in the order \
`Block::validate_structure` evaluates them, plus the precedence between every adjacent pair the \
corrected design contract froze as representable. Each case publishes the header, the exact \
serialized transactions, the seven-key validator context and which engine was selected, and the \
expected side publishes the verdict the reference returned, the payload read out of that \
variant, the evaluation row it belongs to, and the complete set of rules the published input \
violates — so a rejection is evidence about ordering as well as about one guard.",
        cases.clone()
    );

    let manifest = json!({
        "schema": "zro-baseline-vectors/1",
        "phase": "P4.2A",
        "group": "chain.block_structure",
        "description": "Rust-authoritative validation fixtures for the Block Structure rules B-3 \
through B-15 of `zerocoin::consensus::block::Block::validate_structure`, generated for the C++ \
kernel's future port of that function. This is a fixture-first milestone: it publishes what Rust \
returns, and it does not implement, run or claim agreement from any C++ validator.",
        "total_cases": ids.len(),
        "case_ids": ids,
        "groups": {
            "A_isolation": by_group("A"),
            "B_boundary": by_group("B"),
            "C_adjacent_pair": by_group("C"),
            "D_dominance": by_group("D"),
            "sum": by_group("A") + by_group("B") + by_group("C") + by_group("D"),
        },
        "intents": {
            "rule": by_intent("rule"),
            "boundary": by_intent("boundary"),
            "ordering": by_intent("ordering"),
        },
        "verdicts": {
            "accepted": accepted_ids.len(),
            "accepted_case_ids": accepted_ids,
            "rejected": ids.len() - accepted_ids.len(),
        },
        "rule_coverage": {
            "rules_covered": [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            "reported_by_at_least_one_case": reported_rows,
            "violated_in_at_least_one_case": violated_rows,
            "note": "`reported_by_at_least_one_case` is the set of guards some case had the \
reference actually name; `violated_in_at_least_one_case` is the set of guards some case's \
published input fails, whether or not an earlier one masked it. Both are computed from the \
cases at export, so neither is a claim this file makes on its own behalf.",
        },
        "precedence": {
            "witnesses": precedence,
            "adjacent_pairs_represented": [
                [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [9, 10], [10, 11], [11, 12], [12, 13],
                [14, 15],
            ],
            "basis": "a pair is represented when one case's published input violates both rows \
and `reported_rule` equals the smaller of them. The emitter asserts that equality for all 34 \
cases, so the array above is a summary of assertions that ran during generation, not a list of \
hopes.",
        },
        "deferred_pairs": [
            {
                "pair": [8, 9],
                "pair_before": "B-8_B-9",
                "fixture": "none",
                "reason": "`transactions.is_empty()` and `transactions.len() > \
MAX_BLOCK_TRANSACTIONS` are mutually exclusive, so no input can violate both rows at once and no \
input can distinguish the two relative orders. The relative order of B-8 and B-9 is \
observationally vacuous.",
                "not_claimed": "this corpus does not claim to have experimentally proven which of \
B-8 and B-9 a conforming port checks first, and no `.pair_08_09` case identifier exists.",
                "instead_guaranteed_by": [
                    "`.iso_08_no_transactions` and `.pair_07_08_bits_and_empty`: B-8 is reached \
without any read of `transactions[0]`, so an empty list cannot be masked by a later rule",
                    "`.iso_09_too_many_transactions`: `count == 2001` returns \
`TooManyTransactions` with the length read back out of the variant",
                    "`.pair_09_10_over_limit_and_first_not_coinbase`: B-9 dominates B-10, and the \
list carries no coinbase at all, so the verdict cannot be attributed to the coinbase scan",
                    "the emitter's per-case assertion that the derived violated set never holds \
both 8 and 9",
                ],
            },
            {
                "pair": [13, 14],
                "pair_before": "B-13_B-14",
                "fixture": "none",
                "reason": "the pair is representable — a far-future timestamp together with a stale \
root — but the corrected P4.2 design contract did not freeze a case for it, and this milestone \
does not add one. A port's ordering of these two rows is therefore not covered by this corpus \
yet.",
                "not_claimed": "nothing here asserts B-13 precedes B-14, in either direction.",
            },
        ],
        "synthetic_context_cases": synthetic_ids,
        "synthetic_context_meaning": "a case labelled synthetic deliberately combines published \
values that a running node would never produce together — `median_time_past` above `now + \
MAX_FUTURE_SECONDS`, or eleven guards broken in one block. The isolation and boundary cases reach \
their verdicts with ordinary contexts; these two need the label so no reader mistakes an \
observation about guard order for an observation about the network.",
        "reused_from_p41": reused_ids,
        "reuse_meaning": "the listed cases replay a committed `chain.claimed_merkle_root` block \
byte for byte — the same header fields, the same serialized transactions, the same seven-key \
validation context — and add only a validator-level claim P4.1 could not make. \
`p42_reference_fixtures_are_reproducible_and_pinned` compares them against \
`test/p41-vectors/chain/claimed_merkle_root.json` on disk, so the identity is checked against the \
published corpus rather than against a second copy of the same emitter call. The P4.1 corpus \
itself is not modified by this milestone.",
        "source": "cargo +stable-x86_64-pc-windows-gnu test --test export_baseline_vectors",
        "source_commit": P42_SOURCE_COMMIT,
        "source_commit_rule": "the newest commit that touches a Rust build input (`zerocoin/src`, \
`zerocoin/Cargo.toml`, `zerocoin/Cargo.lock`, `zerocoin/build.rs`) and therefore the production \
code that produced every value here; `zerocoin/src` is byte-identical between it and the baseline \
this corpus is committed on. Between it and `reference_commits.validate_structure_introduced` the \
only edit to `block.rs` extracts B-3 and B-4 into `validate_header_identity`, which changes the \
call graph and no verdict.",
        "generator": "zerocoin/tests/export_baseline_vectors.rs, `p42_*` functions, added by the \
P4.2A commit that lands immediately after the baseline; no fixture can record the hash of the \
commit that contains it, and none here claims to have existed before this exporter did",
        "reference_commits": {
            "validate_structure_introduced": P42_REFERENCE_COMMIT,
            "block_error_variants_introduced": P42_REFERENCE_COMMIT,
            "coinbase_rule_introduced": P42_REFERENCE_COMMIT,
            "max_block_transactions_introduced": P42_REFERENCE_COMMIT,
        },
        "provenance": P42_SOURCE_COMMIT.to_string() + " — see `source_commit_rule`, `generator` \
and `reference_commits`; the origin of every expected value is the Rust function named in \
`description`, called directly by the exporter",
        "regenerate": "ZRO_VECTOR_WRITE=1 with the same command, then review the diff",
        "authority_split": {
            "rust_is_the_only_origin_of": [
                "accepted", "error_kind", "error_payload", "reported_rule", "violated_rules",
                "computed_root", "claimed_root", "proof_of_work_meets_target", "coinbase_flags",
                "leaf ids and serialized transaction bytes",
            ],
            "downstream_verification_must_not_be_confused_with": "the Python harness re-derives \
transaction ids, Merkle roots and canonical serializations from the published hex as a second \
opinion about the *encoding*, and a C++ port will later be diffed against the *verdicts* in P4.2B \
(P4.2B, not this milestone). Neither one generates an expected value here, and neither one has \
been run against a C++ Block Structure validator, because this milestone does not implement one \
and claims no parity with it.",
            "exporter_declaration_check": "each fixture carries a declared construction intent — \
the design contract's predicted variant, payload and rule set — which `p42_emit` compares with \
what the reference returned and panics on if they differ. The declarations are inputs to the \
export, not fields of the corpus, so no predicted value can reach a published file.",
        },
        "independent_verifier": "test/harness/zro_vectors.py already provides the transaction \
deserializer, `tx_txid`, `tx_is_coinbase` and `merkle_root` needed to re-derive every published \
digest and every `serialized_hex` from bytes alone; `run_vectors.py` registers no verifier for \
this group and this corpus does not wire one in, so the Rust exporter remains the origin of every \
value published here",
        "determinism": [
            "no wall clock, RNG, wallet, data directory or network is used: `now` is a literal in \
every case, including the three that put it next to `u64::MAX` to separate saturating from \
wrapping addition",
            "every header nonce comes from `consensus::pow::mine`, a deterministic single-thread \
upward scan from zero, or from the same deterministic failing-nonce scan `consensus_rules.rs` \
uses; neither depends on a thread count or a clock",
            "every transaction is a literal: `coinbase_transaction` at a fixed height with the \
published key 1, one of the P0 fixture shapes from a single seed byte, or one of the two filler \
shapes with the index carried in `lock_time` so no two leaves collide",
            "the 2000 and 2001 cases are the same list at two lengths, so the accepted/rejected \
pair differs by one transaction and one root",
            "five cases are rebuilt from the committed P4.1 corpus on disk, and the rebuild is \
compared with the published bytes before anything is derived from them",
            "JSON object keys are emitted in sorted order by serde_json",
        ],
        "notes": [
            "`MAX_BLOCK_TRANSACTIONS` is 2000 and the guard is `len() > 2000`, so 2000 is \
admitted and 2001 is rejected with the length published back out of the variant.",
            "`validate_structure` is called directly, with the seven arguments the reference's own \
in-source test uses, and never through `Chain::connect_block`: the large-list transactions spend \
UTXOs that do not exist, and `connect_block` additionally runs `difficulty::validate_bits` and the \
reward and UTXO checks that a structural fixture has no business asserting.",
            "Three orderings are deliberately not conflated here: `error_kind` names the \
`BlockError` variant, `reported_rule` is the row of `validate_structure`'s body that returned it, \
and the kernel's own `BlockErrorKind` numbering is a C++-side sequence this corpus does not assign \
or assert.",
            "B-15 is reachable only when B-14 passed, which is why `.iso_15_insufficient_pow` \
claims its own root — a shape the P4.1 corpus cannot contain at all.",
            "The version field is published and never validated (F-2), so no case here depends on \
it; `BLOCK_VERSION` is written by `header_at` and read by nothing in the path under test.",
            "These 34 cases are new with the `p42_*` exporter. `reference_commits` names the commit \
whose code is under test, not the commit that introduced these cases, because a fixture cannot \
truthfully claim to predate its own generator.",
        ],
        "files": counts,
    });
    let mut text = serde_json::to_string_pretty(&manifest).expect("reference manifest serialises");
    text.push('\n');
    files.push(("manifest.json".to_string(), text));

    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn p42_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("p42-vectors")
}

#[test]
fn p42_vectors_match_the_committed_reference_corpus() {
    let write = std::env::var("ZRO_VECTOR_WRITE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let root = p42_root();
    let mut drift: Vec<String> = Vec::new();
    let mut written = 0usize;

    for (relative, text) in p42_corpus() {
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

/// The P4.2A half of the determinism gate, the schema gate, and the corpus's own consistency
/// test. Every assertion below reads only what the cases publish: each header, transaction list
/// and validator context is rebuilt from the published JSON, `Block::validate_structure` is
/// called again on that rebuilt input, and the re-call must return the variant, the payload and
/// the rule row written beside it. Nothing consults the emitters, so a case that could no longer
/// be reproduced from its own bytes fails here rather than at generation time. The five reuse
/// cases are additionally compared against `test/p41-vectors/chain/claimed_merkle_root.json` on
/// disk, which is where the byte-identity claim about P4.1 becomes executable.
#[test]
fn p42_reference_fixtures_are_reproducible_and_pinned() {
    let first = p42_corpus();
    let second = p42_corpus();
    assert_eq!(first, second, "two generations must be byte-identical");
    assert_eq!(first.len(), 2, "one group plus the manifest");
    assert_eq!(first[0].0, "chain/block_structure.json", "the group file sorts first");

    let document: Value =
        serde_json::from_str(&first[0].1).expect("the generated corpus parses as JSON");
    assert_eq!(document["schema"], json!("zro-baseline-vectors/1"), "schema");
    assert_eq!(document["group"], json!("chain.block_structure"), "group");
    assert_eq!(document["source_commit"], json!(P42_SOURCE_COMMIT), "source_commit");
    let cases = document["cases"].as_array().expect("a cases array").clone();
    assert_eq!(document["case_count"], json!(cases.len()), "case_count matches the array");
    assert_eq!(cases.len(), 34, "the pinned case count for P4.2A");

    let manifest: Value =
        serde_json::from_str(&first[1].1).expect("the generated manifest parses as JSON");
    assert_eq!(manifest["phase"], json!("P4.2A"), "phase");
    assert_eq!(manifest["group"], json!("chain.block_structure"), "manifest group");
    assert_eq!(manifest["total_cases"], json!(34), "manifest total_cases");
    assert_eq!(manifest["source_commit"], json!(P42_SOURCE_COMMIT), "manifest source_commit");
    assert_eq!(
        manifest["case_ids"].as_array().expect("case_ids").len(),
        34,
        "the manifest lists one id per case"
    );

    // The arithmetic the mission statement froze, checked against the ids actually published.
    let ids: Vec<&str> = cases.iter().map(|c| c["id"].as_str().expect("id")).collect();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), 34, "every fixture id must appear exactly once");
    for &id in &ids {
        assert!(id.starts_with("chain.block_structure."), "{id}: outside the group namespace");
        assert_ne!(id, "chain.block_structure.pair_08_09", "the deferred pair must not gain a fake case");
    }
    let count_group = |letter: &str| -> usize {
        cases
            .iter()
            .filter(|c| c["input"]["group"].as_str() == Some(letter))
            .count()
    };
    assert_eq!(count_group("A"), 14, "Group A is 14 isolation cases");
    assert_eq!(count_group("B"), 8, "Group B is 8 boundary cases");
    assert_eq!(count_group("C"), 11, "Group C is the 11 representable adjacent-pair cases");
    assert_eq!(count_group("D"), 1, "Group D is the single dominance witness");
    assert_eq!(
        manifest["groups"],
        json!({
            "A_isolation": 14,
            "B_boundary": 8,
            "C_adjacent_pair": 11,
            "D_dominance": 1,
            "sum": 34,
        }),
        "the manifest's group counts must equal the published corpus"
    );

    let (mut rule, mut boundary, mut ordering) = (0usize, 0usize, 0usize);
    let (mut accepted_count, mut rejected_count) = (0usize, 0usize);
    let mut reported: Vec<u8> = Vec::new();
    for value in &cases {
        match value["intent"].as_str().expect("intent") {
            "rule" => rule += 1,
            "boundary" => boundary += 1,
            "ordering" => ordering += 1,
            other => panic!(
                "{}: intent `{other}` is not one of rule, boundary, ordering",
                value["id"]
            ),
        }
        if value["expected"]["accepted"].as_bool().expect("accepted") {
            accepted_count += 1;
            assert_eq!(value["expected"]["error_kind"], Value::Null, "an accept publishes no variant");
            assert_eq!(value["expected"]["error_payload"], Value::Null, "an accept publishes no payload");
            assert_eq!(value["expected"]["reported_rule"], Value::Null, "an accept reports no row");
            assert_eq!(value["expected"]["violated_rules"], json!([]), "an accept implies no violated guard");
        } else {
            rejected_count += 1;
            assert!(value["expected"]["error_kind"].is_string(), "a rejection publishes a variant name");
            assert!(value["expected"]["reported_rule"].is_u64(), "a rejection publishes an evaluation row");
            assert_eq!(
                value["expected"]["is_first_violation"],
                json!(true),
                "{}: a rejection must name the earliest guard the published input fails",
                value["id"]
            );
            reported.push(value["expected"]["reported_rule"].as_u64().expect("row") as u8);
        }
    }
    assert_eq!((rule, boundary, ordering), (14, 8, 12), "the published intent mix");
    assert_eq!((accepted_count, rejected_count), (5, 29), "the published verdict mix");
    reported.sort_unstable();
    reported.dedup();
    assert_eq!(
        reported,
        (3u8..=15).collect::<Vec<u8>>(),
        "every guard B-3 through B-15 has to be the reported one in at least one case"
    );

    // Rebuild and re-validate every case from its published bytes alone.
    let trivial = TrivialEngine::new();
    let scratchpad = ScratchPadEngine::balanced();
    let raw_digest = |text: &str| -> Hash256 {
        Hash256::from_slice(&hex::decode(text).expect("published hex decodes"))
            .expect("a published digest is one sha256d wide")
    };
    let internal = |value: &Value| -> String {
        value["internal_hex"]
            .as_str()
            .expect("a published digest carries internal_hex")
            .to_string()
    };
    for case in &cases {
        let id = case["id"].as_str().expect("id");
        let header_json = &case["input"]["header"];
        let header = BlockHeader {
            version: header_json["version"].as_u64().expect("version") as u32,
            chain: header_json["chain"].as_u64().expect("chain") as u32,
            height: header_json["height"].as_u64().expect("height"),
            previous_hash: raw_digest(header_json["previous_hash_hex"].as_str().expect("previous")),
            merkle_root: raw_digest(header_json["merkle_root_hex"].as_str().expect("root")),
            timestamp: header_json["timestamp"].as_u64().expect("timestamp"),
            difficulty_bits: header_json["difficulty_bits"].as_u64().expect("bits") as u32,
            engine_id: header_json["engine_id"].as_u64().expect("engine_id") as u8,
            nonce: header_json["nonce"].as_u64().expect("nonce"),
        };
        assert_eq!(header_input(&header), *header_json, "{id}: the header does not round-trip through its published form");

        let context_json = &case["input"]["validation_context"];
        let name = context_json["engine"].as_str().expect("engine");
        let (engine, selected): (Box<dyn PowEngine>, P42Engine) = if name == trivial.name() {
            (Box::new(trivial), P42Engine::Trivial)
        } else if name == scratchpad.name() {
            (Box::new(scratchpad), P42Engine::ScratchPad)
        } else {
            panic!("{id}: `{name}` is not an engine this corpus knows");
        };
        let context = P42Context {
            expected_chain: context_json["expected_chain"].as_u64().expect("expected_chain") as u32,
            expected_height: context_json["expected_height"].as_u64().expect("expected_height"),
            expected_previous: raw_digest(
                context_json["expected_previous_hex"].as_str().expect("expected_previous_hex"),
            ),
            expected_bits: context_json["expected_bits"].as_u64().expect("expected_bits") as u32,
            median_time_past: context_json["median_time_past"].as_u64().expect("median_time_past"),
            now: context_json["now"].as_u64().expect("now"),
            engine: selected,
        };
        assert_eq!(context.json(), *context_json, "{id}: the context does not round-trip through its published form");

        let from_bytes = |hex_text: &str| -> Transaction {
            let bytes = hex::decode(hex_text).expect("a published serialization is hex");
            let tx = Transaction::deserialize(&bytes)
                .unwrap_or_else(|error| panic!("{id}: a published transaction: {error}"));
            assert_eq!(hx(&tx.serialize()), hex_text, "{id}: canonical serialization is not the published byte string");
            tx
        };
        let transactions: Vec<Transaction> = match case["input"]["transactions"].as_array() {
            Some(entries) => entries
                .iter()
                .map(|entry| from_bytes(entry["serialized_hex"].as_str().expect("serialized_hex")))
                .collect(),
            None => case["input"]["transactions_hex"]
                .as_array()
                .expect("a long list publishes transactions_hex")
                .iter()
                .map(|entry| from_bytes(entry.as_str().expect("a hex string")))
                .collect(),
        };
        assert_eq!(
            transactions.len(),
            case["input"]["tx_count"].as_u64().expect("tx_count") as usize,
            "{id}: tx_count disagrees with the published list"
        );

        let computed = Block::compute_merkle_root(&transactions);
        assert_eq!(
            internal(&case["expected"]["computed_root"]),
            hx(&computed.0),
            "{id}: the published computed root is not the root of the published list"
        );
        assert_eq!(
            case["expected"]["roots_match"],
            json!(computed.0 == header.merkle_root.0),
            "{id}: roots_match disagrees with the two published digests"
        );
        assert_eq!(
            case["expected"]["proof_of_work_meets_target"],
            json!(header.meets_own_target(engine.as_ref())),
            "{id}: the published proof-of-work status is not what the selected engine reports"
        );
        let flags: String = transactions
            .iter()
            .map(|tx| if tx.is_coinbase() { '1' } else { '0' })
            .collect();
        assert_eq!(case["expected"]["coinbase_flags"], json!(flags), "{id}: coinbase_flags disagrees with `Transaction::is_coinbase`");
        assert_eq!(
            case["expected"]["first_is_coinbase"],
            json!(transactions.first().map_or(false, Transaction::is_coinbase)),
            "{id}: first_is_coinbase disagrees with the published list"
        );
        if let Some(leaves) = case["expected"]["leaves"].as_array() {
            assert_eq!(
                leaves.len(),
                transactions.len(),
                "{id}: one published leaf per published transaction"
            );
            for (index, leaf) in leaves.iter().enumerate() {
                assert_eq!(
                    internal(&leaf["txid"]),
                    hx(&transactions[index].txid().0),
                    "{id}: leaf {index} is not `Transaction::txid` of the published transaction"
                );
            }
        } else {
            assert!(transactions.len() > P42_VERBOSE_LIMIT, "{id}: a short list must publish its leaves");
        }

        let outcome = Block {
            header: header.clone(),
            transactions: transactions.clone(),
        }
        .validate_structure(
            engine.as_ref(),
            context.expected_chain,
            context.expected_height,
            &context.expected_previous,
            context.expected_bits,
            context.median_time_past,
            context.now,
        );
        let kind = match &outcome {
            Ok(()) => "Ok",
            Err(error) => block_error_kind(error),
        };
        assert_eq!(
            case["expected"]["error_kind"],
            if kind == "Ok" { json!(null) } else { json!(kind) },
            "{id}: the reference no longer returns the published variant"
        );
        assert_eq!(
            case["expected"]["accepted"],
            json!(outcome.is_ok()),
            "{id}: the published accept no longer matches the reference"
        );
        match &outcome {
            Ok(()) => assert_eq!(
                violated_of(&header, &transactions, &context, engine.as_ref(), &computed),
                Vec::<u8>::new(),
                "{id}: the published input violates a guard while the reference accepts"
            ),
            Err(error) => {
                assert_eq!(
                    p42_canonical(&block_error_payload(error)),
                    p42_canonical(&case["expected"]["error_payload"]),
                    "{id}: the reference no longer returns the published payload"
                );
                let violated = violated_of(&header, &transactions, &context, engine.as_ref(), &computed);
                assert_eq!(
                    case["expected"]["violated_rules"],
                    json!(violated),
                    "{id}: the published violated_rules no longer re-derives from the published input"
                );
                assert_eq!(
                    block_error_rule(error),
                    violated[0],
                    "{id}: the published rejection no longer names the earliest violated guard"
                );
            }
        }
    }

    // The five reuse cases must be the committed P4.1 blocks, byte for byte, on disk.
    let p41_path = p41_root().join("chain").join("claimed_merkle_root.json");
    let p41_text = fs::read_to_string(&p41_path)
        .unwrap_or_else(|error| panic!("reading the committed P4.1 corpus at {}: {error}", p41_path.display()));
    let p41: Value = serde_json::from_str(&p41_text).expect("the P4.1 corpus parses");
    assert_eq!(
        p41["cases"].as_array().expect("P4.1 cases").len(),
        30,
        "P4.1 must still be the 30-case corpus this milestone replays"
    );
    assert_eq!(p41["source_commit"], json!(P41_SOURCE_COMMIT), "the P4.1 corpus is unchanged");
    let p41_case = |name: &str| -> Value {
        let id = format!("chain.claimed_merkle_root.{name}");
        p41["cases"]
            .as_array()
            .expect("P4.1 cases")
            .iter()
            .find(|c| c["id"].as_str() == Some(id.as_str()))
            .cloned()
            .unwrap_or_else(|| panic!("{id}: missing from the committed P4.1 corpus"))
    };
    let hex_list = |case: &Value| -> Vec<String> {
        match case["input"]["transactions"].as_array() {
            Some(entries) => entries
                .iter()
                .map(|e| e["serialized_hex"].as_str().expect("serialized_hex").to_string())
                .collect(),
            None => case["input"]["transactions_hex"]
                .as_array()
                .expect("transactions_hex")
                .iter()
                .map(|e| e.as_str().expect("hex").to_string())
                .collect(),
        }
    };
    for case in &cases {
        let source = match case["input"]["reused_from"].as_str() {
            Some(source) => source,
            None => continue,
        };
        let name = source
            .strip_prefix("chain.claimed_merkle_root.")
            .expect("a reused_from names a P4.1 case");
        let original = p41_case(name);
        let id = case["id"].as_str().expect("id");
        assert_eq!(
            case["input"]["header"], original["input"]["header"],
            "{id}: the reused header is not the header P4.1 published"
        );
        assert_eq!(
            case["input"]["validation_context"], original["input"]["validation_context"],
            "{id}: the reused context is not the context P4.1 published"
        );
        assert_eq!(
            hex_list(case),
            hex_list(&original),
            "{id}: the reused transaction bytes are not the bytes P4.1 published"
        );
        assert_eq!(
            case["expected"]["roots_match"], original["expected"]["roots_match"],
            "{id}: the reused block's root status drifted from P4.1's"
        );
        assert_eq!(
            case["expected"]["proof_of_work_meets_target"],
            original["expected"]["proof_of_work_meets_target"],
            "{id}: the reused block's proof-of-work status drifted from P4.1's"
        );
    }
    assert_eq!(
        cases
            .iter()
            .filter(|c| c["input"]["reused_from"].is_string())
            .count(),
        5,
        "exactly five cases replay a committed P4.1 block"
    );
    // P4.1 already recorded, for its own empty-list case, which guard fired before the
    // comparison. The validator-level claim published beside `.iso_08_no_transactions` has to be
    // the same variant, or the two corpora disagree about a block neither of them changed.
    let empty = p41_case("empty_list_matching_claim");
    assert_eq!(
        empty["expected"]["guard_before_comparison"]["error_kind"],
        json!("NoTransactions"),
        "P4.1's recorded pre-comparison guard changed, so the reuse pairing above needs revisiting"
    );
    assert_eq!(
        cases
            .iter()
            .find(|c| c["input"]["reused_from"] == json!("chain.claimed_merkle_root.empty_list_matching_claim"))
            .expect(".iso_08 reuses the empty list")
            ["expected"]["error_kind"],
        json!("NoTransactions"),
        "the validator and the recorded guard no longer agree about the empty list"
    );

    // The literals the section's comments promise, asserted rather than trusted.
    assert_eq!(MAX_BLOCK_TRANSACTIONS, 2_000, "the B-9 limit this corpus is built around");
    assert_eq!(MAX_FUTURE_SECONDS, 7_200, "the B-13 window this corpus is built around");
    assert_eq!(P42_LIMIT, P42_NOW + MAX_FUTURE_SECONDS, "the anchor limit literal");
    assert_eq!(P42_OVER_LIMIT, P42_LIMIT + 1, "the one-past-limit literal");
    assert_eq!(P42_ANCHOR_TS, header_at(P42_HEIGHT, 0).timestamp, "the anchor timestamp literal");
    assert_eq!(P42_MEDIAN + 1, P42_ANCHOR_TS, "the B-12 isolation rests on this adjacency");
    assert_eq!(P42_EDGE_NOW, u64::MAX - MAX_FUTURE_SECONDS - 1, "the first saturating-edge literal");
    assert_eq!(
        P42_LAST_EXACT_NOW.saturating_add(MAX_FUTURE_SECONDS),
        u64::MAX,
        "the last exact limit literal"
    );
    assert_eq!(
        P42_NOW.wrapping_add(MAX_FUTURE_SECONDS),
        P42_NOW + MAX_FUTURE_SECONDS,
        "the anchor clock must be far from the saturation point: wrapping and checked addition agree"
    );
    assert_eq!(
        P42_EDGE_NOW.saturating_add(MAX_FUTURE_SECONDS),
        u64::MAX - 1,
        "at the first edge the limit is one below `u64::MAX`, so a timestamp of `u64::MAX` is rejected"
    );
}

/// The violated-rule set recomputed inside the pinned test from published input alone. The same
/// pure predicate list `p42_emit` uses, called from the rebuilt values rather than the specs.
fn violated_of(
    header: &BlockHeader,
    transactions: &[Transaction],
    context: &P42Context,
    engine: &dyn PowEngine,
    computed: &Hash256,
) -> Vec<u8> {
    p42_violated_rules(header, transactions, context, engine, computed)
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
