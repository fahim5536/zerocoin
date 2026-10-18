//! P1 consensus regression tests.
//!
//! These tests pin the behavior documented in `docs/consensus/CONSENSUS_RULES.md`.
//! They deliberately **reuse** values that already exist in the repository:
//!
//! - the pinned genesis and state-root anchors from `consensus::immutability`
//!   (which the P0 corpus `test/vectors/chain/anchors.json` also pins),
//! - the reward constants and subsidy table from `reward::*`
//!   (`test/vectors/reward/*.json`),
//! - the difficulty parameters and `validate_bits` vector outcomes
//!   (`test/vectors/difficulty/retarget.json`).
//!
//! No expected hash, reward, or consensus value is invented here. Where a test
//! asserts a numeric edge, the number is either a published constant, an anchor,
//! or arithmetic on one of those.
//!
//! Regtest (Trivial PoW, no retarget) is used for chain tests so blocks are mined
//! instantly and deterministically.

use zerocoin::chain::{Chain, ChainError, CoinInfo};
use zerocoin::consensus::block::{
    Block, BlockError, BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS, MAX_FUTURE_SECONDS,
};
use zerocoin::consensus::difficulty::{
    compact_to_target, next_difficulty, validate_bits, DifficultyError, DIFFICULTY_PARAMS,
};
use zerocoin::consensus::immutability::{
    EMPTY_STATE_ROOT, GENESIS_COINBASE_TXID, GENESIS_HASH_REGTEST, GENESIS_MERKLE_ROOT,
};
use zerocoin::consensus::pow::{mine, PowEngine, ENGINE_ID_SCRATCHPAD, ENGINE_ID_TRIVIAL};
use zerocoin::consensus::reward::{
    block_subsidy, coinbase_transaction, validate_coinbase, RewardError, COINBASE_MATURITY,
    MAX_SUPPLY,
};
use zerocoin::crypto::hash::{Hash160, Hash256};
use zerocoin::crypto::secp256k1::{PrivateKey, PublicKey};
use zerocoin::ledger::script::{p2pkh_script_pubkey, p2pkh_script_sig};
use zerocoin::ledger::sighash::{signature_hash, SIGHASH_ALL};
use zerocoin::ledger::transaction::{
    write_varint, Outpoint, Transaction, TxDecodeError, TxIn, TxOut, MAX_TX_BYTES,
};
use zerocoin::ledger::utxo::{UtxoError, UtxoSet};
use zerocoin::params::{ChainParams, GENESIS_TIMESTAMP};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn key(seed: u8) -> PrivateKey {
    PrivateKey::from_bytes([seed; 32]).expect("seed is a valid scalar")
}

fn regtest() -> Chain {
    Chain::in_memory(ChainParams::regtest()).expect("regtest chain opens")
}

fn trivial_engine() -> Box<dyn PowEngine> {
    ChainParams::regtest().build_engine()
}

/// Re-solve the proof of work after mutating a header field that is part of the
/// preimage. Regtest's target is trivial, so this is effectively instantaneous.
fn remine(chain: &Chain, mut block: Block) -> Block {
    let engine = chain.params().build_engine();
    let target = compact_to_target(block.header.difficulty_bits);
    let (nonce, _) = mine(engine.as_ref(), &block.header.preimage(), &target, 0).expect("mines");
    block.header.nonce = nonce;
    block
}

/// Validate a block against a *fresh* regtest chain whose tip is genesis, so the
/// block is judged as a candidate for height 1 (rule B-4 / B-5).
fn structure_error(block: Block, now: u64) -> BlockError {
    let mut chain = regtest();
    match chain.connect_block(block, now) {
        Err(ChainError::Structure(e)) => e,
        other => panic!("expected a structural rejection, got {other:?}"),
    }
}

fn non_coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint {
                txid: Hash256([0x11; 32]),
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: Vec::new(),
        lock_time: 0,
    }
}

fn sign_input(chain: &Chain, sk: &PrivateKey, tx: &mut Transaction, script_code: &[u8]) {
    let digest = signature_hash(tx, 0, script_code, chain.chain_id(), SIGHASH_ALL)
        .expect("input 0 is in range");
    let mut sig = sk.sign(&digest).expect("signs").to_der().to_vec();
    sig.push(SIGHASH_ALL as u8);
    tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &sk.public_key().to_sec1());
}

struct Funded {
    chain: Chain,
    key: PrivateKey,
    pubkey: PublicKey,
    coin: CoinInfo,
}

/// A regtest chain at height 100 where the miner's height-1 coinbase is spendable
/// by the next block (height 101). Rule U-1.
fn funded_chain() -> Funded {
    let mut chain = regtest();
    let sk = key(11);
    let pk = sk.public_key();
    let mut now = GENESIS_TIMESTAMP + 1_000;
    chain.mine_block(&pk, vec![], now).expect("mines height 1");
    for _ in 0..99 {
        now += 1;
        chain.mine_block(&pk, vec![], now).expect("mines");
    }
    assert_eq!(chain.height(), 100);
    let coin = chain
        .coins_for_pubkey_hash(&pk.key_hash())
        .into_iter()
        .find(|c| c.height == 1)
        .expect("height-1 coinbase exists");
    assert!(coin.spendable, "100 confirmations must unlock the coin");
    Funded {
        chain,
        key: sk,
        pubkey: pk,
        coin,
    }
}

fn spend(f: &Funded, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: f.coin.outpoint,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs,
        lock_time: 0,
    }
}

// ---------------------------------------------------------------------------
// Genesis and anchors
// ---------------------------------------------------------------------------

#[test]
fn regtest_genesis_matches_the_pinned_anchors() {
    let chain = regtest();
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.tip_hash(), GENESIS_HASH_REGTEST);
    assert_eq!(chain.subsidy_issued(), 0, "genesis mints nothing");
    assert!(chain.utxo().is_empty(), "no coins exist at launch");
    assert_eq!(chain.utxo().state_root(), EMPTY_STATE_ROOT);

    let genesis = chain.block_at(0).expect("genesis is stored");
    assert_eq!(genesis.transactions.len(), 1);
    assert_eq!(genesis.transactions[0].txid(), GENESIS_COINBASE_TXID);
    assert_eq!(genesis.header.merkle_root, GENESIS_MERKLE_ROOT);
    assert_eq!(genesis.header.version, BLOCK_VERSION);
    assert_eq!(genesis.header.previous_hash, Hash256::ZERO);
    assert_eq!(genesis.header.timestamp, GENESIS_TIMESTAMP);
    assert_eq!(genesis.header.difficulty_bits, chain.params().genesis_bits);
    assert!(
        genesis.transactions[0].outputs.is_empty(),
        "the zero-premine coinbase creates no outputs"
    );
}

// ---------------------------------------------------------------------------
// Structural block validation (rules B-3 .. B-15)
// ---------------------------------------------------------------------------

#[test]
fn structural_rejections_follow_the_documented_order() {
    let mut source = regtest();
    let miner = key(1).public_key();
    let now = GENESIS_TIMESTAMP + 1_000;
    let base = source.mine_block(&miner, vec![], now).expect("mines height 1");

    // Baseline: the untouched block connects to a fresh chain at the same tip.
    assert!(regtest().connect_block(base.clone(), now).is_ok());

    let mut b = base.clone();
    b.header.chain = ChainParams::devnet().chain_id.0;
    assert!(matches!(structure_error(b, now), BlockError::WrongChain { .. }));

    let mut b = base.clone();
    b.header.height = 99;
    assert!(matches!(
        structure_error(b, now),
        BlockError::BadHeight { expected: 1, found: 99 }
    ));

    let mut b = base.clone();
    b.header.previous_hash = Hash256([0xAA; 32]);
    assert!(matches!(structure_error(b, now), BlockError::BadPreviousHash));

    let mut b = base.clone();
    b.header.engine_id = ENGINE_ID_SCRATCHPAD;
    assert!(matches!(structure_error(b, now), BlockError::WrongEngine { .. }));

    let mut b = base.clone();
    b.header.difficulty_bits = chain_bits() - 1;
    assert!(matches!(structure_error(b, now), BlockError::BadDifficulty { .. }));

    let mut b = base.clone();
    b.transactions.clear();
    assert!(matches!(structure_error(b, now), BlockError::NoTransactions));

    let mut b = base.clone();
    b.transactions = vec![base.transactions[0].clone(); MAX_BLOCK_TRANSACTIONS + 1];
    assert!(matches!(
        structure_error(b, now),
        BlockError::TooManyTransactions(n) if n == MAX_BLOCK_TRANSACTIONS + 1
    ));

    let mut b = base.clone();
    b.transactions[0] = non_coinbase();
    assert!(matches!(structure_error(b, now), BlockError::FirstNotCoinbase));

    let mut b = base.clone();
    b.transactions.push(b.transactions[0].clone());
    assert!(matches!(structure_error(b, now), BlockError::DuplicateCoinbase));

    let mut b = base.clone();
    b.header.timestamp = GENESIS_TIMESTAMP; // equal to MTP: rejected (<=)
    assert!(matches!(
        structure_error(b, now),
        BlockError::TimestampTooOld { median, found }
            if median == GENESIS_TIMESTAMP && found == GENESIS_TIMESTAMP
    ));

    let mut b = base.clone();
    b.header.timestamp = now + MAX_FUTURE_SECONDS + 1;
    assert!(matches!(
        structure_error(b, now),
        BlockError::TimestampTooFarFuture { .. }
    ));

    let mut b = base.clone();
    b.transactions[0].outputs[0].value += 1;
    assert!(matches!(structure_error(b, now), BlockError::RootMismatch));

    // Find a nonce whose hash misses the (trivial) target, deterministically.
    let engine = trivial_engine();
    let mut b = base.clone();
    let bad_nonce = (0u64..512)
        .find(|n| {
            b.header.nonce = *n;
            !b.header.meets_own_target(engine.as_ref())
        })
        .expect("a 50% target yields a failing nonce within 512 tries");
    b.header.nonce = bad_nonce;
    assert!(matches!(
        structure_error(b, now),
        BlockError::InsufficientProofOfWork
    ));
}

fn chain_bits() -> u32 {
    ChainParams::regtest().genesis_bits
}

#[test]
fn transaction_count_boundary_is_two_thousand() {
    let mut source = regtest();
    let miner = key(2).public_key();
    let now = GENESIS_TIMESTAMP + 1_000;
    let base = source.mine_block(&miner, vec![], now).expect("mines");
    let coinbase = base.transactions[0].clone();

    // 2001 entries: the count rule fires first (B-9 before B-11).
    let mut b = base.clone();
    b.transactions = vec![coinbase.clone(); MAX_BLOCK_TRANSACTIONS + 1];
    assert!(matches!(
        structure_error(b, now),
        BlockError::TooManyTransactions(2001)
    ));

    // Exactly 2000 entries is structurally allowed; the duplicate coinbase is then
    // what rejects the block (B-11), proving the boundary is `> 2000`.
    let mut b = base.clone();
    b.transactions = vec![coinbase; MAX_BLOCK_TRANSACTIONS];
    assert!(matches!(structure_error(b, now), BlockError::DuplicateCoinbase));
}

#[test]
fn timestamp_boundaries_are_strictly_above_median_and_at_most_two_hours_ahead() {
    let mut source = regtest();
    let miner = key(3).public_key();
    let base = source
        .mine_block(&miner, vec![], GENESIS_TIMESTAMP + 1_000)
        .expect("mines");

    // MTP + 1 is the first admissible timestamp (B-12 is `<=`, so MTP itself fails).
    let mut b = base.clone();
    b.header.timestamp = GENESIS_TIMESTAMP + 1;
    let b = remine(&source, b);
    assert!(regtest().connect_block(b, GENESIS_TIMESTAMP).is_ok());

    // now + 7200 is accepted (B-13 is `>`).
    let mut b = base.clone();
    b.header.timestamp = GENESIS_TIMESTAMP + MAX_FUTURE_SECONDS;
    let accepted = remine(&source, b);
    assert!(regtest().connect_block(accepted.clone(), GENESIS_TIMESTAMP).is_ok());

    // One second later is rejected.
    let mut too_late = accepted;
    too_late.header.timestamp += 1;
    assert!(matches!(
        structure_error(too_late, GENESIS_TIMESTAMP),
        BlockError::TimestampTooFarFuture { .. }
    ));
}

#[test]
fn merkle_mismatch_is_reported_before_proof_of_work() {
    let mut source = regtest();
    let miner = key(4).public_key();
    let now = GENESIS_TIMESTAMP + 1_000;
    let base = source.mine_block(&miner, vec![], now).expect("mines");

    // Mutating a transaction invalidates both the merkle root and (because the root
    // is in the preimage) the proof of work. Rule B-14 runs first.
    let mut b = base;
    b.transactions[0].outputs[0].value += 1;
    assert!(matches!(structure_error(b, now), BlockError::RootMismatch));
}

#[test]
fn block_version_is_not_validated() {
    // F-2: `BLOCK_VERSION` is written, never checked. Both an old and an absurd
    // version are accepted when the proof of work is re-solved.
    let mut source = regtest();
    let miner = key(5).public_key();
    let now = GENESIS_TIMESTAMP + 1_000;
    let base = source.mine_block(&miner, vec![], now).expect("mines");

    for version in [0u32, u32::MAX] {
        let mut b = base.clone();
        b.header.version = version;
        let b = remine(&source, b);
        assert!(
            regtest().connect_block(b, now).is_ok(),
            "version {version} must be ignored"
        );
    }
}

// ---------------------------------------------------------------------------
// Coinbase rewards (rules R-3 .. R-12)
// ---------------------------------------------------------------------------

#[test]
fn coinbase_claim_must_cover_fees_and_may_not_exceed_reward() {
    let pk = key(6).public_key();
    let height = 1u64;
    let subsidy = block_subsidy(height);
    let fees = 1_000u64;

    // Exactly subsidy + fees is the maximum admissible claim.
    let exact = coinbase_transaction(height, &pk, subsidy + fees);
    assert_eq!(
        validate_coinbase(&exact, height, fees, 0).expect("exact claim is valid"),
        subsidy + fees
    );

    // One Fah more is inflation.
    let over = coinbase_transaction(height, &pk, subsidy + fees + 1);
    assert!(matches!(
        validate_coinbase(&over, height, fees, 0),
        Err(RewardError::TooMuchReward { .. })
    ));

    // Claiming less than the subsidy is allowed (value is simply not minted) ...
    let under = coinbase_transaction(height, &pk, fees);
    assert_eq!(
        validate_coinbase(&under, height, fees, 0).expect("under-claiming the subsidy is allowed"),
        fees
    );

    // ... but claiming less than the fees is not (R-11).
    let below = coinbase_transaction(height, &pk, fees - 1);
    assert!(matches!(
        validate_coinbase(&below, height, fees, 0),
        Err(RewardError::BelowFees { claimed, fees: f }) if claimed == fees - 1 && f == fees
    ));
}

#[test]
fn coinbase_checks_run_in_the_documented_order() {
    let pk = key(7).public_key();

    // R-3: only a coinbase may be validated.
    assert!(matches!(
        validate_coinbase(&non_coinbase(), 1, 0, 0),
        Err(RewardError::NotCoinbase)
    ));

    // R-4: the height commitment is mandatory.
    let mut no_height = coinbase_transaction(1, &pk, 0);
    no_height.inputs[0].script_sig.clear();
    assert!(matches!(
        validate_coinbase(&no_height, 1, 0, 0),
        Err(RewardError::MissingHeightCommitment)
    ));

    // R-5: the committed height must match the block height.
    let wrong_height = coinbase_transaction(7, &pk, 0);
    assert!(matches!(
        validate_coinbase(&wrong_height, 8, 0, 0),
        Err(RewardError::BadCoinbaseHeight {
            expected: 8,
            found: 7
        })
    ));

    // R-7: height 0 may not claim anything, even if the arithmetic would allow it.
    let premine = coinbase_transaction(0, &pk, 1);
    assert!(matches!(
        validate_coinbase(&premine, 0, 0, 0),
        Err(RewardError::GenesisPremine { claimed: 1 })
    ));

    // R-6: output summation overflow is reported before the reward comparison.
    let mut overflow = coinbase_transaction(1, &pk, u64::MAX);
    overflow.outputs[0].value = u64::MAX;
    overflow.outputs.push(TxOut {
        value: u64::MAX,
        script_pubkey: p2pkh_script_pubkey(&pk.key_hash()),
    });
    assert!(matches!(
        validate_coinbase(&overflow, 1, 0, 0),
        Err(RewardError::RewardOverflow)
    ));

    // R-10: the cap is checked against the subsidy; MAX_SUPPLY already issued means
    // the next subsidy can never be minted.
    let coinbase = coinbase_transaction(1, &pk, block_subsidy(1));
    assert!(matches!(
        validate_coinbase(&coinbase, 1, 0, MAX_SUPPLY),
        Err(RewardError::SupplyCapExceeded { .. })
    ));
    // One subsidy of headroom remains admissible.
    assert_eq!(
        validate_coinbase(&coinbase, 1, 0, MAX_SUPPLY - block_subsidy(1))
            .expect("the last subsidy fits the cap"),
        block_subsidy(1)
    );
}

// ---------------------------------------------------------------------------
// UTXO transitions, maturity, and transaction validity
// ---------------------------------------------------------------------------

#[test]
fn maturity_boundary_is_exactly_one_hundred_blocks() {
    let mut chain = regtest();
    let sk = key(8);
    let pk = sk.public_key();
    let recipient = key(9).public_key();
    let mut now = GENESIS_TIMESTAMP + 1_000;

    chain.mine_block(&pk, vec![], now).expect("mines height 1");
    for _ in 0..98 {
        now += 1;
        chain.mine_block(&pk, vec![], now).expect("mines");
    }
    assert_eq!(chain.height(), 99, "the next block is height 100");

    let coin = chain
        .coins_for_pubkey_hash(&pk.key_hash())
        .into_iter()
        .find(|c| c.height == 1)
        .expect("height-1 coinbase exists");
    let script_code = p2pkh_script_pubkey(&pk.key_hash());
    let amount = 1_000_000u64;
    let fee = 1_000u64;
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: coin.outpoint,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![
            TxOut {
                value: amount,
                script_pubkey: p2pkh_script_pubkey(&recipient.key_hash()),
            },
            TxOut {
                value: coin.value - amount - fee,
                script_pubkey: script_code.clone(),
            },
        ],
        lock_time: 0,
    };
    sign_input(&chain, &sk, &mut tx, &script_code);

    // Spent at height 100: one block too early (spendable_at == 101).
    assert!(matches!(
        chain.validate_transaction(&tx),
        Err(ChainError::Utxo(UtxoError::ImmatureCoinbase { matures: 101, spent: 100, .. }))
    ));

    // Mined into height 100, making the next block 101.
    now += 1;
    chain.mine_block(&pk, vec![], now).expect("mines height 100");

    // Spent at height 101: the exact maturity boundary.
    assert_eq!(chain.validate_transaction(&tx).expect("mature"), fee);

    now += 1;
    chain
        .mine_block(&pk, vec![tx], now)
        .expect("a mature spend is included");
    assert_eq!(chain.balance_of_pubkey_hash(&recipient.key_hash()), amount);
}

#[test]
fn invalid_transactions_are_rejected_with_specific_errors() {
    let f = funded_chain();
    let pk = f.pubkey.key_hash();
    let script_code = p2pkh_script_pubkey(&pk);

    // No inputs at all.
    let empty = Transaction {
        version: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
    };
    assert!(matches!(
        f.chain.validate_transaction(&empty),
        Err(ChainError::Utxo(UtxoError::NoInputs))
    ));

    // Unknown outpoint.
    let mut missing = spend(
        &f,
        vec![TxOut {
            value: 1,
            script_pubkey: p2pkh_script_pubkey(&pk),
        }],
    );
    missing.inputs[0].previous_output = Outpoint {
        txid: Hash256([0xEE; 32]),
        vout: 0,
    };
    assert!(matches!(
        f.chain.validate_transaction(&missing),
        Err(ChainError::Utxo(UtxoError::MissingInput(_)))
    ));

    // Same outpoint twice in one transaction (checked before existence).
    let mut double = spend(&f, Vec::new());
    double.inputs.push(double.inputs[0].clone());
    assert!(matches!(
        f.chain.validate_transaction(&double),
        Err(ChainError::Utxo(UtxoError::DoubleSpend(_)))
    ));

    // Valid signature, but more value out than in.
    let mut negative = spend(
        &f,
        vec![TxOut {
            value: f.coin.value + 1,
            script_pubkey: p2pkh_script_pubkey(&pk),
        }],
    );
    sign_input(&f.chain, &f.key, &mut negative, &script_code);
    assert!(matches!(
        f.chain.validate_transaction(&negative),
        Err(ChainError::Utxo(UtxoError::NegativeFee { .. }))
    ));

    // Output sum overflows u64 before the negative-fee comparison.
    let mut overflow = spend(
        &f,
        vec![
            TxOut {
                value: u64::MAX,
                script_pubkey: p2pkh_script_pubkey(&pk),
            },
            TxOut {
                value: u64::MAX,
                script_pubkey: p2pkh_script_pubkey(&pk),
            },
        ],
    );
    sign_input(&f.chain, &f.key, &mut overflow, &script_code);
    assert!(matches!(
        f.chain.validate_transaction(&overflow),
        Err(ChainError::Utxo(UtxoError::OutputOverflow))
    ));

    // A corrupt unlocking script fails verification.
    let mut bad_script = spend(
        &f,
        vec![TxOut {
            value: f.coin.value,
            script_pubkey: p2pkh_script_pubkey(&pk),
        }],
    );
    bad_script.inputs[0].script_sig = vec![0x00];
    assert!(matches!(
        f.chain.validate_transaction(&bad_script),
        Err(ChainError::Utxo(UtxoError::ScriptInvalid { index: 0, .. }))
    ));

    // Replaying the funding outpoint after it is spent reports a missing input.
    let mut spent_twice_in_blocks = spend(
        &f,
        vec![TxOut {
            value: 1,
            script_pubkey: p2pkh_script_pubkey(&pk),
        }],
    );
    sign_input(&f.chain, &f.key, &mut spent_twice_in_blocks, &script_code);
    let mut chain = f.chain;
    let mut replay = spent_twice_in_blocks.clone();
    chain
        .mine_block(&f.pubkey, vec![spent_twice_in_blocks], GENESIS_TIMESTAMP + 5_000)
        .expect("the first spend is mined");
    sign_input(&chain, &f.key, &mut replay, &script_code);
    assert!(matches!(
        chain.validate_transaction(&replay),
        Err(ChainError::Utxo(UtxoError::MissingInput(_)))
    ));
}

// ---------------------------------------------------------------------------
// Transaction decoding (rule T-1) and F-5
// ---------------------------------------------------------------------------

#[test]
fn malformed_transactions_are_rejected() {
    let tx = coinbase_transaction(1, &key(10).public_key(), 5_000_000_000);
    let bytes = tx.serialize();
    assert_eq!(bytes[4], 1, "version(4) is followed by a one-byte input count");

    // Truncation.
    let truncated = &bytes[..bytes.len() - 1];
    assert!(matches!(
        Transaction::deserialize(truncated),
        Err(TxDecodeError::Truncated(_))
    ));

    // Non-minimal varint for the input count: 1 encoded as 0xfd 01 00.
    let mut non_minimal = bytes.clone();
    non_minimal.splice(4..5, [0xfd, 0x01, 0x00]);
    assert!(matches!(
        Transaction::deserialize(&non_minimal),
        Err(TxDecodeError::NonMinimalVarInt)
    ));

    // Input count over the limit; the count is rejected before any input is read.
    let mut too_many_inputs = Vec::new();
    too_many_inputs.extend_from_slice(&1i32.to_le_bytes());
    write_varint(10_001, &mut too_many_inputs);
    assert!(matches!(
        Transaction::deserialize(&too_many_inputs),
        Err(TxDecodeError::TooManyInputs(10_001))
    ));

    // Output count over the limit (zero inputs, then the oversized count).
    let mut too_many_outputs = Vec::new();
    too_many_outputs.extend_from_slice(&1i32.to_le_bytes());
    write_varint(0, &mut too_many_outputs);
    write_varint(10_001, &mut too_many_outputs);
    assert!(matches!(
        Transaction::deserialize(&too_many_outputs),
        Err(TxDecodeError::TooManyOutputs(10_001))
    ));

    // Script length over the limit; rejected before the bytes are read.
    let mut oversized = Vec::new();
    oversized.extend_from_slice(&1i32.to_le_bytes());
    write_varint(1, &mut oversized);
    oversized.extend_from_slice(&[0u8; 32]);
    oversized.extend_from_slice(&0u32.to_le_bytes());
    write_varint((MAX_TX_BYTES + 1) as u64, &mut oversized);
    assert!(matches!(
        Transaction::deserialize(&oversized),
        Err(TxDecodeError::ScriptTooLarge(n)) if n == MAX_TX_BYTES + 1
    ));
}

#[test]
fn trailing_bytes_after_a_transaction_are_ignored() {
    // F-5: decoding stops at the end of the transaction; the txid commits to the
    // canonical re-serialization, never to the received buffer.
    let tx = coinbase_transaction(1, &key(12).public_key(), 5_000_000_000);
    let mut padded = tx.serialize();
    padded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]);

    let decoded = Transaction::deserialize(&padded).expect("trailing bytes are accepted");
    assert_eq!(decoded, tx);
    assert_eq!(decoded.txid(), tx.txid());
}

// ---------------------------------------------------------------------------
// Difficulty (rules D-1 .. D-3, F-6, F-11)
// ---------------------------------------------------------------------------

#[test]
fn difficulty_parameters_match_the_p0_vector() {
    // test/vectors/difficulty/retarget.json → case `difficulty.params`.
    assert_eq!(DIFFICULTY_PARAMS.target_spacing_seconds, 60);
    assert_eq!(DIFFICULTY_PARAMS.retarget_interval, 1_440);
    assert_eq!(DIFFICULTY_PARAMS.max_adjustment_factor, 4);
    assert_eq!(DIFFICULTY_PARAMS.pow_limit_bits, 0x1e00_ffff);
    assert_eq!(DIFFICULTY_PARAMS.target_window_seconds(), 86_400);
}

#[test]
fn validate_bits_boundaries() {
    // The exact outcomes pinned by `difficulty.validate_bits` in the P0 corpus.
    assert!(matches!(
        validate_bits(0, &DIFFICULTY_PARAMS),
        Err(DifficultyError::ZeroTarget(0))
    ));
    assert!(matches!(
        validate_bits(0x2100_ffff, &DIFFICULTY_PARAMS),
        Err(DifficultyError::TargetAbovePowLimit { .. })
    ));
    assert!(validate_bits(0x1e00_ffff, &DIFFICULTY_PARAMS).is_ok());
    assert!(validate_bits(0x1d00_ffff, &DIFFICULTY_PARAMS).is_ok());
}

#[test]
fn next_difficulty_is_deterministic_and_branch_stable() {
    let params = DIFFICULTY_PARAMS;
    let window = params.target_window_seconds();
    let min_window = window / params.max_adjustment_factor; // 21_600
    let max_window = window * params.max_adjustment_factor; // 345_600

    // Both arithmetic branches must be stable across calls. 0x1d00ffff has fewer
    // than 20 leading zero bits (divide-first); 0x0300ffff has more (multiply-first).
    for bits in [0x1d00_ffffu32, 0x0300_ffff] {
        assert_eq!(
            next_difficulty(bits, min_window, &params),
            next_difficulty(bits, min_window, &params),
            "difficulty must be a pure function"
        );
    }

    // A 4x-short window raises difficulty (target shrinks) but never above the floor.
    let fast = next_difficulty(0x0300_ffff, min_window, &params);
    assert!(compact_to_target(fast) <= compact_to_target(0x0300_ffff));

    // A 4x-long window lowers difficulty (target grows).
    let slow = next_difficulty(0x0300_ffff, max_window, &params);
    assert!(compact_to_target(slow) >= compact_to_target(0x0300_ffff));

    // Out-of-range observations clamp to the same 4x bounds (D-1).
    assert_eq!(
        next_difficulty(0x0300_ffff, 0, &params),
        next_difficulty(0x0300_ffff, min_window, &params)
    );
    assert_eq!(
        next_difficulty(0x0300_ffff, u64::MAX, &params),
        next_difficulty(0x0300_ffff, max_window, &params)
    );

    // The floor is absolute (D-3): an easy target can never exceed the pow limit.
    let floored = next_difficulty(0x1e00_ffff, max_window, &params);
    assert!(compact_to_target(floored) <= params.pow_limit());
}

// ---------------------------------------------------------------------------
// Determinism (DET-2, DET-4, DET-5, DET-8, DET-10) and MTP (DET-6)
// ---------------------------------------------------------------------------

#[test]
fn header_and_pow_are_deterministic() {
    let chain = regtest();
    let header = chain.block_at(0).expect("genesis").header.clone();

    let preimage = header.preimage();
    assert_eq!(preimage.len(), 107, "the header preimage layout is frozen");
    assert_eq!(preimage, header.preimage(), "preimage is a pure function");

    let engine = trivial_engine();
    assert_eq!(engine.id(), ENGINE_ID_TRIVIAL);
    assert_eq!(header.pow_hash(engine.as_ref()), header.pow_hash(engine.as_ref()));
    assert!(header.meets_own_target(engine.as_ref()));

    // The scratchpad engine (devnet profile) is deterministic for equal inputs and
    // separates different nonces.
    let scratch = ChainParams::devnet().build_engine();
    assert_eq!(scratch.id(), ENGINE_ID_SCRATCHPAD);
    let a = scratch.hash(&preimage, 7);
    let b = scratch.hash(&preimage, 7);
    assert_eq!(a, b);
    assert_ne!(a, scratch.hash(&preimage, 8));
}

#[test]
fn state_root_is_independent_of_insertion_order() {
    let out_a = TxOut {
        value: 7,
        script_pubkey: p2pkh_script_pubkey(&Hash160([0x11; 20])),
    };
    let out_b = TxOut {
        value: 9,
        script_pubkey: p2pkh_script_pubkey(&Hash160([0x22; 20])),
    };

    let mut first = UtxoSet::new();
    first.insert_coinbase(Hash256([0x01; 32]), 0, out_a.clone(), 1);
    first.insert_coinbase(Hash256([0x02; 32]), 0, out_b.clone(), 2);

    let mut second = UtxoSet::new();
    second.insert_coinbase(Hash256([0x02; 32]), 0, out_b, 2);
    second.insert_coinbase(Hash256([0x01; 32]), 0, out_a, 1);

    assert_eq!(first.state_root(), second.state_root());
    assert_ne!(first.state_root(), EMPTY_STATE_ROOT);
}

#[test]
fn median_time_past_uses_the_upper_median() {
    let mut chain = regtest();
    let miner = key(13).public_key();

    // Ten timestamps: genesis + 10,20,...,90. The upper median (index 10/2 = 5) is
    // genesis + 50; a lower-median or averaged implementation would report 45.
    let mut now = GENESIS_TIMESTAMP;
    for _ in 0..9 {
        now += 10;
        chain.mine_block(&miner, vec![], now).expect("mines");
    }
    assert_eq!(chain.height(), 9);
    assert_eq!(chain.median_time_past(), GENESIS_TIMESTAMP + 50);
}

#[test]
fn mining_is_deterministic_for_a_fixed_header() {
    // DET-10: `mine` searches from the start nonce and returns the first hit, so
    // the same header and target always produce the same nonce.
    let chain = regtest();
    let header = chain.block_at(0).expect("genesis").header.clone();
    let engine = trivial_engine();
    let target = compact_to_target(header.difficulty_bits);

    let (nonce_a, hash_a) = mine(engine.as_ref(), &header.preimage(), &target, 0).expect("mines");
    let (nonce_b, hash_b) = mine(engine.as_ref(), &header.preimage(), &target, 0).expect("mines");
    assert_eq!(nonce_a, nonce_b);
    assert_eq!(hash_a, hash_b);
}

// ---------------------------------------------------------------------------
// Reward constants (pinned by the P0 corpus)
// ---------------------------------------------------------------------------

#[test]
fn reward_constants_match_the_p0_vectors() {
    // test/vectors/reward/subsidy.json → case `reward.constants` and
    // `reward.subsidy.table`.
    assert_eq!(block_subsidy(0), 0);
    assert_eq!(block_subsidy(1), 5_000_000_000);
    assert_eq!(block_subsidy(209_999), 5_000_000_000);
    assert_eq!(block_subsidy(210_000), 2_500_000_000);
    assert_eq!(block_subsidy(420_000), 1_250_000_000);
    assert_eq!(block_subsidy(13_230_000), 0);
    assert_eq!(block_subsidy(u64::MAX), 0);
    assert_eq!(COINBASE_MATURITY, 100);
    assert_eq!(MAX_SUPPLY, 2_100_000_000_000_000);
}
