//! P1.1 regression tests for triaged consensus findings.
//!
//! Each test reproduces one finding from `docs/consensus/CONSENSUS_RULES.md`
//! §14 exactly as documented in `docs/consensus/FINDINGS_TRIAGE.md`. They are
//! **behavior pins**, not fixes: production code is unchanged, so a test that
//! expects a panic today must be rewritten to expect the typed error once the
//! corresponding remediation lands.
//!
//! | Test | Finding | What it pins |
//! |------|---------|--------------|
//! | `f1_connect_block_panics_when_height_exceeds_chain_length` | F-1 | `required_bits` runs before the height check |
//! | `f3_a_block_larger_than_the_frame_cap_is_accepted` | F-3 | no consensus block-size limit |
//! | `f7_required_work_panics_when_target_is_max` | F-7 | `target + 1` wraps to a zero divisor |
//! | `f7_uint256_div_u64_panics_on_zero_divisor` | F-7 | `div_u64` asserts rather than returning an error |
//! | `f8_engine_id_does_not_commit_to_scratchpad_parameters` | F-8 | engine id is constant while the digest depends on params |
//! | `f11_hash_target_comparison_is_inclusive_and_big_endian` | F-11 | `<=` on big-endian byte order |
//!
//! F-2, F-5 and F-6 are already pinned by `tests/consensus_rules.rs`
//! (`block_version_is_not_validated`, `trailing_bytes_after_a_transaction_are_ignored`,
//! `next_difficulty_is_deterministic_and_branch_stable`); F-4, F-9 and F-10 are
//! documentation/robustness observations without a safe behavioral reproduction.

use zerocoin::chain::Chain;
use zerocoin::consensus::block::{Block, BlockHeader, BLOCK_VERSION};
use zerocoin::consensus::difficulty::{hash_meets_target, required_work};
use zerocoin::consensus::pow::{PowEngine, ScratchPadEngine, ENGINE_ID_SCRATCHPAD};
use zerocoin::consensus::Uint256;
use zerocoin::crypto::hash::Hash256;
use zerocoin::crypto::secp256k1::PrivateKey;
use zerocoin::ledger::script::{p2pkh_script_pubkey, p2pkh_script_sig};
use zerocoin::ledger::sighash::{signature_hash, SIGHASH_ALL};
use zerocoin::ledger::transaction::{Transaction, TxIn, TxOut};
use zerocoin::network::frame::MAX_PLAINTEXT_BYTES;
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

fn sign_input(chain: &Chain, sk: &PrivateKey, tx: &mut Transaction, script_code: &[u8]) {
    let digest = signature_hash(tx, 0, script_code, chain.chain_id(), SIGHASH_ALL)
        .expect("input 0 is in range");
    let mut sig = sk.sign(&digest).expect("signs").to_der().to_vec();
    sig.push(SIGHASH_ALL as u8);
    tx.inputs[0].script_sig = p2pkh_script_sig(&sig, &sk.public_key().to_sec1());
}

// ---------------------------------------------------------------------------
// F-1: `connect_block` reads untrusted height before validating it
// ---------------------------------------------------------------------------

/// F-1 (confirmed). `Chain::connect_block` calls `required_bits(block.height)`
/// (`src/chain.rs:277`) before `validate_structure` checks the height
/// (`src/consensus/block.rs:153`). On a retarget-enabled network `required_bits`
/// indexes `self.blocks[(height - 1) as usize]` (`src/chain.rs:260`), so a height
/// past the stored chain panics with an index-out-of-bounds instead of returning
/// `BlockError::BadHeight`.
///
/// Reachability: only local library callers. The P2P handler
/// (`src/node.rs:646-668`) forwards a block only when `height == next_height()`
/// and `previous_hash == tip`, and no RPC, GUI or session method accepts a block.
///
/// When the height guard moves ahead of `required_bits`, replace this test with
/// one asserting `BlockError::BadHeight`.
#[test]
#[should_panic(expected = "index out of bounds")]
fn f1_connect_block_panics_when_height_exceeds_chain_length() {
    let params = ChainParams::devnet(); // retargeting enabled
    let chain_id = params.chain_id.0;
    let genesis_bits = params.genesis_bits;
    let mut chain = Chain::in_memory(params).expect("devnet chain opens");

    // The chain holds only genesis (index 0); height 2 asks for `blocks[1]`.
    let block = Block {
        header: BlockHeader {
            version: BLOCK_VERSION,
            chain: chain_id,
            height: 2,
            previous_hash: chain.tip_hash(),
            merkle_root: Hash256::ZERO,
            timestamp: GENESIS_TIMESTAMP + 1_000,
            difficulty_bits: genesis_bits,
            engine_id: ENGINE_ID_SCRATCHPAD,
            nonce: 0,
        },
        transactions: Vec::new(),
    };
    let _ = chain.connect_block(block, GENESIS_TIMESTAMP + 1_000);
}

// ---------------------------------------------------------------------------
// F-3: no consensus block-size limit
// ---------------------------------------------------------------------------

/// F-3 (confirmed). Nothing in `validate_structure` (`src/consensus/block.rs:135-209`)
/// bounds a block's serialized size, and nothing bounds an output script in
/// `UtxoSet::apply_transaction` (`src/ledger/utxo.rs:191-257`). A spend may
/// therefore carry a multi-megabyte `script_pubkey` that is stored unspent and
/// never executed in this block. The resulting block exceeds the 4 MiB network
/// frame cap (`src/network/frame.rs:71`) and could never be relayed, yet
/// `connect_block` accepts it.
///
/// Reachability: a local miner can build such a block; a remote peer cannot
/// deliver it because of the frame cap. Consensus impact: none today (the rule
/// set simply has no limit); relay/portability risk when the C++ node must
/// agree on a limit.
#[test]
fn f3_a_block_larger_than_the_frame_cap_is_accepted() {
    let mut chain = regtest();
    let sk = key(21);
    let pk = sk.public_key();
    let mut now = GENESIS_TIMESTAMP + 1_000;

    // Height 1 funds the miner; 99 more blocks make its coinbase mature.
    chain.mine_block(&pk, vec![], now).expect("mines height 1");
    for _ in 0..99 {
        now += 1;
        chain.mine_block(&pk, vec![], now).expect("mines");
    }
    let coin = chain
        .coins_for_pubkey_hash(&pk.key_hash())
        .into_iter()
        .find(|c| c.height == 1)
        .expect("height-1 coinbase exists");
    assert!(coin.spendable, "100 confirmations unlock the coin");

    // A 4.5 MB output script: larger than MAX_PLAINTEXT_BYTES by itself. The
    // script is stored verbatim and never executed in this block.
    let big_script = vec![0x51u8; MAX_PLAINTEXT_BYTES + MAX_PLAINTEXT_BYTES / 8];
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: coin.outpoint,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: coin.value - 1_000,
            script_pubkey: big_script,
        }],
        lock_time: 0,
    };
    sign_input(&chain, &sk, &mut tx, &p2pkh_script_pubkey(&pk.key_hash()));

    let tx_size = tx.serialize().len();
    assert!(
        tx_size > MAX_PLAINTEXT_BYTES,
        "the transaction alone must exceed the frame cap, got {tx_size} bytes"
    );

    now += 1;
    let block = chain
        .mine_block(&pk, vec![tx], now)
        .expect("consensus accepts a block larger than the frame cap");
    assert_eq!(chain.height(), 101);
    assert_eq!(block.transactions.len(), 2, "coinbase plus the oversized spend");
    assert!(
        block.transactions[1].serialize().len() > MAX_PLAINTEXT_BYTES,
        "the accepted block embeds the oversized transaction"
    );
}

// ---------------------------------------------------------------------------
// F-7: arithmetic helpers panic instead of returning errors
// ---------------------------------------------------------------------------

/// F-7 (confirmed, latent). `required_work` computes `target + 1` with
/// `wrapping_add` (`src/consensus/difficulty.rs:91`); for `Uint256::MAX` the
/// denominator wraps to zero and `divmod` asserts (`src/consensus/uint256.rs:153`).
/// Not on the validation path: only tests and the vector emitter call it.
///
/// When the helper returns `Option`/`Result`, replace this test accordingly.
#[test]
#[should_panic(expected = "division by zero")]
fn f7_required_work_panics_when_target_is_max() {
    let _ = required_work(&Uint256::MAX);
}

/// F-7 (confirmed, latent). `Uint256::div_u64` asserts on a zero divisor
/// (`src/consensus/uint256.rs:139`) rather than returning an error.
#[test]
#[should_panic(expected = "division by zero")]
fn f7_uint256_div_u64_panics_on_zero_divisor() {
    let _ = Uint256::from_be_bytes([1u8; 32]).div_u64(0);
}

// ---------------------------------------------------------------------------
// F-8: the engine id does not commit to the scratchpad parameters
// ---------------------------------------------------------------------------

/// F-8 (confirmed). Every `ScratchPadEngine` reports `ENGINE_ID_SCRATCHPAD = 1`
/// (`src/consensus/pow.rs:192-194`) regardless of `memory_bytes`/`rounds`,
/// while the digest is a function of those parameters (`pow.rs:200-237`). The
/// header therefore cannot distinguish two incompatible engines; only the
/// hard-coded `ChainParams` keeps a network coherent.
///
/// Reachability: configuration of a node, not remote input — but any future
/// per-device tuning that changes parameters while keeping the id would fork.
#[test]
fn f8_engine_id_does_not_commit_to_scratchpad_parameters() {
    let small = ScratchPadEngine::new(64, 8);
    let large = ScratchPadEngine::new(96, 8);
    assert_eq!(small.id(), ENGINE_ID_SCRATCHPAD);
    assert_eq!(large.id(), ENGINE_ID_SCRATCHPAD);
    assert_ne!(
        small.hash(b"zerocoin-f8", 7),
        large.hash(b"zerocoin-f8", 7),
        "the digest depends on the scratchpad size"
    );
}

// ---------------------------------------------------------------------------
// F-11: big-endian, inclusive target comparison
// ---------------------------------------------------------------------------

/// F-11 (confirmed). `hash_meets_target` compares
/// `Uint256::from_be_bytes(hash) <= target` (`src/consensus/difficulty.rs:81-83`):
/// the comparison is inclusive and interprets the digest big-endian. A port that
/// copies Bitcoin's reversed display order, or that compares strictly, rejects
/// every valid ZeroCoin block.
#[test]
fn f11_hash_target_comparison_is_inclusive_and_big_endian() {
    let mut target_bytes = [0u8; 32];
    target_bytes[31] = 0x10;
    let target = Uint256::from_be_bytes(target_bytes);

    assert!(
        hash_meets_target(&Hash256(target_bytes), &target),
        "hash == target is accepted: the comparison is `<=`"
    );

    let mut greater = target_bytes;
    greater[31] = 0x11;
    assert!(
        !hash_meets_target(&Hash256(greater), &target),
        "one above target is rejected"
    );

    let mut less = target_bytes;
    less[31] = 0x0f;
    assert!(
        hash_meets_target(&Hash256(less), &target),
        "one below target is accepted"
    );

    // Endianness discriminator: 0x10 in the most significant byte is ~2^252
    // big-endian but only 16 little-endian. Rejecting it proves the digest is
    // read big-endian.
    let mut high_byte = [0u8; 32];
    high_byte[0] = 0x10;
    assert!(
        !hash_meets_target(&Hash256(high_byte), &target),
        "the comparison must read the digest big-endian"
    );
}
