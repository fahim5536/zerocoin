//! The genesis block: a chain start nobody owns.
//!
//! Bitcoin's block 0 is compiled into the client. It is not handed to the first node
//! by an operator, nobody chooses who is rich when the network begins, and every
//! machine running the code derives the very same hash from the very same constants.
//! This module is that for ZeroCoin.
//!
//! **The genesis coinbase creates nothing.** Block 0 has *no outputs*, so the value in
//! circulation at height 0 is exactly zero — the anti-premine rule expressed as one
//! empty vector. After block 0, the only way value has ever entered this network is
//! the block subsidy earned by proof of work ([`crate::consensus::reward`]), and the
//! only way to obtain it is to mine or to be paid by someone who did. There is no
//! starting balance to own, no allocation file, and no key privileged at launch.
//!
//! ## Reproducibility
//!
//! Every field of the header is a constant except the nonce, and the nonce is found
//! by a *deterministic* search from zero ([`crate::consensus::pow::mine`]). Because
//! the preimage is fixed and the search is ordered, every node computes the same
//! nonce and therefore the same genesis hash. On regtest and devnet the target is at
//! the easy floor, so this terminates in a hash or two.
//!
//! Mainnet is the exception, exactly as in Bitcoin: at the mainnet difficulty floor
//! the memory-hard engine would search for a long time, so a real launch mines block
//! 0 *once*, offline, and pins the resulting nonce with [`genesis_block_with_nonce`].
//! The constant belongs to the software, not to whoever boots first.

use crate::consensus::block::{Block, BlockHeader, BLOCK_VERSION};
use crate::consensus::difficulty::compact_to_target;
use crate::consensus::pow::{mine, PowEngine};
use crate::crypto::hash::Hash256;
use crate::ledger::script::push_data;
use crate::ledger::transaction::{Outpoint, Transaction, TxIn};
use crate::params::{ChainParams, GENESIS_TIMESTAMP};

/// Carried in the genesis coinbase's `scriptSig`, the way Bitcoin's block 0 carries
/// the day's headline. It makes the starting hash a statement rather than an
/// arbitrary constant someone could silently swap for a funded one.
pub const GENESIS_MESSAGE: &[u8] =
    b"No premine, no owner: ZeroCoin is issued only by proof of work";

/// Block 0's coinbase. It spends the null outpoint, commits the height (0) in the
/// minimal encoding BIP-34 requires, carries the launch message, and has **no
/// outputs** — creating zero value.
pub fn genesis_coinbase() -> Transaction {
    let mut script_sig = Vec::new();
    // Height 0's minimal script-number encoding is empty; `push_data` emits a single
    // zero byte (an empty push), which `coinbase_height` reads back as 0.
    push_data(&[], &mut script_sig);
    push_data(GENESIS_MESSAGE, &mut script_sig);

    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint::null(),
            script_sig,
            sequence: u32::MAX,
        }],
        // No outputs: the genesis block mints nothing.
        outputs: Vec::new(),
        lock_time: 0,
    }
}

/// The genesis header before its nonce is solved. Every field is a constant derived
/// from `params`, so all nodes agree on the preimage. `pub(crate)` so the
/// immutability layer can pin the mainnet header preimage digest at boot.
pub(crate) fn genesis_header(params: &ChainParams, merkle_root: Hash256) -> BlockHeader {
    BlockHeader {
        version: BLOCK_VERSION,
        chain: params.chain_id.0,
        height: 0,
        previous_hash: Hash256::ZERO,
        merkle_root,
        timestamp: GENESIS_TIMESTAMP,
        difficulty_bits: params.genesis_bits,
        engine_id: params.engine.id(),
        nonce: 0,
    }
}

/// Assemble and solve the genesis block for `params` by searching nonces from zero.
///
/// Deterministic: every caller obtains the identical block. Suitable for regtest and
/// devnet, whose easy floor solves almost immediately. Do **not** call this for
/// mainnet at startup — use [`genesis_block_with_nonce`] with the launch nonce.
pub fn genesis_block(params: &ChainParams, engine: &dyn PowEngine) -> Block {
    let coinbase = genesis_coinbase();
    let merkle_root = Block::compute_merkle_root(std::slice::from_ref(&coinbase));
    let mut header = genesis_header(params, merkle_root);
    let target = compact_to_target(params.genesis_bits);
    let (nonce, _hash) = mine(engine, &header.preimage(), &target, 0)
        .expect("the genesis target is at the network floor and is always solvable");
    header.nonce = nonce;
    Block {
        header,
        transactions: vec![coinbase],
    }
}

/// Assemble the genesis block with a precomputed nonce, as a mainnet launch pins it.
/// The caller supplies the nonce that was found once, offline, so no node ever has to
/// re-mine block 0.
pub fn genesis_block_with_nonce(
    params: &ChainParams,
    engine: &dyn PowEngine,
    nonce: u64,
) -> Block {
    let coinbase = genesis_coinbase();
    let merkle_root = Block::compute_merkle_root(std::slice::from_ref(&coinbase));
    let mut header = genesis_header(params, merkle_root);
    header.nonce = nonce;
    let block = Block {
        header,
        transactions: vec![coinbase],
    };
    debug_assert!(
        block.header.meets_own_target(engine),
        "a pinned genesis nonce must satisfy the genesis target"
    );
    block
}

/// The genesis block's identity (its proof-of-work hash) for a network.
pub fn genesis_hash(params: &ChainParams, engine: &dyn PowEngine) -> Hash256 {
    genesis_block(params, engine).id(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::reward::coinbase_height;
    use crate::params::{ChainParams, EngineSpec};

    fn regtest() -> (ChainParams, Box<dyn PowEngine>) {
        let params = ChainParams::regtest();
        let engine = params.build_engine();
        (params, engine)
    }

    #[test]
    fn genesis_coinbase_creates_nothing() {
        let coinbase = genesis_coinbase();
        assert!(coinbase.is_coinbase());
        assert!(coinbase.outputs.is_empty(), "genesis must have no outputs");
        assert_eq!(coinbase.output_value(), Some(0));
    }

    #[test]
    fn genesis_coinbase_commits_height_zero() {
        let coinbase = genesis_coinbase();
        assert_eq!(coinbase_height(&coinbase), Some(0));
    }

    #[test]
    fn genesis_is_deterministic() {
        let (params, engine) = regtest();
        let a = genesis_block(&params, engine.as_ref());
        let b = genesis_block(&params, engine.as_ref());
        assert_eq!(a.id(engine.as_ref()), b.id(engine.as_ref()));
        assert_eq!(a.header.nonce, b.header.nonce);
    }

    #[test]
    fn genesis_satisfies_its_own_target() {
        let (params, engine) = regtest();
        let block = genesis_block(&params, engine.as_ref());
        assert!(block.header.meets_own_target(engine.as_ref()));
    }

    #[test]
    fn genesis_has_the_right_chain_and_height() {
        let (params, engine) = regtest();
        let block = genesis_block(&params, engine.as_ref());
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.chain, params.chain_id.0);
        assert!(block.header.previous_hash.is_zero());
        assert_eq!(block.header.timestamp, GENESIS_TIMESTAMP);
    }

    #[test]
    fn pinned_nonce_matches_a_solved_genesis() {
        let (params, engine) = regtest();
        let solved = genesis_block(&params, engine.as_ref());
        let pinned = genesis_block_with_nonce(&params, engine.as_ref(), solved.header.nonce);
        assert_eq!(pinned.id(engine.as_ref()), solved.id(engine.as_ref()));
    }

    #[test]
    fn different_networks_have_different_genesis() {
        let regtest = ChainParams::regtest();
        let devnet = ChainParams::devnet();
        // Different chain ids and engines give different genesis identities.
        assert_ne!(regtest.chain_id, devnet.chain_id);
        assert_eq!(regtest.engine, EngineSpec::Trivial);
    }
}
