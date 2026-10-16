//! Consensus rules: monetary emission, difficulty retargeting, and proof of work.
//!
//! These are the rules every ZeroCoin node enforces independently. They are pure
//! functions of block data — no I/O, no clocks, no randomness on the validation
//! path — so any node anywhere reaches the same accept/reject decision on the same
//! bytes. That independence is what makes the network trustless.

pub mod reward;
pub mod difficulty;
pub mod pow;
pub mod uint256;
pub mod block;
pub mod immutability;

pub use uint256::Uint256;
pub use block::{merkle_root, Block, BlockError, BlockHeader, BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS};

pub use difficulty::{
    block_target, compact_from_target, compact_to_target, next_difficulty, required_work,
    DifficultyError, Params as DifficultyParams, DIFFICULTY_PARAMS,
};
pub use pow::{PowEngine, PowError, ScratchPadEngine, TrivialEngine, DEFAULT_ENGINE};
pub use reward::{
    block_reward, block_subsidy, coinbase_transaction, maturity_height, total_supply_ceiling,
    validate_coinbase, RewardError, COINBASE_MATURITY, HALVING_INTERVAL, INITIAL_SUBSIDY,
    MAX_SUPPLY,
};

pub use immutability::{isolates_peer, verify_boot_invariants, ImmutabilityError};
