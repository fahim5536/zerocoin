//! The Consensus Immutability Layer: the fair-launch specification, locked.
//!
//! ZeroCoin's launch promises are only as strong as the code that enforces them, so
//! this module turns each one into either a **compile-time failure** or a **boot
//! refusal** — two layers that no runtime flag, no environment variable and no
//! future patch can bypass silently:
//!
//! 1. **Compile-time locks.** The `const _: () = assert!(...)` items below are
//!    evaluated by the compiler. If anyone edits the supply cap, the halving
//!    schedule, the 100-block coinbase maturity, the low-device memory/thread
//!    budgets, the header/Merkle domain tags, the chain ids, the genesis timestamp
//!    or the networks' engine profiles — by even one byte — the crate no longer
//!    compiles.
//! 2. **Boot-time anchors.** The genesis block and the state-root layout are hashed
//!    and compared against the constants pinned here (the `GENESIS_*` and
//!    `*_STATE_ROOT` anchors). If the genesis data or the state-root
//!    serialization drifts by one bit, [`verify_boot_invariants`] fails and
//!    [`crate::chain::Chain::open`] refuses to boot the node.
//!
//! Mainnet is handled with the same care as Bitcoin's block 0: the launch nonce is
//! found once, offline, and pinned by [`crate::genesis::genesis_block_with_nonce`],
//! so this layer pins the *preimage digest* of the mainnet genesis header — the
//! part fixed before mining — plus the fully-solved regtest and devnet genesis
//! hashes, which are cheap to re-derive and compare on every boot.
//!
//! Finally, [`isolates_peer`] is the ledger's trip-wire: when a block tries to
//! spend an immature coinbase the node drops the block whole and disconnects the
//! peer that served it.

use crate::consensus::block::{
    Block, BLOCK_VERSION, EMPTY_MERKLE_TAG, HEADER_TAG, MAX_FUTURE_SECONDS,
};
use crate::consensus::pow::{
    HardwareProfile, ENGINE_ID_SCRATCHPAD, ENGINE_ID_TRIVIAL, LOW_SPEC_SCRATCHPAD_BYTES,
    MAX_THREADS_ABSOLUTE, MAX_THREADS_LOW_SPEC, MAX_THREADS_MOBILE, MOBILE_SCRATCHPAD_BYTES,
};
use crate::consensus::reward::{
    block_subsidy, maturity_height, total_supply_ceiling, COINBASE_MATURITY, FAH_PER_ZRO,
    HALVING_INTERVAL, INITIAL_SUBSIDY, MAX_HALVINGS, MAX_SUPPLY,
};
use crate::crypto::hash::{sha256d, Hash256};
use crate::genesis::{genesis_coinbase, genesis_hash, genesis_header, GENESIS_MESSAGE};
use crate::ledger::transaction::TxOut;
use crate::ledger::utxo::{UtxoError, UtxoSet};
use crate::params::{
    ChainParams, EngineSpec, DEVNET_CHAIN, GENESIS_TIMESTAMP, MAINNET_CHAIN, MAINNET_POW_LIMIT_BITS,
    REGTEST_CHAIN, TRIVIAL_POW_LIMIT_BITS,
};

/// A `const`-evaluable byte-slice equality, so the frozen domain tags can be
/// compared before `main` ever runs (slices cannot use `==` in const contexts).
const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether an engine spec is the memory-hard scratchpad with exactly these
/// parameters. A `const fn` so the networks' engines are pinned at compile time.
const fn matches_scratchpad(spec: EngineSpec, memory_bytes: usize, rounds: usize) -> bool {
    match spec {
        EngineSpec::Scratchpad {
            memory_bytes: m,
            rounds: r,
        } => m == memory_bytes && r == rounds,
        EngineSpec::Trivial => false,
    }
}

// ---------------------------------------------------------------------------
// Rule 1 — economic freeze: 21,000,000 ZRO, halving schedule, zero premine
// ---------------------------------------------------------------------------

const _: () = assert!(
    FAH_PER_ZRO == 100_000_000,
    "one ZRO is exactly 100,000,000 Fah"
);
const _: () = assert!(
    MAX_SUPPLY == 21_000_000 * FAH_PER_ZRO,
    "maximum supply is exactly 21,000,000 ZRO in Fah"
);
const _: () = assert!(
    MAX_SUPPLY == 2_100_000_000_000_000,
    "maximum supply is exactly 2,100,000,000,000,000 Fah"
);
const _: () = assert!(
    INITIAL_SUBSIDY == 50 * FAH_PER_ZRO,
    "the initial subsidy is exactly 50 ZRO"
);
const _: () = assert!(
    HALVING_INTERVAL == 210_000,
    "the halving interval is exactly 210,000 blocks"
);
const _: () = assert!(
    MAX_HALVINGS == 64,
    "the halving schedule is capped at 64 epochs"
);
const _: () = assert!(
    total_supply_ceiling() <= MAX_SUPPLY,
    "the full subsidy schedule never exceeds the 21,000,000 ZRO cap"
);

// The subsidy itself. Height 0 is the zero-premine genesis: exactly zero Fah.
const _: () = assert!(
    block_subsidy(0) == 0,
    "the genesis (height 0) subsidy is exactly zero: no premine"
);
const _: () = assert!(
    block_subsidy(1) == INITIAL_SUBSIDY,
    "issuance starts at height 1 with exactly the 50 ZRO initial subsidy"
);
const _: () = assert!(
    block_subsidy(HALVING_INTERVAL - 1) == INITIAL_SUBSIDY,
    "the last block of the first epoch still pays the initial subsidy"
);
const _: () = assert!(
    block_subsidy(HALVING_INTERVAL) == INITIAL_SUBSIDY / 2,
    "the first block of the second epoch pays exactly half the initial subsidy"
);
const _: () = assert!(
    block_subsidy(HALVING_INTERVAL * 2) == INITIAL_SUBSIDY / 4,
    "the third epoch pays exactly a quarter of the initial subsidy"
);
const _: () = assert!(
    block_subsidy(MAX_HALVINGS * HALVING_INTERVAL) == 0,
    "the subsidy is exactly zero after the final halving"
);

// ---------------------------------------------------------------------------
// Rule 2 — coinbase maturity guard: exactly 100 blocks, never less
// ---------------------------------------------------------------------------

const _: () = assert!(
    COINBASE_MATURITY == 100,
    "the coinbase maturity guard is exactly 100 blocks"
);
const _: () = assert!(
    maturity_height(0) == 100,
    "a coinbase mined in block 0 matures at height 100, not before"
);
const _: () = assert!(
    maturity_height(1) == 101,
    "a coinbase mined in block 1 matures at height 101, not before"
);

// ---------------------------------------------------------------------------
// Rule 3 — hardware safety governance: 256/512 MiB profiles, thread ceilings
// ---------------------------------------------------------------------------

const _: () = assert!(
    MOBILE_SCRATCHPAD_BYTES == 256 * 1024 * 1024,
    "the mobile scratchpad budget is exactly 256 MiB"
);
const _: () = assert!(
    LOW_SPEC_SCRATCHPAD_BYTES == 512 * 1024 * 1024,
    "the low-spec scratchpad budget is exactly 512 MiB"
);
const _: () = assert!(
    MAX_THREADS_MOBILE == 1,
    "a phone mines on exactly one thread, ever"
);
const _: () = assert!(
    MAX_THREADS_LOW_SPEC == 2,
    "a low-spec PC mines on at most two threads, ever"
);
const _: () = assert!(
    MAX_THREADS_MOBILE < MAX_THREADS_LOW_SPEC && MAX_THREADS_LOW_SPEC < MAX_THREADS_ABSOLUTE,
    "the thread ceilings are strictly ordered: mobile < low-spec < absolute"
);
const _: () = assert!(
    HardwareProfile::Mobile.max_mining_threads_for(8) == MAX_THREADS_MOBILE,
    "eight cores do not change the phone thread ceiling"
);
const _: () = assert!(
    HardwareProfile::LowSpec.max_mining_threads_for(64) == MAX_THREADS_LOW_SPEC,
    "sixty-four cores do not change the low-spec PC thread ceiling"
);
const _: () = assert!(
    HardwareProfile::Desktop.max_mining_threads_for(usize::MAX) == MAX_THREADS_ABSOLUTE,
    "the desktop profile is clamped below the absolute thread ceiling"
);
const _: () = assert!(
    HardwareProfile::Server.max_mining_threads_for(usize::MAX) == MAX_THREADS_ABSOLUTE,
    "the server profile is clamped below the absolute thread ceiling"
);
const _: () = assert!(
    HardwareProfile::Mobile.memory_budget_bytes() == MOBILE_SCRATCHPAD_BYTES,
    "the phone memory budget is exactly the 256 MiB mobile scratchpad"
);
const _: () = assert!(
    HardwareProfile::LowSpec.memory_budget_bytes() == LOW_SPEC_SCRATCHPAD_BYTES,
    "the low-spec PC memory budget is exactly the 512 MiB scratchpad"
);
const _: () = assert!(
    HardwareProfile::Desktop.memory_budget_bytes() == LOW_SPEC_SCRATCHPAD_BYTES,
    "the desktop memory budget is capped at the 512 MiB scratchpad"
);
const _: () = assert!(
    HardwareProfile::Server.memory_budget_bytes() == usize::MAX,
    "only the server profile is unconstrained in memory"
);

// ---------------------------------------------------------------------------
// Rule 4 — checksum anchoring: header/domain layout, chain ids, network profiles
// ---------------------------------------------------------------------------

const _: () = assert!(GENESIS_TIMESTAMP == 1_735_689_600, "the genesis timestamp is frozen");
const _: () = assert!(
    MAINNET_CHAIN.0 == 0x5A52_4F01,
    "the mainnet chain id is frozen at 0x5A524F01"
);
const _: () = assert!(
    DEVNET_CHAIN.0 == 0x5A52_4F02,
    "the devnet chain id is frozen at 0x5A524F02"
);
const _: () = assert!(
    REGTEST_CHAIN.0 == 0x5A52_4F00,
    "the regtest chain id is frozen at 0x5A524F00"
);
const _: () = assert!(
    MAINNET_POW_LIMIT_BITS == 0x1e00_ffff,
    "the mainnet difficulty floor is frozen at 0x1e00ffff"
);
const _: () = assert!(
    TRIVIAL_POW_LIMIT_BITS == 0x207f_ffff,
    "the trivial difficulty floor is frozen at 0x207fffff"
);
const _: () = assert!(ENGINE_ID_TRIVIAL == 0, "the trivial engine id is frozen at 0");
const _: () = assert!(
    ENGINE_ID_SCRATCHPAD == 1,
    "the scratchpad engine id is frozen at 1"
);
const _: () = assert!(BLOCK_VERSION == 1, "the block version is frozen at 1");
const _: () = assert!(
    MAX_FUTURE_SECONDS == 7_200,
    "the block timestamp horizon is frozen at 7,200 seconds"
);
const _: () = assert!(
    bytes_eq(HEADER_TAG, b"ZRO/header/v1\0"),
    "the header domain tag is frozen: one byte changes every block hash"
);
const _: () = assert!(
    bytes_eq(EMPTY_MERKLE_TAG, b"ZRO/merkle:empty\0"),
    "the empty-merkle domain tag is frozen"
);
const _: () = assert!(
    bytes_eq(
        GENESIS_MESSAGE,
        b"No premine, no owner: ZeroCoin is issued only by proof of work"
    ),
    "the genesis launch message is frozen"
);

// The networks themselves, as consts, so every consensus-relevant field of every
// network is pinned at compile time.
const MAINNET_PARAMS: ChainParams = ChainParams::mainnet();
const DEVNET_PARAMS: ChainParams = ChainParams::devnet();
const REGTEST_PARAMS: ChainParams = ChainParams::regtest();

const _: () = assert!(
    MAINNET_PARAMS.chain_id.0 == MAINNET_CHAIN.0,
    "mainnet params carry the mainnet chain id"
);
const _: () = assert!(
    DEVNET_PARAMS.chain_id.0 == DEVNET_CHAIN.0,
    "devnet params carry the devnet chain id"
);
const _: () = assert!(
    REGTEST_PARAMS.chain_id.0 == REGTEST_CHAIN.0,
    "regtest params carry the regtest chain id"
);
const _: () = assert!(
    matches_scratchpad(MAINNET_PARAMS.engine, 2 * 1024 * 1024, 4_096),
    "mainnet runs the scratchpad engine at exactly 2 MiB / 4,096 rounds"
);
const _: () = assert!(
    matches_scratchpad(DEVNET_PARAMS.engine, 64 * 1024, 1_024),
    "devnet runs the scratchpad engine at exactly 64 KiB / 1,024 rounds"
);
const _: () = assert!(
    matches!(REGTEST_PARAMS.engine, EngineSpec::Trivial),
    "regtest runs the trivial engine"
);
const _: () = assert!(
    MAINNET_PARAMS.genesis_bits == MAINNET_POW_LIMIT_BITS,
    "mainnet starts at its own difficulty floor"
);
const _: () = assert!(
    DEVNET_PARAMS.genesis_bits == TRIVIAL_POW_LIMIT_BITS,
    "devnet starts at the trivial difficulty floor"
);
const _: () = assert!(
    REGTEST_PARAMS.genesis_bits == TRIVIAL_POW_LIMIT_BITS,
    "regtest starts at the trivial difficulty floor"
);
const _: () = assert!(
    MAINNET_PARAMS.difficulty.target_spacing_seconds == 60,
    "mainnet targets 60-second blocks"
);
const _: () = assert!(
    MAINNET_PARAMS.difficulty.retarget_interval == 1_440,
    "mainnet retargets every 1,440 blocks"
);
const _: () = assert!(
    MAINNET_PARAMS.difficulty.max_adjustment_factor == 4,
    "mainnet clamps retargets to 4x"
);
const _: () = assert!(
    MAINNET_PARAMS.allow_pow_retarget,
    "mainnet retargets difficulty"
);
const _: () = assert!(
    !REGTEST_PARAMS.allow_pow_retarget,
    "regtest pins difficulty: retargeting stays disabled"
);

// ---------------------------------------------------------------------------
// Boot-time anchors: the genesis data and state-root layout, pinned by hash
// ---------------------------------------------------------------------------

/// The txid of the genesis coinbase (the empty-output, no-premine transaction).
pub const GENESIS_COINBASE_TXID: Hash256 = Hash256([
    0xe9, 0x4d, 0x9c, 0x36, 0xf8, 0xd9, 0x63, 0x64, 0xc3, 0x40, 0x43, 0x80, 0xd0, 0xd5, 0xdd, 0x13,
    0x2a, 0x4b, 0x0e, 0xea, 0x7c, 0x33, 0xaf, 0x14, 0x4e, 0xf5, 0x1c, 0x16, 0x3d, 0x5a, 0x41, 0x89,
]);
/// The genesis Merkle root over the single genesis coinbase.
pub const GENESIS_MERKLE_ROOT: Hash256 = Hash256([
    0xe9, 0x4d, 0x9c, 0x36, 0xf8, 0xd9, 0x63, 0x64, 0xc3, 0x40, 0x43, 0x80, 0xd0, 0xd5, 0xdd, 0x13,
    0x2a, 0x4b, 0x0e, 0xea, 0x7c, 0x33, 0xaf, 0x14, 0x4e, 0xf5, 0x1c, 0x16, 0x3d, 0x5a, 0x41, 0x89,
]);
/// The fully-solved regtest genesis block hash.
pub const GENESIS_HASH_REGTEST: Hash256 = Hash256([
    0x3f, 0x0a, 0xdf, 0x40, 0x44, 0x40, 0xfd, 0xa9, 0x1d, 0xe2, 0x06, 0x8b, 0x3c, 0xa6, 0x69, 0x6c,
    0xc9, 0x7f, 0x0d, 0x9e, 0xd8, 0xb2, 0x3b, 0x40, 0x0a, 0x07, 0x15, 0xfe, 0x1f, 0x0e, 0x91, 0x48,
]);
/// The fully-solved devnet genesis block hash.
pub const GENESIS_HASH_DEVNET: Hash256 = Hash256([
    0x7f, 0x2e, 0xe4, 0x93, 0x64, 0xdc, 0x84, 0x1f, 0x81, 0x86, 0x60, 0xec, 0xe8, 0x6b, 0x0b, 0xce,
    0xe8, 0x31, 0xf8, 0xc9, 0x10, 0xac, 0xdf, 0x58, 0x11, 0x8e, 0xf9, 0x25, 0x05, 0x31, 0x4b, 0x76,
]);
/// The mainnet genesis header preimage digest (`sha256d` of the preimage). The
/// nonce is pinned at launch; everything else is fixed here.
pub const GENESIS_PREIMAGE_DIGEST_MAINNET: Hash256 = Hash256([
    0xa3, 0xf7, 0xf6, 0xe3, 0x55, 0xc3, 0xa4, 0x90, 0xa3, 0xda, 0x0d, 0x9a, 0x2c, 0x48, 0x2a, 0xf6,
    0x78, 0x20, 0x07, 0x31, 0x29, 0xf6, 0xf9, 0x3f, 0x24, 0xb1, 0x16, 0x00, 0x2e, 0xab, 0xa2, 0x63,
]);
/// The state root of the empty UTXO set.
pub const EMPTY_STATE_ROOT: Hash256 = Hash256([
    0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
    0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
]);
/// The state root of a fixed two-entry probe set, pinning the exact byte layout
/// of every field [`UtxoSet::state_root`] hashes.
pub const STATE_ROOT_LAYOUT_PROBE: Hash256 = Hash256([
    0xca, 0x21, 0x84, 0x34, 0xf8, 0x8c, 0xad, 0x2a, 0x18, 0x45, 0x1a, 0x98, 0x69, 0x38, 0x8d, 0xe9,
    0x4e, 0x92, 0xbb, 0xa7, 0x98, 0xf3, 0xb5, 0x6c, 0x68, 0x2d, 0xeb, 0x69, 0xca, 0x34, 0x39, 0xe2,
]);

/// A pinned consensus commitment changed: the node must not boot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImmutabilityError {
    #[error("genesis commitment for {network} changed: expected {expected}, found {found}")]
    GenesisChecksum {
        network: &'static str,
        expected: Hash256,
        found: Hash256,
    },
    #[error("the genesis coinbase changed: expected {expected}, found {found}")]
    GenesisCoinbase {
        expected: Hash256,
        found: Hash256,
    },
    #[error("the genesis Merkle root changed: expected {expected}, found {found}")]
    GenesisMerkleRoot {
        expected: Hash256,
        found: Hash256,
    },
    #[error("the state-root layout changed: expected {expected}, found {found}")]
    StateRootLayout {
        expected: Hash256,
        found: Hash256,
    },
}

/// Verify every boot-time anchor: genesis commitments and the state-root layout.
/// Called at the top of [`crate::chain::Chain::open`]; any mismatch is a refusal
/// to boot, not a warning.
pub fn verify_boot_invariants() -> Result<(), ImmutabilityError> {
    verify_genesis_checksums()?;
    verify_state_root_layout()?;
    Ok(())
}

/// Re-derive the genesis coinbase, Merkle root, and the regtest/devnet genesis
/// hashes, and compare each against its pin. For mainnet, re-derive the header
/// preimage digest (the nonce is resolved at launch, so the full hash is pinned
/// by [`crate::genesis::genesis_block_with_nonce`] in the launch tree).
fn verify_genesis_checksums() -> Result<(), ImmutabilityError> {
    let coinbase = genesis_coinbase();
    let txid = coinbase.txid();
    if txid != GENESIS_COINBASE_TXID {
        return Err(ImmutabilityError::GenesisCoinbase {
            expected: GENESIS_COINBASE_TXID,
            found: txid,
        });
    }
    let merkle = Block::compute_merkle_root(std::slice::from_ref(&coinbase));
    if merkle != GENESIS_MERKLE_ROOT {
        return Err(ImmutabilityError::GenesisMerkleRoot {
            expected: GENESIS_MERKLE_ROOT,
            found: merkle,
        });
    }

    let regtest = ChainParams::regtest();
    let engine = regtest.build_engine();
    let found = genesis_hash(&regtest, engine.as_ref());
    if found != GENESIS_HASH_REGTEST {
        return Err(ImmutabilityError::GenesisChecksum {
            network: "regtest",
            expected: GENESIS_HASH_REGTEST,
            found,
        });
    }

    let devnet = ChainParams::devnet();
    let engine = devnet.build_engine();
    let found = genesis_hash(&devnet, engine.as_ref());
    if found != GENESIS_HASH_DEVNET {
        return Err(ImmutabilityError::GenesisChecksum {
            network: "devnet",
            expected: GENESIS_HASH_DEVNET,
            found,
        });
    }

    let mainnet = ChainParams::mainnet();
    let digest = sha256d(&genesis_header(&mainnet, merkle).preimage());
    if digest != GENESIS_PREIMAGE_DIGEST_MAINNET {
        return Err(ImmutabilityError::GenesisChecksum {
            network: "mainnet",
            expected: GENESIS_PREIMAGE_DIGEST_MAINNET,
            found: digest,
        });
    }
    Ok(())
}

/// Re-derive the state root of the empty set and of a fixed layout probe, and
/// compare each against its pin. Together they pin the exact byte order and
/// widths of every field the state commitment hashes: one changed bit in the
/// layout changes the root and blocks the boot.
fn verify_state_root_layout() -> Result<(), ImmutabilityError> {
    let empty = UtxoSet::new().state_root();
    if empty != EMPTY_STATE_ROOT {
        return Err(ImmutabilityError::StateRootLayout {
            expected: EMPTY_STATE_ROOT,
            found: empty,
        });
    }
    let probe = layout_probe_set().state_root();
    if probe != STATE_ROOT_LAYOUT_PROBE {
        return Err(ImmutabilityError::StateRootLayout {
            expected: STATE_ROOT_LAYOUT_PROBE,
            found: probe,
        });
    }
    Ok(())
}

/// The fixed two-entry set whose state root pins the serialization layout: one
/// coinbase entry with a non-empty script and one ordinary entry with an empty
/// script, so both flag values and both script lengths are exercised.
fn layout_probe_set() -> UtxoSet {
    layout_probe_set_with_probe_value(1_234_567_890_123)
}

fn layout_probe_set_with_probe_value(probe_value: u64) -> UtxoSet {
    let mut set = UtxoSet::new();
    set.insert_coinbase(
        Hash256([0x11; 32]),
        0x0201,
        TxOut {
            value: probe_value,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0xab, 0xcd, 0x88, 0xac],
        },
        3,
    );
    set.insert_output(
        Hash256([0x22; 32]),
        7,
        TxOut {
            value: 1,
            script_pubkey: Vec::new(),
        },
        42,
    );
    set
}

/// Whether a ledger error is a violation of a *frozen* consensus invariant, in
/// which case the node must not merely reject the offending block but also
/// isolate the peer that served it. Today exactly one error qualifies: a spend
/// of an immature coinbase output ([`UtxoError::ImmatureCoinbase`]).
pub fn isolates_peer(error: &UtxoError) -> bool {
    matches!(error, UtxoError::ImmatureCoinbase { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::transaction::Outpoint;
    use crate::ledger::utxo::UtxoEntry;

    #[test]
    fn boot_invariants_hold() {
        verify_boot_invariants().expect("the shipped tree matches every pinned commitment");
    }

    #[test]
    fn genesis_commitments_are_pinned() {
        assert_ne!(GENESIS_COINBASE_TXID, Hash256::ZERO);
        assert_ne!(GENESIS_MERKLE_ROOT, Hash256::ZERO);
        assert_ne!(GENESIS_HASH_REGTEST, Hash256::ZERO);
        assert_ne!(GENESIS_HASH_DEVNET, Hash256::ZERO);
        assert_ne!(GENESIS_PREIMAGE_DIGEST_MAINNET, Hash256::ZERO);
        assert_ne!(EMPTY_STATE_ROOT, Hash256::ZERO);
        assert_ne!(STATE_ROOT_LAYOUT_PROBE, Hash256::ZERO);
        assert_ne!(
            GENESIS_HASH_REGTEST, GENESIS_HASH_DEVNET,
            "every network has its own genesis identity"
        );
    }

    #[test]
    fn one_flipped_genesis_bit_breaks_every_commitment() {
        let mut tampered = genesis_coinbase();
        // Flip one bit of the launch message inside the coinbase scriptSig.
        let msg_start = tampered.inputs[0].script_sig.len() - GENESIS_MESSAGE.len();
        tampered.inputs[0].script_sig[msg_start] ^= 0x01;

        assert_ne!(
            tampered.txid(),
            GENESIS_COINBASE_TXID,
            "the genesis txid is bit-sensitive"
        );
        let tampered_merkle = Block::compute_merkle_root(std::slice::from_ref(&tampered));
        assert_ne!(
            tampered_merkle, GENESIS_MERKLE_ROOT,
            "the genesis Merkle root is bit-sensitive"
        );

        let mainnet = ChainParams::mainnet();
        let honest = sha256d(&genesis_header(&mainnet, GENESIS_MERKLE_ROOT).preimage());
        let altered = sha256d(&genesis_header(&mainnet, tampered_merkle).preimage());
        assert_eq!(
            honest, GENESIS_PREIMAGE_DIGEST_MAINNET,
            "the honest genesis header matches its pin"
        );
        assert_ne!(
            altered, GENESIS_PREIMAGE_DIGEST_MAINNET,
            "one flipped bit changes the header commitment"
        );
    }

    #[test]
    fn state_root_layout_is_pinned_and_sensitive() {
        assert_eq!(UtxoSet::new().state_root(), EMPTY_STATE_ROOT);
        assert_eq!(layout_probe_set().state_root(), STATE_ROOT_LAYOUT_PROBE);
        // One Fah more in the probe entry must change the root.
        let tampered = layout_probe_set_with_probe_value(1_234_567_890_124);
        assert_ne!(tampered.state_root(), STATE_ROOT_LAYOUT_PROBE);
    }

    #[test]
    fn only_immature_coinbase_spends_isolate_a_peer() {
        let outpoint = Outpoint {
            txid: Hash256([0x55; 32]),
            vout: 0,
        };
        assert!(isolates_peer(&UtxoError::ImmatureCoinbase {
            outpoint,
            matures: 100,
            spent: 50,
        }));
        assert!(!isolates_peer(&UtxoError::NoInputs));
        assert!(!isolates_peer(&UtxoError::MissingInput(outpoint)));
        assert!(!isolates_peer(&UtxoError::DoubleSpend(outpoint)));
        assert!(!isolates_peer(&UtxoError::InputOverflow));
        assert!(!isolates_peer(&UtxoError::OutputOverflow));
    }

    #[test]
    fn maturity_guard_is_exact_at_the_frozen_boundary() {
        let output = TxOut {
            value: 1,
            script_pubkey: Vec::new(),
        };
        let coinbase = UtxoEntry::new(output.clone(), 1_000, true);
        assert!(
            !coinbase.is_mature(1_099),
            "one block short of 100 confirmations is immature"
        );
        assert!(
            coinbase.is_mature(1_100),
            "exactly 100 confirmations is mature"
        );
        assert_eq!(coinbase.spendable_at(), 1_100);
        let ordinary = UtxoEntry::new(output, 1_000, false);
        assert!(
            ordinary.is_mature(1_000),
            "ordinary outputs have no maturity delay"
        );
    }
}
