//! Per-network consensus parameters.
//!
//! A [`ChainParams`] is the single object that says *which* ZeroCoin network a node
//! is on and how that network's consensus is tuned: its chain id (mixed into every
//! signature so a devnet transaction can never replay on mainnet), its proof-of-work
//! engine, its difficulty schedule, its genesis starting difficulty, and the human
//! conventions around it (address prefix, default ports).
//!
//! Three networks are defined, mirroring Bitcoin's trio:
//!
//! - **mainnet** — the real network. ASIC-resistant scratchpad PoW at CryptoNight
//!   scale, 60-second blocks retargeting every 1,440 blocks, `0x1e00ffff` floor.
//! - **devnet** — a public testing network. The same scratchpad engine at a lighter
//!   profile and an easy floor, so blocks are found quickly without giving up the
//!   ASIC-resistant hash.
//! - **regtest** — a local, private network. Trivial SHA-256d PoW at the easiest
//!   target with retargeting disabled, so a single process can mine on demand. This
//!   is what the devnet setup guide and the test suite use.
//!
//! Everything that varies by network lives here; the consensus code reads these
//! values rather than hard-coding them, so one implementation serves all three.

use crate::consensus::difficulty::Params as DifficultyParams;
use crate::consensus::pow::{
    PowEngine, ScratchPadEngine, TrivialEngine, ENGINE_ID_SCRATCHPAD, ENGINE_ID_TRIVIAL,
};
use crate::ledger::sighash::ChainId;

/// Mainnet chain id. Folded into sighash preimages and block headers.
pub const MAINNET_CHAIN: ChainId = ChainId(0x5A52_4F01);
/// Public devnet chain id.
pub const DEVNET_CHAIN: ChainId = ChainId(0x5A52_4F02);
/// Local regtest chain id.
pub const REGTEST_CHAIN: ChainId = ChainId(0x5A52_4F00);

/// The moment block 0 is defined to have been struck. Fixed, because the timestamp
/// is inside the hashed header: every node must derive the identical genesis hash,
/// and a node that stamped its own start time would fork onto a private chain.
pub const GENESIS_TIMESTAMP: u64 = 1_735_689_600; // 2025-01-01T00:00:00Z

/// The mainnet difficulty floor: `0x1e00ffff`, the same shape as Bitcoin's
/// difficulty-1 target.
pub const MAINNET_POW_LIMIT_BITS: u32 = 0x1e00_ffff;
/// The easiest target a fast network uses so blocks are found in a hash or two.
pub const TRIVIAL_POW_LIMIT_BITS: u32 = 0x207f_ffff;

/// Which proof-of-work engine a network runs, and how heavy it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineSpec {
    /// Plain SHA-256d. Regtest only; never a public network.
    Trivial,
    /// The ASIC-resistant memory-hard scratchpad hash.
    Scratchpad { memory_bytes: usize, rounds: usize },
}

impl EngineSpec {
    /// The engine id committed into block headers.
    pub fn id(&self) -> u8 {
        match self {
            EngineSpec::Trivial => ENGINE_ID_TRIVIAL,
            EngineSpec::Scratchpad { .. } => ENGINE_ID_SCRATCHPAD,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EngineSpec::Trivial => "sha256d-trivial",
            EngineSpec::Scratchpad { .. } => "scratchpad-memory-hard",
        }
    }

    /// Instantiate the engine. Called once per node; the result is shared by every
    /// mining and validation call.
    pub fn build(&self) -> Box<dyn PowEngine> {
        match self {
            EngineSpec::Trivial => Box::new(TrivialEngine::new()),
            EngineSpec::Scratchpad {
                memory_bytes,
                rounds,
            } => Box::new(ScratchPadEngine::new(*memory_bytes, *rounds)),
        }
    }
}

/// A complete description of one ZeroCoin network.
#[derive(Clone, Copy, Debug)]
pub struct ChainParams {
    pub name: &'static str,
    pub chain_id: ChainId,
    pub engine: EngineSpec,
    /// Difficulty schedule: 60-second target, 1,440-block window, 4x clamp.
    pub difficulty: DifficultyParams,
    /// Starting (and floor) difficulty, in compact form.
    pub genesis_bits: u32,
    /// When false, difficulty is pinned at `genesis_bits` and never retargets
    /// (regtest), so a local node can mine instantly and predictably.
    pub allow_pow_retarget: bool,
    /// Base58Check version byte for P2PKH addresses (0x00 mainnet, 0x6f test).
    pub base58_pubkey_prefix: u8,
    pub default_p2p_port: u16,
    pub default_rpc_port: u16,
}

impl ChainParams {
    /// The real network: ASIC-resistant PoW, retargeting on, mainnet floor. Frozen:
    /// a `const fn` so [`crate::consensus::immutability`] can pin every field at
    /// compile time.
    pub const fn mainnet() -> Self {
        ChainParams {
            name: "mainnet",
            chain_id: MAINNET_CHAIN,
            engine: EngineSpec::Scratchpad {
                memory_bytes: 2 * 1024 * 1024,
                rounds: 4_096,
            },
            difficulty: DifficultyParams {
                target_spacing_seconds: 60,
                retarget_interval: 1_440,
                max_adjustment_factor: 4,
                pow_limit_bits: MAINNET_POW_LIMIT_BITS,
            },
            genesis_bits: MAINNET_POW_LIMIT_BITS,
            allow_pow_retarget: true,
            base58_pubkey_prefix: 0x00,
            default_p2p_port: 8233,
            default_rpc_port: 8232,
        }
    }

    /// A public testing network: the ASIC-resistant engine at a lighter profile and
    /// an easy floor, so blocks are quick to find without abandoning the real hash.
    /// Frozen: a `const fn` for compile-time assertions.
    pub const fn devnet() -> Self {
        ChainParams {
            name: "devnet",
            chain_id: DEVNET_CHAIN,
            engine: EngineSpec::Scratchpad {
                memory_bytes: 64 * 1024,
                rounds: 1_024,
            },
            difficulty: DifficultyParams {
                target_spacing_seconds: 60,
                retarget_interval: 1_440,
                max_adjustment_factor: 4,
                pow_limit_bits: TRIVIAL_POW_LIMIT_BITS,
            },
            genesis_bits: TRIVIAL_POW_LIMIT_BITS,
            allow_pow_retarget: true,
            base58_pubkey_prefix: 0x6f,
            default_p2p_port: 18233,
            default_rpc_port: 18232,
        }
    }

    /// A local, private network: trivial PoW, retargeting off, instant blocks.
    /// Frozen: a `const fn` for compile-time assertions.
    pub const fn regtest() -> Self {
        ChainParams {
            name: "regtest",
            chain_id: REGTEST_CHAIN,
            engine: EngineSpec::Trivial,
            difficulty: DifficultyParams {
                target_spacing_seconds: 60,
                retarget_interval: 1_440,
                max_adjustment_factor: 4,
                pow_limit_bits: TRIVIAL_POW_LIMIT_BITS,
            },
            genesis_bits: TRIVIAL_POW_LIMIT_BITS,
            allow_pow_retarget: false,
            base58_pubkey_prefix: 0x6f,
            default_p2p_port: 18444,
            default_rpc_port: 18443,
        }
    }

    /// Look up a network by name, as given on the command line.
    pub fn by_name(name: &str) -> Option<ChainParams> {
        match name {
            "mainnet" => Some(ChainParams::mainnet()),
            "devnet" => Some(ChainParams::devnet()),
            "regtest" | "test" => Some(ChainParams::regtest()),
            _ => None,
        }
    }

    /// Build this network's proof-of-work engine.
    pub fn build_engine(&self) -> Box<dyn PowEngine> {
        self.engine.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_targets_sixty_second_blocks() {
        for params in [
            ChainParams::mainnet(),
            ChainParams::devnet(),
            ChainParams::regtest(),
        ] {
            assert_eq!(params.difficulty.target_spacing_seconds, 60);
            assert_eq!(params.difficulty.retarget_interval, 1_440);
            assert_eq!(params.difficulty.target_window_seconds(), 86_400);
        }
    }

    #[test]
    fn chain_ids_are_distinct() {
        assert_ne!(MAINNET_CHAIN, DEVNET_CHAIN);
        assert_ne!(DEVNET_CHAIN, REGTEST_CHAIN);
        assert_ne!(MAINNET_CHAIN, REGTEST_CHAIN);
    }

    #[test]
    fn engine_ids_match_their_spec() {
        assert_eq!(ChainParams::regtest().engine.id(), ENGINE_ID_TRIVIAL);
        assert_eq!(ChainParams::devnet().engine.id(), ENGINE_ID_SCRATCHPAD);
        assert_eq!(ChainParams::mainnet().engine.id(), ENGINE_ID_SCRATCHPAD);
    }

    #[test]
    fn genesis_bits_never_exceed_the_pow_limit() {
        // The starting difficulty must be legal under the network's own floor, or
        // block 0 would fail `validate_bits`.
        for params in [
            ChainParams::mainnet(),
            ChainParams::devnet(),
            ChainParams::regtest(),
        ] {
            assert_eq!(params.genesis_bits, params.difficulty.pow_limit_bits);
        }
    }

    #[test]
    fn by_name_resolves_known_networks() {
        assert_eq!(ChainParams::by_name("regtest").unwrap().name, "regtest");
        assert_eq!(ChainParams::by_name("devnet").unwrap().name, "devnet");
        assert!(ChainParams::by_name("nonsense").is_none());
    }

    #[test]
    fn regtest_pins_difficulty() {
        assert!(!ChainParams::regtest().allow_pow_retarget);
        assert!(ChainParams::mainnet().allow_pow_retarget);
    }
}
