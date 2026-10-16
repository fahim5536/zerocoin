//! CPU-friendly, ASIC-resistant Proof-of-Work.
//!
//! ZeroCoin's second deviation from Bitcoin. Bitcoin's SHA-256d is cheap per hash
//! and dominated by custom ASICs; ZeroCoin instead uses a **memory-hard scratchpad
//! hash** so that the bottleneck is fast random access to a large working set —
//! something a general-purpose CPU already has and an ASIC gains little from
//! specializing. This keeps mining open to ordinary consumer hardware.
//!
//! The proof of work is pluggable behind [`PowEngine`]:
//! - [`ScratchPadEngine`] — the ASIC-resistant default. It is a CryptoNight-style
//!   construction: derive a seed from the header and nonce, fill a multi-megabyte
//!   scratchpad, then perform many *data-dependent* read-modify-write rounds whose
//!   addresses come from the evolving state. Because the access pattern cannot be
//!   known ahead of time, the whole scratchpad must stay resident, which is exactly
//!   the property that makes the puzzle memory-bound rather than pure-hash-bound.
//! - [`TrivialEngine`] — plain SHA-256d, used only on regtest/devnet so tests and
//!   the local devnet can mine instantly. It is never the mainnet engine.
//!
//! A production deployment can swap in Monero's RandomX by implementing
//! [`PowEngine`] over its bindings; the rest of consensus is agnostic because it
//! only ever calls `engine.hash(...)` and compares the result to the target.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::consensus::difficulty::hash_meets_target;
use crate::consensus::uint256::Uint256;
use crate::crypto::hash::Hash256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PowError {
    #[error("proof-of-work hash {hash} does not meet the required target")]
    InsufficientWork { hash: Hash256 },
    #[error("no nonce below {0} satisfies the target: the block template is unmineable at this difficulty")]
    NonceExhausted(u64),
    #[error("mining was stopped before a proof was found")]
    Aborted,
}

/// A pluggable proof-of-work function. Implementations must be deterministic: the
/// same `(preimage, nonce)` always yields the same hash on every node.
pub trait PowEngine: Send + Sync {
    /// A stable identifier committed to in the block header's engine field.
    fn id(&self) -> u8;

    /// Human-readable engine name for logs and RPC.
    fn name(&self) -> &'static str;

    /// Hash a block-header preimage with a candidate nonce.
    fn hash(&self, preimage: &[u8], nonce: u64) -> Hash256;
}

/// Engine ids committed into the block header, so a block cannot silently switch
/// algorithms without a consensus-visible change.
pub const ENGINE_ID_TRIVIAL: u8 = 0;
pub const ENGINE_ID_SCRATCHPAD: u8 = 1;

/// Plain SHA-256d over `preimage || nonce`. Test/devnet only.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrivialEngine;

impl TrivialEngine {
    pub const fn new() -> Self {
        TrivialEngine
    }
}

impl PowEngine for TrivialEngine {
    fn id(&self) -> u8 {
        ENGINE_ID_TRIVIAL
    }

    fn name(&self) -> &'static str {
        "sha256d-trivial"
    }

    fn hash(&self, preimage: &[u8], nonce: u64) -> Hash256 {
        let mut data = Vec::with_capacity(preimage.len() + 8);
        data.extend_from_slice(preimage);
        data.extend_from_slice(&nonce.to_le_bytes());
        // Double SHA-256, the same primitive Bitcoin uses.
        let first = Sha256::digest(&data);
        Hash256(Sha256::digest(first).into())
    }
}

/// A memory-hard, ASIC-resistant scratchpad hash.
///
/// Cost is governed by two parameters: the scratchpad size (bytes of memory a
/// miner must keep hot) and the number of mixing rounds (data-dependent accesses).
#[derive(Debug, Clone, Copy)]
pub struct ScratchPadEngine {
    /// Scratchpad size in bytes; rounded down to a whole number of 32-byte cells.
    pub memory_bytes: usize,
    /// Number of data-dependent read-modify-write rounds.
    pub rounds: usize,
}

/// 32 bytes per scratchpad cell.
const CELL: usize = 32;

impl ScratchPadEngine {
    pub const fn new(memory_bytes: usize, rounds: usize) -> Self {
        ScratchPadEngine {
            memory_bytes,
            rounds,
        }
    }

    /// A balanced default: 64 KiB scratchpad, 1,024 rounds. Memory-bound enough to
    /// resist hash-only ASICs, light enough to demonstrate and benchmark.
    pub const fn balanced() -> Self {
        ScratchPadEngine::new(64 * 1024, 1_024)
    }

    /// A heavier mainnet profile: 2 MiB scratchpad (CryptoNight-scale), 4,096
    /// rounds. Each hash is deliberately expensive and dominated by memory latency.
    pub const fn mainnet() -> Self {
        ScratchPadEngine::new(2 * 1024 * 1024, 4_096)
    }

    /// The **Mobile/Low-Spec** engine: a 256 MiB scratchpad, memory-hard enough to
    /// resist hash-only ASICs yet small enough for a 4 GB phone to run. A network
    /// that wants low-end hardware to mine adopts this as its consensus engine.
    pub const fn mobile() -> Self {
        ScratchPadEngine::new(MOBILE_SCRATCHPAD_BYTES, 1_024)
    }

    /// The low-spec desktop engine: a 512 MiB scratchpad.
    pub const fn low_spec() -> Self {
        ScratchPadEngine::new(LOW_SPEC_SCRATCHPAD_BYTES, 2_048)
    }

    /// Clamp this engine's scratchpad to a device profile's budget. Used only to
    /// decide what a device may commit *locally*; it never redefines the network's
    /// consensus engine, which every node must match exactly.
    pub fn capped_to(self, profile: HardwareProfile) -> Self {
        let budget = profile.memory_budget_bytes();
        if self.memory_bytes > budget {
            ScratchPadEngine::new(budget, self.rounds)
        } else {
            self
        }
    }

    /// Whether this engine's scratchpad fits in `available_bytes` while leaving the
    /// OS its reserve. A device that gets `false` should not attempt full validation
    /// and should mine shares for a pool instead.
    pub fn fits_in_available_ram(&self, available_bytes: usize) -> bool {
        self.memory_bytes
            .saturating_add(OS_MEMORY_RESERVE_BYTES)
            <= available_bytes
    }

    fn cells(&self) -> usize {
        (self.memory_bytes / CELL).max(1)
    }
}

/// The default ASIC-resistant engine committed to by mainnet blocks.
pub const DEFAULT_ENGINE: ScratchPadEngine = ScratchPadEngine::balanced();

/// The scratchpad a **Mobile/Low-Spec Mode** node commits: 256 MiB. Bounded so a
/// 4 GB phone can run the memory-hard hash for both *validation* and *mining*
/// without the OS killing it for memory pressure.
///
/// This is a **consensus** value, not a per-device preference. The scratchpad length
/// is an input to the hash, so two nodes that allocate different amounts compute
/// different hashes and fork the chain. A network that wants to be mineable on
/// low-end hardware adopts [`ScratchPadEngine::mobile`] as its single engine and
/// *every* node — phone or rig — uses exactly this size. A device that cannot
/// allocate it must never silently shrink it; it should run as a share-submitting
/// light miner instead (see [`crate::pool`]).
pub const MOBILE_SCRATCHPAD_BYTES: usize = 256 * 1024 * 1024;
/// The low-spec desktop ceiling: 512 MiB.
pub const LOW_SPEC_SCRATCHPAD_BYTES: usize = 512 * 1024 * 1024;
/// Head-room a device keeps free for the OS when deciding it can run an engine.
pub const OS_MEMORY_RESERVE_BYTES: usize = 1024 * 1024 * 1024;

/// Hard ceiling on mining threads for a phone: exactly one core, ever.
pub const MAX_THREADS_MOBILE: usize = 1;
/// Hard ceiling on mining threads for a low-end PC: at most two cores.
pub const MAX_THREADS_LOW_SPEC: usize = 2;
/// Hard ceiling on mining threads for *any* device, regardless of profile or of
/// what a [`MiningConfig`] claims. No runtime flag, environment variable or
/// corrupted value may raise the thread footprint past this.
pub const MAX_THREADS_ABSOLUTE: usize = 64;

impl PowEngine for ScratchPadEngine {
    fn id(&self) -> u8 {
        ENGINE_ID_SCRATCHPAD
    }

    fn name(&self) -> &'static str {
        "scratchpad-memory-hard"
    }

    fn hash(&self, preimage: &[u8], nonce: u64) -> Hash256 {
        let cell_count = self.cells();
        let mut scratchpad = vec![[0u8; CELL]; cell_count];

        // 1. Seed from the header preimage and the nonce.
        let mut seed_input = Vec::with_capacity(preimage.len() + 8);
        seed_input.extend_from_slice(preimage);
        seed_input.extend_from_slice(&nonce.to_le_bytes());
        let mut state: [u8; 32] = Sha256::digest(&seed_input).into();

        // 2. Fill the scratchpad with a hash chain seeded by `state`. Filling is
        //    sequential, but every byte must later be reachable at random, so the
        //    whole pad has to live in memory.
        for cell in scratchpad.iter_mut() {
            state = Sha256::digest(state).into();
            *cell = state;
        }

        // 3. Data-dependent read-modify-write rounds. The next index is derived from
        //    the current state, so the access pattern is unpredictable and cannot be
        //    pipelined or precomputed — the property that defeats hash-only ASICs.
        let mask = (cell_count - 1) as u64;
        let power_of_two = cell_count.is_power_of_two();
        for _ in 0..self.rounds {
            let index_word = u64::from_le_bytes(state[0..8].try_into().unwrap());
            let index = if power_of_two {
                (index_word & mask) as usize
            } else {
                (index_word % cell_count as u64) as usize
            };
            // Mix the addressed cell into the state, then write the result back so
            // later rounds depend on earlier writes.
            let mut mixed = [0u8; 64];
            mixed[..32].copy_from_slice(&state);
            mixed[32..].copy_from_slice(&scratchpad[index]);
            state = Sha256::digest(mixed).into();
            scratchpad[index] = state;
        }

        // 4. Fold the scratchpad into the final digest so the result commits to the
        //    entire memory-hard computation, not just the final state.
        let mut finalizer = Sha256::new();
        finalizer.update(state);
        for cell in &scratchpad {
            finalizer.update(cell);
        }
        Hash256(finalizer.finalize().into())
    }
}

/// Check a candidate proof of work: hash the preimage and require it to be at or
/// below the target. This is the whole of a node's PoW validation.
pub fn verify_pow(
    engine: &dyn PowEngine,
    preimage: &[u8],
    nonce: u64,
    target: &Uint256,
) -> Result<Hash256, PowError> {
    let hash = engine.hash(preimage, nonce);
    if hash_meets_target(&hash, target) {
        Ok(hash)
    } else {
        Err(PowError::InsufficientWork { hash })
    }
}

/// Search nonces from `start` upward until one meets the target. Used by a miner;
/// a validator never calls this, it only calls [`verify_pow`].
pub fn mine(
    engine: &dyn PowEngine,
    preimage: &[u8],
    target: &Uint256,
    start: u64,
) -> Result<(u64, Hash256), PowError> {
    let mut nonce = start;
    loop {
        let hash = engine.hash(preimage, nonce);
        if hash_meets_target(&hash, target) {
            return Ok((nonce, hash));
        }
        nonce = nonce.checked_add(1).ok_or(PowError::NonceExhausted(u64::MAX))?;
    }
}

// ---------------------------------------------------------------------------
// Device profiles and eco-mining (non-consensus ergonomics)
// ---------------------------------------------------------------------------

/// A device capability tier. This governs **ergonomics only** — how many threads to
/// mine on, whether to throttle to protect a battery, and how much memory the device
/// can safely commit. It never changes the proof-of-work hash: that is fixed by the
/// network's [`crate::params::EngineSpec`] and is identical on every node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareProfile {
    /// A phone or tablet: exactly one core ([`MAX_THREADS_MOBILE`]), aggressive
    /// thermal throttling, <= 256 MiB pad.
    Mobile,
    /// A low-end PC / single-board computer: at most two cores
    /// ([`MAX_THREADS_LOW_SPEC`]), mild throttling, <= 512 MiB.
    LowSpec,
    /// An ordinary desktop: half the cores, no throttling.
    Desktop,
    /// A server / mining rig: all cores, no throttling.
    Server,
}

impl HardwareProfile {
    /// Classify a device from its usable RAM and core count. `ram_bytes` is `None`
    /// when the platform cannot report it, so we fall back to cores and stay
    /// conservative (a mis-classification only costs hashrate, never correctness).
    pub fn classify(ram_bytes: Option<usize>, cores: usize) -> Self {
        let cores = cores.max(1);
        match ram_bytes {
            Some(ram) if ram <= 4 * 1024 * 1024 * 1024 => HardwareProfile::Mobile,
            Some(ram) if ram <= 8 * 1024 * 1024 * 1024 => HardwareProfile::LowSpec,
            Some(ram) if ram <= 16 * 1024 * 1024 * 1024 => HardwareProfile::Desktop,
            Some(_) => HardwareProfile::Server,
            None if cores <= 2 => HardwareProfile::Mobile,
            None if cores <= 4 => HardwareProfile::LowSpec,
            None if cores <= 8 => HardwareProfile::Desktop,
            None => HardwareProfile::Server,
        }
    }

    /// Best-effort detection on the current machine.
    pub fn detect() -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        HardwareProfile::classify(available_ram_bytes(), cores)
    }

    /// The thread ceiling this profile may *ever* use, given a machine with `cores`
    /// usable cores. Frozen (Rule 3, hardware safety governance): a phone is pinned
    /// to [`MAX_THREADS_MOBILE`] and a low-spec PC to [`MAX_THREADS_LOW_SPEC`] no
    /// matter how many cores exist, and every profile is clamped below
    /// [`MAX_THREADS_ABSOLUTE`]. A `const fn` so the ceilings are checked by
    /// compile-time assertions in [`crate::consensus::immutability`], and by-value so
    /// it evaluates in const contexts.
    pub const fn max_mining_threads_for(self, cores: usize) -> usize {
        let cores = if cores == 0 { 1 } else { cores };
        match self {
            HardwareProfile::Mobile => MAX_THREADS_MOBILE,
            HardwareProfile::LowSpec => MAX_THREADS_LOW_SPEC,
            HardwareProfile::Desktop => {
                let half = cores / 2;
                let wanted = if half == 0 { 1 } else { half };
                if wanted > MAX_THREADS_ABSOLUTE {
                    MAX_THREADS_ABSOLUTE
                } else {
                    wanted
                }
            }
            HardwareProfile::Server => {
                if cores > MAX_THREADS_ABSOLUTE {
                    MAX_THREADS_ABSOLUTE
                } else {
                    cores
                }
            }
        }
    }

    /// Threads this device should mine on, using the machine's actual core count.
    pub fn max_mining_threads(&self) -> usize {
        self.max_mining_threads_for(available_cores())
    }

    /// Cooling interval slept between hash attempts to protect a battery and cap the
    /// temperature. `None` means mine at full speed.
    pub fn eco_throttle(&self) -> Option<Duration> {
        match self {
            HardwareProfile::Mobile => Some(Duration::from_millis(30)),
            HardwareProfile::LowSpec => Some(Duration::from_millis(20)),
            HardwareProfile::Desktop | HardwareProfile::Server => None,
        }
    }

    /// The largest scratchpad this device may commit. Frozen (Rule 3): the mobile
    /// budget is exactly [`MOBILE_SCRATCHPAD_BYTES`] and the low-spec budget exactly
    /// [`LOW_SPEC_SCRATCHPAD_BYTES`]. A `const fn` so the budgets are checked by
    /// compile-time assertions in [`crate::consensus::immutability`].
    pub const fn memory_budget_bytes(self) -> usize {
        match self {
            HardwareProfile::Mobile => MOBILE_SCRATCHPAD_BYTES,
            HardwareProfile::LowSpec | HardwareProfile::Desktop => LOW_SPEC_SCRATCHPAD_BYTES,
            HardwareProfile::Server => usize::MAX,
        }
    }
}

fn available_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Best-effort usable-RAM probe. Reads `MemAvailable` on Linux; returns `None`
/// elsewhere rather than guess, so callers fall back to a core-count heuristic.
fn available_ram_bytes() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: usize = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// How a miner drives the nonce search: how many cores, and whether to cool between
/// attempts. Throttling changes only how *fast* this device searches; it never
/// changes a hash, so it cannot affect consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningConfig {
    /// Maximum CPU threads to search on. Clamped at [`MAX_THREADS_ABSOLUTE`]; eco
    /// profiles pin this to one.
    pub max_threads: usize,
    /// Sleep between nonce attempts, or `None` for full speed.
    pub throttle: Option<Duration>,
}

impl Default for MiningConfig {
    fn default() -> Self {
        MiningConfig::full_speed()
    }
}

impl MiningConfig {
    /// Full speed, all available cores.
    pub fn full_speed() -> Self {
        MiningConfig {
            max_threads: available_cores(),
            throttle: None,
        }
    }

    /// The throttle-safe thread count this configuration will actually run: at most
    /// one thread when throttled (a cooling interval is honoured once per attempt on
    /// the single-threaded path), at least one always, and never above
    /// [`MAX_THREADS_ABSOLUTE`] however the config was built. This is the single
    /// choke point every mining entry runs through, so no runtime flag or corrupted
    /// value can escalate the thread footprint past the hard ceiling.
    pub fn effective_threads(&self) -> usize {
        if self.throttle.is_some() {
            return 1;
        }
        if self.max_threads > MAX_THREADS_ABSOLUTE {
            MAX_THREADS_ABSOLUTE
        } else if self.max_threads == 0 {
            1
        } else {
            self.max_threads
        }
    }

    /// The eco settings for a device profile: mobile/low-spec mine on exactly one
    /// core with a cooling interval; the rest mine at full speed.
    pub fn for_profile(profile: HardwareProfile) -> Self {
        MiningConfig {
            max_threads: profile.max_mining_threads(),
            throttle: profile.eco_throttle(),
        }
    }

    /// The canonical mobile eco-miner: one core, 30 ms cooling per attempt.
    pub fn mobile_eco() -> Self {
        MiningConfig {
            max_threads: 1,
            throttle: Some(Duration::from_millis(30)),
        }
    }
}

/// Mine under an explicit [`MiningConfig`], optionally stopping early if `stop` is
/// set. Eco mode (one thread + throttle) and full-speed multi-core search both route
/// through here. The throttle only paces the search; the hash a nonce produces is
/// identical to [`mine`], so a block or share found in eco mode validates everywhere.
pub fn mine_with_config(
    engine: &dyn PowEngine,
    preimage: &[u8],
    target: &Uint256,
    start: u64,
    config: &MiningConfig,
    stop: Option<&AtomicBool>,
) -> Result<(u64, Hash256), PowError> {
    // Rule 3 (hardware safety governance): every path funnels through the clamp, so
    // a rogue `max_threads` (a corrupted flag, a hostile default) can never spawn
    // more than MAX_THREADS_ABSOLUTE workers.
    let threads = config.effective_threads();
    if threads == 1 {
        // Eco / single-core path. A throttle forces single-threaded search so the
        // cooling interval is honoured exactly once per attempt.
        mine_throttled(engine, preimage, target, start, config.throttle, stop)
    } else {
        mine_parallel(engine, preimage, target, start, threads, stop)
    }
}

fn mine_throttled(
    engine: &dyn PowEngine,
    preimage: &[u8],
    target: &Uint256,
    start: u64,
    throttle: Option<Duration>,
    stop: Option<&AtomicBool>,
) -> Result<(u64, Hash256), PowError> {
    let mut nonce = start;
    loop {
        if let Some(flag) = stop {
            if flag.load(Ordering::Relaxed) {
                return Err(PowError::Aborted);
            }
        }
        let hash = engine.hash(preimage, nonce);
        if hash_meets_target(&hash, target) {
            return Ok((nonce, hash));
        }
        // Cooling interval, paced *between* attempts so it never touches the hash.
        if let Some(interval) = throttle {
            std::thread::sleep(interval);
        }
        nonce = nonce.checked_add(1).ok_or(PowError::NonceExhausted(u64::MAX))?;
    }
}

fn mine_parallel(
    engine: &dyn PowEngine,
    preimage: &[u8],
    target: &Uint256,
    start: u64,
    threads: usize,
    stop: Option<&AtomicBool>,
) -> Result<(u64, Hash256), PowError> {
    use std::sync::Mutex;
    let found = AtomicBool::new(false);
    let best: Mutex<Option<(u64, Hash256)>> = Mutex::new(None);
    std::thread::scope(|scope| {
        for worker in 0..threads {
            let found = &found;
            let best = &best;
            scope.spawn(move || {
                let stride = threads as u64;
                let mut nonce = start.saturating_add(worker as u64);
                loop {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(flag) = stop {
                        if flag.load(Ordering::Relaxed) {
                            return;
                        }
                    }
                    let hash = engine.hash(preimage, nonce);
                    if hash_meets_target(&hash, target) {
                        let mut guard = best.lock().unwrap();
                        if guard.is_none() {
                            *guard = Some((nonce, hash));
                        }
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                    match nonce.checked_add(stride) {
                        Some(next) => nonce = next,
                        None => return,
                    }
                }
            });
        }
    });
    best.into_inner().unwrap().ok_or(PowError::Aborted)
}

// ---------------------------------------------------------------------------
// Partial proofs of work ("shares") for the in-built pool
// ---------------------------------------------------------------------------

/// A share is this much easier to find than a block by default (2^20, about one
/// million times easier), so a phone that could never win a block race can still
/// produce valid proofs steadily and earn a proportional micro-reward.
pub const DEFAULT_SHARE_EASINESS: u64 = 1 << 20;

/// The easier target a partial proof must meet to count as a share: the block target
/// scaled up by `easiness` (a larger target is easier), never above the network's
/// `pow_limit`. The math is overflow-safe — it compares against `pow_limit / easiness`
/// before multiplying, so the 256-bit product can never wrap.
pub fn share_target(block_target: &Uint256, easiness: u64, pow_limit: &Uint256) -> Uint256 {
    if easiness <= 1 || *block_target >= *pow_limit {
        return clamp_to_limit(*block_target, pow_limit);
    }
    let threshold = pow_limit.div_u64(easiness);
    if *block_target > threshold {
        return *pow_limit;
    }
    clamp_to_limit(block_target.mul_u64(easiness), pow_limit)
}

fn clamp_to_limit(target: Uint256, pow_limit: &Uint256) -> Uint256 {
    if target.is_zero() || target > *pow_limit {
        *pow_limit
    } else {
        target
    }
}

/// Validate a partial proof against the (easier) share target. This is the whole of
/// a pool coordinator's share check: one hash, compared to the share target. It mints
/// nothing and touches no consensus state, so a flood of bogus shares costs a peer
/// only a single hash each and can never inflate the supply.
pub fn validate_share(
    engine: &dyn PowEngine,
    preimage: &[u8],
    nonce: u64,
    share_target: &Uint256,
) -> Result<Hash256, PowError> {
    verify_pow(engine, preimage, nonce, share_target)
}

/// Search for a share under an eco [`MiningConfig`] — the low-power path a mobile
/// miner runs to produce partial proofs for the pool.
pub fn mine_share_with_config(
    engine: &dyn PowEngine,
    preimage: &[u8],
    share_target: &Uint256,
    start: u64,
    config: &MiningConfig,
    stop: Option<&AtomicBool>,
) -> Result<(u64, Hash256), PowError> {
    mine_with_config(engine, preimage, share_target, start, config, stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::difficulty::compact_to_target;

    // Tiny parameters so the test suite stays fast while covering the same path.
    fn fast_engine() -> ScratchPadEngine {
        ScratchPadEngine::new(4 * 1024, 64)
    }

    #[test]
    fn trivial_engine_is_double_sha256() {
        let engine = TrivialEngine::new();
        let a = engine.hash(b"block", 1);
        let b = engine.hash(b"block", 1);
        let c = engine.hash(b"block", 2);
        assert_eq!(a, b, "deterministic for the same nonce");
        assert_ne!(a, c, "different nonce => different hash");
    }

    #[test]
    fn scratchpad_engine_is_deterministic_and_nonce_sensitive() {
        let engine = fast_engine();
        assert_eq!(engine.hash(b"header", 7), engine.hash(b"header", 7));
        assert_ne!(engine.hash(b"header", 7), engine.hash(b"header", 8));
        assert_ne!(engine.hash(b"header", 7), engine.hash(b"other", 7));
    }

    #[test]
    fn scratchpad_engine_differs_from_trivial() {
        let pad = fast_engine();
        let trivial = TrivialEngine::new();
        assert_ne!(pad.hash(b"x", 0), trivial.hash(b"x", 0));
        assert_ne!(pad.id(), trivial.id());
    }

    #[test]
    fn mining_finds_a_nonce_that_verifies() {
        let engine = fast_engine();
        // A very easy target (difficulty floor) so mining terminates immediately.
        let target = compact_to_target(0x207f_ffff);
        let (nonce, hash) = mine(&engine, b"template", &target, 0).expect("mines");
        assert_eq!(verify_pow(&engine, b"template", nonce, &target), Ok(hash));
    }

    #[test]
    fn verify_rejects_insufficient_work() {
        let engine = fast_engine();
        // A near-impossible target: the all-zeros-ish target no random hash meets.
        let hard = Uint256::from_u64(1);
        assert!(matches!(
            verify_pow(&engine, b"template", 0, &hard),
            Err(PowError::InsufficientWork { .. })
        ));
    }

    #[test]
    fn scratchpad_size_rounds_to_cells() {
        let engine = ScratchPadEngine::new(100, 1); // < one full 32-byte cell boundary
        assert!(engine.cells() >= 1);
    }

    #[test]
    fn engine_ids_are_distinct_and_stable() {
        assert_eq!(TrivialEngine::new().id(), ENGINE_ID_TRIVIAL);
        assert_eq!(DEFAULT_ENGINE.id(), ENGINE_ID_SCRATCHPAD);
        assert_eq!(DEFAULT_ENGINE.name(), "scratchpad-memory-hard");
    }

    #[test]
    fn eco_throttle_never_changes_the_hash() {
        let engine = fast_engine();
        // Every nonce meets the maximum target, so the search stops at `start`.
        let target = Uint256::MAX;
        let direct = engine.hash(b"template", 3);
        let eco = MiningConfig {
            max_threads: 1,
            throttle: Some(Duration::from_millis(1)),
        };
        let (nonce, hash) =
            mine_with_config(&engine, b"template", &target, 3, &eco, None).expect("mines");
        // Eco mode paces the search; the proof it produces is byte-identical.
        assert_eq!(nonce, 3);
        assert_eq!(hash, direct);
    }

    #[test]
    fn mobile_profile_is_single_core_and_throttled_within_20_to_30ms() {
        let eco = MiningConfig::for_profile(HardwareProfile::Mobile);
        assert_eq!(eco.max_threads, 1, "mobile mines on exactly one core");
        let interval = eco.throttle.expect("mobile throttles");
        assert!(interval >= Duration::from_millis(20) && interval <= Duration::from_millis(30));
        // A low-spec PC is capped at two cores and inside the cooling window.
        let low = MiningConfig::for_profile(HardwareProfile::LowSpec);
        assert_eq!(low.max_threads, 2);
        assert!(low.throttle.is_some());
        // A server neither pins to one core nor throttles.
        let server = MiningConfig::for_profile(HardwareProfile::Server);
        assert!(server.throttle.is_none());
    }

    #[test]
    fn thread_footprint_cannot_be_escalated_past_the_hard_caps() {
        // Profile ceilings: a phone is one core and a low-spec PC two, even on a
        // machine that reports a thousand cores.
        assert_eq!(
            HardwareProfile::Mobile.max_mining_threads_for(1_000),
            MAX_THREADS_MOBILE
        );
        assert_eq!(
            HardwareProfile::LowSpec.max_mining_threads_for(1_000),
            MAX_THREADS_LOW_SPEC
        );
        // Desktop (half the cores) and Server (all cores) are clamped absolutely.
        assert_eq!(
            HardwareProfile::Desktop.max_mining_threads_for(usize::MAX),
            MAX_THREADS_ABSOLUTE
        );
        assert_eq!(
            HardwareProfile::Server.max_mining_threads_for(usize::MAX),
            MAX_THREADS_ABSOLUTE
        );
        // A zero-core (or corrupted) report still yields one worker, never zero.
        assert_eq!(HardwareProfile::Server.max_mining_threads_for(0), 1);

        // A rogue MiningConfig cannot raise the footprint: it is clamped down.
        let rogue = MiningConfig {
            max_threads: usize::MAX,
            throttle: None,
        };
        assert_eq!(rogue.effective_threads(), MAX_THREADS_ABSOLUTE);
        // A zero thread count still mines on exactly one thread.
        let zero = MiningConfig {
            max_threads: 0,
            throttle: None,
        };
        assert_eq!(zero.effective_threads(), 1);
        // Throttled configs are pinned to a single thread whatever they claim.
        let throttled = MiningConfig {
            max_threads: 8,
            throttle: Some(Duration::from_millis(1)),
        };
        assert_eq!(throttled.effective_threads(), 1);
        // Eco profiles never exceed their hard ceilings either.
        assert_eq!(MiningConfig::mobile_eco().effective_threads(), 1);
        assert_eq!(
            MiningConfig::for_profile(HardwareProfile::LowSpec).effective_threads(),
            1
        );

        // End to end: even a zero thread count mines (clamped to the one-thread
        // path) and finds the first candidate under the maximum target.
        let engine = fast_engine();
        let (nonce, _hash) =
            mine_with_config(&engine, b"clamp", &Uint256::MAX, 0, &zero, None)
                .expect("mines on the clamped single-thread path");
        assert_eq!(nonce, 0);
    }

    #[test]
    fn classify_scales_with_device_resources() {
        assert_eq!(
            HardwareProfile::classify(Some(3 * 1024 * 1024 * 1024), 8),
            HardwareProfile::Mobile
        );
        assert_eq!(
            HardwareProfile::classify(Some(6 * 1024 * 1024 * 1024), 4),
            HardwareProfile::LowSpec
        );
        assert_eq!(
            HardwareProfile::classify(Some(32 * 1024 * 1024 * 1024), 16),
            HardwareProfile::Server
        );
        // With no RAM report, cores decide, conservatively.
        assert_eq!(HardwareProfile::classify(None, 2), HardwareProfile::Mobile);
    }

    #[test]
    fn mobile_engine_memory_is_phone_safe_and_capped() {
        assert!(ScratchPadEngine::mobile().memory_bytes <= MOBILE_SCRATCHPAD_BYTES);
        assert!(MOBILE_SCRATCHPAD_BYTES <= 256 * 1024 * 1024);
        assert!(LOW_SPEC_SCRATCHPAD_BYTES <= 512 * 1024 * 1024);
        // A 4 GB phone with ~2 GB free can run the 256 MiB mobile engine plus reserve.
        assert!(ScratchPadEngine::mobile().fits_in_available_ram(2 * 1024 * 1024 * 1024));
        // A 4 GiB engine is clamped down to the mobile budget, never the reverse.
        let clamped =
            ScratchPadEngine::new(4 * 1024 * 1024 * 1024, 10).capped_to(HardwareProfile::Mobile);
        assert_eq!(clamped.memory_bytes, MOBILE_SCRATCHPAD_BYTES);
    }

    #[test]
    fn stop_flag_aborts_mining_before_any_hash() {
        let engine = fast_engine();
        let impossible = Uint256::from_u64(1);
        let stop = AtomicBool::new(true);
        assert!(matches!(
            mine_with_config(
                &engine,
                b"x",
                &impossible,
                0,
                &MiningConfig::mobile_eco(),
                Some(&stop)
            ),
            Err(PowError::Aborted)
        ));
    }

    #[test]
    fn parallel_miner_finds_a_verifiable_nonce() {
        let engine = fast_engine();
        let target = compact_to_target(0x1f7f_ffff); // about 1-in-256 work
        let cfg = MiningConfig {
            max_threads: 4,
            throttle: None,
        };
        let (nonce, hash) =
            mine_with_config(&engine, b"parallel", &target, 0, &cfg, None).expect("mines");
        assert_eq!(verify_pow(&engine, b"parallel", nonce, &target), Ok(hash));
    }

    #[test]
    fn share_target_is_easier_than_the_block_and_bounded_by_the_floor() {
        let block = compact_to_target(0x1d00_ffff);
        let limit = compact_to_target(0x207f_ffff);
        let share = share_target(&block, DEFAULT_SHARE_EASINESS, &limit);
        assert!(share >= block, "a share target is at least as easy as a block");
        assert!(share <= limit, "never easier than the network floor");
        // At the floor already (regtest/devnet), shares equal the limit.
        let at_floor = share_target(&limit, DEFAULT_SHARE_EASINESS, &limit);
        assert_eq!(at_floor, limit);
    }

    #[test]
    fn a_mined_share_validates_as_a_share() {
        let engine = fast_engine();
        let limit = compact_to_target(0x207f_ffff);
        let block = compact_to_target(0x1d00_ffff);
        let share = share_target(&block, 1 << 16, &limit);
        let (nonce, _hash) = mine_share_with_config(
            &engine,
            b"share",
            &share,
            0,
            &MiningConfig::full_speed(),
            None,
        )
        .expect("a share is easy to find");
        assert!(validate_share(&engine, b"share", nonce, &share).is_ok());
    }
}
