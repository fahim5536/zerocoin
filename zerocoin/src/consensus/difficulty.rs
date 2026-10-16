//! Difficulty retargeting: a 60-second target block time, adjusted every 1,440
//! blocks using Bitcoin's simple-moving-average rule.
//!
//! ZeroCoin's first deviation from Bitcoin. Bitcoin targets one block every 600
//! seconds and retargets every 2,016 blocks (two weeks). ZeroCoin targets one
//! block every **60 seconds** and retargets every **1,440 blocks**, which is the
//! same two ideas on a faster clock: 1,440 × 60s = 86,400s = 24 hours.
//!
//! The retarget formula is Bitcoin's, unchanged in shape. At each boundary the
//! network measures how long the previous window *actually* took, clamps that
//! timespan to `[¼, 4]×` the ideal window so a single outlier cannot swing
//! difficulty wildly, and scales the target by `actual / expected`. Blocks arriving
//! too fast shrink the target (more work required); blocks arriving too slowly grow
//! it (less work). The target is never allowed above `pow_limit`, the easiest
/// difficulty the network permits.

use crate::consensus::uint256::Uint256;
use crate::crypto::hash::Hash256;

/// Immutable retargeting parameters for a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Desired seconds between blocks. ZeroCoin: 60.
    pub target_spacing_seconds: u64,
    /// Blocks per retarget window. ZeroCoin: 1,440 (24 hours).
    pub retarget_interval: u64,
    /// Per-window clamp: difficulty may move by at most this factor. Bitcoin: 4.
    pub max_adjustment_factor: u64,
    /// Compact encoding of the easiest allowed target (the difficulty floor).
    pub pow_limit_bits: u32,
}

impl Params {
    /// Ideal wall-clock duration of one retarget window: `interval × spacing`.
    pub fn target_window_seconds(&self) -> u64 {
        self.retarget_interval.saturating_mul(self.target_spacing_seconds)
    }

    /// The easiest target the network allows, as a full 256-bit value.
    pub fn pow_limit(&self) -> Uint256 {
        Uint256::from_compact(self.pow_limit_bits)
    }
}

/// ZeroCoin's mainnet parameters: 60-second blocks, 1,440-block (24h) retarget,
/// 4× clamp, and a difficulty floor of `0x1e00ffff`.
pub const DIFFICULTY_PARAMS: Params = Params {
    target_spacing_seconds: 60,
    retarget_interval: 1_440,
    max_adjustment_factor: 4,
    pow_limit_bits: 0x1e00_ffff,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DifficultyError {
    #[error("block target {found:#x} is above the proof-of-work limit {limit:#x}")]
    TargetAbovePowLimit { found: u32, limit: u32 },
    #[error("block carries difficulty {found:#x} but the network requires {expected:#x}")]
    UnexpectedBits { expected: u32, found: u32 },
    #[error("compact difficulty encoding {0:#x} decodes to a zero target")]
    ZeroTarget(u32),
}

/// Expand a compact "nBits" difficulty into its full 256-bit target.
pub fn compact_to_target(bits: u32) -> Uint256 {
    Uint256::from_compact(bits)
}

/// Compress a 256-bit target into compact "nBits".
pub fn compact_from_target(target: &Uint256) -> u32 {
    target.to_compact()
}

/// The target a block advertising `bits` must meet.
pub fn block_target(bits: u32) -> Uint256 {
    compact_to_target(bits)
}

/// True when a proof-of-work hash is at or below the target, i.e. the block found
/// enough work. Comparison is on the big-endian byte value, like Bitcoin.
pub fn hash_meets_target(pow_hash: &Hash256, target: &Uint256) -> bool {
    Uint256::from_be_bytes(pow_hash.0) <= *target
}

/// The work a target represents: `(~target) / (target + 1) + 1`, Bitcoin's formula.
/// Summed along a branch this is the cumulative chain work used for fork choice.
pub fn required_work(target: &Uint256) -> Uint256 {
    if target.is_zero() {
        return Uint256::ZERO;
    }
    let denominator = target.wrapping_add(Uint256::ONE);
    let (quotient, _) = target.bitwise_not().divmod(denominator);
    quotient.wrapping_add(Uint256::ONE)
}

/// Compute the difficulty for the next retarget boundary.
///
/// `prev_bits` is the difficulty in force during the window that just finished and
/// `actual_window_seconds` is how long that window actually took (the timestamp
/// difference across the window's blocks). The result is the new compact target,
/// clamped to `[prev/4, prev×4]` by the timespan clamp and never above `pow_limit`.
pub fn next_difficulty(prev_bits: u32, actual_window_seconds: u64, params: &Params) -> u32 {
    let prev_target = compact_to_target(prev_bits);
    let expected = params.target_window_seconds().max(1);
    let factor = params.max_adjustment_factor.max(2);

    // Clamp the observed timespan so one anomalous window cannot move difficulty by
    // more than the adjustment factor in either direction.
    let min_timespan = expected / factor;
    let max_timespan = expected * factor;
    let actual = actual_window_seconds.clamp(min_timespan.max(1), max_timespan);

    // new_target = prev_target × actual / expected. When the target is very large
    // (near the easy floor) the multiply could overflow 256 bits, so divide first in
    // that regime; the tiny precision loss there is irrelevant next to the floor.
    let new_target = if prev_target.leading_zeros() >= 20 {
        prev_target.mul_u64(actual).div_u64(expected)
    } else {
        prev_target.div_u64(expected).mul_u64(actual)
    };

    // Difficulty may never fall below the network floor (target above pow_limit).
    let pow_limit = params.pow_limit();
    let capped = if new_target > pow_limit || new_target.is_zero() {
        pow_limit
    } else {
        new_target
    };
    compact_from_target(&capped)
}

/// Whether a block's advertised difficulty is legal on its own: a non-zero target
/// that does not exceed the proof-of-work limit.
pub fn validate_bits(bits: u32, params: &Params) -> Result<(), DifficultyError> {
    let target = compact_to_target(bits);
    if target.is_zero() {
        return Err(DifficultyError::ZeroTarget(bits));
    }
    if target > params.pow_limit() {
        return Err(DifficultyError::TargetAbovePowLimit {
            found: bits,
            limit: params.pow_limit_bits,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_24_hours() {
        // 1,440 blocks × 60 seconds = 86,400 seconds = one day.
        assert_eq!(DIFFICULTY_PARAMS.target_window_seconds(), 86_400);
    }

    #[test]
    fn on_schedule_difficulty_is_unchanged() {
        let bits = 0x1d00_ffff;
        let next = next_difficulty(bits, DIFFICULTY_PARAMS.target_window_seconds(), &DIFFICULTY_PARAMS);
        // A window that took exactly the ideal time keeps the same difficulty
        // (up to compact-encoding granularity).
        assert_eq!(next, bits);
    }

    #[test]
    fn fast_blocks_raise_difficulty() {
        let bits = 0x1c00_ffff;
        // Window finished in half the ideal time => target should shrink (harder).
        let half = DIFFICULTY_PARAMS.target_window_seconds() / 2;
        let next = next_difficulty(bits, half, &DIFFICULTY_PARAMS);
        assert!(compact_to_target(next) < compact_to_target(bits));
    }

    #[test]
    fn slow_blocks_lower_difficulty() {
        let bits = 0x1c00_ffff;
        // Window took twice as long => target should grow (easier).
        let double = DIFFICULTY_PARAMS.target_window_seconds() * 2;
        let next = next_difficulty(bits, double, &DIFFICULTY_PARAMS);
        assert!(compact_to_target(next) > compact_to_target(bits));
    }

    #[test]
    fn adjustment_is_clamped_to_four_x() {
        let bits = 0x1c00_ffff;
        // An absurdly short window must not shrink the target by more than 4×.
        let next = next_difficulty(bits, 1, &DIFFICULTY_PARAMS);
        let prev_target = compact_to_target(bits);
        let new_target = compact_to_target(next);
        // new_target >= prev_target / 4  =>  prev_target <= new_target * 4
        assert!(prev_target <= new_target.mul_u64(4));
    }

    #[test]
    fn target_never_exceeds_pow_limit() {
        let bits = DIFFICULTY_PARAMS.pow_limit_bits;
        // Even a catastrophically slow window cannot push past the easy floor.
        let next = next_difficulty(bits, u64::MAX, &DIFFICULTY_PARAMS);
        assert!(compact_to_target(next) <= DIFFICULTY_PARAMS.pow_limit());
    }

    #[test]
    fn validate_bits_rejects_zero_and_over_limit() {
        assert_eq!(
            validate_bits(0, &DIFFICULTY_PARAMS),
            Err(DifficultyError::ZeroTarget(0))
        );
        // 0x2100ffff is far easier than the 0x1e00ffff floor.
        assert!(matches!(
            validate_bits(0x2100_ffff, &DIFFICULTY_PARAMS),
            Err(DifficultyError::TargetAbovePowLimit { .. })
        ));
        assert!(validate_bits(0x1d00_ffff, &DIFFICULTY_PARAMS).is_ok());
    }

    #[test]
    fn work_is_larger_for_harder_targets() {
        let easy = compact_to_target(0x1e00_ffff);
        let hard = compact_to_target(0x1d00_ffff);
        assert!(required_work(&hard) > required_work(&easy));
    }

    #[test]
    fn hash_meets_target_boundary() {
        let target = compact_to_target(0x1d00_ffff);
        // A hash of all zeros is below any non-zero target.
        assert!(hash_meets_target(&Hash256::ZERO, &target));
        // A hash of all 0xff is above the difficulty-1 target.
        assert!(!hash_meets_target(&Hash256([0xff; 32]), &target));
    }
}
