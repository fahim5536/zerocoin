//! Block subsidy, the 21,000,000 ZRO supply cap, and coinbase validation.
//!
//! Value enters ZeroCoin exactly as it enters Bitcoin: the first transaction of
//! every block is a coinbase that pays the miner `subsidy + fees`. The subsidy
//! starts at 50 ZRO and halves every 210,000 blocks, so the subsidy stream
//! converges on — and can never exceed — 21,000,000 ZRO. Coinbase outputs are
//! subject to a 100-block maturity delay before they may be spent, which stops a
//! deep reorganization from spending rewards that may disappear.
//!
//! There is no premine and no owner: the genesis coinbase creates nothing
//! (see [`crate::genesis`]), so the *only* way value has ever entered this chain is
//! the subsidy earned by proof of work.
//!
//! ## Immutability
//!
//! These economics are frozen by [`crate::consensus::immutability`]: compile-time
//! `const` assertions pin the 21,000,000 ZRO cap, the halving schedule and the
//! 100-block maturity delay, and the node refuses to boot if any of them (or the
//! genesis and state-root layouts they rest on) ever drifts. At height 0 the
//! subsidy is exactly zero, and [`validate_coinbase`] rejects any genesis coinbase
//! that claims otherwise as a premine ([`RewardError::GenesisPremine`]).

use crate::crypto::hash::Hash160;
use crate::crypto::secp256k1::PublicKey;
use crate::ledger::script::{p2pkh_script_pubkey, push_data};
use crate::ledger::transaction::{Outpoint, Transaction, TxIn, TxOut};

/// Fah per ZRO: the fixed 8-decimal precision, like satoshis per bitcoin.
pub const FAH_PER_ZRO: u64 = 100_000_000;
/// 50 ZRO expressed in Fah.
pub const INITIAL_SUBSIDY: u64 = 50 * FAH_PER_ZRO;
/// Blocks per halving epoch.
pub const HALVING_INTERVAL: u64 = 210_000;
/// After this many halvings the shift reaches zero; 64 is a safe upper bound.
pub const MAX_HALVINGS: u64 = 64;
/// The hard cap: 21,000,000 ZRO in Fah.
pub const MAX_SUPPLY: u64 = 21_000_000 * FAH_PER_ZRO;
/// A mined coinbase cannot be spent until it has this many confirmations.
pub const COINBASE_MATURITY: u64 = 100;

/// The subsidy minted at a given height, halving as the epoch counter advances.
///
/// Frozen economics. Height 0 is the zero-premine genesis: the subsidy there is
/// exactly zero (asserted at compile time in [`crate::consensus::immutability`]),
/// and [`validate_coinbase`] refuses any genesis coinbase that claims more. A
/// `const fn` so the schedule itself is locked compile-time, not just at run time.
pub const fn block_subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let halvings = height / HALVING_INTERVAL;
    if halvings >= MAX_HALVINGS {
        return 0;
    }
    INITIAL_SUBSIDY >> halvings
}

/// The total a coinbase at `height` may claim: new issuance plus the block's fees.
/// Returns `None` on overflow, which consensus treats as an invalid block.
pub const fn block_reward(height: u64, fees: u64) -> Option<u64> {
    block_subsidy(height).checked_add(fees)
}

/// The height at which a coinbase mined at `height` becomes spendable. Frozen: a
/// `const fn` so [`crate::consensus::immutability`] pins the 100-block delay with
/// compile-time assertions.
pub const fn maturity_height(height: u64) -> u64 {
    height.saturating_add(COINBASE_MATURITY)
}

/// Sum of every subsidy that will ever be issued. The truncating halving schedule
/// lands just under the cap; this is used by the cap test and by `validate_coinbase`.
pub const fn total_supply_ceiling() -> u64 {
    let mut total: u64 = 0;
    let mut halvings = 0u64;
    while halvings < MAX_HALVINGS {
        let per_block = INITIAL_SUBSIDY >> halvings;
        if per_block == 0 {
            break;
        }
        total = total.saturating_add(per_block.saturating_mul(HALVING_INTERVAL));
        halvings += 1;
    }
    total
}

/// Encode a non-negative integer as a minimal Bitcoin script number.
fn script_num(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    // If the high bit of the top byte is set, append a zero byte so the number is
    // not read as negative.
    if bytes.last().copied().unwrap_or(0) & 0x80 != 0 {
        bytes.push(0x00);
    }
    bytes
}

/// Decode a minimal script number back to a height, or `None` if it is not one.
fn parse_script_num(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return Some(0);
    }
    if bytes.len() > 8 {
        return None;
    }
    // Reject non-minimal / negative encodings for a height commitment.
    if bytes.last().copied().unwrap_or(0) & 0x80 != 0 {
        return None;
    }
    let mut value = 0u64;
    for &byte in bytes.iter().rev() {
        value = (value << 8) | byte as u64;
    }
    Some(value)
}

/// Build a block's coinbase paying `reward` to `payout`. The block height is
/// committed into the coinbase's `scriptSig` (BIP-34's role), which guarantees two
/// blocks can never produce the same coinbase txid and stops a stolen block
/// template from being replayed at another height.
pub fn coinbase_transaction(height: u64, payout: &PublicKey, reward: u64) -> Transaction {
    let mut script_sig = Vec::new();
    let height_bytes = script_num(height);
    push_data(&height_bytes, &mut script_sig);
    // A short free-text tag, the way Bitcoin's coinbase carries a miner signature.
    push_data(b"ZeroCoin", &mut script_sig);

    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint::null(),
            script_sig,
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: reward,
            script_pubkey: p2pkh_script_pubkey(&payout.key_hash()),
        }],
        lock_time: 0,
    }
}

/// One pool contributor's destination (a P2PKH public-key hash) paired with the
/// share weight that earned it. Weights are *relative*: the reward is divided in
/// proportion to them, so their absolute scale does not matter, only their ratio.
pub type PoolPayout = (Hash160, u64);

/// Split a block reward across pool contributors in proportion to their weights.
///
/// This is the arithmetic behind the in-built pool's micro-rewards, and it is
/// deliberately **exact and cap-safe**:
/// - each contributor is paid `reward * weight / total_weight` rounded *down*,
///   computed in `u128` so the intermediate product can never overflow;
/// - the round-down remainder is credited to the first contributor, so the
///   returned payouts sum to *exactly* `reward` — never one Fah more;
/// - zero-weight contributors and zero-value shares are dropped, so the coinbase
///   carries no empty outputs.
///
/// Because the split only ever redistributes value that already exists, a
/// multi-output pool coinbase built from it claims the same total as a solo
/// coinbase, and [`validate_coinbase`] enforces the 21,000,000 ZRO cap identically.
/// Returns an empty vector when there is nothing to split (`reward == 0`) or no one
/// to split it among (all weights zero).
pub fn split_reward(reward: u64, weights: &[PoolPayout]) -> Vec<PoolPayout> {
    let total_weight: u128 = weights.iter().map(|(_, w)| *w as u128).sum();
    if reward == 0 || total_weight == 0 {
        return Vec::new();
    }
    let reward128 = reward as u128;
    let mut out: Vec<PoolPayout> = Vec::with_capacity(weights.len());
    let mut allocated: u128 = 0;
    for (hash, weight) in weights {
        if *weight == 0 {
            continue;
        }
        // reward <= MAX_SUPPLY (~2^51) and weight <= u64::MAX (~2^64), so the
        // product is < 2^115 and cannot overflow a u128.
        let share = (reward128 * (*weight as u128) / total_weight) as u64;
        allocated += share as u128;
        out.push((*hash, share));
    }
    // total_weight > 0 guarantees at least one contributor was pushed, so `out` is
    // non-empty. Crediting the remainder here makes the split sum to exactly
    // `reward`; `allocated` is always <= reward because every share rounded down.
    if let Some(first) = out.first_mut() {
        first.1 += (reward128 - allocated) as u64;
    }
    out.retain(|(_, value)| *value > 0);
    out
}

/// Build a pool coinbase that redistributes one block's reward across many
/// contributors in a single transaction — one P2PKH output per payout, plus the
/// BIP-34 height commitment. This is how the in-built pool pays mobile and low-spec
/// share-miners alongside the block finder.
///
/// The reward is *split, never enlarged*: `payouts` must already sum to at most
/// `reward` (as [`split_reward`] guarantees). The resulting coinbase therefore
/// claims exactly what a solo coinbase would, so it passes [`validate_coinbase`]
/// and respects the supply cap by construction. Any value in `reward` not covered
/// by `payouts` is simply never minted, which is also safe (it leaves circulation,
/// as an under-claiming Bitcoin coinbase does).
pub fn pool_coinbase_transaction(height: u64, reward: u64, payouts: &[PoolPayout]) -> Transaction {
    debug_assert!(
        payouts.iter().map(|(_, v)| *v as u128).sum::<u128>() <= reward as u128,
        "pool payouts must never exceed the block reward"
    );

    let mut script_sig = Vec::new();
    let height_bytes = script_num(height);
    push_data(&height_bytes, &mut script_sig);
    // A distinct tag so a pool coinbase is recognizable on-chain and can never
    // collide in txid with a solo coinbase at the same height.
    push_data(b"ZeroCoin/pool", &mut script_sig);

    let outputs = payouts
        .iter()
        .map(|(pubkey_hash, value)| TxOut {
            value: *value,
            script_pubkey: p2pkh_script_pubkey(pubkey_hash),
        })
        .collect();

    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: Outpoint::null(),
            script_sig,
            sequence: u32::MAX,
        }],
        outputs,
        lock_time: 0,
    }
}

/// The height a coinbase commits to, if `tx` is a coinbase at all.
pub fn coinbase_height(tx: &Transaction) -> Option<u64> {
    if !tx.is_coinbase() {
        return None;
    }
    let script = &tx.inputs[0].script_sig;
    if script.is_empty() {
        return None;
    }
    let len = script[0] as usize;
    // A height commitment is a single small push (0..=8 bytes). len == 0 is the
    // minimal encoding of height 0 (an empty script number), which is valid.
    if len > 8 || script.len() < 1 + len {
        return None;
    }
    parse_script_num(&script[1..1 + len])
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewardError {
    #[error("the first transaction of a block must be a coinbase")]
    NotCoinbase,
    #[error("coinbase commits to height {found} but the block is height {expected}")]
    BadCoinbaseHeight { expected: u64, found: u64 },
    #[error("coinbase could not be parsed for its committed height")]
    MissingHeightCommitment,
    #[error("height 0 is the zero-premine genesis: a coinbase there may not claim {claimed} Fah")]
    GenesisPremine { claimed: u64 },
    #[error(
        "coinbase claims {claimed} Fah but height {height} allows at most subsidy {subsidy} plus fees {fees}"
    )]
    TooMuchReward {
        height: u64,
        claimed: u64,
        subsidy: u64,
        fees: u64,
    },
    #[error("coinbase claims {claimed} Fah but must collect at least the {fees} Fah of fees in the block")]
    BelowFees { claimed: u64, fees: u64 },
    #[error("subsidy issued so far ({issued}) plus this block ({new}) exceeds the 21000000 ZRO cap")]
    SupplyCapExceeded { issued: u64, new: u64 },
    #[error("coinbase reward overflows the value range")]
    RewardOverflow,
}

/// Validate a block's coinbase against the exact reward the protocol allows.
///
/// Claiming less than `subsidy + fees` is accepted — unclaimed value leaves
/// circulation forever, as in Bitcoin. Claiming more is inflation and is rejected.
/// At height 0 the only valid claim is zero: the genesis coinbase creates nothing.
/// Returns the value the coinbase actually claims so the caller can update the
/// running supply counters.
pub fn validate_coinbase(
    tx: &Transaction,
    height: u64,
    fees: u64,
    subsidy_issued: u64,
) -> Result<u64, RewardError> {
    if !tx.is_coinbase() {
        return Err(RewardError::NotCoinbase);
    }
    // BIP-34: the coinbase must name the height it mints at.
    let committed = coinbase_height(tx).ok_or(RewardError::MissingHeightCommitment)?;
    if committed != height {
        return Err(RewardError::BadCoinbaseHeight {
            expected: height,
            found: committed,
        });
    }

    let claimed: u64 = tx
        .outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or(RewardError::RewardOverflow)?;
    // Frozen rule (see `crate::consensus::immutability`): height 0 mints nothing.
    // Any non-zero claim — even one dressed up as fee collection, which the
    // arithmetic below would otherwise allow — is a premine and invalid.
    if height == 0 && claimed != 0 {
        return Err(RewardError::GenesisPremine { claimed });
    }
    let subsidy = block_subsidy(height);
    let allowed = block_reward(height, fees).ok_or(RewardError::RewardOverflow)?;
    if claimed > allowed {
        return Err(RewardError::TooMuchReward {
            height,
            claimed,
            subsidy,
            fees,
        });
    }
    if claimed < fees {
        // The coinbase must at least carry the fees it collects; claiming less
        // would destroy other users' value.
        return Err(RewardError::BelowFees { claimed, fees });
    }
    // The running supply must never pass the hard cap.
    let issued = subsidy_issued
        .checked_add(subsidy)
        .ok_or(RewardError::RewardOverflow)?;
    if issued > MAX_SUPPLY {
        return Err(RewardError::SupplyCapExceeded {
            issued: subsidy_issued,
            new: subsidy,
        });
    }
    Ok(claimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp256k1::PrivateKey;

    fn pubkey() -> PublicKey {
        PrivateKey::from_bytes([9u8; 32]).unwrap().public_key()
    }

    #[test]
    fn subsidy_is_zero_at_the_genesis_and_fifty_zro_from_height_one() {
        // The zero-premine genesis mints nothing; issuance starts at block 1.
        assert_eq!(block_subsidy(0), 0);
        assert_eq!(block_subsidy(1), 50 * FAH_PER_ZRO);
        assert_eq!(INITIAL_SUBSIDY, 5_000_000_000);
    }

    #[test]
    fn subsidy_halves_every_210k_blocks() {
        assert_eq!(block_subsidy(HALVING_INTERVAL - 1), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL), INITIAL_SUBSIDY / 2);
        assert_eq!(block_subsidy(HALVING_INTERVAL * 2), INITIAL_SUBSIDY / 4);
        assert_eq!(block_subsidy(HALVING_INTERVAL * 3), INITIAL_SUBSIDY / 8);
    }

    #[test]
    fn subsidy_eventually_reaches_zero() {
        assert_eq!(block_subsidy(MAX_HALVINGS * HALVING_INTERVAL), 0);
    }

    #[test]
    fn total_supply_never_exceeds_cap() {
        let ceiling = total_supply_ceiling();
        assert!(ceiling <= MAX_SUPPLY, "ceiling {ceiling} over cap {MAX_SUPPLY}");
        // Bitcoin's truncating schedule lands just shy of 21 million coins: the
        // unissued remainder is bounded by a single initial subsidy.
        assert!(MAX_SUPPLY - ceiling < INITIAL_SUBSIDY);
    }

    #[test]
    fn maturity_is_one_hundred_blocks() {
        assert_eq!(COINBASE_MATURITY, 100);
        assert_eq!(maturity_height(1), 101);
    }

    #[test]
    fn coinbase_commits_to_its_height() {
        let cb = coinbase_transaction(147, &pubkey(), block_subsidy(147));
        assert!(cb.is_coinbase());
        assert_eq!(coinbase_height(&cb), Some(147));
    }

    #[test]
    fn each_height_mints_a_distinct_coinbase() {
        let a = coinbase_transaction(1, &pubkey(), block_subsidy(1));
        let b = coinbase_transaction(2, &pubkey(), block_subsidy(2));
        assert_ne!(a.txid(), b.txid());
    }

    #[test]
    fn valid_coinbase_accepted() {
        let cb = coinbase_transaction(10, &pubkey(), block_subsidy(10));
        assert_eq!(validate_coinbase(&cb, 10, 0, 0), Ok(block_subsidy(10)));
    }

    #[test]
    fn genesis_coinbase_may_not_claim_value() {
        // A non-zero output at height 0 is a premine, however small it is.
        let premine = coinbase_transaction(0, &pubkey(), 1);
        assert_eq!(
            validate_coinbase(&premine, 0, 0, 0),
            Err(RewardError::GenesisPremine { claimed: 1 })
        );
        // The honest genesis coinbase — claiming nothing — is valid.
        let zero = coinbase_transaction(0, &pubkey(), 0);
        assert_eq!(validate_coinbase(&zero, 0, 0, 0), Ok(0));
    }

    #[test]
    fn genesis_premine_is_rejected_even_when_disguised_as_fees() {
        // Without the height-0 guard, claimed == fees would pass every other check
        // (subsidy 0 + fees 5 allows a claim of 5, and 5 >= fees). The freeze
        // closes that gap: at height 0 the only valid claim is zero.
        let cb = coinbase_transaction(0, &pubkey(), 5);
        assert_eq!(
            validate_coinbase(&cb, 0, 5, 0),
            Err(RewardError::GenesisPremine { claimed: 5 })
        );
    }

    #[test]
    fn wrong_height_commitment_rejected() {
        let cb = coinbase_transaction(5, &pubkey(), block_subsidy(5));
        assert_eq!(
            validate_coinbase(&cb, 6, 0, 0),
            Err(RewardError::BadCoinbaseHeight {
                expected: 6,
                found: 5
            })
        );
    }

    #[test]
    fn over_claiming_reward_rejected() {
        let mut cb = coinbase_transaction(10, &pubkey(), block_subsidy(10));
        cb.outputs[0].value += 1; // one Fah of inflation
        assert!(matches!(
            validate_coinbase(&cb, 10, 0, 0),
            Err(RewardError::TooMuchReward { .. })
        ));
    }

    #[test]
    fn under_claiming_fees_rejected() {
        // Coinbase claims less than the fees in the block: destroys user value.
        let cb = coinbase_transaction(10, &pubkey(), 0);
        assert!(matches!(
            validate_coinbase(&cb, 10, 500, 0),
            Err(RewardError::BelowFees { .. })
        ));
    }

    #[test]
    fn supply_cap_enforced() {
        let cb = coinbase_transaction(1, &pubkey(), block_subsidy(1));
        // Already at the cap: minting one more subsidy must be refused.
        assert!(matches!(
            validate_coinbase(&cb, 1, 0, MAX_SUPPLY),
            Err(RewardError::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn script_num_roundtrips_heights() {
        for height in [0u64, 1, 16, 127, 128, 255, 256, 65535, 1_000_000, u32::MAX as u64] {
            let encoded = script_num(height);
            assert_eq!(parse_script_num(&encoded), Some(height), "height {height}");
        }
    }

    #[test]
    fn split_reward_sums_exactly_to_the_block_reward() {
        let a = Hash160([1u8; 20]);
        let b = Hash160([2u8; 20]);
        let c = Hash160([3u8; 20]);
        let reward = block_subsidy(1); // 50 ZRO
        // Weights that do not divide the reward evenly, forcing rounding.
        let payouts = split_reward(reward, &[(a, 1u64), (b, 2), (c, 4)]);
        let total: u64 = payouts.iter().map(|(_, v)| *v).sum();
        assert_eq!(total, reward, "the split never creates or destroys value");
        // Proportional: the weight-4 contributor earns the most, weight-1 the least.
        let va = payouts.iter().find(|(h, _)| *h == a).unwrap().1;
        let vc = payouts.iter().find(|(h, _)| *h == c).unwrap().1;
        assert!(vc > va);
    }

    #[test]
    fn split_reward_credits_the_rounding_remainder_to_the_first() {
        let a = Hash160([1u8; 20]);
        let b = Hash160([2u8; 20]);
        // 11 Fah split evenly in two: 5 each, remainder 1 onto the first.
        let payouts = split_reward(11, &[(a, 1u64), (b, 1)]);
        assert_eq!(payouts, vec![(a, 6), (b, 5)]);
        assert_eq!(payouts.iter().map(|(_, v)| *v).sum::<u64>(), 11);
    }

    #[test]
    fn split_reward_drops_zero_weight_contributors() {
        let a = Hash160([1u8; 20]);
        let b = Hash160([2u8; 20]);
        let payouts = split_reward(1000, &[(a, 0u64), (b, 5)]);
        assert_eq!(payouts, vec![(b, 1000)]);
    }

    #[test]
    fn split_reward_with_nothing_to_split_is_empty() {
        assert!(split_reward(block_subsidy(1), &[]).is_empty());
        let a = Hash160([1u8; 20]);
        assert!(split_reward(0, &[(a, 5u64)]).is_empty());
        assert!(split_reward(100, &[(a, 0u64)]).is_empty());
    }

    #[test]
    fn a_small_share_weight_earns_a_micro_reward() {
        let finder = Hash160([9u8; 20]);
        let mobile = Hash160([8u8; 20]);
        // The finder is credited one block's worth of share weight; a single mobile
        // share sits beside it. The mobile earns a small, non-zero slice of 50 ZRO.
        let finder_weight = crate::consensus::pow::DEFAULT_SHARE_EASINESS;
        let reward = block_subsidy(1);
        let payouts = split_reward(reward, &[(finder, finder_weight), (mobile, 1)]);
        let mobile_value = payouts.iter().find(|(h, _)| *h == mobile).unwrap().1;
        assert!(mobile_value > 0, "a mobile share earns a micro-reward");
        assert!(
            mobile_value < reward / 1000,
            "but only a micro-reward relative to the finder"
        );
        assert_eq!(payouts.iter().map(|(_, v)| *v).sum::<u64>(), reward);
    }

    #[test]
    fn pool_coinbase_splits_the_subsidy_and_validates() {
        let a = Hash160([1u8; 20]);
        let b = Hash160([2u8; 20]);
        let reward = block_subsidy(7);
        let payouts = split_reward(reward, &[(a, 3u64), (b, 1)]);
        let cb = pool_coinbase_transaction(7, reward, &payouts);
        assert!(cb.is_coinbase());
        assert_eq!(coinbase_height(&cb), Some(7));
        assert_eq!(cb.outputs.len(), 2);
        // It claims exactly the subsidy, so the running supply advances by exactly
        // one subsidy and the 21,000,000 ZRO cap is untouched.
        assert_eq!(validate_coinbase(&cb, 7, 0, 0), Ok(reward));
    }

    #[test]
    fn pool_coinbase_cannot_inflate_the_reward() {
        let a = Hash160([1u8; 20]);
        let b = Hash160([2u8; 20]);
        let reward = block_subsidy(3);
        let payouts = split_reward(reward, &[(a, 1u64), (b, 1)]);
        let mut cb = pool_coinbase_transaction(3, reward, &payouts);
        // Smuggle one Fah of inflation into a pool output after construction.
        cb.outputs[0].value += 1;
        assert!(matches!(
            validate_coinbase(&cb, 3, 0, 0),
            Err(RewardError::TooMuchReward { .. })
        ));
    }
}
