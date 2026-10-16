//! A minimal, dependency-free 256-bit unsigned integer for difficulty targets.
//!
//! Bitcoin's proof-of-work target and its retarget arithmetic are 256-bit, so
//! ZeroCoin needs a real big integer rather than a lossy `u128`. Limbs are stored
//! little-endian (`limbs[0]` least significant). Only the operations consensus
//! actually uses are implemented — comparison, add/sub, multiply by a small scalar,
//! full division, bitwise NOT, and single-bit shifts — each covered by a test.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// 256-bit unsigned integer in four 64-bit little-endian limbs.
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Uint256(pub [u64; 4]);

impl Uint256 {
    pub const ZERO: Uint256 = Uint256([0, 0, 0, 0]);
    pub const ONE: Uint256 = Uint256([1, 0, 0, 0]);
    pub const MAX: Uint256 = Uint256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    pub fn from_u64(value: u64) -> Self {
        Uint256([value, 0, 0, 0])
    }

    /// Build from 32 big-endian bytes (the natural order of a proof-of-work hash).
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            // bytes[0..8] is the most significant limb => limbs[3].
            limbs[3 - i] = u64::from_be_bytes(chunk);
        }
        Uint256(limbs)
    }

    /// Serialize to 32 big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Decode Bitcoin's compact "nBits" difficulty encoding.
    ///
    /// The top byte is a base-256 exponent and the low three bytes are the
    /// mantissa: `value = mantissa * 256^(exponent - 3)`. The mantissa's sign bit
    /// (0x00800000) means the target is zero, since a negative target is nonsense.
    pub fn from_compact(bits: u32) -> Self {
        let exponent = (bits >> 24) as u32;
        let mantissa = bits & 0x007f_ffff;
        if bits & 0x0080_0000 != 0 {
            // Negative: treated as zero, matching Bitcoin's consensus handling.
            return Uint256::ZERO;
        }
        let mut result = Uint256::from_u64(mantissa as u64);
        if exponent <= 3 {
            // Shift the small mantissa down into place.
            result = result.shr_bits(8 * (3 - exponent));
        } else {
            // Multiply by 256^(exponent-3) == shift left by 8*(exponent-3) bits.
            result = result.shl_bits(8 * (exponent - 3));
        }
        result
    }

    /// Encode as Bitcoin's compact "nBits", rounding the mantissa down so the
    /// encoded target is never larger than the true target (which would let a miner
    /// claim more work than it did).
    pub fn to_compact(&self) -> u32 {
        if self.is_zero() {
            return 0;
        }
        let bit_length = 256 - self.leading_zeros();
        // Number of bytes needed to represent the value.
        let size = bit_length.div_ceil(8) as u32;
        let shifted = if size <= 3 {
            self.shl_bits(8 * (3 - size))
        } else {
            self.shr_bits(8 * (size - 3))
        };
        let mut mantissa = (shifted.0[0] & 0x00ff_ffff) as u32;
        let mut exponent = size;
        // Keep the value positive: if the sign bit would be set, drop a byte.
        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            exponent += 1;
        }
        (exponent << 24) | (mantissa & 0x007f_ffff)
    }

    /// Wrapping addition.
    pub fn wrapping_add(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            out[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        Uint256(out)
    }

    /// Wrapping subtraction.
    pub fn wrapping_sub(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        Uint256(out)
    }

    /// Multiply by a small scalar, modulo 2^256.
    pub fn mul_u64(self, rhs: u64) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let product = self.0[i] as u128 * rhs as u128 + carry;
            out[i] = product as u64;
            carry = product >> 64;
        }
        Uint256(out)
    }

    /// Divide by a small scalar, returning the quotient (remainder discarded).
    pub fn div_u64(self, rhs: u64) -> Self {
        assert!(rhs != 0, "division by zero");
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            out[i] = (cur / rhs as u128) as u64;
            rem = cur % rhs as u128;
        }
        Uint256(out)
    }

    /// Full 256-bit division, returning `(quotient, remainder)`. Bit-by-bit long
    /// division: simple, obviously correct, and only ever run at block connect time.
    pub fn divmod(self, divisor: Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "division by zero");
        let mut quotient = Uint256::ZERO;
        let mut remainder = Uint256::ZERO;
        for bit in (0..256).rev() {
            remainder = remainder.shl_one();
            if self.bit(bit) {
                remainder.0[0] |= 1;
            }
            if remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.set_bit(bit);
            }
        }
        (quotient, remainder)
    }

    pub fn bit(&self, index: u32) -> bool {
        if index >= 256 {
            return false;
        }
        let limb = (index / 64) as usize;
        let within = index % 64;
        (self.0[limb] >> within) & 1 == 1
    }

    fn set_bit(&mut self, index: u32) {
        let limb = (index / 64) as usize;
        let within = index % 64;
        self.0[limb] |= 1u64 << within;
    }

    /// Shift left by one bit (mod 2^256).
    pub fn shl_one(self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            out[i] = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 63;
        }
        Uint256(out)
    }

    /// Shift left by an arbitrary number of bits (mod 2^256).
    pub fn shl_bits(self, bits: u32) -> Self {
        if bits >= 256 {
            return Uint256::ZERO;
        }
        let mut result = self;
        for _ in 0..bits {
            result = result.shl_one();
        }
        result
    }

    /// Shift right by one bit.
    pub fn shr_one(self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in (0..4).rev() {
            out[i] = (self.0[i] >> 1) | (carry << 63);
            carry = self.0[i] & 1;
        }
        Uint256(out)
    }

    /// Shift right by an arbitrary number of bits.
    pub fn shr_bits(self, bits: u32) -> Self {
        if bits >= 256 {
            return Uint256::ZERO;
        }
        let mut result = self;
        for _ in 0..bits {
            result = result.shr_one();
        }
        result
    }

    /// Bitwise complement.
    pub fn bitwise_not(self) -> Self {
        Uint256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// How many leading zero bits the value has, useful for diagnostics.
    pub fn leading_zeros(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return (3 - i as u32) * 64 + self.0[i].leading_zeros();
            }
        }
        256
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Uint256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare from the most significant limb down.
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl std::fmt::Debug for Uint256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Uint256(0x{})", hex::encode(self.to_be_bytes()))
    }
}

impl std::fmt::Display for Uint256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_be_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_bytes_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xff;
        bytes[31] = 0x01;
        let value = Uint256::from_be_bytes(bytes);
        assert_eq!(value.to_be_bytes(), bytes);
    }

    #[test]
    fn ordering_is_by_magnitude() {
        let small = Uint256::from_u64(1);
        // A value whose most significant limb is set is larger than any low-limb one.
        let big = Uint256([0, 0, 0, 1]);
        assert!(big > small);
        assert!(Uint256::from_u64(2) > Uint256::from_u64(1));
    }

    #[test]
    fn bitcoin_genesis_compact_roundtrip() {
        // 0x1d00ffff is Bitcoin's difficulty-1 target.
        let target = Uint256::from_compact(0x1d00_ffff);
        assert_eq!(target.to_compact(), 0x1d00_ffff);
        // value = 0xffff * 2^208, so the two 0xff bytes land at big-endian
        // positions 4 and 5 (bit length 224 => 28 significant bytes).
        let be = target.to_be_bytes();
        assert_eq!(be[4], 0xff);
        assert_eq!(be[5], 0xff);
        assert_eq!(be[0], 0x00);
    }

    #[test]
    fn add_and_sub() {
        let a = Uint256::from_u64(u64::MAX);
        let b = Uint256::ONE;
        let sum = a.wrapping_add(b);
        // Carries into the second limb.
        assert_eq!(sum.0[0], 0);
        assert_eq!(sum.0[1], 1);
        assert_eq!(sum.wrapping_sub(b), a);
    }

    #[test]
    fn mul_and_div() {
        let a = Uint256::from_u64(1_000_000);
        assert_eq!(a.mul_u64(7).div_u64(7), a);
        let big = Uint256([u64::MAX, 0, 0, 0]);
        assert_eq!(big.div_u64(3).mul_u64(3) <= big, true);
    }

    #[test]
    fn divmod_full_division() {
        let a = Uint256::from_u64(100);
        let b = Uint256::from_u64(7);
        let (q, r) = a.divmod(b);
        assert_eq!(q, Uint256::from_u64(14));
        assert_eq!(r, Uint256::from_u64(2));
    }

    #[test]
    fn shl_and_not() {
        let one = Uint256::ONE;
        assert_eq!(one.shl_bits(64), Uint256([0, 1, 0, 0]));
        assert_eq!(Uint256::ZERO.bitwise_not(), Uint256::MAX);
    }

    #[test]
    fn negative_compact_is_zero() {
        // Sign bit set in the mantissa => target zero.
        assert!(Uint256::from_compact(0x1d80_0000).is_zero());
    }
}
