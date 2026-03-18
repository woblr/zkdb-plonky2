//! Field element abstraction.
//!
//! Wraps the underlying field used by the proving backend.
//! Currently backed by u64 (Goldilocks-compatible).
//! Backend-specific conversions are feature-gated.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, Mul, Sub};

/// The Goldilocks prime: 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// A field element in the Goldilocks field (p = 2^64 - 2^32 + 1).
///
/// All arithmetic is modular. For circuit use, this is the canonical
/// representation. For commitment use, bytes are extracted via
/// `to_canonical_bytes()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct FieldElement(pub u64);

impl FieldElement {
    pub const ZERO: FieldElement = FieldElement(0);
    pub const ONE: FieldElement = FieldElement(1);

    pub fn new(val: u64) -> Self {
        // Reduce into [0, p)
        if val < GOLDILOCKS_PRIME {
            Self(val)
        } else {
            Self(val % GOLDILOCKS_PRIME)
        }
    }

    pub fn from_bool(b: bool) -> Self {
        Self(b as u64)
    }

    /// Canonical little-endian byte representation (8 bytes).
    pub fn to_canonical_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Reconstruct from canonical LE bytes.
    pub fn from_canonical_bytes(bytes: [u8; 8]) -> Self {
        Self::new(u64::from_le_bytes(bytes))
    }

    /// Split into 8 byte-sized field elements (for byte-decomposition gadgets).
    pub fn to_byte_fields(self) -> [FieldElement; 8] {
        let bytes = self.to_canonical_bytes();
        bytes.map(|b| FieldElement(b as u64))
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn double(self) -> Self {
        self + self
    }

    pub fn square(self) -> Self {
        self * self
    }

    /// Modular negation.
    pub fn neg(self) -> Self {
        if self.0 == 0 {
            Self::ZERO
        } else {
            Self(GOLDILOCKS_PRIME - self.0)
        }
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for FieldElement {
    fn from(v: u64) -> Self {
        Self::new(v)
    }
}

impl From<u32> for FieldElement {
    fn from(v: u32) -> Self {
        Self(v as u64)
    }
}

impl From<u8> for FieldElement {
    fn from(v: u8) -> Self {
        Self(v as u64)
    }
}

impl From<bool> for FieldElement {
    fn from(b: bool) -> Self {
        Self::from_bool(b)
    }
}

impl TryFrom<i64> for FieldElement {
    type Error = crate::types::ZkDbError;

    fn try_from(v: i64) -> Result<Self, Self::Error> {
        if v < 0 {
            // Represent negative as p - |v|
            let abs = v.unsigned_abs();
            if abs > GOLDILOCKS_PRIME {
                return Err(crate::types::ZkDbError::Encoding(format!(
                    "i64 value {} out of field range",
                    v
                )));
            }
            Ok(Self(GOLDILOCKS_PRIME - abs))
        } else {
            Ok(Self::new(v as u64))
        }
    }
}

impl Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        // Use wrapping add then reduce
        let (sum, overflow) = self.0.overflowing_add(rhs.0);
        if overflow || sum >= GOLDILOCKS_PRIME {
            Self(sum.wrapping_sub(GOLDILOCKS_PRIME))
        } else {
            Self(sum)
        }
    }
}

impl Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self(GOLDILOCKS_PRIME - rhs.0 + self.0)
        }
    }
}

impl Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        // u128 multiply then reduce
        let product = (self.0 as u128) * (rhs.0 as u128);
        let reduced = (product % GOLDILOCKS_PRIME as u128) as u64;
        Self(reduced)
    }
}

/// Convert a slice of bytes into field elements (one per byte).
pub fn bytes_to_fields(bytes: &[u8]) -> Vec<FieldElement> {
    bytes.iter().map(|&b| FieldElement(b as u64)).collect()
}

/// Pack up to 8 bytes into a single field element (LE).
pub fn pack_bytes_to_field(bytes: &[u8]) -> FieldElement {
    assert!(
        bytes.len() <= 8,
        "cannot pack more than 8 bytes into one field element"
    );
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    FieldElement::new(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_no_overflow() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(200);
        assert_eq!((a + b).0, 300);
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::new(3);
        let b = FieldElement::new(4);
        assert_eq!((a * b).0, 12);
    }

    #[test]
    fn test_byte_round_trip() {
        let fe = FieldElement::new(12345678);
        let bytes = fe.to_canonical_bytes();
        let fe2 = FieldElement::from_canonical_bytes(bytes);
        assert_eq!(fe, fe2);
    }

    #[test]
    fn test_byte_fields() {
        let fe = FieldElement::new(0x0102030405060708);
        let fields = fe.to_byte_fields();
        assert_eq!(fields[0].0, 0x08);
        assert_eq!(fields[1].0, 0x07);
    }
}
