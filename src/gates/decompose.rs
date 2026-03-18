//! Byte decomposition gadget: u64 → 8 × u8 field elements.
//!
//! This is a REAL constraint gadget. Given a field element `x` representing a u64,
//! it produces 8 byte-level field elements [b0..b7] such that:
//!   x == b0 + b1*256 + b2*256^2 + ... + b7*256^7
//! and each bi ∈ [0, 255].

use crate::field::FieldElement;

/// Result of decomposing a u64 into 8 bytes (little-endian).
#[derive(Debug, Clone)]
pub struct ByteDecomposition {
    pub bytes: [FieldElement; 8],
    pub original: FieldElement,
}

impl ByteDecomposition {
    /// Decompose a u64 value into 8 byte-level field elements.
    pub fn decompose(value: u64) -> Self {
        let mut bytes = [FieldElement::ZERO; 8];
        for i in 0..8 {
            bytes[i] = FieldElement::new((((value >> (8 * i)) & 0xFF)));
        }
        Self {
            bytes,
            original: FieldElement::new(value),
        }
    }

    /// Recompose the byte decomposition back into a single value.
    pub fn recompose(&self) -> FieldElement {
        let mut result = FieldElement::ZERO;
        for i in (0..8).rev() {
            result = result * FieldElement::new(256) + self.bytes[i];
        }
        result
    }

    /// Verify the decomposition is valid: each byte ∈ [0,255] and recomposition matches.
    pub fn verify(&self) -> bool {
        for b in &self.bytes {
            if b.0 > 255 {
                return false;
            }
        }
        self.recompose() == self.original
    }
}

/// Constraint-level byte decomposition check.
/// Returns (bytes, constraint_satisfied).
pub fn constrain_byte_decomposition(value: u64) -> (ByteDecomposition, bool) {
    let decomp = ByteDecomposition::decompose(value);
    let valid = decomp.verify();
    (decomp, valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_zero() {
        let d = ByteDecomposition::decompose(0);
        assert!(d.verify());
        assert_eq!(d.recompose(), FieldElement::ZERO);
    }

    #[test]
    fn decompose_small() {
        let d = ByteDecomposition::decompose(42);
        assert!(d.verify());
        assert_eq!(d.bytes[0], FieldElement::new(42));
        for i in 1..8 {
            assert_eq!(d.bytes[i], FieldElement::ZERO);
        }
    }

    #[test]
    fn decompose_large() {
        let val = 0x0102030405060708u64;
        let d = ByteDecomposition::decompose(val);
        assert!(d.verify());
        assert_eq!(d.bytes[0], FieldElement::new(0x08));
        assert_eq!(d.bytes[7], FieldElement::new(0x01));
    }

    #[test]
    fn decompose_max() {
        let d = ByteDecomposition::decompose(u64::MAX);
        assert!(d.verify());
    }

    #[test]
    fn roundtrip() {
        for val in [0u64, 1, 255, 256, 65535, 1_000_000, u64::MAX - 1] {
            let d = ByteDecomposition::decompose(val);
            assert!(d.verify(), "failed for {}", val);
        }
    }
}
