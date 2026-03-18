//! Multiplexer / conditional-select gadget.
//!
//! mux(selector, a, b) = selector * a + (1 - selector) * b

use crate::field::FieldElement;

/// Select between two values based on a boolean selector.
/// selector=1 → a, selector=0 → b
pub fn mux(selector: u64, a: u64, b: u64) -> u64 {
    debug_assert!(selector == 0 || selector == 1);
    if selector == 1 {
        a
    } else {
        b
    }
}

/// Field-level mux.
pub fn field_mux(selector: &FieldElement, a: &FieldElement, b: &FieldElement) -> FieldElement {
    // sel * a + (1 - sel) * b = b + sel * (a - b)
    *b + *selector * (*a - *b)
}

/// Multi-way selector: given index i and values[], return values[i].
/// Enforced by: Σ(selector_j * values_j) where exactly one selector_j = 1.
pub fn multi_mux(selectors: &[u64], values: &[u64]) -> u64 {
    assert_eq!(selectors.len(), values.len());
    debug_assert_eq!(
        selectors.iter().sum::<u64>(),
        1,
        "exactly one selector must be 1"
    );
    selectors
        .iter()
        .zip(values.iter())
        .map(|(&s, &v)| s * v)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_basic() {
        assert_eq!(mux(1, 42, 99), 42);
        assert_eq!(mux(0, 42, 99), 99);
    }

    #[test]
    fn field_mux_basic() {
        let a = FieldElement::new(42);
        let b = FieldElement::new(99);
        assert_eq!(field_mux(&FieldElement::new(1), &a, &b), a);
        assert_eq!(field_mux(&FieldElement::new(0), &a, &b), b);
    }

    #[test]
    fn multi_mux_basic() {
        let sels = vec![0, 0, 1, 0];
        let vals = vec![10, 20, 30, 40];
        assert_eq!(multi_mux(&sels, &vals), 30);
    }
}
