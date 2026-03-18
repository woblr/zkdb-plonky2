//! Boolean constraint gadgets.
//!
//! Enforce that wire values are 0 or 1, and implement AND, OR, NOT, XOR.

/// Verify a value is boolean (0 or 1).
pub fn is_boolean(v: u64) -> bool {
    v == 0 || v == 1
}

/// Boolean AND: a * b (both must be boolean).
pub fn boolean_and(a: u64, b: u64) -> u64 {
    debug_assert!(is_boolean(a) && is_boolean(b));
    a & b
}

/// Boolean OR: a + b - a*b.
pub fn boolean_or(a: u64, b: u64) -> u64 {
    debug_assert!(is_boolean(a) && is_boolean(b));
    a | b
}

/// Boolean NOT: 1 - a.
pub fn boolean_not(a: u64) -> u64 {
    debug_assert!(is_boolean(a));
    1 - a
}

/// Boolean XOR: a + b - 2*a*b.
pub fn boolean_xor(a: u64, b: u64) -> u64 {
    debug_assert!(is_boolean(a) && is_boolean(b));
    a ^ b
}

/// Evaluate a filter predicate over field values.
/// Returns a selector bitmap (0 or 1 per row).
pub fn evaluate_selector(values: &[u64], predicate: impl Fn(u64) -> bool) -> Vec<u64> {
    values
        .iter()
        .map(|&v| if predicate(v) { 1 } else { 0 })
        .collect()
}

/// Verify selector bitmap is all-boolean.
pub fn verify_selector(selector: &[u64]) -> bool {
    selector.iter().all(|&v| is_boolean(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_ops() {
        assert_eq!(boolean_and(1, 1), 1);
        assert_eq!(boolean_and(1, 0), 0);
        assert_eq!(boolean_or(0, 1), 1);
        assert_eq!(boolean_or(0, 0), 0);
        assert_eq!(boolean_not(0), 1);
        assert_eq!(boolean_not(1), 0);
        assert_eq!(boolean_xor(1, 0), 1);
        assert_eq!(boolean_xor(1, 1), 0);
    }

    #[test]
    fn selector_evaluation() {
        let vals = vec![10, 20, 30, 40, 50];
        let sel = evaluate_selector(&vals, |v| v > 25);
        assert_eq!(sel, vec![0, 0, 1, 1, 1]);
        assert!(verify_selector(&sel));
    }
}
