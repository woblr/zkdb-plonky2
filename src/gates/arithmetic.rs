//! Arithmetic gadgets: field addition, multiplication, conditional accumulation.

use crate::field::FieldElement;

/// Conditional addition: accumulate value only when selector == 1.
/// sum = Σ (selector[i] * value[i])
pub fn conditional_sum(values: &[u64], selectors: &[u64]) -> u64 {
    assert_eq!(values.len(), selectors.len());
    values
        .iter()
        .zip(selectors.iter())
        .map(|(&v, &s)| {
            debug_assert!(s == 0 || s == 1);
            v.wrapping_mul(s)
        })
        .fold(0u64, |acc, x| acc.wrapping_add(x))
}

/// Conditional count: count of rows where selector == 1.
pub fn conditional_count(selectors: &[u64]) -> u64 {
    selectors.iter().filter(|&&s| s == 1).count() as u64
}

/// Compute running sum of values with selectors.
/// Returns vector of partial sums (useful for aggregate witness).
pub fn running_sum(values: &[u64], selectors: &[u64]) -> Vec<u64> {
    assert_eq!(values.len(), selectors.len());
    let mut sums = Vec::with_capacity(values.len());
    let mut acc = 0u64;
    for (&v, &s) in values.iter().zip(selectors.iter()) {
        acc = acc.wrapping_add(v.wrapping_mul(s));
        sums.push(acc);
    }
    sums
}

/// Dot product of two u64 vectors (wrapping arithmetic).
pub fn dot_product(a: &[u64], b: &[u64]) -> u64 {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(0u64, |acc, (&x, &y)| acc.wrapping_add(x.wrapping_mul(y)))
}

/// Field-level conditional sum using FieldElement.
pub fn field_conditional_sum(values: &[FieldElement], selectors: &[FieldElement]) -> FieldElement {
    assert_eq!(values.len(), selectors.len());
    values
        .iter()
        .zip(selectors.iter())
        .fold(FieldElement::ZERO, |acc, (v, s)| acc + (*v * *s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_sum_basic() {
        let vals = vec![10, 20, 30, 40, 50];
        let sels = vec![1, 0, 1, 0, 1];
        assert_eq!(conditional_sum(&vals, &sels), 90); // 10+30+50
    }

    #[test]
    fn conditional_count_basic() {
        let sels = vec![1, 0, 1, 1, 0];
        assert_eq!(conditional_count(&sels), 3);
    }

    #[test]
    fn running_sum_basic() {
        let vals = vec![10, 20, 30];
        let sels = vec![1, 1, 1];
        let sums = running_sum(&vals, &sels);
        assert_eq!(sums, vec![10, 30, 60]);
    }

    #[test]
    fn dot_product_basic() {
        assert_eq!(dot_product(&[1, 2, 3], &[4, 5, 6]), 32);
    }
}
