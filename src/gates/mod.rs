//! Gate and gadget interfaces plus real reusable building blocks.
//!
//! The trait layer (`GateContext`, `Gate`) is backend-agnostic.
//! The concrete implementations in submodules provide real constraint logic
//! that can be used by operator circuits.

pub mod arithmetic;
pub mod boolean;
pub mod comparison;
pub mod decompose;
pub mod group;
pub mod join;
pub mod merkle;
pub mod mux;
pub mod permutation;
pub mod running_sum;
pub mod sort;

// ─────────────────────────────────────────────────────────────────────────────
// Core trait: GateContext — backend-independent constraint builder
// ─────────────────────────────────────────────────────────────────────────────

use crate::field::FieldElement;

/// An opaque wire reference — each backend maps this to its own wire type.
pub trait Wire: Clone + std::fmt::Debug + Send + Sync + 'static {}

/// Backend handle that gates add constraints to.
pub trait GateContext: Send + Sync {
    type W: Wire;

    fn zero(&self) -> Self::W;
    fn one(&self) -> Self::W;
    fn constant(&self, val: FieldElement) -> Self::W;
    fn public_input(&mut self) -> Self::W;

    fn add(&self, a: &Self::W, b: &Self::W) -> Self::W;
    fn sub(&self, a: &Self::W, b: &Self::W) -> Self::W;
    fn mul(&self, a: &Self::W, b: &Self::W) -> Self::W;

    fn assert_equal(&self, a: &Self::W, b: &Self::W);
    fn assert_bool(&self, a: &Self::W);
}

/// A gate that can be built inside a GateContext.
pub trait Gate<C: GateContext> {
    type Output;
    fn build(&self, ctx: &mut C) -> Self::Output;
}
