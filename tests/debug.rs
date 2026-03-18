use std::sync::Arc;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
type D = <C as GenericConfig<2>>::Hasher;

fn main() {
    println!("Hello");
}
