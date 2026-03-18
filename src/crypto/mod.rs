//! Cryptographic primitives.

pub trait HashFunction: Send + Sync {
    fn hash(&self, data: &[u8]) -> [u8; 32];
    fn hash2(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32];
    fn name(&self) -> &'static str;
}

pub struct Blake3Hash;

impl HashFunction for Blake3Hash {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    fn hash2(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
        *blake3::hash(&buf).as_bytes()
    }

    fn name(&self) -> &'static str {
        "blake3"
    }
}
