//! Hash selection, hash chains, and domain-separated derivation helpers.
//!
//! Only hashes with a native Script opcode are usable on chain: `OP_RIPEMD160`
//! (20 bytes), `OP_HASH160` (20 bytes) and `OP_SHA256` (32 bytes). There is no
//! truncation opcode, so the digest width is fixed by the opcode.

use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use bitcoin::opcodes::all as op;
use bitcoin::opcodes::Opcode;

/// A digest. Its length is `HashKind::len()`.
pub type Digest = Vec<u8>;

/// Hash function backing a chain or a Lamport commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HashKind {
    /// `RIPEMD160(x)`, `OP_RIPEMD160`, 20 bytes.
    Ripemd160,
    /// `RIPEMD160(SHA256(x))`, `OP_HASH160`, 20 bytes.
    Hash160,
    /// `SHA256(x)`, `OP_SHA256`, 32 bytes.
    Sha256,
}

impl HashKind {
    /// Digest length in bytes (also the length of every secret and opener).
    pub const fn len(self) -> usize {
        match self {
            HashKind::Ripemd160 | HashKind::Hash160 => 20,
            HashKind::Sha256 => 32,
        }
    }

    /// Digest length in bits, `n`.
    pub const fn bits(self) -> u32 {
        (self.len() * 8) as u32
    }

    /// Short name used in file names and JSON.
    pub const fn name(self) -> &'static str {
        match self {
            HashKind::Ripemd160 => "ripemd160",
            HashKind::Hash160 => "hash160",
            HashKind::Sha256 => "sha256",
        }
    }

    /// One application of the hash.
    pub fn digest(self, x: &[u8]) -> Digest {
        match self {
            HashKind::Ripemd160 => ripemd160::Hash::hash(x).to_byte_array().to_vec(),
            HashKind::Hash160 => hash160::Hash::hash(x).to_byte_array().to_vec(),
            HashKind::Sha256 => sha256::Hash::hash(x).to_byte_array().to_vec(),
        }
    }

    /// The single opcode that applies this hash on chain.
    pub const fn opcode(self) -> Opcode {
        match self {
            HashKind::Ripemd160 => op::OP_RIPEMD160,
            HashKind::Hash160 => op::OP_HASH160,
            HashKind::Sha256 => op::OP_SHA256,
        }
    }

    /// Apply the hash `n` times. `iterate(x, 0) == x`.
    pub fn iterate(self, x: &[u8], n: u32) -> Digest {
        let mut v = x.to_vec();
        for _ in 0..n {
            v = self.digest(&v);
        }
        v
    }
}

/// Tagged SHA-256, `SHA256(SHA256(tag) || SHA256(tag) || parts...)` (BIP-340 style).
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes()).to_byte_array();
    let mut buf = Vec::with_capacity(64 + parts.iter().map(|p| p.len()).sum::<usize>());
    buf.extend_from_slice(&t);
    buf.extend_from_slice(&t);
    for p in parts {
        buf.extend_from_slice(p);
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Deterministic secret of `len <= 32` bytes derived from a master seed.
///
/// Used so a million-chain commitment needs only a 32-byte master secret and so
/// every benchmark and fixture is reproducible.
pub fn derive_secret(master: &[u8; 32], scheme: &str, digit: u32, chain: u32, len: usize) -> Vec<u8> {
    assert!(len <= 32);
    tagged(
        "pqcd/secret",
        &[master, scheme.as_bytes(), &digit.to_le_bytes(), &chain.to_le_bytes()],
    )[..len]
        .to_vec()
}

/// Counter-mode pseudorandom pad, domain separated from the chain hash by a tag.
///
/// Instantiates the random oracle used to bind a table row to the openers of one
/// codeword.
pub fn pad(seed: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + 32);
    let mut ctr: u32 = 0;
    while out.len() < out_len {
        out.extend_from_slice(&tagged("pqcd/pad", &[context, &ctr.to_le_bytes(), seed]));
        ctr += 1;
    }
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_lengths() {
        for hk in [HashKind::Ripemd160, HashKind::Hash160, HashKind::Sha256] {
            assert_eq!(hk.digest(b"x").len(), hk.len());
        }
        assert_ne!(HashKind::Hash160.digest(b"x"), HashKind::Ripemd160.digest(b"x"));
    }

    #[test]
    fn iterate_composes() {
        let hk = HashKind::Hash160;
        let a = hk.iterate(b"seed", 3);
        let b = hk.iterate(&hk.iterate(b"seed", 1), 2);
        assert_eq!(a, b);
    }

    #[test]
    fn pad_prefix_property() {
        assert_eq!(&pad(b"s", b"c", 64)[..32], &pad(b"s", b"c", 32)[..]);
        assert_ne!(pad(b"s", b"c1", 32), pad(b"s", b"c2", 32));
        assert_ne!(pad(b"s1", b"c", 32), pad(b"s2", b"c", 32));
    }
}
