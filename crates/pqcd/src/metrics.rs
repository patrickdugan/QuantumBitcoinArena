//! Size metrics measured on real Taproot script-path spends.

use crate::codeword::CodewordSpace;
use crate::scheme::{Opening, Scheme, SecretKey};
use crate::taproot::LeafSpend;

/// Which message the cost is measured on. Witness size depends on the coordinate
/// values (a zero is one byte, anything else two), so this matters at the percent level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg {
    /// The balanced middle codeword the reference crate uses (all bits false for Lamport).
    Canonical,
    /// Uniformly random message bits.
    Random(u64),
    /// Largest witness: every coordinate nonzero where possible.
    Worst,
}

/// The balanced codeword `(R/k +- 1, ...)` the reference crate benchmarks.
pub fn canonical_codeword(k: u32, l: u32) -> Vec<u32> {
    let r = crate::codeword::middle_rank(k, l);
    let (base, rem) = (r / k, r % k);
    (0..k).map(|i| if i < rem { base + 1 } else { base }).collect()
}

/// Opening of `n_digits` digits under `msg`.
pub fn opening_for(sk: &SecretKey, msg: Msg) -> Opening {
    use rand::{Rng, SeedableRng};
    let scheme = sk.scheme;
    let n = sk.n_digits;
    match (scheme, msg) {
        (Scheme::Acw { k, l, .. }, Msg::Canonical) => {
            let c = canonical_codeword(k, l);
            Opening { digits: (0..n).map(|d| sk.open_codeword(d, &c)).collect() }
        }
        (Scheme::Acw { k, l, .. }, Msg::Worst) => {
            // Posted coordinates cost 2 bytes when nonzero (1 byte when zero): pick a
            // codeword whose first k-1 coordinates are all nonzero.
            let sp = CodewordSpace::new(k, l);
            let c = (0..sp.count().min(200_000))
                .map(|r| sp.unrank(r).unwrap())
                .find(|c| c[..k as usize - 1].iter().all(|&a| a >= 1))
                .unwrap_or_else(|| canonical_codeword(k, l));
            Opening { digits: (0..n).map(|d| sk.open_codeword(d, &c)).collect() }
        }
        (_, Msg::Canonical) => sk.open_bits(&vec![false; n * scheme.bits_per_digit() as usize]),
        (_, Msg::Worst) => sk.open_bits(&vec![true; n * scheme.bits_per_digit() as usize]),
        (_, Msg::Random(seed)) => {
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
            let bits: Vec<bool> = (0..n * scheme.bits_per_digit() as usize).map(|_| rng.gen()).collect();
            sk.open_bits(&bits)
        }
    }
}

/// Leaf spend for `n_digits` digits under `msg` with a fixed test key.
pub fn spend_for(scheme: Scheme, n_digits: usize, msg: Msg) -> LeafSpend {
    let sk = SecretKey::new(scheme, [9u8; 32], n_digits);
    let com = sk.commit();
    let o = match (scheme, msg) {
        (Scheme::Acw { .. }, Msg::Random(seed)) => {
            use rand::{Rng, SeedableRng};
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
            let bits = scheme.bits_per_digit();
            Opening { digits: (0..n_digits).map(|d| sk.open_digit(d, rng.gen::<u64>() & ((1 << bits) - 1))).collect() }
        }
        _ => opening_for(&sk, msg),
    };
    LeafSpend { script: com.verify_script(), stack: o.witness_stack(&scheme) }
}

/// Marginal witness vbytes per message bit: the per-digit growth of leaf-script bytes plus
/// revealed-item bytes (with their length prefixes), divided by 4 and by bits per digit.
///
/// This equals the reference crate's "difference two transaction sizes" figure whenever
/// the two sizes do not straddle a compact-size boundary (253 items, 65536 script bytes);
/// computing it from components removes that dependence.
pub fn marginal_vb_per_bit(scheme: Scheme, msg: Msg) -> f64 {
    let (d1, d2) = (64usize, 128usize);
    let (a, b) = (spend_for(scheme, d1, msg), spend_for(scheme, d2, msg));
    let bytes = |s: &LeafSpend| (s.script_bytes() + s.stack_bytes()) as f64;
    let per_digit = (bytes(&b) - bytes(&a)) / (d2 - d1) as f64;
    per_digit / 4.0 / f64::from(scheme.bits_per_digit())
}
