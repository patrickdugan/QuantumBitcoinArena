//! Constant-sum codewords: the antichain that Antichain Winternitz commits per digit.
//!
//! A codeword is `(a_1..a_k)` with every `a_j in [0, L-1]` and `sum a_j = R`.
//! Codewords are ordered lexicographically (`a_1` most significant), which is the
//! same canonical order as the reference `antichain-winternitz` crate. Rank and
//! unrank use a counting table, so tables with millions of codewords never have
//! to be enumerated.

use std::fmt;

/// Counting table for one `(k, L)` pair: `ways[m][s]` is the number of
/// `m`-tuples in `[0, L-1]^m` that sum to `s`.
#[derive(Clone)]
pub struct CodewordSpace {
    k: u32,
    l: u32,
    r: u32,
    ways: Vec<Vec<u128>>,
}

impl fmt::Debug for CodewordSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CodewordSpace(k={}, L={}, R={}, N={})", self.k, self.l, self.r, self.count())
    }
}

/// The middle-rank sum `R = floor(k (L-1) / 2)`, which maximises the antichain
/// (de Bruijn, Tengbergen and Kruyswijk).
pub const fn middle_rank(k: u32, l: u32) -> u32 {
    (k * (l - 1)) / 2
}

impl CodewordSpace {
    /// Build the space for `k` chains of length `L` at the middle rank.
    pub fn new(k: u32, l: u32) -> Self {
        assert!(k >= 2 && l >= 2, "need k >= 2 and L >= 2");
        let r = middle_rank(k, l);
        let max = (k * (l - 1)) as usize;
        let mut ways = vec![vec![0u128; max + 1]; k as usize + 1];
        ways[0][0] = 1;
        for m in 1..=k as usize {
            for s in 0..=max {
                let mut acc = 0u128;
                for a in 0..l as usize {
                    if a > s {
                        break;
                    }
                    acc += ways[m - 1][s - a];
                }
                ways[m][s] = acc;
            }
        }
        Self { k, l, r, ways }
    }

    /// Number of chains per digit.
    pub fn k(&self) -> u32 {
        self.k
    }
    /// Chain length.
    pub fn l(&self) -> u32 {
        self.l
    }
    /// Codeword sum.
    pub fn r(&self) -> u32 {
        self.r
    }

    /// Number of codewords `N`.
    pub fn count(&self) -> u128 {
        self.ways[self.k as usize][self.r as usize]
    }

    /// Whole bits a digit can carry: `floor(log2 N)`.
    pub fn bits(&self) -> u32 {
        self.count().ilog2()
    }

    /// `log2 N` as a float (for reporting how much capacity the floor throws away).
    pub fn log2_count(&self) -> f64 {
        (self.count() as f64).log2()
    }

    /// Is `c` an admissible codeword (right arity, in range, sum `R`)?
    pub fn is_codeword(&self, c: &[u32]) -> bool {
        c.len() == self.k as usize
            && c.iter().all(|&a| a < self.l)
            && c.iter().map(|&a| u64::from(a)).sum::<u64>() == u64::from(self.r)
    }

    /// Lexicographic rank of a codeword, `0 <= rank < N`. `None` if `c` is not a codeword.
    pub fn rank(&self, c: &[u32]) -> Option<u128> {
        if !self.is_codeword(c) {
            return None;
        }
        let k = self.k as usize;
        let mut remaining = self.r as usize;
        let mut rank = 0u128;
        for (i, &a) in c.iter().enumerate() {
            let tail = k - i - 1;
            for x in 0..a as usize {
                if x <= remaining {
                    rank += self.ways[tail][remaining - x];
                }
            }
            remaining -= a as usize;
        }
        Some(rank)
    }

    /// Inverse of [`CodewordSpace::rank`]. `None` if `rank >= N`.
    pub fn unrank(&self, mut rank: u128) -> Option<Vec<u32>> {
        if rank >= self.count() {
            return None;
        }
        let k = self.k as usize;
        let mut remaining = self.r as usize;
        let mut out = Vec::with_capacity(k);
        for i in 0..k {
            let tail = k - i - 1;
            let mut chosen = None;
            for x in 0..self.l as usize {
                if x > remaining {
                    break;
                }
                let w = self.ways[tail][remaining - x];
                if rank < w {
                    chosen = Some(x);
                    break;
                }
                rank -= w;
            }
            let x = chosen.expect("rank within count always lands in a coordinate");
            out.push(x as u32);
            remaining -= x;
        }
        Some(out)
    }

    /// The codeword that carries digit value `v` (`v < 2^bits`): the one with rank `v`.
    pub fn encode_value(&self, v: u64) -> Vec<u32> {
        debug_assert!((u128::from(v)) < (1u128 << self.bits()));
        self.unrank(u128::from(v)).expect("value below N")
    }

    /// Digit value of any admissible codeword: `rank mod 2^bits`.
    ///
    /// The map is total on the antichain. Codewords with `rank >= 2^bits` (there are
    /// `N - 2^bits` of them) alias onto a smaller value, so a garbler can never open
    /// an admissible codeword that unlocks nothing.
    pub fn decode_value(&self, c: &[u32]) -> Option<u64> {
        let r = self.rank(c)?;
        Some((r & ((1u128 << self.bits()) - 1)) as u64)
    }

    /// All codewords in lexicographic order. Only for small spaces.
    pub fn enumerate(&self) -> Vec<Vec<u32>> {
        assert!(self.count() <= 1 << 24, "refusing to enumerate {} codewords", self.count());
        (0..self.count()).map(|r| self.unrank(r).unwrap()).collect()
    }

    /// Coordinatewise `x <= y`.
    pub fn leq(x: &[u32], y: &[u32]) -> bool {
        x.len() == y.len() && x.iter().zip(y).all(|(a, b)| a <= b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_match_reference_table() {
        // Counts reproduced from antichain-winternitz plots/sweep.csv bits_per_digit.
        for &(k, l, bits) in &[
            (2u32, 4u32, 2u32), (2, 8, 3), (2, 16, 4), (3, 4, 3), (3, 8, 5), (3, 16, 7),
            (4, 4, 5), (4, 8, 8), (4, 16, 11), (5, 4, 7), (5, 8, 11), (5, 16, 15),
        ] {
            assert_eq!(CodewordSpace::new(k, l).bits(), bits, "k={k} L={l}");
        }
    }

    #[test]
    fn rank_unrank_roundtrip_and_order() {
        for &(k, l) in &[(2u32, 4u32), (3, 4), (3, 8), (4, 4), (4, 8), (5, 4)] {
            let sp = CodewordSpace::new(k, l);
            let all = sp.enumerate();
            assert_eq!(all.len() as u128, sp.count());
            let mut sorted = all.clone();
            sorted.sort();
            assert_eq!(all, sorted, "unrank is lexicographic");
            for (i, c) in all.iter().enumerate() {
                assert!(sp.is_codeword(c));
                assert_eq!(sp.rank(c), Some(i as u128));
            }
            assert_eq!(sp.unrank(sp.count()), None);
        }
    }

    #[test]
    fn k3_l4_worked_example() {
        let sp = CodewordSpace::new(3, 4);
        assert_eq!(sp.count(), 12);
        assert_eq!(sp.unrank(0), Some(vec![0, 1, 3]));
    }

    #[test]
    fn decode_is_total_and_covers_all_values() {
        let sp = CodewordSpace::new(4, 8); // N = 344 over 256 values
        assert_eq!(sp.count(), 344);
        let mut seen = vec![0u32; 256];
        for c in sp.enumerate() {
            seen[sp.decode_value(&c).unwrap() as usize] += 1;
        }
        assert!(seen.iter().all(|&n| n >= 1), "every value has a codeword");
        assert_eq!(seen.iter().sum::<u32>(), 344);
    }

    #[test]
    fn constant_sum_is_an_antichain() {
        let sp = CodewordSpace::new(3, 8);
        let all = sp.enumerate();
        for x in &all {
            for y in &all {
                if x != y {
                    assert!(!CodewordSpace::leq(x, y), "{x:?} <= {y:?}");
                }
            }
        }
    }
}
