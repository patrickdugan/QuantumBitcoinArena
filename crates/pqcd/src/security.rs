//! Concrete-security model for the hash-chain commitments, classical and quantum.
//!
//! Everything here is a *generic-attack* model: bits of work for the best known generic
//! attacks on an ideal `n`-bit hash. It says nothing about structural attacks on
//! RIPEMD-160 or SHA-256 and is not a proof. See `docs/security.md` for the argument that
//! ties these numbers to the scheme and for the assumptions behind each row.
//!
//! What the script argument actually needs from the hash:
//!
//! * **Evaluator (unforgeability / label privacy).** After one opening it holds `T` revealed
//!   chain elements and the public terminals. To open a second codeword it must find, on some
//!   chain, a *preimage* of a public or revealed value under `H^m` (a backward step). Generic
//!   cost: `2^n / T` evaluations classically; Grover with `T` marked items needs about
//!   `sqrt(2^n / T)` sequential iterations. **This is the figure that bounds the scheme.**
//! * **Garbler.** It knows every chain secret, so it can already open any codeword it likes;
//!   Bitcoin's single-spend rule, not a hash, stops it opening two. Collision resistance is
//!   therefore *not* used by the script argument. The collision figures below are reported
//!   because hash commitments elsewhere in a protocol (table roots, circuit commitments,
//!   a hash of all terminals) do need it: classically `2^(n/2)`; Brassard-Hoyer-Tapp needs
//!   `2^(n/3)` queries but also `2^(n/3)` quantum-accessible memory, which makes it
//!   non-competitive once memory is costed (Chailloux, Naya-Plasencia, Schrottenloher 2017).

use crate::hash::HashKind;
use crate::scheme::Scheme;

/// Security estimate in bits of work (`log2`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Security {
    /// Digest size `n`.
    pub digest_bits: u32,
    /// Revealed digests an evaluator can target after a full opening.
    pub targets: u64,
    /// Conservative loss from iterating a public hash: the image of `H^i` is about `2/i` of
    /// the domain, so a chain element has about `i/2` preimages instead of one (bits; `log2 L`
    /// for ACW, 0 for Lamport). This is the usual Winternitz "w" term, not a bound on any
    /// structural attack.
    pub chain_loss_bits: f64,
    /// Classical generic cost of unlocking an unopened row (multi-target preimage).
    pub evaluator_classical: f64,
    /// Quantum cost in sequential Grover iterations (multi-target).
    pub evaluator_quantum_iterations: f64,
    /// Classical generic collision cost (needed by hash commitments elsewhere, not by the script argument).
    pub garbler_collision_classical: f64,
    /// BHT collision queries (needs the same amount of qRAM; shown for completeness).
    pub garbler_collision_quantum_bht: f64,
}

/// Number of chain elements an evaluator can try to invert after the whole message is opened.
pub fn targets(scheme: &Scheme, nbits: usize) -> u64 {
    let digits = scheme.digits_for(nbits) as u64;
    match scheme {
        // one unopened digest per bit
        Scheme::Lamport { .. } | Scheme::LamportNoBit { .. } => digits,
        // one revealed element per chain
        Scheme::Acw { k, .. } => digits * u64::from(*k),
    }
}

/// Estimate for a scheme committing `nbits` bits.
pub fn estimate(scheme: &Scheme, nbits: usize) -> Security {
    let n = scheme.hash().bits();
    let t = targets(scheme, nbits).max(1);
    let lt = (t as f64).log2();
    let loss = match scheme {
        Scheme::Acw { l, .. } => f64::from(*l).log2(),
        _ => 0.0,
    };
    Security {
        digest_bits: n,
        targets: t,
        chain_loss_bits: loss,
        evaluator_classical: f64::from(n) - lt - loss,
        evaluator_quantum_iterations: (f64::from(n) - lt - loss) / 2.0,
        garbler_collision_classical: f64::from(n) / 2.0,
        garbler_collision_quantum_bht: f64::from(n) / 3.0,
    }
}

/// Label length (bits) of the garbled circuit and its generic-attack costs, for the
/// weakest-link comparison. `ckt-gobble` uses 128-bit labels (AES-128 based CCRND hash).
pub fn label_security(label_bits: u32) -> (f64, f64) {
    (f64::from(label_bits), f64::from(label_bits) / 2.0)
}

/// Smallest digest (from the three Script-native hashes) whose evaluator-side quantum
/// cost for `nbits` stays at or above `target_quantum_bits`.
pub fn smallest_hash_for(nbits: usize, target_quantum_bits: f64) -> Option<HashKind> {
    for hk in [HashKind::Hash160, HashKind::Sha256] {
        let s = estimate(&Scheme::Acw { k: 4, l: 16, hash: hk }, nbits);
        if s.evaluator_quantum_iterations >= target_quantum_bits {
            return Some(hk);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grover_halves_the_exponent() {
        let s = estimate(&Scheme::Acw { k: 4, l: 16, hash: HashKind::Sha256 }, 1024);
        assert!((s.evaluator_quantum_iterations * 2.0 - s.evaluator_classical).abs() < 1e-9);
    }

    #[test]
    fn hash160_is_below_a_100_bit_quantum_target() {
        assert_eq!(smallest_hash_for(1024, 100.0), Some(HashKind::Sha256));
        assert_eq!(smallest_hash_for(1024, 64.0), Some(HashKind::Hash160));
    }
}
