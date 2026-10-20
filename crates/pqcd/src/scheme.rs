//! Commitment schemes over a bitstring: per-bit Lamport and Antichain Winternitz.
//!
//! A [`SecretKey`] is a 32-byte master seed; every chain secret is derived from it.
//! [`SecretKey::commit`] produces the public [`Commitment`] (the terminals that go
//! into the Tapscript leaf). [`SecretKey::open_bits`] produces an [`Opening`], the
//! data that is posted in the witness. [`Commitment::verify`] checks an opening
//! with exactly the acceptance semantics of the generated script, and
//! [`Commitment::verify_script`] emits that script.

use std::fmt;

use bitcoin::opcodes::all as op;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::ScriptBuf;

use crate::codeword::CodewordSpace;
use crate::hash::{derive_secret, Digest, HashKind};

/// Which one-time commitment is used per digit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Scheme {
    /// Per-bit Lamport in the seven-opcode form of the BitVM design notes:
    /// the witness carries the preimage and the bit, `OP_IF` picks the digest.
    Lamport {
        /// Digest.
        hash: HashKind,
    },
    /// Per-bit Lamport without the bit item: the script hashes the preimage and
    /// accepts if it equals either committed digest. Saves one witness byte per bit.
    LamportNoBit {
        /// Digest.
        hash: HashKind,
    },
    /// Antichain Winternitz with `k` chains of length `L` (a power of two).
    Acw {
        /// Chains per digit.
        k: u32,
        /// Chain length.
        l: u32,
        /// Digest.
        hash: HashKind,
    },
}

impl Scheme {
    /// Hash function.
    pub fn hash(&self) -> HashKind {
        match *self {
            Scheme::Lamport { hash } | Scheme::LamportNoBit { hash } | Scheme::Acw { hash, .. } => hash,
        }
    }

    /// Human-readable identifier, stable across runs (used in JSON and fixtures).
    pub fn name(&self) -> String {
        match *self {
            Scheme::Lamport { hash } => format!("lamport-{}", hash.name()),
            Scheme::LamportNoBit { hash } => format!("lamport-nobit-{}", hash.name()),
            Scheme::Acw { k, l, hash } => format!("acw-k{k}-l{l}-{}", hash.name()),
        }
    }

    /// Codeword space (ACW only).
    pub fn space(&self) -> Option<CodewordSpace> {
        match *self {
            Scheme::Acw { k, l, .. } => Some(CodewordSpace::new(k, l)),
            _ => None,
        }
    }

    /// Message bits carried by one digit.
    pub fn bits_per_digit(&self) -> u32 {
        match self.space() {
            Some(sp) => sp.bits(),
            None => 1,
        }
    }

    /// Public hash values committed per digit (2 for Lamport, `k` for ACW).
    pub fn pks_per_digit(&self) -> usize {
        match *self {
            Scheme::Lamport { .. } | Scheme::LamportNoBit { .. } => 2,
            Scheme::Acw { k, .. } => k as usize,
        }
    }

    /// Items one digit contributes to the initial witness stack.
    pub fn witness_items_per_digit(&self) -> usize {
        match *self {
            Scheme::Lamport { .. } => 2,
            Scheme::LamportNoBit { .. } => 1,
            Scheme::Acw { k, .. } => 2 * k as usize - 1,
        }
    }

    /// Number of digits needed for `nbits` message bits.
    pub fn digits_for(&self, nbits: usize) -> usize {
        nbits.div_ceil(self.bits_per_digit() as usize)
    }

    /// Validate parameters (power-of-two `L`, `k >= 2`).
    pub fn validate(&self) -> Result<(), String> {
        if let Scheme::Acw { k, l, .. } = *self {
            if k < 2 {
                return Err("k must be >= 2".into());
            }
            if l < 2 || !l.is_power_of_two() {
                return Err("L must be a power of two >= 2 (the bare-count verifier relies on L = 2^w)".into());
            }
        }
        Ok(())
    }
}

/// Reasons a commitment or an opening is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Wrong number of digits.
    DigitCount { expected: usize, got: usize },
    /// Wrong number of openers or posted values in a digit.
    Arity { digit: usize },
    /// An opener has the wrong length for the hash.
    DigestLen { digit: usize },
    /// A posted or derived coordinate lies outside `[0, L-1]` (or a bit is not 0/1).
    OutOfRange { digit: usize },
    /// An opener does not hash to its committed terminal.
    ChainMismatch { digit: usize, chain: usize },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VerifyError {}

/// Defects a garbler could plant in the public commitment itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitmentDefect {
    /// Wrong number of digits or chains.
    Shape,
    /// A terminal has the wrong length.
    DigestLen,
    /// Two terminals in one digit are equal. For Lamport this makes the bit
    /// unbound; for ACW it lets one opener serve two chains.
    DuplicateInDigit { digit: usize },
    /// The same terminal appears in two digits, so openings can be swapped between them.
    DuplicateAcrossDigits { first: usize, second: usize },
}

/// One digit of an opening: the revealed openers and the posted coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigitOpening {
    /// Revealed hash values: one preimage for Lamport, `k` chain elements for ACW.
    pub openers: Vec<Digest>,
    /// Posted script numbers: the bit (Lamport), nothing (LamportNoBit), or the
    /// first `k-1` coordinates (ACW; the last is derived in script).
    pub posted: Vec<i64>,
}

/// A full opening: one [`DigitOpening`] per digit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Per-digit openings.
    pub digits: Vec<DigitOpening>,
}

/// Public commitment: the terminals embedded in the script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    /// Scheme and parameters.
    pub scheme: Scheme,
    /// `pks[d]` are the terminals of digit `d`.
    pub pks: Vec<Vec<Digest>>,
}

/// Secret key: a master seed from which every chain secret is derived.
#[derive(Clone)]
pub struct SecretKey {
    /// Scheme and parameters.
    pub scheme: Scheme,
    /// Number of digits.
    pub n_digits: usize,
    master: [u8; 32],
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({}, {} digits, <redacted>)", self.scheme.name(), self.n_digits)
    }
}

/// Minimal Script-number encoding.
pub fn scriptnum(v: i64) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let neg = v < 0;
    let mut abs = v.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().is_some_and(|b| b & 0x80 != 0) {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

impl SecretKey {
    /// New key for `n_digits` digits from a master seed.
    pub fn new(scheme: Scheme, master: [u8; 32], n_digits: usize) -> Self {
        scheme.validate().expect("valid scheme");
        Self { scheme, n_digits, master }
    }

    /// Key sized for `nbits` message bits.
    pub fn for_bits(scheme: Scheme, master: [u8; 32], nbits: usize) -> Self {
        Self::new(scheme, master, scheme.digits_for(nbits))
    }

    fn secret(&self, digit: usize, chain: usize) -> Vec<u8> {
        derive_secret(&self.master, &self.scheme.name(), digit as u32, chain as u32, self.scheme.hash().len())
    }

    /// Chain element `x_i = H^i(s)` of chain `chain` in digit `digit`. `x_0` is the
    /// secret and is never revealed.
    pub fn chain_element(&self, digit: usize, chain: usize, i: u32) -> Digest {
        self.scheme.hash().iterate(&self.secret(digit, chain), i)
    }

    /// Public commitment.
    pub fn commit(&self) -> Commitment {
        let hk = self.scheme.hash();
        let mut pks = Vec::with_capacity(self.n_digits);
        for d in 0..self.n_digits {
            let digit_pks = match self.scheme {
                Scheme::Lamport { .. } | Scheme::LamportNoBit { .. } => {
                    (0..2).map(|b| hk.digest(&self.secret(d, b))).collect()
                }
                Scheme::Acw { k, l, .. } => (0..k as usize)
                    .map(|j| hk.iterate(&self.secret(d, j), l))
                    .collect(),
            };
            pks.push(digit_pks);
        }
        Commitment { scheme: self.scheme, pks }
    }

    /// Open digit `d` to value `v` (`v < 2^bits_per_digit`).
    pub fn open_digit(&self, d: usize, v: u64) -> DigitOpening {
        match self.scheme {
            Scheme::Lamport { .. } => {
                assert!(v < 2);
                DigitOpening { openers: vec![self.secret(d, v as usize)], posted: vec![v as i64] }
            }
            Scheme::LamportNoBit { .. } => {
                assert!(v < 2);
                DigitOpening { openers: vec![self.secret(d, v as usize)], posted: vec![] }
            }
            Scheme::Acw { k, l, .. } => {
                let sp = CodewordSpace::new(k, l);
                self.open_codeword(d, &sp.encode_value(v))
            }
        }
    }

    /// Open an ACW digit to an explicit codeword (must be admissible).
    pub fn open_codeword(&self, d: usize, c: &[u32]) -> DigitOpening {
        let Scheme::Acw { k, l, .. } = self.scheme else { panic!("ACW only") };
        let sp = CodewordSpace::new(k, l);
        assert!(sp.is_codeword(c), "not an admissible codeword: {c:?}");
        let openers = c
            .iter()
            .enumerate()
            .map(|(j, &a)| self.chain_element(d, j, l - a))
            .collect();
        DigitOpening { openers, posted: c[..k as usize - 1].iter().map(|&a| i64::from(a)).collect() }
    }

    /// Open the whole message. `bits` is LSB-first within each digit; the final
    /// digit is zero-padded.
    pub fn open_bits(&self, bits: &[bool]) -> Opening {
        let b = self.scheme.bits_per_digit() as usize;
        assert!(bits.len() <= self.n_digits * b);
        let digits = (0..self.n_digits)
            .map(|d| {
                let mut v = 0u64;
                for i in 0..b {
                    if bits.get(d * b + i).copied().unwrap_or(false) {
                        v |= 1 << i;
                    }
                }
                self.open_digit(d, v)
            })
            .collect();
        Opening { digits }
    }
}

/// What a verified digit decodes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigitValue {
    /// Digit value in `[0, 2^bits)`.
    pub value: u64,
    /// Codeword (ACW) or empty (Lamport).
    pub codeword: Vec<u32>,
}

impl Commitment {
    /// Number of digits.
    pub fn n_digits(&self) -> usize {
        self.pks.len()
    }

    /// Check the garbler-chosen commitment for structural defects. An evaluator
    /// must run this on every commitment it is about to trust.
    pub fn validate(&self) -> Result<(), CommitmentDefect> {
        let hk = self.scheme.hash();
        let want = self.scheme.pks_per_digit();
        let mut seen: std::collections::HashMap<&[u8], usize> = std::collections::HashMap::new();
        for (d, pks) in self.pks.iter().enumerate() {
            if pks.len() != want {
                return Err(CommitmentDefect::Shape);
            }
            if pks.iter().any(|p| p.len() != hk.len()) {
                return Err(CommitmentDefect::DigestLen);
            }
            for (i, p) in pks.iter().enumerate() {
                if pks[..i].contains(p) {
                    return Err(CommitmentDefect::DuplicateInDigit { digit: d });
                }
                if let Some(&first) = seen.get(p.as_slice()) {
                    if first != d {
                        return Err(CommitmentDefect::DuplicateAcrossDigits { first, second: d });
                    }
                }
                seen.insert(p.as_slice(), d);
            }
        }
        Ok(())
    }

    /// Verify one digit with the exact acceptance semantics of the script.
    pub fn verify_digit(&self, d: usize, o: &DigitOpening) -> Result<DigitValue, VerifyError> {
        let hk = self.scheme.hash();
        let pks = &self.pks[d];
        if o.openers.iter().any(|x| x.len() != hk.len()) {
            return Err(VerifyError::DigestLen { digit: d });
        }
        match self.scheme {
            Scheme::Lamport { .. } => {
                if o.openers.len() != 1 || o.posted.len() != 1 {
                    return Err(VerifyError::Arity { digit: d });
                }
                let bit = o.posted[0];
                if bit != 0 && bit != 1 {
                    return Err(VerifyError::OutOfRange { digit: d });
                }
                if hk.digest(&o.openers[0]) != pks[bit as usize] {
                    return Err(VerifyError::ChainMismatch { digit: d, chain: bit as usize });
                }
                Ok(DigitValue { value: bit as u64, codeword: vec![] })
            }
            Scheme::LamportNoBit { .. } => {
                if o.openers.len() != 1 || !o.posted.is_empty() {
                    return Err(VerifyError::Arity { digit: d });
                }
                let h = hk.digest(&o.openers[0]);
                if h == pks[0] {
                    Ok(DigitValue { value: 0, codeword: vec![] })
                } else if h == pks[1] {
                    Ok(DigitValue { value: 1, codeword: vec![] })
                } else {
                    Err(VerifyError::ChainMismatch { digit: d, chain: 0 })
                }
            }
            Scheme::Acw { k, l, .. } => {
                let k = k as usize;
                if o.openers.len() != k || o.posted.len() != k - 1 {
                    return Err(VerifyError::Arity { digit: d });
                }
                let sp = CodewordSpace::new(k as u32, l);
                let mut coords = Vec::with_capacity(k);
                let mut sum: i64 = 0;
                for j in 0..k - 1 {
                    let a = o.posted[j];
                    if a < 0 || a >= i64::from(l) {
                        return Err(VerifyError::OutOfRange { digit: d });
                    }
                    if hk.iterate(&o.openers[j], a as u32) != pks[j] {
                        return Err(VerifyError::ChainMismatch { digit: d, chain: j });
                    }
                    sum += a;
                    coords.push(a as u32);
                }
                let last = i64::from(sp.r()) - sum;
                if last < 0 || last >= i64::from(l) {
                    return Err(VerifyError::OutOfRange { digit: d });
                }
                if hk.iterate(&o.openers[k - 1], last as u32) != pks[k - 1] {
                    return Err(VerifyError::ChainMismatch { digit: d, chain: k - 1 });
                }
                coords.push(last as u32);
                let value = sp.decode_value(&coords).expect("admissible by construction");
                Ok(DigitValue { value, codeword: coords })
            }
        }
    }

    /// Verify a full opening and decode the message bits (LSB-first within digits).
    pub fn verify(&self, o: &Opening) -> Result<Vec<DigitValue>, VerifyError> {
        if o.digits.len() != self.n_digits() {
            return Err(VerifyError::DigitCount { expected: self.n_digits(), got: o.digits.len() });
        }
        o.digits.iter().enumerate().map(|(d, od)| self.verify_digit(d, od)).collect()
    }

    /// Decode verified digits to the first `nbits` message bits.
    pub fn bits_of(&self, vals: &[DigitValue], nbits: usize) -> Vec<bool> {
        let b = self.scheme.bits_per_digit() as usize;
        (0..nbits).map(|i| (vals[i / b].value >> (i % b)) & 1 == 1).collect()
    }

    /// The Tapscript leaf that accepts exactly the openings `verify` accepts.
    pub fn verify_script(&self) -> ScriptBuf {
        let hk = self.scheme.hash();
        let mut b = Builder::new();
        for pks in &self.pks {
            match self.scheme {
                Scheme::Lamport { .. } => {
                    b = b.push_opcode(op::OP_IF).push_opcode(hk.opcode());
                    b = push_digest(b, &pks[1]).push_opcode(op::OP_EQUALVERIFY).push_opcode(op::OP_ELSE);
                    b = b.push_opcode(hk.opcode());
                    b = push_digest(b, &pks[0]).push_opcode(op::OP_EQUALVERIFY).push_opcode(op::OP_ENDIF);
                }
                Scheme::LamportNoBit { .. } => {
                    b = b.push_opcode(hk.opcode()).push_opcode(op::OP_DUP);
                    b = push_digest(b, &pks[0]).push_opcode(op::OP_EQUAL).push_opcode(op::OP_SWAP);
                    b = push_digest(b, &pks[1]).push_opcode(op::OP_EQUAL).push_opcode(op::OP_BOOLOR).push_opcode(op::OP_VERIFY);
                }
                Scheme::Acw { k, l, .. } => {
                    let sp = CodewordSpace::new(k, l);
                    let nb = l.trailing_zeros();
                    let k = k as usize;
                    for (j, pk) in pks.iter().enumerate().take(k - 1) {
                        b = if j == 0 {
                            b.push_opcode(op::OP_DUP).push_opcode(op::OP_TOALTSTACK)
                        } else {
                            b.push_opcode(op::OP_DUP)
                                .push_opcode(op::OP_FROMALTSTACK)
                                .push_opcode(op::OP_ADD)
                                .push_opcode(op::OP_TOALTSTACK)
                        };
                        b = binary_hash_loop(b, nb, hk);
                        b = push_digest(b, pk).push_opcode(op::OP_EQUALVERIFY);
                    }
                    // derived count: R - sum
                    b = b.push_int(i64::from(sp.r())).push_opcode(op::OP_FROMALTSTACK).push_opcode(op::OP_SUB);
                    b = binary_hash_loop(b, nb, hk);
                    b = push_digest(b, &pks[k - 1]).push_opcode(op::OP_EQUALVERIFY);
                }
            }
        }
        b.push_opcode(op::OP_PUSHNUM_1).into_script()
    }
}

fn push_digest(b: Builder, d: &[u8]) -> Builder {
    b.push_slice(PushBytesBuf::try_from(d.to_vec()).expect("digest fits a push"))
}

/// `<value> <count>` -> `<H^count(value)>` for `count in [0, 2^nb - 1]`; any other
/// count leaves a residue outside `{0,1}` that the final `OP_IF` rejects (MINIMALIF).
fn binary_hash_loop(mut b: Builder, nb: u32, hk: HashKind) -> Builder {
    for bit in (0..nb).rev() {
        if bit != 0 {
            let pow = 1i64 << bit;
            b = b
                .push_opcode(op::OP_DUP)
                .push_int(pow)
                .push_opcode(op::OP_GREATERTHANOREQUAL)
                .push_opcode(op::OP_IF)
                .push_int(pow)
                .push_opcode(op::OP_SUB)
                .push_opcode(op::OP_SWAP);
            for _ in 0..pow {
                b = b.push_opcode(hk.opcode());
            }
            b = b.push_opcode(op::OP_SWAP).push_opcode(op::OP_ENDIF);
        } else {
            b = b.push_opcode(op::OP_IF).push_opcode(hk.opcode()).push_opcode(op::OP_ENDIF);
        }
    }
    b
}

impl Opening {
    /// Initial witness stack in push order (last element is the top of the stack).
    /// Digit 0 ends on top so the script consumes digits in order.
    pub fn witness_stack(&self, scheme: &Scheme) -> Vec<Vec<u8>> {
        let mut st = Vec::new();
        for d in self.digits.iter().rev() {
            match scheme {
                Scheme::Lamport { .. } => {
                    st.push(d.openers[0].clone());
                    st.push(scriptnum(d.posted[0]));
                }
                Scheme::LamportNoBit { .. } => st.push(d.openers[0].clone()),
                Scheme::Acw { k, .. } => {
                    let k = *k as usize;
                    st.push(d.openers[k - 1].clone());
                    for j in (0..k - 1).rev() {
                        st.push(d.openers[j].clone());
                        st.push(scriptnum(d.posted[j]));
                    }
                }
            }
        }
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn schemes() -> Vec<Scheme> {
        let h = HashKind::Hash160;
        vec![
            Scheme::Lamport { hash: HashKind::Ripemd160 },
            Scheme::LamportNoBit { hash: HashKind::Ripemd160 },
            Scheme::Acw { k: 2, l: 16, hash: h },
            Scheme::Acw { k: 3, l: 8, hash: h },
            Scheme::Acw { k: 4, l: 8, hash: h },
            Scheme::Acw { k: 4, l: 16, hash: HashKind::Sha256 },
        ]
    }

    #[test]
    fn scriptnum_matches_consensus_encoding() {
        assert_eq!(scriptnum(0), Vec::<u8>::new());
        assert_eq!(scriptnum(1), vec![1]);
        assert_eq!(scriptnum(16), vec![16]);
        assert_eq!(scriptnum(127), vec![0x7f]);
        assert_eq!(scriptnum(128), vec![0x80, 0x00]);
        assert_eq!(scriptnum(-1), vec![0x81]);
        assert_eq!(scriptnum(-128), vec![0x80, 0x80]);
        assert_eq!(scriptnum(256), vec![0x00, 0x01]);
    }

    #[test]
    fn honest_roundtrip_all_schemes() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        for s in schemes() {
            let nbits = 37;
            let sk = SecretKey::for_bits(s, [7u8; 32], nbits);
            let com = sk.commit();
            com.validate().unwrap();
            let bits: Vec<bool> = (0..nbits).map(|_| rng.gen()).collect();
            let op = sk.open_bits(&bits);
            let vals = com.verify(&op).unwrap();
            assert_eq!(com.bits_of(&vals, nbits), bits, "{}", s.name());
        }
    }

    #[test]
    fn open_value_decodes_back_for_every_value() {
        let s = Scheme::Acw { k: 3, l: 8, hash: HashKind::Hash160 };
        let sk = SecretKey::new(s, [1u8; 32], 1);
        let com = sk.commit();
        for v in 0..(1u64 << s.bits_per_digit()) {
            let o = sk.open_digit(0, v);
            assert_eq!(com.verify_digit(0, &o).unwrap().value, v);
        }
    }
}
