//! Public label table: turns an authenticated ACW opening into garbled-circuit input labels.
//!
//! For each digit and each admissible codeword `c` (rank `r`) the table stores
//! `row_r = pad(seed(c)) XOR payload(value(c))`, where `seed(c)` is the
//! concatenation of the `k` openers of `c` and `payload(v)` is whatever the garbler
//! wants to hand out for digit value `v` (for a bit-oriented circuit: one label per
//! bit of `v`). The map `rank -> value` is total, so **every** opening the script
//! accepts unlocks exactly one payload.
//!
//! Why other rows stay closed: reaching any other codeword `c'` needs an opener
//! `H^{L-c'_j}(s_j)` with `c'_j > c_j` for some chain `j`, which is a *preimage* of an
//! opener already revealed. See `docs/security.md`.

use crate::codeword::CodewordSpace;
use crate::hash::{pad, tagged, Digest};
use crate::scheme::{Commitment, DigitOpening, Scheme, SecretKey, VerifyError};

/// Table for one digit.
#[derive(Clone, Debug)]
pub struct DigitTable {
    /// `rows[r]` = `pad(seed(unrank(r))) XOR payload(value)`.
    pub rows: Vec<Vec<u8>>,
    /// Merkle root over the rows.
    pub root: [u8; 32],
}

fn ctx(table_id: &[u8], digit: usize) -> Vec<u8> {
    let mut c = table_id.to_vec();
    c.extend_from_slice(&(digit as u64).to_le_bytes());
    c
}

fn leaf_hash(row: &[u8], rank: usize) -> [u8; 32] {
    tagged("pqcd/leaf", &[&(rank as u64).to_le_bytes(), row])
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    tagged("pqcd/node", &[l, r])
}

/// Merkle root of leaf hashes (odd node promoted).
pub fn merkle_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for ch in level.chunks(2) {
            next.push(if ch.len() == 2 { node_hash(&ch[0], &ch[1]) } else { ch[0] });
        }
        level = next;
    }
    level[0]
}

/// Merkle authentication path for leaf `idx`.
pub fn merkle_path(leaves: &[[u8; 32]], mut idx: usize) -> Vec<[u8; 32]> {
    let mut level = leaves.to_vec();
    let mut path = Vec::new();
    while level.len() > 1 {
        let sib = idx ^ 1;
        if sib < level.len() {
            path.push(level[sib]);
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for ch in level.chunks(2) {
            next.push(if ch.len() == 2 { node_hash(&ch[0], &ch[1]) } else { ch[0] });
        }
        level = next;
        idx /= 2;
    }
    path
}

/// Verify a Merkle path produced by [`merkle_path`].
pub fn merkle_verify(root: &[u8; 32], leaf: [u8; 32], mut idx: usize, mut n: usize, path: &[[u8; 32]]) -> bool {
    let mut h = leaf;
    let mut it = path.iter();
    while n > 1 {
        let sib = idx ^ 1;
        if sib < n {
            let Some(s) = it.next() else { return false };
            h = if idx % 2 == 0 { node_hash(&h, s) } else { node_hash(s, &h) };
        }
        idx /= 2;
        n = n.div_ceil(2);
    }
    it.next().is_none() && &h == root
}

/// Concatenated openers of codeword `c` for digit `d` (the pad seed).
pub fn seed_of(sk: &SecretKey, d: usize, c: &[u32]) -> Vec<u8> {
    let Scheme::Acw { l, .. } = sk.scheme else { panic!("ACW only") };
    let mut s = Vec::new();
    for (j, &a) in c.iter().enumerate() {
        s.extend_from_slice(&sk.chain_element(d, j, l - a));
    }
    s
}

/// Build the table of digit `d`. `payload(v)` must return equal-length payloads.
pub fn build_digit_table(
    sk: &SecretKey,
    d: usize,
    table_id: &[u8],
    payload: &dyn Fn(u64) -> Vec<u8>,
) -> DigitTable {
    let Scheme::Acw { k, l, .. } = sk.scheme else { panic!("ACW only") };
    let sp = CodewordSpace::new(k, l);
    let cx = ctx(table_id, d);
    let n = sp.count() as usize;
    // One payload per value, computed once.
    let nv = 1usize << sp.bits();
    let payloads: Vec<Vec<u8>> = (0..nv as u64).map(payload).collect();
    let plen = payloads[0].len();
    assert!(payloads.iter().all(|p| p.len() == plen), "payloads must share a length");
    let mut rows: Vec<Vec<u8>> = Vec::with_capacity(n);
    for r in 0..n {
        let c = sp.unrank(r as u128).unwrap();
        let v = (r & (nv - 1)) as usize; // rank mod 2^bits, the total value map
        let p = pad(&seed_of(sk, d, &c), &cx, plen);
        rows.push(p.iter().zip(&payloads[v]).map(|(a, b)| a ^ b).collect::<Vec<u8>>());
    }
    let leaves: Vec<[u8; 32]> = rows.iter().enumerate().map(|(r, row)| leaf_hash(row, r)).collect();
    DigitTable { rows, root: merkle_root(leaves) }
}

/// Per-value commitments `C_v = tagged(ctx, v, payload)`; published so the evaluator
/// can check that a recovered payload is the one committed for value `v`.
pub fn value_commitments(table_id: &[u8], d: usize, bits: u32, payload: &dyn Fn(u64) -> Vec<u8>) -> Vec<[u8; 32]> {
    let cx = ctx(table_id, d);
    (0..1u64 << bits).map(|v| tagged("pqcd/value", &[&cx, &v.to_le_bytes(), &payload(v)])).collect()
}

/// Check one recovered payload against its value commitment.
pub fn check_value(table_id: &[u8], d: usize, v: u64, payload: &[u8], commitment: &[u8; 32]) -> bool {
    &tagged("pqcd/value", &[&ctx(table_id, d), &v.to_le_bytes(), payload]) == commitment
}

/// Evaluator side: from a verified digit opening, derive the payload of the opened codeword.
pub fn recover_payload(
    com: &Commitment,
    d: usize,
    opening: &DigitOpening,
    table: &DigitTable,
    table_id: &[u8],
) -> Result<(u64, Vec<u8>), VerifyError> {
    let val = com.verify_digit(d, opening)?;
    let Scheme::Acw { k, l, .. } = com.scheme else { panic!("ACW only") };
    let sp = CodewordSpace::new(k, l);
    let rank = sp.rank(&val.codeword).expect("verified codeword is admissible") as usize;
    let seed: Vec<u8> = opening.openers.iter().flat_map(|o| o.iter().copied()).collect();
    let row = &table.rows[rank];
    let p = pad(&seed, &ctx(table_id, d), row.len());
    Ok((val.value, row.iter().zip(&p).map(|(a, b)| a ^ b).collect()))
}

/// Garbler-secret audit (what an evaluator does on a challenged, fully opened
/// instance): every row must equal `pad(seed) XOR payload(rank mod 2^bits)`.
/// Returns the first bad rank.
pub fn audit_digit_table(
    sk: &SecretKey,
    d: usize,
    table_id: &[u8],
    table: &DigitTable,
    payload: &dyn Fn(u64) -> Vec<u8>,
) -> Result<(), usize> {
    let Scheme::Acw { k, l, .. } = sk.scheme else { panic!("ACW only") };
    let sp = CodewordSpace::new(k, l);
    let cx = ctx(table_id, d);
    let nv = 1usize << sp.bits();
    if table.rows.len() != sp.count() as usize {
        return Err(table.rows.len().min(sp.count() as usize));
    }
    for (r, row) in table.rows.iter().enumerate() {
        let c = sp.unrank(r as u128).unwrap();
        let want = payload((r & (nv - 1)) as u64);
        let p = pad(&seed_of(sk, d, &c), &cx, want.len());
        let expect: Vec<u8> = p.iter().zip(&want).map(|(a, b)| a ^ b).collect();
        if *row != expect {
            return Err(r);
        }
    }
    let leaves: Vec<[u8; 32]> = table.rows.iter().enumerate().map(|(r, row)| leaf_hash(row, r)).collect();
    if merkle_root(leaves) != table.root {
        return Err(usize::MAX);
    }
    Ok(())
}

/// Off-chain bytes of one digit table: rows plus Merkle root plus per-value commitments.
pub fn table_bytes(scheme: &Scheme, payload_len: usize, with_value_commitments: bool) -> usize {
    let sp = scheme.space().expect("ACW only");
    let rows = sp.count() as usize * payload_len;
    let vc = if with_value_commitments { (1usize << sp.bits()) * 32 } else { 0 };
    rows + 32 + vc
}

/// Convenience: openers of every codeword reachable by forward hashing from `known` openings
/// (the union over the openings of the per-chain reachable set). Returns all admissible
/// codewords `c'` with `c'_j <= max over openings of c_j` for every chain `j`.
pub fn reachable_codewords(sp: &CodewordSpace, known: &[Vec<u32>]) -> Vec<Vec<u32>> {
    let k = sp.k() as usize;
    let ceiling: Vec<u32> = (0..k).map(|j| known.iter().map(|c| c[j]).max().unwrap_or(0)).collect();
    sp.enumerate().into_iter().filter(|c| c.iter().zip(&ceiling).all(|(a, m)| a <= m)).collect()
}

/// Unused-but-handy re-export so callers can name digests uniformly.
pub type Opener = Digest;
