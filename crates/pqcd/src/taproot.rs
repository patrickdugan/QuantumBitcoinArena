//! Taproot packaging, transaction weight, and chunking under the stack limit.
//!
//! Every leaf is the only leaf of its output (control block = 33 bytes), the
//! internal key is the BIP-341 NUMS point (key path unspendable), and a message
//! longer than one stack allows is split over several inputs.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::scheme::{Commitment, Opening, Scheme, SecretKey};

/// BIP-341 NUMS internal key (`H = lift_x(sha256(G))`), so the key path is provably unspendable.
pub const NUMS_X: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Maximum initial witness stack (BIP-342).
pub const MAX_STACK: usize = 1000;

/// Taproot output for one leaf script.
pub fn spend_info(leaf: &ScriptBuf) -> TaprootSpendInfo {
    let secp = Secp256k1::verification_only();
    let internal: UntweakedPublicKey =
        UntweakedPublicKey::from_slice(&hex::decode(NUMS_X).unwrap()).expect("valid NUMS x-only key");
    TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("single leaf")
        .finalize(&secp, internal)
        .expect("finalize")
}

/// Control block of the (single) leaf.
pub fn control_block(leaf: &ScriptBuf) -> ControlBlock {
    spend_info(leaf)
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("leaf is in the tree")
}

/// One taproot input's spend data.
#[derive(Clone, Debug)]
pub struct LeafSpend {
    /// Leaf script.
    pub script: ScriptBuf,
    /// Initial stack items (everything except script and control block).
    pub stack: Vec<Vec<u8>>,
}

impl LeafSpend {
    /// Full witness: stack items, then script, then control block.
    pub fn witness(&self) -> Witness {
        let mut w = Witness::new();
        for it in &self.stack {
            w.push(it);
        }
        w.push(self.script.as_bytes());
        w.push(control_block(&self.script).serialize());
        w
    }

    /// Serialized witness size in bytes (equal to its weight units).
    pub fn witness_bytes(&self) -> usize {
        self.witness().size()
    }

    /// Bytes of the leaf script alone.
    pub fn script_bytes(&self) -> usize {
        self.script.len()
    }

    /// Bytes of the revealed data items alone (including per-item length prefixes).
    pub fn stack_bytes(&self) -> usize {
        self.stack.iter().map(|i| i.len() + compact_len(i.len())).sum()
    }
}

fn compact_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

/// Skeleton transaction spending `spends` (one input each) into one empty output.
pub fn skeleton_tx(spends: &[LeafSpend]) -> Transaction {
    let input = spends
        .iter()
        .enumerate()
        .map(|(i, s)| TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([i as u8 + 1; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: s.witness(),
        })
        .collect();
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: vec![TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new_op_return([0u8; 0]) }],
    }
}

/// Transaction weight in weight units.
pub fn tx_weight(spends: &[LeafSpend]) -> u64 {
    skeleton_tx(spends).weight().to_wu()
}

/// Split a message of `nbits` into digit ranges, each fitting `max_items` initial
/// stack items. Returns `(first_digit, n_digits)` per chunk.
pub fn chunk_digits(scheme: &Scheme, nbits: usize, max_items: usize) -> Vec<(usize, usize)> {
    let per = scheme.witness_items_per_digit();
    let total = scheme.digits_for(nbits);
    let cap = (max_items / per).max(1);
    let mut out = Vec::new();
    let mut d = 0;
    while d < total {
        let n = cap.min(total - d);
        out.push((d, n));
        d += n;
    }
    out
}

/// Slice a commitment's digit range into its own commitment.
pub fn slice_commitment(c: &Commitment, first: usize, n: usize) -> Commitment {
    Commitment { scheme: c.scheme, pks: c.pks[first..first + n].to_vec() }
}

/// Slice an opening's digit range.
pub fn slice_opening(o: &Opening, first: usize, n: usize) -> Opening {
    Opening { digits: o.digits[first..first + n].to_vec() }
}

/// Spend data for one chunk.
pub fn chunk_spend(c: &Commitment, o: &Opening, first: usize, n: usize) -> LeafSpend {
    let cc = slice_commitment(c, first, n);
    let oo = slice_opening(o, first, n);
    LeafSpend { script: cc.verify_script(), stack: oo.witness_stack(&c.scheme) }
}

/// Largest number of digits whose honest opening still executes under the interpreter's
/// consensus limits (initial stack <= 1000 items and stack + altstack <= 1000 throughout).
/// Bisection; the regtest harness confirms the boundary against Bitcoin Core.
pub fn max_digits_by_execution(scheme: &Scheme) -> usize {
    use crate::exec::{accepts, Mode};
    let ok = |n: usize| {
        let bits = n * scheme.bits_per_digit() as usize;
        let sk = SecretKey::for_bits(*scheme, [0x42; 32], bits);
        let com = sk.commit();
        let msg: Vec<bool> = (0..bits).map(|i| (i * 2654435761usize) >> 7 & 1 == 1).collect();
        let o = sk.open_bits(&msg);
        accepts(&com.verify_script(), &o.witness_stack(scheme), Mode::Consensus)
    };
    let per = scheme.witness_items_per_digit();
    let (mut lo, mut hi) = (1usize, MAX_STACK / per + 1);
    assert!(ok(lo), "a single digit must execute");
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if ok(mid) { lo = mid } else { hi = mid }
    }
    lo
}
