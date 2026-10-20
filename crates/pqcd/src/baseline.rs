//! Cost model of the reveal used by Mosaic today: one BIP-340 Schnorr adaptor
//! signature completed per 8-bit wide label.
//!
//! This is a *cost* comparator only. It is not post-quantum (secp256k1) and, per the
//! ACW paper, an adaptor does not by itself guarantee that the spend reveals the
//! label. The script is `OP_CODESEPARATOR <pk> OP_CHECKSIGVERIFY` per wire (the
//! separator gives each wire a distinct signature hash inside one input); the witness
//! carries one 64-byte signature per wire.

use bitcoin::opcodes::all as op;
use bitcoin::script::{Builder, PushBytesBuf};

use crate::taproot::LeafSpend;

/// Bits revealed by one signature in Mosaic's wide-label design.
pub const WIDE_LABEL_BITS: usize = 8;

/// Spend data for `wires` adaptor-completed signatures, with size-exact dummy contents.
pub fn schnorr_reveal_spend(wires: usize) -> LeafSpend {
    let mut b = Builder::new();
    for w in 0..wires {
        let pk = PushBytesBuf::try_from(vec![(w % 251) as u8 + 2; 32]).unwrap();
        b = b.push_opcode(op::OP_CODESEPARATOR).push_slice(pk);
        b = b.push_opcode(if w + 1 == wires { op::OP_CHECKSIG } else { op::OP_CHECKSIGVERIFY });
    }
    // Top of stack is the first wire's signature.
    let stack = (0..wires).rev().map(|w| vec![(w % 251) as u8 + 3; 64]).collect();
    LeafSpend { script: b.into_script(), stack }
}
