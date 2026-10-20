//! Count non-push opcodes of one digit's leaf (the P2WSH consensus limit is 201 per script).
use bitcoin::blockdata::script::Instruction;
use pqcd::scheme::{Scheme, SecretKey};
use pqcd::HashKind;
fn main() {
    for s in [Scheme::Lamport { hash: HashKind::Ripemd160 }, Scheme::Acw { k: 2, l: 16, hash: HashKind::Hash160 },
              Scheme::Acw { k: 4, l: 8, hash: HashKind::Hash160 }, Scheme::Acw { k: 4, l: 16, hash: HashKind::Hash160 }] {
        let sk = SecretKey::new(s, [1; 32], 1);
        let script = sk.commit().verify_script();
        let nonpush = script.instructions().filter_map(|i| i.ok()).filter(|i| matches!(i, Instruction::Op(op) if op.to_u8() > 0x60)).count();
        println!("{:<22} non-push opcodes per digit: {nonpush:>4}  -> digits under a 201-opcode cap: {}", s.name(), 200 / nonpush.max(1));
    }
}
