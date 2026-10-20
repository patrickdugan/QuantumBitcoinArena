//! Honest openings execute; sizes reproduce the reference crate's numbers.

use pqcd::exec::{accepts, run, Mode};
use pqcd::metrics::{marginal_vb_per_bit, Msg};
use pqcd::scheme::{Scheme, SecretKey};
use pqcd::HashKind;

fn all_schemes() -> Vec<Scheme> {
    let mut v = vec![];
    for h in [HashKind::Ripemd160, HashKind::Hash160, HashKind::Sha256] {
        v.push(Scheme::Lamport { hash: h });
        v.push(Scheme::LamportNoBit { hash: h });
        for (k, l) in [(2, 4), (2, 16), (3, 8), (4, 8), (4, 16)] {
            v.push(Scheme::Acw { k, l, hash: h });
        }
    }
    v
}

#[test]
fn honest_openings_execute_in_both_modes() {
    for s in all_schemes() {
        let sk = SecretKey::for_bits(s, [3u8; 32], 40);
        let com = sk.commit();
        let bits: Vec<bool> = (0..40).map(|i| (i * 7 + 3) % 5 < 2).collect();
        let op = sk.open_bits(&bits);
        let script = com.verify_script();
        let st = op.witness_stack(&s);
        for mode in [Mode::Consensus, Mode::Policy] {
            let r = run(&script, &st, mode);
            assert!(r.ok, "{} {:?}: {:?}", s.name(), mode, r.error);
        }
        assert!(com.verify(&op).is_ok());
    }
}

#[test]
fn reproduces_reference_vbytes() {
    let h20 = HashKind::Hash160;
    let near = |a: f64, b: f64| (a - b).abs() < 0.006;
    // reference: Lamport RIPEMD160 17.75, SHA256 26.75; ACW k=2 L=16 11.31 / 14.31; k=4 8.36 / 10.55
    assert!(near(marginal_vb_per_bit(Scheme::Lamport { hash: HashKind::Ripemd160 }, Msg::Canonical), 17.75));
    assert!(near(marginal_vb_per_bit(Scheme::Lamport { hash: HashKind::Sha256 }, Msg::Canonical), 26.75));
    assert!(near(marginal_vb_per_bit(Scheme::Acw { k: 2, l: 16, hash: h20 }, Msg::Canonical), 11.31));
    assert!(near(marginal_vb_per_bit(Scheme::Acw { k: 2, l: 16, hash: HashKind::Sha256 }, Msg::Canonical), 14.31));
    assert!(near(marginal_vb_per_bit(Scheme::Acw { k: 4, l: 16, hash: h20 }, Msg::Canonical), 8.36));
    assert!(near(marginal_vb_per_bit(Scheme::Acw { k: 4, l: 16, hash: HashKind::Sha256 }, Msg::Canonical), 10.55));
}

#[test]
fn op_cat_is_disabled_in_the_harness() {
    use bitcoin::opcodes::all as op;
    use bitcoin::script::Builder;
    let script = Builder::new().push_opcode(op::OP_CAT).push_opcode(op::OP_PUSHNUM_1).into_script();
    assert!(!accepts(&script, &[vec![1], vec![2]], Mode::Consensus));
}
