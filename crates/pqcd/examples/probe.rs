use pqcd::metrics::{marginal_vb_per_bit, Msg};
use pqcd::{HashKind, Scheme};
fn main() {
    for s in [
        Scheme::Lamport { hash: HashKind::Ripemd160 },
        Scheme::Lamport { hash: HashKind::Sha256 },
        Scheme::LamportNoBit { hash: HashKind::Ripemd160 },
        Scheme::Acw { k: 2, l: 16, hash: HashKind::Hash160 },
        Scheme::Acw { k: 4, l: 16, hash: HashKind::Hash160 },
    ] {
        println!("{:<28} canon {:.4} worst {:.4} rand {:.4}", s.name(),
            marginal_vb_per_bit(s, Msg::Canonical), marginal_vb_per_bit(s, Msg::Worst), marginal_vb_per_bit(s, Msg::Random(1)));
    }
}
