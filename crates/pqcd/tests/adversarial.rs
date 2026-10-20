//! Adversarial property tests.
//!
//! Attacker models:
//! * **Evaluator**: holds the public commitment, the public label table and one valid
//!   opening. Capabilities: apply the hash forward any number of times. No preimages.
//! * **Garbler**: holds the secrets. Can open any coordinates it likes, but the script
//!   (not the garbler) decides what is accepted.
//!
//! Every test checks the native verifier *and* the generated Tapscript, executed with
//! `OP_CAT` off and MINIMALIF/stack limits on.

use pqcd::codeword::CodewordSpace;
use pqcd::exec::{accepts, Mode};
use pqcd::gadget::{self};
use pqcd::scheme::{scriptnum, CommitmentDefect, DigitOpening, Opening, Scheme, SecretKey};
use pqcd::{Commitment, HashKind};
use proptest::prelude::*;

const H: HashKind = HashKind::Hash160;

fn script_ok(com: &Commitment, o: &Opening, mode: Mode) -> bool {
    accepts(&com.verify_script(), &o.witness_stack(&com.scheme), mode)
}

fn one_digit(com: &Commitment, d: usize) -> Commitment {
    Commitment { scheme: com.scheme, pks: vec![com.pks[d].clone()] }
}

/// Native and script verdicts must agree; returns the common verdict.
fn both(com: &Commitment, o: &Opening) -> bool {
    let native = com.verify(o).is_ok();
    let script = script_ok(com, o, Mode::Consensus);
    assert_eq!(native, script, "native verifier and script disagree");
    native
}

fn acw(k: u32, l: u32) -> Scheme {
    Scheme::Acw { k, l, hash: H }
}

fn one_digit_key(s: Scheme, seed: u8) -> (SecretKey, Commitment) {
    let sk = SecretKey::new(s, [seed; 32], 1);
    let com = sk.commit();
    (sk, com)
}

// ------------------------------------------------------------ 1. alternate-bit opening

#[test]
fn lamport_alternate_bit_opening_is_rejected() {
    for s in [Scheme::Lamport { hash: HashKind::Ripemd160 }, Scheme::LamportNoBit { hash: HashKind::Ripemd160 }] {
        let (sk, com) = one_digit_key(s, 1);
        for honest in 0..2u64 {
            let o = sk.open_digit(0, honest);
            assert!(both(&com, &Opening { digits: vec![o.clone()] }));
            let other = 1 - honest as i64;
            // (i) claim the other bit with the same preimage, (ii) a forward-hashed preimage, (iii) garbage
            let mut tries: Vec<DigitOpening> = vec![];
            for pre in [o.openers[0].clone(), s.hash().digest(&o.openers[0]), vec![0xAB; s.hash().len()]] {
                let posted = if matches!(s, Scheme::Lamport { .. }) { vec![other] } else { vec![] };
                tries.push(DigitOpening { openers: vec![pre], posted });
            }
            for t in tries {
                let accepted = both(&com, &Opening { digits: vec![t.clone()] });
                // For the no-bit variant the "claim" is implicit: acceptance must then mean
                // the *honest* preimage only, which decodes to the honest bit.
                if accepted {
                    let v = com.verify_digit(0, &t).unwrap().value;
                    assert_eq!(v, honest, "alternate bit accepted for {}", s.name());
                }
            }
        }
    }
}

/// Exhaustive: from the honest opener of codeword `c`, the strongest evaluator forgery for
/// any other codeword `c'` is rejected. The reason is the lemma checked on the way:
/// `c != c'` and equal sums force some `c'_j > c_j`, i.e. a backward step on chain `j`.
fn alternate_codeword_exhaustive(k: u32, l: u32, script_stride: usize) {
    let s = acw(k, l);
    let sp = CodewordSpace::new(k, l);
    let (sk, com) = one_digit_key(s, 2);
    let all = sp.enumerate();
    let mut pair = 0usize;
    for c in &all {
        let honest = sk.open_codeword(0, c);
        for c2 in &all {
            if c == c2 {
                continue;
            }
            // lemma
            assert!(c2.iter().zip(c).any(|(b, a)| b > a), "antichain lemma violated");
            // best-effort forgery: forward-hash every chain that can reach c2, keep the rest
            let openers: Vec<Vec<u8>> = (0..k as usize)
                .map(|j| {
                    if c2[j] <= c[j] {
                        H.iterate(&honest.openers[j], c[j] - c2[j])
                    } else {
                        honest.openers[j].clone()
                    }
                })
                .collect();
            let forged = DigitOpening { openers, posted: c2[..k as usize - 1].iter().map(|&a| i64::from(a)).collect() };
            let o = Opening { digits: vec![forged] };
            assert!(com.verify(&o).is_err(), "native accepted forgery {c:?} -> {c2:?}");
            if pair % script_stride == 0 {
                assert!(!script_ok(&com, &o, Mode::Consensus), "script accepted forgery {c:?} -> {c2:?}");
            }
            pair += 1;
        }
    }
}

#[test]
fn acw_alternate_codeword_exhaustive_small() {
    alternate_codeword_exhaustive(2, 8, 1);
    alternate_codeword_exhaustive(3, 4, 1);
    alternate_codeword_exhaustive(3, 8, 1);
}

#[test]
fn acw_alternate_codeword_exhaustive_k4_l8() {
    // 344 codewords: 118k ordered pairs. Native on all, script on every 61st.
    alternate_codeword_exhaustive(4, 8, 61);
}

// ------------------------------------------------------------ 2. forward-hashing forgery

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, .. ProptestConfig::default() })]

    /// Random attacker strategies built from forward hashing and coordinate edits. The only
    /// accepted outcome is the honest codeword, and native and script always agree.
    #[test]
    fn forward_hashing_never_equivocates(
        pick in 0usize..3,
        rank_seed in any::<u64>(),
        fwd in proptest::collection::vec(0u32..4, 6),
        edit in proptest::collection::vec(-2i64..3, 5),
        seed in any::<u8>(),
    ) {
        let (k, l) = [(3u32, 8u32), (4, 8), (2, 16)][pick];
        let s = acw(k, l);
        let sp = CodewordSpace::new(k, l);
        let (sk, com) = one_digit_key(s, seed);
        let c = sp.unrank(u128::from(rank_seed) % sp.count()).unwrap();
        let honest = sk.open_codeword(0, &c);
        let mut o = honest.clone();
        for j in 0..k as usize {
            o.openers[j] = H.iterate(&o.openers[j], fwd[j]);
        }
        for j in 0..k as usize - 1 {
            o.posted[j] += edit[j];
        }
        let opening = Opening { digits: vec![o.clone()] };
        let verdict = both(&com, &opening);
        if verdict {
            let got = com.verify_digit(0, &o).unwrap().codeword;
            prop_assert_eq!(got, c, "an accepted forgery decoded to a different codeword");
        }
    }

    /// Native verifier == script on arbitrary witnesses (random bytes, random numbers).
    #[test]
    fn native_equals_script_on_garbage(
        pick in 0usize..3,
        junk in proptest::collection::vec(any::<u8>(), 20),
        coords in proptest::collection::vec(-3i64..20, 4),
    ) {
        let (k, l) = [(2u32, 16u32), (3, 8), (4, 8)][pick];
        let s = acw(k, l);
        let (sk, com) = one_digit_key(s, 7);
        let c = CodewordSpace::new(k, l).unrank(5).unwrap();
        let mut o = sk.open_codeword(0, &c);
        o.openers[0] = junk;
        for j in 0..k as usize - 1 { o.posted[j] = coords[j]; }
        both(&com, &Opening { digits: vec![o] });
    }
}

// ------------------------------------------------------------ 3. unauthorized codewords

/// A *garbler* with every secret tries every coordinate tuple around the valid box,
/// including out-of-range values and wrong sums. The accepted set must be exactly the
/// antichain: `0 <= a_j < L` for all j and `sum = R`.
fn accept_set_is_exactly_the_antichain(k: u32, l: u32) {
    let s = acw(k, l);
    let sp = CodewordSpace::new(k, l);
    let (sk, com) = one_digit_key(s, 3);
    let kk = k as usize;
    let lo = -1i64;
    let hi = i64::from(l);
    let mut idx = vec![lo; kk - 1];
    let mut accepted = 0usize;
    loop {
        for mk in 0..=i64::from(l) + 1 {
            // honest-relative openers for the posted coordinates (index L - a), arbitrary last opener
            let mut openers = vec![];
            for j in 0..kk - 1 {
                openers.push(sk.chain_element(0, j, (i64::from(l) - idx[j]) as u32));
            }
            openers.push(sk.chain_element(0, kk - 1, mk as u32));
            let o = DigitOpening { openers, posted: idx.clone() };
            let sum: i64 = idx.iter().sum();
            let last = i64::from(sp.r()) - sum;
            let in_range = idx.iter().all(|&a| (0..i64::from(l)).contains(&a)) && (0..i64::from(l)).contains(&last);
            let predicted = in_range && mk == i64::from(l) - last;
            let got = both(&com, &Opening { digits: vec![o] });
            assert_eq!(got, predicted, "k={k} L={l} posted={idx:?} last_opener_index={mk}");
            if got {
                accepted += 1;
            }
        }
        // odometer
        let mut j = 0;
        loop {
            if j == kk - 1 {
                assert_eq!(accepted as u128, sp.count(), "accepted openings != |antichain|");
                return;
            }
            idx[j] += 1;
            if idx[j] <= hi {
                break;
            }
            idx[j] = lo;
            j += 1;
        }
    }
}

#[test]
fn acw_accept_set_equals_antichain_k2() {
    accept_set_is_exactly_the_antichain(2, 4);
    accept_set_is_exactly_the_antichain(2, 8);
}

#[test]
fn acw_accept_set_equals_antichain_k3() {
    accept_set_is_exactly_the_antichain(3, 4);
    accept_set_is_exactly_the_antichain(3, 8);
}

#[test]
fn acw_accept_set_equals_antichain_k4() {
    accept_set_is_exactly_the_antichain(4, 4);
}

#[test]
fn unauthorized_value_between_layers_is_rejected() {
    // Same chains, but the garbler opens a codeword one layer above and one below R.
    let s = acw(3, 8);
    let sp = CodewordSpace::new(3, 8);
    let (sk, com) = one_digit_key(s, 4);
    for delta in [-2i64, -1, 1, 2] {
        let mut c: Vec<i64> = sp.unrank(7).unwrap().into_iter().map(i64::from).collect();
        c[2] += delta; // sum becomes R + delta
        if c[2] < 0 || c[2] > 7 {
            continue;
        }
        let openers = (0..3).map(|j| sk.chain_element(0, j, (8 - c[j]) as u32)).collect();
        let o = DigitOpening { openers, posted: c[..2].to_vec() };
        assert!(!both(&com, &Opening { digits: vec![o] }), "layer R{delta:+} codeword accepted");
    }
}

// ------------------------------------------------------------ 4. malformed commitments / witnesses

#[test]
fn validate_flags_every_planted_defect() {
    let s = acw(4, 8);
    let sk = SecretKey::new(s, [5u8; 32], 6);
    let good = sk.commit();
    assert_eq!(good.validate(), Ok(()));

    let mut c = good.clone();
    c.pks[2][1] = c.pks[2][0].clone();
    assert_eq!(c.validate(), Err(CommitmentDefect::DuplicateInDigit { digit: 2 }));

    let mut c = good.clone();
    c.pks[4][3] = c.pks[1][3].clone();
    assert_eq!(c.validate(), Err(CommitmentDefect::DuplicateAcrossDigits { first: 1, second: 4 }));

    let mut c = good.clone();
    c.pks[0][0].pop();
    assert_eq!(c.validate(), Err(CommitmentDefect::DigestLen));

    let mut c = good.clone();
    c.pks[3].pop();
    assert_eq!(c.validate(), Err(CommitmentDefect::Shape));

    let l = SecretKey::new(Scheme::Lamport { hash: HashKind::Ripemd160 }, [5u8; 32], 4).commit();
    let mut c = l.clone();
    c.pks[1][1] = c.pks[1][0].clone();
    assert_eq!(c.validate(), Err(CommitmentDefect::DuplicateInDigit { digit: 1 }));
}

#[test]
fn identical_lamport_terminals_let_one_preimage_open_both_bits() {
    // Why validate() exists: a garbler that commits p0 == p1 equivocates at will.
    let s = Scheme::Lamport { hash: HashKind::Ripemd160 };
    let (sk, mut com) = one_digit_key(s, 6);
    com.pks[0][1] = com.pks[0][0].clone();
    let pre = sk.open_digit(0, 0).openers[0].clone();
    for bit in [0i64, 1] {
        let o = Opening { digits: vec![DigitOpening { openers: vec![pre.clone()], posted: vec![bit] }] };
        assert!(both(&com, &o), "bit {bit} should (wrongly) open under the defective commitment");
    }
    assert!(com.validate().is_err());
}

#[test]
fn duplicate_acw_chains_let_the_garbler_open_two_codewords() {
    // pk_0 == pk_1 (same secret on two chains): swapping coordinates opens a different codeword.
    let s = acw(3, 8);
    let sk = SecretKey::new(s, [8u8; 32], 1);
    let mut com = sk.commit();
    com.pks[0][1] = com.pks[0][0].clone();
    let sp = CodewordSpace::new(3, 8);
    let c = vec![2u32, 3, 5];
    let c_swapped = vec![3u32, 2, 5];
    assert!(sp.is_codeword(&c) && sp.is_codeword(&c_swapped));
    let elem = |j: usize, a: u32| if j == 1 { sk.chain_element(0, 0, 8 - a) } else { sk.chain_element(0, j, 8 - a) };
    let mk = |c: &[u32]| DigitOpening {
        openers: (0..3).map(|j| elem(j, c[j])).collect(),
        posted: c[..2].iter().map(|&a| i64::from(a)).collect(),
    };
    let (a, b) = (mk(&c), mk(&c_swapped));
    assert!(both(&com, &Opening { digits: vec![a.clone()] }));
    assert!(both(&com, &Opening { digits: vec![b.clone()] }));
    assert_ne!(com.verify_digit(0, &a).unwrap().value, com.verify_digit(0, &b).unwrap().value);
    assert!(com.validate().is_err(), "the defect is detectable from public data");
}

#[test]
fn malformed_witness_stacks_are_rejected() {
    let s = acw(4, 8);
    let sk = SecretKey::for_bits(s, [9u8; 32], 24);
    let com = sk.commit();
    let o = sk.open_bits(&[true; 24]);
    let script = com.verify_script();
    let stack = o.witness_stack(&s);
    assert!(accepts(&script, &stack, Mode::Policy));

    // missing item, extra item, empty stack
    let mut t = stack.clone();
    t.remove(3);
    assert!(!accepts(&script, &t, Mode::Consensus));
    let mut t = stack.clone();
    t.insert(0, vec![1]);
    assert!(!accepts(&script, &t, Mode::Consensus), "leftover stack item must fail (clean stack)");
    assert!(!accepts(&script, &[], Mode::Consensus));

    // wrong opener lengths: 19, 21, 33, 0
    for len in [19usize, 21, 33, 0] {
        let mut t = stack.clone();
        let top = t.len() - 2;
        t[top] = vec![0x11; len];
        assert!(!accepts(&script, &t, Mode::Consensus), "opener of length {len}");
    }

    // swapped adjacent witness items
    let mut t = stack.clone();
    let n = t.len();
    t.swap(n - 1, n - 2);
    assert!(!accepts(&script, &t, Mode::Consensus));
}

#[test]
fn non_minimal_numbers_are_consensus_valid_but_not_standard() {
    // A coordinate pushed as 0x03 0x00 instead of 0x03. Consensus parses it as 3; policy
    // (MINIMALDATA) rejects it. Documented so no one relies on the witness being unique.
    let s = acw(3, 8);
    let (sk, com) = one_digit_key(s, 10);
    let c = vec![3u32, 3, 4];
    let o = Opening { digits: vec![sk.open_codeword(0, &c)] };
    let mut st = o.witness_stack(&s);
    assert!(accepts(&com.verify_script(), &st, Mode::Policy));
    let top = st.len() - 1;
    assert_eq!(st[top], scriptnum(3));
    st[top] = vec![3, 0];
    assert!(accepts(&com.verify_script(), &st, Mode::Consensus));
    assert!(!accepts(&com.verify_script(), &st, Mode::Policy));
    // And the decoded value is unchanged: malleability cannot change which label unlocks.
}

#[test]
fn audit_detects_a_corrupted_terminal_that_validate_cannot() {
    // A terminal that is not H^L(s) for the garbler's secret is invisible to public checks;
    // the secret-holder audit (cut-and-choose on an opened instance) finds it.
    let s = acw(3, 8);
    let sk = SecretKey::new(s, [11u8; 32], 5);
    let good = sk.commit();
    let mut bad = good.clone();
    bad.pks[3][1][0] ^= 1;
    assert_eq!(bad.validate(), Ok(()));
    assert_ne!(bad, sk.commit());
    assert_eq!(good, sk.commit());
}

// ------------------------------------------------------------ 5. replay and equivocation

#[test]
fn cross_instance_and_cross_position_replay_are_rejected() {
    let s = acw(4, 8);
    let a = SecretKey::for_bits(s, [1u8; 32], 40);
    let b = SecretKey::for_bits(s, [2u8; 32], 40);
    let (ca, cb) = (a.commit(), b.commit());
    let bits: Vec<bool> = (0..40).map(|i| i % 3 == 0).collect();
    let oa = a.open_bits(&bits);
    assert!(both(&ca, &oa));
    assert!(!both(&cb, &oa), "opening of instance A must not satisfy instance B");

    // Swap two digits inside one opening.
    let mut sw = oa.clone();
    sw.digits.swap(0, 3);
    assert!(!both(&ca, &sw), "digit-position replay");
}

#[test]
fn key_reuse_equivocation_leaks_additional_labels() {
    // If the same keys are used in two spends (the garbler signs two valid openings), the
    // evaluator can decrypt every codeword below the coordinatewise maximum. This is why
    // keys are strictly one-time and why each spend must be a separate, single-use UTXO.
    let s = acw(2, 8);
    let sp = CodewordSpace::new(2, 8);
    let (sk, com) = one_digit_key(s, 12);
    let payload = |v: u64| -> Vec<u8> { vec![v as u8 ^ 0x5a; 16] };
    let table = gadget::build_digit_table(&sk, 0, b"t", &payload);

    let (c1, c2) = (vec![2u32, 5], vec![5u32, 2]);
    let (o1, o2) = (sk.open_codeword(0, &c1), sk.open_codeword(0, &c2));
    assert!(com.verify_digit(0, &o1).is_ok() && com.verify_digit(0, &o2).is_ok());

    let reach = gadget::reachable_codewords(&sp, &[c1.clone(), c2.clone()]);
    assert!(reach.len() > 2, "two openings reach {} codewords", reach.len());

    // Actually decrypt each reachable row from forward-hashed openers.
    let mut recovered = 0;
    for c in &reach {
        let openers: Vec<Vec<u8>> = (0..2)
            .map(|j| {
                // choose the opening that dominates on chain j, hash forward the difference
                let (src, a) = if c1[j] >= c2[j] { (&o1, c1[j]) } else { (&o2, c2[j]) };
                H.iterate(&src.openers[j], a - c[j])
            })
            .collect();
        let d = DigitOpening { openers, posted: vec![i64::from(c[0])] };
        let (v, p) = gadget::recover_payload(&com, 0, &d, &table, b"t").expect("derivable opening verifies");
        assert_eq!(p, payload(v));
        recovered += 1;
    }
    assert_eq!(recovered, reach.len());
    println!("key reuse: 2 openings unlock {recovered} of {} rows", sp.count());
}

#[test]
fn single_opening_unlocks_exactly_one_row() {
    // Positive control for the test above: with one opening, every other row stays closed.
    for (k, l) in [(2u32, 8u32), (3, 8)] {
        let s = acw(k, l);
        let sp = CodewordSpace::new(k, l);
        let (sk, com) = one_digit_key(s, 13);
        let payload = |v: u64| -> Vec<u8> { (0..16).map(|i| (v as u8).wrapping_mul(31).wrapping_add(i)).collect() };
        let table = gadget::build_digit_table(&sk, 0, b"t", &payload);
        for c in sp.enumerate() {
            let honest = sk.open_codeword(0, &c);
            let reach = gadget::reachable_codewords(&sp, &[c.clone()]);
            assert_eq!(reach, vec![c.clone()], "an antichain: one opening reaches only itself");
            // Best-effort decryption of every other row with the strongest available openers.
            for c2 in sp.enumerate() {
                if c2 == c {
                    continue;
                }
                let seed: Vec<u8> = (0..k as usize)
                    .flat_map(|j| {
                        if c2[j] <= c[j] { H.iterate(&honest.openers[j], c[j] - c2[j]) } else { honest.openers[j].clone() }
                    })
                    .collect();
                let rank = sp.rank(&c2).unwrap() as usize;
                let p = pqcd::hash::pad(&seed, &[b't'].iter().chain(0u64.to_le_bytes().iter()).copied().collect::<Vec<u8>>(), 16);
                let guess: Vec<u8> = table.rows[rank].iter().zip(&p).map(|(a, b)| a ^ b).collect();
                let v = (rank & ((1usize << sp.bits()) - 1)) as u64;
                assert_ne!(guess, payload(v), "row {rank} opened from the opening of {c:?}");
            }
            let (v, p) = gadget::recover_payload(&com, 0, &honest, &table, b"t").unwrap();
            assert_eq!(p, payload(v));
        }
    }
}

// ------------------------------------------------------------ 6. label permutation

#[test]
fn table_row_permutation_is_caught_by_audit_and_value_commitments() {
    let s = acw(3, 8);
    let sp = CodewordSpace::new(3, 8);
    let (sk, com) = one_digit_key(s, 14);
    let payload = |v: u64| -> Vec<u8> { (0..16).map(|i| (v as u8).wrapping_mul(17) ^ i).collect() };
    let vc = gadget::value_commitments(b"t", 0, sp.bits(), &payload);
    let table = gadget::build_digit_table(&sk, 0, b"t", &payload);
    assert_eq!(gadget::audit_digit_table(&sk, 0, b"t", &table, &payload), Ok(()));

    // The garbler swaps the payloads of ranks 3 and 9: each opening now yields the other's label.
    let mut bad = table.clone();
    let (r1, r2) = (3usize, 9usize);
    let c1 = sp.unrank(r1 as u128).unwrap();
    let c2 = sp.unrank(r2 as u128).unwrap();
    let pad_of = |c: &Vec<u32>| pqcd::hash::pad(&gadget::seed_of(&sk, 0, c), &{
        let mut x = b"t".to_vec();
        x.extend_from_slice(&0u64.to_le_bytes());
        x
    }, 16);
    let (p1, p2) = (payload(sp.decode_value(&c1).unwrap()), payload(sp.decode_value(&c2).unwrap()));
    bad.rows[r1] = pad_of(&c1).iter().zip(&p2).map(|(a, b)| a ^ b).collect();
    bad.rows[r2] = pad_of(&c2).iter().zip(&p1).map(|(a, b)| a ^ b).collect();

    // 1. Secret-holder audit (challenged instance) pinpoints the first bad row.
    assert_eq!(gadget::audit_digit_table(&sk, 0, b"t", &bad, &payload), Err(r1));

    // 2. Without the secrets the evaluator still catches it at use time via the value commitment.
    let o = sk.open_codeword(0, &c1);
    let (v, got) = gadget::recover_payload(&com, 0, &o, &bad, b"t").unwrap();
    assert!(!gadget::check_value(b"t", 0, v, &got, &vc[v as usize]), "mislabelled payload passed the value commitment");
    let (v, got) = gadget::recover_payload(&com, 0, &o, &table, b"t").unwrap();
    assert!(gadget::check_value(b"t", 0, v, &got, &vc[v as usize]));
}

#[test]
fn table_covers_every_admissible_opening() {
    // "Guaranteed revelation": every opening the script accepts maps to a payload.
    let s = acw(4, 8); // 344 codewords, 256 values: 88 codewords alias onto a lower value
    let sp = CodewordSpace::new(4, 8);
    let (sk, com) = one_digit_key(s, 15);
    let payload = |v: u64| -> Vec<u8> { v.to_le_bytes().to_vec() };
    let table = gadget::build_digit_table(&sk, 0, b"t", &payload);
    assert_eq!(table.rows.len(), 344);
    for c in sp.enumerate() {
        let o = sk.open_codeword(0, &c);
        let (v, p) = gadget::recover_payload(&com, 0, &o, &table, b"t").expect("accepted opening");
        assert_eq!(p, payload(v));
        assert_eq!(v, sp.decode_value(&c).unwrap());
    }
}
