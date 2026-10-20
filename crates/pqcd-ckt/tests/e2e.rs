//! End-to-end: ACW-authenticated input labels driving a ckt-gobble garbled circuit.

use ckt_gobble::{translate_output, Label};
use pqcd::exec::{accepts, Mode};
use pqcd::gadget;
use pqcd::scheme::{DigitOpening, Opening};
use pqcd::HashKind;
use pqcd_ckt::*;

const SEED: [u8; 32] = *b"pqcd-ckt reproducible seed v0001";
const TARGET: u16 = 0xA55A;

fn script_accepts(p: &Public, o: &Opening) -> bool {
    accepts(&p.script, &o.witness_stack(&BYTE_SCHEME), Mode::Policy)
}

#[test]
fn circuit_is_tiny_and_matches_the_oracle_in_the_clear() {
    let (x, a) = gate_counts();
    assert_eq!((x, a), (16, 15), "16 XOR (free) + 15 AND (one ciphertext each)");
    assert!(valid(TARGET, TARGET) && !valid(TARGET, TARGET ^ 1));
}

#[test]
fn every_16_bit_claim_evaluates_correctly_from_authenticated_labels() {
    let (sec, p) = setup(SEED, TARGET);
    for x in 0..=u16::MAX {
        let (opening, res) = reveal_and_evaluate(&sec, &p, x);
        let ev = res.expect("honest opening recovers labels");
        assert_eq!(ev.output_value, valid(TARGET, x), "x={x:#06x}");
        if valid(TARGET, x) {
            assert_eq!(ev.output_label, sec.out_labels[1], "true output label");
            assert!(ev.secret.is_none());
        } else {
            assert_eq!(ev.output_label, sec.out_labels[0], "false output label");
            assert_eq!(ev.secret, Some(sec.fault_secret), "fault secret recovered for x={x:#06x}");
        }
        if x % 997 == 0 {
            assert!(script_accepts(&p, &opening), "script rejects an honest opening, x={x:#06x}");
        }
    }
}

#[test]
fn labels_exist_only_for_openings_the_script_accepts() {
    let (sec, p) = setup(SEED, TARGET);
    let (honest, _) = reveal_and_evaluate(&sec, &p, 0x1234);
    assert!(script_accepts(&p, &honest));

    // Evaluator forges byte 0 from the honest opener: value 0x34 -> any other codeword by forward hashing.
    let sp = BYTE_SCHEME.space().unwrap();
    let c = p.commitment.verify_digit(0, &honest.digits[0]).unwrap().codeword;
    let mut tried = 0;
    for r in 0..sp.count() {
        let c2 = sp.unrank(r).unwrap();
        if c2 == c {
            continue;
        }
        let openers = (0..4)
            .map(|j| if c2[j] <= c[j] { HashKind::Hash160.iterate(&honest.digits[0].openers[j], c[j] - c2[j]) } else { honest.digits[0].openers[j].clone() })
            .collect();
        let mut forged = honest.clone();
        forged.digits[0] = DigitOpening { openers, posted: c2[..3].iter().map(|&a| i64::from(a)).collect() };
        assert!(!script_accepts(&p, &forged), "script accepted a forged byte");
        assert!(labels_from_opening(&p, &forged).is_err(), "labels derived from a forged byte");
        tried += 1;
    }
    assert_eq!(tried as u128, sp.count() - 1);
}

#[test]
fn evaluator_cannot_decrypt_the_secret_after_a_valid_claim() {
    let (sec, p) = setup(SEED, TARGET);
    let (_, res) = reveal_and_evaluate(&sec, &p, TARGET);
    let ev = res.unwrap();
    assert!(ev.output_value && ev.secret.is_none());
    // Attack: pretend the (true) output label is a false output and decrypt anyway.
    let forced = translate_output(&[Label::from(ev.output_label)], &[false], &p.output_translation).unwrap()[0];
    assert_ne!(forced, Some(sec.fault_secret), "true-output label must not decrypt the secret");
    assert_ne!(tagged_commit(&forced.unwrap()), p.secret_commitment);
}

fn tagged_commit(s: &[u8; 32]) -> [u8; 32] {
    pqcd::hash::tagged("pqcd-ckt/secret", &[s])
}

#[test]
fn swapping_labels_between_input_wires_breaks_evaluation() {
    let (sec, p) = setup(SEED, TARGET);
    // A claim that is invalid, so an honest run recovers the secret.
    let x = TARGET ^ 0x0101;
    let (opening, res) = reveal_and_evaluate(&sec, &p, x);
    assert_eq!(res.unwrap().secret, Some(sec.fault_secret));
    let (labels, values, _) = labels_from_opening(&p, &opening).unwrap();

    // Permute: exchange the label blocks of byte 0 and byte 1 (values left in place).
    let mut swapped = labels.clone();
    for i in 0..8 {
        swapped.swap(i, 8 + i);
    }
    let ev = evaluate(&p, &swapped, &values);
    assert!(ev.output_label != sec.out_labels[0] && ev.output_label != sec.out_labels[1], "garbage output label expected");
    assert_eq!(ev.secret, None);

    // Permute two wires inside one byte.
    let mut swapped = labels.clone();
    swapped.swap(0, 1);
    let ev = evaluate(&p, &swapped, &values);
    assert_eq!(ev.secret, None);

    // Control: untouched labels still work.
    assert_eq!(evaluate(&p, &labels, &values).secret, Some(sec.fault_secret));
}

#[test]
fn lying_about_input_values_breaks_authenticity() {
    // Privacy-free evaluation takes the input *values* from the evaluator. Using the label
    // of one value while claiming another must not produce an authentic output label.
    let (sec, p) = setup(SEED, TARGET);
    let (opening, _) = reveal_and_evaluate(&sec, &p, TARGET); // valid claim: output true, no secret
    let (labels, mut values, _) = labels_from_opening(&p, &opening).unwrap();
    values[3] = !values[3]; // claim a different bit than the label carries
    let ev = evaluate(&p, &labels, &values);
    assert!(ev.output_label != sec.out_labels[0], "must not reach the false output label");
    assert_eq!(ev.secret, None);
}

#[test]
fn tampered_table_row_is_caught_by_the_value_commitment() {
    let (sec, mut p) = setup(SEED, TARGET);
    let (opening, _) = reveal_and_evaluate(&sec, &p, 0x00FF); // byte 0 = 0xFF, byte 1 = 0x00
    let sp = BYTE_SCHEME.space().unwrap();
    let c = p.commitment.verify_digit(1, &opening.digits[1]).unwrap().codeword;
    let rank = sp.rank(&c).unwrap() as usize;
    p.tables[1].rows[rank][0] ^= 1; // a garbler (or relay) corrupts the row the opening will use
    assert_eq!(labels_from_opening(&p, &opening), Err(RecoverError::LabelCommitment { byte: 1 }));
    let _ = gadget::merkle_root; // the Merkle root over rows would also change; see pqcd::gadget
}
