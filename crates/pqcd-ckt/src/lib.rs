//! Authenticated garbled-input evaluation: pqcd openings feeding the `ckt-gobble` engine.
//!
//! The flow mirrors a conditional-disclosure bridge in miniature:
//!
//! 1. The garbler garbles a tiny verifier circuit `valid(x) = [x == TARGET]` (16 input
//!    wires = two bytes) and embeds a **fault secret** that is recoverable only if the
//!    circuit outputs `false` (ckt's output translation).
//! 2. For each input byte it publishes an Antichain Winternitz commitment (the Tapscript
//!    leaf) and a label table whose payload is the byte's **wide label** (a 128-bit label
//!    per value), exactly the object ckt's input translation consumes.
//! 3. To make a claim the garbler reveals the two bytes. The Script accepts only an
//!    admissible codeword per byte; the evaluator turns the revealed openers into the wide
//!    labels, translates them to bit labels, evaluates, and, if the output is `false`,
//!    recovers the secret.
//!
//! Everything is derived from a seed, so the golden vectors are reproducible.

use bitvec::vec::BitVec;
use ckt_gobble::traits::{
    EvaluationInstance as _, EvaluationInstanceConfig, GarblingInstance as _, GarblingInstanceConfig, GobbleEngine as _,
};
use ckt_gobble::{
    generate_input_translation_material, generate_output_translation_material, translate_input, translate_output, BitLabel,
    ByteLabel, Ciphertext, Engine, InputTranslationMaterial, Label,
};
use pqcd::gadget::{self, DigitTable};
use pqcd::hash::tagged;
use pqcd::scheme::{Commitment, Opening, Scheme, SecretKey};
use pqcd::HashKind;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// ACW parameters used for each input byte: 4 chains of length 8 carry exactly 8 bits
/// (344 codewords for 256 values), matching the 8-bit wide label of ckt and Mosaic.
pub const BYTE_SCHEME: Scheme = Scheme::Acw { k: 4, l: 8, hash: HashKind::Hash160 };

/// Number of input bytes of the tiny circuit.
pub const N_BYTES: usize = 2;
/// Number of input wires.
pub const N_IN: usize = N_BYTES * 8;
const SCRATCH: u32 = 64;
const OUT_WIRE: usize = 2 + N_IN + N_IN + (N_IN - 1) - 1;

#[derive(Clone, Copy, Debug)]
enum Gate {
    Xor(usize, usize, usize),
    And(usize, usize, usize),
}

fn gates(target: u16) -> Vec<Gate> {
    let mut g = vec![];
    // eq_i = x_i XNOR target_i, i.e. x_i XOR (target_i ? 0 : 1); wire 0 = false, wire 1 = true.
    for i in 0..N_IN {
        let c = if (target >> i) & 1 == 1 { 0 } else { 1 };
        g.push(Gate::Xor(2 + i, c, 2 + N_IN + i));
    }
    let mut acc = 2 + N_IN; // eq_0
    for i in 1..N_IN {
        let out = 2 + N_IN + N_IN + (i - 1);
        g.push(Gate::And(acc, 2 + N_IN + i, out));
        acc = out;
    }
    debug_assert_eq!(acc, OUT_WIRE);
    g
}

/// Gate count `(xor, and)` of the tiny circuit.
pub fn gate_counts() -> (usize, usize) {
    let g = gates(0);
    (g.iter().filter(|x| matches!(x, Gate::Xor(..))).count(), g.iter().filter(|x| matches!(x, Gate::And(..))).count())
}

/// Cleartext oracle: the claim is valid iff the input equals the target.
pub fn valid(target: u16, x: u16) -> bool {
    x == target
}

fn rnd16(rng: &mut ChaCha20Rng) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Everything the garbler keeps secret.
#[derive(Clone)]
pub struct GarblerSecrets {
    /// Chain-secret key for the per-byte ACW commitments.
    pub sk: SecretKey,
    /// Free-XOR offset.
    pub delta: [u8; 16],
    /// False labels of the 16 input wires.
    pub in_false: Vec<[u8; 16]>,
    /// Wide labels, one per value, for each input byte.
    pub byte_labels: Vec<Vec<[u8; 16]>>,
    /// Output labels (false, true).
    pub out_labels: [[u8; 16]; 2],
    /// The conditional-disclosure secret.
    pub fault_secret: [u8; 32],
}

/// Everything published (and what an evaluator needs).
#[derive(Clone)]
pub struct Public {
    /// Which circuit.
    pub target: u16,
    /// ACW commitment (one digit per input byte).
    pub commitment: Commitment,
    /// Label table per byte (rows hold `pad XOR wide_label`).
    pub tables: Vec<DigitTable>,
    /// Per-value commitments to the wide labels, per byte.
    pub value_commitments: Vec<Vec<[u8; 32]>>,
    /// Identifier bound into every table pad.
    pub table_id: Vec<u8>,
    /// ckt input translation material, per byte.
    pub input_translation: Vec<InputTranslationMaterial>,
    /// AND-gate ciphertexts.
    pub ciphertexts: Vec<[u8; 16]>,
    /// Output translation: `H(L_out,0) XOR secret`.
    pub output_translation: Vec<[u8; 32]>,
    /// Commitment to the fault secret.
    pub secret_commitment: [u8; 32],
    /// AES key of the garbling instance.
    pub aes_key: [u8; 16],
    /// Public `S` of the CCRND hash.
    pub public_s: [u8; 16],
    /// Constant wire label (false).
    pub const_zero: [u8; 16],
    /// Constant wire label (true).
    pub const_one: [u8; 16],
    /// The Tapscript leaf (verifier of both bytes).
    pub script: bitcoin::ScriptBuf,
}

/// Garble the circuit and build all public material from a seed.
pub fn setup(seed: [u8; 32], target: u16) -> (GarblerSecrets, Public) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let delta = rnd16(&mut rng);
    let in_false: Vec<[u8; 16]> = (0..N_IN).map(|_| rnd16(&mut rng)).collect();
    let aes_key = rnd16(&mut rng);
    let public_s = rnd16(&mut rng);
    let const_zero = rnd16(&mut rng);
    let const_one = rnd16(&mut rng);
    let mut fault_secret = [0u8; 32];
    rng.fill_bytes(&mut fault_secret);
    let mut master = [0u8; 32];
    rng.fill_bytes(&mut master);

    // Garble.
    let engine = Engine::new();
    let cfg = GarblingInstanceConfig {
        scratch_space: SCRATCH,
        delta,
        primary_input_false_labels: &in_false,
        aes128_key: aes_key,
        public_s,
        constant_zero_label: const_zero,
        constant_one_label: const_one,
    };
    let mut g = engine.new_garbling_instance(cfg);
    let mut ciphertexts = vec![];
    for gate in gates(target) {
        match gate {
            Gate::Xor(a, b, o) => g.feed_xor_gate(a, b, o),
            Gate::And(a, b, o) => ciphertexts.push(g.feed_and_gate(a, b, o).into()),
        }
    }
    let mut out_f = [[0u8; 16]];
    let mut out_t = [[0u8; 16]];
    let mut v0 = BitVec::new();
    v0.push(false);
    let mut v1 = BitVec::new();
    v1.push(true);
    g.get_selected_labels(&[OUT_WIRE as u64], &v0, &mut out_f);
    g.get_selected_labels(&[OUT_WIRE as u64], &v1, &mut out_t);
    let out_labels = [out_f[0], out_t[0]];
    debug_assert_eq!(xor16(out_labels[0], out_labels[1]), delta);

    // Wide labels and input translation per byte.
    let mut byte_labels = vec![];
    let mut input_translation = vec![];
    for p in 0..N_BYTES {
        let labels: Vec<[u8; 16]> = (0..256).map(|_| rnd16(&mut rng)).collect();
        let bl: Vec<Label> = labels.iter().map(|&l| Label::from(l)).collect();
        let byte_label = ByteLabel::new(bl.try_into().map_err(|_| ()).expect("256 labels"));
        let bits: [BitLabel; 8] = std::array::from_fn(|i| {
            let f = in_false[p * 8 + i];
            BitLabel::new([Label::from(f), Label::from(xor16(f, delta))])
        });
        input_translation.push(generate_input_translation_material(p as u64, byte_label, bits));
        byte_labels.push(labels);
    }

    // Output translation of the fault secret.
    let ob = [BitLabel::new([Label::from(out_labels[0]), Label::from(out_labels[1])])];
    let output_translation = generate_output_translation_material(&ob, &[fault_secret]).expect("one output");
    let secret_commitment = tagged("pqcd-ckt/secret", &[&fault_secret]);

    // ACW commitment and label tables: payload = the wide label of the digit value.
    let sk = SecretKey::new(BYTE_SCHEME, master, N_BYTES);
    let commitment = sk.commit();
    let table_id = b"pqcd-ckt/tiny".to_vec();
    let mut tables = vec![];
    let mut value_commitments = vec![];
    for p in 0..N_BYTES {
        let payload = |v: u64| byte_labels[p][v as usize].to_vec();
        tables.push(gadget::build_digit_table(&sk, p, &table_id, &payload));
        value_commitments.push(gadget::value_commitments(&table_id, p, BYTE_SCHEME.bits_per_digit(), &payload));
    }
    let script = commitment.verify_script();
    (
        GarblerSecrets { sk, delta, in_false, byte_labels, out_labels, fault_secret },
        Public {
            target, commitment, tables, value_commitments, table_id, input_translation, ciphertexts, output_translation,
            secret_commitment, aes_key, public_s, const_zero, const_one, script,
        },
    )
}

/// Outcome of an evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// Output label obtained.
    pub output_label: [u8; 16],
    /// Output value computed by the privacy-free evaluator.
    pub output_value: bool,
    /// Recovered secret, if the output was `false` and the decryption verifies.
    pub secret: Option<[u8; 32]>,
    /// Raw decryption result when the output was `false`, even if it does not verify.
    pub raw_decryption: Option<[u8; 32]>,
}

/// Why authenticated label recovery failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoverError {
    /// The opening did not verify.
    Opening(pqcd::VerifyError),
    /// A recovered wide label does not match its published commitment.
    LabelCommitment {
        /// Byte position.
        byte: usize,
    },
}

/// Evaluator: from an ACW opening of the two bytes, recover the bit labels and values.
pub fn labels_from_opening(p: &Public, opening: &Opening) -> Result<(Vec<[u8; 16]>, Vec<bool>, u16), RecoverError> {
    let mut labels = Vec::with_capacity(N_IN);
    let mut values = Vec::with_capacity(N_IN);
    let mut x: u16 = 0;
    for b in 0..N_BYTES {
        let (v, payload) = gadget::recover_payload(&p.commitment, b, &opening.digits[b], &p.tables[b], &p.table_id)
            .map_err(RecoverError::Opening)?;
        if !gadget::check_value(&p.table_id, b, v, &payload, &p.value_commitments[b][v as usize]) {
            return Err(RecoverError::LabelCommitment { byte: b });
        }
        let wide: [u8; 16] = payload.try_into().expect("16-byte wide label");
        let bit_labels = translate_input(b as u64, Label::from(wide), v as u8, p.input_translation[b]);
        for i in 0..8 {
            labels.push(bit_labels[i].into());
            values.push((v >> i) & 1 == 1);
        }
        x |= (v as u16) << (8 * b);
    }
    Ok((labels, values, x))
}

/// Evaluate the garbled circuit on given input labels/values and try to decrypt the secret.
pub fn evaluate(p: &Public, labels: &[[u8; 16]], values: &[bool]) -> Evaluation {
    let engine = Engine::new();
    let mut bv = BitVec::new();
    for &v in values {
        bv.push(v);
    }
    let cfg = EvaluationInstanceConfig {
        scratch_space: SCRATCH,
        selected_primary_input_labels: labels,
        selected_primary_input_values: &bv,
        aes128_key: p.aes_key,
        public_s: p.public_s,
        constant_zero_label: p.const_zero,
        constant_one_label: p.const_one,
    };
    let mut e = engine.new_evaluation_instance(cfg);
    let mut ct = 0usize;
    for gate in gates(p.target) {
        match gate {
            Gate::Xor(a, b, o) => e.feed_xor_gate(a, b, o),
            Gate::And(a, b, o) => {
                e.feed_and_gate(a, b, o, Ciphertext::from(p.ciphertexts[ct]));
                ct += 1;
            }
        }
    }
    let mut l = [[0u8; 16]];
    let mut v = [false];
    e.get_labels(&[OUT_WIRE as u64], &mut l);
    e.get_values(&[OUT_WIRE as u64], &mut v);
    let dec = translate_output(&[Label::from(l[0])], &v, &p.output_translation).expect("one output")[0];
    let secret = dec.filter(|s| tagged("pqcd-ckt/secret", &[s]) == p.secret_commitment);
    Evaluation { output_label: l[0], output_value: v[0], secret, raw_decryption: dec }
}

/// Honest end-to-end: reveal `x` through ACW, recover labels, evaluate.
pub fn reveal_and_evaluate(sec: &GarblerSecrets, p: &Public, x: u16) -> (Opening, Result<Evaluation, RecoverError>) {
    let bits: Vec<bool> = (0..N_IN).map(|i| (x >> i) & 1 == 1).collect();
    let opening = sec.sk.open_bits(&bits);
    let res = labels_from_opening(p, &opening).map(|(labels, values, _)| evaluate(p, &labels, &values));
    (opening, res)
}
