//! Writes Bitcoin Script fixtures to `fixtures/`.
//!
//! * `script_vectors.json`   small, human-readable vectors for every scheme (16-32 bits)
//! * `bridge_1024_<scheme>.json`   one full 1,024-bit input (Mosaic's 128 wires x 8 bits)
//!
//! Every positive and negative expectation is asserted against the interpreter before it is
//! written, and `tests/fixtures.rs` replays the stored hex from scratch.

use bitcoin::{Address, Network, ScriptBuf};
use pqcd::codeword::CodewordSpace;
use pqcd::exec::{accepts, Mode};
use pqcd::scheme::{scriptnum, DigitOpening, Scheme, SecretKey};
use pqcd::taproot::{control_block, spend_info, NUMS_X};
use pqcd::HashKind;
use serde_json::{json, Value};

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn stack_json(st: &[Vec<u8>]) -> Value {
    Value::Array(st.iter().map(|i| json!(hx(i))).collect())
}

fn message_bits(n: usize) -> Vec<bool> {
    (0..n).map(|i| (i.wrapping_mul(2654435761)) >> 7 & 1 == 1).collect()
}

fn vector(name: &str, scheme: Scheme, nbits: usize, seed_byte: u8, with_negatives: bool) -> Value {
    let master = [seed_byte; 32];
    let sk = SecretKey::for_bits(scheme, master, nbits);
    let com = sk.commit();
    let bits = message_bits(nbits);
    let opening = sk.open_bits(&bits);
    let script = com.verify_script();
    let stack = opening.witness_stack(&scheme);
    assert!(accepts(&script, &stack, Mode::Policy), "{name}: honest vector must be standard-valid");

    let info = spend_info(&script);
    let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
    let addr = Address::p2tr_tweaked(info.output_key(), Network::Regtest).to_string();
    let mut msg = vec![0u8; nbits.div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            msg[i / 8] |= 1 << (i % 8);
        }
    }
    let mut negatives = vec![];
    if with_negatives {
        let mut neg = |name: &str, st: Vec<Vec<u8>>, mode: Mode, expect: bool| {
            let got = accepts(&script, &st, mode);
            assert_eq!(got, expect, "{name}");
            negatives.push(json!({"name": name, "mode": format!("{mode:?}").to_lowercase(), "expect": if expect { "accept" } else { "reject" }, "witness_stack": stack_json(&st)}));
        };
        // 1. a different value in digit 1, forged from the honest opening by forward hashing
        let mut forged = opening.clone();
        match scheme {
            Scheme::Acw { k, l, .. } => {
                let sp = CodewordSpace::new(k, l);
                let c = com.verify_digit(1, &opening.digits[1]).unwrap().codeword;
                let c2 = sp.unrank((sp.rank(&c).unwrap() + 1) % sp.count()).unwrap();
                let openers = (0..k as usize)
                    .map(|j| if c2[j] <= c[j] { scheme.hash().iterate(&opening.digits[1].openers[j], c[j] - c2[j]) } else { opening.digits[1].openers[j].clone() })
                    .collect();
                forged.digits[1] = DigitOpening { openers, posted: c2[..k as usize - 1].iter().map(|&a| i64::from(a)).collect() };
            }
            Scheme::Lamport { .. } => forged.digits[1].posted[0] ^= 1,
            Scheme::LamportNoBit { .. } => forged.digits[1].openers[0] = scheme.hash().digest(&forged.digits[1].openers[0]),
        }
        neg("forged_other_value", forged.witness_stack(&scheme), Mode::Consensus, false);
        let mut st = stack.clone();
        st.remove(2);
        neg("missing_item", st, Mode::Consensus, false);
        let mut st = stack.clone();
        st.insert(0, vec![1]);
        neg("extra_item", st, Mode::Consensus, false);
        let mut st = stack.clone();
        let n = st.len();
        let idx = if matches!(scheme, Scheme::Acw { .. } | Scheme::Lamport { .. }) { n - 2 } else { n - 1 };
        st[idx].pop();
        neg("short_opener", st, Mode::Consensus, false);
        if let Scheme::Acw { .. } = scheme {
            let mut st = stack.clone();
            let top = st.len() - 1;
            let mut v = scriptnum(opening.digits[0].posted[0]);
            if v.is_empty() { v = vec![0x80] } else { v.push(0x00) }
            st[top] = v;
            neg("non_minimal_number__policy", st.clone(), Mode::Policy, false);
            neg("non_minimal_number__consensus", st, Mode::Consensus, true);
        }
    }
    json!({
        "name": name, "scheme": scheme.name(),
        "params": match scheme { Scheme::Acw { k, l, hash } => json!({"kind": "acw", "k": k, "l": l, "hash": hash.name()}),
                                 Scheme::Lamport { hash } => json!({"kind": "lamport", "hash": hash.name()}),
                                 Scheme::LamportNoBit { hash } => json!({"kind": "lamport_nobit", "hash": hash.name()}) },
        "nbits": nbits, "digits": com.n_digits(), "bits_per_digit": scheme.bits_per_digit(),
        "master_seed_hex": hx(&master), "message_lsb_first_hex": hx(&msg),
        "commitment_terminals": com.pks.iter().map(|d| d.iter().map(|t| hx(t)).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "leaf_script_hex": hx(script.as_bytes()),
        "leaf_script_asm": if script.len() <= 600 { Value::String(script.to_asm_string()) } else { Value::Null },
        "taproot": {
            "internal_key_nums_x": NUMS_X, "leaf_version": "0xc0",
            "control_block_hex": hx(&control_block(&script).serialize()),
            "output_key_x": hx(&info.output_key().to_x_only_public_key().serialize()),
            "script_pubkey_hex": hx(spk.as_bytes()), "regtest_address": addr,
        },
        "witness_stack_initial_bottom_to_top": stack_json(&stack),
        "expect": "accept",
        "sizes": { "leaf_script_bytes": script.len(), "stack_items": stack.len(), "witness_total_bytes": pqcd::taproot::LeafSpend { script: script.clone(), stack: stack.clone() }.witness_bytes() },
        "negatives": negatives,
    })
}

fn main() {
    std::fs::create_dir_all("fixtures").unwrap();
    let h20 = HashKind::Hash160;
    let small = vec![
        vector("lamport_ripemd160_16bit", Scheme::Lamport { hash: HashKind::Ripemd160 }, 16, 1, true),
        vector("lamport_nobit_ripemd160_16bit", Scheme::LamportNoBit { hash: HashKind::Ripemd160 }, 16, 2, true),
        vector("acw_k2_l16_hash160_16bit", Scheme::Acw { k: 2, l: 16, hash: h20 }, 16, 3, true),
        vector("acw_k4_l8_hash160_16bit", Scheme::Acw { k: 4, l: 8, hash: h20 }, 16, 4, true),
        vector("acw_k4_l16_hash160_22bit", Scheme::Acw { k: 4, l: 16, hash: h20 }, 22, 5, true),
        vector("acw_k4_l16_sha256_22bit", Scheme::Acw { k: 4, l: 16, hash: HashKind::Sha256 }, 22, 6, true),
    ];
    let doc = json!({
        "about": "Bitcoin Script fixtures for pqcd. Each vector gives the Tapscript leaf, its P2TR packaging (NUMS internal key, single leaf) and the initial witness stack (bottom to top). 'expect' is the verdict of the interpreter with OP_CAT disabled; mode 'policy' additionally enforces minimal encodings. Accepted vectors were also mined/relayed on Bitcoin Core 31.1 regtest, see results/regtest.json.",
        "vectors": small,
    });
    std::fs::write("fixtures/script_vectors.json", serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    println!("wrote fixtures/script_vectors.json");

    for (name, s, seed) in [
        ("lamport_ripemd160", Scheme::Lamport { hash: HashKind::Ripemd160 }, 11u8),
        ("acw_k4_l8_hash160", Scheme::Acw { k: 4, l: 8, hash: h20 }, 12),
        ("acw_k4_l16_hash160", Scheme::Acw { k: 4, l: 16, hash: h20 }, 13),
    ] {
        // 1,024 bits = Mosaic's 128 withdrawal wires x 8 bits. One leaf per input if it fits one stack.
        let per = (990 / s.witness_items_per_digit()) * s.bits_per_digit() as usize;
        let nbits = 1024usize.min(per);
        let v = vector(&format!("bridge_{name}_{nbits}bit_first_input"), s, nbits, seed, false);
        std::fs::write(format!("fixtures/bridge_{name}.json"), serde_json::to_string(&v).unwrap()).unwrap();
        println!("wrote fixtures/bridge_{name}.json ({nbits} bits in the first input)");
    }
}
