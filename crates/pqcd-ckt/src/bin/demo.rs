//! `demo vectors [path]`  writes reproducible golden vectors (no node needed).
//! `demo regtest`         runs the claims through Bitcoin Core regtest: the garbler spends the
//!                        committed leaf, the evaluator reads the openers from the *confirmed*
//!                        transaction, derives the labels, and evaluates the garbled circuit.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use pqcd::rpc::Rpc;
use pqcd::scheme::Opening;
use pqcd::taproot::{control_block, spend_info};
use pqcd_ckt::*;
use serde_json::{json, Value};

const SEED_A: [u8; 32] = *b"pqcd-ckt reproducible seed v0001";
const TARGET: u16 = 0xA55A;

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn scenario(seed: [u8; 32], x: u16) -> Value {
    let (sec, p) = setup(seed, TARGET);
    let (opening, res) = reveal_and_evaluate(&sec, &p, x);
    let ev = res.expect("honest");
    let (labels, values, _) = labels_from_opening(&p, &opening).unwrap();
    let st = opening.witness_stack(&BYTE_SCHEME);
    let ct_hash = pqcd::hash::tagged("vec/ct", &p.ciphertexts.iter().map(|c| c.as_slice()).collect::<Vec<_>>());
    json!({
        "claim_x": format!("{x:#06x}"), "claim_valid": valid(TARGET, x),
        "seed": hx(&seed), "target": format!("{TARGET:#06x}"),
        "acw_scheme": pqcd::Scheme::name(&BYTE_SCHEME),
        "commitment_terminals": p.commitment.pks.iter().map(|d| d.iter().map(|t| hx(t)).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "leaf_script": hx(p.script.as_bytes()),
        "witness_stack": st.iter().map(|i| hx(i)).collect::<Vec<_>>(),
        "table_roots": p.tables.iter().map(|t| hx(&t.root)).collect::<Vec<_>>(),
        "gc_ciphertexts_digest": hx(&ct_hash),
        "recovered_input_labels": labels.iter().map(|l| hx(l)).collect::<Vec<_>>(),
        "input_values": values.iter().map(|&b| b as u8).collect::<Vec<_>>(),
        "output_label": hx(&ev.output_label), "output_value": ev.output_value,
        "output_label_is": if ev.output_label == sec.out_labels[0] { "false-label" } else if ev.output_label == sec.out_labels[1] { "true-label" } else { "invalid" },
        "secret_recovered": ev.secret.is_some(),
        "secret_commitment": hx(&p.secret_commitment),
        "recovered_secret_digest": ev.secret.map(|s| hx(&pqcd::hash::tagged("vec/secret", &[&s]))),
    })
}

fn vectors(path: &str) {
    let mut seed_b = SEED_A;
    seed_b[31] = b'2';
    let doc = json!({
        "about": "Reproducible vectors: ACW-authenticated input labels evaluated by ckt-gobble. Regenerate with `demo vectors`.",
        "circuit": { "xor": gate_counts().0, "and": gate_counts().1, "inputs": N_IN, "outputs": 1, "semantics": "output = [x == target]; fault secret recoverable iff output = false" },
        "scenarios": [ scenario(SEED_A, TARGET), scenario(seed_b, TARGET ^ 0x0100) ],
    });
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    println!("wrote {path}");
}

fn regtest() {
    let rpc = Rpc::new(18643, "pqcd", "pqcd-regtest-only");
    let _ = rpc.call(None, "createwallet", json!(["pqcd"]));
    let _ = rpc.call(None, "loadwallet", json!(["pqcd"]));
    let w = Some("pqcd");
    if rpc.call(None, "getblockchaininfo", json!([])).unwrap()["blocks"].as_u64().unwrap() < 101 {
        let a = rpc.call(w, "getnewaddress", json!([])).unwrap();
        rpc.call(w, "generatetoaddress", json!([101, a])).unwrap();
    }
    for (name, seed, x) in [("valid claim", SEED_A, TARGET), ("invalid claim", { let mut s = SEED_A; s[31] = b'2'; s }, TARGET ^ 0x0100)] {
        let (sec, p) = setup(seed, TARGET);
        let leaf: ScriptBuf = p.script.clone();
        let info = spend_info(&leaf);
        let addr = Address::p2tr_tweaked(info.output_key(), Network::Regtest).to_string();
        // fund
        let fund_txid = rpc.call(w, "sendtoaddress", json!([addr, 0.001])).unwrap().as_str().unwrap().to_string();
        let a = rpc.call(w, "getnewaddress", json!([])).unwrap();
        rpc.call(w, "generatetoaddress", json!([1, a])).unwrap();
        let raw = rpc.call(None, "getrawtransaction", json!([fund_txid, true])).unwrap();
        let want = hex::encode(ScriptBuf::new_p2tr_tweaked(info.output_key()).as_bytes());
        let vout = raw["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == want.as_str()).unwrap()["n"].as_u64().unwrap();
        // garbler reveals x
        let bits: Vec<bool> = (0..N_IN).map(|i| (x >> i) & 1 == 1).collect();
        let opening = sec.sk.open_bits(&bits);
        let mut wit = bitcoin::Witness::new();
        for it in opening.witness_stack(&BYTE_SCHEME) {
            wit.push(it);
        }
        wit.push(leaf.as_bytes());
        wit.push(control_block(&leaf).serialize());
        let dest: String = rpc.call(w, "getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
        let dest = Address::from_str(&dest).unwrap().require_network(Network::Regtest).unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_str(&fund_txid).unwrap(), vout: vout as u32 }, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: wit }],
            output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: dest.script_pubkey() }],
        };
        let spend_txid = rpc.call(None, "sendrawtransaction", json!([serialize_hex(&tx)])).expect("Core accepts the reveal").as_str().unwrap().to_string();
        let a = rpc.call(w, "getnewaddress", json!([])).unwrap();
        rpc.call(w, "generatetoaddress", json!([1, a])).unwrap();

        // evaluator: read the witness from the confirmed transaction, nothing else from the garbler
        let conf = rpc.call(None, "getrawtransaction", json!([spend_txid, true])).unwrap();
        assert!(conf["confirmations"].as_u64().unwrap() >= 1);
        let items: Vec<Vec<u8>> = conf["vin"][0]["txinwitness"].as_array().unwrap().iter().map(|h| hex::decode(h.as_str().unwrap()).unwrap()).collect();
        let stack = &items[..items.len() - 2];
        let opening = Opening::from_witness_stack(&BYTE_SCHEME, stack).expect("parse witness");
        let (labels, values, got_x) = labels_from_opening(&p, &opening).expect("labels from on-chain openers");
        let ev = evaluate(&p, &labels, &values);
        println!(
            "[{name}] spend {} confirmed; evaluator read x={got_x:#06x} from the chain, output={} secret recovered={}",
            &spend_txid[..16], ev.output_value, ev.secret.is_some()
        );
        assert_eq!(got_x, x);
        assert_eq!(ev.output_value, valid(TARGET, x));
        assert_eq!(ev.secret.is_some(), !valid(TARGET, x));
        if let Some(s) = ev.secret {
            assert_eq!(s, sec.fault_secret);
        }
    }
    println!("ok");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vectors") => vectors(args.get(2).map(String::as_str).unwrap_or("fixtures/ckt_vectors.json")),
        Some("regtest") => regtest(),
        _ => eprintln!("usage: demo vectors [path] | demo regtest"),
    }
}
