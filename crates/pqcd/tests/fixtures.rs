//! Replays the stored fixtures from raw hex only (no key derivation, no generator code).

use bitcoin::ScriptBuf;
use pqcd::exec::{accepts, Mode};
use serde_json::Value;

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn stack(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().expect("array").iter().map(unhex).collect()
}

fn replay(vec: &Value) -> usize {
    let script = ScriptBuf::from_bytes(unhex(&vec["leaf_script_hex"]));
    let st = stack(&vec["witness_stack_initial_bottom_to_top"]);
    assert!(accepts(&script, &st, Mode::Policy), "{}: honest witness", vec["name"]);
    assert!(accepts(&script, &st, Mode::Consensus), "{}: honest witness (consensus)", vec["name"]);
    let mut n = 1;
    for neg in vec["negatives"].as_array().unwrap_or(&vec![]) {
        let mode = if neg["mode"] == "policy" { Mode::Policy } else { Mode::Consensus };
        let want = neg["expect"] == "accept";
        assert_eq!(accepts(&script, &stack(&neg["witness_stack"]), mode), want, "{} / {}", vec["name"], neg["name"]);
        n += 1;
    }
    // The taproot packaging must commit to exactly this leaf.
    let spk = hex::encode(
        ScriptBuf::new_p2tr_tweaked(pqcd::taproot::spend_info(&script).output_key()).as_bytes(),
    );
    assert_eq!(spk, vec["taproot"]["script_pubkey_hex"].as_str().unwrap(), "{}: scriptPubKey", vec["name"]);
    n
}

#[test]
fn small_vectors_replay() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string("../../fixtures/script_vectors.json").expect("run `fixtures` first")).unwrap();
    let total: usize = doc["vectors"].as_array().unwrap().iter().map(replay).sum();
    assert!(total >= 30, "replayed {total} expectations");
}

#[test]
fn bridge_size_vectors_replay() {
    for name in ["lamport_ripemd160", "acw_k4_l8_hash160", "acw_k4_l16_hash160"] {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(format!("../../fixtures/bridge_{name}.json")).unwrap()).unwrap();
        replay(&v);
    }
}
