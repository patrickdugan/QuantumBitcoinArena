//! Validates the Schnorr-adaptor cost model against Bitcoin Core with real BIP-340 signatures:
//! one `OP_CODESEPARATOR <pk> OP_CHECKSIGVERIFY` per 8-bit wide label, each wire signed over a
//! distinct signature hash (the codeseparator position is part of the BIP-342 sighash).
//! Writes `results/regtest_schnorr.json`.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::opcodes::all as op;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use pqcd::rpc::Rpc;
use pqcd::taproot::{control_block, spend_info};
use serde_json::{json, Value};

fn main() {
    let rpc = Rpc::new(18643, "pqcd", "pqcd-regtest-only");
    let w = Some("pqcd");
    let _ = rpc.call(None, "loadwallet", json!(["pqcd"]));
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let (xonly, _) = kp.x_only_public_key();

    let mut rows = vec![];
    for wires in [16usize, 128, 500] {
        // script: per wire  OP_CODESEPARATOR <pk> OP_CHECKSIG(VERIFY)
        let mut b = Builder::new();
        for i in 0..wires {
            b = b.push_opcode(op::OP_CODESEPARATOR).push_slice(PushBytesBuf::try_from(xonly.serialize().to_vec()).unwrap());
            b = b.push_opcode(if i + 1 == wires { op::OP_CHECKSIG } else { op::OP_CHECKSIGVERIFY });
        }
        let leaf: ScriptBuf = b.into_script();
        let info = spend_info(&leaf);
        let addr = Address::p2tr_tweaked(info.output_key(), Network::Regtest).to_string();
        let value = 1_000_000u64;
        let fund = rpc.call(w, "sendtoaddress", json!([addr, value as f64 / 1e8])).unwrap().as_str().unwrap().to_string();
        let a = rpc.call(w, "getnewaddress", json!([])).unwrap();
        rpc.call(w, "generatetoaddress", json!([1, a])).unwrap();
        let raw = rpc.call(None, "getrawtransaction", json!([fund, true])).unwrap();
        let want = hex::encode(ScriptBuf::new_p2tr_tweaked(info.output_key()).as_bytes());
        let vout = raw["vout"].as_array().unwrap().iter().find(|o| o["scriptPubKey"]["hex"] == want.as_str()).unwrap();
        let (vout_n, vout_val) = (vout["n"].as_u64().unwrap() as u32, (vout["value"].as_f64().unwrap() * 1e8).round() as u64);
        let dest: String = rpc.call(w, "getnewaddress", json!([])).unwrap().as_str().unwrap().to_string();
        let dest = Address::from_str(&dest).unwrap().require_network(Network::Regtest).unwrap();
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_str(&fund).unwrap(), vout: vout_n }, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(vout_val - 5_000), script_pubkey: dest.script_pubkey() }],
        };
        let prevout = TxOut { value: Amount::from_sat(vout_val), script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()) };
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let mut sigs = vec![];
        {
            let mut cache = SighashCache::new(&tx);
            for i in 0..wires {
                // opcode position of the last executed OP_CODESEPARATOR before this CHECKSIG: 3 opcodes per wire
                let sh = cache
                    .taproot_signature_hash(0, &Prevouts::All(&[prevout.clone()]), None, Some((leaf_hash, 3 * i as u32)), TapSighashType::Default)
                    .unwrap();
                let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &kp);
                sigs.push(sig.serialize().to_vec());
            }
        }
        // top of stack = first wire's signature
        let mut wit = Witness::new();
        for s in sigs.iter().rev() {
            wit.push(s);
        }
        wit.push(leaf.as_bytes());
        wit.push(control_block(&leaf).serialize());
        tx.input[0].witness = wit;
        let v = rpc.call(None, "testmempoolaccept", json!([[serialize_hex(&tx)]])).unwrap();
        let ok = v[0]["allowed"] == true;
        let model = pqcd::baseline::schnorr_reveal_spend(wires);
        let model_wu = pqcd::taproot::tx_weight(&[model]);
        println!("{wires:>4} wires ({} bits): Core accepts={ok} vsize={} (model weight {} WU -> {} vB) {}", wires * 8, v[0]["vsize"], model_wu, model_wu.div_ceil(4), v[0]["reject-reason"]);
        assert!(ok, "Core rejected the real-signature spend: {v}");
        rows.push(json!({"wires": wires, "bits": wires * 8, "core_vsize": v[0]["vsize"], "model_weight_wu": model_wu, "per_bit_vb": v[0]["vsize"].as_f64().unwrap() / (wires * 8) as f64}));
    }
    let doc = json!({"description": "BIP-340 signature per 8-bit wide label, OP_CODESEPARATOR for distinct sighashes; accepted by Core testmempoolaccept", "rows": Value::Array(rows)});
    std::fs::write("results/regtest_schnorr.json", serde_json::to_string_pretty(&doc).unwrap()).unwrap();
}
