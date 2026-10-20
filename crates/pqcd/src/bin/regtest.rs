//! Ground truth against Bitcoin Core: fund and spend every generated leaf on regtest.
//!
//! Needs a regtest node (see `scripts/regtest-node.sh`): RPC 127.0.0.1:18643, user
//! `pqcd`, password `pqcd-regtest-only`. Writes `results/regtest.json`.
//!
//! What it establishes that the in-process interpreter cannot: the scripts are accepted
//! by Core's *policy* (`testmempoolaccept`, i.e. standard) and *consensus* (a mined block),
//! the real transaction weight equals ours, and forged / malformed witnesses are rejected
//! by Core itself.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use pqcd::codeword::CodewordSpace;
use pqcd::rpc::Rpc;
use pqcd::scheme::{DigitOpening, Opening, Scheme, SecretKey};
use pqcd::taproot::{chunk_digits, chunk_spend, spend_info, tx_weight, LeafSpend};
use pqcd::HashKind;
use serde_json::{json, Value};

const WALLET: &str = "pqcd";
const FUND_SAT: u64 = 400_000;
const MAX_TX_WU: u64 = 390_000;

fn spk(leaf: &ScriptBuf) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(spend_info(leaf).output_key())
}

fn addr(leaf: &ScriptBuf) -> String {
    Address::p2tr_tweaked(spend_info(leaf).output_key(), Network::Regtest).to_string()
}

struct Funded {
    outpoint: OutPoint,
    value: u64,
    spend: LeafSpend,
}

fn fund(rpc: &Rpc, spends: &[LeafSpend]) -> Result<Vec<Funded>, String> {
    let mut out = Vec::new();
    // sendmany in batches to keep the funding tx standard-sized.
    for batch in spends.chunks(60) {
        let mut map = serde_json::Map::new();
        for s in batch {
            map.insert(addr(&s.script), json!(FUND_SAT as f64 / 1e8));
        }
        let txid = rpc
            .call(Some(WALLET), "sendmany", json!(["", Value::Object(map)]))?
            .as_str()
            .ok_or("sendmany txid")?
            .to_string();
        let addr_ = rpc.call(Some(WALLET), "getnewaddress", json!([]))?;
        rpc.call(Some(WALLET), "generatetoaddress", json!([1, addr_]))?;
        let tx = rpc.call(None, "getrawtransaction", json!([txid, true]))?;
        for s in batch {
            let want = hex::encode(spk(&s.script).as_bytes());
            let vout = tx["vout"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["scriptPubKey"]["hex"].as_str() == Some(&want))
                .ok_or("funded output not found")?;
            out.push(Funded {
                outpoint: OutPoint { txid: Txid::from_str(&txid).unwrap(), vout: vout["n"].as_u64().unwrap() as u32 },
                value: FUND_SAT,
                spend: s.clone(),
            });
        }
    }
    Ok(out)
}

fn build_spend(rpc: &Rpc, ins: &[&Funded], rate_sat_per_vb: f64) -> Result<Transaction, String> {
    let dest: String = rpc.call(Some(WALLET), "getnewaddress", json!([]))?.as_str().unwrap().to_string();
    let dest = Address::from_str(&dest).unwrap().require_network(Network::Regtest).unwrap();
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: ins
            .iter()
            .map(|f| TxIn {
                previous_output: f.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: f.spend.witness(),
            })
            .collect(),
        output: vec![TxOut { value: Amount::from_sat(0), script_pubkey: dest.script_pubkey() }],
    };
    let total: u64 = ins.iter().map(|f| f.value).sum();
    let vsize = tx.weight().to_wu().div_ceil(4);
    let fee = (vsize as f64 * rate_sat_per_vb).ceil() as u64 + 200;
    tx.output[0].value = Amount::from_sat(total.checked_sub(fee).ok_or("funding too small for fee")?);
    Ok(tx)
}

fn accept(rpc: &Rpc, tx: &Transaction) -> Result<Value, String> {
    let r = rpc.call(None, "testmempoolaccept", json!([[serialize_hex(tx)]]))?;
    Ok(r[0].clone())
}

fn open_msg(scheme: Scheme, nbits: usize) -> (SecretKey, pqcd::Commitment, Opening) {
    let sk = SecretKey::for_bits(scheme, [0x42; 32], nbits);
    let com = sk.commit();
    let bits: Vec<bool> = (0..nbits).map(|i| (i * 2654435761usize) >> 7 & 1 == 1).collect();
    let o = sk.open_bits(&bits);
    (sk, com, o)
}

fn main() {
    let rpc = Rpc::new(18643, "pqcd", "pqcd-regtest-only");
    let info = rpc.call(None, "getblockchaininfo", json!([])).expect("node reachable (start scripts/regtest-node.sh)");
    assert_eq!(info["chain"], "regtest");
    let _ = rpc.call(None, "createwallet", json!([WALLET]));
    let _ = rpc.call(None, "loadwallet", json!([WALLET]));
    if info["blocks"].as_u64().unwrap() < 101 {
        let a = rpc.call(Some(WALLET), "getnewaddress", json!([])).unwrap();
        rpc.call(Some(WALLET), "generatetoaddress", json!([101, a])).unwrap();
    }
    let version = rpc.call(None, "getnetworkinfo", json!([])).unwrap();

    let mut results = serde_json::Map::new();
    results.insert("node".into(), json!({ "version": version["version"], "subversion": version["subversion"] }));

    // ---------------------------------------------------------------- positive: 1024-bit bridge-size inputs
    let h20 = HashKind::Hash160;
    let positives: Vec<Scheme> = vec![
        Scheme::Lamport { hash: HashKind::Ripemd160 },
        Scheme::LamportNoBit { hash: HashKind::Ripemd160 },
        Scheme::Acw { k: 2, l: 16, hash: h20 },
        Scheme::Acw { k: 4, l: 8, hash: h20 },
        Scheme::Acw { k: 4, l: 16, hash: h20 },
        Scheme::Acw { k: 4, l: 16, hash: HashKind::Sha256 },
    ];
    let nbits = 1024usize;
    let mut pos_rows = vec![];
    for s in positives {
        let (_sk, com, o) = open_msg(s, nbits);
        let chunks = chunk_digits(&s, nbits, 900);
        let spends: Vec<LeafSpend> = chunks.iter().map(|&(f, n)| chunk_spend(&com, &o, f, n)).collect();
        let funded = fund(&rpc, &spends).expect("fund");
        // pack into standard-size transactions
        let mut groups: Vec<Vec<&Funded>> = vec![vec![]];
        for f in &funded {
            let mut trial: Vec<LeafSpend> = groups.last().unwrap().iter().map(|g| g.spend.clone()).collect();
            trial.push(f.spend.clone());
            if tx_weight(&trial) > MAX_TX_WU && !groups.last().unwrap().is_empty() {
                groups.push(vec![]);
            }
            groups.last_mut().unwrap().push(f);
        }
        let (mut my_wu, mut core_wu, mut core_vsize, mut txids) = (0u64, 0u64, 0u64, vec![]);
        for g in &groups {
            let tx = build_spend(&rpc, g, 2.0).expect("build");
            let verdict = accept(&rpc, &tx).expect("testmempoolaccept");
            assert_eq!(verdict["allowed"], true, "{}: Core policy rejected an honest spend: {verdict}", s.name());
            let txid = rpc.call(None, "sendrawtransaction", json!([serialize_hex(&tx)])).expect("send").to_string();
            my_wu += tx.weight().to_wu();
            core_wu += verdict["vsize"].as_u64().unwrap_or(0) * 4; // rounded up, upper bound
            core_vsize += verdict["vsize"].as_u64().unwrap_or(0);
            txids.push(txid);
        }
        let a = rpc.call(Some(WALLET), "getnewaddress", json!([])).unwrap();
        rpc.call(Some(WALLET), "generatetoaddress", json!([1, a])).unwrap();
        let confirmed = txids
            .iter()
            .all(|t| rpc.call(None, "getrawtransaction", json!([t.trim_matches('"'), true])).map(|r| r["confirmations"].as_u64().unwrap_or(0) >= 1).unwrap_or(false));
        println!("{:<28} {} inputs, {} tx, {} vB (core) {} WU (ours), confirmed={}", s.name(), spends.len(), groups.len(), core_vsize, my_wu, confirmed);
        assert!(confirmed, "{} did not confirm", s.name());
        assert!(core_wu >= my_wu && core_wu - my_wu < 4 * groups.len() as u64 + 4, "weight mismatch");
        pos_rows.push(json!({
            "scheme": s.name(), "nbits": nbits, "inputs": spends.len(), "transactions": groups.len(),
            "our_weight_wu": my_wu, "core_vsize": core_vsize, "confirmed": confirmed, "txids": txids,
        }));
    }
    results.insert("positive_1024_bit".into(), Value::Array(pos_rows));

    // ---------------------------------------------------------------- negative: forged and malformed witnesses
    let mut neg_rows = vec![];
    let negs: Vec<Scheme> = vec![
        Scheme::Lamport { hash: HashKind::Ripemd160 },
        Scheme::Acw { k: 4, l: 8, hash: h20 },
        Scheme::Acw { k: 2, l: 16, hash: h20 },
    ];
    for s in negs {
        let (sk, com, o) = open_msg(s, 64 * s.bits_per_digit() as usize);
        let honest = chunk_spend(&com, &o, 0, com.n_digits());
        let mut variants: Vec<(&str, LeafSpend)> = vec![];
        // 1. a different value in digit 3, forged from the honest opening
        let mut forged = o.clone();
        match s {
            Scheme::Acw { k, l, .. } => {
                let sp = CodewordSpace::new(k, l);
                let c = com.verify_digit(3, &o.digits[3]).unwrap().codeword;
                let c2 = sp.unrank((sp.rank(&c).unwrap() + 1) % sp.count()).unwrap();
                let openers = (0..k as usize)
                    .map(|j| {
                        if c2[j] <= c[j] { s.hash().iterate(&o.digits[3].openers[j], c[j] - c2[j]) } else { o.digits[3].openers[j].clone() }
                    })
                    .collect();
                forged.digits[3] = DigitOpening { openers, posted: c2[..k as usize - 1].iter().map(|&a| i64::from(a)).collect() };
            }
            _ => {
                forged.digits[3].posted[0] ^= 1; // claim the other bit with the same preimage
            }
        }
        variants.push(("forged_other_value", LeafSpend { script: honest.script.clone(), stack: forged.witness_stack(&s) }));
        // 2. a witness item removed, 3. an extra item, 4. a short opener
        let mut st = honest.stack.clone();
        st.remove(5);
        variants.push(("missing_item", LeafSpend { script: honest.script.clone(), stack: st }));
        let mut st = honest.stack.clone();
        st.insert(0, vec![1]);
        variants.push(("extra_item", LeafSpend { script: honest.script.clone(), stack: st }));
        let mut st = honest.stack.clone();
        let n = st.len();
        st[n - 2].pop();
        variants.push(("short_opener", LeafSpend { script: honest.script.clone(), stack: st }));
        let _ = &sk;
        let funded = fund(&rpc, &variants.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>()).expect("fund neg");
        for ((name, _), f) in variants.iter().zip(&funded) {
            let tx = build_spend(&rpc, &[f], 2.0).expect("build");
            let v = accept(&rpc, &tx).expect("tma");
            let rejected = v["allowed"] == false;
            println!("{:<22} {:<20} core rejects: {} ({})", s.name(), name, rejected, v["reject-reason"].as_str().unwrap_or(""));
            assert!(rejected, "Core accepted {name} on {}", s.name());
            neg_rows.push(json!({"scheme": s.name(), "attack": name, "rejected": rejected, "reason": v["reject-reason"]}));
        }
    }
    results.insert("negative".into(), Value::Array(neg_rows));

    // ---------------------------------------------------------------- policy vs consensus: non-minimal number
    {
        let s = Scheme::Acw { k: 3, l: 8, hash: h20 };
        let (_, com, o) = open_msg(s, 5);
        let mut leaf = chunk_spend(&com, &o, 0, 1);
        let top = leaf.stack.len() - 1;
        assert_eq!(leaf.stack[top], pqcd::scheme::scriptnum(o.digits[0].posted[0]));
        let mut v = leaf.stack[top].clone();
        v.push(0x00); // non-minimal encoding of the same number
        if v.len() == 1 {
            v = vec![0x80]; // negative zero for an empty push
        }
        leaf.stack[top] = v;
        let funded = fund(&rpc, &[leaf.clone()]).expect("fund");
        let tx = build_spend(&rpc, &[&funded[0]], 2.0).unwrap();
        let verdict = accept(&rpc, &tx).unwrap();
        let policy_rejects = verdict["allowed"] == false;
        let a = rpc.call(Some(WALLET), "getnewaddress", json!([])).unwrap();
        let mined = rpc.call(Some(WALLET), "generateblock", json!([a, [serialize_hex(&tx)]]));
        println!("non-minimal number: policy rejects={policy_rejects} ({}), consensus (mined)={}", verdict["reject-reason"], mined.is_ok());
        results.insert(
            "policy_vs_consensus".into(),
            json!({"non_minimal_number": {"policy_rejects": policy_rejects, "reject_reason": verdict["reject-reason"], "consensus_valid_mined": mined.is_ok()}}),
        );
    }

    // ---------------------------------------------------------------- initial-stack limit
    // Core is the authority. Scan downward from just above the interpreter's bisection result
    // until Core accepts, and record both numbers (they need not agree).
    {
        let mut rows = vec![];
        for s in [Scheme::LamportNoBit { hash: HashKind::Ripemd160 }, Scheme::Lamport { hash: HashKind::Ripemd160 }, Scheme::Acw { k: 4, l: 8, hash: h20 }, Scheme::Acw { k: 4, l: 16, hash: h20 }] {
            let interp = pqcd::taproot::max_digits_by_execution(&s);
            let per = s.witness_items_per_digit();
            let probe = |n: usize| -> (bool, Value) {
                let bits = n * s.bits_per_digit() as usize;
                let (_, com, o) = open_msg(s, bits);
                let leaf = chunk_spend(&com, &o, 0, n);
                let funded = fund(&rpc, &[leaf]).unwrap();
                let tx = build_spend(&rpc, &[&funded[0]], 2.0).unwrap();
                let v = accept(&rpc, &tx).unwrap();
                (v["allowed"] == true, v["reject-reason"].clone())
            };
            let mut n = interp + 1;
            let mut first_reason = Value::Null;
            let core_max = loop {
                let (ok, why) = probe(n);
                if ok { break n; }
                if first_reason.is_null() { first_reason = why; }
                n -= 1;
                assert!(n > 0);
            };
            let (above_ok, above_reason) = probe(core_max + 1);
            println!("{:<22} interpreter max {interp} digits, Core max {core_max} digits ({} items); Core rejects {}: {} ({})", s.name(), core_max * per, core_max + 1, !above_ok, above_reason);
            assert!(!above_ok);
            rows.push(json!({"scheme": s.name(), "items_per_digit": per, "interpreter_max_digits": interp, "core_max_digits": core_max,
                "core_max_items": core_max * per, "core_max_bits": core_max * s.bits_per_digit() as usize, "reject_reason_above": above_reason}));
        }
        results.insert("stack_limit".into(), Value::Array(rows));
    }

    let path = std::env::args().nth(1).unwrap_or_else(|| "results/regtest.json".into());
    std::fs::write(&path, serde_json::to_string_pretty(&Value::Object(results)).unwrap()).unwrap();
    println!("wrote {path}");
}
