//! Machine-readable benchmarks: `results/bench.json` and `results/bench.csv`.
//!
//! Usage: `bench [out_dir] [--quick]`. `--quick` skips the 100k-bit runs.
//!
//! For every scheme and message size it measures: on-chain bytes (script, revealed items,
//! witness, whole-transaction vbytes), generation/open/verify time, Tapscript execution
//! (steps, executed opcodes, hash opcodes, peak stack, wall time), peak heap, the concrete
//! security estimate, and the off-chain label-table cost for ACW.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use pqcd::baseline::{schnorr_reveal_spend, WIDE_LABEL_BITS};
use pqcd::exec::{run, Mode};
use pqcd::gadget;
use pqcd::metrics::{marginal_vb_per_bit, Msg};
use pqcd::scheme::{Scheme, SecretKey};
use pqcd::security;
use pqcd::taproot::{chunk_digits, chunk_spend, tx_weight, LeafSpend};
use pqcd::HashKind;
use serde_json::{json, Value};

struct Tracking;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call unchanged to the system allocator; only counters are added.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let c = CUR.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(c, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        CUR.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            if new >= l.size() {
                let c = CUR.fetch_add(new - l.size(), Ordering::Relaxed) + (new - l.size());
                PEAK.fetch_max(c, Ordering::Relaxed);
            } else {
                CUR.fetch_sub(l.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}
#[global_allocator]
static A: Tracking = Tracking;

/// Reset the peak to the current level; returns the baseline.
fn mem_mark() -> usize {
    let c = CUR.load(Ordering::Relaxed);
    PEAK.store(c, Ordering::Relaxed);
    c
}
fn mem_peak_since(base: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

const MAX_ITEMS: usize = 990;
const MAX_TX_WU: u64 = 390_000;

fn pack_weight(spends: &[LeafSpend]) -> (usize, u64) {
    let mut groups: Vec<Vec<LeafSpend>> = vec![vec![]];
    let mut cur_wu: u64 = 0;
    for s in spends {
        // incremental: weight of one input = witness + 41 base bytes * 4 (+1 for count byte growth)
        let w = s.witness().size() as u64 + 41 * 4;
        if cur_wu + w + 10 * 4 > MAX_TX_WU && !groups.last().unwrap().is_empty() {
            groups.push(vec![]);
            cur_wu = 0;
        }
        groups.last_mut().unwrap().push(s.clone());
        cur_wu += w;
    }
    let total: u64 = groups.iter().map(|g| tx_weight(g)).sum();
    (groups.len(), total)
}

fn bits_for(nbits: usize) -> Vec<bool> {
    (0..nbits).map(|i| (i.wrapping_mul(2654435761)) >> 7 & 1 == 1).collect()
}

fn measure(scheme: Scheme, nbits: usize, table_sample: usize) -> Value {
    let master = [0x5a; 32];
    let digits = scheme.digits_for(nbits);
    let bits = bits_for(nbits);

    let base = mem_mark();
    let sk = SecretKey::for_bits(scheme, master, nbits);
    let t = Instant::now();
    let com = sk.commit();
    let commit_ms = ms(t);
    let commit_peak = mem_peak_since(base);
    let com_bytes: usize = com.pks.iter().map(|d| d.iter().map(|x| x.len()).sum::<usize>()).sum();

    let t = Instant::now();
    let opening = sk.open_bits(&bits);
    let open_ms = ms(t);

    let base = mem_mark();
    let t = Instant::now();
    let vals = com.verify(&opening).expect("honest opening verifies");
    let verify_ms = ms(t);
    let verify_peak = mem_peak_since(base);
    assert_eq!(com.bits_of(&vals, nbits), bits);

    // Script generation and per-chunk execution.
    let chunks = chunk_digits(&scheme, nbits, MAX_ITEMS);
    let t = Instant::now();
    let base = mem_mark();
    let spends: Vec<LeafSpend> = chunks.iter().map(|&(f, n)| chunk_spend(&com, &opening, f, n)).collect();
    let script_build_ms = ms(t);
    let script_build_peak = mem_peak_since(base);

    let (mut steps, mut ops, mut hashes, mut max_stack, mut exec_us) = (0u64, 0u64, 0u64, 0usize, 0u128);
    let t = Instant::now();
    for s in &spends {
        let r = run(&s.script, &s.stack, Mode::Policy);
        assert!(r.ok, "honest chunk must execute: {:?}", r.error);
        steps += r.steps;
        ops += r.ops_executed;
        hashes += r.hash_ops;
        max_stack = max_stack.max(r.max_stack);
        exec_us += r.micros;
    }
    let exec_wall_ms = ms(t);

    let script_bytes: usize = spends.iter().map(|s| s.script_bytes()).sum();
    let item_bytes: usize = spends.iter().map(|s| s.stack_bytes()).sum();
    let witness_bytes: usize = spends.iter().map(|s| s.witness_bytes()).sum();
    let items: usize = spends.iter().map(|s| s.stack.len()).sum();
    let (txs, total_wu) = pack_weight(&spends);
    let sec = security::estimate(&scheme, nbits);

    let mut row = json!({
        "scheme": scheme.name(), "hash": scheme.hash().name(), "nbits": nbits, "digits": digits,
        "bits_per_digit": scheme.bits_per_digit(), "chains_per_digit": scheme.pks_per_digit(),
        "inputs": spends.len(), "transactions": txs,
        "onchain": {
            "script_bytes": script_bytes, "revealed_item_bytes": item_bytes, "witness_items": items,
            "witness_bytes_total": witness_bytes, "witness_vbytes_total": witness_bytes as f64 / 4.0,
            "tx_vbytes_total": total_wu as f64 / 4.0,
            "authenticated_bytes_per_bit": (script_bytes + item_bytes) as f64 / nbits as f64,
            "witness_bytes_per_bit": witness_bytes as f64 / nbits as f64,
            "witness_vb_per_bit": witness_bytes as f64 / 4.0 / nbits as f64,
            "tx_vb_per_bit": total_wu as f64 / 4.0 / nbits as f64,
            "marginal_vb_per_bit_canonical": marginal_vb_per_bit(scheme, Msg::Canonical),
            "marginal_vb_per_bit_random": marginal_vb_per_bit(scheme, Msg::Random(1)),
        },
        "script_execution": {
            "steps": steps, "opcodes_executed": ops, "hash_opcodes_executed": hashes,
            "peak_stack_items": max_stack, "sum_exec_micros": exec_us, "wall_ms": exec_wall_ms,
            "hash_opcodes_per_bit": hashes as f64 / nbits as f64,
        },
        "offchain_compute": {
            "commit_ms": commit_ms, "open_ms": open_ms, "verify_ms": verify_ms, "script_build_ms": script_build_ms,
            "commitment_bytes": com_bytes,
            "peak_heap_bytes": { "commit": commit_peak, "verify": verify_peak, "script_build": script_build_peak },
        },
        "security": serde_json::to_value(&sec).unwrap(),
    });

    if let Scheme::Acw { .. } = scheme {
        let b = scheme.bits_per_digit() as usize;
        let payload_len = 16 * b; // one 128-bit label per bit of the digit
        let payload = |v: u64| -> Vec<u8> {
            (0..b).flat_map(|i| {
                let bit = ((v >> i) & 1) as u8;
                (0..16u8).map(move |x| x.wrapping_mul(7).wrapping_add(i as u8 * 31).wrapping_add(bit * 101))
            }).collect()
        };
        let sample = table_sample.min(digits).max(1);
        let base = mem_mark();
        let t = Instant::now();
        let mut rows = 0usize;
        for d in 0..sample {
            let tab = gadget::build_digit_table(&sk, d, b"bench", &payload);
            rows = tab.rows.len();
        }
        let per_digit_ms = ms(t) / sample as f64;
        let tab_peak = mem_peak_since(base);
        let sp = scheme.space().unwrap();
        let bytes_per_digit = gadget::table_bytes(&scheme, payload_len, false);
        row["offchain_table"] = json!({
            "payload": "one 16-byte label per digit bit",
            "rows_per_digit": rows, "log2_rows": sp.log2_count(), "bits_per_digit": b,
            "payload_bytes": payload_len,
            "table_bytes_per_digit": bytes_per_digit,
            "table_bytes_per_bit": bytes_per_digit as f64 / b as f64,
            "table_bytes_total": bytes_per_digit as u128 * digits as u128,
            "build_ms_per_digit": per_digit_ms,
            "build_s_total_extrapolated": per_digit_ms * digits as f64 / 1e3,
            "sampled_digits": sample,
            "peak_heap_bytes_one_digit": tab_peak,
            "with_value_commitments_bytes_per_digit": gadget::table_bytes(&scheme, payload_len, true),
        });
        if nbits <= 1_024 {
            let t = Instant::now();
            for d in 0..digits {
                let _ = gadget::build_digit_table(&sk, d, b"bench", &payload);
            }
            row["offchain_table"]["build_s_total_measured"] = json!(t.elapsed().as_secs_f64());
        }
    }
    row
}

fn baseline_row(nbits: usize) -> Value {
    let wires = nbits.div_ceil(WIDE_LABEL_BITS);
    let per_input = MAX_ITEMS;
    let mut spends = vec![];
    let mut left = wires;
    while left > 0 {
        let n = left.min(per_input);
        spends.push(schnorr_reveal_spend(n));
        left -= n;
    }
    let script_bytes: usize = spends.iter().map(|s| s.script_bytes()).sum();
    let item_bytes: usize = spends.iter().map(|s| s.stack_bytes()).sum();
    let witness_bytes: usize = spends.iter().map(|s| s.witness_bytes()).sum();
    let (txs, total_wu) = pack_weight(&spends);
    json!({
        "scheme": "schnorr-adaptor-baseline", "hash": "n/a (BIP-340 on secp256k1)", "nbits": nbits, "digits": wires,
        "bits_per_digit": WIDE_LABEL_BITS, "inputs": spends.len(), "transactions": txs,
        "post_quantum": false,
        "onchain": {
            "script_bytes": script_bytes, "revealed_item_bytes": item_bytes, "witness_bytes_total": witness_bytes,
            "witness_vbytes_total": witness_bytes as f64 / 4.0, "tx_vbytes_total": total_wu as f64 / 4.0,
            "authenticated_bytes_per_bit": (script_bytes + item_bytes) as f64 / nbits as f64,
            "witness_bytes_per_bit": witness_bytes as f64 / nbits as f64,
            "witness_vb_per_bit": witness_bytes as f64 / 4.0 / nbits as f64,
            "tx_vb_per_bit": total_wu as f64 / 4.0 / nbits as f64,
        },
        "note": "cost model only: size-exact dummy signatures; one OP_CODESEPARATOR <pk> OP_CHECKSIGVERIFY per 8-bit wide label",
    })
}

/// On-chain cost frontier over (k, L), 20-byte digests, with the off-chain table price.
fn frontier() -> Vec<Value> {
    let mut v = vec![];
    for k in 2..=6u32 {
        for l in [4u32, 8, 16, 32] {
            let s = Scheme::Acw { k, l, hash: HashKind::Hash160 };
            let sp = s.space().unwrap();
            let b = sp.bits();
            v.push(json!({
                "k": k, "l": l, "n_codewords": sp.count().to_string(), "log2_n": sp.log2_count(), "bits_per_digit": b,
                "capacity_efficiency": f64::from(b) / (f64::from(k) * f64::from(l).log2()),
                "marginal_vb_per_bit": marginal_vb_per_bit(s, Msg::Canonical),
                "witness_items_per_digit": s.witness_items_per_digit(),
                "table_bytes_per_bit_16B_labels": 16.0 * sp.count() as f64,
                "max_message_bits_per_input": (990 / s.witness_items_per_digit()) * b as usize,
            }));
        }
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quick = args.iter().any(|a| a == "--quick");
    let out_dir = args.iter().find(|a| !a.starts_with("--")).cloned().unwrap_or_else(|| "results".into());
    std::fs::create_dir_all(&out_dir).unwrap();

    let h20 = HashKind::Hash160;
    let schemes = [
        Scheme::Lamport { hash: HashKind::Ripemd160 },
        Scheme::LamportNoBit { hash: HashKind::Ripemd160 },
        Scheme::Lamport { hash: HashKind::Sha256 },
        Scheme::Acw { k: 2, l: 16, hash: h20 },
        Scheme::Acw { k: 4, l: 8, hash: h20 },
        Scheme::Acw { k: 4, l: 16, hash: h20 },
        Scheme::Acw { k: 4, l: 16, hash: HashKind::Sha256 },
        Scheme::Acw { k: 5, l: 16, hash: h20 },
    ];
    let sizes: Vec<usize> = if quick { vec![1_056, 10_000] } else { vec![1_056, 1_000, 10_000, 100_000] };
    let mut rows = vec![];
    let mut baselines = vec![];
    for &n in &sizes {
        for s in schemes {
            // k=5 L=16 tables hold ~42k rows per digit: sample fewer digits.
            let sample = if matches!(s, Scheme::Acw { k: 5, .. }) { 2 } else { 24 };
            let t = Instant::now();
            let r = measure(s, n, sample);
            println!("{:<26} {:>7} bits  {:>8.2} tx-vB/bit  {:>6.1}s", s.name(), n, r["onchain"]["tx_vb_per_bit"].as_f64().unwrap(), t.elapsed().as_secs_f64());
            rows.push(r);
        }
        baselines.push(baseline_row(n));
    }
    let doc = json!({
        "generated_by": "pqcd bench", "mode": if quick { "quick" } else { "full" },
        "max_items_per_input": MAX_ITEMS, "max_tx_weight_wu": MAX_TX_WU,
        "label_security_bits_128bit_labels": { "classical": security::label_security(128).0, "quantum_grover": security::label_security(128).1 },
        "rows": rows, "schnorr_adaptor_baseline": baselines, "frontier_hash160": frontier(),
    });
    std::fs::write(format!("{out_dir}/bench.json"), serde_json::to_string_pretty(&doc).unwrap()).unwrap();

    let mut csv = String::from("scheme,nbits,inputs,txs,witness_bytes,tx_vbytes,tx_vb_per_bit,witness_vb_per_bit,marginal_vb_per_bit,hash_ops,ops_executed,commit_ms,verify_ms,exec_wall_ms,peak_heap_commit,table_bytes_per_bit,eval_pre_classical_bits,eval_pre_quantum_bits\n");
    for r in doc["rows"].as_array().unwrap() {
        csv += &format!(
            "{},{},{},{},{},{},{:.3},{:.3},{:.4},{},{},{:.2},{:.2},{:.2},{},{},{:.1},{:.1}\n",
            r["scheme"].as_str().unwrap(), r["nbits"], r["inputs"], r["transactions"],
            r["onchain"]["witness_bytes_total"], r["onchain"]["tx_vbytes_total"],
            r["onchain"]["tx_vb_per_bit"].as_f64().unwrap(), r["onchain"]["witness_vb_per_bit"].as_f64().unwrap(),
            r["onchain"]["marginal_vb_per_bit_canonical"].as_f64().unwrap(),
            r["script_execution"]["hash_opcodes_executed"], r["script_execution"]["opcodes_executed"],
            r["offchain_compute"]["commit_ms"].as_f64().unwrap(), r["offchain_compute"]["verify_ms"].as_f64().unwrap(),
            r["script_execution"]["wall_ms"].as_f64().unwrap(), r["offchain_compute"]["peak_heap_bytes"]["commit"],
            r["offchain_table"]["table_bytes_per_bit"].as_f64().map(|x| x.to_string()).unwrap_or_default(),
            r["security"]["evaluator_classical"].as_f64().unwrap(), r["security"]["evaluator_quantum_iterations"].as_f64().unwrap(),
        );
    }
    for r in &baselines {
        csv += &format!(
            "{},{},{},{},{},{},{:.3},{:.3},,,,,,,,,,\n",
            r["scheme"].as_str().unwrap(), r["nbits"], r["inputs"], r["transactions"],
            r["onchain"]["witness_bytes_total"], r["onchain"]["tx_vbytes_total"],
            r["onchain"]["tx_vb_per_bit"].as_f64().unwrap(), r["onchain"]["witness_vb_per_bit"].as_f64().unwrap(),
        );
    }
    std::fs::write(format!("{out_dir}/bench.csv"), csv).unwrap();
    println!("wrote {out_dir}/bench.json and bench.csv");
}
