"""Render the markdown tables used in docs/research-note.md from results/*.json.

    python scripts/summarize.py > results/summary.md
"""
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent
bench = json.loads((root / "results" / "bench.json").read_text())
core = json.loads((root / "results" / "regtest.json").read_text())
schn = json.loads((root / "results" / "regtest_schnorr.json").read_text())

rows = bench["rows"]
base = {r["nbits"]: r for r in rows if r["scheme"] == "lamport-ripemd160"}


def get(scheme, n):
    return next(r for r in rows if r["scheme"] == scheme and r["nbits"] == n)


order = [
    "lamport-ripemd160", "lamport-nobit-ripemd160", "lamport-sha256",
    "acw-k2-l16-hash160", "acw-k4-l8-hash160", "acw-k4-l16-hash160", "acw-k4-l16-sha256", "acw-k5-l16-hash160",
]

print("### A. Measured on Bitcoin Core 31.1 regtest, 1,024-bit reveal (accepted spends)\n")
print("| scheme | inputs | tx vbytes (Core) | vB/bit | vs Lamport |")
print("|---|---:|---:|---:|---:|")
lam = next(r for r in core["positive_1024_bit"] if r["scheme"] == "lamport-ripemd160")["core_vsize"]
for r in core["positive_1024_bit"]:
    print(f"| {r['scheme']} | {r['inputs']} | {r['core_vsize']:,} | {r['core_vsize']/1024:.2f} | {100*(r['core_vsize']/lam-1):+.1f}% |")
s128 = next(r for r in schn["rows"] if r["wires"] == 128)
print(f"| schnorr-adaptor (real BIP-340 sigs, not PQ) | 1 | {s128['core_vsize']:,} | {s128['core_vsize']/1024:.2f} | {100*(s128['core_vsize']/lam-1):+.1f}% |")

print("\n### B. Scaling (transaction vbytes incl. per-input overhead; packed into standard-size transactions)\n")
print("| scheme | 1,056 bits | inputs/tx | 10,000 | inputs/tx | 100,000 | inputs/tx |")
print("|---|---:|---:|---:|---:|---:|---:|")
for s in order:
    cells = []
    for n in (1056, 10000, 100000):
        r = get(s, n)
        cells += [f"{r['onchain']['tx_vbytes_total']:,.0f}", f"{r['inputs']}/{r['transactions']}"]
    print(f"| {s} | " + " | ".join(cells) + " |")
cells = []
for n in (1056, 10000, 100000):
    r = next(b for b in bench["schnorr_adaptor_baseline"] if b["nbits"] == n)
    cells += [f"{r['onchain']['tx_vbytes_total']:,.0f}", f"{r['inputs']}/{r['transactions']}"]
print("| schnorr-adaptor (model; not PQ) | " + " | ".join(cells) + " |")

print("\n### C. Per-bit metrics at 10,000 bits\n")
print("| scheme | auth. bytes/bit (script+items) | witness bytes/bit | vB/bit (tx) | hash ops/bit | opcodes/bit | commit ms | open ms | verify ms | exec ms | peak heap (commit) |")
print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
for s in order:
    r = get(s, 10000)
    o, e, c = r["onchain"], r["script_execution"], r["offchain_compute"]
    print(f"| {s} | {o['authenticated_bytes_per_bit']:.1f} | {o['witness_bytes_per_bit']:.1f} | {o['tx_vb_per_bit']:.2f} | {e['hash_opcodes_per_bit']:.2f} | {e['opcodes_executed']/10000:.1f} | {c['commit_ms']:.0f} | {c['open_ms']:.0f} | {c['verify_ms']:.0f} | {e['wall_ms']:.0f} | {c['peak_heap_bytes']['commit']/1e6:.2f} MB |")

print("\n### D. Off-chain label tables (ACW), payload = one 16-byte label per digit bit\n")
print("| scheme | codewords N | bits/digit | table bytes per digit | **bytes per message bit** | build ms/digit | table for 1,056 bits |")
print("|---|---:|---:|---:|---:|---:|---:|")
for s in order:
    r = get(s, 1056)
    if "offchain_table" not in r:
        continue
    t = r["offchain_table"]
    print(f"| {s} | {t['rows_per_digit']:,} | {t['bits_per_digit']} | {t['table_bytes_per_digit']:,} | {t['table_bytes_per_bit']:,.0f} | {t['build_ms_per_digit']:.2f} | {t['table_bytes_total']/1e6:.1f} MB |")

print("\n### E. Security estimates (generic attacks; log2 of work)\n")
print("| scheme | bits | evaluator classical | evaluator quantum (Grover iterations) |")
print("|---|---:|---:|---:|")
for s in ("lamport-ripemd160", "acw-k4-l8-hash160", "acw-k4-l16-hash160", "acw-k4-l16-sha256"):
    for n in (1056, 100000):
        sec = get(s, n)["security"]
        print(f"| {s} | {n:,} | {sec['evaluator_classical']:.1f} | {sec['evaluator_quantum_iterations']:.1f} |")

print("\n### F. Initial-stack limit per input (Core is the authority)\n")
print("| scheme | items/digit | max digits (Core) | max message bits per input | interpreter says |")
print("|---|---:|---:|---:|---:|")
for r in core["stack_limit"]:
    print(f"| {r['scheme']} | {r['items_per_digit']} | {r['core_max_digits']} | {r['core_max_bits']:,} | {r['interpreter_max_digits']} |")
