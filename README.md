# pq-conditional-disclosure

Research prototype: can a Bitcoin verifier authenticate and selectively reveal **garbled-circuit input
labels using only hashes**, at materially lower Script cost than per-bit Lamport commitments? The
reference architecture is Alpen's Mosaic; the primary source is
[Antichain Winternitz](https://github.com/alpenlabs/antichain-winternitz) (ePrint 2026/1568).

**Read first:** [`docs/research-note.md`](docs/research-note.md) (results and verdict). Then
[`docs/security.md`](docs/security.md) (argument, assumptions, quantum parameters) and
[`docs/requirements-gap.md`](docs/requirements-gap.md) (what a post-quantum, maliciously secure
disclosure still lacks).

## Headline (measured on Bitcoin Core 31.1 regtest, 1,024-bit reveal)

| scheme | tx vbytes | vs Lamport |
|---|---:|---:|
| per-bit Lamport (RIPEMD-160) | 18,499 | - |
| ACW `k=4, L=8` (byte-aligned) | 9,657 | -47.8% |
| **ACW `k=4, L=16`** | **8,735** | **-52.8%** |
| Schnorr adaptor (Mosaic today; real BIP-340 sigs; **not post-quantum**) | 3,292 | -82.2% |

* The paper's numbers reproduce exactly. ACW beats Lamport by about half, but is about 2.7x the cost of today's adaptor reveal.
* No scheme here beats ACW at the same parameters; past `k=4` the on-chain gain flattens while the off-chain table grows 10x per step.
* This is **not** a post-quantum bridge: the polynomial commitments, the verified statement (Groth16), the fault secret and the Taproot output type all remain open.

## Layout

```
crates/pqcd         library + tools
  src/codeword.rs     constant-sum codewords, rank/unrank
  src/scheme.rs       Lamport, Lamport-nobit, ACW: commit / open / verify / Tapscript generator
  src/gadget.rs       public label table, value commitments, audit
  src/taproot.rs      packaging, weight, chunking      src/exec.rs   interpreter harness (OP_CAT off)
  src/security.rs     generic-attack security model    src/baseline.rs   Schnorr-adaptor cost model
  src/bin/{bench,regtest,regtest_schnorr,fixtures}.rs
  tests/adversarial.rs  20 attack tests (+ unit tests, fixture replay)
crates/pqcd-ckt     ACW-authenticated labels driving the real ckt-gobble engine (+ demo, golden vectors)
fixtures/           Script vectors (replayable from hex) and ckt golden vectors
results/            bench.json/csv, regtest.json, regtest_schnorr.json, summary.md, frontier.png
docs/               research note, security argument, requirements gap
scripts/            regtest node launcher, summarize.py, plot_frontier.py
```

## Run

```bash
cargo test --release                                   # all tests, incl. 65,536-claim ckt evaluation
cargo run --release --bin bench results                # benchmarks (add --quick to skip 100K bits)
scripts/regtest-node.sh <datadir> <bitcoind>           # then: regtest, regtest_schnorr, demo regtest
```

Full commands and pins are in section 10 of the research note. On Windows use the MSVC Rust toolchain
(the GNU toolchain has no `gcc` for `secp256k1-sys`).

## Claims policy

Security statements are arguments plus tests, tagged in `docs/security.md` as exhaustive-tested, argued or assumed. Nothing is
machine-checked, the garbled-circuit layer is taken as given, and Mosaic was read but not run or audited.
