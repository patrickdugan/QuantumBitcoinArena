# Cryptographic argument and assumptions

Status: **research prototype.** Statements below are tagged **[exhaustive-tested]** (checked by
exhaustive enumeration at small parameters plus fuzzing and Bitcoin Core), **[argued]** (a
short mathematical argument that I believe is correct but have not mechanised), or
**[assumed]**. Nothing here is a machine-checked proof, and the garbled-circuit layer is
taken as given.

## 1. Setting

* A **garbler** G holds an input `x` (the bridge proof bits). An **evaluator** E holds a
  garbled verifier circuit and wants, if and only if `x` is *invalid*, a fault secret.
* G must reveal the input labels for `x` on Bitcoin. A Tapscript leaf spent by G must
  (i) accept only a well-formed reveal, and (ii) hand E labels for exactly one value
  of each input, never labels for any other value.
* Everything in this crate uses only opcodes enabled on Bitcoin today. `OP_CAT` is off in
  the test interpreter, and the generated leaves are accepted by Bitcoin Core 31.1.

## 2. The construction

Notation: `H` is one of `OP_RIPEMD160`, `OP_HASH160`, `OP_SHA256` (digest `n` bits, 160/160/256).

**Chain.** For a secret `s` the chain is `x_0 = s`, `x_i = H^i(s)`. The terminal is
`tau = x_L`. `x_0` is never revealed.

**Codeword space.** `C(k,L) = { a in [0,L-1]^k : sum a_j = R }`, `R = floor(k(L-1)/2)`.
The number of codewords is `N`, and a digit carries `b = floor(log2 N)` bits.

**Opener.** For coordinate `a` on chain `j` the opener is `x_{L-a}`. Hashing it `a` more
times reaches `tau_j`. A larger coordinate means a shorter hash path, so an opener for a
larger coordinate is a *predecessor* on the chain.

**Reach.** Anyone holding the opener for coordinate `a` can compute the opener for every
`a' <= a` by hashing forward. They cannot compute one for `a' > a` without inverting `H`.

**Script (per digit).** Witness: `k` openers and the first `k-1` coordinates. For each of the
first `k-1` chains the script adds the coordinate to a running sum and hashes the opener
that many times with a binary loop (`nb = log2 L` chunks of `DUP <2^i> GE IF <2^i> SUB SWAP H^(2^i) SWAP ENDIF`,
then `IF H ENDIF`), then `<tau_j> EQUALVERIFY`. The last coordinate is *derived* as
`R - sum` and checked the same way. The coordinates are fed to the loop "bare", with no
clamp, so an out-of-range value leaves a residue outside `{0,1}` which the final `OP_IF`
rejects (tapscript MINIMALIF). This needs `L = 2^nb`.

**Label table (off chain, public).** For each digit and each codeword `c` of rank `r`:
`row_r = pad(seed(c)) XOR payload(v(c))`, with `seed(c)` = concatenation of the `k` openers of
`c` and `v(c) = r mod 2^b`. `pad` is tagged SHA-256 in counter mode.
`payload(v)` is whatever the garbler hands out for value `v`: one 128-bit label per
bit of the digit, or ckt's wide label.

## 3. What is established

### Lemma 1 (accepted set equals the antichain) — **[exhaustive-tested] + [argued]**

A witness is accepted iff every posted coordinate and the derived coordinate lie in `[0,L-1]`
and `H^{a_j}(O_j) = tau_j` for all `j`. Hence the decoded tuple lies in `C`.

*Argument.* For a count `c` fed to the loop: if `0 <= c <= 2^nb - 1` the loop performs
exactly `c` hashes and leaves a residue in `{0,1}`. If `c < 0` no chunk fires and the
residue is `c` itself; if `c >= 2^nb` the chunks remove at most `2^nb - 2` so the residue is
at least 2. In both cases the last `OP_IF` sees a value other than empty/`0x01` and aborts.
*Testing.* `acw_accept_set_equals_antichain_k{2,3,4}` enumerate all posted coordinates in
`[-1, L]^{k-1}` times every last-opener index in `[0, L+1]` for `(k,L)` in
`{(2,4),(2,8),(3,4),(3,8),(4,4)}`. The set the **script** accepts equals the predicted
set and has exactly `N` elements. The native verifier agrees on every case. A proptest
differential (400 cases of random garbage) and Core's own rejection of forged witnesses
(`results/regtest.json`) cover larger parameters. Mutating the script (dropping the final
`EQUALVERIFY`, changing `R`) or the native verifier makes this suite fail, so it has
discriminating power.

### Theorem 1 (guaranteed revelation) — **[argued], unconditional**

If the table has one row per element of `C` and the value map is total, then every
opening the script accepts unlocks exactly one row. There is no accepted opening that
leaves E with nothing, and none that leaves E with two payloads.

*Argument.* Lemma 1 plus totality of `r -> r mod 2^b`. The `N - 2^b` codewords whose rank is
at least `2^b` alias onto a smaller value instead of being unusable
(`table_covers_every_admissible_opening`).

This property does not depend on any hash assumption. It depends on the table having been built
honestly, which is Section 5.

### Theorem 2 (unforgeability from one opening) — **[argued]**

Let G open `a in C`. Any `a' != a` in `C` has `sum a' = sum a`, so some chain `j` has
`a'_j > a_j`. An accepted opening for `a'` therefore contains `O'_j` with
`H^{a'_j}(O'_j) = tau_j`, where the revealed opener `O_j = x_{L-a_j}` only gives a preimage
under `H^{a_j}`. The adversary must go *backwards* by `a'_j - a_j >= 1` steps.

Define **BackStep**: given `tau_j` and the revealed chain elements, output `O'` with
`H^m(O') = tau_j` for some `m` above the revealed coordinate. In the random-oracle model for `H`,
an algorithm making `q` queries succeeds with probability at most about
`q * T / 2^n`, up to the image-shrinkage factor `L/2` described below, where `T` is the
number of chain elements it can target (`security::targets`). In the quantum random-oracle model Grover
with `T` marked items is optimal up to constants (BBBV), giving about `sqrt(2^n / T)`
sequential iterations.

*Why this is not a collision problem.* The adversary needs a preimage of a *public* value, so
nothing here uses collision resistance of `H`.

*Image shrinkage.* Iterating a public function shrinks the image to about `2/i` of the domain,
so a chain element has about `i/2` preimages instead of one. That makes backwards steps a
factor `~L/2` easier (the standard Winternitz "w" term). `security.rs` conservatively subtracts
`log2 L` bits. It does **not** cover structural weaknesses of RIPEMD-160 or SHA-256, and it does not apply
to schemes with per-position tweaks, which Script cannot afford.

*Tested.* `acw_alternate_codeword_exhaustive_*` tries the strongest evaluator forgery
(forward-hash every chain that can reach the target, reuse the rest) for every ordered pair
`c != c'` (118,000 pairs at `k=4, L=8`) on the native verifier, and the interpreter on small
spaces and a stride of larger ones. Every attempt is rejected. The forward-hashing proptest
never finds an accepted opening that decodes differently from the honest one.

### Theorem 3 (row privacy) — **[argued]**

In the ROM for `pad`, E's view of `payload(v(a'))` for any `a'` with `v(a') != v(a)` is
independent of the payload unless E queries `pad` on `seed(a')`. That query contains
`O'_j = x_{L-a'_j}` for the chain `j` above, which is a BackStep solution, so
`Adv^priv <= Adv^BackStep`. Rows whose value equals the opened value carry the same
payload and leak nothing new. `single_opening_unlocks_exactly_one_row` checks, for every
codeword at `(2,8)` and `(3,8)`, that the best-effort decryption of every other row fails and that
the reachable set from one opening is a singleton.

### Proposition 4 (key reuse breaks the guarantee) — **[exhaustive-tested]**

If G reveals two openings with the same keys, E unlocks every row `c <= max(a, a~)`
coordinatewise. At `k=2` that is the whole interval between the two values.
`key_reuse_equivocation_leaks_additional_labels` decrypts those rows end to end.
Consequence: **each commitment is one-time**. Bitcoin's single-spend rule enforces this
only if the commitment appears in exactly one script. A design where the same terminals appear
in two spendable branches does not enjoy the guarantee.

### Proposition 5 (public well-formedness) — **[tested]**

A garbler-chosen commitment can be defective: equal terminals within a digit (for Lamport
this leaves the bit unbound, for ACW a single opener serves two chains), equal terminals
across digits (openings become swappable), or wrong digest lengths.
`Commitment::validate` detects all of these from public data. A terminal that is not
`H^L(s)` for any secret the garbler holds is **not** detectable publicly; only the audit
that opens an instance's secrets (cut-and-choose) finds it
(`audit_detects_a_corrupted_terminal_that_validate_cannot`).

## 4. Assumptions

| # | Assumption | Used for |
|---|---|---|
| A1 | `H` is multi-target preimage resistant on iterated chain elements, up to the `L/2` image-shrinkage term | Theorems 2, 3 |
| A2 | `pad` (tagged SHA-256, counter mode) behaves as a random oracle | Theorem 3 |
| A3 | Chain secrets are fresh and unpredictable: derived from a 256-bit master seed with tagged SHA-256 and truncated to `n` bits | A1's premise |
| A4 | Bitcoin consensus and tapscript rules as implemented in Core 31.1: MINIMALIF, numeric opcodes, the 1000-element stack limit, single spend per outpoint | Lemma 1, Prop. 4 |
| A5 | Each commitment is used in exactly one script and one spend | Prop. 4 |
| A6 | Tables are honest or audited (cut-and-choose) | Theorem 1's payload part |
| A7 | The garbled-circuit layer (half-gates, AES-128 CCRND, free-XOR) is secure as ckt documents | Everything about *what the labels mean*; not analysed here |

Not claimed: UC security, composition with a particular bridge protocol, security of the GC layer,
resistance to structural attacks on RIPEMD-160/SHA-256, or any statement about Bitcoin's own
signature scheme.

## 5. Table integrity

Two checks protect against a dishonest garbler, and they have different power:

* **Value commitments** `C_v = tagged(ctx, v, payload)` are public. E checks every recovered
  payload against `C_v`. This catches a *swapped or corrupted row at use time* without any
  secret (`table_row_permutation_is_caught_by_audit_and_value_commitments`,
  `tampered_table_row_is_caught_by_the_value_commitment`). It does not prove the labels are the ones the
  garbled circuit was garbled with; that is the circuit commitment's job.
* **Audit** (`audit_digit_table`) recomputes every row from the opened chain secrets and checks the
  Merkle root. It is exact but needs the secrets, so it applies to the instances that cut-and-choose opens.

Row permutation by the garbler is therefore detected with certainty on opened instances and
at use time on every instance through `C_v`, provided `C_v` itself is bound to the circuit.

## 6. Quantum analysis

Generic-attack model only (`security.rs`; the numbers below are in `results/bench.json`).

**Grover.** Inverting an `n`-bit hash costs about `2^{n/2}` sequential iterations. With `T` targets
it is about `sqrt(2^n/T)`. Grover parallelises badly: `P` machines give only a `sqrt(P)` speed-up,
so the work figure is the right one to compare, not wall-clock. Each iteration also needs a
reversible hash circuit (thousands of gates), which the iteration count ignores.

| Digest | Evaluator-side classical | Evaluator-side quantum iterations (1k bits / 100k bits) | Collision (classical / BHT) |
|---|---|---|---|
| 160-bit (RIPEMD160, HASH160), ACW k=4 L=16 | 2^147 / 2^141 | **2^73.7 / 2^70.4** | 2^80 / 2^53 (+2^53 qRAM) |
| 256-bit (SHA256), ACW k=4 L=16 | 2^243 / 2^237 | **2^121.7 / 2^118.4** | 2^128 / 2^85 (+2^85 qRAM) |
| 160-bit, Lamport | 2^150 / 2^143 | 2^75 / 2^72 | same |

(Included: `log2 L` bits of chain loss and the multi-target factor.)

**Reading the table.**

1. For the script argument the figure that matters is the **evaluator-side** one. At 160 bits it
   is about `2^70`-`2^74` Grover iterations, above the `2^64` iterations of AES-128 key search
   that NIST uses for category 1, by iteration count alone. I have not re-derived gate-level
   costs, and the hash circuit per iteration is at least as large as an AES circuit.
2. Collision resistance is **not** used by the script argument (Theorem 2). The collision column
   matters only for hash commitments elsewhere (table roots, circuit commitments, the
   secret commitment). Those should be 256-bit.
3. Going to 256-bit chain digests raises the evaluator-side quantum cost to about `2^118`-`2^122` but costs
   `+26%` on-chain (10.55 vs 8.36 vB/bit at `k=4, L=16`).
4. The **label length is the binding limit.** ckt's labels are 128-bit (AES-128 CCRND). If an adversary can test a
   guessed label against something verifiable (a published commitment to the output
   secret), Grover gives `2^64` iterations. Digest size above about 160 bits adds nothing until
   the labels are widened, which `ckt-gobble` does not support.
5. Statistical cut-and-choose soundness (Mosaic's 181-choose-174, at least 40 bits) is unaffected by quantum computers.

**Recommended parameters** (for a stated target; each is the smallest that meets it):

| Goal | Chain digest | Hash commitments elsewhere | Labels |
|---|---|---|---|
| NIST-category-1-like (`>= 2^64` Grover iterations) | 160-bit (HASH160), `k=4`, `L=8` or `16` | SHA-256 | 128-bit (as now) |
| `>= 2^96` | SHA-256 chains (`k=4, L=16`: 10.55 vB/bit) | SHA-256 | needs 192-bit labels (not available in ckt) |
| `>= 2^128` | SHA-256 chains | SHA-256 / BLAKE3-256 | needs 256-bit labels |

Unless the labels are widened, the system's quantum security is capped by the labels at about
`2^64`; a 160-bit digest already matches that cap, and SHA-256 chains buy margin only on the Script side.

## 7. What the tests do and do not show

* Tests show: the script accepts exactly the antichain (small `(k,L)`), forged and
  malformed witnesses are rejected by the script and by Core, `native == script` on garbage,
  key reuse leaks as predicted, tampered tables are detected, and every 16-bit claim
  evaluates correctly through ckt-gobble.
* Tests do **not** show: security at the real parameters (that rests on A1 and the argument above),
  absence of structural attacks on the hashes, or anything about a deployed bridge.
* The interpreter used for fast tests (`bitcoin-scriptexec`) differs from Core on one boundary
  (initial stack limit for no-bit Lamport: 999 vs Core's 998 digits). Core is treated as the authority
  and the regtest harness records both numbers.
