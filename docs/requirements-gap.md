# What is still missing for a maliciously secure, post-quantum conditional disclosure

Scope: Mosaic (`alpenlabs/mosaic` @ c01b70d, spec + code read, **not run**; it needs a
FoundationDB cluster), ckt (`alpenlabs/ckt`, tag v0.4.0 used), duty-free-bits
(`alpenlabs/duty-free-bits` @ 1946270), and the ACW paper abstract (ePrint 2026/1568). I read
the Mosaic specification, `crates/vs3`, `crates/adaptor-sigs`, `crates/cac/types`,
`crates/common/constants.rs` and the ckt/gobble translation layer. I did not audit any of them.
The Mosaic paper (ePrint 2026/812) page I could fetch states **no quantum-security analysis**.

## 1. Requirements and status

| # | Requirement for malicious security of conditional disclosure | Status with this work | Notes |
|---|---|---|---|
| R1 | **Guaranteed revelation**: any witness the verifier accepts gives the evaluator labels for exactly one input value | **Met** (Theorem 1, unconditional given an honest table) | Table must cover every admissible codeword; `rank mod 2^b` makes the map total. |
| R2 | **No extra labels**: from one reveal the evaluator cannot derive labels for another value | **Met under A1/A2** (Theorems 2-3) | Needs one-time keys (Prop. 4) and preimage resistance with the `L/2` chain term. |
| R3 | **Authenticated input**: a third party cannot substitute a different input | **Met** (same argument) | Forging = backward step on some chain. |
| R4 | **Circuit correctness against a malicious garbler** (cut-and-choose) | Not touched | Mosaic: 181 circuits, 174 opened, `>= 2^40` statistical. Not a quantum issue. |
| R5 | **Input-label consistency across the N garbled copies** | **NOT MET, and it is the hard one** | See section 2. |
| R6 | **Fault secret is usable by a post-quantum spend** | **NOT MET in Mosaic; easy to fix** | See section 3. |
| R7 | **Atomic complete reveal** | Met at bridge size, **not above ~1.5k bits** | One input holds at most 142 ACW digits (k=4): 1,562 bits at L=16, 1,136 at L=8. Mosaic's 1,024-1,056 bits fit one input of one transaction. Beyond ~1.5k bits several inputs are needed, and past ~100 kvB several transactions, which breaks atomicity: a garbler can reveal part of the input. |
| R8 | **Output-label authenticity at a post-quantum margin** | **Capped at ~2^64** | ckt labels are 128-bit; widening needs changes in `ckt-gobble` (hard-wired 16-byte labels, AES-128 CCRND). |
| R9 | **Soundness of the verified statement** | **NOT MET** | Mosaic's circuit is a Groth16 verifier (pairing-based). |
| R10 | **Output type / key path** | **NOT MET, outside protocol control** | See section 4. |

## 2. R5, label consistency: where quantum-vulnerable primitives sit

Mosaic makes input labels *polynomially correlated* across the N garbled copies: each
wire-value has a degree-`t` polynomial over the **secp256k1 scalar field** (`vs3`:
`ark_secp256k1::Fr`, commitments are `Projective` points, one commitment per coefficient).
The evaluator checks opened shares against the **elliptic-curve** polynomial commitment, which is
what forces the unopened copies' labels to lie on the same polynomial. The only value released at
withdrawal is the share at index 0.

What survives, and where (all read from source, none run):

* **VS3 polynomial commitments** (`PolynomialCommitment`, `ShareCommitment`): discrete-log based.
  A quantum adversary recovers every committed coefficient from the points, so the evaluator-side
  secrets (the polynomial's constant terms = labels) are no longer hidden. This breaks R2
  at the protocol level even if the on-chain reveal is hash-based.
* **`input_share_commitments`** and the **output commitment** (`Point`): same primitive.
* **BIP-340 adaptor signatures** (`adaptor-sigs`): the current reveal mechanism. This is
  exactly the piece ACW replaces. ACW does *not* replace the commitments above.

What a hash-only replacement lacks: the **homomorphism** that lets the evaluator check that
unopened shares lie on a committed polynomial without seeing them. Candidate routes, none
implemented here:

1. A post-quantum homomorphic commitment (lattice / SIS-style) in place of the EC commitments.
   Larger, but a drop-in for the verification equation. Needs its own review.
2. Hash commitments to every per-copy label plus a hash-based proof (STARK) of correct sharing. Post-quantum
   with only symmetric assumptions, but heavy.
3. Per-copy label commitments (hashes) checked at reveal time, with a dispute path. The dispute
   would need the label-derivation relation to be checkable in Script, which without
   concatenation (`OP_CAT`) and with 520-byte-class limits is not practical today.

I treat R5 as the principal open requirement. This crate gives the on-chain half of the
reveal only.

## 3. R6, the fault secret

ckt's output translation yields a 256-bit secret when the output is `false`. In the Mosaic spec the
recovered secret is a secp256k1 `Scalar` checked against a `Point` commitment
(`candidate_secret.commit == secret_commit`, where `secret_commit` is the zeroth coefficient of the
output polynomial's EC commitment). I did not trace how Bridge Core then spends with it, so I make
only the narrower claim: **the check itself is discrete-log based**, and a quantum adversary can
recover the committed scalar from the point without any fault. If the slash path is also an EC
signature the dependency is end to end. Making the secret a **hash preimage**
(`OP_SHA256 <h> OP_EQUALVERIFY` in the slash script, `h` published) removes it. The tiny-circuit
integration in `pqcd-ckt` commits to the secret with a hash and checks that the recovered value
verifies against it.

## 4. R10, Taproot itself

Every Taproot output carries a tweaked public key `Q = P + t*G` that is visible on chain.
A cryptographically relevant quantum computer solves the discrete log of `Q` and spends via the
**key path**, ignoring the script tree. A NUMS internal key (used throughout this crate) makes the key path
unspendable *classically* but does nothing against this. So a hash-locked leaf inside Taproot is not
post-quantum as an *output*.

Alternatives today fail on limits: a P2WSH script is limited to 201 non-push opcodes (counted
over the whole script, executed or not), 100 standard stack items, and ~3,600 bytes standard.
Measured on the generated leaves (`examples/opcount.rs`): one ACW digit costs 168 non-push
opcodes at `k=4, L=16` and 108 at `k=4, L=8`, so a P2WSH script carries **one digit** (11 or 8
bits); Lamport costs 7 per bit, about 28 bits per script. The scripts here port to a future script-only
output type that keeps Tapscript semantics (the proposals for a pay-to-Merkle-root type that
removes the key path), but that requires a soft fork. I did not test any such proposal.

## 5. Other survivors, ranked by how much they matter

| Survivor | Where | Effect | Replacement |
|---|---|---|---|
| Groth16 (BN254 pairing) verifier | Mosaic's `g16.v5c` circuit | A quantum adversary forges proofs, so the circuit accepts invalid withdrawals. The garbled circuit faithfully evaluates a broken statement. | A hash-based (STARK) verifier garbled instead: far larger circuit, not evaluated here. |
| secp256k1 everywhere else in the bridge | presigned transaction graph, deposit keys | Funds spendable by the key path / signatures | Protocol-wide change; out of scope. |
| Peer identity: Ed25519, QUIC/TLS | `bin/mosaic-peer-id`, `crates/net` | Impersonation / DoS; not a direct forgery of the disclosure | PQ TLS / signatures. |
| Base OT (public-key) for **evaluator inputs** | not in Mosaic (evaluator has no private input); *is* in the BABE/Argo-style designs that duty-free-bits targets | Evaluator-input privacy | PQ base OT. duty-free-bits itself is a symmetric-key transformation "plus base OTs". |
| Output-label length 128 | ckt-gobble | ~2^64 Grover | 192/256-bit labels. |

## 6. One-line summary

The on-chain reveal can be made hash-based and cheaper than Lamport, and this crate shows how. A
post-quantum conditional disclosure needs four more things: a post-quantum replacement for the
EC polynomial commitments (R5), a hash-preimage fault secret (R6), a hash-based verified statement (R9),
and a Taproot-free output type (R10).
