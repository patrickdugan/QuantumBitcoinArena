### A. Measured on Bitcoin Core 31.1 regtest, 1,024-bit reveal (accepted spends)

| scheme | inputs | tx vbytes (Core) | vB/bit | vs Lamport |
|---|---:|---:|---:|---:|
| lamport-ripemd160 | 3 | 18,499 | 18.07 | +0.0% |
| lamport-nobit-ripemd160 | 2 | 18,064 | 17.64 | -2.4% |
| acw-k2-l16-hash160 | 1 | 11,677 | 11.40 | -36.9% |
| acw-k4-l8-hash160 | 1 | 9,657 | 9.43 | -47.8% |
| acw-k4-l16-hash160 | 1 | 8,735 | 8.53 | -52.8% |
| acw-k4-l16-sha256 | 1 | 10,991 | 10.73 | -40.6% |
| schnorr-adaptor (real BIP-340 sigs, not PQ) | 1 | 3,292 | 3.21 | -82.2% |

### B. Scaling (transaction vbytes incl. per-input overhead; packed into standard-size transactions)

| scheme | 1,056 bits | inputs/tx | 10,000 | inputs/tx | 100,000 | inputs/tx |
|---|---:|---:|---:|---:|---:|---:|
| lamport-ripemd160 | 19,051 | 3/1 | 179,869 | 21/2 | 1,798,355 | 203/21 |
| lamport-nobit-ripemd160 | 18,604 | 2/1 | 175,606 | 11/2 | 1,755,678 | 102/21 |
| lamport-sha256 | 28,555 | 3/1 | 269,890 | 21/3 | 2,698,527 | 203/29 |
| acw-k2-l16-hash160 | 12,019 | 1/1 | 113,578 | 8/2 | 1,135,424 | 76/13 |
| acw-k4-l8-hash160 | 9,936 | 1/1 | 93,881 | 9/1 | 938,760 | 89/10 |
| acw-k4-l16-hash160 | 8,898 | 1/1 | 84,039 | 7/1 | 839,315 | 65/10 |
| acw-k4-l16-sha256 | 11,202 | 1/1 | 105,900 | 7/2 | 1,057,564 | 65/13 |
| acw-k5-l16-hash160 | 8,250 | 1/1 | 77,210 | 7/1 | 771,281 | 61/9 |
| schnorr-adaptor (model; not PQ) | 3,372 | 1/1 | 31,374 | 2/1 | 313,249 | 13/4 |

### C. Per-bit metrics at 10,000 bits

| scheme | auth. bytes/bit (script+items) | witness bytes/bit | vB/bit (tx) | hash ops/bit | opcodes/bit | commit ms | open ms | verify ms | exec ms | peak heap (commit) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| lamport-ripemd160 | 71.5 | 71.6 | 17.99 | 1.00 | 4.0 | 41 | 12 | 21 | 33 | 1.12 MB |
| lamport-nobit-ripemd160 | 70.0 | 70.0 | 17.56 | 1.00 | 7.0 | 53 | 12 | 17 | 49 | 1.12 MB |
| lamport-sha256 | 107.5 | 107.6 | 26.99 | 1.00 | 4.0 | 25 | 14 | 11 | 31 | 1.36 MB |
| acw-k2-l16-hash160 | 45.3 | 45.3 | 11.36 | 3.75 | 16.0 | 66 | 53 | 47 | 65 | 0.28 MB |
| acw-k4-l8-hash160 | 37.4 | 37.4 | 9.39 | 1.75 | 11.1 | 37 | 30 | 19 | 33 | 0.25 MB |
| acw-k4-l16-hash160 | 33.5 | 33.5 | 8.40 | 2.73 | 11.8 | 47 | 49 | 30 | 58 | 0.18 MB |
| acw-k4-l16-sha256 | 42.2 | 42.2 | 10.59 | 2.73 | 11.8 | 24 | 34 | 18 | 31 | 0.23 MB |
| acw-k5-l16-hash160 | 30.7 | 30.8 | 7.72 | 2.47 | 10.9 | 45 | 38 | 26 | 37 | 0.16 MB |

### D. Off-chain label tables (ACW), payload = one 16-byte label per digit bit

| scheme | codewords N | bits/digit | table bytes per digit | **bytes per message bit** | build ms/digit | table for 1,056 bits |
|---|---:|---:|---:|---:|---:|---:|
| acw-k2-l16-hash160 | 16 | 4 | 1,056 | 264 | 0.06 | 0.3 MB |
| acw-k4-l8-hash160 | 344 | 8 | 44,064 | 5,508 | 1.46 | 5.8 MB |
| acw-k4-l16-hash160 | 2,736 | 11 | 481,568 | 43,779 | 19.58 | 46.2 MB |
| acw-k4-l16-sha256 | 2,736 | 11 | 481,568 | 43,779 | 20.70 | 46.2 MB |
| acw-k5-l16-hash160 | 39,280 | 15 | 9,427,232 | 628,482 | 313.68 | 669.3 MB |

### E. Security estimates (generic attacks; log2 of work)

| scheme | bits | evaluator classical | evaluator quantum (Grover iterations) |
|---|---:|---:|---:|
| lamport-ripemd160 | 1,056 | 150.0 | 75.0 |
| lamport-ripemd160 | 100,000 | 143.4 | 71.7 |
| acw-k4-l8-hash160 | 1,056 | 148.0 | 74.0 |
| acw-k4-l8-hash160 | 100,000 | 141.4 | 70.7 |
| acw-k4-l16-hash160 | 1,056 | 147.4 | 73.7 |
| acw-k4-l16-hash160 | 100,000 | 140.8 | 70.4 |
| acw-k4-l16-sha256 | 1,056 | 243.4 | 121.7 |
| acw-k4-l16-sha256 | 100,000 | 236.8 | 118.4 |

### F. Initial-stack limit per input (Core is the authority)

| scheme | items/digit | max digits (Core) | max message bits per input | interpreter says |
|---|---:|---:|---:|---:|
| lamport-nobit-ripemd160 | 1 | 998 | 998 | 999 |
| lamport-ripemd160 | 2 | 500 | 500 | 500 |
| acw-k4-l8-hash160 | 7 | 142 | 1,136 | 142 |
| acw-k4-l16-hash160 | 7 | 142 | 1,562 | 142 |
