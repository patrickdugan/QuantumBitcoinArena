//! # pqcd: hash-based conditional disclosure of garbled-circuit input labels
//!
//! Research prototype. It implements, from the ground up and with its own Script
//! generator, three ways for a Bitcoin verifier to authenticate which input label
//! a garbler reveals: per-bit Lamport, Antichain Winternitz (ACW), and the
//! Schnorr-adaptor reveal used by Mosaic today (cost model only). See `docs/`.

pub mod baseline;
pub mod codeword;
pub mod exec;
pub mod gadget;
pub mod hash;
pub mod metrics;
pub mod scheme;
pub mod taproot;

pub use codeword::CodewordSpace;
pub use hash::HashKind;
pub use scheme::{Commitment, Opening, Scheme, SecretKey, VerifyError};
