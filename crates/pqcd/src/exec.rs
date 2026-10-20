//! Tapscript execution harness around `bitcoin-scriptexec`.
//!
//! Two deliberate choices differ from the upstream default: `OP_CAT` is disabled
//! (the question is about opcodes enabled today; upstream turns an experimental
//! implementation on by default), and the minimal-encoding rule is selectable so a
//! test can say whether a witness is *consensus*-valid or also *policy*-standard.

use std::time::Instant;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all as op;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::{ScriptBuf, Transaction};
use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};

/// Which rule set to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Consensus only: non-minimal script numbers are tolerated.
    Consensus,
    /// Consensus plus the standardness rules that matter here (minimal pushes and numbers).
    Policy,
}

/// Result of one script execution.
#[derive(Clone, Debug)]
pub struct ExecReport {
    /// The script finished with exactly one true element.
    pub ok: bool,
    /// Failure description, if any.
    pub error: Option<String>,
    /// Instructions the interpreter stepped through (taken and untaken branches).
    pub steps: u64,
    /// Opcodes actually executed (untaken branch bodies excluded, pushes excluded).
    pub ops_executed: u64,
    /// Hash opcodes executed (`OP_RIPEMD160`, `OP_SHA256`, `OP_HASH160`).
    pub hash_ops: u64,
    /// Peak of stack + altstack depth.
    pub max_stack: usize,
    /// Wall time of the execution in microseconds.
    pub micros: u128,
}

fn options(mode: Mode) -> Options {
    Options {
        require_minimal: mode == Mode::Policy,
        verify_cltv: true,
        verify_csv: true,
        verify_minimal_if: true,
        enforce_stack_limit: true,
        experimental: Experimental { op_cat: false },
    }
}

/// Run `script` against the initial witness `stack` under Tapscript rules.
pub fn run(script: &ScriptBuf, stack: &[Vec<u8>], mode: Mode) -> ExecReport {
    let t0 = Instant::now();
    let exec = Exec::new(
        ExecCtx::Tapscript,
        options(mode),
        TxTemplate {
            tx: Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![], output: vec![] },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script.clone(),
        stack.to_vec(),
    );
    let mut exec = match exec {
        Ok(e) => e,
        Err(e) => {
            return ExecReport {
                ok: false,
                error: Some(format!("{e:?}")),
                steps: 0,
                ops_executed: 0,
                hash_ops: 0,
                max_stack: 0,
                micros: t0.elapsed().as_micros(),
            }
        }
    };
    let (mut steps, mut ops_executed, mut hash_ops) = (0u64, 0u64, 0u64);
    let hash_bytes = [op::OP_RIPEMD160.to_u8(), op::OP_SHA256.to_u8(), op::OP_HASH160.to_u8()];
    loop {
        let active = exec.cond_stack().all_true();
        let next = exec.remaining_script().as_bytes().first().copied();
        if let Some(b) = next {
            steps += 1;
            // Push opcodes are 0x00..=0x4e; everything above is an operation.
            if active && b > 0x4e {
                ops_executed += 1;
                if hash_bytes.contains(&b) {
                    hash_ops += 1;
                }
            }
        }
        if let Err(res) = exec.exec_next() {
            let (ok, error) = (res.success, res.error.as_ref().map(|e| format!("{e:?}")));
            let max_stack = exec.stats().max_nb_stack_items;
            return ExecReport { ok, error, steps, ops_executed, hash_ops, max_stack, micros: t0.elapsed().as_micros() };
        }
    }
}

/// Convenience: does the script accept the stack?
pub fn accepts(script: &ScriptBuf, stack: &[Vec<u8>], mode: Mode) -> bool {
    run(script, stack, mode).ok
}
