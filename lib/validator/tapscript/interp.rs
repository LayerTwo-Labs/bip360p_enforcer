//! Fail-closed subset-Tapscript stack interpreter for BIP360+ leaf enforcement.
//!
//! This executes a revealed Taproot v1 (leaf version `0xc0`) leaf that contains
//! a BIP360+ opcode, under BIP342 stack semantics, and requires it to evaluate
//! to a single truthy element. It is deliberately a **subset**: only the opcodes
//! needed to give the BIP360+ opcodes meaning are implemented; every other
//! opcode — including standard ones not yet needed and the reserved future
//! BIP360+ bytes — is rejected (`UnimplementedOpcode` / `ReservedOpcode`). The
//! implemented set grows as CTV (Phase 5) and OP_VAULT (Phase 6) land.
//!
//! Fail-closed is the guiding rule: any underflow, oversized element, malformed
//! script, unknown opcode, or non-true final stack is a rejection.

use bitcoin::{
    Script, Transaction,
    blockdata::opcodes::{Opcode, all as opcodes},
    consensus::encode::serialize as consensus_serialize,
    hashes::{Hash as _, hash160, ripemd160, sha256, sha256d},
    script::Instruction,
};
use thiserror::Error;

use super::{OP_CAT, OP_CTV, OP_VAULT, OP_VAULT_RECOVER};

/// BIP119 template-hash / OP_CTV argument size.
const CTV_HASH_LEN: usize = 32;

/// Maximum size (bytes) of a single stack element (BIP347 keeps the 520-byte
/// script-element limit for `OP_CAT`).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of elements on the stack at any point (matches Bitcoin's
/// `MAX_STACK_SIZE`).
pub const MAX_STACK_SIZE: usize = 1000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InterpError {
    #[error("leaf script could not be parsed")]
    MalformedScript,
    #[error("stack underflow executing {opcode}")]
    StackUnderflow { opcode: &'static str },
    #[error("stack element exceeds {MAX_SCRIPT_ELEMENT_SIZE} bytes (got {size})")]
    ElementTooLarge { size: usize },
    #[error("stack exceeds {MAX_STACK_SIZE} elements")]
    StackOverflow,
    #[error("reserved BIP360+ opcode {byte:#04x} is not yet active")]
    ReservedOpcode { byte: u8 },
    #[error("OP_CHECKTEMPLATEVERIFY argument is not {CTV_HASH_LEN} bytes (got {len})")]
    CtvBadArgLength { len: usize },
    #[error("OP_CHECKTEMPLATEVERIFY template hash mismatch")]
    CtvTemplateMismatch,
    #[error("opcode {opcode} is not implemented by the BIP360+ interpreter")]
    UnimplementedOpcode { opcode: Opcode },
    #[error("OP_VERIFY / *VERIFY failed")]
    VerifyFailed,
    #[error("script left {n} elements; exactly one is required")]
    CleanStackRequired { n: usize },
    #[error("script evaluated to false")]
    EvalFalse,
}

/// A BIP342-style execution stack of byte-vector elements.
struct Stack {
    items: Vec<Vec<u8>>,
}

impl Stack {
    fn new(initial: Vec<Vec<u8>>) -> Result<Self, InterpError> {
        for item in &initial {
            if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(InterpError::ElementTooLarge { size: item.len() });
            }
        }
        if initial.len() > MAX_STACK_SIZE {
            return Err(InterpError::StackOverflow);
        }
        Ok(Self { items: initial })
    }

    fn push(&mut self, item: Vec<u8>) -> Result<(), InterpError> {
        if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(InterpError::ElementTooLarge { size: item.len() });
        }
        self.items.push(item);
        if self.items.len() > MAX_STACK_SIZE {
            return Err(InterpError::StackOverflow);
        }
        Ok(())
    }

    fn pop(&mut self, opcode: &'static str) -> Result<Vec<u8>, InterpError> {
        self.items
            .pop()
            .ok_or(InterpError::StackUnderflow { opcode })
    }

    /// Peek the top element without popping (for verify-in-place opcodes).
    fn top(&self, opcode: &'static str) -> Result<&[u8], InterpError> {
        self.items
            .last()
            .map(Vec::as_slice)
            .ok_or(InterpError::StackUnderflow { opcode })
    }
}

/// Bitcoin's `CastToBool`: an element is true unless it is empty, all-zero, or
/// all-zero with a `0x80` sign byte (negative zero).
fn is_truthy(v: &[u8]) -> bool {
    for (i, &b) in v.iter().enumerate() {
        if b != 0 {
            return !(i == v.len() - 1 && b == 0x80);
        }
    }
    false
}

/// BIP119 `DefaultCheckTemplateVerifyHash` of `tx` at `input_index`.
///
/// Single-SHA256 over: nVersion (4 LE signed), nLockTime (4 LE), the scriptSigs
/// hash (only if any input has a non-empty scriptSig), input count (4 LE), the
/// sequences hash, output count (4 LE), the outputs hash, and the input index
/// (4 LE). Each sub-hash is a single SHA256.
pub fn default_check_template_verify_hash(tx: &Transaction, input_index: usize) -> [u8; 32] {
    let sha = |data: &[u8]| sha256::Hash::hash(data).to_byte_array();

    let mut seq_bytes = Vec::with_capacity(tx.input.len() * 4);
    for input in &tx.input {
        seq_bytes.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    }
    let sequences_hash = sha(&seq_bytes);

    let mut out_bytes = Vec::new();
    for output in &tx.output {
        out_bytes.extend_from_slice(&consensus_serialize(output));
    }
    let outputs_hash = sha(&out_bytes);

    let mut r = Vec::new();
    r.extend_from_slice(&tx.version.0.to_le_bytes());
    r.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    if tx.input.iter().any(|i| !i.script_sig.is_empty()) {
        let mut ss = Vec::new();
        for input in &tx.input {
            ss.extend_from_slice(&consensus_serialize(&input.script_sig));
        }
        r.extend_from_slice(&sha(&ss));
    }
    r.extend_from_slice(&(tx.input.len() as u32).to_le_bytes());
    r.extend_from_slice(&sequences_hash);
    r.extend_from_slice(&(tx.output.len() as u32).to_le_bytes());
    r.extend_from_slice(&outputs_hash);
    r.extend_from_slice(&(input_index as u32).to_le_bytes());
    sha(&r)
}

/// Execute a revealed BIP360+ leaf against the initial witness stack. Returns
/// `Ok(())` iff execution leaves exactly one truthy element. `tx`/`input_index`
/// identify the spending transaction and the input being validated, for opcodes
/// that introspect the transaction (e.g. OP_CHECKTEMPLATEVERIFY).
pub fn execute_leaf(
    tx: &Transaction,
    input_index: usize,
    leaf: &Script,
    initial_stack: Vec<Vec<u8>>,
) -> Result<(), InterpError> {
    let mut stack = Stack::new(initial_stack)?;

    for instruction in leaf.instructions() {
        match instruction.map_err(|_| InterpError::MalformedScript)? {
            Instruction::PushBytes(bytes) => stack.push(bytes.as_bytes().to_vec())?,
            Instruction::Op(op) => exec_op(op, &mut stack, tx, input_index)?,
        }
    }

    match stack.items.len() {
        1 if is_truthy(&stack.items[0]) => Ok(()),
        1 => Err(InterpError::EvalFalse),
        n => Err(InterpError::CleanStackRequired { n }),
    }
}

fn exec_op(
    op: Opcode,
    stack: &mut Stack,
    tx: &Transaction,
    input_index: usize,
) -> Result<(), InterpError> {
    let byte = op.to_u8();

    // BIP360+ opcodes are dispatched by raw byte: they occupy the high
    // OP_SUCCESSx range (0xfb–0xfe), which the `bitcoin` crate does not give
    // dedicated names — and note our OP_CAT is byte 0xfe, NOT the crate's
    // historical `OP_CAT` (0x7e).
    if byte == OP_CAT {
        // OP_CAT (0xfe) — BIP347. Pop x2 (top) and x1, push x1 || x2.
        let x2 = stack.pop("OP_CAT")?;
        let x1 = stack.pop("OP_CAT")?;
        let mut cat = x1;
        cat.extend_from_slice(&x2);
        if cat.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(InterpError::ElementTooLarge { size: cat.len() });
        }
        return stack.push(cat);
    }
    if byte == OP_CTV {
        // OP_CHECKTEMPLATEVERIFY (0xfd) — BIP119. Verify-in-place: the top
        // element must be the 32-byte DefaultCheckTemplateVerifyHash of the
        // spending tx at this input; the element is NOT popped. Fail-closed on a
        // non-32-byte argument (fresh OP_SUCCESS deployment, no OP_NOP4 legacy).
        let arg = stack.top("OP_CHECKTEMPLATEVERIFY")?;
        if arg.len() != CTV_HASH_LEN {
            return Err(InterpError::CtvBadArgLength { len: arg.len() });
        }
        if arg != default_check_template_verify_hash(tx, input_index) {
            return Err(InterpError::CtvTemplateMismatch);
        }
        return Ok(());
    }
    // Reserved future BIP360+ opcodes: recognized but not yet active.
    if byte == OP_VAULT || byte == OP_VAULT_RECOVER {
        return Err(InterpError::ReservedOpcode { byte });
    }

    match op {
        // Small-number pushes.
        opcodes::OP_PUSHNUM_1
        | opcodes::OP_PUSHNUM_2
        | opcodes::OP_PUSHNUM_3
        | opcodes::OP_PUSHNUM_4
        | opcodes::OP_PUSHNUM_5
        | opcodes::OP_PUSHNUM_6
        | opcodes::OP_PUSHNUM_7
        | opcodes::OP_PUSHNUM_8
        | opcodes::OP_PUSHNUM_9
        | opcodes::OP_PUSHNUM_10
        | opcodes::OP_PUSHNUM_11
        | opcodes::OP_PUSHNUM_12
        | opcodes::OP_PUSHNUM_13
        | opcodes::OP_PUSHNUM_14
        | opcodes::OP_PUSHNUM_15
        | opcodes::OP_PUSHNUM_16 => {
            let n = byte - (opcodes::OP_PUSHNUM_1.to_u8() - 1); // 1..=16
            stack.push(vec![n])
        }

        // Stack ops.
        opcodes::OP_DUP => {
            let top = stack.pop("OP_DUP")?;
            stack.push(top.clone())?;
            stack.push(top)
        }
        opcodes::OP_DROP => {
            stack.pop("OP_DROP")?;
            Ok(())
        }
        opcodes::OP_SWAP => {
            let a = stack.pop("OP_SWAP")?;
            let b = stack.pop("OP_SWAP")?;
            stack.push(a)?;
            stack.push(b)
        }

        // Equality / verification.
        opcodes::OP_EQUAL => {
            let a = stack.pop("OP_EQUAL")?;
            let b = stack.pop("OP_EQUAL")?;
            stack.push(if a == b { vec![1] } else { vec![] })
        }
        opcodes::OP_EQUALVERIFY => {
            let a = stack.pop("OP_EQUALVERIFY")?;
            let b = stack.pop("OP_EQUALVERIFY")?;
            if a == b {
                Ok(())
            } else {
                Err(InterpError::VerifyFailed)
            }
        }
        opcodes::OP_VERIFY => {
            let top = stack.pop("OP_VERIFY")?;
            if is_truthy(&top) {
                Ok(())
            } else {
                Err(InterpError::VerifyFailed)
            }
        }

        // Hash functions.
        opcodes::OP_SHA256 => {
            let top = stack.pop("OP_SHA256")?;
            stack.push(sha256::Hash::hash(&top).to_byte_array().to_vec())
        }
        opcodes::OP_HASH256 => {
            let top = stack.pop("OP_HASH256")?;
            stack.push(sha256d::Hash::hash(&top).to_byte_array().to_vec())
        }
        opcodes::OP_HASH160 => {
            let top = stack.pop("OP_HASH160")?;
            stack.push(hash160::Hash::hash(&top).to_byte_array().to_vec())
        }
        opcodes::OP_RIPEMD160 => {
            let top = stack.pop("OP_RIPEMD160")?;
            stack.push(ripemd160::Hash::hash(&top).to_byte_array().to_vec())
        }

        // Everything else — including standard opcodes not yet needed and any
        // signature-checking opcodes — is fail-closed rejected.
        other => Err(InterpError::UnimplementedOpcode { opcode: other }),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        OutPoint, ScriptBuf, Sequence, TxIn, Witness, locktime::absolute::LockTime,
        script::Builder, transaction::Version,
    };

    use super::*;

    /// A minimal single-input spending tx for opcodes that don't introspect it.
    fn dummy_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        }
    }

    fn run(leaf: &Script, stack: Vec<Vec<u8>>) -> Result<(), InterpError> {
        execute_leaf(&dummy_tx(), 0, leaf, stack)
    }

    #[test]
    fn op_cat_concatenates_and_checks_hash() {
        // Leaf: OP_CAT OP_SHA256 <expected> OP_EQUAL — reconstruct "abcd" from
        // two witness pushes, hash it, compare.
        let expected = sha256::Hash::hash(b"abcd").to_byte_array().to_vec();
        let leaf = Builder::new()
            .push_opcode(Opcode::from(super::OP_CAT))
            .push_opcode(opcodes::OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(expected.as_slice()).unwrap())
            .push_opcode(opcodes::OP_EQUAL)
            .into_script();
        // witness stack: x1="ab", x2="cd" (x2 on top)
        run(&leaf, vec![b"ab".to_vec(), b"cd".to_vec()]).expect("valid CAT spend");
        // Wrong pieces → EvalFalse.
        assert!(run(&leaf, vec![b"ax".to_vec(), b"cd".to_vec()]).is_err());
    }

    #[test]
    fn op_cat_underflow_rejected() {
        let leaf = Builder::new()
            .push_opcode(Opcode::from(super::OP_CAT))
            .into_script();
        assert_eq!(
            run(&leaf, vec![b"only-one".to_vec()]),
            Err(InterpError::StackUnderflow { opcode: "OP_CAT" })
        );
    }

    #[test]
    fn op_cat_oversize_rejected() {
        let leaf = Builder::new()
            .push_opcode(Opcode::from(super::OP_CAT))
            .into_script();
        let big = vec![0u8; 300];
        let err = run(&leaf, vec![big.clone(), big]).unwrap_err();
        assert!(matches!(err, InterpError::ElementTooLarge { size: 600 }));
    }

    #[test]
    fn reserved_opcodes_rejected() {
        // OP_CTV (0xfd) is now implemented; only OP_VAULT/OP_VAULT_RECOVER remain reserved.
        for byte in [OP_VAULT, OP_VAULT_RECOVER] {
            let leaf = Builder::new().push_opcode(Opcode::from(byte)).into_script();
            assert_eq!(
                run(&leaf, vec![]),
                Err(InterpError::ReservedOpcode { byte })
            );
        }
    }

    /// A leaf `<hash> OP_CTV` where <hash> is the correct template hash of the
    /// spending tx must accept; a wrong hash and a non-32-byte arg must reject.
    #[test]
    fn op_ctv_matches_template() {
        let tx = dummy_tx();
        let good = default_check_template_verify_hash(&tx, 0);
        let ctv_leaf = |hash: &[u8]| {
            Builder::new()
                .push_slice(<&bitcoin::script::PushBytes>::try_from(hash).unwrap())
                .push_opcode(Opcode::from(OP_CTV))
                .into_script()
        };
        // Correct template hash: CTV leaves the (truthy) hash on the stack -> accept.
        execute_leaf(&tx, 0, &ctv_leaf(&good), vec![]).expect("matching CTV template");
        // Wrong hash -> mismatch.
        let mut bad = good;
        bad[0] ^= 0x01;
        assert_eq!(
            execute_leaf(&tx, 0, &ctv_leaf(&bad), vec![]),
            Err(InterpError::CtvTemplateMismatch)
        );
        // Non-32-byte argument -> fail-closed.
        assert_eq!(
            execute_leaf(&tx, 0, &ctv_leaf(&[0u8; 16]), vec![]),
            Err(InterpError::CtvBadArgLength { len: 16 })
        );
    }

    /// Proof of BIP119 compliance: our DefaultCheckTemplateVerifyHash matches a
    /// representative subset of BIP119's authoritative `ctvhash.json` vectors
    /// (scriptSig present/absent, single/multi input, single/multi output, and
    /// edge input indices). The full set was verified against this same code.
    #[test]
    fn bip119_ctvhash_golden_vectors() {
        let json = include_str!("vectors/ctvhash.json");
        let entries: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        let mut checked = 0usize;
        for entry in &entries {
            let Some(hex_tx) = entry.get("hex_tx").and_then(|v| v.as_str()) else {
                continue; // skip the leading format-description string
            };
            let tx: Transaction =
                bitcoin::consensus::encode::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();
            let indices = entry["spend_index"].as_array().unwrap();
            let results = entry["result"].as_array().unwrap();
            for (idx, res) in indices.iter().zip(results) {
                let input_index = idx.as_u64().unwrap() as usize;
                let expected = hex::decode(res.as_str().unwrap()).unwrap();
                assert_eq!(
                    default_check_template_verify_hash(&tx, input_index).as_slice(),
                    expected.as_slice(),
                    "CTV hash mismatch at spend_index {input_index} for tx {hex_tx}"
                );
                checked += 1;
            }
        }
        assert!(
            checked > 20,
            "expected the representative BIP119 vector set, got {checked}"
        );
    }

    #[test]
    fn unimplemented_opcode_fails_closed() {
        // OP_CHECKSIG is deliberately not implemented in Phase 4.
        let leaf = Builder::new()
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();
        assert!(matches!(
            run(&leaf, vec![vec![1], vec![1]]),
            Err(InterpError::UnimplementedOpcode { .. })
        ));
    }

    #[test]
    fn non_clean_or_false_stack_rejected() {
        // Two leftover elements → CleanStackRequired.
        let leaf = Builder::new()
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .into_script();
        assert_eq!(
            run(&leaf, vec![]),
            Err(InterpError::CleanStackRequired { n: 2 })
        );
        // Single false element → EvalFalse.
        let leaf_false = Builder::new().into_script();
        assert_eq!(run(&leaf_false, vec![vec![]]), Err(InterpError::EvalFalse));
    }
}
