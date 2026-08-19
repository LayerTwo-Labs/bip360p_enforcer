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
    Script,
    blockdata::opcodes::{Opcode, all as opcodes},
    hashes::{Hash as _, hash160, ripemd160, sha256, sha256d},
    script::Instruction,
};
use thiserror::Error;

use super::{OP_CAT, OP_CTV, OP_VAULT, OP_VAULT_RECOVER};

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

/// Execute a revealed BIP360+ leaf against the initial witness stack. Returns
/// `Ok(())` iff execution leaves exactly one truthy element.
pub fn execute_leaf(leaf: &Script, initial_stack: Vec<Vec<u8>>) -> Result<(), InterpError> {
    let mut stack = Stack::new(initial_stack)?;

    for instruction in leaf.instructions() {
        match instruction.map_err(|_| InterpError::MalformedScript)? {
            Instruction::PushBytes(bytes) => stack.push(bytes.as_bytes().to_vec())?,
            Instruction::Op(op) => exec_op(op, &mut stack)?,
        }
    }

    match stack.items.len() {
        1 if is_truthy(&stack.items[0]) => Ok(()),
        1 => Err(InterpError::EvalFalse),
        n => Err(InterpError::CleanStackRequired { n }),
    }
}

fn exec_op(op: Opcode, stack: &mut Stack) -> Result<(), InterpError> {
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
    // Reserved future BIP360+ opcodes: recognized but not yet active.
    if byte == OP_CTV || byte == OP_VAULT || byte == OP_VAULT_RECOVER {
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
    use bitcoin::script::Builder;

    use super::*;

    fn run(leaf: &Script, stack: Vec<Vec<u8>>) -> Result<(), InterpError> {
        execute_leaf(leaf, stack)
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
        for byte in [OP_CTV, OP_VAULT, OP_VAULT_RECOVER] {
            let leaf = Builder::new().push_opcode(Opcode::from(byte)).into_script();
            assert_eq!(
                run(&leaf, vec![]),
                Err(InterpError::ReservedOpcode { byte })
            );
        }
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
