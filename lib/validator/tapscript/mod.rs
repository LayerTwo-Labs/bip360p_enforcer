//! BIP360+ Tapscript opcode enforcement (Taproot v1 script-path).
//!
//! Enforces the BIP360+ opcodes — OP_CAT (`0xfe`) now, plus the reserved CTV /
//! OP_VAULT / OP_VAULT_RECOVER (`0xfd`/`0xfc`/`0xfb`) — inside **standard
//! Taproot v1** leaves (leaf version `0xc0`). These bytes are OP_SUCCESSx to
//! stock Bitcoin Core (anyone-can-spend no-ops), so this enforcer gives them
//! real, fail-closed meaning: at/after activation, any v1 script-path spend
//! whose revealed leaf contains one of these opcodes must EXECUTE to a single
//! truthy element under [`interp`], else the spend — and its block — is
//! rejected (`invalidateblock`).
//!
//! This is **decoupled from P2MR**: it inspects ordinary Taproot v1 spends, not
//! P2MR (witness-v2) outputs, and the P2MR signature-validation path is
//! untouched. Core verifies the taproot commitment before its OP_SUCCESS
//! short-circuit, so a revealed leaf is guaranteed committed — this pass needs
//! no prevout to trust and execute the revealed (signature-less) leaf.

mod interp;

use bitcoin::{
    Script, Transaction, Witness,
    script::Instruction,
    taproot::{ControlBlock, LeafVersion},
};
use thiserror::Error;

pub use self::interp::{InterpError, default_check_template_verify_hash};

/// OP_CHECKTEMPLATEVERIFY (0xfd) argument / template-hash size.
pub const CTV_HASH_LEN: usize = 32;

/// OP_CAT — BIP347 (byte `0xfe`, top of the OP_SUCCESSx range).
pub const OP_CAT: u8 = 0xfe;
/// OP_CHECKTEMPLATEVERIFY / CTV — BIP119 (byte `0xfd`).
pub const OP_CTV: u8 = 0xfd;
/// OP_VAULT — BIP345 (byte `0xfc`). Reserved until Phase 6.
pub const OP_VAULT: u8 = 0xfc;
/// OP_VAULT_RECOVER — BIP345 (byte `0xfb`). Reserved until Phase 6.
pub const OP_VAULT_RECOVER: u8 = 0xfb;

/// The BIP360+ opcode bytes whose presence in a v1 leaf triggers enforcement.
pub const ENFORCED_OPCODES: [u8; 4] = [OP_CAT, OP_CTV, OP_VAULT, OP_VAULT_RECOVER];

/// Taproot annex prefix (BIP341).
const ANNEX_PREFIX: u8 = 0x50;

#[derive(Debug, Error)]
pub enum TapscriptError {
    #[error("BIP360+ opcode validation failed at input {input_index}: {source}")]
    Interp {
        input_index: usize,
        #[source]
        source: InterpError,
    },
}

/// Enforce BIP360+ opcodes for every input of `tx`. For each Taproot v1
/// script-path input whose revealed leaf uses an enforced opcode, execute the
/// leaf and require a truthy result. Inputs that are not v1 script-path, or
/// whose leaf uses none of the enforced opcodes, are left to Core (ignored).
///
/// The caller must gate this on the activation height — below activation the
/// opcodes stay OP_SUCCESS no-ops (Core-compatible).
pub fn enforce_transaction(tx: &Transaction) -> Result<(), TapscriptError> {
    for (input_index, input) in tx.input.iter().enumerate() {
        if let Some((leaf, stack)) = detect_enforced_leaf(&input.witness) {
            interp::execute_leaf(tx, input_index, leaf, stack).map_err(|source| {
                TapscriptError::Interp {
                    input_index,
                    source,
                }
            })?;
        }
    }
    Ok(())
}

/// If `witness` is a Taproot v1 script-path spend whose revealed 0xc0 leaf uses
/// an enforced opcode, return the leaf script plus the initial stack (the
/// witness elements below the leaf script + control block, annex stripped).
fn detect_enforced_leaf(witness: &Witness) -> Option<(&Script, Vec<Vec<u8>>)> {
    let mut elems: Vec<&[u8]> = witness.iter().collect();
    if elems.len() < 2 {
        return None; // key-path spend or non-script-path
    }
    // Strip the optional annex (last element beginning with 0x50).
    if elems
        .last()
        .is_some_and(|e| e.first() == Some(&ANNEX_PREFIX))
    {
        elems.pop();
    }
    if elems.len() < 2 {
        return None;
    }
    let control_block = elems.pop().expect("len checked");
    let leaf_bytes = elems.pop().expect("len checked");

    // Must be a valid control block committing to a v1 tapscript (0xc0) leaf.
    let control = ControlBlock::decode(control_block).ok()?;
    if control.leaf_version != LeafVersion::TapScript {
        return None;
    }

    let leaf = Script::from_bytes(leaf_bytes);
    if !leaf_uses_enforced_opcode(leaf) {
        return None;
    }

    // Remaining elements are the initial execution stack, in bottom-to-top order.
    let stack = elems.into_iter().map(<[u8]>::to_vec).collect();
    Some((leaf, stack))
}

/// Whether `leaf` contains any [`ENFORCED_OPCODES`] byte as an opcode (not push
/// data). If the script fails to parse before any enforced opcode is seen, it
/// is not our concern (a malformed non-OP_SUCCESS script Core rejects anyway).
fn leaf_uses_enforced_opcode(leaf: &Script) -> bool {
    for instruction in leaf.instructions() {
        match instruction {
            Ok(Instruction::Op(op)) if ENFORCED_OPCODES.contains(&op.to_u8()) => return true,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Opcode, ScriptBuf, Sequence, TxIn,
        opcodes::all::OP_SHA256,
        script::Builder,
        secp256k1::{Secp256k1, SecretKey},
        taproot::TaprootBuilder,
    };

    use super::*;

    // Build a real Taproot v1 script-path witness [<stack...>, leaf, control].
    fn taproot_script_path_witness(leaf: &ScriptBuf, stack: Vec<Vec<u8>>) -> Witness {
        let secp = Secp256k1::new();
        let internal = SecretKey::from_slice(&[0x11; 32]).unwrap().keypair(&secp);
        let (internal_xonly, _) = internal.x_only_public_key();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal_xonly)
            .unwrap();
        let control = spend_info
            .control_block(&(leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .unwrap();
        let mut w = Witness::new();
        for elem in stack {
            w.push(elem);
        }
        w.push(leaf.as_bytes());
        w.push(control.serialize());
        w
    }

    fn cat_hash_leaf() -> ScriptBuf {
        use bitcoin::hashes::{Hash, sha256};
        let expected = sha256::Hash::hash(b"abcd").to_byte_array().to_vec();
        Builder::new()
            .push_opcode(Opcode::from(OP_CAT))
            .push_opcode(OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(expected.as_slice()).unwrap())
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script()
    }

    fn tx_with_witness(w: Witness) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w,
            }],
            output: vec![],
        }
    }

    #[test]
    fn valid_cat_spend_accepted() {
        let leaf = cat_hash_leaf();
        let w = taproot_script_path_witness(&leaf, vec![b"ab".to_vec(), b"cd".to_vec()]);
        enforce_transaction(&tx_with_witness(w)).expect("valid CAT spend accepted");
    }

    #[test]
    fn invalid_cat_spend_rejected() {
        let leaf = cat_hash_leaf();
        let w = taproot_script_path_witness(&leaf, vec![b"ax".to_vec(), b"cd".to_vec()]);
        assert!(enforce_transaction(&tx_with_witness(w)).is_err());
    }

    #[test]
    fn keypath_spend_ignored() {
        // A single-element (key-path) witness is not our concern.
        let mut w = Witness::new();
        w.push(vec![0u8; 64]);
        enforce_transaction(&tx_with_witness(w)).expect("key-path ignored");
    }

    #[test]
    fn script_path_without_enforced_opcode_ignored() {
        // A pure OP_TRUE leaf (no BIP360+ opcode) is left to Core.
        let leaf = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let w = taproot_script_path_witness(&leaf, vec![]);
        enforce_transaction(&tx_with_witness(w)).expect("non-enforced leaf ignored");
    }
}
