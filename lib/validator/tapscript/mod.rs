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

use std::collections::HashMap;

use bitcoin::{
    OutPoint, Script, Transaction, TxOut, Witness,
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
    #[error("BIP360+ deferred value-preservation check failed: {source}")]
    Deferred {
        #[source]
        source: InterpError,
    },
}

/// Enforce BIP360+ opcodes for every input of `tx`. For each Taproot v1
/// script-path input whose revealed leaf uses an enforced opcode, execute the
/// leaf and require a truthy result; queued cross-input value-preservation
/// checks (OP_VAULT / OP_VAULT_RECOVER) are evaluated once after every input.
/// Inputs that are not v1 script-path, or whose leaf uses none of the enforced
/// opcodes, are left to Core (ignored).
///
/// `prevouts` supplies each input's resolved `TxOut` (amount + scriptPubKey) —
/// needed for the BIP341 sighash of signature opcodes and OP_VAULT amount
/// checks. When a required prevout is absent, the opcode that needs it fails
/// closed (`InterpError::MissingPrevout`); CAT/CTV/timelock opcodes need none.
///
/// The caller must gate this on the activation height — below activation the
/// opcodes stay OP_SUCCESS no-ops (Core-compatible).
pub fn enforce_transaction(
    tx: &Transaction,
    prevouts: &HashMap<OutPoint, TxOut>,
) -> Result<(), TapscriptError> {
    let mut deferred = Vec::new();
    for (input_index, input) in tx.input.iter().enumerate() {
        if let Some((leaf, stack, control, annex)) = detect_enforced_leaf(&input.witness) {
            let ctx = interp::LeafContext {
                tx,
                input_index,
                prevouts,
                input_txout: prevouts.get(&input.previous_output),
                control: &control,
                annex: annex.as_deref(),
                leaf,
            };
            interp::execute_leaf(&ctx, stack, &mut deferred).map_err(|source| {
                TapscriptError::Interp {
                    input_index,
                    source,
                }
            })?;
        }
    }
    interp::evaluate_deferred_checks(&deferred, tx)
        .map_err(|source| TapscriptError::Deferred { source })?;
    Ok(())
}

/// Whether `witness` is a Taproot v1 script-path spend whose revealed leaf uses
/// OP_VAULT or OP_VAULT_RECOVER. The block-connect prefetch uses this to decide
/// which transactions need all their input prevouts resolved from bitcoind (the
/// committing trigger-auth sighash covers every co-input).
pub fn input_reveals_vault_leaf(witness: &Witness) -> bool {
    match detect_enforced_leaf(witness) {
        Some((leaf, _, _, _)) => leaf_uses_vault_opcode(leaf),
        None => false,
    }
}

/// The decoded pieces of a revealed enforced leaf: the leaf script, the initial
/// execution stack, the control block (internal key + merkle branch, for
/// OP_VAULT taptree reconstruction), and the annex bytes if present.
type EnforcedLeaf<'a> = (&'a Script, Vec<Vec<u8>>, ControlBlock, Option<Vec<u8>>);

/// If `witness` is a Taproot v1 script-path spend whose revealed 0xc0 leaf uses
/// an enforced opcode, return its [`EnforcedLeaf`] pieces (the annex is
/// committed by the BIP341 sighash).
fn detect_enforced_leaf(witness: &Witness) -> Option<EnforcedLeaf<'_>> {
    let mut elems: Vec<&[u8]> = witness.iter().collect();
    if elems.len() < 2 {
        return None; // key-path spend or non-script-path
    }
    // Strip the optional annex (last element beginning with 0x50, only when there
    // are >=2 elements — a lone element is a key-path signature, not an annex).
    let mut annex: Option<Vec<u8>> = None;
    if elems
        .last()
        .is_some_and(|e| e.first() == Some(&ANNEX_PREFIX))
    {
        annex = elems.pop().map(<[u8]>::to_vec);
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
    Some((leaf, stack, control, annex))
}

/// Whether `leaf` contains OP_VAULT or OP_VAULT_RECOVER as an opcode (not push
/// data), before any parse error.
fn leaf_uses_vault_opcode(leaf: &Script) -> bool {
    for instruction in leaf.instructions() {
        match instruction {
            Ok(Instruction::Op(op)) if op.to_u8() == OP_VAULT || op.to_u8() == OP_VAULT_RECOVER => {
                return true;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    false
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
        enforce_transaction(&tx_with_witness(w), &HashMap::new())
            .expect("valid CAT spend accepted");
    }

    #[test]
    fn invalid_cat_spend_rejected() {
        let leaf = cat_hash_leaf();
        let w = taproot_script_path_witness(&leaf, vec![b"ax".to_vec(), b"cd".to_vec()]);
        assert!(enforce_transaction(&tx_with_witness(w), &HashMap::new()).is_err());
    }

    #[test]
    fn keypath_spend_ignored() {
        // A single-element (key-path) witness is not our concern.
        let mut w = Witness::new();
        w.push(vec![0u8; 64]);
        enforce_transaction(&tx_with_witness(w), &HashMap::new()).expect("key-path ignored");
    }

    #[test]
    fn script_path_without_enforced_opcode_ignored() {
        // A pure OP_TRUE leaf (no BIP360+ opcode) is left to Core.
        let leaf = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let w = taproot_script_path_witness(&leaf, vec![]);
        enforce_transaction(&tx_with_witness(w), &HashMap::new())
            .expect("non-enforced leaf ignored");
    }
}

/// End-to-end OP_VAULT / OP_VAULT_RECOVER tests over real Taproot vaults built
/// with `TaprootBuilder` and real Schnorr signatures. The trigger-output taptree
/// is built *independently* of the interpreter's reconstruction, so a match
/// proves the reconstruction; forged signatures, tampered outputs, and
/// value-not-preserved must each reject.
#[cfg(test)]
mod vault_tests {
    use bitcoin::{
        Amount, Opcode, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
        hashes::Hash as _,
        opcodes::all::{OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_PUSHNUM_2},
        script::Builder,
        secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
        transaction::Version,
    };

    use super::*;

    const INPUT_AMOUNT: u64 = 100_000;
    const SPEND_DELAY: u8 = 6;

    fn secp() -> Secp256k1<bitcoin::secp256k1::All> {
        Secp256k1::new()
    }

    fn internal_key() -> XOnlyPublicKey {
        let kp = SecretKey::from_slice(&[0x22; 32]).unwrap().keypair(&secp());
        kp.x_only_public_key().0
    }

    fn trigger_keypair() -> Keypair {
        SecretKey::from_slice(&[0x33; 32]).unwrap().keypair(&secp())
    }

    /// The withdrawal leaf-update body: `OP_CSV OP_DROP OP_CTV`.
    fn body_script() -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_opcode(Opcode::from(OP_CTV))
            .into_script()
    }

    fn recover_leaf(recovery_spk_hash: &[u8; 32]) -> ScriptBuf {
        Builder::new()
            .push_slice(recovery_spk_hash)
            .push_opcode(Opcode::from(OP_VAULT_RECOVER))
            .into_script()
    }

    /// The canonical trigger leaf:
    /// `<trigger-pubkey> OP_CHECKSIGVERIFY <spend-delay> 2 <body> OP_VAULT`.
    fn trigger_leaf(trigger_xonly: &XOnlyPublicKey) -> ScriptBuf {
        let body = body_script();
        Builder::new()
            .push_slice(trigger_xonly.serialize())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice([SPEND_DELAY])
            .push_opcode(OP_PUSHNUM_2)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(body.as_bytes()).unwrap())
            .push_opcode(Opcode::from(OP_VAULT))
            .into_script()
    }

    /// The leaf-update (withdrawal) leaf built the way a wallet would —
    /// independently of the interpreter's reconstruction:
    /// `<target-CTV-hash> <spend-delay> OP_CSV OP_DROP OP_CTV`. The spend-delay is
    /// pushed minimally (`push_int` → OP_6 for delay 6), matching the reference
    /// `PushAll` encoding the interpreter reconstructs with.
    fn leaf_update(ctv_hash: &[u8; 32]) -> ScriptBuf {
        Builder::new()
            .push_slice(ctv_hash)
            .push_int(SPEND_DELAY as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_opcode(Opcode::from(OP_CTV))
            .into_script()
    }

    fn taptree(leaf_a: &ScriptBuf, leaf_b: &ScriptBuf) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, leaf_a.clone())
            .unwrap()
            .add_leaf(1, leaf_b.clone())
            .unwrap()
            .finalize(&secp(), internal_key())
            .unwrap()
    }

    fn p2tr_spk(info: &TaprootSpendInfo) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(info.output_key())
    }

    fn control_bytes(info: &TaprootSpendInfo, leaf: &ScriptBuf) -> Vec<u8> {
        info.control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize()
    }

    fn vault_outpoint(n: u32) -> OutPoint {
        OutPoint {
            txid: OutPoint::null().txid,
            vout: n,
        }
    }

    /// Build a fully-signed single-input trigger spend of a vault, returning the
    /// tx and its prevout map. `mutate_trigger_out` can tamper with the trigger
    /// output before signing (outputs are committed by the sighash).
    fn signed_trigger(
        mutate_trigger_out: impl FnOnce(&mut TxOut),
    ) -> (Transaction, ScriptBuf, HashMap<OutPoint, TxOut>) {
        let trigger_kp = trigger_keypair();
        let trigger_xonly = trigger_kp.x_only_public_key().0;
        let recovery_spk = ScriptBuf::from_bytes(vec![0x51]); // arbitrary recovery sPK
        let recovery_hash = interp_recovery_hash(&recovery_spk);
        let recover = recover_leaf(&recovery_hash);
        let trigger = trigger_leaf(&trigger_xonly);
        let vault_info = taptree(&recover, &trigger);
        let vault_spk = p2tr_spk(&vault_info);

        let ctv_hash = [0x77u8; 32];
        let lu = leaf_update(&ctv_hash);
        let trig_info = taptree(&recover, &lu);
        let mut trigger_out = TxOut {
            value: Amount::from_sat(INPUT_AMOUNT),
            script_pubkey: p2tr_spk(&trig_info),
        };
        mutate_trigger_out(&mut trigger_out);

        let vault_txout = TxOut {
            value: Amount::from_sat(INPUT_AMOUNT),
            script_pubkey: vault_spk,
        };
        let outpoint = vault_outpoint(0);
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![trigger_out],
        };

        // Sign the trigger-auth signature over the BIP341 script-spend sighash.
        let leaf_hash = TapLeafHash::from_script(&trigger, LeafVersion::TapScript);
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&vault_txout)),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let sig = secp()
            .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &trigger_kp);
        let tap_sig = bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };

        // Witness stack (bottom→top): revault-amount(0), revault-idx(-1),
        // trigger-idx(0), target-CTV-hash, signature; then leaf + control.
        let mut w = Witness::new();
        w.push::<&[u8]>(&[]); // revault-amount = 0
        w.push([0x81]); // revault-idx = -1
        w.push::<&[u8]>(&[]); // trigger-idx = 0
        w.push(ctv_hash);
        w.push(tap_sig.to_vec());
        w.push(trigger.as_bytes());
        w.push(control_bytes(&vault_info, &trigger));
        tx.input[0].witness = w;

        let prevouts = HashMap::from([(outpoint, vault_txout)]);
        (tx, recovery_spk, prevouts)
    }

    /// Compute the VaultRecoverySPK tagged hash the same way the interpreter
    /// does — used to build the recover leaf's committed hash.
    fn interp_recovery_hash(spk: &ScriptBuf) -> [u8; 32] {
        use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
        let tag = sha256::Hash::hash(b"VaultRecoverySPK");
        let mut msg = Vec::new();
        // CompactSize(len) — spk lengths in tests are < 0xfd.
        msg.push(spk.len() as u8);
        msg.extend_from_slice(spk.as_bytes());
        let mut eng = sha256::Hash::engine();
        eng.input(tag.as_ref());
        eng.input(tag.as_ref());
        eng.input(&msg);
        sha256::Hash::from_engine(eng).to_byte_array()
    }

    #[test]
    fn valid_trigger_accepts_and_reconstructs_taptree() {
        let (tx, _recovery_spk, prevouts) = signed_trigger(|_| {});
        enforce_transaction(&tx, &prevouts).expect("valid signed trigger accepts");
    }

    #[test]
    fn forged_signature_rejected() {
        let (mut tx, _r, prevouts) = signed_trigger(|_| {});
        // Corrupt the signature element (index 4 of the witness stack).
        let mut elems: Vec<Vec<u8>> = tx.input[0].witness.to_vec();
        elems[4][10] ^= 0x01;
        let mut w = Witness::new();
        for e in elems {
            w.push(e);
        }
        tx.input[0].witness = w;
        let err = enforce_transaction(&tx, &prevouts).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::SchnorrVerifyFailed,
                    ..
                }
            ),
            "expected SchnorrVerifyFailed, got {err:?}"
        );
    }

    #[test]
    fn tampered_trigger_output_rejected() {
        // A trigger output whose taptree does not match the leaf-update
        // reconstruction must reject. Point it at a bare p2tr instead.
        let (tx, _r, prevouts) = signed_trigger(|out| {
            out.script_pubkey = p2tr_spk(&taptree(&body_script(), &body_script()));
        });
        let err = enforce_transaction(&tx, &prevouts).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::VaultTriggerMismatch,
                    ..
                }
            ),
            "expected VaultTriggerMismatch, got {err:?}"
        );
    }

    #[test]
    fn value_not_preserved_rejected() {
        // Trigger output carries less than the input value (no revault): the
        // OP_VAULT short-circuit value check must reject.
        let (tx, _r, prevouts) = signed_trigger(|out| {
            out.value = Amount::from_sat(INPUT_AMOUNT - 1);
        });
        let err = enforce_transaction(&tx, &prevouts).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::VaultValueNotPreserved,
                    ..
                }
            ),
            "expected VaultValueNotPreserved, got {err:?}"
        );
    }

    #[test]
    fn missing_prevout_fails_closed() {
        // Without the vault input's prevout, OP_VAULT cannot resolve the amount.
        let (tx, _r, _prevouts) = signed_trigger(|_| {});
        let err = enforce_transaction(&tx, &HashMap::new()).unwrap_err();
        // The trigger-auth sighash needs the prevout first → MissingPrevout.
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::MissingPrevout,
                    ..
                }
            ),
            "expected MissingPrevout, got {err:?}"
        );
    }

    /// Build a signed (unauthorized) recovery spending `n_inputs` vault inputs
    /// into a single recovery output — exercising deferred value aggregation.
    fn recovery_spend(
        n_inputs: usize,
        recovery_value: u64,
    ) -> (Transaction, HashMap<OutPoint, TxOut>) {
        let trigger_xonly = trigger_keypair().x_only_public_key().0;
        let recovery_spk = ScriptBuf::from_bytes(vec![0x51]);
        let recovery_hash = interp_recovery_hash(&recovery_spk);
        let recover = recover_leaf(&recovery_hash);
        let trigger = trigger_leaf(&trigger_xonly);
        let vault_info = taptree(&recover, &trigger);
        let vault_spk = p2tr_spk(&vault_info);
        let control = control_bytes(&vault_info, &recover);

        let mut inputs = Vec::new();
        let mut prevouts = HashMap::new();
        for i in 0..n_inputs {
            let outpoint = vault_outpoint(i as u32);
            prevouts.insert(
                outpoint,
                TxOut {
                    value: Amount::from_sat(INPUT_AMOUNT),
                    script_pubkey: vault_spk.clone(),
                },
            );
            // Witness (bottom→top): recovery-vout-idx(0); then recover leaf +
            // control. The recovery-sPK-hash is pushed by the leaf.
            let mut w = Witness::new();
            w.push::<&[u8]>(&[]); // recovery-vout-idx = 0
            w.push(recover.as_bytes());
            w.push(control.clone());
            inputs.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w,
            });
        }
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: vec![TxOut {
                value: Amount::from_sat(recovery_value),
                script_pubkey: recovery_spk,
            }],
        };
        (tx, prevouts)
    }

    #[test]
    fn valid_recovery_accepts() {
        let (tx, prevouts) = recovery_spend(1, INPUT_AMOUNT);
        enforce_transaction(&tx, &prevouts).expect("valid recovery accepts");
    }

    #[test]
    fn batched_recovery_aggregates_value() {
        // Two vault inputs recovered into one output: the output must carry the
        // sum. Exactly the sum accepts; one sat short rejects.
        let (tx_ok, prevouts_ok) = recovery_spend(2, INPUT_AMOUNT * 2);
        enforce_transaction(&tx_ok, &prevouts_ok).expect("batched recovery accepts at full sum");

        let (tx_bad, prevouts_bad) = recovery_spend(2, INPUT_AMOUNT * 2 - 1);
        let err = enforce_transaction(&tx_bad, &prevouts_bad).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Deferred {
                    source: InterpError::VaultValueNotPreserved,
                }
            ),
            "expected deferred VaultValueNotPreserved, got {err:?}"
        );
    }

    #[test]
    fn recovery_wrong_output_spk_rejected() {
        // Recovery output whose sPK does not hash to the committed value rejects.
        let (mut tx, prevouts) = recovery_spend(1, INPUT_AMOUNT);
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x52]); // different sPK
        let err = enforce_transaction(&tx, &prevouts).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::VaultRecoverMismatch,
                    ..
                }
            ),
            "expected VaultRecoverMismatch, got {err:?}"
        );
    }

    /// Minimal `CScriptNum` encoder (mirrors the interpreter's) for building
    /// witness stack items in tests.
    fn cscriptnum(n: i64) -> Vec<u8> {
        if n == 0 {
            return Vec::new();
        }
        let neg = n < 0;
        let mut abs = n.unsigned_abs();
        let mut out = Vec::new();
        while abs > 0 {
            out.push((abs & 0xff) as u8);
            abs >>= 8;
        }
        if *out.last().unwrap() & 0x80 != 0 {
            out.push(if neg { 0x80 } else { 0x00 });
        } else if neg {
            let last = out.len() - 1;
            out[last] |= 0x80;
        }
        out
    }

    /// Build a withdrawal spend of a *triggered* vault output: the leaf-update
    /// leaf `<CTV-hash> <spend-delay> OP_CSV OP_DROP OP_CTV`. `seq` is the input's
    /// nSequence (the relative timelock the enforcer checks against the delay).
    /// The CTV hash is bound to this exact tx so OP_CTV always matches — only the
    /// timelock varies.
    fn withdrawal_spend(seq: u32) -> Transaction {
        let recovery_spk = ScriptBuf::from_bytes(vec![0x51]);
        let recover = recover_leaf(&interp_recovery_hash(&recovery_spk));

        let mut wtx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: vault_outpoint(0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(seq),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(INPUT_AMOUNT),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        // CTV commits to the tx template (not the prevout), so compute it now.
        let ctv_hash = default_check_template_verify_hash(&wtx, 0);
        let lu = leaf_update(&ctv_hash);
        let trig_info = taptree(&recover, &lu);
        let control = control_bytes(&trig_info, &lu);
        let mut w = Witness::new();
        w.push(lu.as_bytes());
        w.push(control);
        wtx.input[0].witness = w;
        wtx
    }

    #[test]
    fn withdrawal_after_delay_accepts() {
        // The leaf-update withdrawal (timelocked CTV) reuses our shipped CTV
        // enforcement and the new OP_CSV. Sequence == delay satisfies the lock.
        let tx = withdrawal_spend(SPEND_DELAY as u32);
        enforce_transaction(&tx, &HashMap::new()).expect("withdrawal at delay accepts");
    }

    #[test]
    fn early_withdrawal_rejected() {
        // Sequence below the spend-delay must reject — the delay is real, so a
        // triggered withdrawal cannot complete before the recovery window.
        let tx = withdrawal_spend((SPEND_DELAY - 1) as u32);
        let err = enforce_transaction(&tx, &HashMap::new()).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::TimelockNotSatisfied,
                    ..
                }
            ),
            "expected TimelockNotSatisfied, got {err:?}"
        );
    }

    /// Build a signed trigger with a revault output: `revault_amount` goes to a
    /// revault output (idx 1) reusing the vault sPK; the rest to the trigger
    /// output (idx 0). `revault_spk_override` can break the revault sPK match.
    fn signed_trigger_revault(
        revault_amount: u64,
        revault_spk_override: Option<ScriptBuf>,
    ) -> (Transaction, HashMap<OutPoint, TxOut>) {
        let trigger_kp = trigger_keypair();
        let trigger_xonly = trigger_kp.x_only_public_key().0;
        let recovery_spk = ScriptBuf::from_bytes(vec![0x51]);
        let recover = recover_leaf(&interp_recovery_hash(&recovery_spk));
        let trigger = trigger_leaf(&trigger_xonly);
        let vault_info = taptree(&recover, &trigger);
        let vault_spk = p2tr_spk(&vault_info);

        let ctv_hash = [0x77u8; 32];
        let lu = leaf_update(&ctv_hash);
        let trig_info = taptree(&recover, &lu);
        let trigger_out = TxOut {
            value: Amount::from_sat(INPUT_AMOUNT - revault_amount),
            script_pubkey: p2tr_spk(&trig_info),
        };
        let revault_out = TxOut {
            value: Amount::from_sat(revault_amount),
            script_pubkey: revault_spk_override.unwrap_or_else(|| vault_spk.clone()),
        };

        let vault_txout = TxOut {
            value: Amount::from_sat(INPUT_AMOUNT),
            script_pubkey: vault_spk,
        };
        let outpoint = vault_outpoint(0);
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![trigger_out, revault_out],
        };
        let leaf_hash = TapLeafHash::from_script(&trigger, LeafVersion::TapScript);
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&vault_txout)),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let sig = secp()
            .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &trigger_kp);
        let tap_sig = bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };
        // Witness (bottom→top): revault-amount(R), revault-idx(1), trigger-idx(0),
        // target-CTV-hash, signature.
        let mut w = Witness::new();
        w.push(cscriptnum(revault_amount as i64));
        w.push(cscriptnum(1));
        w.push(cscriptnum(0));
        w.push(ctv_hash);
        w.push(tap_sig.to_vec());
        w.push(trigger.as_bytes());
        w.push(control_bytes(&vault_info, &trigger));
        tx.input[0].witness = w;

        let prevouts = HashMap::from([(outpoint, vault_txout)]);
        (tx, prevouts)
    }

    #[test]
    fn valid_revault_accepts() {
        let (tx, prevouts) = signed_trigger_revault(40_000, None);
        enforce_transaction(&tx, &prevouts).expect("valid revault accepts");
    }

    #[test]
    fn revault_wrong_spk_rejected() {
        // Revault output must reuse the input's scriptPubKey exactly.
        let (tx, prevouts) =
            signed_trigger_revault(40_000, Some(ScriptBuf::from_bytes(vec![0x52])));
        let err = enforce_transaction(&tx, &prevouts).unwrap_err();
        assert!(
            matches!(
                err,
                TapscriptError::Interp {
                    source: InterpError::VaultRevaultMismatch,
                    ..
                }
            ),
            "expected VaultRevaultMismatch, got {err:?}"
        );
    }
}
