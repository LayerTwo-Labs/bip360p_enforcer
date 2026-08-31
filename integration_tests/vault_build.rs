//! Hand-built OP_VAULT / OP_VAULT_RECOVER transactions for the BIP360+ vault
//! enforcement trial.
//!
//! These build the vault taptree, a signed trigger spend, and an unauthorized
//! recovery spend **independently of the enforcer's interpreter** — so the trial
//! genuinely cross-checks the enforcer's taptree reconstruction, signature
//! verification, and value/recovery checks against a separate construction. In
//! particular the leaf-update script pushes the spend-delay with `push_int`
//! (minimal encoding → `OP_6`), matching the reference `PushAll` the interpreter
//! reconstructs with.

use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    hashes::{Hash as _, HashEngine as _, sha256},
    opcodes::all::{OP_CSV, OP_DROP},
    script::Builder,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
};

/// BIP360+ opcode bytes (top-of-range OP_SUCCESSx, our scheme).
const OP_CTV: u8 = 0xfd;
const OP_VAULT: u8 = 0xfc;
const OP_VAULT_RECOVER: u8 = 0xfb;

/// Fixed keys so vault addresses are deterministic across a run.
const INTERNAL_KEY_BYTES: [u8; 32] = [0x22; 32];
const TRIGGER_KEY_BYTES: [u8; 32] = [0x33; 32];
/// Relative-timelock spend delay (blocks). Small (≤16) on purpose, so the
/// leaf-update encoding exercises the `OP_1..OP_16` minimal-push path.
const SPEND_DELAY: u8 = 6;
/// Arbitrary CTV target hash locked into the trigger's leaf-update script (the
/// trigger does not verify CTV; it only commits the hash into the new leaf).
const TARGET_CTV_HASH: [u8; 32] = [0x77; 32];

/// How to (mis)build a trigger spend.
#[derive(Clone, Copy)]
pub enum TriggerKind {
    /// A correct, fully-signed trigger — the enforcer must accept it.
    Valid,
    /// A trigger with a corrupted signature — reject (`SchnorrVerifyFailed`).
    ForgeSig,
    /// A trigger whose output taptree does not match the leaf-update
    /// reconstruction — reject (`VaultTriggerMismatch`).
    TamperTriggerOut,
}

fn secp() -> Secp256k1<bitcoin::secp256k1::All> {
    Secp256k1::new()
}

fn internal_key() -> XOnlyPublicKey {
    SecretKey::from_slice(&INTERNAL_KEY_BYTES)
        .unwrap()
        .keypair(&secp())
        .x_only_public_key()
        .0
}

fn trigger_keypair() -> Keypair {
    SecretKey::from_slice(&TRIGGER_KEY_BYTES)
        .unwrap()
        .keypair(&secp())
}

/// The recovery-path scriptPubKey (bare `OP_TRUE` — its bytes are all that
/// matter here; the recover leaf commits to its tagged hash).
pub fn recovery_spk() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

/// BIP340 tagged hash `SHA256(SHA256(tag)||SHA256(tag)||msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(msg);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// BIP345 `tagged_hash("VaultRecoverySPK", CompactSize(len(spk)) || spk)`.
fn vault_recovery_spk_hash(spk: &ScriptBuf) -> [u8; 32] {
    let mut msg = Vec::new();
    // spk lengths here are < 0xfd, so a single CompactSize byte.
    msg.push(spk.len() as u8);
    msg.extend_from_slice(spk.as_bytes());
    tagged_hash(b"VaultRecoverySPK", &msg)
}

fn body_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(bitcoin::Opcode::from(OP_CTV))
        .into_script()
}

fn recover_leaf() -> ScriptBuf {
    Builder::new()
        .push_slice(vault_recovery_spk_hash(&recovery_spk()))
        .push_opcode(bitcoin::Opcode::from(OP_VAULT_RECOVER))
        .into_script()
}

/// `<trigger-pubkey> OP_CHECKSIGVERIFY <spend-delay> 2 <body> OP_VAULT`.
fn trigger_leaf() -> ScriptBuf {
    let xonly = trigger_keypair().x_only_public_key().0;
    Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY)
        .push_slice([SPEND_DELAY])
        .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_2)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(body_script().as_bytes()).unwrap())
        .push_opcode(bitcoin::Opcode::from(OP_VAULT))
        .into_script()
}

/// `<target-CTV-hash> <spend-delay> OP_CSV OP_DROP OP_CTV` — the withdrawal leaf,
/// with the delay pushed minimally (`push_int` → OP_6).
fn leaf_update() -> ScriptBuf {
    Builder::new()
        .push_slice(TARGET_CTV_HASH)
        .push_int(SPEND_DELAY as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(bitcoin::Opcode::from(OP_CTV))
        .into_script()
}

fn two_leaf_tree(leaf_a: &ScriptBuf, leaf_b: &ScriptBuf) -> TaprootSpendInfo {
    TaprootBuilder::new()
        .add_leaf(1, leaf_a.clone())
        .unwrap()
        .add_leaf(1, leaf_b.clone())
        .unwrap()
        .finalize(&secp(), internal_key())
        .unwrap()
}

fn vault_spend_info() -> TaprootSpendInfo {
    two_leaf_tree(&recover_leaf(), &trigger_leaf())
}

fn p2tr_spk(info: &TaprootSpendInfo) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(info.output_key())
}

fn control_bytes(info: &TaprootSpendInfo, leaf: &ScriptBuf) -> Vec<u8> {
    info.control_block(&(leaf.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize()
}

/// The vault deposit address (fund this to create a vault UTXO).
pub fn vault_address() -> bitcoin::Address {
    bitcoin::Address::p2tr_tweaked(vault_spend_info().output_key(), Network::Regtest)
}

/// The vault deposit scriptPubKey.
pub fn vault_spk() -> ScriptBuf {
    p2tr_spk(&vault_spend_info())
}

/// The expected, correct trigger-output scriptPubKey: the vault taptree with the
/// trigger leaf replaced by the leaf-update (withdrawal) leaf.
fn correct_trigger_out_spk() -> ScriptBuf {
    p2tr_spk(&two_leaf_tree(&recover_leaf(), &leaf_update()))
}

/// Build a trigger spend of a prior-block vault UTXO `(outpoint, value)`.
/// The single trigger output carries the full input value (no revault).
pub fn build_trigger(outpoint: OutPoint, value: u64, kind: TriggerKind) -> Transaction {
    let trigger = trigger_leaf();
    let vault_txout = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: vault_spk(),
    };

    let trigger_out_spk = match kind {
        TriggerKind::Valid | TriggerKind::ForgeSig => correct_trigger_out_spk(),
        // A mismatching taptree: bare vault sPK instead of the reconstruction.
        TriggerKind::TamperTriggerOut => vault_spk(),
    };
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: trigger_out_spk,
        }],
    };

    // Sign the trigger-auth signature over the BIP341 script-spend sighash
    // (outputs are committed, so sign after the output is set).
    let leaf_hash = TapLeafHash::from_script(&trigger, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&vault_txout)),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    let sig = secp().sign_schnorr_no_aux_rand(
        &Message::from_digest(sighash.to_byte_array()),
        &trigger_keypair(),
    );
    let mut sig_bytes = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    }
    .to_vec();
    if matches!(kind, TriggerKind::ForgeSig) {
        sig_bytes[10] ^= 0x01;
    }

    // Witness (bottom→top): revault-amount(0), revault-idx(-1), trigger-idx(0),
    // target-CTV-hash, signature; then leaf + control.
    let control = control_bytes(&vault_spend_info(), &trigger);
    let stack: Vec<Vec<u8>> = vec![
        Vec::new(),               // revault-amount = 0
        vec![0x81],               // revault-idx = -1
        Vec::new(),               // trigger-idx = 0
        TARGET_CTV_HASH.to_vec(), // target-CTV-hash
        sig_bytes,                // signature
        trigger.as_bytes().to_vec(),
        control,
    ];
    let mut witness = Witness::new();
    for elem in stack {
        witness.push(elem);
    }
    tx.input[0].witness = witness;
    tx
}

/// Build an unauthorized recovery spend of a prior-block vault UTXO into the
/// recovery output (index 0), carrying the full input value.
pub fn build_recovery(outpoint: OutPoint, value: u64) -> Transaction {
    let recover = recover_leaf();
    let control = control_bytes(&vault_spend_info(), &recover);

    let mut witness = Witness::new();
    witness.push::<&[u8]>(&[]); // recovery-vout-idx = 0
    witness.push(recover.as_bytes());
    witness.push(control);

    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: recovery_spk(),
        }],
    }
}
