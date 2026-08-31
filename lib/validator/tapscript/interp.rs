//! Fail-closed subset-Tapscript stack interpreter for BIP360+ leaf enforcement.
//!
//! This executes a revealed Taproot v1 (leaf version `0xc0`) leaf that contains
//! a BIP360+ opcode, under BIP342 stack semantics, and requires it to evaluate
//! to a single truthy element. It is deliberately a **subset**: only the opcodes
//! needed to give the BIP360+ opcodes meaning are implemented; every other
//! opcode not in that set is rejected (`UnimplementedOpcode`).
//!
//! The implemented set: OP_CAT (Phase 4), OP_CHECKTEMPLATEVERIFY (Phase 5), and
//! (Phase 6) OP_VAULT / OP_VAULT_RECOVER plus the opcodes a working vault needs —
//! `OP_CHECKSIG`/`OP_CHECKSIGVERIFY`/`OP_CHECKSIGADD` (BIP342 Schnorr, so
//! **private-key ownership is the sole withdrawal authority**) and
//! `OP_CHECKSEQUENCEVERIFY`/`OP_CHECKLOCKTIMEVERIFY` (BIP112/65 timelocks, so the
//! withdrawal spend-delay is real).
//!
//! Because our vault opcodes are `OP_SUCCESSx`, stock Bitcoin Core deems the
//! entire leaf valid without executing any of it — it never checks the trigger
//! signature or the timelock. So this interpreter must. Signature verification
//! reuses `libsecp256k1` (the `secp256k1` crate, the same engine Core uses) and
//! the `bitcoin` crate's cross-tested BIP341 sighash — no hand-rolled crypto.
//!
//! Fail-closed is the guiding rule: any underflow, oversized element, malformed
//! script, unknown opcode, missing prevout, bad signature, unmet timelock, or
//! non-true final stack is a rejection.

use std::collections::HashMap;

use bitcoin::{
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxOut,
    blockdata::opcodes::{Opcode, all as opcodes},
    consensus::encode::serialize as consensus_serialize,
    hashes::{Hash as _, HashEngine as _, hash160, ripemd160, sha256, sha256d},
    key::{TapTweak as _, UntweakedPublicKey},
    script::Instruction,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{Annex, Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash},
};
use thiserror::Error;

use super::{OP_CAT, OP_CTV, OP_VAULT, OP_VAULT_RECOVER};

/// BIP119 template-hash / OP_CTV argument size.
const CTV_HASH_LEN: usize = 32;

/// BIP345 `<recovery-sPK-hash>` size.
const RECOVERY_SPK_HASH_LEN: usize = 32;

/// Maximum size (bytes) of a single stack element (BIP347 keeps the 520-byte
/// script-element limit for `OP_CAT`).
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of elements on the stack at any point (matches Bitcoin's
/// `MAX_STACK_SIZE`).
pub const MAX_STACK_SIZE: usize = 1000;

/// BIP112 nSequence flags (relative timelock).
const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000_ffff;

/// BIP65 locktime threshold: below is a block height, at/above is a unix time.
const LOCKTIME_THRESHOLD: i64 = 500_000_000;

/// Sentinel codeseparator position for BIP341 script-path sighash — we do not
/// implement `OP_CODESEPARATOR`, so it is always "none".
const NO_CODESEPARATOR: u32 = 0xffff_ffff;

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
    // --- Phase 6 (OP_VAULT / signatures / timelocks) ---
    #[error("required prevout is unavailable (fail-closed)")]
    MissingPrevout,
    #[error("malformed BIP341 taproot signature encoding")]
    BadSignatureEncoding,
    #[error("unsupported public key type (len {len}); only 32-byte x-only keys are allowed")]
    UnknownPubkeyType { len: usize },
    #[error("schnorr signature verification failed")]
    SchnorrVerifyFailed,
    #[error("failed to compute BIP341 sighash")]
    SighashError,
    #[error("relative/absolute timelock not satisfied")]
    TimelockNotSatisfied,
    #[error("non-minimally-encoded or oversized CScriptNum")]
    BadScriptNum,
    #[error("OP_VAULT stack is malformed")]
    VaultBadStack,
    #[error("OP_VAULT trigger output is not a v1 witness program")]
    VaultTriggerNotV1,
    #[error("OP_VAULT trigger output taptree does not match the leaf-update reconstruction")]
    VaultTriggerMismatch,
    #[error("OP_VAULT revault output scriptPubKey does not match the input")]
    VaultRevaultMismatch,
    #[error("OP_VAULT_RECOVER hash argument is not {RECOVERY_SPK_HASH_LEN} bytes (got {len})")]
    VaultRecoverBadHashLen { len: usize },
    #[error("OP_VAULT_RECOVER recovery output scriptPubKey hash mismatch")]
    VaultRecoverMismatch,
    #[error("OP_VAULT value-preservation deferred check failed")]
    VaultValueNotPreserved,
}

/// A deferred, cross-input value-preservation check (BIP345 "Deferred check
/// evaluation"). Queued during per-input execution, evaluated once after every
/// input's leaf has run, so batched vault spends aggregate into shared outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferredCheck {
    /// Queued by `OP_VAULT`: `input_amount - revault_amount` must land in the
    /// trigger output, and `revault_amount` (if non-zero) in the revault output.
    Trigger {
        input_amount: u64,
        revault_amount: u64,
        trigger_idx: usize,
        /// Output index of the revault output, or -1 when there is none.
        revault_idx: i64,
    },
    /// Queued by `OP_VAULT_RECOVER`: the whole `input_amount` must land in the
    /// recovery output.
    Recovery { input_amount: u64, vout_idx: usize },
}

/// Read-only per-input context threaded through leaf execution. Bundles the
/// transaction introspection surface the BIP360+ opcodes need.
pub(super) struct LeafContext<'a> {
    pub tx: &'a Transaction,
    pub input_index: usize,
    /// All resolved prevouts for the spending tx (amount + scriptPubKey), used
    /// for the committing (non-ANYONECANPAY) BIP341 sighash. Includes the
    /// prefetched external prevouts merged upstream.
    pub prevouts: &'a HashMap<OutPoint, TxOut>,
    /// The prevout of the input being executed (`None` if unresolved → the
    /// opcodes that need it fail closed).
    pub input_txout: Option<&'a TxOut>,
    /// Decoded control block of this script-path spend — its internal key and
    /// merkle branch drive OP_VAULT taptree reconstruction.
    pub control: &'a ControlBlock,
    /// The witness annex bytes (including the `0x50` prefix), if present —
    /// committed by the BIP341 sighash.
    pub annex: Option<&'a [u8]>,
    /// The revealed leaf script being executed.
    pub leaf: &'a Script,
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

/// Decode a minimally-encoded `CScriptNum` (little-endian, sign-magnitude) of at
/// most `max_len` bytes. Rejects non-minimal encodings and over-length inputs
/// fail-closed. Empty is zero.
fn read_scriptnum(bytes: &[u8], max_len: usize) -> Result<i64, InterpError> {
    if bytes.len() > max_len {
        return Err(InterpError::BadScriptNum);
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    // Minimal-encoding: the most-significant byte must not be 0x00/0x80 unless it
    // provides the sign bit for a set high bit in the next-most-significant byte.
    let last = bytes[bytes.len() - 1];
    if last & 0x7f == 0 && (bytes.len() <= 1 || bytes[bytes.len() - 2] & 0x80 == 0) {
        return Err(InterpError::BadScriptNum);
    }
    let mut result: i64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    if last & 0x80 != 0 {
        // Negative: clear the sign bit of the top byte and negate.
        let sign_bit = 0x80i64 << (8 * (bytes.len() - 1));
        Ok(-(result & !sign_bit))
    } else {
        Ok(result)
    }
}

/// Encode `n` as a minimally-encoded `CScriptNum` stack element.
fn encode_scriptnum(n: i64) -> Vec<u8> {
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
    let top = *out.last().expect("non-zero");
    if top & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let last = out.len() - 1;
        out[last] |= 0x80;
    }
    out
}

/// Append the **minimal** push encoding of `data` to `out`, matching the
/// reference OP_VAULT implementation's `PushAll` helper (Bitcoin Core's minimal
/// push): an empty vector becomes `OP_0`, a single byte `1..=16` becomes
/// `OP_1..OP_16`, a single `0x81` becomes `OP_1NEGATE`, and everything else is a
/// length-prefixed data push. The leaf hash of the reconstructed leaf-update
/// script must byte-match the committed trigger output, so this encoding is
/// consensus-critical: a wallet builds the withdrawal leaf the same way (BIP345
/// "prefixed as minimally-encoded push-data arguments").
fn push_minimal(out: &mut Vec<u8>, data: &[u8]) {
    match data {
        [] => out.push(0x00),               // OP_0
        [b @ 1..=16] => out.push(0x50 + b), // OP_1 (0x51) ..= OP_16 (0x60)
        [0x81] => out.push(0x4f),           // OP_1NEGATE
        _ => {
            let len = data.len();
            if len < 0x4c {
                out.push(len as u8);
            } else if len <= 0xff {
                out.push(opcodes::OP_PUSHDATA1.to_u8());
                out.push(len as u8);
            } else {
                // BIP347 caps elements at 520 bytes, so PUSHDATA2 is widest.
                out.push(opcodes::OP_PUSHDATA2.to_u8());
                out.extend_from_slice(&(len as u16).to_le_bytes());
            }
            out.extend_from_slice(data);
        }
    }
}

/// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(msg);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// Bitcoin `CompactSize` (varint) encoding appended to `out`.
fn compact_size(n: u64, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// BIP345 `tagged_hash("VaultRecoverySPK", CompactSize(len(spk)) || spk)`.
fn vault_recovery_spk_hash(spk: &Script) -> [u8; 32] {
    let mut msg = Vec::with_capacity(spk.len() + 9);
    compact_size(spk.len() as u64, &mut msg);
    msg.extend_from_slice(spk.as_bytes());
    tagged_hash(b"VaultRecoverySPK", &msg)
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

/// Reconstruct the expected *triggerOut* v1 witness program for an `OP_VAULT`
/// tapleaf-update: substitute the executing leaf with `leaf_update` and fold the
/// (unchanged) merkle branch back to an output key. Mirrors
/// [`bitcoin::taproot::ControlBlock::verify_taproot_commitment`] with the leaf
/// hash swapped. The witness program is the x-only output key, so a single
/// byte-compare covers both output-key parities.
fn reconstruct_trigger_spk(control: &ControlBlock, leaf_update: &Script) -> ScriptBuf {
    let secp = Secp256k1::verification_only();
    let mut node = TapNodeHash::from_script(leaf_update, LeafVersion::TapScript);
    for elem in control.merkle_branch.as_slice() {
        node = TapNodeHash::from_node_hashes(node, *elem);
    }
    let internal: UntweakedPublicKey = control.internal_key;
    let (output_key, _parity) = internal.tap_tweak(&secp, Some(node));
    ScriptBuf::new_p2tr_tweaked(output_key)
}

/// Build the ordered prevout `TxOut` list for every input of `tx`, for a
/// committing (non-ANYONECANPAY) BIP341 sighash. Fail-closed if any is missing.
fn ordered_prevouts(
    tx: &Transaction,
    prevouts: &HashMap<OutPoint, TxOut>,
) -> Result<Vec<TxOut>, InterpError> {
    let mut all = Vec::with_capacity(tx.input.len());
    for input in &tx.input {
        let txout = prevouts
            .get(&input.previous_output)
            .ok_or(InterpError::MissingPrevout)?;
        all.push(txout.clone());
    }
    Ok(all)
}

/// Verify a BIP342 taproot script-path Schnorr signature for the current input.
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on a well-formed but
/// invalid one, and `Err(..)` on anything fail-closed (bad encoding, unknown
/// pubkey type, missing prevout, sighash failure).
fn verify_schnorr(
    sig_bytes: &[u8],
    pubkey_bytes: &[u8],
    ctx: &LeafContext,
) -> Result<bool, InterpError> {
    if pubkey_bytes.len() != 32 {
        // BIP342 treats other lengths as "unknown pubkey type" (upgradeable). We
        // fail closed instead: vault auth keys are 32-byte x-only, and honoring
        // the always-succeed upgrade path here would be a bypass vector.
        return Err(InterpError::UnknownPubkeyType {
            len: pubkey_bytes.len(),
        });
    }
    let xonly =
        XOnlyPublicKey::from_slice(pubkey_bytes).map_err(|_| InterpError::UnknownPubkeyType {
            len: pubkey_bytes.len(),
        })?;
    let sig = bitcoin::taproot::Signature::from_slice(sig_bytes)
        .map_err(|_| InterpError::BadSignatureEncoding)?;

    let leaf_hash = TapLeafHash::from_script(ctx.leaf, LeafVersion::TapScript);
    let annex = match ctx.annex {
        Some(bytes) => Some(Annex::new(bytes).map_err(|_| InterpError::MalformedScript)?),
        None => None,
    };
    let acp = matches!(
        sig.sighash_type,
        TapSighashType::AllPlusAnyoneCanPay
            | TapSighashType::NonePlusAnyoneCanPay
            | TapSighashType::SinglePlusAnyoneCanPay
    );
    let mut cache = SighashCache::new(ctx.tx);
    let sighash = if acp {
        let txout = ctx.input_txout.ok_or(InterpError::MissingPrevout)?;
        cache
            .taproot_signature_hash(
                ctx.input_index,
                &Prevouts::One(ctx.input_index, txout),
                annex,
                Some((leaf_hash, NO_CODESEPARATOR)),
                sig.sighash_type,
            )
            .map_err(|_| InterpError::SighashError)?
    } else {
        let all = ordered_prevouts(ctx.tx, ctx.prevouts)?;
        cache
            .taproot_signature_hash(
                ctx.input_index,
                &Prevouts::All(&all),
                annex,
                Some((leaf_hash, NO_CODESEPARATOR)),
                sig.sighash_type,
            )
            .map_err(|_| InterpError::SighashError)?
    };
    // The free `schnorr::verify` needs secp256k1's `global-context` feature
    // (not enabled); the context method is the non-global path.
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(sighash.to_byte_array());
    Ok(secp.verify_schnorr(&sig.signature, &msg, &xonly).is_ok())
}

/// BIP112 `CheckSequence` for `OP_CHECKSEQUENCEVERIFY` (relative timelock).
fn check_sequence(n: i64, tx: &Transaction, input_index: usize) -> Result<(), InterpError> {
    // A stack argument with the disable bit set makes OP_CSV a no-op (BIP112).
    if n & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return Ok(());
    }
    if (tx.version.0 as u32) < 2 {
        return Err(InterpError::TimelockNotSatisfied);
    }
    let tx_seq = tx.input[input_index].sequence.to_consensus_u32() as i64;
    if tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return Err(InterpError::TimelockNotSatisfied);
    }
    let mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
    let tx_masked = tx_seq & mask;
    let n_masked = n & mask;
    let same_type = (tx_masked < SEQUENCE_LOCKTIME_TYPE_FLAG
        && n_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
        || (tx_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG && n_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG);
    if !same_type || tx_masked < n_masked {
        return Err(InterpError::TimelockNotSatisfied);
    }
    Ok(())
}

/// BIP65 `CheckLockTime` for `OP_CHECKLOCKTIMEVERIFY` (absolute timelock).
fn check_locktime(n: i64, tx: &Transaction, input_index: usize) -> Result<(), InterpError> {
    let tx_lock = tx.lock_time.to_consensus_u32() as i64;
    let same_type = (tx_lock < LOCKTIME_THRESHOLD && n < LOCKTIME_THRESHOLD)
        || (tx_lock >= LOCKTIME_THRESHOLD && n >= LOCKTIME_THRESHOLD);
    if !same_type || n > tx_lock {
        return Err(InterpError::TimelockNotSatisfied);
    }
    if tx.input[input_index].sequence == Sequence::MAX {
        return Err(InterpError::TimelockNotSatisfied);
    }
    Ok(())
}

/// Execute a revealed BIP360+ leaf against the initial witness stack, queuing any
/// cross-input deferred value checks into `deferred`. Returns `Ok(())` iff
/// execution leaves exactly one truthy element.
pub(super) fn execute_leaf(
    ctx: &LeafContext,
    initial_stack: Vec<Vec<u8>>,
    deferred: &mut Vec<DeferredCheck>,
) -> Result<(), InterpError> {
    let mut stack = Stack::new(initial_stack)?;

    for instruction in ctx.leaf.instructions() {
        match instruction.map_err(|_| InterpError::MalformedScript)? {
            Instruction::PushBytes(bytes) => stack.push(bytes.as_bytes().to_vec())?,
            Instruction::Op(op) => exec_op(op, &mut stack, ctx, deferred)?,
        }
    }

    match stack.items.len() {
        1 if is_truthy(&stack.items[0]) => Ok(()),
        1 => Err(InterpError::EvalFalse),
        n => Err(InterpError::CleanStackRequired { n }),
    }
}

/// Evaluate the queued deferred checks once all inputs' leaves have executed
/// (BIP345 "Deferred check evaluation"): aggregate expected per-output values and
/// require each designated output to carry at least its accumulated amount.
pub(super) fn evaluate_deferred_checks(
    checks: &[DeferredCheck],
    tx: &Transaction,
) -> Result<(), InterpError> {
    if checks.is_empty() {
        return Ok(());
    }
    let mut out_map: HashMap<usize, u64> = HashMap::new();
    let mut add = |idx: usize, amount: u64| -> Result<(), InterpError> {
        let entry = out_map.entry(idx).or_insert(0);
        *entry = entry
            .checked_add(amount)
            .ok_or(InterpError::VaultValueNotPreserved)?;
        Ok(())
    };
    for check in checks {
        match *check {
            DeferredCheck::Trigger {
                input_amount,
                revault_amount,
                trigger_idx,
                revault_idx,
            } => {
                let carry = input_amount
                    .checked_sub(revault_amount)
                    .ok_or(InterpError::VaultValueNotPreserved)?;
                add(trigger_idx, carry)?;
                if revault_amount > 0 {
                    // Parsing guarantees revault_idx >= 0 when revault_amount > 0.
                    add(revault_idx as usize, revault_amount)?;
                }
            }
            DeferredCheck::Recovery {
                input_amount,
                vout_idx,
            } => add(vout_idx, input_amount)?,
        }
    }
    for (idx, amount) in out_map {
        if tx.output[idx].value.to_sat() < amount {
            return Err(InterpError::VaultValueNotPreserved);
        }
    }
    Ok(())
}

fn exec_op(
    op: Opcode,
    stack: &mut Stack,
    ctx: &LeafContext,
    deferred: &mut Vec<DeferredCheck>,
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
        if arg != default_check_template_verify_hash(ctx.tx, ctx.input_index) {
            return Err(InterpError::CtvTemplateMismatch);
        }
        return Ok(());
    }
    if byte == OP_VAULT {
        return exec_op_vault(stack, ctx, deferred);
    }
    if byte == OP_VAULT_RECOVER {
        return exec_op_vault_recover(stack, ctx, deferred);
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

        // Relative/absolute timelocks (verify-in-place; do not pop).
        opcodes::OP_CSV => {
            let n = read_scriptnum(stack.top("OP_CHECKSEQUENCEVERIFY")?, 5)?;
            if n < 0 {
                return Err(InterpError::TimelockNotSatisfied);
            }
            check_sequence(n, ctx.tx, ctx.input_index)
        }
        opcodes::OP_CLTV => {
            let n = read_scriptnum(stack.top("OP_CHECKLOCKTIMEVERIFY")?, 5)?;
            if n < 0 {
                return Err(InterpError::TimelockNotSatisfied);
            }
            check_locktime(n, ctx.tx, ctx.input_index)
        }

        // BIP342 Schnorr signature checks.
        opcodes::OP_CHECKSIG => {
            let pubkey = stack.pop("OP_CHECKSIG")?;
            let sig = stack.pop("OP_CHECKSIG")?;
            if sig.is_empty() {
                return stack.push(Vec::new()); // false
            }
            if verify_schnorr(&sig, &pubkey, ctx)? {
                stack.push(vec![1])
            } else {
                // BIP342: a non-empty signature that fails verification makes the
                // whole script fail (not merely push false).
                Err(InterpError::SchnorrVerifyFailed)
            }
        }
        opcodes::OP_CHECKSIGVERIFY => {
            let pubkey = stack.pop("OP_CHECKSIGVERIFY")?;
            let sig = stack.pop("OP_CHECKSIGVERIFY")?;
            if sig.is_empty() {
                return Err(InterpError::VerifyFailed);
            }
            if verify_schnorr(&sig, &pubkey, ctx)? {
                Ok(())
            } else {
                Err(InterpError::SchnorrVerifyFailed)
            }
        }
        opcodes::OP_CHECKSIGADD => {
            let pubkey = stack.pop("OP_CHECKSIGADD")?;
            let n = read_scriptnum(&stack.pop("OP_CHECKSIGADD")?, 4)?;
            let sig = stack.pop("OP_CHECKSIGADD")?;
            if sig.is_empty() {
                return stack.push(encode_scriptnum(n));
            }
            if verify_schnorr(&sig, &pubkey, ctx)? {
                stack.push(encode_scriptnum(n + 1))
            } else {
                Err(InterpError::SchnorrVerifyFailed)
            }
        }

        // Everything else — including standard opcodes not yet needed — is
        // fail-closed rejected.
        other => Err(InterpError::UnimplementedOpcode { opcode: other }),
    }
}

/// OP_VAULT (0xfc) — BIP345. Parse the tapleaf-update parameters, reconstruct and
/// verify the trigger output taptree, verify the optional revault output, and
/// queue the value-preservation deferred check. Leaves a single `0x01`.
fn exec_op_vault(
    stack: &mut Stack,
    ctx: &LeafContext,
    deferred: &mut Vec<DeferredCheck>,
) -> Result<(), InterpError> {
    let input_txout = ctx.input_txout.ok_or(InterpError::MissingPrevout)?;
    let num_outputs = ctx.tx.output.len() as i64;

    // <leaf-update-script-body>
    let body = stack.pop("OP_VAULT")?;
    // <push-count>
    let push_count = read_scriptnum(&stack.pop("OP_VAULT")?, 4)?;
    if push_count < 0 {
        return Err(InterpError::VaultBadStack);
    }
    let push_count = push_count as usize;
    // After popping the body + push-count, at least 3 + push-count items remain
    // (the data items plus trigger/revault indices and revault amount).
    if stack.items.len() < 3 + push_count {
        return Err(InterpError::VaultBadStack);
    }

    // Pop the leaf-update data items and prepend each (first-popped innermost) to
    // the body as a minimal push: yields `<item_{n-1}> .. <item_0> <body>`.
    let mut items = Vec::with_capacity(push_count);
    for _ in 0..push_count {
        items.push(stack.pop("OP_VAULT")?);
    }
    let mut script_bytes = Vec::new();
    for item in items.iter().rev() {
        push_minimal(&mut script_bytes, item);
    }
    script_bytes.extend_from_slice(&body);
    let leaf_update_script = ScriptBuf::from_bytes(script_bytes);

    // <trigger-vout-idx>
    let trigger_idx = read_scriptnum(&stack.pop("OP_VAULT")?, 4)?;
    if trigger_idx < 0 || trigger_idx >= num_outputs {
        return Err(InterpError::VaultBadStack);
    }
    let trigger_idx = trigger_idx as usize;
    // <revault-vout-idx> (>= num_outputs invalid; negative only allowed as -1)
    let revault_idx = read_scriptnum(&stack.pop("OP_VAULT")?, 4)?;
    if revault_idx >= num_outputs || (revault_idx < 0 && revault_idx != -1) {
        return Err(InterpError::VaultBadStack);
    }
    // <revault-amount> (up to 7 bytes, >= 0)
    let revault_amount = read_scriptnum(&stack.pop("OP_VAULT")?, 7)?;
    if revault_amount < 0
        || (revault_amount > 0 && revault_idx < 0)
        || (revault_amount == 0 && revault_idx != -1)
    {
        return Err(InterpError::VaultBadStack);
    }
    let revault_amount = revault_amount as u64;

    // triggerOut must be a v1 witness program (p2tr).
    let trigger_out = &ctx.tx.output[trigger_idx];
    if !trigger_out.script_pubkey.is_p2tr() {
        return Err(InterpError::VaultTriggerNotV1);
    }
    // Taptree reconstruction: expected triggerOut sPK with the executing leaf
    // replaced by the leaf-update script.
    let expected = reconstruct_trigger_spk(ctx.control, &leaf_update_script);
    if trigger_out.script_pubkey != expected {
        return Err(InterpError::VaultTriggerMismatch);
    }

    // revaultOut (if any) must reuse the input's scriptPubKey exactly.
    if revault_idx >= 0 {
        let revault_out = &ctx.tx.output[revault_idx as usize];
        if revault_out.script_pubkey != input_txout.script_pubkey {
            return Err(InterpError::VaultRevaultMismatch);
        }
    }

    let input_amount = input_txout.value.to_sat();
    // SHOULD short-circuit: trigger (+ revault) value must at least carry the
    // input; the authoritative check is the deferred aggregation below.
    let trigger_value = trigger_out.value;
    let revault_value = if revault_idx >= 0 {
        ctx.tx.output[revault_idx as usize].value
    } else {
        Amount::ZERO
    };
    if trigger_value
        .checked_add(revault_value)
        .ok_or(InterpError::VaultValueNotPreserved)?
        .to_sat()
        < input_amount
    {
        return Err(InterpError::VaultValueNotPreserved);
    }

    deferred.push(DeferredCheck::Trigger {
        input_amount,
        revault_amount,
        trigger_idx,
        revault_idx,
    });
    stack.push(vec![1])
}

/// OP_VAULT_RECOVER (0xfb) — BIP345. Verify the recovery output's scriptPubKey
/// tagged hash matches the pushed hash, and queue the value-preservation check.
fn exec_op_vault_recover(
    stack: &mut Stack,
    ctx: &LeafContext,
    deferred: &mut Vec<DeferredCheck>,
) -> Result<(), InterpError> {
    let input_txout = ctx.input_txout.ok_or(InterpError::MissingPrevout)?;
    let num_outputs = ctx.tx.output.len() as i64;

    // <recovery-sPK-hash> (exactly 32 bytes)
    let hash_arg = stack.pop("OP_VAULT_RECOVER")?;
    if hash_arg.len() != RECOVERY_SPK_HASH_LEN {
        return Err(InterpError::VaultRecoverBadHashLen {
            len: hash_arg.len(),
        });
    }
    // <recovery-vout-idx>
    let vout_idx = read_scriptnum(&stack.pop("OP_VAULT_RECOVER")?, 4)?;
    if vout_idx < 0 || vout_idx >= num_outputs {
        return Err(InterpError::VaultBadStack);
    }
    let vout_idx = vout_idx as usize;

    let recovery_out = &ctx.tx.output[vout_idx];
    if vault_recovery_spk_hash(&recovery_out.script_pubkey)[..] != hash_arg[..] {
        return Err(InterpError::VaultRecoverMismatch);
    }

    deferred.push(DeferredCheck::Recovery {
        input_amount: input_txout.value.to_sat(),
        vout_idx,
    });
    stack.push(vec![1])
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

    /// A control block with an empty merkle branch — sufficient for opcodes that
    /// don't reconstruct the taptree (CAT/CTV/timelock/sig tests).
    fn dummy_control() -> ControlBlock {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let kp = SecretKey::from_slice(&[0x11; 32]).unwrap().keypair(&secp);
        let (xonly, _) = kp.x_only_public_key();
        let mut bytes = vec![0xc0];
        bytes.extend_from_slice(&xonly.serialize());
        ControlBlock::decode(&bytes).unwrap()
    }

    /// Execute a leaf with an empty prevout set and dummy control block, for the
    /// opcodes that don't need them.
    fn run(leaf: &Script, stack: Vec<Vec<u8>>) -> Result<(), InterpError> {
        run_on(&dummy_tx(), 0, leaf, stack)
    }

    fn run_on(
        tx: &Transaction,
        input_index: usize,
        leaf: &Script,
        stack: Vec<Vec<u8>>,
    ) -> Result<(), InterpError> {
        let prevouts = HashMap::new();
        let control = dummy_control();
        let ctx = LeafContext {
            tx,
            input_index,
            prevouts: &prevouts,
            input_txout: None,
            control: &control,
            annex: None,
            leaf,
        };
        let mut deferred = Vec::new();
        execute_leaf(&ctx, stack, &mut deferred)?;
        evaluate_deferred_checks(&deferred, tx)
    }

    #[test]
    fn op_cat_concatenates_and_checks_hash() {
        let expected = sha256::Hash::hash(b"abcd").to_byte_array().to_vec();
        let leaf = Builder::new()
            .push_opcode(Opcode::from(super::OP_CAT))
            .push_opcode(opcodes::OP_SHA256)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(expected.as_slice()).unwrap())
            .push_opcode(opcodes::OP_EQUAL)
            .into_script();
        run(&leaf, vec![b"ab".to_vec(), b"cd".to_vec()]).expect("valid CAT spend");
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
        run_on(&tx, 0, &ctv_leaf(&good), vec![]).expect("matching CTV template");
        let mut bad = good;
        bad[0] ^= 0x01;
        assert_eq!(
            run_on(&tx, 0, &ctv_leaf(&bad), vec![]),
            Err(InterpError::CtvTemplateMismatch)
        );
        assert_eq!(
            run_on(&tx, 0, &ctv_leaf(&[0u8; 16]), vec![]),
            Err(InterpError::CtvBadArgLength { len: 16 })
        );
    }

    /// Proof of BIP119 compliance against BIP119's authoritative vectors.
    #[test]
    fn bip119_ctvhash_golden_vectors() {
        let json = include_str!("vectors/ctvhash.json");
        let entries: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        let mut checked = 0usize;
        for entry in &entries {
            let Some(hex_tx) = entry.get("hex_tx").and_then(|v| v.as_str()) else {
                continue;
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
            "expected the representative BIP119 vector set"
        );
    }

    #[test]
    fn unimplemented_opcode_fails_closed() {
        let leaf = Builder::new().push_opcode(opcodes::OP_ADD).into_script();
        assert!(matches!(
            run(&leaf, vec![vec![1], vec![1]]),
            Err(InterpError::UnimplementedOpcode { .. })
        ));
    }

    #[test]
    fn non_clean_or_false_stack_rejected() {
        let leaf = Builder::new()
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .into_script();
        assert_eq!(
            run(&leaf, vec![]),
            Err(InterpError::CleanStackRequired { n: 2 })
        );
        let leaf_false = Builder::new().into_script();
        assert_eq!(run(&leaf_false, vec![vec![]]), Err(InterpError::EvalFalse));
    }

    /// Cross-check our BIP340 `tagged_hash` + `compact_size` against the
    /// `bitcoin` crate's BIP341-vector-tested `TapLeafHash`, which is itself
    /// `tagged_hash("TapLeaf", leaf_version || CompactSize(len(script)) ||
    /// script)`. A match proves the primitives underlying the BIP345
    /// `VaultRecoverySPK` hash (there are no standalone BIP345 vectors).
    #[test]
    fn tagged_hash_matches_bip341_tapleaf() {
        for script_bytes in [b"\x51".as_slice(), b"\xb2\x75\xfd", &[0xab; 40]] {
            let mut preimage = vec![LeafVersion::TapScript.to_consensus()];
            compact_size(script_bytes.len() as u64, &mut preimage);
            preimage.extend_from_slice(script_bytes);
            let ours = tagged_hash(b"TapLeaf", &preimage);

            let theirs =
                TapLeafHash::from_script(Script::from_bytes(script_bytes), LeafVersion::TapScript)
                    .to_byte_array();
            assert_eq!(ours, theirs, "tagged_hash/compact_size vs BIP341 TapLeaf");
        }
    }

    /// The VaultRecoverySPK preimage is `CompactSize(len(spk)) || spk`; confirm
    /// our helper hashes exactly that under the BIP345 tag.
    #[test]
    fn vault_recovery_spk_hash_preimage() {
        let spk = Script::from_bytes(b"\x51\x20\x00\x01\x02\x03");
        let mut preimage = Vec::new();
        compact_size(spk.len() as u64, &mut preimage);
        preimage.extend_from_slice(spk.as_bytes());
        assert_eq!(
            vault_recovery_spk_hash(spk),
            tagged_hash(b"VaultRecoverySPK", &preimage)
        );
    }

    /// Lock `push_minimal` to the reference OP_VAULT `PushAll` minimal encoding —
    /// the consensus-critical rule for reconstructing the leaf-update script.
    #[test]
    fn push_minimal_matches_reference() {
        let enc = |d: &[u8]| {
            let mut o = Vec::new();
            push_minimal(&mut o, d);
            o
        };
        assert_eq!(enc(&[]), vec![0x00], "empty -> OP_0");
        assert_eq!(enc(&[1]), vec![0x51], "1 -> OP_1");
        assert_eq!(enc(&[6]), vec![0x56], "6 -> OP_6");
        assert_eq!(enc(&[16]), vec![0x60], "16 -> OP_16");
        assert_eq!(enc(&[0x81]), vec![0x4f], "0x81 -> OP_1NEGATE");
        assert_eq!(
            enc(&[0]),
            vec![0x01, 0x00],
            "1-byte 0x00 -> length-prefixed"
        );
        assert_eq!(enc(&[17]), vec![0x01, 17], "17 -> length-prefixed");
        assert_eq!(
            enc(&[0xab, 0xcd]),
            vec![0x02, 0xab, 0xcd],
            "2-byte -> len-prefixed"
        );
        let big = vec![0x11u8; 80];
        let mut expect = vec![0x4c, 80];
        expect.extend_from_slice(&big);
        assert_eq!(enc(&big), expect, "80 bytes -> PUSHDATA1");
    }

    #[test]
    fn scriptnum_roundtrip_and_minimality() {
        for n in [
            0i64, 1, -1, 16, 127, 128, -128, 255, 256, -256, 65535, 500_000,
        ] {
            let enc = encode_scriptnum(n);
            assert_eq!(read_scriptnum(&enc, 7).unwrap(), n, "roundtrip {n}");
        }
        // Non-minimal encodings rejected.
        assert_eq!(read_scriptnum(&[0x00], 4), Err(InterpError::BadScriptNum));
        assert_eq!(
            read_scriptnum(&[0x01, 0x00], 4),
            Err(InterpError::BadScriptNum)
        );
        // Over-length rejected.
        assert_eq!(
            read_scriptnum(&[1, 2, 3, 4, 5], 4),
            Err(InterpError::BadScriptNum)
        );
    }
}
