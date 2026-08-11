//! P2MR script-path signing helpers.
//!
//! Builds and signs single-leaf P2MR spends for the four supported schemes
//! (Schnorr, ML-DSA, SLH-DSA, hybrid EC+SLH). Used by the wallet's spend path
//! (`build_p2mr_spend_from_prevout` / `build_hybrid_ec_slh_spend_from_prevout`)
//! and by the validation unit tests.

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    blockdata::{opcodes::all::OP_CHECKSIG, script::Builder},
    hashes::Hash as _,
    key::Secp256k1,
    secp256k1::{Keypair, Message, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
};
use bitcoin_p2mr_pqc::{
    TapScriptBuf,
    p2mr::P2MR_LEAF_VERSION,
    taproot::{LeafVersion as P2mrLeafVersion, TapNodeHash, TapNodeHashExt as _},
};
use bitcoinpqc::{Algorithm, generate_keypair, sign};

use super::{leaf_script::build_hybrid_ec_slh_leaf, limits::ML_DSA_44_PUBLIC_KEY_SIZE};

/// Signature algorithm for single-leaf `PUSH <pk> OP_CHECKSIG` spends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignAlgorithm {
    Schnorr,
    Mldsa,
    Slh,
}

impl SignAlgorithm {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Schnorr => "schnorr",
            Self::Mldsa => "mldsa",
            Self::Slh => "slh",
        }
    }

    pub(crate) const fn to_bitcoinpqc(self) -> Algorithm {
        match self {
            Self::Schnorr => Algorithm::SECP256K1_SCHNORR,
            Self::Mldsa => Algorithm::ML_DSA_44,
            Self::Slh => Algorithm::SLH_DSA_SHA2_128S,
        }
    }
}

/// Canonical sighash names matching the `p2mr_signer` CLI `--sighash` values.
#[must_use]
pub fn sighash_label(sighash_type: TapSighashType) -> &'static str {
    match sighash_type {
        TapSighashType::Default | TapSighashType::All => "all",
        TapSighashType::None => "none",
        TapSighashType::Single => "single",
        TapSighashType::AllPlusAnyoneCanPay => "all,anyonecanpay",
        TapSighashType::NonePlusAnyoneCanPay => "none,anyonecanpay",
        TapSighashType::SinglePlusAnyoneCanPay => "single,anyonecanpay",
    }
}

/// Output of a single-leaf P2MR script-path sign operation.
#[derive(Clone, Debug)]
pub struct SignedP2mrSpend {
    pub algorithm: SignAlgorithm,
    pub sighash_type: TapSighashType,
    pub public_key: Vec<u8>,
    pub leaf_script: ScriptBuf,
    pub merkle_root: [u8; 32],
    pub script_pubkey: ScriptBuf,
    pub control_block: Vec<u8>,
    pub sighash: [u8; 32],
    pub signature: Vec<u8>,
    pub witness: Witness,
    pub funding_tx: Transaction,
    pub unsigned_spend_tx: Transaction,
    pub signed_spend_tx: Transaction,
}

/// Core signing artifacts shared by output-only and coinbase-funded spend builders.
struct P2mrSpendSigningResult {
    public_key: Vec<u8>,
    leaf_script: ScriptBuf,
    merkle_root: [u8; 32],
    script_pubkey: ScriptBuf,
    control_block: Vec<u8>,
    sighash: [u8; 32],
    witness_sig: Vec<u8>,
    witness: Witness,
    unsigned_spend_tx: Transaction,
    signed_spend_tx: Transaction,
}

/// Validate entropy length for the chosen algorithm.
pub fn validate_entropy(entropy: &[u8], algorithm: SignAlgorithm) -> Result<(), String> {
    match algorithm {
        SignAlgorithm::Schnorr if entropy.len() != 32 => Err(
            "--entropy-hex must be exactly 32 bytes (64 hex chars) for schnorr; \
             bitcoinpqc uses only the first 32 bytes as the secret key scalar"
                .into(),
        ),
        SignAlgorithm::Mldsa | SignAlgorithm::Slh if entropy.len() < 128 => {
            Err("--entropy-hex must be at least 128 bytes (256 hex chars) for mldsa / slh".into())
        }
        _ => Ok(()),
    }
}

/// Validate spend output value does not exceed the funding prevout value.
pub fn validate_output_value(output_value: u64, prevout_value: u64) -> Result<(), String> {
    if output_value > prevout_value {
        return Err(format!(
            "--output-value ({output_value}) must be <= --prevout-value ({prevout_value})"
        ));
    }
    Ok(())
}

/// Build a single-sig `PUSH <pk> OP_CHECKSIG` leaf script.
pub fn build_checksig_leaf(pubkey: &[u8]) -> Result<ScriptBuf, String> {
    if pubkey.len() == ML_DSA_44_PUBLIC_KEY_SIZE {
        let mut bytes = Vec::with_capacity(3 + pubkey.len() + 1);
        bytes.push(0x4d); // OP_PUSHDATA2
        bytes.extend_from_slice(&(pubkey.len() as u16).to_le_bytes());
        bytes.extend_from_slice(pubkey);
        bytes.push(OP_CHECKSIG.to_u8());
        Ok(ScriptBuf::from_bytes(bytes))
    } else {
        let pk32: [u8; 32] = pubkey
            .try_into()
            .map_err(|_| format!("expected 32-byte pubkey, got {} bytes", pubkey.len()))?;
        Ok(Builder::new()
            .push_slice(pk32)
            .push_opcode(OP_CHECKSIG)
            .into_script())
    }
}

/// Compute the merkle root for a single-leaf P2MR tree.
#[must_use]
pub fn single_leaf_merkle_root(leaf_script: &ScriptBuf) -> [u8; 32] {
    let leaf_version =
        P2mrLeafVersion::from_consensus(P2MR_LEAF_VERSION).expect("valid P2MR leaf version");
    TapNodeHash::from_script(
        &TapScriptBuf::from_bytes(leaf_script.as_bytes().to_vec()),
        leaf_version,
    )
    .to_byte_array()
}

/// Single-leaf P2MR control block — Core wire: exactly one byte `0xc1` (empty branch).
///
/// P2MR Core `P2MR_CONTROL_BASE_SIZE = 1` (no internal key). Do **not** pad with 32
/// zero bytes; Core would treat them as a merkle sibling and fail witness-program match.
#[must_use]
pub fn single_leaf_control_block() -> Vec<u8> {
    vec![0xc1]
}

/// Build P2MR `scriptPubKey` from a merkle root (`0x52 0x20 <root>`).
#[must_use]
pub fn p2mr_script_pubkey(merkle_root: [u8; 32]) -> ScriptBuf {
    let mut spk = vec![0x52, 0x20];
    spk.extend_from_slice(&merkle_root);
    ScriptBuf::from_bytes(spk)
}

/// Append the tapscript sighash type byte when required by BIP 341/342.
///
/// Only [`TapSighashType::Default`] (hash_type `0x00`) omits the trailing byte: a bare
/// 64-byte Schnorr (or bare canonical PQ sig) is verified by Core as `SIGHASH_DEFAULT`.
///
/// **Do not** treat [`TapSighashType::All`] like Default. Signing with `All` embeds
/// `hash_type = 0x01` in the TapSighash preimage; if the witness omits the `0x01` byte,
/// Core re-hashes with `0x00` and rejects with "Invalid Schnorr signature".
#[must_use]
pub fn append_sighash(mut sig: Vec<u8>, sighash_type: TapSighashType) -> Vec<u8> {
    if sighash_type != TapSighashType::Default {
        sig.push(sighash_type as u8);
    }
    sig
}

fn generate_p2mr_keypair(
    algorithm: SignAlgorithm,
    entropy: &[u8],
) -> Result<bitcoinpqc::KeyPair, String> {
    validate_entropy(entropy, algorithm)?;
    generate_keypair(algorithm.to_bitcoinpqc(), entropy)
        .map_err(|e| format!("key generation failed: {e}"))
}

/// Shared sighash and witness construction for P2MR script-path spends.
fn sign_p2mr_spend_core(
    keypair: &bitcoinpqc::KeyPair,
    sighash_type: TapSighashType,
    prevout: TxOut,
    spend_previous_output: OutPoint,
    outputs: Vec<TxOut>,
) -> Result<P2mrSpendSigningResult, String> {
    let total_out: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    validate_output_value(total_out, prevout.value.to_sat())?;

    let leaf_script = build_checksig_leaf(&keypair.public_key.bytes)?;
    let merkle_root = single_leaf_merkle_root(&leaf_script);
    let script_pubkey = p2mr_script_pubkey(merkle_root);
    let control_block = single_leaf_control_block();

    let unsigned_spend_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: spend_previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let leaf_hash = TapLeafHash::from_script(
        leaf_script.as_script(),
        LeafVersion::from_consensus(P2MR_LEAF_VERSION).expect("valid leaf version"),
    );
    let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
    let mut cache = SighashCache::new(&unsigned_spend_tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
        .map_err(|e| format!("sighash computation failed: {e}"))?;

    let signature = sign(&keypair.secret_key, sighash.as_byte_array())
        .map_err(|e| format!("signing failed: {e}"))?;
    let witness_sig = append_sighash(signature.bytes, sighash_type);

    let mut witness = Witness::new();
    witness.push(&witness_sig);
    witness.push(leaf_script.as_bytes());
    witness.push(&control_block);

    let mut signed_spend_tx = unsigned_spend_tx.clone();
    signed_spend_tx.input[0].witness = witness.clone();

    Ok(P2mrSpendSigningResult {
        public_key: keypair.public_key.bytes.clone(),
        leaf_script,
        merkle_root,
        script_pubkey,
        control_block,
        sighash: sighash.to_byte_array(),
        witness_sig,
        witness,
        unsigned_spend_tx,
        signed_spend_tx,
    })
}

/// Sign a single-leaf P2MR script-path spend (overload model).
pub fn sign_p2mr_script_path_spend(
    algorithm: SignAlgorithm,
    entropy: &[u8],
    sighash_type: TapSighashType,
    prevout_value: u64,
    output_value: u64,
) -> Result<SignedP2mrSpend, String> {
    validate_output_value(output_value, prevout_value)?;
    let keypair = generate_p2mr_keypair(algorithm, entropy)?;

    let leaf_script = build_checksig_leaf(&keypair.public_key.bytes)?;
    let script_pubkey = p2mr_script_pubkey(single_leaf_merkle_root(&leaf_script));

    // Synthetic funding tx: output-only (no inputs). Valid for submitblock harnesses.
    let funding_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(prevout_value),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let funding_txid = funding_tx.compute_txid();
    let prevout = funding_tx.output[0].clone();

    let signed = sign_p2mr_spend_core(
        &keypair,
        sighash_type,
        prevout,
        OutPoint {
            txid: funding_txid,
            vout: 0,
        },
        vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: ScriptBuf::new(),
        }],
    )?;

    Ok(SignedP2mrSpend {
        algorithm,
        sighash_type,
        public_key: signed.public_key,
        leaf_script: signed.leaf_script,
        merkle_root: signed.merkle_root,
        script_pubkey: signed.script_pubkey,
        control_block: signed.control_block,
        sighash: signed.sighash,
        signature: signed.witness_sig,
        witness: signed.witness,
        funding_tx,
        unsigned_spend_tx: signed.unsigned_spend_tx,
        signed_spend_tx: signed.signed_spend_tx,
    })
}

/// Validate entropy lengths for hybrid EC (32 B) + SLH (≥128 B) P2MR spends.
pub fn validate_hybrid_entropy(ec_entropy: &[u8], slh_entropy: &[u8]) -> Result<(), String> {
    if ec_entropy.len() != 32 {
        return Err(
            "EC entropy must be exactly 32 bytes (64 hex chars) for secp256k1 Schnorr".into(),
        );
    }
    if slh_entropy.len() < 128 {
        return Err(
            "SLH entropy must be at least 128 bytes (256 hex chars) for SLH-DSA-SHA2-128s".into(),
        );
    }
    Ok(())
}

fn ec_keypair_from_entropy(ec_entropy: &[u8; 32]) -> Result<Keypair, String> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(ec_entropy).map_err(|e| format!("invalid EC entropy: {e}"))?;
    Ok(Keypair::from_secret_key(&secp, &sk))
}

fn slh_pk32(keypair: &bitcoinpqc::KeyPair) -> Result<[u8; 32], String> {
    keypair.public_key.bytes.as_slice().try_into().map_err(|_| {
        format!(
            "expected 32-byte SLH pubkey, got {} bytes",
            keypair.public_key.bytes.len()
        )
    })
}

/// Build a P2MR `scriptPubKey` for a single Schnorr / ML-DSA / SLH leaf.
pub fn p2mr_output_for_algorithm(
    algorithm: SignAlgorithm,
    entropy: &[u8],
) -> Result<(ScriptBuf, ScriptBuf), String> {
    let keypair = generate_p2mr_keypair(algorithm, entropy)?;
    let leaf_script = build_checksig_leaf(&keypair.public_key.bytes)?;
    let script_pubkey = p2mr_script_pubkey(single_leaf_merkle_root(&leaf_script));
    Ok((script_pubkey, leaf_script))
}

/// Build a P2MR `scriptPubKey` for a hybrid EC+SLH leaf.
pub fn p2mr_output_for_hybrid_ec_slh(
    ec_entropy: &[u8; 32],
    slh_entropy: &[u8],
) -> Result<(ScriptBuf, ScriptBuf), String> {
    validate_hybrid_entropy(ec_entropy, slh_entropy)?;
    let ec_keypair = ec_keypair_from_entropy(ec_entropy)?;
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_SHA2_128S, slh_entropy)
        .map_err(|e| format!("SLH key generation failed: {e}"))?;
    let ec_pk: [u8; 32] = XOnlyPublicKey::from_keypair(&ec_keypair).0.serialize();
    let slh_pk = slh_pk32(&slh_keypair)?;
    let leaf_script = build_hybrid_ec_slh_leaf(&ec_pk, &slh_pk);
    let script_pubkey = p2mr_script_pubkey(single_leaf_merkle_root(&leaf_script));
    Ok((script_pubkey, leaf_script))
}

/// Sign a single-leaf P2MR script-path spend from an existing confirmed prevout.
pub fn build_p2mr_spend_from_prevout(
    algorithm: SignAlgorithm,
    entropy: &[u8],
    sighash_type: TapSighashType,
    spend_previous_output: OutPoint,
    prevout: TxOut,
    outputs: Vec<TxOut>,
) -> Result<Transaction, String> {
    let keypair = generate_p2mr_keypair(algorithm, entropy)?;
    let signed = sign_p2mr_spend_core(
        &keypair,
        sighash_type,
        prevout,
        spend_previous_output,
        outputs,
    )?;
    Ok(signed.signed_spend_tx)
}

/// Sign a hybrid EC+SLH P2MR script-path spend from an existing confirmed prevout.
pub fn build_hybrid_ec_slh_spend_from_prevout(
    ec_entropy: &[u8; 32],
    slh_entropy: &[u8],
    sighash_type: TapSighashType,
    spend_previous_output: OutPoint,
    prevout: TxOut,
    outputs: Vec<TxOut>,
) -> Result<Transaction, String> {
    validate_hybrid_entropy(ec_entropy, slh_entropy)?;
    let total_out: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    validate_output_value(total_out, prevout.value.to_sat())?;

    let ec_keypair = ec_keypair_from_entropy(ec_entropy)?;
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_SHA2_128S, slh_entropy)
        .map_err(|e| format!("SLH key generation failed: {e}"))?;

    let ec_pk: [u8; 32] = XOnlyPublicKey::from_keypair(&ec_keypair).0.serialize();
    let slh_pk = slh_pk32(&slh_keypair)?;
    let leaf_script = build_hybrid_ec_slh_leaf(&ec_pk, &slh_pk);
    let leaf_hash = TapLeafHash::from_script(
        leaf_script.as_script(),
        LeafVersion::from_consensus(P2MR_LEAF_VERSION).expect("valid leaf version"),
    );

    let unsigned_spend_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: spend_previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let prevouts = Prevouts::All(std::slice::from_ref(&prevout));
    let mut cache = SighashCache::new(&unsigned_spend_tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
        .map_err(|e| format!("sighash computation failed: {e}"))?;

    let secp = Secp256k1::new();
    let ec_sig =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &ec_keypair);
    let slh_sig = sign(&slh_keypair.secret_key, sighash.as_byte_array())
        .map_err(|e| format!("SLH signing failed: {e}"))?;

    let mut witness = Witness::new();
    witness.push(append_sighash(ec_sig.serialize().to_vec(), sighash_type));
    witness.push(append_sighash(slh_sig.bytes, sighash_type));
    witness.push(leaf_script.as_bytes());
    witness.push(single_leaf_control_block());

    let mut signed_spend_tx = unsigned_spend_tx;
    signed_spend_tx.input[0].witness = witness;
    Ok(signed_spend_tx)
}

#[cfg(test)]
mod tests {
    use super::{
        super::schemes::{self, SignatureScheme, TapscriptVerifyContext},
        *,
    };

    #[test]
    fn single_leaf_control_block_is_core_wire_one_byte() {
        let cb = single_leaf_control_block();
        assert_eq!(cb.len(), 1);
        assert_eq!(cb, vec![0xc1]);
    }

    /// BIP 341: bare 64-byte Schnorr ⇒ `SIGHASH_DEFAULT` (hash_type 0x00 in preimage).
    /// Signing with `All` (0x01) and omitting the trailing byte is Core-incompatible.
    #[test]
    fn bare_schnorr_must_use_default_not_all_preimage() {
        const ENTROPY: [u8; 32] = [0x42; 32];
        let signed_default = sign_p2mr_script_path_spend(
            SignAlgorithm::Schnorr,
            &ENTROPY,
            TapSighashType::Default,
            50_000,
            40_000,
        )
        .expect("sign default");
        let signed_all = sign_p2mr_script_path_spend(
            SignAlgorithm::Schnorr,
            &ENTROPY,
            TapSighashType::All,
            50_000,
            40_000,
        )
        .expect("sign all");

        // Same keys/prevout shape, different hash_type byte → different messages.
        assert_ne!(
            signed_default.sighash, signed_all.sighash,
            "TapSighashType::Default and ::All must produce different TapSighash digests"
        );

        // Default → bare 64 B (Core SIGHASH_DEFAULT path).
        assert_eq!(signed_default.signature.len(), 64);
        assert_eq!(
            schemes::parse_sighash_type(&signed_default.signature),
            TapSighashType::Default
        );

        // All → 65 B with explicit 0x01 (Core SIGHASH_ALL path).
        assert_eq!(signed_all.signature.len(), 65);
        assert_eq!(signed_all.signature[64], TapSighashType::All as u8);
        assert_eq!(
            schemes::parse_sighash_type(&signed_all.signature),
            TapSighashType::All
        );

        // Fixed-entropy, fixed template (Version::TWO, empty dest spk, 50k→40k):
        // re-sign must be bit-identical (detects non-determinism / template drift).
        let re_signed = sign_p2mr_script_path_spend(
            SignAlgorithm::Schnorr,
            &ENTROPY,
            TapSighashType::Default,
            50_000,
            40_000,
        )
        .expect("re-sign");
        assert_eq!(re_signed.sighash, signed_default.sighash);
        assert_eq!(re_signed.signature, signed_default.signature);
        // Distinct from All preimage (already asserted) — pin that Default digest is
        // non-zero and 32 bytes so accidental empty/placeholder can't pass.
        assert_ne!(signed_default.sighash, [0u8; 32]);
        assert_eq!(signed_default.sighash.len(), 32);

        // Self-verify both under enforcer schemes (matches Core hashtype selection).
        for signed in [&signed_default, &signed_all] {
            let prevout = &signed.funding_tx.output[0];
            let prevouts = Prevouts::All(std::slice::from_ref(prevout));
            let leaf_hash = TapLeafHash::from_script(
                signed.leaf_script.as_script(),
                LeafVersion::from_consensus(P2MR_LEAF_VERSION).expect("leaf version"),
            );
            let mut budget = None;
            let mut ctx = TapscriptVerifyContext {
                tx: &signed.signed_spend_tx,
                input_index: 0,
                prevouts: &prevouts,
                leaf_hash,
                pqc_budget: &mut budget,
            };
            schemes::verify_tapscript_signature(
                SignatureScheme::Schnorr,
                &signed.signature,
                &signed.public_key,
                &mut ctx,
            )
            .expect("enforcer verifies own Schnorr spend");
        }

        // Legacy bug: All-preimage + bare 64 B must NOT verify (Core would reject).
        let mut legacy = signed_all.signature.clone();
        legacy.truncate(64);
        let prevout = &signed_all.funding_tx.output[0];
        let prevouts = Prevouts::All(std::slice::from_ref(prevout));
        let leaf_hash = TapLeafHash::from_script(
            signed_all.leaf_script.as_script(),
            LeafVersion::from_consensus(P2MR_LEAF_VERSION).expect("leaf version"),
        );
        let mut budget = None;
        let mut ctx = TapscriptVerifyContext {
            tx: &signed_all.signed_spend_tx,
            input_index: 0,
            prevouts: &prevouts,
            leaf_hash,
            pqc_budget: &mut budget,
        };
        // Witness still holds full sig; verify the truncated element alone.
        let err = schemes::verify_tapscript_signature(
            SignatureScheme::Schnorr,
            &legacy,
            &signed_all.public_key,
            &mut ctx,
        );
        assert!(
            err.is_err(),
            "All-preimage signature without 0x01 byte must fail (Core Invalid Schnorr)"
        );
    }
}
