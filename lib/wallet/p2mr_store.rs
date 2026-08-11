//! Persistent store for the wallet's BIP 360 (P2MR) keys and addresses.
//!
//! BDK descriptors cannot model a bare merkle-root scriptPubKey
//! (`OP_2 OP_PUSHBYTES_32 <root>`), so P2MR key material is kept here, separate
//! from the BDK wallet, in a single JSON file (`p2mr.json`) in the wallet data
//! dir. The stored entropy is secret; the file is written owner-only. It is
//! plaintext (like the seed store's plaintext mode) — encrypting it under the
//! wallet password is a possible future hardening.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use bitcoin::{
    Address, OutPoint, ScriptBuf, Transaction, TxOut, params::Params, sighash::TapSighashType,
};
use serde::{Deserialize, Serialize};

use crate::{
    validator::pqc::signer::{
        SignAlgorithm, build_hybrid_ec_slh_spend_from_prevout, build_p2mr_spend_from_prevout,
        p2mr_output_for_algorithm, p2mr_output_for_hybrid_ec_slh,
    },
    wallet::error,
};

const P2MR_FILE_NAME: &str = "p2mr.json";
const CURRENT_VERSION: u32 = 1;

/// Entropy sizes (bytes). Schnorr uses a 32-byte seed; the PQC schemes require
/// at least 128 bytes of user entropy for key generation.
const EC_ENTROPY_LEN: usize = 32;
const PQC_ENTROPY_LEN: usize = 128;

/// Which spend scheme a P2MR address uses. The single-leaf schemes carry one
/// key; the hybrid scheme carries one key per algorithm in the leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum P2mrScheme {
    Schnorr,
    Mldsa,
    Slh,
    /// EC (Schnorr) + SLH-DSA in one leaf.
    HybridEcSlh,
}

impl P2mrScheme {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Schnorr => "schnorr",
            Self::Mldsa => "mldsa",
            Self::Slh => "slh",
            Self::HybridEcSlh => "hybrid_ec_slh",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "schnorr" => Some(Self::Schnorr),
            "mldsa" | "ml-dsa" | "ml_dsa" => Some(Self::Mldsa),
            "slh" | "slh-dsa" | "slh_dsa" => Some(Self::Slh),
            "hybrid_ec_slh" | "hybrid" => Some(Self::HybridEcSlh),
            _ => None,
        }
    }
}

/// One P2MR address the wallet controls, with the key material needed to spend
/// it. `entropy` holds one 32-byte EC seed and/or one 128-byte PQC seed per the
/// scheme (concatenated for composite schemes, EC first).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2mrAddressRecord {
    pub scheme: P2mrScheme,
    #[serde(with = "hex::serde")]
    pub entropy: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub leaf_script: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub merkle_root: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub script_pubkey: Vec<u8>,
}

impl P2mrAddressRecord {
    /// The scriptPubKey as a `ScriptBuf`.
    #[must_use]
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::from_bytes(self.script_pubkey.clone())
    }

    /// Render the witness-v2 bech32m address for the given network.
    pub fn address(&self, network: bitcoin::Network) -> Result<Address, error::P2mrStore> {
        Address::from_script(self.script_pubkey().as_script(), Params::from(network))
            .map_err(|source| error::P2mrStore::Address { source })
    }

    /// Build and sign a P2MR spend of `outpoint` (whose prevout is `prevout`)
    /// with the given `outputs` (the recipient output, plus an optional change
    /// output), using this address's key(s). The implicit fee is
    /// `prevout − sum(outputs)`. Dispatches on the scheme. The returned tx is
    /// fully witnessed.
    pub fn build_spend(
        &self,
        outpoint: OutPoint,
        prevout: TxOut,
        outputs: Vec<TxOut>,
        sighash_type: TapSighashType,
    ) -> Result<Transaction, error::P2mrStore> {
        let e = &self.entropy;
        let tx = match self.scheme {
            P2mrScheme::Schnorr => build_p2mr_spend_from_prevout(
                SignAlgorithm::Schnorr,
                e,
                sighash_type,
                outpoint,
                prevout,
                outputs,
            ),
            P2mrScheme::Mldsa => build_p2mr_spend_from_prevout(
                SignAlgorithm::Mldsa,
                e,
                sighash_type,
                outpoint,
                prevout,
                outputs,
            ),
            P2mrScheme::Slh => build_p2mr_spend_from_prevout(
                SignAlgorithm::Slh,
                e,
                sighash_type,
                outpoint,
                prevout,
                outputs,
            ),
            P2mrScheme::HybridEcSlh => {
                let (ec, slh) = split_ec_pqc(e).map_err(error::P2mrStore::BuildOutput)?;
                build_hybrid_ec_slh_spend_from_prevout(
                    &ec,
                    slh,
                    sighash_type,
                    outpoint,
                    prevout,
                    outputs,
                )
            }
        };
        tx.map_err(error::P2mrStore::BuildOutput)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct P2mrFile {
    version: u32,
    addresses: Vec<P2mrAddressRecord>,
}

/// The wallet's P2MR key store.
pub(in crate::wallet) struct P2mrStore {
    path: PathBuf,
    /// Serializes create/read-modify-write so concurrent creates don't clobber.
    lock: tokio::sync::Mutex<()>,
}

impl P2mrStore {
    pub(in crate::wallet) fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(P2MR_FILE_NAME),
            lock: tokio::sync::Mutex::new(()),
        }
    }

    fn read_file(&self) -> Result<P2mrFile, error::P2mrStore> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|source| error::P2mrStore::Deserialize { source }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(P2mrFile {
                version: CURRENT_VERSION,
                addresses: Vec::new(),
            }),
            Err(source) => Err(error::P2mrStore::Read { source }),
        }
    }

    fn write_file(&self, file: &P2mrFile) -> Result<(), error::P2mrStore> {
        let json = serde_json::to_string_pretty(file)
            .map_err(|source| error::P2mrStore::Serialize { source })?;
        // Write owner-only, atomically via a temp file + rename.
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f =
                std::fs::File::create(&tmp).map_err(|source| error::P2mrStore::Write { source })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let perms = std::fs::Permissions::from_mode(0o600);
                f.set_permissions(perms)
                    .map_err(|source| error::P2mrStore::Write { source })?;
            }
            f.write_all(json.as_bytes())
                .map_err(|source| error::P2mrStore::Write { source })?;
            f.sync_all()
                .map_err(|source| error::P2mrStore::Write { source })?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|source| error::P2mrStore::Write { source })
    }

    /// Build the scriptPubKey + leaf for a scheme from freshly generated
    /// entropy, returning the assembled record (not yet persisted).
    fn build_record(scheme: P2mrScheme) -> Result<P2mrAddressRecord, error::P2mrStore> {
        let mk_output = |entropy: &[u8]| -> Result<(ScriptBuf, ScriptBuf, Vec<u8>), String> {
            let (spk, leaf) = match scheme {
                P2mrScheme::Schnorr => p2mr_output_for_algorithm(SignAlgorithm::Schnorr, entropy)?,
                P2mrScheme::Mldsa => p2mr_output_for_algorithm(SignAlgorithm::Mldsa, entropy)?,
                P2mrScheme::Slh => p2mr_output_for_algorithm(SignAlgorithm::Slh, entropy)?,
                P2mrScheme::HybridEcSlh => {
                    let (ec, slh) = split_ec_pqc(entropy)?;
                    p2mr_output_for_hybrid_ec_slh(&ec, slh)?
                }
            };
            // Recover the merkle root from the scriptPubKey (0x52 0x20 <root>).
            let root = spk.as_bytes()[2..].to_vec();
            Ok((spk, leaf, root))
        };

        let entropy = random_entropy(scheme)?;
        let (spk, leaf, root) = mk_output(&entropy).map_err(error::P2mrStore::BuildOutput)?;
        Ok(P2mrAddressRecord {
            scheme,
            entropy,
            leaf_script: leaf.into_bytes(),
            merkle_root: root,
            script_pubkey: spk.into_bytes(),
        })
    }

    /// Generate a new P2MR key/address for `scheme` and persist it.
    pub(in crate::wallet) async fn create(
        &self,
        scheme: P2mrScheme,
    ) -> Result<P2mrAddressRecord, error::P2mrStore> {
        let _guard = self.lock.lock().await;
        let record = Self::build_record(scheme)?;
        let mut file = self.read_file()?;
        file.version = CURRENT_VERSION;
        file.addresses.push(record.clone());
        self.write_file(&file)?;
        Ok(record)
    }

    /// All stored P2MR addresses. Reserved for a future "list my addresses"
    /// RPC; presently exercised only by the store's unit tests.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "reserved for a future list-addresses RPC")
    )]
    pub(in crate::wallet) fn list(&self) -> Result<Vec<P2mrAddressRecord>, error::P2mrStore> {
        Ok(self.read_file()?.addresses)
    }

    /// Find the record whose scriptPubKey matches `spk` (i.e. the key that can
    /// spend a UTXO with that scriptPubKey), if the wallet controls it.
    pub(in crate::wallet) fn get_by_spk(
        &self,
        spk: &bitcoin::Script,
    ) -> Result<Option<P2mrAddressRecord>, error::P2mrStore> {
        let target = spk.as_bytes();
        Ok(self
            .read_file()?
            .addresses
            .into_iter()
            .find(|r| r.script_pubkey == target))
    }
}

/// Fresh cryptographic entropy sized for the scheme.
fn random_entropy(scheme: P2mrScheme) -> Result<Vec<u8>, error::P2mrStore> {
    use rand::TryRng as _;
    let len = match scheme {
        P2mrScheme::Schnorr => EC_ENTROPY_LEN,
        P2mrScheme::Mldsa | P2mrScheme::Slh => PQC_ENTROPY_LEN,
        P2mrScheme::HybridEcSlh => EC_ENTROPY_LEN + PQC_ENTROPY_LEN,
    };
    let mut buf = vec![0u8; len];
    // `SysRng` (OS CSPRNG) — same source the seed store uses for salts.
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|source| error::P2mrStore::Entropy { source })?;
    Ok(buf)
}

/// Split concatenated `[ec(32) | pqc(128)]` entropy.
fn split_ec_pqc(entropy: &[u8]) -> Result<([u8; 32], &[u8]), String> {
    if entropy.len() < EC_ENTROPY_LEN + PQC_ENTROPY_LEN {
        return Err(format!(
            "hybrid entropy too short: {} < {}",
            entropy.len(),
            EC_ENTROPY_LEN + PQC_ENTROPY_LEN
        ));
    }
    let mut ec = [0u8; 32];
    ec.copy_from_slice(&entropy[..EC_ENTROPY_LEN]);
    Ok((ec, &entropy[EC_ENTROPY_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cusf-p2mr-store-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn create_list_and_lookup_each_scheme() {
        let dir = tmp_dir("crud");
        let store = P2mrStore::new(&dir);
        for scheme in [
            P2mrScheme::Schnorr,
            P2mrScheme::Mldsa,
            P2mrScheme::Slh,
            P2mrScheme::HybridEcSlh,
        ] {
            let rec = store.create(scheme).await.unwrap();
            assert_eq!(rec.scheme, scheme);
            // scriptPubKey is a v2 witness program: 0x52 0x20 <32-byte root>.
            assert_eq!(rec.script_pubkey.len(), 34);
            assert_eq!(rec.script_pubkey[0], 0x52);
            assert_eq!(rec.script_pubkey[1], 0x20);
            assert_eq!(rec.merkle_root.len(), 32);
            assert_eq!(&rec.script_pubkey[2..], rec.merkle_root.as_slice());
            // Renders a bech32m regtest address (bcrt1z...).
            let addr = rec.address(bitcoin::Network::Regtest).unwrap();
            assert!(addr.to_string().starts_with("bcrt1"));
            // Round-trips through the store and is findable by scriptPubKey.
            let found = store
                .get_by_spk(rec.script_pubkey().as_script())
                .unwrap()
                .expect("record present");
            assert_eq!(found.entropy, rec.entropy);
            assert_eq!(found.scheme, scheme);
        }
        assert_eq!(store.list().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn unknown_spk_is_not_found() {
        let dir = tmp_dir("unknown");
        let store = P2mrStore::new(&dir);
        store.create(P2mrScheme::Schnorr).await.unwrap();
        let other = P2mrStore::build_record(P2mrScheme::Slh).unwrap();
        assert!(
            store
                .get_by_spk(other.script_pubkey().as_script())
                .unwrap()
                .is_none()
        );
    }

    fn dummy_outpoint() -> OutPoint {
        OutPoint {
            txid: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            vout: 0,
        }
    }

    fn txout(value: u64, script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey,
        }
    }

    /// A partial spend keeps a change output; the fee is the implicit remainder.
    #[test]
    fn build_spend_partial_keeps_change_output() {
        let record = P2mrStore::build_record(P2mrScheme::Schnorr).unwrap();
        let dest = P2mrStore::build_record(P2mrScheme::Mldsa).unwrap();
        let change = P2mrStore::build_record(P2mrScheme::Schnorr).unwrap();
        let prevout = txout(100_000, record.script_pubkey());
        let outputs = vec![
            txout(60_000, dest.script_pubkey()),
            txout(38_000, change.script_pubkey()),
        ];
        let tx = record
            .build_spend(dummy_outpoint(), prevout, outputs, TapSighashType::Default)
            .unwrap();
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].value.to_sat(), 60_000);
        assert_eq!(tx.output[1].value.to_sat(), 38_000);
        assert_eq!(tx.output[1].script_pubkey, change.script_pubkey());
        // Implicit fee = 100_000 − (60_000 + 38_000) = 2_000. Witness present.
        assert!(!tx.input[0].witness.is_empty());
    }

    /// A full drain is a single output. Exercises the hybrid EC+SLH builder too.
    #[test]
    fn build_spend_drain_is_single_output_hybrid() {
        let record = P2mrStore::build_record(P2mrScheme::HybridEcSlh).unwrap();
        let dest = P2mrStore::build_record(P2mrScheme::Schnorr).unwrap();
        let prevout = txout(100_000, record.script_pubkey());
        let tx = record
            .build_spend(
                dummy_outpoint(),
                prevout,
                vec![txout(99_000, dest.script_pubkey())],
                TapSighashType::Default,
            )
            .unwrap();
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 99_000);
        assert!(!tx.input[0].witness.is_empty());
    }

    /// Outputs summing above the prevout (negative fee) are rejected.
    #[test]
    fn build_spend_rejects_outputs_exceeding_prevout() {
        let record = P2mrStore::build_record(P2mrScheme::Slh).unwrap();
        let dest = P2mrStore::build_record(P2mrScheme::Schnorr).unwrap();
        let prevout = txout(100_000, record.script_pubkey());
        let result = record.build_spend(
            dummy_outpoint(),
            prevout,
            vec![txout(100_001, dest.script_pubkey())],
            TapSighashType::Default,
        );
        assert!(result.is_err());
    }
}
