//! The wallet's seed store: a single JSON file (`seed.json`).
//!

use std::path::{Path, PathBuf};

use bdk_wallet::bip39::{Language, Mnemonic};
use either::Either;
use serde::{Deserialize, Serialize};

use crate::wallet::{error, mnemonic::EncryptedMnemonic};

/// A seed to persist: either plaintext, or encrypted under a password.
pub(in crate::wallet) enum Seed<'a> {
    Plaintext(&'a Mnemonic),
    Encrypted(&'a EncryptedMnemonic),
}

const SEED_FILE_NAME: &str = "seed.json";

const CURRENT_VERSION: u32 = 1;

/// The seed as stored in `seed.json`
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredSeed {
    Plaintext {
        mnemonic: String,
    },
    Encrypted {
        #[serde(with = "hex::serde")]
        initialization_vector: Vec<u8>,
        #[serde(with = "hex::serde")]
        ciphertext_mnemonic: Vec<u8>,
        #[serde(with = "hex::serde")]
        key_salt: Vec<u8>,
    },
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SeedFile {
    version: u32,
    /// Informational only.
    created_at: std::time::SystemTime,
    /// The node's tip height when this seed was generated `None` for restored
    /// seeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birthday_height: Option<u32>,
    seed: StoredSeed,
}

/// The wallet's seed store.
pub(in crate::wallet) struct SeedStore {
    path: PathBuf,
    /// Serializes seed inserts, so two concurrent `CreateWallet` calls cannot
    /// both pass the "does a seed already exist" check.
    insert_lock: tokio::sync::Mutex<()>,
}

impl SeedStore {
    pub(in crate::wallet) fn new(data_dir: &Path) -> Result<Self, error::InitSeedStore> {
        let path = data_dir.join(SEED_FILE_NAME);
        Ok(Self {
            path,
            insert_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The stored seed, if the wallet has been created.
    pub(in crate::wallet) async fn read_mnemonic(
        &self,
    ) -> Result<Option<Either<Mnemonic, EncryptedMnemonic>>, error::ReadSeed> {
        let Some(seed_file) = read_seed_file(&self.path)? else {
            return Ok(None);
        };
        let seed = match seed_file.seed {
            StoredSeed::Plaintext { mnemonic } => Either::Left(
                Mnemonic::parse_in_normalized(Language::English, &mnemonic)
                    .map_err(error::ParseMnemonic::from)?,
            ),
            StoredSeed::Encrypted {
                initialization_vector,
                ciphertext_mnemonic,
                key_salt,
            } => Either::Right(EncryptedMnemonic {
                initialization_vector,
                ciphertext_mnemonic,
                key_salt,
            }),
        };
        Ok(Some(seed))
    }

    /// The wallet's birthday height, if one was recorded at creation.
    pub(in crate::wallet) async fn read_birthday_height(
        &self,
    ) -> Result<Option<u32>, error::ReadSeed> {
        Ok(read_seed_file(&self.path)?.and_then(|seed_file| seed_file.birthday_height))
    }

    /// Persist the seed for a newly created wallet. `birthday_height` must
    /// only be `Some` for freshly GENERATED seeds (see [`SeedFile`]).
    pub(in crate::wallet) async fn insert_seed(
        &self,
        seed: Seed<'_>,
        birthday_height: Option<u32>,
    ) -> Result<(), error::InsertSeed> {
        let _guard = self.insert_lock.lock().await;
        if self.path.exists() {
            return Err(error::InsertSeed::AlreadyExists);
        }
        let seed_file = SeedFile {
            version: CURRENT_VERSION,
            created_at: std::time::SystemTime::now(),
            birthday_height,
            seed: match seed {
                Seed::Plaintext(mnemonic) => StoredSeed::Plaintext {
                    mnemonic: mnemonic.to_string(),
                },
                Seed::Encrypted(encrypted) => StoredSeed::Encrypted {
                    initialization_vector: encrypted.initialization_vector.clone(),
                    ciphertext_mnemonic: encrypted.ciphertext_mnemonic.clone(),
                    key_salt: encrypted.key_salt.clone(),
                },
            },
        };
        let () = write_seed_file(&self.path, &seed_file)?;
        Ok(())
    }
}

fn read_seed_file(path: &Path) -> Result<Option<SeedFile>, error::ReadSeed> {
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(error::ReadSeedInner::Io(err).into()),
    };
    let seed_file: SeedFile =
        serde_json::from_slice(&contents).map_err(error::ReadSeedInner::Json)?;
    Ok(Some(seed_file))
}

/// Write the seed file atomically and durably: temp file (0600) + fsync +
/// rename + directory fsync, so a crash can never leave a bad seed file.
fn write_seed_file(path: &Path, seed_file: &SeedFile) -> Result<(), std::io::Error> {
    let contents = serde_json::to_vec_pretty(seed_file).expect("seed file serialization is total");
    let tmp_path = path.with_extension("json.tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp_path)?;
        let () = std::io::Write::write_all(&mut file, &contents)?;
        let () = file.sync_all()?;
    }
    let () = std::fs::rename(&tmp_path, path)?;
    let dir = std::fs::File::open(path.parent().expect("seed file path has a parent"))?;
    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bip39::{Language, Mnemonic};

    use super::{Seed, SeedStore, error};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cusf-enforcer-seed-store-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // The all-zeros BIP39 test vector; any valid mnemonic works here.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";

    /// A second seed insert must be rejected with `AlreadyExists`, so a repeated
    /// `CreateWallet` surfaces `AlreadyExists` rather than storing two seeds.
    #[tokio::test]
    async fn insert_seed_rejects_a_second_seed() {
        let dir = temp_dir("already-exists");
        let store = SeedStore::new(&dir).unwrap();
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();

        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();
        let err = store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .expect_err("second insert must fail");
        assert!(matches!(err, error::InsertSeed::AlreadyExists));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A recorded birthday round-trips; absence stays absent; and a seed
    /// file written before the field existed reads back as `None`.
    #[tokio::test]
    async fn birthday_height_roundtrip_and_backcompat() {
        let dir = temp_dir("birthday");
        let store = SeedStore::new(&dir).unwrap();
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();
        store
            .insert_seed(Seed::Plaintext(&mnemonic), Some(958_537))
            .await
            .unwrap();
        assert_eq!(
            store.read_birthday_height().await.unwrap(),
            Some(958_537),
            "birthday must round-trip"
        );
        drop(store);
        std::fs::remove_dir_all(&dir).ok();

        // Restored seed: no birthday.
        let dir = temp_dir("birthday-none");
        let store = SeedStore::new(&dir).unwrap();
        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();
        assert_eq!(store.read_birthday_height().await.unwrap(), None);

        // Pre-birthday seed file (field absent entirely) must parse as None.
        let raw = std::fs::read_to_string(dir.join("seed.json")).unwrap();
        assert!(
            !raw.contains("birthday_height"),
            "None must not be serialized"
        );
        assert!(store.read_mnemonic().await.unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The seed file must not be readable by other users.
    #[cfg(unix)]
    #[tokio::test]
    async fn seed_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir("permissions");
        let store = SeedStore::new(&dir).unwrap();
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();
        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();

        let mode = std::fs::metadata(dir.join("seed.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }
}
