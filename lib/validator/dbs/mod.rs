use std::path::{Path, PathBuf};

use heed_types::SerdeBincode;
use sneed::{DatabaseUnique, Env, RoTxn, RwTxn, UnitKey, env, rwtxn};
use thiserror::Error;

mod block_hashes;
pub(in crate::validator) mod diff;

pub use self::block_hashes::{BlockHashDbs, error as block_hash_dbs_error};

/// On-disk schema version of the validator databases.
///
/// Bump this whenever the set of tables (or their encodings) changes.
/// Databases created by older versions are incompatible; since the enforcer
/// state is fully chain-derivable, the fix is deleting the datadir and
/// resyncing.
const DB_VERSION: u32 = 2;

/// Name of the schema-version marker file inside the datadir.
const DB_VERSION_FILE: &str = "db_version";

#[derive(transitive::Transitive, Debug, Error)]
#[expect(clippy::duplicated_attributes)]
#[transitive(
    from(env::error::CreateDb, env::Error),
    from(env::error::OpenEnv, env::Error),
    from(env::error::WriteTxn, env::Error)
)]
pub enum CreateDbsError {
    #[error(transparent)]
    CommitWriteTxn(#[from] rwtxn::error::Commit),
    #[error("Error creating directory (`{path}`)")]
    CreateDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Env(#[from] env::Error),
    #[error(
        "Validator database at `{path}` has schema version {found} but this \
         enforcer requires version {DB_VERSION}. Delete the datadir and \
         resync (the enforcer state is rebuilt from the chain)."
    )]
    IncompatibleSchema { path: PathBuf, found: u32 },
    #[error("Error reading database version file (`{path}`)")]
    ReadVersion {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Error writing database version file (`{path}`)")]
    WriteVersion {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Check or stamp the schema-version marker for a database directory.
///
/// * Fresh directory (no LMDB data file): stamp [`DB_VERSION`].
/// * Existing database with a matching marker: ok.
/// * Existing database with a missing or older marker: incompatible — the
///   caller must delete the datadir and resync.
fn check_or_stamp_db_version(db_dir: &Path) -> Result<(), CreateDbsError> {
    let version_path = db_dir.join(DB_VERSION_FILE);
    let has_existing_db = db_dir.join("data.mdb").exists();
    let found: Option<u32> = match std::fs::read_to_string(&version_path) {
        Ok(contents) => contents.trim().parse().ok(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(CreateDbsError::ReadVersion {
                path: version_path,
                source: err,
            });
        }
    };
    match found {
        Some(version) if version == DB_VERSION => Ok(()),
        Some(version) => Err(CreateDbsError::IncompatibleSchema {
            path: db_dir.to_owned(),
            found: version,
        }),
        None if has_existing_db => Err(CreateDbsError::IncompatibleSchema {
            path: db_dir.to_owned(),
            found: 1,
        }),
        None => std::fs::write(&version_path, format!("{DB_VERSION}\n")).map_err(|err| {
            CreateDbsError::WriteVersion {
                path: version_path,
                source: err,
            }
        }),
    }
}

#[derive(Clone)]
pub(super) struct Dbs {
    env: Env,
    pub block_hashes: BlockHashDbs,
    /// Tip that the enforcer is synced to
    pub current_chain_tip: DatabaseUnique<UnitKey, SerdeBincode<bitcoin::BlockHash>>,
}

impl Dbs {
    const NUM_DBS: u32 = BlockHashDbs::NUM_DBS + 1 + 1;

    pub fn new(data_dir: &Path, network: bitcoin::Network) -> Result<Self, CreateDbsError> {
        let db_dir = data_dir.join(format!("{network}.mdb"));
        if let Err(err) = std::fs::create_dir_all(&db_dir) {
            let err = CreateDbsError::CreateDirectory {
                path: db_dir,
                source: err,
            };
            return Err(err);
        }
        let () = check_or_stamp_db_version(&db_dir)?;
        let env = {
            // 1 GB
            const GB: usize = 1024 * 1024 * 1024;
            // 10 GB
            const DB_MAP_SIZE: usize = 10 * GB;
            let mut env_opts = env::OpenOptions::new();
            let _: &mut env::OpenOptions = env_opts.max_dbs(Self::NUM_DBS).map_size(DB_MAP_SIZE);
            unsafe { Env::open(&env_opts, &db_dir) }?
        };
        let mut rwtxn = env.write_txn()?;
        let block_hashes = BlockHashDbs::new(&env, &mut rwtxn)?;
        let current_chain_tip = DatabaseUnique::create(&env, &mut rwtxn, "current_chain_tip")?;
        let () = rwtxn.commit()?;

        tracing::info!("Created validator DBs in {}", db_dir.display());
        Ok(Self {
            env,
            block_hashes,
            current_chain_tip,
        })
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_, heed::WithTls>, env::error::ReadTxn> {
        self.env.read_txn()
    }

    pub fn nested_write_txn<'p>(
        &'p self,
        parent: &'p mut RwTxn<'_>,
    ) -> Result<RwTxn<'p>, env::error::NestedWriteTxn> {
        self.env.nested_write_txn(parent)
    }

    pub fn write_txn(&self) -> Result<RwTxn<'_>, env::error::WriteTxn> {
        self.env.write_txn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_datadir_is_stamped_with_current_version() {
        let dir = temp_dir::TempDir::new().unwrap();
        let dbs = Dbs::new(dir.path(), bitcoin::Network::Regtest);
        assert!(dbs.is_ok());
        let marker = dir.path().join("regtest.mdb").join(DB_VERSION_FILE);
        let contents = std::fs::read_to_string(marker).unwrap();
        assert_eq!(contents.trim(), DB_VERSION.to_string());
        // Re-opening succeeds against the stamped marker.
        drop(dbs);
        assert!(Dbs::new(dir.path(), bitcoin::Network::Regtest).is_ok());
    }

    #[test]
    fn unversioned_existing_database_is_rejected() {
        let dir = temp_dir::TempDir::new().unwrap();
        let db_dir = dir.path().join("regtest.mdb");
        std::fs::create_dir_all(&db_dir).unwrap();
        // Simulate a pre-version-marker (v1) database.
        std::fs::write(db_dir.join("data.mdb"), b"stale").unwrap();
        let Err(err) = Dbs::new(dir.path(), bitcoin::Network::Regtest) else {
            panic!("expected IncompatibleSchema error");
        };
        assert!(
            matches!(err, CreateDbsError::IncompatibleSchema { found: 1, .. }),
            "expected IncompatibleSchema, got: {err}"
        );
    }

    #[test]
    fn older_version_marker_is_rejected() {
        let dir = temp_dir::TempDir::new().unwrap();
        let db_dir = dir.path().join("regtest.mdb");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::write(db_dir.join(DB_VERSION_FILE), b"1\n").unwrap();
        let Err(err) = Dbs::new(dir.path(), bitcoin::Network::Regtest) else {
            panic!("expected IncompatibleSchema error");
        };
        assert!(
            matches!(err, CreateDbsError::IncompatibleSchema { found: 1, .. }),
            "expected IncompatibleSchema, got: {err}"
        );
    }
}
