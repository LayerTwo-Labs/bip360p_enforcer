//! Block diff that can be applied or undone when connecting / disconnecting
//! blocks.

use serde::{Deserialize, Serialize};
use sneed::{RwTxn, db};
use thiserror::Error;
use transitive::Transitive;

use crate::validator::dbs;

pub(in crate::validator) trait Diff {
    /// The DBs that the diff applies to
    type Dbs;

    type ApplyError;
    type UndoError;

    fn apply(
        &self,
        rwtxn: &mut RwTxn,
        dbs: &Self::Dbs,
        height: u32,
    ) -> Result<(), Self::ApplyError>;

    fn undo(&self, rwtxn: &mut RwTxn, dbs: &Self::Dbs) -> Result<(), Self::UndoError>;
}

/// Errors that can occur when undoing a block diff.
#[derive(Debug, Error, Transitive)]
#[expect(clippy::duplicated_attributes)]
#[transitive(
    from(db::error::Delete, db::Error),
    from(db::error::Get, db::Error),
    from(db::error::Put, db::Error),
    from(db::error::TryGet, db::Error)
)]
pub(in crate::validator) enum UndoError {
    #[error(transparent)]
    Db(Box<db::Error>),
}

impl From<db::Error> for UndoError {
    fn from(err: db::Error) -> Self {
        Self::Db(Box::new(err))
    }
}

/// All state changes a connected block made to the validator databases,
/// recorded so that [`Diff::undo`] can reverse them on reorg.
#[derive(Debug, Default, Deserialize, Serialize)]
#[must_use]
pub struct Block {
    // Template: no per-block validator state yet. Forks that track state
    // derived from blocks (e.g. a UTXO subset) add fields here, apply them
    // in [`Diff::apply`], and reverse them in [`Diff::undo`] so reorgs
    // roll the state back automatically.
}

impl Diff for Block {
    type Dbs = dbs::Dbs;
    type ApplyError = db::Error;
    type UndoError = UndoError;

    fn apply(&self, _rwtxn: &mut RwTxn, _dbs: &Self::Dbs, _height: u32) -> Result<(), db::Error> {
        Ok(())
    }

    fn undo(&self, _rwtxn: &mut RwTxn, _dbs: &Self::Dbs) -> Result<(), UndoError> {
        Ok(())
    }
}
