use std::sync::Arc;

use bdk_wallet::chain::{ChainPosition, ConfirmationBlockTime};
use bitcoin::{Amount, BlockHash, Transaction, Txid, Work};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proto::{StatusBuilder, ToStatus};

/// Network-specific consensus parameters for the enforcer's rule set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkParams {
    /// Blocks strictly below this height are plain Bitcoin history: they are
    /// recorded, but not validated against the enforcer's rules. `0`
    /// enforces from genesis.
    pub activation_height: u32,
    /// Datadir namespace suffix, so state for a parameter variant never
    /// collides with a default enforcer datadir for the same chain.
    pub datadir_suffix: Option<&'static str>,
}

impl NetworkParams {
    /// The non-preset defaults: enforcement from genesis.
    pub const fn for_network(_network: bitcoin::Network) -> Self {
        Self {
            activation_height: 0,
            datadir_suffix: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct HeaderInfo {
    pub block_hash: BlockHash,
    pub prev_block_hash: BlockHash,
    pub height: u32,
    pub work: Work,
    pub timestamp: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockInfo {
    pub coinbase_txid: Txid,
}

#[derive(Clone, Debug)]
pub enum Event {
    ConnectBlock {
        header_info: HeaderInfo,
        block_info: BlockInfo,
    },
    DisconnectBlock {
        block_hash: BlockHash,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BDKWalletTransaction {
    pub txid: bitcoin::Txid,
    pub tx: Arc<Transaction>,
    pub chain_position: ChainPosition<ConfirmationBlockTime>,
    pub fee: Amount,
    pub received: Amount,
    pub sent: Amount,
}

#[derive(Debug)]
pub enum FeePolicy {
    Absolute(Amount),
    Rate(bitcoin::FeeRate),
}

impl From<Amount> for FeePolicy {
    fn from(amount: Amount) -> Self {
        Self::Absolute(amount)
    }
}

impl From<bitcoin::FeeRate> for FeePolicy {
    fn from(fee_rate: bitcoin::FeeRate) -> Self {
        Self::Rate(fee_rate)
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error("Amount overflow")]
pub struct AmountOverflowError;

impl ToStatus for AmountOverflowError {
    fn builder(&self) -> StatusBuilder<'_> {
        StatusBuilder::new(self)
    }
}

#[derive(Debug, Diagnostic, Error)]
#[error("Amount underflow")]
pub struct AmountUnderflowError;

impl ToStatus for AmountUnderflowError {
    fn builder(&self) -> StatusBuilder<'_> {
        StatusBuilder::new(self)
    }
}
