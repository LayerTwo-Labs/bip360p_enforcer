use bitcoin::OutPoint;
use buffa::MessageField;
use buffa_types::google::protobuf::{StringValue, Timestamp, UInt32Value, UInt64Value};
use connectrpc::{ConnectError, error::ErrorCode};
use thiserror::Error;

use crate::proto::{
    common::{ConsensusHex, ReverseHex},
    mainchain::{
        BlockHeaderInfo, BlockInfo, Network, send_transaction_request, subscribe_events_response,
        wallet_transaction,
    },
};

/// Wiring for `file_per_package=true` codegen.
///
/// `buf generate` emits one self-contained `<dotted.pkg>.rs` per proto
/// package under `lib/proto/generated/{buffa,connect}/`. This module
/// arranges them into a `cusf::<pkg>::v1::*` tree via `include!()` so
/// the rest of the crate can reach types by their proto package path.
///
/// The wiring lives here because anything inside the codegen output
/// directories is wiped by `buf generate --clean`. Keeping it in
/// `lib/proto.rs` makes the build survive a clean regen.
///
/// `#![allow(...)]` mirrors `buffa_codegen::ALLOW_LINTS`. Copy in any
/// new lint that fires under `cargo clippy -D warnings` after a regen.
#[allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_qualifications,
    // Nightly lint (`just clippy` opts in via -Zcrate-attr); bridge-mode
    // codegen re-exports `__buffa::reflect::descriptor_pool` unqualified.
    // `unknown_lints` keeps stable rustc from warning about the name.
    unknown_lints,
    unqualified_local_imports,
    clippy::derivable_impls,
    clippy::match_single_binding,
    clippy::uninlined_format_args,
    clippy::doc_lazy_continuation,
    clippy::module_inception,
    // buffa 0.7 codegen emits inline `#[allow(...)]` attributes; the workspace
    // denies `clippy::allow_attributes`, so permit them inside generated code.
    clippy::allow_attributes,
    // `reflect_mode=bridge` codegen uses wildcard imports.
    clippy::wildcard_imports
)]
pub mod generated {
    pub mod buffa {
        pub mod cusf {
            pub mod common {
                pub mod v1 {
                    include!("proto/generated/buffa/cusf.common.v1.rs");
                }
            }
            pub mod crypto {
                pub mod v1 {
                    include!("proto/generated/buffa/cusf.crypto.v1.rs");
                }
            }
            pub mod mainchain {
                pub mod v1 {
                    include!("proto/generated/buffa/cusf.mainchain.v1.rs");
                }
            }
        }
    }

    pub mod connect {
        pub mod cusf {
            // `cusf.common.v1` has no services, so no connect-side file.
            pub mod crypto {
                pub mod v1 {
                    include!("proto/generated/connect/cusf.crypto.v1.rs");
                }
            }
            pub mod mainchain {
                pub mod v1 {
                    include!("proto/generated/connect/cusf.mainchain.v1.rs");
                }
            }
        }
    }
}

pub mod common {
    pub use crate::proto::generated::buffa::cusf::common::v1::*;
}

pub mod crypto {
    pub use crate::proto::generated::buffa::cusf::crypto::v1::*;
}

pub mod mainchain {
    pub use crate::proto::generated::buffa::cusf::mainchain::v1::*;

    #[derive(Copy, Clone, Debug)]
    pub struct HeaderSyncProgress {
        pub current_height: Option<u32>,
    }

    impl From<HeaderSyncProgress> for SubscribeHeaderSyncProgressResponse {
        fn from(progress: HeaderSyncProgress) -> Self {
            Self {
                current_height: progress
                    .current_height
                    .map(super::wrap_u32)
                    .unwrap_or_default(),
            }
        }
    }
}

pub use crate::proto::generated::connect::cusf::{
    crypto::v1 as crypto_service, mainchain::v1 as mainchain_service,
};

pub trait ToStatus {
    fn builder(&self) -> StatusBuilder<'_>;
}

/// Construct a `ConnectError` from an Error.
pub struct StatusBuilder<'a> {
    pub code: ErrorCode,
    pub fmt_message: Box<dyn Fn(&mut std::fmt::Formatter<'_>) -> std::fmt::Result + 'a>,
    pub source:
        Option<either::Either<Box<StatusBuilder<'a>>, &'a (dyn std::error::Error + 'static)>>,
}

impl<'a> StatusBuilder<'a> {
    /// Default builder, using error source chain.
    /// Use this for errors without a source error, or errors with source
    /// errors that do not implement `ToStatus`.
    /// Transparent error variants should use this on their source when
    /// implementing `ToStatus`, if their source error does not impl
    /// `ToStatus`. If the source error does impl `ToStatus`, delegate to
    /// the source error's `StatusBuilder`.
    /// Non-transparent error variants should use `StatusBuilder::with_code`
    /// if the source error impls `ToStatus`.
    pub fn new<E>(err: &'a E) -> Self
    where
        E: std::error::Error,
    {
        Self {
            code: ErrorCode::Unknown,
            fmt_message: Box::new(move |f| std::fmt::Display::fmt(err, f)),
            source: err.source().map(either::Right),
        }
    }

    pub fn code(mut self, code: ErrorCode) -> Self {
        self.code = code;
        self
    }

    /// Defines the message, without source
    pub fn message<F>(mut self, message: F) -> Self
    where
        F: Fn(&mut std::fmt::Formatter<'_>) -> std::fmt::Result + 'a,
    {
        self.fmt_message = Box::new(message);
        self
    }

    /// Set the source to another `StatusBuilder`.
    pub fn source(mut self, source: Self) -> Self {
        self.source = Some(either::Left(Box::new(source)));
        self
    }

    /// Inherit code from a source status builder.
    /// Use this for non-transparent error variants, where the source
    /// implements `ToStatus`.
    /// Transparent error variants should delegate to the source error's
    /// `StatusBuilder` instead of using this function.
    pub fn with_code<T>(err_msg: &'a T, source_builder: Self) -> Self
    where
        T: std::fmt::Display,
    {
        Self {
            code: source_builder.code,
            fmt_message: Box::new(move |f| std::fmt::Display::fmt(&err_msg, f)),
            source: Some(either::Left(Box::new(source_builder))),
        }
    }

    /// Full status message, including source errors in alternate mode
    fn status_message(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let () = (self.fmt_message)(f)?;
        if !f.alternate() {
            return Ok(());
        }
        match &self.source {
            Some(either::Left(source)) => {
                std::fmt::Display::fmt(": ", f)?;
                source.status_message(f)
            }
            Some(either::Right(source)) => {
                std::fmt::Display::fmt(": ", f)?;
                std::fmt::Display::fmt(source, f)?;
                let mut source = *source;
                while let Some(cause) = source.source() {
                    source = cause;
                    std::fmt::Display::fmt(": ", f)?;
                    std::fmt::Display::fmt(source, f)?;
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn to_connect_error(&self) -> ConnectError {
        let msg = format!(
            "{:#}",
            crate::display::DisplayFn::new(|f| self.status_message(f))
        );
        ConnectError::new(self.code, msg)
    }
}

impl From<StatusBuilder<'_>> for ConnectError {
    fn from(builder: StatusBuilder<'_>) -> Self {
        builder.to_connect_error()
    }
}

#[derive(miette::Diagnostic, Debug, Error)]
pub enum Error {
    #[error(
        "Invalid enum variant in field `{field_name}` of message `{message_name}`: `{variant_name}`"
    )]
    InvalidEnumVariant {
        field_name: String,
        message_name: String,
        variant_name: String,
    },
    #[error("Invalid field value in field `{field_name}` of message `{message_name}`: `{value}`")]
    InvalidFieldValue {
        field_name: String,
        message_name: String,
        value: String,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    #[error(
        "Invalid value in repeated field `{field_name}` of message `{message_name}`: `{value}`"
    )]
    InvalidRepeatedValue {
        field_name: String,
        message_name: String,
        value: String,
    },
    #[error("Missing field in message `{message_name}`: `{field_name}`")]
    MissingField {
        field_name: String,
        message_name: String,
    },
    #[error("Unknown enum tag in field `{field_name}` of message `{message_name}`: `{tag}`")]
    UnknownEnumTag {
        field_name: String,
        message_name: String,
        tag: i32,
    },
}

impl Error {
    pub fn invalid_enum_variant<Message: buffa::MessageName>(
        field_name: &str,
        variant_name: &str,
    ) -> Self {
        Self::InvalidEnumVariant {
            field_name: field_name.to_owned(),
            message_name: Message::FULL_NAME.to_owned(),
            variant_name: variant_name.to_owned(),
        }
    }

    pub fn invalid_field_value<Message: buffa::MessageName, Error>(
        field_name: &str,
        value: &str,
        source: Error,
    ) -> Self
    where
        Error: std::error::Error + Send + Sync + 'static,
    {
        Self::InvalidFieldValue {
            field_name: field_name.to_owned(),
            message_name: Message::FULL_NAME.to_owned(),
            value: value.to_owned(),
            source: Box::new(source),
        }
    }

    pub fn invalid_repeated_value<Message: buffa::MessageName>(
        field_name: &str,
        value: &str,
    ) -> Self {
        Self::InvalidRepeatedValue {
            field_name: field_name.to_owned(),
            message_name: Message::FULL_NAME.to_owned(),
            value: value.to_owned(),
        }
    }

    pub fn missing_field<Message: buffa::MessageName>(field_name: &str) -> Self {
        Self::MissingField {
            field_name: field_name.to_owned(),
            message_name: Message::FULL_NAME.to_owned(),
        }
    }
}

impl ToStatus for Error {
    fn builder(&self) -> StatusBuilder<'_> {
        StatusBuilder::new(self).code(ErrorCode::InvalidArgument)
    }
}

impl From<Error> for ConnectError {
    fn from(err: Error) -> Self {
        err.builder().into()
    }
}

pub fn wrap_string(value: impl Into<String>) -> MessageField<StringValue> {
    MessageField::some(StringValue {
        value: value.into(),
        ..Default::default()
    })
}

pub fn wrap_u32(value: u32) -> MessageField<UInt32Value> {
    MessageField::some(UInt32Value {
        value,
        ..Default::default()
    })
}

pub fn wrap_u64(value: u64) -> MessageField<UInt64Value> {
    MessageField::some(UInt64Value {
        value,
        ..Default::default()
    })
}

pub fn wrap_timestamp(seconds: i64) -> MessageField<Timestamp> {
    MessageField::some(Timestamp {
        seconds,
        nanos: 0,
        ..Default::default()
    })
}

pub fn unwrap_string(field: MessageField<StringValue>) -> Option<String> {
    field.into_option().map(|sv| sv.value)
}

pub fn unwrap_u32(field: MessageField<UInt32Value>) -> Option<u32> {
    field.into_option().map(|uv| uv.value)
}

pub fn unwrap_u64(field: MessageField<UInt64Value>) -> Option<u64> {
    field.into_option().map(|uv| uv.value)
}

impl common::ConsensusHex {
    pub fn decode<Message: buffa::MessageName, T>(self, field_name: &str) -> Result<T, Error>
    where
        T: bitcoin::consensus::Decodable,
    {
        let hex = unwrap_string(self.hex).ok_or_else(|| Error::missing_field::<Self>("hex"))?;
        bitcoin::consensus::encode::deserialize_hex(&hex)
            .map_err(|err| Error::invalid_field_value::<Message, _>(field_name, &hex, err))
    }

    pub fn decode_status<Message: buffa::MessageName, T>(
        self,
        field_name: &str,
    ) -> Result<T, ConnectError>
    where
        T: bitcoin::consensus::Decodable,
    {
        self.decode::<Message, _>(field_name)
            .map_err(ConnectError::from)
    }

    pub fn encode<T>(value: &T) -> Self
    where
        T: bitcoin::consensus::Encodable,
    {
        let hex = bitcoin::consensus::encode::serialize_hex(value);
        Self {
            hex: wrap_string(hex),
        }
    }
}

impl common::Hex {
    pub fn decode<Message: buffa::MessageName, T>(self, field_name: &str) -> Result<T, Error>
    where
        T: hex::FromHex,
        <T as hex::FromHex>::Error: std::error::Error + Send + Sync + 'static,
    {
        let hex = unwrap_string(self.hex).ok_or_else(|| Error::missing_field::<Self>("hex"))?;
        T::from_hex(&hex)
            .map_err(|err| Error::invalid_field_value::<Message, _>(field_name, &hex, err))
    }

    pub fn decode_status<Message: buffa::MessageName, T>(
        self,
        field_name: &str,
    ) -> Result<T, ConnectError>
    where
        T: hex::FromHex,
        <T as hex::FromHex>::Error: std::error::Error + Send + Sync + 'static,
    {
        self.decode::<Message, _>(field_name)
            .map_err(ConnectError::from)
    }

    pub fn encode<T>(value: &T) -> Self
    where
        T: hex::ToHex,
    {
        let hex: String = value.encode_hex();
        Self {
            hex: wrap_string(hex),
        }
    }
}

impl common::ReverseHex {
    pub fn decode<Message: buffa::MessageName, T>(self, field_name: &str) -> Result<T, Error>
    where
        T: bitcoin::consensus::Decodable,
    {
        let hex = unwrap_string(self.hex).ok_or_else(|| Error::missing_field::<Self>("hex"))?;
        let mut bytes = hex::decode(&hex)
            .map_err(|err| Error::invalid_field_value::<Message, _>(field_name, &hex, err))?;
        bytes.reverse();
        bitcoin::consensus::deserialize(&bytes)
            .map_err(|err| Error::invalid_field_value::<Message, _>(field_name, &hex, err))
    }

    pub fn decode_status<Message: buffa::MessageName, T>(
        self,
        field_name: &str,
    ) -> Result<T, ConnectError>
    where
        T: bitcoin::consensus::Decodable,
    {
        self.decode::<Message, _>(field_name)
            .map_err(ConnectError::from)
    }

    pub fn encode<T>(value: &T) -> Self
    where
        T: bitcoin::consensus::Encodable,
    {
        let mut bytes = bitcoin::consensus::encode::serialize(value);
        bytes.reverse();
        Self {
            hex: wrap_string(hex::encode(bytes)),
        }
    }
}

impl From<&OutPoint> for mainchain::OutPoint {
    fn from(outpoint: &OutPoint) -> Self {
        Self {
            txid: MessageField::some(ReverseHex::encode(&outpoint.txid)),
            vout: wrap_u32(outpoint.vout),
        }
    }
}

impl From<bitcoin::Network> for Network {
    fn from(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => Network::NETWORK_MAINNET,
            bitcoin::Network::Regtest => Network::NETWORK_REGTEST,
            bitcoin::Network::Signet => Network::NETWORK_SIGNET,
            bitcoin::Network::Testnet => Network::NETWORK_TESTNET,
            bitcoin::Network::Testnet4 => Network::NETWORK_TESTNET,
        }
    }
}

impl From<crate::types::HeaderInfo> for BlockHeaderInfo {
    fn from(info: crate::types::HeaderInfo) -> Self {
        Self {
            block_hash: MessageField::some(ReverseHex::encode(&info.block_hash)),
            prev_block_hash: MessageField::some(ReverseHex::encode(&info.prev_block_hash)),
            height: info.height,
            work: MessageField::some(ConsensusHex::encode(&info.work.to_le_bytes())),
            timestamp: info.timestamp as u64,
        }
    }
}

impl crate::types::BlockInfo {
    pub fn as_proto(&self) -> BlockInfo {
        BlockInfo::default()
    }
}

impl crate::types::Event {
    pub fn into_proto(self) -> subscribe_events_response::event::Event {
        use subscribe_events_response::event::{ConnectBlock, DisconnectBlock};
        match self {
            Self::ConnectBlock {
                header_info,
                block_info,
            } => {
                let cb = ConnectBlock {
                    header_info: MessageField::some(header_info.into()),
                    block_info: MessageField::some(block_info.as_proto()),
                };
                subscribe_events_response::event::Event::ConnectBlock(Box::new(cb))
            }
            Self::DisconnectBlock { block_hash } => {
                let db = DisconnectBlock {
                    block_hash: MessageField::some(ReverseHex::encode(&block_hash)),
                };
                subscribe_events_response::event::Event::DisconnectBlock(Box::new(db))
            }
        }
    }
}

impl From<subscribe_events_response::event::Event> for subscribe_events_response::Event {
    fn from(ev: subscribe_events_response::event::Event) -> Self {
        Self { event: Some(ev) }
    }
}

impl From<&bdk_wallet::chain::ChainPosition<bdk_wallet::chain::ConfirmationBlockTime>>
    for wallet_transaction::Confirmation
{
    fn from(
        chain_position: &bdk_wallet::chain::ChainPosition<bdk_wallet::chain::ConfirmationBlockTime>,
    ) -> Self {
        match chain_position {
            bdk_wallet::chain::ChainPosition::Confirmed {
                anchor: conf,
                transitively: _,
            } => Self {
                height: conf.block_id.height,
                block_hash: MessageField::some(ReverseHex::encode(&conf.block_id.hash)),
                timestamp: wrap_timestamp(conf.confirmation_time as i64),
            },
            bdk_wallet::chain::ChainPosition::Unconfirmed {
                last_seen,
                first_seen: _,
            } => Self {
                height: 0,
                block_hash: MessageField::none(),
                timestamp: last_seen
                    .map(|s| wrap_timestamp(s as i64))
                    .unwrap_or_default(),
            },
        }
    }
}

impl From<&crate::types::BDKWalletTransaction> for mainchain::WalletTransaction {
    fn from(tx: &crate::types::BDKWalletTransaction) -> Self {
        Self {
            txid: MessageField::some(ReverseHex::encode(&tx.txid)),
            raw_transaction: MessageField::some(ConsensusHex::encode(&tx.tx)),
            fee_sats: tx.fee.to_sat(),
            received_sats: tx.received.to_sat(),
            sent_sats: tx.sent.to_sat(),
            confirmation_info: MessageField::some((&tx.chain_position).into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid sats per vbyte")]
pub struct InvalidSatsPerVbyte {
    pub sats_per_vbyte: u64,
}

impl TryFrom<send_transaction_request::fee_rate::Fee> for crate::types::FeePolicy {
    type Error = InvalidSatsPerVbyte;

    fn try_from(fee: send_transaction_request::fee_rate::Fee) -> Result<Self, Self::Error> {
        use send_transaction_request::fee_rate::Fee;
        match fee {
            Fee::SatPerVbyte(sats_per_vbyte) => {
                let rate = bitcoin::FeeRate::from_sat_per_vb(sats_per_vbyte)
                    .ok_or(InvalidSatsPerVbyte { sats_per_vbyte })?;
                Ok(rate.into())
            }
            Fee::Sats(sats) => {
                let amount = bitcoin::Amount::from_sat(sats);
                Ok(amount.into())
            }
        }
    }
}

impl TryFrom<send_transaction_request::FeeRate> for crate::types::FeePolicy {
    type Error = Error;

    fn try_from(fee_rate: send_transaction_request::FeeRate) -> Result<Self, Self::Error> {
        use send_transaction_request::FeeRate;
        let FeeRate { fee, .. } = fee_rate;
        fee.ok_or_else(|| Error::missing_field::<FeeRate>("fee"))?
            .try_into()
            .map_err(|err: InvalidSatsPerVbyte| {
                Error::invalid_field_value::<FeeRate, _>(
                    "fee",
                    &err.sats_per_vbyte.to_string(),
                    err,
                )
            })
    }
}
