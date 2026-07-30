use std::{collections::HashMap, str::FromStr};

use bdk_wallet::bip39::Mnemonic;
use bitcoin::{Address, Amount};
use buffa::MessageField;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

use crate::{
    proto::{
        ToStatus,
        common::ReverseHex,
        mainchain::{
            CreateNewAddressRequest, CreateNewAddressResponse, CreateWalletRequest,
            CreateWalletResponse, GetBalanceRequest, GetBalanceResponse, GetInfoRequest,
            GetInfoResponse, ListTransactionsRequest, ListTransactionsResponse,
            ListUnspentOutputsRequest, ListUnspentOutputsResponse, SendTransactionRequest,
            SendTransactionResponse, UnlockWalletRequest, UnlockWalletResponse, WalletTransaction,
            get_info_response, list_unspent_outputs_response,
            send_transaction_request::RequiredUtxo,
        },
        mainchain_service::WalletService,
        wrap_timestamp,
    },
    server::missing_field,
    wallet::{CreateTransactionParams, error::WalletInitialization},
};

#[expect(refining_impl_trait_reachable)]
impl WalletService for crate::wallet::Wallet {
    async fn get_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetInfoRequest>,
    ) -> ServiceResult<GetInfoResponse> {
        let info = self
            .get_wallet_info()
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        Ok(Response::new(GetInfoResponse {
            network: info.network.to_string(),
            transaction_count: info.transaction_count as u32,
            unspent_output_count: info.unspent_output_count as u32,
            descriptors: info
                .keychain_descriptors
                .iter()
                .map(|(kind, descriptor)| {
                    (
                        match kind {
                            bdk_wallet::KeychainKind::External => "external".to_string(),
                            bdk_wallet::KeychainKind::Internal => "internal".to_string(),
                        },
                        descriptor.to_string(),
                    )
                })
                .collect(),
            tip: MessageField::some(get_info_response::Tip {
                height: info.tip.1,
                hash: MessageField::some(ReverseHex::encode(&info.tip.0)),
            }),
        }))
    }

    async fn create_new_address(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CreateNewAddressRequest>,
    ) -> ServiceResult<CreateNewAddressResponse> {
        let address = self
            .get_new_address()
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        Ok(Response::new(CreateNewAddressResponse {
            address: address.to_string(),
        }))
    }

    async fn get_balance(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetBalanceRequest>,
    ) -> ServiceResult<GetBalanceResponse> {
        let (balance, has_synced) = self
            .get_wallet_balance()
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        Ok(Response::new(GetBalanceResponse {
            confirmed_sats: balance.confirmed.to_sat(),
            pending_sats: (balance.total() - balance.confirmed).to_sat(),
            has_synced,
        }))
    }

    async fn list_unspent_outputs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListUnspentOutputsRequest>,
    ) -> ServiceResult<ListUnspentOutputsResponse> {
        let bdk_utxos = self
            .get_utxos()
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        let outputs = bdk_utxos
            .into_iter()
            .map(|utxo| {
                let chain_position = match utxo.chain_position {
                    bdk_wallet::chain::ChainPosition::Unconfirmed { .. } => None,
                    bdk_wallet::chain::ChainPosition::Confirmed {
                        anchor,
                        transitively,
                    } => Some((anchor, transitively)),
                };

                let unconfirmed_last_seen = match utxo.chain_position {
                    bdk_wallet::chain::ChainPosition::Unconfirmed {
                        last_seen,
                        first_seen: _,
                    } => last_seen
                        .map(|s| wrap_timestamp(s as i64))
                        .unwrap_or_default(),
                    bdk_wallet::chain::ChainPosition::Confirmed { .. } => MessageField::none(),
                };
                list_unspent_outputs_response::Output {
                    txid: MessageField::some(ReverseHex::encode(&utxo.outpoint.txid)),
                    vout: utxo.outpoint.vout,
                    value_sats: utxo.txout.value.to_sat(),
                    is_internal: utxo.keychain == bdk_wallet::KeychainKind::Internal,
                    is_confirmed: chain_position.is_some(),
                    confirmed_at_block: chain_position
                        .map(|(anchor, _)| anchor.block_id.height)
                        .unwrap_or_default(),
                    confirmed_at_time: chain_position
                        .map(|(anchor, _)| wrap_timestamp(anchor.confirmation_time as i64))
                        .unwrap_or_default(),
                    confirmed_transitively: chain_position
                        .and_then(|(_, t)| t)
                        .map(|t| MessageField::some(ReverseHex::encode(&t)))
                        .unwrap_or_default(),
                    unconfirmed_last_seen,
                    address: Address::from_script(
                        utxo.txout.script_pubkey.as_script(),
                        self.validator().network(),
                    )
                    .map(|addr| crate::proto::wrap_string(addr.to_string()))
                    .unwrap_or_default(),
                }
            })
            .collect();

        Ok(Response::new(ListUnspentOutputsResponse { outputs }))
    }

    async fn list_transactions(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, ListTransactionsRequest>,
    ) -> ServiceResult<ListTransactionsResponse> {
        let transactions = self
            .list_wallet_transactions()
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        Ok(Response::new(ListTransactionsResponse {
            transactions: transactions.iter().map(WalletTransaction::from).collect(),
        }))
    }

    async fn send_transaction(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SendTransactionRequest>,
    ) -> ServiceResult<SendTransactionResponse> {
        use crate::proto::mainchain::SendTransactionRequest;
        let SendTransactionRequest {
            destinations,
            fee_rate,
            op_return_message,
            required_utxos,
            drain_wallet_to,
            ..
        } = request.to_owned_message();

        let required_utxos = required_utxos
            .into_iter()
            .map(|utxo| {
                let txid = utxo
                    .txid
                    .into_option()
                    .ok_or_else(|| missing_field::<RequiredUtxo>("txid"))?
                    .decode_status::<RequiredUtxo, _>("txid")?;
                Ok(bdk_wallet::bitcoin::OutPoint {
                    txid,
                    vout: utxo.vout,
                })
            })
            .collect::<Result<Vec<_>, ConnectError>>()?;

        // Parse and validate all destination addresses, but assume network valid
        let destinations_validated = destinations
            .iter()
            .map(|(address, amount)| {
                use bdk_wallet::IsDust;

                let address = self.parse_checked_address(address)?;

                let amount = Amount::from_sat(*amount);
                if amount.is_dust(&address.script_pubkey()) {
                    return Err(ConnectError::invalid_argument(format!(
                        "amount is below dust limit: {amount} to {address}"
                    )));
                }

                Ok((address, amount))
            })
            .collect::<Result<HashMap<bdk_wallet::bitcoin::Address, Amount>, ConnectError>>()?;

        if destinations_validated.is_empty()
            && !op_return_message.is_set()
            && drain_wallet_to.is_none()
        {
            return Err(ConnectError::invalid_argument(
                "no destinations or op_return_message provided",
            ));
        }

        let drain_wallet_to = drain_wallet_to
            .map(|s| self.parse_checked_address(&s))
            .transpose()?;

        if drain_wallet_to.is_some() && !required_utxos.is_empty() {
            return Err(ConnectError::invalid_argument(
                "cannot provide both drain_wallet_to and required_utxos",
            ));
        }

        let fee_policy = fee_rate
            .into_option()
            .map(|fee_rate| fee_rate.try_into())
            .transpose()?;

        let op_return_message = op_return_message
            .into_option()
            .map(|m| m.decode_status::<SendTransactionRequest, _>("op_return_message"))
            .transpose()?;

        let txid = self
            .send_wallet_transaction(
                destinations_validated,
                CreateTransactionParams {
                    fee_policy,
                    op_return_message,
                    required_utxos,
                    drain_wallet_to,
                },
            )
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        Ok(Response::new(SendTransactionResponse {
            txid: MessageField::some(ReverseHex::encode(&txid)),
        }))
    }

    async fn unlock_wallet(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, UnlockWalletRequest>,
    ) -> ServiceResult<UnlockWalletResponse> {
        use crate::proto::mainchain::UnlockWalletRequest;
        let UnlockWalletRequest { password, .. } = request.to_owned_message();
        self.unlock_existing_wallet(password.as_str())
            .await
            .map_err(|err| err.builder().to_connect_error())?;
        Ok(Response::new(UnlockWalletResponse::default()))
    }

    async fn create_wallet(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CreateWalletRequest>,
    ) -> ServiceResult<CreateWalletResponse> {
        // TODO: needs a way of creating /multiple/ wallets. RPC for unloading/erasing a wallet?
        if self.is_initialized().await {
            let err = WalletInitialization::AlreadyExists;
            return Err(ConnectError::already_exists(format!("{err:#}")));
        }
        use crate::proto::mainchain::CreateWalletRequest;
        let CreateWalletRequest {
            mut mnemonic_words,
            mnemonic_path,
            password,
        } = request.to_owned_message();
        if !mnemonic_words.is_empty() && !mnemonic_path.is_empty() {
            return Err(ConnectError::invalid_argument(
                "cannot provide both mnemonic and mnemonic path",
            ));
        }
        if !mnemonic_path.is_empty() {
            let read = std::fs::read_to_string(&mnemonic_path).map_err(|err| {
                ConnectError::invalid_argument(format!(
                    "failed to read mnemonic from {mnemonic_path}: {err:#}"
                ))
            })?;
            mnemonic_words = read.split_whitespace().map(|s| s.to_string()).collect();
        }
        if !mnemonic_words.is_empty() && mnemonic_words.len() != 12 {
            return Err(ConnectError::invalid_argument("mnemonic must be 12 words"));
        }

        let parsed = if mnemonic_words.is_empty() {
            None
        } else {
            Some(
                Mnemonic::from_str(&mnemonic_words.join(" ")).map_err(|err| {
                    ConnectError::invalid_argument(format!("failed to parse mnemonic: {err:#}"))
                })?,
            )
        };

        let password = if password.is_empty() {
            None
        } else {
            Some(password.as_str())
        };

        self.create_wallet(parsed, password)
            .await
            .map_err(|err| err.builder().to_connect_error())?;

        Ok(Response::new(CreateWalletResponse::default()))
    }
}
