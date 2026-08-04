use buffa::MessageField;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use futures::{StreamExt as _, stream::BoxStream};

use crate::{
    proto::{
        ToStatus as _,
        mainchain::{
            GetBlockHeaderInfoRequest, GetBlockHeaderInfoResponse, GetBlockInfoRequest,
            GetBlockInfoResponse, GetChainInfoRequest, GetChainInfoResponse, GetChainTipRequest,
            GetChainTipResponse, Network, StopRequest, StopResponse, SubscribeEventsRequest,
            SubscribeEventsResponse, SubscribeHeaderSyncProgressRequest,
            SubscribeHeaderSyncProgressResponse, get_block_info_response,
        },
        mainchain_service::ValidatorService,
    },
    server::{internal_err, missing_field, validator::Server},
};

#[expect(refining_impl_trait_reachable)]
impl ValidatorService for Server {
    async fn get_block_header_info(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetBlockHeaderInfoRequest>,
    ) -> ServiceResult<GetBlockHeaderInfoResponse> {
        use crate::proto::mainchain::GetBlockHeaderInfoRequest;
        let GetBlockHeaderInfoRequest {
            block_hash,
            max_ancestors,
            ..
        } = request.to_owned_message();
        let block_hash = block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetBlockHeaderInfoRequest>("block_hash"))?
            .decode_status::<GetBlockHeaderInfoRequest, _>("block_hash")?;
        let max_ancestors = max_ancestors.unwrap_or(0) as usize;
        let resp = match self
            .validator
            .try_get_header_infos(&block_hash, max_ancestors)
            .map_err(internal_err)?
        {
            Some(infos) => GetBlockHeaderInfoResponse {
                header_infos: infos.into_iter().map(Into::into).collect(),
            },
            None => GetBlockHeaderInfoResponse::default(),
        };
        Ok(Response::new(resp))
    }

    async fn get_block_info(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetBlockInfoRequest>,
    ) -> ServiceResult<GetBlockInfoResponse> {
        use crate::proto::mainchain::GetBlockInfoRequest;
        let GetBlockInfoRequest {
            block_hash,
            max_ancestors,
            ..
        } = request.to_owned_message();
        let block_hash = block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetBlockInfoRequest>("block_hash"))?
            .decode_status::<GetBlockInfoRequest, _>("block_hash")?;
        let max_ancestors = max_ancestors.unwrap_or(0) as usize;
        let resp = match self
            .validator
            .try_get_block_infos(&block_hash, max_ancestors)
            .map_err(internal_err)?
        {
            None => GetBlockInfoResponse::default(),
            Some(infos) => GetBlockInfoResponse {
                infos: infos
                    .into_iter()
                    .map(|(header_info, block_info)| get_block_info_response::Info {
                        header_info: MessageField::some(header_info.into()),
                        block_info: MessageField::some(block_info.as_proto()),
                    })
                    .collect(),
            },
        };
        Ok(Response::new(resp))
    }

    async fn get_chain_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetChainInfoRequest>,
    ) -> ServiceResult<GetChainInfoResponse> {
        let bitcoin_network = self.validator.network();
        let network: Network = bitcoin_network.into();
        let network_params = self.validator.network_params();
        Ok(Response::new(GetChainInfoResponse {
            network: network.into(),
            activation_height: network_params.activation_height,
        }))
    }

    async fn get_chain_tip(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetChainTipRequest>,
    ) -> ServiceResult<GetChainTipResponse> {
        let Some(tip_hash) = self
            .validator
            .try_get_mainchain_tip()
            .map_err(|err| err.builder().to_connect_error())?
        else {
            return Err(ConnectError::unavailable("Validator is not synced"));
        };
        let header_info = self
            .validator
            .get_header_info(&tip_hash)
            .map_err(internal_err)?;
        Ok(Response::new(GetChainTipResponse {
            block_header_info: MessageField::some(header_info.into()),
        }))
    }

    async fn subscribe_events(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, SubscribeEventsRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<SubscribeEventsResponse>> {
        let stream: BoxStream<'static, _> = self
            .validator
            .subscribe_events()
            .map(move |res| match res {
                Ok(event) => Ok(SubscribeEventsResponse {
                    event: MessageField::some(event.into_proto().into()),
                }),
                Err(err) => Err(err.builder().to_connect_error()),
            })
            .boxed();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn subscribe_header_sync_progress(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, SubscribeHeaderSyncProgressRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<SubscribeHeaderSyncProgressResponse>> {
        let Some(rx) = self.validator.subscribe_header_sync_progress() else {
            return Err(ConnectError::unavailable("No header sync in progress"));
        };
        let stream: BoxStream<'static, _> = tokio_stream::wrappers::WatchStream::new(rx)
            .map(|progress| Ok(progress.into()))
            .boxed();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn stop(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, StopRequest>,
    ) -> ServiceResult<StopResponse> {
        if self.cancel.is_cancelled() {
            return Err(ConnectError::unavailable(
                "Validator is already shutting down",
            ));
        }
        tracing::info!("received stop request, cancelling token");
        self.cancel.cancel();
        Ok(Response::new(StopResponse::default()))
    }
}
