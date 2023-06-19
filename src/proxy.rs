use std::sync::Arc;

use bitcoin::consensus::Encodable;
use color_eyre::eyre::{eyre, Error};
use http::header::AUTHORIZATION;
use hyper::{body::to_bytes, Body, Request, Response};

use crate::{
    client::{RpcRequest, RpcResponse},
    rpc_methods::{
        GetBlock, GetBlockHeader, GetBlockHeaderParams, GetBlockResult, GetRawTransactionResult,
    },
    util::{Either, HexBytes},
};
use crate::{fetch_blocks::fetch_block, state::State};

pub async fn proxy_request(
    state: Arc<State>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let (parts, body) = request.into_parts();
    let body_data = to_bytes(body).await?;
    if let (Ok(req), Some(auth)) = (
        serde_json::from_slice::<RpcRequest<GetBlock>>(body_data.as_ref()),
        parts.headers.get(AUTHORIZATION),
    ) {
        let peers = state.clone().get_peers(auth.clone()).await?;
        let block = fetch_block(state.clone(), peers, auth, req.params.0).await?;
        match req.params.1.unwrap_or(1) {
            0 => {
                let mut block_data = Vec::new();
                block
                    .consensus_encode(&mut block_data)
                    .map_err(Error::from)?;
                RpcResponse::<GetBlock> {
                    id: req.id.clone(),
                    result: Some(Either::Left(HexBytes(block_data.into()))),
                    error: None,
                }
                .into_response()
            }
            1 => {
                let header = state
                    .rpc_client
                    .call(
                        auth,
                        &RpcRequest {
                            id: None,
                            method: GetBlockHeader,
                            params: GetBlockHeaderParams(req.params.0, Some(true)),
                        },
                    )
                    .await?
                    .into_result()?;
                let size = block.size();
                let witness = block
                    .txdata
                    .iter()
                    .flat_map(|tx| tx.input.iter())
                    .flat_map(|input| input.witness.iter())
                    .map(|witness| witness.len())
                    .fold(0, |acc, x| acc + x);
                RpcResponse::<GetBlock> {
                    id: req.id.clone(),
                    result: Some(Either::Right(GetBlockResult {
                        header: header
                            .into_right()
                            .ok_or_else(|| eyre!("unexpected response for getblockheader"))?,
                        size,
                        strippedsize: if witness > 0 {
                            Some(size - witness)
                        } else {
                            None
                        },
                        weight: block.weight().to_wu() as usize,
                        tx: Either::Left(block.txdata.into_iter().map(|tx| tx.txid()).collect()),
                    })),
                    error: None,
                }
                .into_response()
            }
            2 => {
                let header = state
                    .rpc_client
                    .call(
                        auth,
                        &RpcRequest {
                            id: None,
                            method: GetBlockHeader,
                            params: GetBlockHeaderParams(req.params.0, Some(true)),
                        },
                    )
                    .await?
                    .into_result()?
                    .into_right()
                    .ok_or_else(|| eyre!("unexpected response for getblockheader"))?;
                let size = block.size();
                let witness = block
                    .txdata
                    .iter()
                    .flat_map(|tx| tx.input.iter())
                    .flat_map(|input| input.witness.iter())
                    .map(|witness| witness.len())
                    .fold(0, |acc, x| acc + x);
                RpcResponse::<GetBlock> {
                    id: req.id.clone(),
                    result: Some(Either::Right(GetBlockResult {
                        size,
                        strippedsize: if witness > 0 {
                            Some(size - witness)
                        } else {
                            None
                        },
                        weight: block.weight().to_wu() as usize,
                        tx: Either::Right(
                            block
                                .txdata
                                .into_iter()
                                .map(|tx| GetRawTransactionResult::from_raw(tx, &header))
                                .collect::<Result<_, _>>()?,
                        ),
                        header,
                    })),
                    error: None,
                }
                .into_response()
            }
            verbosity => Err(eyre!("unknown verbosity: {verbosity}")),
        }
    } else {
        Ok(state
            .rpc_client
            .send(Request::from_parts(parts, body_data.into()))
            .await?)
    }
}
