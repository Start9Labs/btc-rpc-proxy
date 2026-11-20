use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use hyper::{
    body::to_bytes,
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
    Body, Method, Request, Response, StatusCode,
};

use crate::client::{RpcError, RpcResponse};
use crate::state::State;

const UNAUTHORIZED_DELAY: Duration = Duration::from_millis(250);

pub async fn proxy_request(
    state: Arc<State>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let (parts, body) = request.into_parts();
    if parts.uri.path() == "/" || parts.uri.path() == "" || parts.uri.path().starts_with("/wallet/")
    {
        if parts.method == Method::POST {
            let state_local = state.clone();
            if let Some((name, user)) = parts
                .headers
                .get(AUTHORIZATION)
                .and_then(|auth| state_local.users.get(auth))
            {
                let body_data = to_bytes(body).await?;
                match serde_json::from_slice(body_data.as_ref()) {
                    Ok(req) => {
                        let state_local = state.clone();
                        let name_local = Arc::new(name);
                        let path = user
                            .override_wallet
                            .as_ref()
                            .map(AsRef::as_ref)
                            .unwrap_or(parts.uri.path());
                        let response = state
                            .rpc_client
                            .send(path, &req, move |_path, req| {
                                use futures::TryFutureExt;
                                let name_local_ok = name_local.clone();
                                let name_local_err = name_local.clone();
                                let state_local_ok = state_local.clone();
                                let state_local_err = state_local.clone();
                                user.intercept(state_local.clone(), req)
                                    .map_ok(move |res| {
                                        let action_description = if res.is_some() {
                                            "INTERCEPTED"
                                        } else {
                                            "FORWARDED"
                                        };

                                        debug!(
                                            state_local_ok.logger,
                                            "processed request";
                                            "params" => serde_json::to_string(&req.params).unwrap_or_default(),
                                            "user" => name_local_ok,
                                            "method" => req.method.0.clone(),
                                            "action" => action_description,
                                        );
                                        res
                                    })
                                    .map_err(move |error| {
                                        warn!(
                                            state_local_err.logger,
                                            "failed request";
                                            "params" => serde_json::to_string(&req.params).unwrap_or_default(),
                                            "user" => name_local_err,
                                            "method" => req.method.0.clone(),
                                            "error_code" => error.code,
                                            "error_message" => &error.message
                                        );
                                        error
                                    })
                            })
                            .await?;
                        Ok(response)
                    }
                    Err(e) => Ok(RpcResponse::from(RpcError::from(e)).into_response()?),
                }
            } else {
                // Bitcoin Core's brute-force deterrent, httprpc.cpp.
                tokio::time::sleep(UNAUTHORIZED_DELAY).await;
                Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")
                    .body(Body::empty())?)
            }
        } else {
            Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body("JSONRPC server handles only POST requests".into())?)
        }
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::time::{Duration, Instant};

    use hyper::{header::AUTHORIZATION, Body, Method, Request, StatusCode};

    use super::{proxy_request, UNAUTHORIZED_DELAY};
    use crate::{AuthSource, BlockCache, Peers, RpcClient, State};

    fn state() -> std::sync::Arc<State> {
        let logger = slog::Logger::root(slog::Discard, o!());
        let mut users = HashMap::new();
        users.insert(
            "satoshi".to_owned(),
            crate::users::input::User {
                password: "secret".try_into().unwrap(),
                allowed_calls: None,
                fetch_blocks: None,
                override_wallet: None,
            },
        );
        State {
            rpc_client: RpcClient::new(
                AuthSource::from_config(Some("u".into()), Some("p".into()), None).unwrap(),
                "http://127.0.0.1:1".parse().unwrap(),
                &logger,
            ),
            tor: None,
            i2p_proxy: None,
            users: crate::users::input::map_default(users, false),
            logger,
            peer_timeout: Duration::from_secs(1),
            peers: tokio::sync::RwLock::new(std::sync::Arc::new(Peers::new())),
            max_peer_age: Duration::from_secs(1),
            max_peer_concurrency: None,
            network: tokio::sync::OnceCell::new(),
            block_cache: BlockCache::new(0),
        }
        .arc()
    }

    #[tokio::test]
    async fn every_refused_login_waits_before_its_401() {
        let state = state();
        for auth in [
            None,
            Some(format!("Basic {}", base64::encode("satoshi:wrong"))),
            Some(format!("Basic {}", base64::encode("nobody:secret"))),
            Some(format!("Basic {}", base64::encode("satoshi:"))),
        ] {
            let mut req = Request::builder().method(Method::POST).uri("/");
            if let Some(auth) = &auth {
                req = req.header(AUTHORIZATION, auth);
            }
            let start = Instant::now();
            let res = proxy_request(state.clone(), req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{:?}", auth);
            assert!(start.elapsed() >= UNAUTHORIZED_DELAY, "{:?}", auth);
        }
    }
}
