pub mod client;
pub mod fetch_blocks;
pub mod proxy;
pub mod rpc_methods;
pub mod state;
pub mod util;

use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};

use color_eyre::eyre::Error;
use hyper::{
    server::Server,
    service::{make_service_fn, service_fn},
};

pub use crate::client::RpcClient;
pub use crate::fetch_blocks::Peers;
use crate::proxy::proxy_request;
pub use crate::state::{State, TorState};

pub async fn main(state: Arc<State>, bind_addr: SocketAddr) -> Result<(), Error> {
    let make_service = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move {
                    match proxy_request(state, req).await {
                        Err(e) => {
                            tracing::error!("{e}");
                            tracing::debug!("{e:?}");
                            Err(e)
                        }
                        Ok(a) => Ok(a),
                    }
                }
            }))
        }
    });

    let server = Server::bind(&bind_addr).serve(make_service);

    Ok(server.await?)
}
