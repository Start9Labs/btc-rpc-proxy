use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::Error;
use http::HeaderValue;
use tokio::sync::RwLock;

use crate::client::RpcClient;
use crate::fetch_blocks::{PeerHandle, Peers};

#[derive(Debug)]
pub struct TorState {
    pub proxy: SocketAddr,
    pub only: bool,
}

#[derive(Debug)]
pub struct State {
    pub rpc_client: RpcClient,
    pub tor: Option<TorState>,
    pub peer_timeout: Duration,
    pub peers: RwLock<Arc<Peers>>,
    pub max_peer_age: Duration,
    pub max_peer_concurrency: Option<usize>,
}
impl State {
    pub fn leak(self) -> &'static Self {
        Box::leak(Box::new(self))
    }
    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }
    pub async fn get_peers(self: Arc<Self>, auth: HeaderValue) -> Result<Vec<PeerHandle>, Error> {
        let mut peers = self.peers.read().await.clone();
        if peers.stale(self.max_peer_age) {
            let handle = tokio::task::spawn(async move {
                match Peers::updated(&self.rpc_client, &auth).await {
                    Ok(peers) => {
                        let res = Arc::new(peers);
                        *self.peers.write().await = res.clone();
                        Ok(res)
                    }
                    Err(error) => {
                        tracing::error!("failed to update peers: {}", error);
                        Err(error)
                    }
                }
            });
            if peers.is_empty() {
                peers = handle.await??;
            }
        }
        Ok(peers.handles())
    }
}
