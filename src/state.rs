use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::hashes::{sha256d, Hash};
use slog::Logger;
use tokio::sync::{OnceCell, RwLock};

use crate::block_cache::BlockCache;
use crate::client::{RpcClient, RpcRequest};
use crate::fetch_blocks::{PeerHandle, Peers};
use crate::rpc_methods::{BlockchainInfo, GetBlockchainInfo};
use crate::users::Users;

#[derive(Debug)]
pub struct TorState {
    pub proxy: SocketAddr,
    pub only: bool,
}

/// What the p2p handshake needs to know about the chain bitcoind is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkParams {
    /// The four bytes every p2p message starts with, read as a little-endian
    /// `u32` the way `RawNetworkMessage` wants them: mainnet's `f9 be b4 d9`
    /// on the wire is `0xD9B4BEF9` here. A peer on another network drops the
    /// connection rather than answering.
    pub magic: u32,
    /// Port to assume when `getpeerinfo` reports a peer address without one.
    pub default_peer_port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("bitcoind reports an unrecognized chain: {0:?}")]
    UnknownChain(String),
    #[error("bitcoind reports chain \"signet\" but no signet_challenge, which its p2p magic is derived from")]
    MissingSignetChallenge,
}

impl NetworkParams {
    /// The chain names are `ChainTypeToString` in Core's `util/chaintype.cpp`,
    /// which is what `getblockchaininfo` reports and what `-chain=` accepts.
    /// The magic and port for each are `kernel/chainparams.cpp`.
    pub fn from_blockchain_info(info: &BlockchainInfo) -> Result<Self, NetworkError> {
        Ok(match &*info.chain {
            "main" => NetworkParams {
                magic: 0xD9B4BEF9,
                default_peer_port: 8333,
            },
            "test" => NetworkParams {
                magic: 0x0709110B,
                default_peer_port: 18333,
            },
            "testnet4" => NetworkParams {
                magic: 0x283F161C,
                default_peer_port: 48333,
            },
            "signet" => NetworkParams {
                magic: signet_magic(
                    info.signet_challenge
                        .as_ref()
                        .ok_or(NetworkError::MissingSignetChallenge)?,
                ),
                default_peer_port: 38333,
            },
            "regtest" => NetworkParams {
                magic: 0xDAB5BFFA,
                default_peer_port: 18444,
            },
            other => return Err(NetworkError::UnknownChain(other.to_owned())),
        })
    }
}

/// Signet is the one network with no fixed magic: it is the first four bytes of
/// the double SHA256 of the block challenge, so every custom signet has its
/// own. This mirrors `CSigNetParams`, length prefix included — the challenge is
/// hashed as a serialized byte vector, not bare.
fn signet_magic(challenge: &[u8]) -> u32 {
    let mut buf = Vec::with_capacity(challenge.len() + 9);
    VarInt(challenge.len() as u64)
        .consensus_encode(&mut buf)
        .expect("writing to a Vec cannot fail");
    buf.extend_from_slice(challenge);
    let mut magic = [0; 4];
    magic.copy_from_slice(&sha256d::Hash::hash(&buf).into_inner()[..4]);
    u32::from_le_bytes(magic)
}

#[derive(Debug)]
pub struct State {
    pub rpc_client: RpcClient,
    pub tor: Option<TorState>,
    pub i2p_proxy: Option<SocketAddr>,
    pub users: Users,
    pub logger: Logger,
    pub peer_timeout: Duration,
    pub peers: RwLock<Arc<Peers>>,
    pub max_peer_age: Duration,
    pub max_peer_concurrency: Option<usize>,
    /// Filled in from bitcoind the first time a block is fetched from a peer.
    /// A node cannot change chain without a restart, and this restarts with it.
    pub network: OnceCell<NetworkParams>,
    /// Blocks fetched from peers, so the same one is not pulled twice.
    pub block_cache: BlockCache,
}
impl State {
    pub fn leak(self) -> &'static Self {
        Box::leak(Box::new(self))
    }
    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }
    /// The magic and default peer port for bitcoind's chain, asked for once and
    /// cached.
    ///
    /// Deliberately lazy, and it costs nothing to be. The only caller is the
    /// peer-fetch path, which `fetch_block_raw` reaches only after `getblock`
    /// has come back pruned and `getpeerinfo` has returned a peer list. Both go
    /// to this same client, so by the time this runs bitcoind has answered
    /// twice: it can add no startup requirement, and a proxy that never fetches
    /// never asks at all. Concurrent first fetches queue on the `OnceCell`
    /// rather than each issuing the call.
    pub async fn network_params(&self) -> Result<NetworkParams, Error> {
        self.network
            .get_or_try_init(|| async {
                let info = self
                    .rpc_client
                    .call(&RpcRequest {
                        id: None,
                        method: GetBlockchainInfo,
                        params: [],
                    })
                    .await?
                    .into_result()?;
                let params = NetworkParams::from_blockchain_info(&info)?;
                info!(self.logger, "took p2p parameters from bitcoind";
                    "chain" => info.chain.as_str(),
                    "magic" => format!("{:08x}", params.magic),
                    "default_peer_port" => params.default_peer_port);
                Ok::<_, Error>(params)
            })
            .await
            .copied()
    }
    pub async fn get_peers(self: Arc<Self>) -> Result<Vec<PeerHandle>, Error> {
        let mut peers = self.peers.read().await.clone();
        if peers.stale(self.max_peer_age) {
            let handle = tokio::task::spawn(async move {
                match Peers::updated(&self.rpc_client).await {
                    Ok(peers) => {
                        let res = Arc::new(peers);
                        *self.peers.write().await = res.clone();
                        Ok(res)
                    }
                    Err(error) => {
                        error!(self.logger, "failed to update peers"; "error" => #%error);
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

#[cfg(test)]
mod tests {
    use super::{NetworkError, NetworkParams};
    use crate::rpc_methods::BlockchainInfo;

    fn params(json: &str) -> Result<NetworkParams, NetworkError> {
        let info: BlockchainInfo = serde_json::from_str(json).expect("failed to parse");
        NetworkParams::from_blockchain_info(&info)
    }

    /// The four bytes in wire order, which is how `pchMessageStart` reads in
    /// Core's `kernel/chainparams.cpp`.
    fn wire(magic: u32) -> String {
        hex::encode(magic.to_le_bytes())
    }

    #[test]
    fn every_chain_gets_its_own_magic_and_port() {
        for (chain, magic, port) in [
            ("main", "f9beb4d9", 8333u16),
            ("test", "0b110907", 18333),
            ("testnet4", "1c163f28", 48333),
            ("regtest", "fabfb5da", 18444),
        ] {
            let got = params(&format!(r#"{{"chain":"{}"}}"#, chain)).expect(chain);
            assert_eq!(wire(got.magic), magic, "magic for {}", chain);
            assert_eq!(got.default_peer_port, port, "port for {}", chain);
        }
    }

    /// The default signet challenge, verbatim from a Knots 29.4.1 node started
    /// with `-chain=signet`. Hashing it has to land on the signet magic that
    /// rust-bitcoin carries as a hardcoded constant, which is what makes this a
    /// check of the derivation rather than of itself. Core does not carry it:
    /// it computes it the same way this does.
    const DEFAULT_SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

    #[test]
    fn the_default_signet_challenge_hashes_to_the_known_signet_magic() {
        let got = params(&format!(
            r#"{{"chain":"signet","signet_challenge":"{}"}}"#,
            DEFAULT_SIGNET_CHALLENGE
        ))
        .expect("signet");
        assert_eq!(got.magic, 0x40CF030A);
        assert_eq!(wire(got.magic), "0a03cf40");
        assert_eq!(got.default_peer_port, 38333);
    }

    /// A custom signet is a different network on the wire. A configured network
    /// name could not say which one; the challenge can.
    #[test]
    fn a_custom_signet_gets_a_different_magic() {
        let got = params(r#"{"chain":"signet","signet_challenge":"51"}"#).expect("signet");
        assert_ne!(got.magic, 0x40CF030A);
        assert_eq!(got.default_peer_port, 38333);
    }

    #[test]
    fn signet_without_a_challenge_is_an_error() {
        assert!(matches!(
            params(r#"{"chain":"signet"}"#),
            Err(NetworkError::MissingSignetChallenge)
        ));
    }

    /// `bitcoin` was the accepted spelling while this was configured. It is not
    /// what bitcoind calls mainnet, and guessing at it is the whole point of
    /// asking instead.
    #[test]
    fn an_unrecognized_chain_is_an_error() {
        assert!(matches!(
            params(r#"{"chain":"bitcoin"}"#),
            Err(NetworkError::UnknownChain(chain)) if chain == "bitcoin"
        ));
    }
}
