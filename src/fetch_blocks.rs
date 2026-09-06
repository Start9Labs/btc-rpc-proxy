use std::io::{Read, Write};
use std::iter::FromIterator;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Error;
use async_channel as mpmc;
use bitcoin::{
    consensus::{Decodable, Encodable},
    hash_types::BlockHash,
    network::{
        constants::ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::Inventory,
        message_network::VersionMessage,
    },
    Block,
};
use futures::FutureExt;
use hyper::body::Bytes;
use socks::Socks5Stream;

use crate::client::{
    ClientError, RpcClient, RpcError, RpcRequest, MISC_ERROR_CODE, PRUNE_ERROR_MESSAGE,
};
use crate::rpc_methods::{GetBlock, GetBlockParams, GetPeerInfo, PeerAddressError};
use crate::state::{State, TorState};

fn ver_ack(magic: u32) -> RawNetworkMessage {
    RawNetworkMessage {
        magic,
        payload: NetworkMessage::Verack,
    }
}

fn version_message(magic: u32) -> RawNetworkMessage {
    use std::time::SystemTime;
    RawNetworkMessage {
        magic,
        payload: NetworkMessage::Version(VersionMessage::new(
            ServiceFlags::NONE,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            bitcoin::network::Address::new(&([127, 0, 0, 1], 8332).into(), ServiceFlags::NONE),
            bitcoin::network::Address::new(&([127, 0, 0, 1], 8332).into(), ServiceFlags::NONE),
            0,
            format!("BTC RPC Proxy v{}", env!("CARGO_PKG_VERSION")),
            0,
        )),
    }
}

const COMMITMENT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// `Block::check_witness_commitment` returns true for any block with no
/// witnesses at all, which is exactly what a stripping peer returns.
fn check_witnesses(block: &Block) -> bool {
    let commits = block.txdata.first().map_or(false, |coinbase| {
        coinbase.output.iter().any(|o| {
            o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[..6] == COMMITMENT_MAGIC
        })
    });
    if !commits {
        // BIP141 requires a commitment from any block carrying witness data.
        return !block
            .txdata
            .iter()
            .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));
    }
    check_witness_commitment(block)
}

/// The coinbase reserved value became a consensus rule only at SegWit
/// activation, so a signalling-era block commits with no coinbase witness
/// behind it -- mainnet 434499 onwards. Those salt with 32 zero bytes.
fn check_witness_commitment(block: &Block) -> bool {
    use bitcoin::hashes::Hash as _;

    let coinbase = match block.txdata.first() {
        Some(cb) if cb.is_coin_base() => cb,
        _ => return false,
    };
    let pos = match coinbase.output.iter().rposition(|o| {
        o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[..6] == COMMITMENT_MAGIC
    }) {
        Some(p) => p,
        None => return false,
    };
    let commitment = match bitcoin::util::hash::bitcoin_merkle_root(
        block.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                bitcoin::Wtxid::all_zeros().as_hash()
            } else {
                t.wtxid().as_hash()
            }
        }),
    ) {
        Some(root) => root,
        None => return false,
    };
    const ZERO_RESERVED: [u8; 32] = [0u8; 32];
    let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
    let reserved: &[u8] = match witness_vec.len() {
        0 => &ZERO_RESERVED,
        1 if witness_vec[0].len() == 32 => witness_vec[0],
        _ => return false,
    };
    let expected = {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::HashEngine;
        let mut engine = bitcoin::hash_types::WitnessCommitment::engine();
        bitcoin::WitnessMerkleNode::from(commitment)
            .consensus_encode(&mut engine)
            .expect("engines do not error");
        engine.input(reserved);
        bitcoin::hash_types::WitnessCommitment::from_engine(engine)
    };
    let found = match bitcoin::hash_types::WitnessCommitment::from_slice(
        &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };
    found == expected
}

#[derive(Debug)]
pub struct Peers {
    fetched: Option<Instant>,
    peers: Vec<Peer>,
}
impl Peers {
    pub fn new() -> Self {
        Peers {
            fetched: None,
            peers: Vec::new(),
        }
    }
    pub fn stale(&self, max_peer_age: Duration) -> bool {
        self.fetched
            .map(|f| f.elapsed() > max_peer_age)
            .unwrap_or(true)
    }
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
    pub async fn updated(client: &RpcClient) -> Result<Self, PeerUpdateError> {
        Ok(Self {
            peers: client
                .call(&RpcRequest {
                    id: None,
                    method: GetPeerInfo,
                    params: [],
                })
                .await?
                .into_result()?
                .into_iter()
                .filter(|p| !p.inbound)
                .filter(|p| {
                    p.servicesnames.contains("NETWORK") && p.servicesnames.contains("WITNESS")
                })
                .map(|p| Peer::new(Arc::new(p.addr)))
                .collect(),
            fetched: Some(Instant::now()),
        })
    }
    pub fn handles<C: FromIterator<PeerHandle>>(&self) -> C {
        self.peers.iter().map(|p| p.handle()).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PeerUpdateError {
    #[error("Bitcoin RPC failed")]
    Rpc(#[from] RpcError),
    #[error("failed to call Bitcoin RPC")]
    Client(#[from] ClientError),
    #[error("invalid peer address")]
    InvalidPeerAddress(#[from] PeerAddressError),
}

pub enum BitcoinPeerConnection {
    Direct(TcpStream),
    Proxied(Socks5Stream),
}
impl Read for BitcoinPeerConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            BitcoinPeerConnection::Direct(a) => a.read(buf),
            BitcoinPeerConnection::Proxied(a) => a.read(buf),
        }
    }
}
impl Write for BitcoinPeerConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            BitcoinPeerConnection::Direct(a) => a.write(buf),
            BitcoinPeerConnection::Proxied(a) => a.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            BitcoinPeerConnection::Direct(a) => a.flush(),
            BitcoinPeerConnection::Proxied(a) => a.flush(),
        }
    }
    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        match self {
            BitcoinPeerConnection::Direct(a) => a.write_vectored(bufs),
            BitcoinPeerConnection::Proxied(a) => a.write_vectored(bufs),
        }
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            BitcoinPeerConnection::Direct(a) => a.write_all(buf),
            BitcoinPeerConnection::Proxied(a) => a.write_all(buf),
        }
    }
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        match self {
            BitcoinPeerConnection::Direct(a) => a.write_fmt(fmt),
            BitcoinPeerConnection::Proxied(a) => a.write_fmt(fmt),
        }
    }
}
impl BitcoinPeerConnection {
    /// `consensus_encode` writes a message in several small pieces, so Nagle
    /// holds all but the first until the peer's delayed-ACK timer fires.
    fn set_nodelay(&self) -> std::io::Result<()> {
        match self {
            BitcoinPeerConnection::Direct(s) => s.set_nodelay(true),
            BitcoinPeerConnection::Proxied(s) => s.get_ref().set_nodelay(true),
        }
    }

    pub async fn connect(state: Arc<State>, mut addr: Arc<String>) -> Result<Self, Error> {
        let network = state.network_params().await?;
        if !addr.contains(":") {
            addr = Arc::new(format!("{}:{}", &*addr, network.default_peer_port));
        }
        tokio::time::timeout(
            state.peer_timeout,
            tokio::task::spawn_blocking(move || {
                // bitcoind reports i2p peers as `<base32>.b32.i2p:0`, which is
                // neither routable nor resolvable outside i2p, so those need
                // their own SOCKS proxy — Tor's cannot reach them.
                let host = addr.rsplit_once(':').map_or(&**addr, |(host, _)| host);
                let mut stream = if host.ends_with(".i2p") {
                    let proxy = state.i2p_proxy.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("no i2p proxy configured, cannot reach {}", addr)
                    })?;
                    BitcoinPeerConnection::Proxied(Socks5Stream::connect(proxy, &**addr)?)
                } else {
                    match &state.tor {
                        Some(TorState { only, proxy }) if *only || host.ends_with(".onion") => {
                            BitcoinPeerConnection::Proxied(Socks5Stream::connect(proxy, &**addr)?)
                        }
                        _ => BitcoinPeerConnection::Direct(TcpStream::connect(&*addr)?),
                    }
                };
                if let Err(e) = stream.set_nodelay() {
                    warn!(state.logger, "failed to set TCP_NODELAY"; "error" => %e);
                }
                version_message(network.magic).consensus_encode(&mut stream)?;
                stream.flush()?;
                let _ =
                    bitcoin::network::message::RawNetworkMessage::consensus_decode(&mut stream)?; // version
                let _ =
                    bitcoin::network::message::RawNetworkMessage::consensus_decode(&mut stream)?; // verack
                ver_ack(network.magic).consensus_encode(&mut stream)?;
                stream.flush()?;

                Ok(stream)
            }),
        )
        .await??
    }
}

pub struct Peer {
    addr: Arc<String>,
    send: mpmc::Sender<BitcoinPeerConnection>,
    recv: mpmc::Receiver<BitcoinPeerConnection>,
}
impl Peer {
    pub fn new(addr: Arc<String>) -> Self {
        let (send, recv) = mpmc::bounded(1);
        Peer { addr, send, recv }
    }
    pub fn handle(&self) -> PeerHandle {
        PeerHandle {
            addr: self.addr.clone(),
            conn: self.recv.try_recv().ok(),
            send: self.send.clone(),
        }
    }
}
impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Peer").field("addr", &self.addr).finish()
    }
}

pub struct PeerHandle {
    addr: Arc<String>,
    conn: Option<BitcoinPeerConnection>,
    send: mpmc::Sender<BitcoinPeerConnection>,
}
impl PeerHandle {
    pub async fn connect(&mut self, state: Arc<State>) -> Result<RecyclableConnection, Error> {
        if let Some(conn) = self.conn.take() {
            Ok(RecyclableConnection {
                conn,
                send: self.send.clone(),
            })
        } else {
            Ok(RecyclableConnection {
                conn: BitcoinPeerConnection::connect(state, (&self.addr).clone()).await?,
                send: self.send.clone(),
            })
        }
    }
}

pub struct RecyclableConnection {
    conn: BitcoinPeerConnection,
    send: mpmc::Sender<BitcoinPeerConnection>,
}
impl RecyclableConnection {
    fn recycle(self) {
        self.send.try_send(self.conn).unwrap_or_default()
    }
}
impl std::ops::Deref for RecyclableConnection {
    type Target = BitcoinPeerConnection;
    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}
impl std::ops::DerefMut for RecyclableConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

/// The block as bitcoind serialized it, or `None` if bitcoind has pruned it.
async fn fetch_block_from_self(state: &State, hash: BlockHash) -> Result<Option<Bytes>, RpcError> {
    match state
        .rpc_client
        .call(&RpcRequest {
            id: None,
            method: GetBlock,
            params: GetBlockParams(hash, Some(0)),
        })
        .await?
        .into_result()
    {
        Ok(b) => Ok(Some(
            b.into_left()
                .ok_or_else(|| anyhow::anyhow!("unexpected response for getblock"))?
                .into_inner(),
        )),
        Err(e) if e.code == MISC_ERROR_CODE && e.message == PRUNE_ERROR_MESSAGE => Ok(None),
        Err(e) => Err(e),
    }
}

async fn fetch_block_from_peer<'a>(
    state: Arc<State>,
    hash: BlockHash,
    mut conn: RecyclableConnection,
) -> Result<(Block, RecyclableConnection), Error> {
    let magic = state.network_params().await?.magic;
    tokio::time::timeout(state.peer_timeout, async move {
        conn = tokio::task::spawn_blocking(move || {
            RawNetworkMessage {
                magic,
                // MSG_BLOCK gets the witness-stripped serialization.
                payload: NetworkMessage::GetData(vec![Inventory::WitnessBlock(hash)]),
            }
            .consensus_encode(&mut *conn)
            .map_err(Error::from)
            .map(|_| conn)
        })
        .await??;

        loop {
            let (msg, conn_) = tokio::task::spawn_blocking(move || {
                RawNetworkMessage::consensus_decode(&mut *conn)
                    .map_err(Error::from)
                    .map(|msg| (msg, conn))
            })
            .await??;
            conn = conn_;
            match msg.payload {
                NetworkMessage::Block(b) => {
                    let returned_hash = b.block_hash();
                    let merkle_check = b.check_merkle_root();
                    let witness_check = check_witnesses(&b);
                    return match (returned_hash == hash, merkle_check, witness_check) {
                        (true, true, true) => Ok((b, conn)),
                        (true, true, false) => {
                            Err(anyhow::anyhow!("Witness check failed for {:?}", hash))
                        }
                        (true, false, _) => {
                            Err(anyhow::anyhow!("Merkle check failed for {:?}", hash))
                        }
                        (false, _, _) => Err(anyhow::anyhow!(
                            "Expected block hash {:?}, got {:?}",
                            hash,
                            returned_hash
                        )),
                    };
                }
                NetworkMessage::Ping(p) => {
                    conn = tokio::task::spawn_blocking(move || {
                        RawNetworkMessage {
                            magic,
                            payload: NetworkMessage::Pong(p),
                        }
                        .consensus_encode(&mut *conn)
                        .map_err(Error::from)
                        .map(|_| conn)
                    })
                    .await??;
                }
                m => warn!(state.logger, "Invalid Message Received: {:?}", m),
            }
        }
    })
    .await?
}

async fn fetch_block_from_peers(
    state: Arc<State>,
    peers: Vec<PeerHandle>,
    hash: BlockHash,
) -> Option<Block> {
    use futures::stream::StreamExt;

    let (send, mut recv) = futures::channel::mpsc::channel(1);
    let fut_unordered: futures::stream::FuturesUnordered<_> =
        peers.into_iter().map(futures::future::ready).collect();
    let state_local = state.clone();
    let runner = fut_unordered
        .then(move |mut peer| {
            let state_local = state_local.clone();
            async move {
                fetch_block_from_peer(
                    state_local.clone(),
                    hash.clone(),
                    peer.connect(state_local).await?,
                )
                .await
            }
        })
        .for_each_concurrent(state.max_peer_concurrency, |block_res| {
            match block_res {
                Ok((block, conn)) => {
                    conn.recycle();
                    send.clone().try_send(block).unwrap_or_default();
                }
                Err(e) => warn!(state.logger, "Error fetching block from peer: {}", e),
            }
            futures::future::ready(())
        });
    let mut blk_future = recv.next().fuse();
    let mut b = futures::select! {
        b = &mut blk_future => b,
        _ = runner.boxed().fuse() => None
    };
    if b.is_none() {
        b = match futures::poll!(blk_future) {
            std::task::Poll::Ready(Some(b)) => Some(b),
            _ => None,
        };
    }
    b
}

/// The consensus-serialized block, from the local node if it still has it and
/// from peers otherwise. Callers wanting `getblock` verbosity 0 use this
/// directly and never pay to parse the block.
pub async fn fetch_block_raw(
    state: Arc<State>,
    hash: BlockHash,
) -> Result<Option<Bytes>, RpcError> {
    // Ahead of bitcoind, not behind it: the cache only holds blocks bitcoind did
    // not have, so a hit is always cheaper than the round trip that would miss.
    if let Some(block) = state.block_cache.get(&hash) {
        debug!(state.logger, "Serving a block from the peer-fetch cache."; "block_hash" => %hash);
        return Ok(Some(block));
    }
    if let Some(block) = fetch_block_from_self(&*state, hash).await? {
        return Ok(Some(block));
    }
    debug!(
        state.logger,
        "Block is pruned from Core, attempting fetch from peers.";
        "block_hash" => %hash
    );
    // Resolved here rather than by the caller so that a failure to enumerate
    // peers can only ever affect blocks Core no longer has.
    let peers = state.clone().get_peers().await?;
    let block = match fetch_block_from_peers(state.clone(), peers, hash).await {
        Some(block) => block,
        None => {
            error!(state.logger, "Could not fetch block from peers."; "block_hash" => %hash);
            return Ok(None);
        }
    };
    let mut serialized = Vec::new();
    block
        .consensus_encode(&mut serialized)
        .map_err(Error::from)?;
    let serialized = Bytes::from(serialized);
    state.block_cache.insert(hash, serialized.clone());
    Ok(Some(serialized))
}

pub async fn fetch_block(state: Arc<State>, hash: BlockHash) -> Result<Option<Block>, RpcError> {
    Ok(match fetch_block_raw(state, hash).await? {
        Some(block) => Some(
            Block::consensus_decode(&mut std::io::Cursor::new(block.as_ref()))
                .map_err(Error::from)?,
        ),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::check_witnesses;
    use bitcoin::blockdata::{
        block::{Block, BlockHeader},
        script::Script,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
    };
    use bitcoin::hashes::Hash;

    fn block(commitment: bool, witness: bool) -> Block {
        let mut commitment_spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_spk.extend_from_slice(&[0x11; 32]);
        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata: vec![Transaction {
                version: 1,
                lock_time: bitcoin::PackedLockTime(0),
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from(vec![0x51, 0x51]),
                    sequence: bitcoin::Sequence::MAX,
                    witness: if witness {
                        bitcoin::Witness::from_vec(vec![vec![0; 32]])
                    } else {
                        bitcoin::Witness::default()
                    },
                }],
                output: vec![TxOut {
                    value: 0,
                    script_pubkey: Script::from(if commitment {
                        commitment_spk
                    } else {
                        vec![0x51]
                    }),
                }],
            }],
        }
    }

    /// A commitment nobody could have produced is still refused. The block
    /// says witness data exists and hands over a value that does not describe
    /// the transactions it carries.
    #[test]
    fn a_commitment_that_does_not_describe_the_block_is_refused() {
        // `block` writes a fixed 0x11.. commitment, which no real merkle root
        // reproduces.
        assert!(!check_witnesses(&block(true, false)));
    }

    #[test]
    fn a_block_with_no_commitment_needs_no_witnesses() {
        assert!(check_witnesses(&block(false, false)));
    }

    /// Witness data with nothing committing to it is not something BIP141
    /// allows, and it is not something a peer should be able to add.
    #[test]
    fn witnesses_with_no_commitment_are_refused() {
        assert!(!check_witnesses(&block(false, true)));
    }

    /// A non-coinbase transaction, optionally carrying a witness.
    fn spending_tx(witness: bool) -> Transaction {
        Transaction {
            version: 1,
            lock_time: bitcoin::PackedLockTime(0),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: if witness {
                    bitcoin::Witness::from_vec(vec![vec![0xab; 71], vec![0xcd; 33]])
                } else {
                    bitcoin::Witness::default()
                },
            }],
            output: vec![TxOut {
                value: 1,
                script_pubkey: Script::from(vec![0x51]),
            }],
        }
    }

    /// A block whose coinbase commits to exactly the witnesses it carries.
    ///
    /// `reserved` picks the salt shape: `Some(v)` puts a 32-byte reserved value
    /// in the coinbase witness, and `None` leaves the coinbase witness empty,
    /// which is the shape mainnet blocks mined during SegWit signalling have.
    fn committing_block(txs: Vec<Transaction>, reserved: Option<[u8; 32]>) -> Block {
        let salt = reserved.unwrap_or([0u8; 32]);
        let root = bitcoin::util::hash::bitcoin_merkle_root(
            std::iter::once(bitcoin::Wtxid::all_zeros().as_hash())
                .chain(txs.iter().map(|t| t.wtxid().as_hash())),
        )
        .expect("a root");
        let commitment = {
            use bitcoin::consensus::Encodable;
            use bitcoin::hashes::HashEngine;
            let mut engine = bitcoin::hash_types::WitnessCommitment::engine();
            bitcoin::WitnessMerkleNode::from(root)
                .consensus_encode(&mut engine)
                .expect("engines do not error");
            engine.input(&salt);
            bitcoin::hash_types::WitnessCommitment::from_engine(engine)
        };
        let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        spk.extend_from_slice(&commitment.into_inner());

        let coinbase = Transaction {
            version: 1,
            lock_time: bitcoin::PackedLockTime(0),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from(vec![0x51, 0x51]),
                sequence: bitcoin::Sequence::MAX,
                witness: match reserved {
                    Some(v) => bitcoin::Witness::from_vec(vec![v.to_vec()]),
                    None => bitcoin::Witness::default(),
                },
            }],
            output: vec![
                TxOut {
                    value: 0,
                    script_pubkey: Script::from(vec![0x51]),
                },
                TxOut {
                    value: 0,
                    script_pubkey: Script::from(spk),
                },
            ],
        };
        let mut txdata = vec![coinbase];
        txdata.extend(txs);
        Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata,
        }
    }

    /// The shape of mainnet 434499: a witness commitment in the coinbase, no
    /// witness data anywhere, and no reserved value, because SegWit had not
    /// activated when it was mined. Rejecting this on sight is what stops a
    /// pruned index dead at that height, since every peer returns the same
    /// bytes and so every peer appears to fail.
    #[test]
    fn a_signalling_era_block_that_commits_but_carries_nothing_is_accepted() {
        let b = committing_block(vec![spending_tx(false)], None);
        assert!(
            check_witnesses(&b),
            "a block mined during SegWit signalling must be fetchable"
        );
    }

    /// The rule `rust-bitcoin` does not have, which is the whole reason this
    /// check exists: a peer that removes witness data the block commits to
    /// must still be caught. It is caught now by the commitment failing to
    /// reproduce rather than by the block's shape.
    ///
    /// The reserved value here is the all-zero one, so stripping leaves the
    /// salt unchanged. That makes the wtxid root the only thing that can catch
    /// the peer, which is exactly what needs proving.
    #[test]
    fn a_peer_that_strips_committed_witnesses_is_still_caught() {
        let honest = committing_block(vec![spending_tx(true)], Some([0u8; 32]));
        assert!(check_witnesses(&honest), "the honest block verifies");

        // What a peer serving the witness-stripped serialization returns: no
        // witnesses at all, the coinbase reserved value included.
        let mut stripped = honest;
        for tx in stripped.txdata.iter_mut() {
            for input in tx.input.iter_mut() {
                input.witness = bitcoin::Witness::default();
            }
        }
        // rust-bitcoin is satisfied by this block. That is the problem.
        assert!(stripped.check_witness_commitment());
        assert!(
            !check_witnesses(&stripped),
            "a stripped block must not pass"
        );
    }
}
