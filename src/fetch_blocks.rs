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
use std::convert::TryInto;

use bitcoin::hashes::Hash as _;

use crate::any_block::AnyBlock;
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

/// The largest p2p payload this will hold in memory.
///
/// Bitcoin Core caps a protocol message at 4 MB and `rust-bitcoin` bounds its
/// own decoding at the same figure. The framing below reads a length straight
/// off the wire before it can be validated any other way, so it needs a bound
/// of its own or a peer could name any number and have us allocate it.
const MAX_FRAME_PAYLOAD: usize = 4_000_000;

/// One p2p message, with a `block` payload deliberately left unparsed.
enum Frame {
    /// The raw payload of a `block` message, still bytes.
    Block(Vec<u8>),
    Other(RawNetworkMessage),
}

/// Read one p2p message, without letting `rust-bitcoin` parse a block.
///
/// This exists because `RawNetworkMessage::consensus_decode` eagerly decodes a
/// `block` payload into `bitcoin::Block`, whose header is fixed at 80 bytes. On
/// a header-v2 chain that fails on the wire, before any of the proxy's checks
/// run, so a pruned block on such a chain could not be fetched at all. Framing
/// the message here and handing a `block` payload to `AnyBlock` instead is what
/// makes both formats reachable.
///
/// Everything else is re-assembled and passed to `rust-bitcoin` unchanged, so
/// version, verack and ping keep their existing handling.
fn read_frame(conn: &mut impl Read, expected_magic: u32) -> Result<Frame, Error> {
    let mut head = [0u8; 24];
    conn.read_exact(&mut head)?;

    let magic = u32::from_le_bytes(head[0..4].try_into().unwrap());
    if magic != expected_magic {
        anyhow::bail!(
            "wrong network magic: expected {:x}, got {:x}",
            expected_magic,
            magic
        );
    }
    let len = u32::from_le_bytes(head[16..20].try_into().unwrap()) as usize;
    if len > MAX_FRAME_PAYLOAD {
        anyhow::bail!(
            "peer announced a {}-byte message, over the {}-byte cap",
            len,
            MAX_FRAME_PAYLOAD
        );
    }

    let mut payload = vec![0u8; len];
    conn.read_exact(&mut payload)?;

    // The checksum is normally rust-bitcoin's job. A block payload never
    // reaches it, so verify here rather than trust a length and a command.
    let digest = bitcoin::hashes::sha256d::Hash::hash(&payload);
    if digest.into_inner()[0..4] != head[20..24] {
        anyhow::bail!("p2p message checksum mismatch");
    }

    if &head[4..16] == b"block\0\0\0\0\0\0\0" {
        return Ok(Frame::Block(payload));
    }

    let mut whole = Vec::with_capacity(24 + len);
    whole.extend_from_slice(&head);
    whole.extend_from_slice(&payload);
    Ok(Frame::Other(RawNetworkMessage::consensus_decode(
        &mut std::io::Cursor::new(whole),
    )?))
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
) -> Result<(AnyBlock, RecyclableConnection), Error> {
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
            let (frame, conn_) = tokio::task::spawn_blocking(move || {
                read_frame(&mut *conn, magic).map(|f| (f, conn))
            })
            .await??;
            conn = conn_;
            let msg = match frame {
                Frame::Block(payload) => {
                    // Parsed here rather than by rust-bitcoin, so a 164-byte
                    // header is readable. The checks are the same three as
                    // before, over a type that can hold either format.
                    let b = AnyBlock::parse(&payload)?;
                    let returned_hash = b.block_hash();
                    let merkle_check = b.check_merkle_root();
                    let witness_check = b.check_witnesses();
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
                Frame::Other(m) => m,
            };
            match msg.payload {
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
) -> Option<AnyBlock> {
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
    // The bytes the peer sent, which are the bytes that were verified. Serving
    // a re-serialization would risk handing back something subtly different
    // from what the hash, merkle and witness checks actually ran against.
    let serialized = Bytes::from(block.raw().to_vec());
    state.block_cache.insert(hash, serialized.clone());
    Ok(Some(serialized))
}

pub async fn fetch_block(state: Arc<State>, hash: BlockHash) -> Result<Option<AnyBlock>, RpcError> {
    Ok(match fetch_block_raw(state, hash).await? {
        // `AnyBlock` rather than `bitcoin::Block`, so the callers that read a
        // block's transactions work on a header-v2 chain too. This is the path
        // `getblock` verbosity 1 and `getrawtransaction` take.
        Some(block) => Some(AnyBlock::parse(block.as_ref()).map_err(Error::from)?),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::{read_frame, Frame};
    use crate::any_block::AnyBlock;
    use bitcoin::blockdata::{
        block::{Block, BlockHeader},
        script::Script,
        transaction::{OutPoint, Transaction, TxIn, TxOut},
    };
    use bitcoin::consensus::Decodable;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hashes::Hash;
    use bitcoin::network::message::NetworkMessage;

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

    /// Frame a payload the way a peer does: magic, command, length, checksum.
    fn frame(magic: u32, command: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(24 + payload.len());
        v.extend_from_slice(&magic.to_le_bytes());
        let mut cmd = [0u8; 12];
        cmd[..command.len()].copy_from_slice(command);
        v.extend_from_slice(&cmd);
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let digest = bitcoin::hashes::sha256d::Hash::hash(payload);
        v.extend_from_slice(&digest.into_inner()[0..4]);
        v.extend_from_slice(payload);
        v
    }

    fn v2_block_bytes() -> Vec<u8> {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("tests/blake2b_regtest.json")).expect("json");
        hex::decode(doc["blocks"]["131"]["raw"].as_str().expect("raw")).expect("hex")
    }

    /// The reason `read_frame` exists. A `block` message carrying a 164-byte
    /// header must reach us as bytes; letting `rust-bitcoin` decode the frame
    /// fails here, before any of the proxy's checks can run.
    #[test]
    fn a_v2_block_message_survives_framing() {
        let raw = v2_block_bytes();
        let wire = frame(0xDAB5BFFA, b"block", &raw);

        // What the old path did, and it is worse than failing. rust-bitcoin
        // decodes this frame happily and returns a block with no transactions
        // and a hash that is not the block's, because it reads the transaction
        // count from a hardcoded offset 80, which in a 164-byte header lands in
        // the middle of `m_extranonce`. The proxy then compared that hash
        // against the one it asked for and reported a mismatch, so the fetch
        // failed for a reason that pointed nowhere near the cause.
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("tests/blake2b_regtest.json")).expect("json");
        let real_hash = doc["blocks"]["131"]["hash"].as_str().expect("hash");
        let real_ntx = doc["blocks"]["131"]["ntx"].as_u64().expect("ntx") as usize;
        match bitcoin::network::message::RawNetworkMessage::consensus_decode(
            &mut std::io::Cursor::new(wire.clone()),
        ) {
            Err(_) => { /* also acceptable: it failed loudly */ }
            Ok(m) => match m.payload {
                NetworkMessage::Block(b) => {
                    assert_ne!(b.block_hash().to_string(), real_hash, "hash");
                    assert_ne!(b.txdata.len(), real_ntx, "transaction count");
                }
                _ => panic!("expected a block message"),
            },
        }

        match read_frame(&mut std::io::Cursor::new(wire), 0xDAB5BFFA).expect("frames") {
            Frame::Block(payload) => {
                assert_eq!(payload, raw, "payload preserved byte for byte");
                // And through the parser it becomes the block the chain knows.
                let b = AnyBlock::parse(&payload).expect("parses");
                assert_eq!(b.block_hash().to_string(), real_hash);
                assert_eq!(b.txdata.len(), real_ntx);
                assert!(b.check_merkle_root() && b.check_witnesses());
            }
            _ => panic!("expected a block frame"),
        }
    }

    #[test]
    fn a_non_block_message_still_goes_through_rust_bitcoin() {
        let wire = frame(0xDAB5BFFA, b"verack", &[]);
        match read_frame(&mut std::io::Cursor::new(wire), 0xDAB5BFFA).expect("frames") {
            Frame::Other(m) => assert!(matches!(m.payload, NetworkMessage::Verack)),
            _ => panic!("expected a decoded message"),
        }
    }

    #[test]
    fn a_frame_from_the_wrong_network_is_refused() {
        let wire = frame(0xD9B4BEF9, b"verack", &[]);
        assert!(read_frame(&mut std::io::Cursor::new(wire), 0xDAB5BFFA).is_err());
    }

    #[test]
    fn a_corrupted_payload_is_caught_by_the_checksum() {
        let raw = v2_block_bytes();
        let mut wire = frame(0xDAB5BFFA, b"block", &raw);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(
            read_frame(&mut std::io::Cursor::new(wire), 0xDAB5BFFA).is_err(),
            "the checksum is ours to verify once rust-bitcoin no longer sees the payload"
        );
    }

    #[test]
    fn an_absurd_length_is_refused_before_allocating() {
        let mut wire = frame(0xDAB5BFFA, b"block", &[]);
        wire[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_frame(&mut std::io::Cursor::new(wire), 0xDAB5BFFA).is_err());
    }

    /// The rule `rust-bitcoin` does not have, which is the whole reason the
    /// proxy does its own witness check. Kept here, pointed at `AnyBlock`,
    /// because the check moved there when blocks stopped being `bitcoin::Block`.
    #[test]
    fn a_block_that_commits_to_witnesses_must_carry_them() {
        let stripped = block(true, false);
        // rust-bitcoin is satisfied by this block. That is the problem.
        assert!(stripped.check_witness_commitment());
        assert!(!AnyBlock::from(stripped).check_witnesses());
    }

    #[test]
    fn a_block_with_no_commitment_needs_no_witnesses() {
        assert!(AnyBlock::from(block(false, false)).check_witnesses());
    }
}
