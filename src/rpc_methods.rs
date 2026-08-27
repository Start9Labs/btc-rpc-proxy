use bitcoin::hash_types::{BlockHash, Txid};
use linear_map::set::LinearSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::client::RpcMethod;
use crate::util::{Either, HexBytes};

#[derive(Debug)]
pub struct GetBlock;
#[derive(Debug, Deserialize, Serialize)]
pub struct GetBlockParams(
    pub BlockHash,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<u8>,
);
impl RpcMethod for GetBlock {
    type Params = GetBlockParams;
    type Response = Either<HexBytes, GetBlockResult>;
    fn as_str(&self) -> &'static str {
        "getblock"
    }
}
impl Serialize for GetBlock {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for GetBlock {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &'de str = Deserialize::deserialize(deserializer)?;
        if s == Self.as_str() {
            Ok(Self)
        } else {
            Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(s),
                &Self.as_str(),
            ))
        }
    }
}

#[derive(Debug)]
pub struct GetBlockHeader;
#[derive(Debug, Deserialize, Serialize)]
pub struct GetBlockHeaderParams(
    pub BlockHash,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<bool>,
);
impl RpcMethod for GetBlockHeader {
    type Params = GetBlockHeaderParams;
    type Response = Either<HexBytes, GetBlockHeaderResult>;
    fn as_str(&self) -> &'static str {
        "getblockheader"
    }
}
impl Serialize for GetBlockHeader {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for GetBlockHeader {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &'de str = Deserialize::deserialize(deserializer)?;
        if s == Self.as_str() {
            Ok(Self)
        } else {
            Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(s),
                &Self.as_str(),
            ))
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: bitcoin::BlockHash,
    /// Signed, because Core returns **-1** for a header that is not on the main
    /// chain. As `u32` this failed to deserialize and surfaced as "can't be
    /// parsed as json", which is a confusing way to learn a block was reorged
    /// out. Both callers of this struct go through `getblockheader` with
    /// verbose set, so both could hit it.
    pub confirmations: i32,
    pub height: usize,
    pub version: i32,
    pub version_hex: Option<HexBytes>,
    pub merkleroot: bitcoin::TxMerkleNode,
    pub time: usize,
    pub mediantime: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: HexBytes,
    pub n_tx: usize,
    pub previousblockhash: Option<bitcoin::BlockHash>,
    pub nextblockhash: Option<bitcoin::BlockHash>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
    #[serde(flatten)]
    pub header: GetBlockHeaderResult,
    pub size: usize,
    pub strippedsize: Option<usize>,
    pub weight: usize,
    pub tx: Vec<bitcoin::Txid>,
}

#[derive(Debug)]
pub struct GetPeerInfo;

/// Only the fields `Peers::updated` selects on. Every other key Core emits is
/// left to serde to ignore: naming one here makes it mandatory, and Core drops
/// or conditionalizes keys between releases — `startingheight` went behind
/// `-deprecatedrpc` in 31.0, and `addrbind` is emitted only for a valid bind
/// address.
#[derive(Debug, Deserialize, Serialize)]
pub struct PeerInfo {
    /// The IP address and port of the peer
    pub addr: String,
    /// The services offered
    pub servicesnames: LinearSet<String>,
    /// Inbound (true) or Outbound (false)
    pub inbound: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PeerAddressError {
    #[error("invalid hexadecimal encoding of {string}")]
    InvalidHex {
        string: String,
        #[source]
        error: hex::FromHexError,
    },
    #[error("can't consensus-decode {string}")]
    ConsensusDecode {
        string: String,
        #[source]
        error: bitcoin::consensus::encode::Error,
    },
    #[error("missing port in peer address {0}")]
    MissingPort(String),
    #[error("invalid port in address {address}")]
    InvalidPort {
        address: String,
        #[source]
        error: std::num::ParseIntError,
    },
    #[error("the peer address {0} is neither clearnet address nor onion address")]
    Unknown(String),
    #[error("base32 encoding of onion address {0} is invalid")]
    InvalidOnionEncoding(String),
    #[error("invalid length of onion address {0}")]
    InvalidOnionLength(String),
}

impl RpcMethod for GetPeerInfo {
    type Params = [(); 0];
    type Response = Vec<PeerInfo>;
    fn as_str(&self) -> &'static str {
        "getpeerinfo"
    }
}
impl Serialize for GetPeerInfo {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for GetPeerInfo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &'de str = Deserialize::deserialize(deserializer)?;
        if s == Self.as_str() {
            Ok(Self)
        } else {
            Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(s),
                &Self.as_str(),
            ))
        }
    }
}

#[derive(Debug)]
pub struct GetRawTransaction;

/// `getrawtransaction "txid" ( verbose "blockhash" )`.
///
/// Only the three-argument form is intercepted. Without a blockhash Core needs
/// `txindex`, and the proxy has no txid index of its own to substitute for one.
#[derive(Debug, Deserialize, Serialize)]
pub struct GetRawTransactionParams(
    pub Txid,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Option<BlockHash>,
);
impl RpcMethod for GetRawTransaction {
    type Params = GetRawTransactionParams;
    type Response = Value;
    fn as_str(&self) -> &'static str {
        "getrawtransaction"
    }
}
impl Serialize for GetRawTransaction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

#[derive(Debug)]
pub struct DecodeRawTransaction;

/// The rendering half of a verbose `getrawtransaction`, done by Core rather
/// than reimplemented here.
///
/// `decoderawtransaction` returns `txid`, `hash`, `version`, `size`, `vsize`,
/// `weight`, `locktime`, `vin` and `vout`, and those nine are byte-identical to
/// what verbose `getrawtransaction` returns for the same transaction. That
/// matters: `vout[].scriptPubKey` carries `asm`, `desc`, `address` and `type`,
/// which are Core's own script classification and address encoding. Producing
/// them here would mean reproducing that classifier and getting it wrong at the
/// edges. Asking Core cannot be wrong.
///
/// A one-element tuple rather than a newtype struct: serde renders a
/// single-field tuple struct as the bare inner value, which JSON-RPC rejects
/// with "Params must be an array or object".
pub type DecodeRawTransactionParams = (String,);
impl RpcMethod for DecodeRawTransaction {
    type Params = DecodeRawTransactionParams;
    type Response = Value;
    fn as_str(&self) -> &'static str {
        "decoderawtransaction"
    }
}
impl Serialize for DecodeRawTransaction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

#[derive(Debug)]
pub struct GetBlockchainInfo;

/// Only the fields the proxy reads, for the same reason as `PeerInfo`: naming a
/// key here makes it mandatory, and this response has changed shape under it
/// twice. `softforks` moved to `getdeploymentinfo` in Core 23.0 and was dropped
/// outright in 24.0.1, and `warnings` became an array in 28.0 — both used to be
/// named here, so as written this struct could not parse a current node at all.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockchainInfo {
    /// The chain bitcoind is on, spelled as `-chain=` takes it: `main`, `test`,
    /// `testnet4`, `signet` or `regtest`.
    pub chain: String,
    /// The block challenge, emitted only on signet. Signet derives its p2p
    /// magic from this, so a custom signet's differs from the default one's.
    pub signet_challenge: Option<HexBytes>,
}

impl RpcMethod for GetBlockchainInfo {
    type Params = [(); 0];
    type Response = BlockchainInfo;
    fn as_str(&self) -> &'static str {
        "getblockchaininfo"
    }
}
impl Serialize for GetBlockchainInfo {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for GetBlockchainInfo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &'de str = Deserialize::deserialize(deserializer)?;
        if s == Self.as_str() {
            Ok(Self)
        } else {
            Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(s),
                &Self.as_str(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockchainInfo, PeerInfo};

    /// One `getpeerinfo` entry exactly as Bitcoin Core v31.1 emits it for an
    /// outbound clearnet peer. Core 31.0 put `startingheight` behind
    /// `-deprecatedrpc=startingheight`; naming it in `PeerInfo` made every
    /// peer-list refresh fail, which took `getblock` down with it.
    const CORE_31_PEER: &str = r#"{
      "id": 7,
      "addr": "203.0.113.9:8333",
      "addrbind": "10.0.3.5:44212",
      "network": "ipv4",
      "services": "0000000000000409",
      "servicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
      "relaytxes": true,
      "last_inv_sequence": 0,
      "inv_to_send": 0,
      "lastsend": 1755096000,
      "lastrecv": 1755096001,
      "last_transaction": 1755095990,
      "last_block": 1755095900,
      "bytessent": 123456,
      "bytesrecv": 654321,
      "conntime": 1755090000,
      "timeoffset": 0,
      "pingtime": 0.041,
      "minping": 0.039,
      "version": 70016,
      "subver": "/Satoshi:31.1.0/",
      "inbound": false,
      "bip152_hb_to": false,
      "bip152_hb_from": false,
      "presynced_headers": -1,
      "synced_headers": 962297,
      "synced_blocks": 962297,
      "inflight": [],
      "addr_relay_enabled": true,
      "addr_processed": 100,
      "addr_rate_limited": 0,
      "permissions": [],
      "minfeefilter": 0.00001000,
      "bytessent_per_msg": { "version": 126 },
      "bytesrecv_per_msg": { "version": 126 },
      "connection_type": "outbound-full-relay",
      "transport_protocol_type": "v2",
      "session_id": "abc"
    }"#;

    #[test]
    fn parses_core_31_peer() {
        let peer: PeerInfo = serde_json::from_str(CORE_31_PEER).expect("failed to parse");
        assert_eq!(peer.addr, "203.0.113.9:8333");
        assert!(!peer.inbound);
        assert!(peer.servicesnames.contains("NETWORK"));
    }

    /// Core omits `addrbind` when the bind address is not valid, and drops or
    /// conditionalizes other keys between releases. None of that may break the
    /// peer list.
    #[test]
    fn tolerates_omitted_optional_keys() {
        let stripped = CORE_31_PEER
            .replace(r#""addrbind": "10.0.3.5:44212","#, "")
            .replace(r#""pingtime": 0.041,"#, "")
            .replace(r#""session_id": "abc""#, r#""session_id": """#);
        serde_json::from_str::<PeerInfo>(&stripped).expect("failed to parse");
    }

    /// `getblockchaininfo` off a Knots 29.4.1 node started with `-chain=signet`,
    /// verbatim. Note `warnings` as an array, which Core 28.0 changed it to, and
    /// no `softforks`, which Core 24.0.1 dropped.
    const CORE_29_SIGNET: &str = r#"{
      "chain": "signet",
      "blocks": 0,
      "headers": 0,
      "bestblockhash": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
      "bits": "1e0377ae",
      "target": "00000377ae000000000000000000000000000000000000000000000000000000",
      "difficulty": 0.001126515290698186,
      "time": 1598918400,
      "mediantime": 1598918400,
      "verificationprogress": 1.509425027448838e-08,
      "initialblockdownload": true,
      "chainwork": "000000000000000000000000000000000000000000000000000000000049d414",
      "size_on_disk": 293,
      "pruned": false,
      "signet_challenge": "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
      "warnings": [
      ]
    }"#;

    #[test]
    fn parses_core_29_signet() {
        let info: BlockchainInfo = serde_json::from_str(CORE_29_SIGNET).expect("failed to parse");
        assert_eq!(info.chain, "signet");
        assert_eq!(
            info.signet_challenge.as_ref().map(|c| c.len()),
            Some(71),
            "the challenge the signet magic is derived from"
        );
    }

    /// Same node, `-chain=testnet4`. Every chain but signet omits the
    /// challenge, and a missing key may not be an error.
    #[test]
    fn parses_core_29_testnet4() {
        let info: BlockchainInfo = serde_json::from_str(
            r#"{
              "chain": "testnet4",
              "blocks": 0,
              "headers": 0,
              "bestblockhash": "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
              "bits": "1d00ffff",
              "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
              "difficulty": 1,
              "time": 1714777860,
              "mediantime": 1714777860,
              "verificationprogress": 1.528233146510922e-08,
              "initialblockdownload": true,
              "chainwork": "0000000000000000000000000000000000000000000000000000000100010001",
              "size_on_disk": 269,
              "pruned": false,
              "warnings": [
              ]
            }"#,
        )
        .expect("failed to parse");
        assert_eq!(info.chain, "testnet4");
        assert!(info.signet_challenge.is_none());
    }

    /// Core reports -1 confirmations for a header that is not on the main
    /// chain. This was `u32`, so a reorged-out block surfaced as "can't be
    /// parsed as json" from whichever call happened to ask.
    #[test]
    fn parses_a_stale_block_header() {
        let header: super::GetBlockHeaderResult = serde_json::from_str(
            r#"{
              "hash": "07bf0e81736da8923db558d5768a7006e2b93ce355103ca84af823fcade035e6",
              "confirmations": -1,
              "height": 804,
              "version": 536870912,
              "versionHex": "20000000",
              "merkleroot": "578e22da1ca66f343029c9e95afa42e8ea34e1c407c57cb2f3e87f0073ae9362",
              "time": 1787000000,
              "mediantime": 1787000000,
              "nonce": 1,
              "bits": "207fffff",
              "difficulty": 4.656542373906925e-10,
              "chainwork": "0000000000000000000000000000000000000000000000000000000000000002",
              "nTx": 2,
              "previousblockhash": "60facf42231c33113d9bd67062d2ec290604458937db0fa0d0c13f2c074e9344"
            }"#,
        )
        .expect("a stale header must parse");
        assert_eq!(header.confirmations, -1);
    }

    /// The single-string `warnings` of Core 27 and earlier, and the `softforks`
    /// object dropped in 24.0.1, both still parse — nothing here names either.
    /// A proxy may be pointed at a node older than the one above.
    #[test]
    fn parses_older_node_shape() {
        let info: BlockchainInfo = serde_json::from_str(
            r#"{
              "chain": "main",
              "blocks": 800000,
              "headers": 800000,
              "bestblockhash": "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
              "difficulty": 53911173001054.59,
              "mediantime": 1690168629,
              "verificationprogress": 0.9999,
              "initialblockdownload": false,
              "chainwork": "00000000000000000000000000000000000000004fd66f4dd0d1a9b8a4b6a7ad",
              "size_on_disk": 500000000,
              "pruned": true,
              "pruneheight": 799000,
              "automatic_pruning": true,
              "prune_target_size": 550000000,
              "softforks": { "bip34": { "type": "buried", "active": true, "height": 227931 } },
              "warnings": ""
            }"#,
        )
        .expect("failed to parse");
        assert_eq!(info.chain, "main");
    }
}
