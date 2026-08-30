//! A block whose header may be 80 bytes or 164.
//!
//! `rust-bitcoin`'s `Block` reads its transaction count from a hardcoded offset
//! 80, so it cannot parse a header-v2 block: it either refuses outright or
//! yields a zero-transaction block whose SHA256d hash is not the block's hash.
//! That is what stopped the proxy serving a pruned block on a BLAKE2b chain,
//! and it is not fixable from outside `rust-bitcoin` because `Block` is a fixed
//! two-field struct over a fixed six-field header.
//!
//! So this parses the block itself. Only the header differs between the two
//! formats: a v2 header's first 80 bytes are byte-for-byte a v1 header, the
//! transaction encoding is untouched by the fork, and the merkle root sits at
//! offset 36 either way. What changes is the header's length and the block's
//! identity, which is a staged BLAKE2b rather than SHA256d.
//!
//! The verification here is the same set the proxy already applied through
//! `rust-bitcoin`, reimplemented over this type rather than weakened: the hash
//! is what was asked for, the merkle root commits to the transactions, and the
//! witness commitment is satisfied. The stricter witness rule is carried over
//! too, and it is the one that is not `rust-bitcoin`'s.

use anyhow::{ensure, Result};
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::consensus::{deserialize, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::util::hash::bitcoin_merkle_root;
use bitcoin::{BlockHash, Transaction, TxMerkleNode};

use crate::header_v2::{header_size, HeaderV2, HEADER_V1_SIZE, HEADER_V2_SIZE};

/// The commitment output's `OP_RETURN` prefix, from BIP141.
const COMMITMENT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

#[derive(Debug, Clone)]
pub enum AnyHeader {
    V1(BlockHeader),
    V2(HeaderV2),
}

impl AnyHeader {
    pub fn block_hash(&self) -> BlockHash {
        match self {
            AnyHeader::V1(h) => h.block_hash(),
            AnyHeader::V2(h) => h.block_hash(),
        }
    }

    pub fn merkle_root(&self) -> TxMerkleNode {
        match self {
            AnyHeader::V1(h) => h.merkle_root,
            AnyHeader::V2(h) => h.merkle_root,
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, AnyHeader::V2(_))
    }
}

/// A parsed block, keeping the bytes it came from.
///
/// The raw serialization is retained because that is what the proxy actually
/// serves: callers want the block back verbatim, and re-serializing a parsed
/// block risks handing back something subtly different from what was verified.
#[derive(Debug, Clone)]
pub struct AnyBlock {
    pub header: AnyHeader,
    pub txdata: Vec<Transaction>,
    raw: Vec<u8>,
}

impl AnyBlock {
    /// Parse a block whose header is either format.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let hsize = header_size(bytes)?;
        ensure!(
            bytes.len() > hsize,
            "block is {} bytes, shorter than its {}-byte header",
            bytes.len(),
            hsize
        );
        let header = match hsize {
            HEADER_V1_SIZE => AnyHeader::V1(deserialize(&bytes[..HEADER_V1_SIZE])?),
            HEADER_V2_SIZE => AnyHeader::V2(HeaderV2::parse(&bytes[..HEADER_V2_SIZE])?),
            other => anyhow::bail!("unreachable header size {}", other),
        };

        // The transaction list is a CompactSize count followed by that many
        // transactions, identically in both formats.
        let mut cursor = std::io::Cursor::new(&bytes[hsize..]);
        let count = bitcoin::VarInt::consensus_decode(&mut cursor)?.0;
        // A block claiming more transactions than there are bytes to hold them
        // would otherwise have us preallocate on a peer's say-so.
        ensure!(
            count <= (bytes.len() - hsize) as u64,
            "block claims {} transactions but has only {} bytes left",
            count,
            bytes.len() - hsize
        );
        let mut txdata = Vec::with_capacity(count as usize);
        for _ in 0..count {
            txdata.push(Transaction::consensus_decode(&mut cursor)?);
        }
        let consumed = hsize + cursor.position() as usize;
        ensure!(
            consumed == bytes.len(),
            "block has {} trailing bytes after {} transactions",
            bytes.len() - consumed,
            count
        );

        // A v2 header commits to its own transaction count, which is the point
        // of the field: it closes CVE-2017-12842, where two different blocks
        // could share a hash. Checking it here is what makes that commitment
        // mean something to the proxy.
        if let AnyHeader::V2(h) = &header {
            ensure!(
                h.txcount as u64 == count,
                "header commits to {} transactions, block carries {}",
                h.txcount,
                count
            );
        }

        Ok(AnyBlock {
            header,
            txdata,
            raw: bytes.to_vec(),
        })
    }

    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    pub fn is_v2(&self) -> bool {
        self.header.is_v2()
    }

    /// The bytes this was parsed from, which is what gets served.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Serialized size, which is simply the bytes it arrived as.
    ///
    /// `Block::size()` recomputes this by re-encoding; here the bytes are
    /// already held, so this is the size of what will actually be served rather
    /// than the size of something equal to it.
    pub fn size(&self) -> usize {
        self.raw.len()
    }

    /// Size of everything that is not a transaction: the header and the count.
    ///
    /// `Block::base_size()` hardcodes 80 for the header. This is the one place
    /// that difference matters for weight, which is why weight is reimplemented
    /// rather than borrowed.
    fn base_size(&self) -> usize {
        let header_len = match &self.header {
            AnyHeader::V1(_) => HEADER_V1_SIZE,
            AnyHeader::V2(_) => HEADER_V2_SIZE,
        };
        header_len + bitcoin::VarInt(self.txdata.len() as u64).len()
    }

    /// Block weight, as BIP141 defines it.
    ///
    /// Mirrors `Block::weight()`. A v2 header is 84 bytes longer, and since the
    /// header is base data it counts four times, so a v2 block's weight exceeds
    /// a v1 block's by 336 for the header alone.
    pub fn weight(&self) -> usize {
        const WITNESS_SCALE_FACTOR: usize = 4;
        let base_weight = WITNESS_SCALE_FACTOR * self.base_size();
        let txs_weight: usize = self.txdata.iter().map(|tx| tx.weight()).sum();
        base_weight + txs_weight
    }

    /// Serialized size with witness data removed.
    ///
    /// Mirrors `Block::strippedsize()`, with the header length taken from the
    /// header rather than assumed to be 80.
    pub fn strippedsize(&self) -> usize {
        let txs: usize = self.txdata.iter().map(|tx| tx.strippedsize()).sum();
        self.base_size() + txs
    }

    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|tx| tx.txid().as_hash());
        bitcoin_merkle_root(hashes).map(|h| h.into())
    }

    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(root) => root == self.header.merkle_root(),
            None => false,
        }
    }

    /// The witness commitment check, plus the rule `rust-bitcoin` lacks.
    ///
    /// `Block::check_witness_commitment` returns true for any block carrying no
    /// witnesses at all, because BIP141 makes the commitment optional in that
    /// case. A peer that strips witness data produces exactly that shape, so
    /// the check passes on a block that has been quietly mutilated. A
    /// commitment in the coinbase is the block's own statement that witness
    /// data exists, so "commits but carries none" is rejected here.
    ///
    /// This is the same rule the proxy already applied to v1 blocks; it is
    /// reimplemented over this type rather than dropped.
    pub fn check_witnesses(&self) -> bool {
        let commits = self.txdata.first().map_or(false, |coinbase| {
            coinbase.output.iter().any(|o| {
                o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[..6] == COMMITMENT_MAGIC
            })
        });
        let carries = self
            .txdata
            .iter()
            .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));
        if !(carries || !commits) {
            return false;
        }
        self.check_witness_commitment()
    }

    /// Mirrors `Block::check_witness_commitment`, over a header of either size.
    ///
    /// The computation is entirely about the transaction list, so nothing in it
    /// is v2-specific; it needs reimplementing only because it hangs off
    /// `Block`, which cannot hold a 164-byte header.
    fn check_witness_commitment(&self) -> bool {
        if self
            .txdata
            .iter()
            .all(|t| t.input.iter().all(|i| i.witness.is_empty()))
        {
            return true;
        }
        let coinbase = match self.txdata.first() {
            Some(cb) if cb.is_coin_base() => cb,
            _ => return false,
        };
        let pos = coinbase.output.iter().rposition(|o| {
            o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[..6] == COMMITMENT_MAGIC
        });
        let pos = match pos {
            Some(p) => p,
            None => return false,
        };
        let commitment = match bitcoin::util::hash::bitcoin_merkle_root(
            self.txdata.iter().enumerate().map(|(i, t)| {
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
        let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
        if witness_vec.len() != 1 || witness_vec[0].len() != 32 {
            return false;
        }
        let expected = {
            use bitcoin::consensus::Encodable;
            use bitcoin::hashes::HashEngine;
            let mut engine = bitcoin::hash_types::WitnessCommitment::engine();
            bitcoin::WitnessMerkleNode::from(commitment)
                .consensus_encode(&mut engine)
                .expect("engines do not error");
            engine.input(witness_vec[0]);
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
}

impl From<Block> for AnyBlock {
    fn from(b: Block) -> Self {
        let raw = bitcoin::consensus::serialize(&b);
        AnyBlock {
            header: AnyHeader::V1(b.header),
            txdata: b.txdata,
            raw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn regtest_doc() -> Value {
        serde_json::from_str(include_str!("tests/blake2b_regtest.json")).expect("valid json")
    }

    fn block_at(height: &str) -> (Vec<u8>, String, usize) {
        let doc = regtest_doc();
        let e = &doc["blocks"][height];
        (
            hex::decode(e["raw"].as_str().expect("raw")).expect("hex"),
            e["hash"].as_str().expect("hash").to_owned(),
            e["ntx"].as_u64().expect("ntx") as usize,
        )
    }

    /// The whole point: a real v2 block off a BLAKE2b chain, parsed, with the
    /// hash the chain gave it.
    #[test]
    fn a_v2_block_parses_and_hashes_to_what_the_chain_says() {
        for height in ["19", "20", "131"] {
            let (raw, hash, ntx) = block_at(height);
            let b = AnyBlock::parse(&raw).expect("parses");
            assert_eq!(b.block_hash().to_string(), hash, "height {}", height);
            assert_eq!(b.txdata.len(), ntx, "height {} tx count", height);
            assert_eq!(b.raw(), &raw[..], "height {} raw bytes preserved", height);
        }
    }

    /// The failure this module exists to fix, kept as a test so it cannot
    /// silently start passing and make the module look unnecessary.
    #[test]
    fn rust_bitcoin_cannot_do_the_same() {
        let (raw, hash, ntx) = block_at("131");
        match bitcoin::consensus::deserialize::<Block>(&raw) {
            Err(_) => {}
            Ok(b) => {
                assert_ne!(b.block_hash().to_string(), hash, "it got the hash right");
                assert_ne!(b.txdata.len(), ntx, "it got the transaction count right");
            }
        }
    }

    #[test]
    fn a_v2_block_commits_to_its_own_transaction_count() {
        let (raw, _, _) = block_at("131");
        let mut b = AnyBlock::parse(&raw).expect("parses");
        // The committed count lives at offset 108 of the header.
        let mut tampered = raw.clone();
        let wrong = (b.txdata.len() as u16).wrapping_add(1);
        tampered[108..110].copy_from_slice(&wrong.to_le_bytes());
        assert!(
            AnyBlock::parse(&tampered).is_err(),
            "a header claiming the wrong transaction count should be refused"
        );
        b.txdata.clear();
    }

    #[test]
    fn merkle_and_witness_checks_hold_on_a_real_v2_block() {
        for height in ["19", "20", "131"] {
            let (raw, _, _) = block_at(height);
            let b = AnyBlock::parse(&raw).expect("parses");
            assert!(b.check_merkle_root(), "height {} merkle", height);
            assert!(b.check_witnesses(), "height {} witnesses", height);
        }
    }

    #[test]
    fn a_tampered_merkle_root_is_caught() {
        let (raw, _, _) = block_at("131");
        let mut tampered = raw.clone();
        tampered[36] ^= 0x01; // merkle root sits at offset 36 in both formats
        let b = AnyBlock::parse(&tampered).expect("still parses");
        assert!(!b.check_merkle_root(), "a flipped merkle root should fail");
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let (raw, _, _) = block_at("19");
        let mut extra = raw.clone();
        extra.push(0);
        assert!(AnyBlock::parse(&extra).is_err(), "trailing byte");
    }

    #[test]
    fn a_v1_block_still_works() {
        // A v1 block built with rust-bitcoin, round-tripped through this parser,
        // so the common path is not regressed by the v2 support.
        let block: Block = deserialize(&hex::decode(V1_BLOCK).expect("hex")).expect("v1 block");
        let raw = bitcoin::consensus::serialize(&block);
        let parsed = AnyBlock::parse(&raw).expect("parses");
        assert!(!parsed.is_v2());
        assert_eq!(parsed.block_hash(), block.block_hash());
        assert_eq!(parsed.txdata.len(), block.txdata.len());
        assert_eq!(parsed.check_merkle_root(), block.check_merkle_root());
    }

    /// Mainnet block 100000, the canonical small v1 block with four
    /// transactions and no witnesses.
    const V1_BLOCK: &str = "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b57100401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a010000004341041b0e8c2567c12536aa13357b79a073dc4444acb83c4ec7a0e2f99dd7457516c5817242da796924ca4e99947d087fedf9ce467cb9f7c6287078f801df276fdf84ac000000000100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac88fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c209275ca9470abfcd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca164593c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3ffffffff0200e32321000000001976a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac000000000100000001c33ebff2a709f13d9f9a7569ab16a32786af7d7e2de09265e41c61d078294ecf010000008a4730440220032d30df5ee6f57fa46cddb5eb8d0d9fe8de6b342d27942ae90a3231e0ba333e02203deee8060fdc70230a7f5b4ad7d7bc3e628cbe219a886b84269eaeb81e26b4fe014104ae31c31bf91278d99b8377a35bbce5b27d9fff15456839e919453fc7b3f721f0ba403ff96c9deeb680e5fd341c0fc3a7b90da4631ee39560639db462e9cb850fffffffff0240420f00000000001976a914b0dcbf97eabf4404e31d952477ce822dadbe7e1088acc060d211000000001976a9146b1281eec25ab4e1e0793ff4e08ab1abb3409cd988ac0000000001000000010b6072b386d4a773235237f64c1126ac3b240c84b917a3909ba1c43ded5f51f4000000008c493046022100bb1ad26df930a51cce110cf44f7a48c3c561fd977500b1ae5d6b6fd13d0b3f4a022100c5b42951acedff14abba2736fd574bdb465f3e6f8da12e2c5303954aca7f78f3014104a7135bfe824c97ecc01ec7d7e336185c81e2aa2c41ab175407c09484ce9694b44953fcb751206564a9c24dd094d42fdbfdd5aad3e063ce6af4cfaaea4ea14fbbffffffff0140420f00000000001976a91439aa3d569e06a1d7926dc4be1193c99bf2eb9ee088ac00000000";
}
