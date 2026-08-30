//! BLAKE2b header v2, as introduced by Bitcoin Knots PR #359.
//!
//! A v2 header is 164 bytes rather than 80, and its block hash is a staged
//! BLAKE2b computation rather than SHA256d. Both are consensus, so a chain that
//! has activated it cannot be served by code that assumes either.
//!
//! This matters here specifically because the proxy is what serves blocks
//! bitcoind has pruned. `rust-bitcoin`'s `Block` decoder reads a transaction
//! count from a hardcoded offset 80, so on a v2 block it either refuses or
//! yields a zero-transaction block whose SHA256d hash is not the block's hash.
//! Either way the proxy could not verify what a peer sent it, which is why
//! pruning and BLAKE2b did not compose until this existed.
//!
//! The format is self-describing: bit 31 of the version field, the first four
//! bytes on the wire, marks v2. So a stream mixing both is parseable without
//! anyone agreeing an activation height, and this module needs no notion of one.
//!
//! Ported from the implementation in this project's electrs fork, which carries
//! the same algorithm against `rust-bitcoin` 0.32. The proxy is on 0.29, whose
//! hash newtypes use `from_inner`/`into_inner` rather than
//! `from_byte_array`/`to_byte_array`, so the two cannot be shared as one file
//! until the proxy's dependency moves.

use std::convert::TryInto;

use anyhow::{ensure, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHash, TxMerkleNode};

/// Bit 31 of the version field. `CompressedHeader::VERSION_HEADER_V2_FLAG`.
pub const VERSION_HEADER_V2_FLAG: u32 = 0x8000_0000;

pub const HEADER_V1_SIZE: usize = 80;
pub const HEADER_V2_SIZE: usize = 164;

/// Bit 2 of `m_flags`: the miner rolls `nTime` via `m_time_offset`.
const FLAG_USE_TIME_OFFSET: u8 = 0x04;

/// Size of the header beginning at `bytes`, from its version field alone.
///
/// This is the whole reason a mixed stream can be walked: four bytes in, the
/// length is known.
pub fn header_size(bytes: &[u8]) -> Result<usize> {
    ensure!(bytes.len() >= 4, "need 4 bytes to read the version field");
    let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    Ok(if version & VERSION_HEADER_V2_FLAG != 0 {
        HEADER_V2_SIZE
    } else {
        HEADER_V1_SIZE
    })
}

/// A BLAKE2b header, in wire field order.
///
/// Byte containers are held in wire order, not display order, which is what
/// both the serializer and the hash want.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderV2 {
    /// Without the v2 flag. `complete_version()` puts it back.
    pub version: u32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: TxMerkleNode,
    /// `nTime - m_time_offset` when the time-offset flag is set, else `nTime`.
    pub time_on_wire: u32,
    pub bits: u32,
    pub nonce: u32,
    pub nonce2: u32,
    pub nonce3: u32,
    pub extranonce: [u8; 16],
    pub time_offset: u32,
    /// Consensus-committed transaction count. Fixes CVE-2017-12842.
    pub txcount: u16,
    /// Low 2 bits select the ASIC profile; bit 2 enables time rolling.
    pub flags: u8,
    pub xor_key_mask_clear_bits: u8,
    /// Pool anti-block-withholding key. Null for solo mining.
    pub xor_key: [u8; 16],
    /// Consensus-committed height.
    pub height: u32,
    /// Merge-mining hook.
    pub mm_rhs: [u8; 32],
}

/// Every intermediate value of the staged hash.
///
/// Exposed because the published vectors carry all of them, which turns a
/// byte-order mistake into a one-line diff rather than a wrong final hash with
/// no clue where it went wrong. That is not hypothetical: porting this caught
/// an `xor_key` order error on the very first stage.
#[derive(Debug, Clone)]
pub struct Stages {
    pub xor_key_hash: [u8; 32],
    pub mask: [u8; 32],
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub blake2b_1: [u8; 32],
    pub asic_input: Vec<u8>,
    pub blake2b_2: [u8; 32],
    pub block_hash: [u8; 32],
}

fn tagged(tag: &str, payload: &[u8]) -> [u8; 32] {
    // BIP340 tagged hash. The C++ asserts `BytesWritten() == 0x40 + n`, the
    // 0x40 being the doubled tag digest, which is what pins this reading.
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut buf = Vec::with_capacity(64 + payload.len());
    buf.extend_from_slice(&t.into_inner());
    buf.extend_from_slice(&t.into_inner());
    buf.extend_from_slice(payload);
    sha256::Hash::hash(&buf).into_inner()
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    // Unkeyed BLAKE2b with a 32-byte digest, which is what Knots uses. The
    // digest length is part of BLAKE2b's parameter block, so this is not a
    // truncation of the 64-byte variant and the two do not agree.
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(data)
        .as_bytes()
        .try_into()
        .expect("hash_length(32) yields 32 bytes")
}

impl HeaderV2 {
    pub fn complete_version(&self) -> u32 {
        (self.version & !VERSION_HEADER_V2_FLAG) | VERSION_HEADER_V2_FLAG
    }

    pub fn time(&self) -> u32 {
        if self.flags & FLAG_USE_TIME_OFFSET != 0 {
            self.time_on_wire.wrapping_add(self.time_offset)
        } else {
            self.time_on_wire
        }
    }

    pub fn asic_profile(&self) -> u8 {
        self.flags & 3
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        ensure!(
            b.len() == HEADER_V2_SIZE,
            "v2 header is {} bytes, got {}",
            HEADER_V2_SIZE,
            b.len()
        );
        let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
        ensure!(
            version & VERSION_HEADER_V2_FLAG != 0,
            "not a v2 header: bit 31 of the version field is clear"
        );
        let u32at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Ok(Self {
            version: version & !VERSION_HEADER_V2_FLAG,
            prev_blockhash: deserialize(&b[4..36])?,
            merkle_root: deserialize(&b[36..68])?,
            time_on_wire: u32at(68),
            bits: u32at(72),
            nonce: u32at(76),
            nonce2: u32at(80),
            nonce3: u32at(84),
            extranonce: b[88..104].try_into().unwrap(),
            time_offset: u32at(104),
            txcount: u16::from_le_bytes(b[108..110].try_into().unwrap()),
            flags: b[110],
            xor_key_mask_clear_bits: b[111],
            xor_key: b[112..128].try_into().unwrap(),
            height: u32at(128),
            mm_rhs: b[132..164].try_into().unwrap(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_V2_SIZE);
        v.extend_from_slice(&self.complete_version().to_le_bytes());
        v.extend_from_slice(&serialize(&self.prev_blockhash));
        v.extend_from_slice(&serialize(&self.merkle_root));
        v.extend_from_slice(&self.time_on_wire.to_le_bytes());
        v.extend_from_slice(&self.bits.to_le_bytes());
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v.extend_from_slice(&self.nonce2.to_le_bytes());
        v.extend_from_slice(&self.nonce3.to_le_bytes());
        v.extend_from_slice(&self.extranonce);
        v.extend_from_slice(&self.time_offset.to_le_bytes());
        v.extend_from_slice(&self.txcount.to_le_bytes());
        v.push(self.flags);
        v.push(self.xor_key_mask_clear_bits);
        v.extend_from_slice(&self.xor_key);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.mm_rhs);
        debug_assert_eq!(v.len(), HEADER_V2_SIZE);
        v
    }

    /// The block hash, which for v2 is the staged BLAKE2b computation rather
    /// than SHA256d over the header bytes.
    ///
    /// Mirrors `CBlockHeader::GetHash()` in `src/primitives/block.cpp`.
    pub fn block_hash(&self) -> BlockHash {
        let s = self.stages();
        // `final_hash` is written backwards from `end()`, so its internal bytes
        // are the reverse of `b2 ^ mask`. `from_inner` takes internal order.
        let mut internal = s.block_hash;
        internal.reverse();
        BlockHash::from_inner(internal)
    }

    pub fn stages(&self) -> Stages {
        let xor_key_hash = tagged("Bitcoin block hash PoW XOR key", &self.xor_key);

        let mut mask = [0u8; 32];
        if self.xor_key.iter().any(|b| *b != 0) {
            mask = tagged("Bitcoin block hash PoW XOR mask", &self.xor_key);
            let clear_bytes = (self.xor_key_mask_clear_bits / 8) as usize;
            for b in mask.iter_mut().take(clear_bytes) {
                *b = 0;
            }
            mask[clear_bytes] &= 0xffu8 >> (self.xor_key_mask_clear_bits % 8);
        }

        // `hashPrevBlock.ReversedBytes()`: the display-order bytes.
        let mut prev_sane = self.prev_blockhash.into_inner();
        prev_sane.reverse();
        let mut prev_hidden = tagged("Bitcoin prevblock header, hashed", &prev_sane);

        let mut h1p = Vec::with_capacity(119);
        h1p.extend_from_slice(&self.complete_version().to_le_bytes());
        h1p.extend_from_slice(&prev_sane);
        h1p.extend_from_slice(&self.height.to_le_bytes());
        h1p.extend_from_slice(&serialize(&self.merkle_root));
        h1p.extend_from_slice(&self.time_on_wire.to_le_bytes());
        h1p.push(0); // reserved for an extended 40-bit time
        h1p.extend_from_slice(&self.bits.to_le_bytes());
        h1p.extend_from_slice(&(self.txcount as u32).to_le_bytes());
        h1p.push(self.flags);
        h1p.push(self.xor_key_mask_clear_bits);
        h1p.extend_from_slice(&xor_key_hash);
        debug_assert_eq!(h1p.len(), 119);
        let h1 = tagged("Bitcoin block header 1", &h1p);

        let mut h2p = Vec::with_capacity(0x60);
        h2p.extend_from_slice(&h1);
        h2p.extend_from_slice(&[0u8; 32]); // two null uint128s
        h2p.extend_from_slice(&self.mm_rhs);
        debug_assert_eq!(h2p.len(), 0x60);
        let h2 = tagged("Merge-mining hook", &h2p);

        let mut ss = Vec::with_capacity(52);
        ss.extend_from_slice(&0u32.to_le_bytes());
        ss.extend_from_slice(&h2);
        ss.extend_from_slice(&self.extranonce);
        debug_assert_eq!(ss.len(), 52);
        let blake2b_1 = blake2b256(&ss);

        // The layout the mining hardware sees. Four profiles, selected by the
        // low two bits of m_flags, because different vendors' devices expect
        // the fields in different orders.
        let mut asic = Vec::with_capacity(160);
        match self.asic_profile() {
            0 => {
                prev_hidden[..6].fill(0);
                asic.extend_from_slice(&prev_hidden);
                asic.extend_from_slice(&self.nonce.to_le_bytes());
                asic.extend_from_slice(&self.nonce2.to_le_bytes());
                asic.extend_from_slice(&self.time_offset.to_le_bytes());
                asic.extend_from_slice(&self.nonce3.to_le_bytes());
                asic.extend_from_slice(&blake2b_1);
            }
            1 => {
                asic.extend_from_slice(&self.nonce.to_le_bytes());
                asic.extend_from_slice(&self.nonce2.to_le_bytes());
                asic.extend_from_slice(&self.nonce3.to_le_bytes());
                asic.extend_from_slice(&self.time_offset.to_le_bytes());
                asic.extend_from_slice(&blake2b_1);
                asic.extend_from_slice(&h2);
            }
            profile => {
                if profile == 3 {
                    asic.extend_from_slice(&[0u8; 32]);
                }
                asic.extend_from_slice(&[0u8; 48]);
                asic.extend_from_slice(&h2);
                asic.extend_from_slice(&self.nonce.to_le_bytes());
                asic.extend_from_slice(&self.nonce2.to_le_bytes());
                asic.extend_from_slice(&self.time_offset.to_le_bytes());
                asic.extend_from_slice(&self.nonce3.to_le_bytes());
                asic.extend_from_slice(&blake2b_1);
            }
        }
        let blake2b_2 = blake2b256(&asic);

        let mut block_hash = [0u8; 32];
        for i in 0..32 {
            block_hash[i] = blake2b_2[i] ^ mask[i];
        }

        Stages {
            xor_key_hash,
            mask,
            h1,
            h2,
            blake2b_1,
            asic_input: asic,
            blake2b_2,
            block_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().expect("hex string")).expect("valid hex")
    }

    fn vectors() -> Vec<Value> {
        let doc: Value =
            serde_json::from_str(include_str!("tests/block_header_v2.json")).expect("valid json");
        doc["headers"].as_array().expect("headers array").to_vec()
    }

    /// Knots publishes every intermediate value, so check every one. A final
    /// hash alone tells you it is wrong, not where.
    #[test]
    fn every_published_stage_matches() {
        let vs = vectors();
        assert!(!vs.is_empty(), "no vectors loaded");
        for v in &vs {
            let h = HeaderV2::parse(&bytes(&v["serialized"])).expect("parses");
            let s = h.stages();
            let want = |k: &str| bytes(&v[k]);
            assert_eq!(
                s.xor_key_hash.to_vec(),
                want("xor_key_hash"),
                "xor_key_hash"
            );
            assert_eq!(s.mask.to_vec(), want("mask"), "mask");
            assert_eq!(s.h1.to_vec(), want("h1"), "h1");
            assert_eq!(s.h2.to_vec(), want("h2"), "h2");
            assert_eq!(s.blake2b_1.to_vec(), want("blake2b_1"), "blake2b_1");
            assert_eq!(s.asic_input, want("asic_input"), "asic_input");
            assert_eq!(s.blake2b_2.to_vec(), want("blake2b_2"), "blake2b_2");
            assert_eq!(
                h.block_hash().to_string(),
                v["block_hash"].as_str().expect("block_hash"),
                "block hash"
            );
        }
    }

    #[test]
    fn all_four_asic_profiles_are_covered_by_the_vectors() {
        let seen: std::collections::BTreeSet<u8> = vectors()
            .iter()
            .map(|v| {
                HeaderV2::parse(&bytes(&v["serialized"]))
                    .expect("parses")
                    .asic_profile()
            })
            .collect();
        assert_eq!(
            seen,
            [0u8, 1, 2, 3].iter().copied().collect(),
            "the vectors should exercise every profile"
        );
    }

    #[test]
    fn serialization_round_trips() {
        for v in vectors() {
            let raw = bytes(&v["serialized"]);
            let h = HeaderV2::parse(&raw).expect("parses");
            assert_eq!(h.serialize(), raw);
        }
    }

    #[test]
    fn the_version_bit_decides_the_length() {
        // A v1 header's version has bit 31 clear.
        assert_eq!(header_size(&0x2000_0000u32.to_le_bytes()).unwrap(), 80);
        assert_eq!(header_size(&0xa000_0000u32.to_le_bytes()).unwrap(), 164);
        assert!(header_size(&[0u8; 3]).is_err(), "needs four bytes");
    }

    #[test]
    fn a_v1_header_is_refused_as_v2() {
        let mut b = vec![0u8; HEADER_V2_SIZE];
        b[0..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        assert!(HeaderV2::parse(&b).is_err(), "bit 31 is clear");
    }

    /// Headers off the live BLAKE2b chain on Bitcoin mainnet.
    ///
    /// The published vectors are synthetic and prove the algorithm; these prove
    /// it against what miners are actually producing, which is a different
    /// claim and the one that was missing.
    ///
    /// 961731 is the useful one: a pool-mined header carrying a non-null
    /// `xor_key`, with `xor_key_mask_clear_bits` of 47. The arithmetic it
    /// reaches is not new, since vector `profile_3` already covers a non-zero
    /// clear-byte count with the same partial-byte shift. What is new is that
    /// it is not synthetic. Every other live header this crate is tested
    /// against, here and in the regtest fixture, was solo-mined with a null
    /// key, so the mask branch had never run on a header off a real chain.
    #[test]
    fn live_mainnet_headers_hash_to_what_the_chain_says() {
        let doc: Value =
            serde_json::from_str(include_str!("tests/blake2b_mainnet.json")).expect("valid json");
        let headers = doc["headers"].as_array().expect("headers array");
        assert!(!headers.is_empty(), "fixture is not empty");
        for h in headers {
            let raw = bytes(&h["header"]);
            let height = h["height"].as_u64().expect("height");
            let parsed = HeaderV2::parse(&raw).expect("v2 header parses");
            assert_eq!(
                parsed.block_hash().to_string(),
                h["hash"].as_str().expect("hash"),
                "height {}",
                height
            );
            assert_eq!(
                parsed.height as u64, height,
                "header commits to its own height"
            );
            assert_eq!(parsed.serialize(), raw, "height {} re-serializes", height);
        }
    }
}
