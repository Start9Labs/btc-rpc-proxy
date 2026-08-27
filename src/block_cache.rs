//! A bounded in-memory cache of blocks fetched from peers.
//!
//! Only blocks that came from the network are stored. A block bitcoind still
//! has is already cheap to ask for, and caching it here would duplicate storage
//! the node is paying for anyway.
//!
//! Caching a block is safe in a way that caching most things is not: the key is
//! the block's own hash, and the fetch path has already checked that the bytes
//! hash to it, that the merkle root matches, and that the witness commitment is
//! satisfied. A block's contents cannot change, and a reorg does not make a
//! block something else, so there is no staleness to reason about. The only
//! thing bounded here is memory.
//!
//! Hand-rolled rather than pulling in an LRU crate, because it is fifty lines
//! and the alternative is a dependency for one data structure.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use bitcoin::hash_types::BlockHash;
use hyper::body::Bytes;

#[derive(Debug, Default)]
struct Inner {
    blocks: HashMap<BlockHash, Bytes>,
    /// Least recently used at the front, which is the end eviction takes from.
    order: VecDeque<BlockHash>,
    bytes: usize,
}

#[derive(Debug)]
pub struct BlockCache {
    max_bytes: usize,
    inner: Mutex<Inner>,
}

impl BlockCache {
    /// A cache holding at most `max_bytes` of blocks. Zero disables it.
    pub fn new(max_bytes: usize) -> Self {
        BlockCache {
            max_bytes,
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.max_bytes > 0
    }

    /// A poisoned lock means some other thread panicked mid-update. The
    /// invariants here are a map, a queue and a running total, so recovering is
    /// preferable to propagating a panic into every later block fetch.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, hash: &BlockHash) -> Option<Bytes> {
        if !self.enabled() {
            return None;
        }
        let mut inner = self.lock();
        let block = inner.blocks.get(hash).cloned()?;
        if let Some(pos) = inner.order.iter().position(|h| h == hash) {
            inner.order.remove(pos);
            inner.order.push_back(*hash);
        }
        Some(block)
    }

    pub fn insert(&self, hash: BlockHash, block: Bytes) {
        if !self.enabled() {
            return;
        }
        let size = block.len();
        // A block bigger than the whole cache would evict everything else to
        // hold one entry, which is worse than not caching it.
        if size > self.max_bytes {
            return;
        }
        let mut inner = self.lock();
        if inner.blocks.contains_key(&hash) {
            return;
        }
        inner.bytes += size;
        inner.blocks.insert(hash, block);
        inner.order.push_back(hash);
        while inner.bytes > self.max_bytes {
            match inner.order.pop_front() {
                Some(evicted) => {
                    if let Some(block) = inner.blocks.remove(&evicted) {
                        inner.bytes -= block.len();
                    }
                }
                None => break,
            }
        }
    }

    /// Blocks held and bytes held.
    pub fn stats(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.blocks.len(), inner.bytes)
    }

    /// The running byte total agrees with what is actually held, and the queue
    /// holds exactly the keys the map does. Test-only: the accounting is what
    /// keeps the bound honest, and a drift in it would show up as memory growth
    /// long before it showed up as a wrong answer.
    #[cfg(test)]
    fn check_invariants(&self) {
        let inner = self.lock();
        let summed: usize = inner.blocks.values().map(|b| b.len()).sum();
        assert_eq!(inner.bytes, summed, "byte total drifted from what is held");
        assert_eq!(
            inner.order.len(),
            inner.blocks.len(),
            "queue and map disagree on how many blocks there are"
        );
        for hash in &inner.order {
            assert!(
                inner.blocks.contains_key(hash),
                "queue holds a key the map does not"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BlockCache;
    use bitcoin::hash_types::BlockHash;
    use bitcoin::hashes::Hash;
    use hyper::body::Bytes;

    fn hash(n: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        BlockHash::from_slice(&bytes).unwrap()
    }

    fn block(size: usize) -> Bytes {
        Bytes::from(vec![0u8; size])
    }

    #[test]
    fn a_stored_block_comes_back() {
        let cache = BlockCache::new(1024);
        cache.insert(hash(1), block(100));
        assert_eq!(cache.get(&hash(1)).map(|b| b.len()), Some(100));
        assert_eq!(cache.get(&hash(2)), None);
    }

    /// The bound is the point: memory is what stops this eating the disk saving
    /// that motivates running pruned in the first place.
    #[test]
    fn eviction_keeps_the_cache_under_its_bound() {
        let cache = BlockCache::new(250);
        for n in 1..=5 {
            cache.insert(hash(n), block(100));
        }
        let (count, bytes) = cache.stats();
        assert!(bytes <= 250, "held {} bytes, bound was 250", bytes);
        assert_eq!(count, 2, "two 100-byte blocks fit under 250");
        assert!(cache.get(&hash(1)).is_none(), "the oldest should be gone");
        assert!(cache.get(&hash(5)).is_some(), "the newest should be held");
    }

    /// Least *recently used*, not least recently inserted: reading a block
    /// should save it from the next eviction.
    #[test]
    fn a_read_block_survives_longer_than_an_unread_one() {
        let cache = BlockCache::new(250);
        cache.insert(hash(1), block(100));
        cache.insert(hash(2), block(100));
        assert!(cache.get(&hash(1)).is_some());
        cache.insert(hash(3), block(100));
        assert!(
            cache.get(&hash(1)).is_some(),
            "read recently, should survive"
        );
        assert!(cache.get(&hash(2)).is_none(), "not read, should be evicted");
    }

    #[test]
    fn a_block_larger_than_the_cache_is_not_stored() {
        let cache = BlockCache::new(100);
        cache.insert(hash(1), block(50));
        cache.insert(hash(2), block(500));
        assert!(cache.get(&hash(2)).is_none(), "oversized, not stored");
        assert!(cache.get(&hash(1)).is_some(), "and it evicted nothing");
    }

    #[test]
    fn zero_disables_it() {
        let cache = BlockCache::new(0);
        assert!(!cache.enabled());
        cache.insert(hash(1), block(100));
        assert!(cache.get(&hash(1)).is_none());
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn inserting_the_same_block_twice_counts_it_once() {
        let cache = BlockCache::new(1024);
        cache.insert(hash(1), block(100));
        cache.insert(hash(1), block(100));
        assert_eq!(cache.stats(), (1, 100));
        cache.check_invariants();
    }

    /// Mixed inserts, repeats and reads against a cache small enough to be
    /// evicting throughout, checking the accounting after every step. The bound
    /// is only as good as the running total that enforces it.
    #[test]
    fn the_accounting_holds_through_churn() {
        let cache = BlockCache::new(1000);
        for round in 0..40u8 {
            cache.insert(hash(round), block(60 + (round as usize % 7) * 30));
            cache.insert(hash(round / 2), block(100));
            let _ = cache.get(&hash(round / 3));
            cache.check_invariants();
            let (_, bytes) = cache.stats();
            assert!(bytes <= 1000, "round {}: held {} bytes", round, bytes);
        }
    }

    /// Blocks vary from a few hundred bytes to megabytes, and the bound has to
    /// hold across that range rather than for uniform test-sized entries.
    #[test]
    fn the_bound_holds_for_realistic_block_sizes() {
        let cache = BlockCache::new(8 * 1024 * 1024);
        for n in 0..40u8 {
            // roughly 200 bytes to 4 MiB, the real spread
            let size = if n % 5 == 0 {
                200
            } else {
                (n as usize % 4 + 1) * 1024 * 1024
            };
            cache.insert(hash(n), block(size));
            cache.check_invariants();
            assert!(cache.stats().1 <= 8 * 1024 * 1024);
        }
    }

    /// The lock is what makes this safe to share; the accounting is what makes
    /// it correct. Hammer both at once.
    #[test]
    fn concurrent_use_keeps_the_accounting_straight() {
        use std::sync::Arc;
        let cache = Arc::new(BlockCache::new(4096));
        let threads: Vec<_> = (0..8u8)
            .map(|t| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for n in 0..64u8 {
                        cache.insert(hash(t.wrapping_mul(64).wrapping_add(n)), block(200));
                        let _ = cache.get(&hash(n));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("a worker panicked");
        }
        cache.check_invariants();
        assert!(cache.stats().1 <= 4096);
    }
}
