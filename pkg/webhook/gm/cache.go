package gm

import (
	"crypto/sha256"
	"encoding/hex"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

// Cache memoizes positive HSM verify results to dodge per-Pod admission
// round-trips when the same image+sig+signer combo is admitted repeatedly
// (think: 50 pods restarting on the same node after a kubelet bounce).
//
// Design choices:
//
//   - POSITIVE RESULTS ONLY. Caching a "false" would amplify an HSM hiccup
//     (a single transport error becomes a TTL-window admission outage), so
//     misses always re-call HSM. The cost is one HSM call per genuine
//     forgery attempt, which is the right side to err on.
//
//   - Bounded by LRU + TTL together. LRU caps memory; TTL caps trust window
//     for any single entry. A cert/key rotation invalidates everything in
//     the cache within at most one TTL period without explicit purging.
//
//   - Key is sha256(sigBytes || appId || nodeId || userId). SM2 is
//     non-deterministic, so identical sigBytes implies "this exact (payload,
//     random-k) pair" — same key = same answer. Signer triple is mixed in
//     so a different signer can't get a cache hit from someone else's sig.
//
//   - Image digest is NOT in the key because the Simple Signing payload
//     embeds it and the SM3 hash is computed over the payload — a sig only
//     verifies against the image it claims. Including it would be redundant
//     (or wrong: same sig fetched for a digested ref vs tag-resolved ref
//     should still hit).
//
// Default sizing: 4096 entries × ~64 bytes each ≈ 256 KB. Adjustable via
// the constructor and per-CIP TTL via the zjrcu.gm/cache-ttl-seconds
// annotation (0 disables caching for that CIP entirely).
type Cache struct {
	c *lru.LRU[string, struct{}]

	// stats for /metrics later (Phase 3)
	hits   atomic.Uint64
	misses atomic.Uint64
}

// NewCache returns a Cache with the given capacity and default TTL.
// TTL=0 returns a no-op cache that never hits, never stores — used by CIPs
// that set cache-ttl-seconds=0 to opt out of memoization entirely.
//
// capacity=0 also disables caching; callers should pass at least 1 unless
// they intentionally want the no-op behavior.
func NewCache(capacity int, defaultTTL time.Duration) *Cache {
	if capacity <= 0 || defaultTTL <= 0 {
		return &Cache{}
	}
	return &Cache{
		c: lru.NewLRU[string, struct{}](capacity, nil, defaultTTL),
	}
}

// Lookup returns true if the (sig, signer) pair is a known-verified entry
// that hasn't expired. Misses are silent — callers should call HSM and then
// Store on success. Safe to call on a nil receiver (returns false without
// touching stats).
func (cache *Cache) Lookup(sig []byte, signer SignerTriple) bool {
	if cache == nil {
		return false
	}
	if cache.c == nil {
		// Cache constructed but disabled (capacity=0 or TTL=0). Count as miss
		// for stats accuracy, but the lookup itself is a no-op.
		cache.misses.Add(1)
		return false
	}
	if _, ok := cache.c.Get(cacheKey(sig, signer)); ok {
		cache.hits.Add(1)
		return true
	}
	cache.misses.Add(1)
	return false
}

// Store memoizes a successful HSM verify. No-op if the cache is disabled.
// We only store positives — never call Store after a HSM error or
// verified=false response.
func (cache *Cache) Store(sig []byte, signer SignerTriple) {
	if cache == nil || cache.c == nil {
		return
	}
	cache.c.Add(cacheKey(sig, signer), struct{}{})
}

// Stats returns the lifetime hit + miss counters. Read-only snapshot;
// the caller can compute hit rate as hits/(hits+misses).
func (cache *Cache) Stats() (hits, misses uint64) {
	if cache == nil {
		return 0, 0
	}
	return cache.hits.Load(), cache.misses.Load()
}

// cacheKey deterministically fingerprints a (sig, signer) pair. We hash
// instead of concatenating raw bytes to bound key size (sig can be 70+
// bytes) and to avoid any ambiguity from concatenation collisions.
func cacheKey(sig []byte, signer SignerTriple) string {
	h := sha256.New()
	h.Write(sig)
	// length-prefixed components so "ab|cd" can't collide with "abc|d"
	writeLen(h, []byte(signer.AppID))
	writeLen(h, []byte(signer.NodeID))
	writeLen(h, []byte(signer.UserID))
	return hex.EncodeToString(h.Sum(nil))
}

func writeLen(h interface{ Write([]byte) (int, error) }, b []byte) {
	var lenBuf [4]byte
	lenBuf[0] = byte(len(b) >> 24)
	lenBuf[1] = byte(len(b) >> 16)
	lenBuf[2] = byte(len(b) >> 8)
	lenBuf[3] = byte(len(b))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(b)
}
