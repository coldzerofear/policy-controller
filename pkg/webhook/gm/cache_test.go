package gm

import (
	"testing"
	"time"
)

func TestCache_HitMiss(t *testing.T) {
	c := NewCache(8, 1*time.Second)

	sig := []byte("sig-bytes-1")
	signer := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}

	if c.Lookup(sig, signer) {
		t.Error("expected miss on fresh cache")
	}
	c.Store(sig, signer)
	if !c.Lookup(sig, signer) {
		t.Error("expected hit after Store")
	}

	hits, misses := c.Stats()
	if hits != 1 || misses != 1 {
		t.Errorf("stats hits=%d misses=%d, want 1/1", hits, misses)
	}
}

func TestCache_KeysAreSignerScoped(t *testing.T) {
	c := NewCache(8, 1*time.Second)

	sig := []byte("same-sig")
	signerA := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}
	signerB := SignerTriple{AppID: "b", NodeID: "n", UserID: "u"}

	c.Store(sig, signerA)
	if c.Lookup(sig, signerB) {
		t.Error("signer B should not hit signer A's cache entry (key scoping bug)")
	}
	if !c.Lookup(sig, signerA) {
		t.Error("signer A should still hit")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := NewCache(8, 50*time.Millisecond)

	sig := []byte("expiring")
	signer := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}

	c.Store(sig, signer)
	if !c.Lookup(sig, signer) {
		t.Fatal("immediate lookup should hit")
	}
	time.Sleep(70 * time.Millisecond)
	if c.Lookup(sig, signer) {
		t.Error("expected miss after TTL expiry")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	// Capacity 2 — third Store must evict the LRU.
	c := NewCache(2, 5*time.Second)
	signer := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}

	c.Store([]byte("sig1"), signer)
	c.Store([]byte("sig2"), signer)
	// touch sig1 so sig2 becomes LRU
	if !c.Lookup([]byte("sig1"), signer) {
		t.Fatal("sig1 should be present before eviction")
	}
	c.Store([]byte("sig3"), signer)

	if c.Lookup([]byte("sig2"), signer) {
		t.Error("sig2 (LRU) should have been evicted")
	}
	if !c.Lookup([]byte("sig1"), signer) {
		t.Error("sig1 (recently touched) should still be present")
	}
	if !c.Lookup([]byte("sig3"), signer) {
		t.Error("sig3 (just added) should be present")
	}
}

func TestCache_DisabledByZeroCapacity(t *testing.T) {
	c := NewCache(0, 30*time.Second)
	signer := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}
	c.Store([]byte("x"), signer) // must not panic
	if c.Lookup([]byte("x"), signer) {
		t.Error("cache with capacity=0 should never hit")
	}
}

func TestCache_DisabledByZeroTTL(t *testing.T) {
	c := NewCache(8, 0)
	signer := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}
	c.Store([]byte("x"), signer) // must not panic
	if c.Lookup([]byte("x"), signer) {
		t.Error("cache with TTL=0 should never hit")
	}
}

func TestCache_NilReceiver(t *testing.T) {
	// Verify.go passes a nil *Cache when the CIP opts out — these calls
	// must be no-ops without panicking and without touching stats.
	var c *Cache
	signer := SignerTriple{AppID: "a", NodeID: "n", UserID: "u"}

	c.Store([]byte("x"), signer) // no panic
	if c.Lookup([]byte("x"), signer) {
		t.Error("nil cache should never hit")
	}
	hits, misses := c.Stats()
	if hits != 0 || misses != 0 {
		t.Errorf("nil cache stats should be zero, got hits=%d misses=%d", hits, misses)
	}
}

func TestParseCIPAnnotations_CacheDisableFlag(t *testing.T) {
	base := map[string]string{
		AnnAlgorithm: AlgorithmSM2SM3,
		AnnVerifyURL: "http://hsm/{tenantId}/{appId}/sm2/verify",
		AnnTenantID:  "t1",
		AnnAppID:     "app1",
		AnnNodeID:    "node1",
	}

	t.Run("unset -> CacheDisabled false", func(t *testing.T) {
		cfg, err := ParseCIPAnnotations(base)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CacheDisabled {
			t.Error("missing annotation should leave caching enabled")
		}
	})

	t.Run("zero -> CacheDisabled true", func(t *testing.T) {
		ann := cloneMap(base)
		ann[AnnCacheTTLSeconds] = "0"
		cfg, err := ParseCIPAnnotations(ann)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.CacheDisabled {
			t.Error("zero annotation should disable cache")
		}
	})

	t.Run("positive int -> CacheDisabled false (accepted for fwd-compat)", func(t *testing.T) {
		ann := cloneMap(base)
		ann[AnnCacheTTLSeconds] = "60"
		cfg, err := ParseCIPAnnotations(ann)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CacheDisabled {
			t.Error("positive ttl should not disable cache")
		}
	})

	t.Run("negative or malformed -> error", func(t *testing.T) {
		for _, bad := range []string{"-1", "abc", "30.5"} {
			ann := cloneMap(base)
			ann[AnnCacheTTLSeconds] = bad
			if _, err := ParseCIPAnnotations(ann); err == nil {
				t.Errorf("expected error for %s=%q", AnnCacheTTLSeconds, bad)
			}
		}
	})
}
