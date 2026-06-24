package gm

import "context"

// Process-wide GM state is carried through the policy-controller call stack
// via context values, so dispatch in pkg/webhook/validator.go doesn't need
// any new parameter on existing functions.

type clientKey struct{}
type cacheKeyType struct{}

// WithClient stamps the singleton HSM Client onto ctx. Done once in
// cmd/webhook/main.go at process start; never replaced.
func WithClient(ctx context.Context, c *Client) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

// ClientFromContext returns the singleton Client. Returns nil when the
// webhook starts without GM enabled — Verify() treats nil as "GM not
// configured" and bails with a clear error rather than panicking, so a
// misconfigured deployment fails admission cleanly.
func ClientFromContext(ctx context.Context) *Client {
	v, _ := ctx.Value(clientKey{}).(*Client)
	return v
}

// WithCache stamps the process-wide positive-verify cache onto ctx. Done
// once in cmd/webhook/main.go alongside WithClient. nil is acceptable —
// CacheFromContext returns a nil *Cache and Lookup/Store become safe no-ops
// so the verify flow still works (just without memoization).
func WithCache(ctx context.Context, cache *Cache) context.Context {
	return context.WithValue(ctx, cacheKeyType{}, cache)
}

// CacheFromContext returns the singleton Cache or nil if not initialized.
// Nil is a normal state — the Cache type's methods are nil-safe.
func CacheFromContext(ctx context.Context) *Cache {
	v, _ := ctx.Value(cacheKeyType{}).(*Cache)
	return v
}
