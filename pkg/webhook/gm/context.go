package gm

import "context"

// Two context keys carry the per-CIP and process-wide GM state through the
// existing policy-controller call stack without changing any function
// signatures (and therefore without changing upstream code beyond a single
// dispatch line in validation.valid()).

type cipAnnotationsKey struct{}
type clientKey struct{}
type cacheKeyType struct{}

// WithCIPAnnotations stamps a CIP's annotation map onto ctx. Done once per
// CIP in validator.ValidatePolicy so the dispatch site in validation.valid()
// can read it without plumbing through extra parameters.
func WithCIPAnnotations(ctx context.Context, annotations map[string]string) context.Context {
	if annotations == nil {
		return ctx
	}
	return context.WithValue(ctx, cipAnnotationsKey{}, annotations)
}

// CIPAnnotationsFromContext returns the annotation map stamped by
// WithCIPAnnotations, or nil if no GM-annotated CIP is in scope. nil is a
// valid value — callers use IsGmCIP(nil) (false) to leave the default
// cosign path untouched.
func CIPAnnotationsFromContext(ctx context.Context) map[string]string {
	v, _ := ctx.Value(cipAnnotationsKey{}).(map[string]string)
	return v
}

// WithClient stamps the singleton HSM Client onto ctx. Done once in
// cmd/webhook/main.go at process start; never replaced.
func WithClient(ctx context.Context, c *Client) context.Context {
	return context.WithValue(ctx, clientKey{}, c)
}

// ClientFromContext returns the singleton Client. Returns nil when the
// webhook starts without GM enabled — verify.go treats nil as "GM not
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
