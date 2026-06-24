// Package gm extends policy-controller with 国密 (Chinese national crypto)
// signature verification, dispatched on the GMSignature CRD field on Authority.
//
// Activation is via the typed CRD field: an Authority with GMSignature set
// routes through this package's Verify(). Authorities without GMSignature
// (i.e. the default Key/Keyless/Static cases) are completely untouched.
//
// The gmctl CLI (separate project) writes the signer-identifying annotation
// keys defined below onto the signature artifact's layer; the verifier here
// matches them against the CIP's expected signer triple before any HSM call.
//
// Threat model summary:
//   - The HSM holds the SM2 private key. A forged signature still fails
//     verification regardless of forged annotations.
//   - Mismatched signer triple (sig declares signer A, CIP requires B) is
//     rejected before the HSM call, so a different valid signer can't sneak
//     in through CIP A's policy.
//   - CIP modification requires cluster-admin RBAC (standard K8s boundary).
package gm

// ── Sig artifact (镜像签名工件) layer annotations — written by gmctl, read here ──
// These are NOT user-facing config; they're part of the artifact format
// produced by the signing side and consumed by the verifying side.

const (
	// SigAnnAlg is the algorithm declared by the sig artifact. Must equal
	// AlgorithmSM2SM3 — a sig without this annotation (or with a different
	// value) is rejected on the GM path with a clear error message.
	SigAnnAlg = "zjrcu.gm/alg"

	// SigAnnSignature is the base64-encoded SM2 signature.
	SigAnnSignature = "zjrcu.gm/signature"

	// SigAnnUserID identifies the signer's user id on the HSM platform.
	SigAnnUserID = "zjrcu.gm/user-id"

	// SigAnnSignerAppID identifies the signer's app id.
	SigAnnSignerAppID = "zjrcu.gm/signer-app-id"

	// SigAnnSignerNodeID identifies the signer's node id.
	SigAnnSignerNodeID = "zjrcu.gm/signer-node-id"

	// SigAnnSignerBusinessNum is optional cert identifier.
	SigAnnSignerBusinessNum = "zjrcu.gm/signer-business-num"

	// SigAnnSignerCertSerial is optional cert serial number.
	SigAnnSignerCertSerial = "zjrcu.gm/signer-cert-serial"
)

// ── Algorithm name(s) ──

const (
	// AlgorithmSM2SM3 is the only algorithm currently supported.
	// (SM2 signature over SM3 hash of payload.)
	AlgorithmSM2SM3 = "SM2-with-SM3"
)

// ── Defaults ──

const (
	// DefaultRequestTimeoutMS is the HSM call timeout when the CIP field
	// GMSignatureRef.RequestTimeoutMs is zero / unset.
	DefaultRequestTimeoutMS = 5000

	// DefaultCacheCapacity is the LRU bound for the positive-verify cache.
	// 4096 × ~64 bytes ≈ 256 KB. Tunable via GM_CACHE_CAPACITY env var.
	DefaultCacheCapacity = 4096

	// DefaultCacheTTLSeconds is the per-entry validity window for cached
	// positive verifies. 30s is short enough that cert/key rotations
	// invalidate the cache promptly without explicit purging, and long
	// enough to absorb typical Pod-bursts (node restart, deployment scale).
	// Tunable via GM_CACHE_TTL_SECONDS env var (0 disables the cache).
	DefaultCacheTTLSeconds = 30
)
