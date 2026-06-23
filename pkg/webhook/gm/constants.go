// Package gm extends policy-controller with 国密 (Chinese national crypto)
// signature verification, without modifying the upstream CRD schema.
//
// Activation is annotation-driven: a ClusterImagePolicy declares it wants the
// GM verifier by setting metadata.annotations on the CR. When the webhook sees
// the algorithm annotation, it routes verification through this package
// (SM3 hash + HSM SM2 /sm2/verify HTTP call) instead of the default cosign
// ECDSA path. CIPs without these annotations are completely untouched.
//
// The gmctl CLI (separate project) embeds the same annotation keys on the
// signature artifact's layer, so the webhook can match a sig's signer identity
// against the CIP's expected signer triple (app-id, node-id, user-id).
//
// Threat model summary (full table in the design doc):
//   - Forged sig annotations only change verifier routing; the HSM holds the
//     actual SM2 private key, so a forged sig still fails verification.
//   - Mismatched signer triple (CIP says signer A, sig was made by signer B)
//     is rejected before any HSM call — no chance for a different valid signer
//     to slip through.
//   - CIP modification requires cluster-admin RBAC, which is the standard
//     K8s trust boundary.
package gm

// ── CIP-level annotations (集群管理员在 ClusterImagePolicy.metadata.annotations 里配) ──

const (
	// AnnAlgorithm is the dispatch switch. Setting it to AlgorithmSM2SM3 routes
	// this CIP's signature verification through the GM path. Any other value
	// (or missing) leaves the default cosign path untouched.
	AnnAlgorithm = "zjrcu.gm/algorithm"

	// AnnVerifyURL is the full HSM verify URL template containing {tenantId}
	// and {appId} placeholders. Identical semantics to the gmctl CLI's
	// gm.http.verify-url config key. Example:
	//   http://158.218.101.121:28080/fc-api/v3.0/{tenantId}/{appId}/sm2/verify
	AnnVerifyURL = "zjrcu.gm/verify-url"

	// AnnTenantID is the HSM tenant identifier substituted into {tenantId}
	// and sent as the Tenant-Id HTTP header.
	AnnTenantID = "zjrcu.gm/tenant-id"

	// AnnAppID is the expected signer's app id. Substituted into {appId}.
	// Also matched against the sig artifact's zjrcu.gm/signer-app-id annotation
	// — mismatch causes rejection before any HSM call.
	AnnAppID = "zjrcu.gm/app-id"

	// AnnNodeID is the expected signer's node id. Matched against the sig
	// artifact's zjrcu.gm/signer-node-id annotation.
	AnnNodeID = "zjrcu.gm/node-id"

	// AnnUserID is the optional expected signer user id. If set on the CIP,
	// must match the sig's zjrcu.gm/user-id; if unset, any user-id passes.
	AnnUserID = "zjrcu.gm/user-id"

	// AnnRequestTimeoutMS overrides the default HSM call timeout (5000ms).
	// Plain integer, milliseconds.
	AnnRequestTimeoutMS = "zjrcu.gm/request-timeout-ms"
)

// ── Sig artifact (镜像签名工件) layer annotations — written by gmctl, read here ──

const (
	// SigAnnAlg is the algorithm declared by the sig artifact. Must equal
	// AlgorithmSM2SM3 when CIP routes to the GM path; otherwise the sig is
	// rejected (a misrouted ECDSA sig wouldn't verify anyway, but failing
	// fast on the annotation gives a much clearer error message).
	SigAnnAlg = "zjrcu.gm/alg"

	// SigAnnSignature is the base64-encoded SM2 signature itself.
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
	// DefaultRequestTimeoutMS is the HSM call timeout when neither the CIP
	// AnnRequestTimeoutMS nor a programmatic override is provided.
	DefaultRequestTimeoutMS = 5000
)
