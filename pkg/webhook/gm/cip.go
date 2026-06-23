package gm

import (
	"fmt"
	"strconv"
)

// CIPConfig is the parsed + validated subset of CIP annotations needed to run
// a GM verify. Built once per CIP load by ParseCIPAnnotations.
type CIPConfig struct {
	// URLTemplate is the HSM verify URL with {tenantId}/{appId} placeholders
	// still present (substituted per-call inside Client.SM2Verify).
	URLTemplate string
	TenantID    string

	// ExpectedSigner is the (app-id, node-id, user-id) triple the CIP requires.
	// UserID is empty when the CIP did not pin one — in that case any user-id
	// in the sig artifact annotations passes.
	ExpectedSigner SignerTriple

	// RequestTimeoutMS overrides Client.SM2Verify's default. Zero = default.
	RequestTimeoutMS int

	// CacheDisabled is true when the CIP set AnnCacheTTLSeconds to "0",
	// requesting that every admission round skip the positive-verify cache
	// and call HSM directly. Empty / unset annotation leaves this false
	// (default = cache enabled per the process-wide TTL).
	CacheDisabled bool
}

// IsGmCIP returns true when the CIP's annotations declare the GM algorithm.
// Callers use this as the single dispatch switch in validation.valid().
//
// A nil or empty annotation map returns false — i.e. CIPs that don't opt in
// are completely untouched and continue to use the upstream cosign verifier.
func IsGmCIP(cipAnnotations map[string]string) bool {
	return cipAnnotations[AnnAlgorithm] == AlgorithmSM2SM3
}

// ParseCIPAnnotations extracts and validates GM config from a CIP's annotation
// map. Returns a non-nil error if any required field is missing or malformed
// — callers should reject the admission rather than fall back to the default
// verifier (a CIP that opted in but is misconfigured is an admin error, not
// a "no GM signature" situation).
//
// Required CIP annotations:
//   - zjrcu.gm/algorithm   (must equal "SM2-with-SM3")
//   - zjrcu.gm/verify-url  (URL template with {tenantId}/{appId})
//   - zjrcu.gm/tenant-id   (substitutes {tenantId} + Tenant-Id header)
//   - zjrcu.gm/app-id      (expected signer app id, also substitutes {appId})
//   - zjrcu.gm/node-id     (expected signer node id)
//
// Optional:
//   - zjrcu.gm/user-id              (when set, sig must match)
//   - zjrcu.gm/request-timeout-ms   (integer, default 5000)
func ParseCIPAnnotations(cipAnnotations map[string]string) (*CIPConfig, error) {
	if !IsGmCIP(cipAnnotations) {
		return nil, fmt.Errorf("CIP annotation %s is not %q",
			AnnAlgorithm, AlgorithmSM2SM3)
	}

	required := map[string]string{
		AnnVerifyURL: cipAnnotations[AnnVerifyURL],
		AnnTenantID:  cipAnnotations[AnnTenantID],
		AnnAppID:     cipAnnotations[AnnAppID],
		AnnNodeID:    cipAnnotations[AnnNodeID],
	}
	for k, v := range required {
		if v == "" {
			return nil, fmt.Errorf("CIP annotation %s is required when %s=%s",
				k, AnnAlgorithm, AlgorithmSM2SM3)
		}
	}

	cfg := &CIPConfig{
		URLTemplate: cipAnnotations[AnnVerifyURL],
		TenantID:    cipAnnotations[AnnTenantID],
		ExpectedSigner: SignerTriple{
			AppID:  cipAnnotations[AnnAppID],
			NodeID: cipAnnotations[AnnNodeID],
			UserID: cipAnnotations[AnnUserID], // optional
		},
	}

	if raw := cipAnnotations[AnnRequestTimeoutMS]; raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil || ms <= 0 {
			return nil, fmt.Errorf("CIP annotation %s=%q is not a positive integer",
				AnnRequestTimeoutMS, raw)
		}
		cfg.RequestTimeoutMS = ms
	}

	// AnnCacheTTLSeconds: only the disable case ("0") is honored in Phase 2.
	// Empty/unset = use process-wide default. Any positive value is accepted
	// for forward-compatibility but currently ignored.
	if raw := cipAnnotations[AnnCacheTTLSeconds]; raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil || secs < 0 {
			return nil, fmt.Errorf("CIP annotation %s=%q must be a non-negative integer",
				AnnCacheTTLSeconds, raw)
		}
		cfg.CacheDisabled = secs == 0
	}

	return cfg, nil
}

// MatchSigner returns nil when the sig artifact's annotations identify the
// same signer the CIP expects. Returns an error describing the mismatch
// otherwise — used as the pre-HSM gate so an obviously wrong-signer
// signature is rejected without any network call.
//
// Match rules:
//   - sig must declare zjrcu.gm/alg == "SM2-with-SM3" (catches misrouted sigs)
//   - sig's signer-app-id must equal CIP's app-id
//   - sig's signer-node-id must equal CIP's node-id
//   - if CIP pins user-id, sig's user-id must equal it; if not, any user-id ok
func (c *CIPConfig) MatchSigner(sigAnnotations map[string]string) error {
	if got := sigAnnotations[SigAnnAlg]; got != AlgorithmSM2SM3 {
		return fmt.Errorf("sig annotation %s=%q (expected %q)",
			SigAnnAlg, got, AlgorithmSM2SM3)
	}
	if got := sigAnnotations[SigAnnSignerAppID]; got != c.ExpectedSigner.AppID {
		return fmt.Errorf("sig annotation %s=%q does not match CIP %s=%q",
			SigAnnSignerAppID, got, AnnAppID, c.ExpectedSigner.AppID)
	}
	if got := sigAnnotations[SigAnnSignerNodeID]; got != c.ExpectedSigner.NodeID {
		return fmt.Errorf("sig annotation %s=%q does not match CIP %s=%q",
			SigAnnSignerNodeID, got, AnnNodeID, c.ExpectedSigner.NodeID)
	}
	if c.ExpectedSigner.UserID != "" {
		if got := sigAnnotations[SigAnnUserID]; got != c.ExpectedSigner.UserID {
			return fmt.Errorf("sig annotation %s=%q does not match CIP %s=%q",
				SigAnnUserID, got, AnnUserID, c.ExpectedSigner.UserID)
		}
	}
	return nil
}
