package gm

import (
	"fmt"

	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
)

// Validate returns a non-nil error when the CRD GMSignatureRef is missing
// any required field. We refuse to fall back to the default verifier path
// in that case — a CIP that declared GMSignature but is misconfigured is
// an admin error, and silently passing through to ECDSA would mask it.
func Validate(ref *webhookcip.GMSignatureRef) error {
	if ref == nil {
		return fmt.Errorf("GMSignature is nil")
	}
	if ref.VerifyURL == "" {
		return fmt.Errorf("GMSignature.verifyUrl is required")
	}
	if ref.TenantID == "" {
		return fmt.Errorf("GMSignature.tenantId is required")
	}
	if ref.Signer.AppID == "" {
		return fmt.Errorf("GMSignature.signer.appId is required")
	}
	if ref.Signer.NodeID == "" {
		return fmt.Errorf("GMSignature.signer.nodeId is required")
	}
	return nil
}

// MatchSigner returns nil when the sig artifact's annotations identify the
// same signer the CIP expects. Returns an error describing the mismatch
// otherwise — used as the pre-HSM gate so an obviously wrong-signer
// signature is rejected without any network call.
//
// Match rules:
//   - sig must declare zjrcu.gm/alg == AlgorithmSM2SM3 (catches misrouted sigs)
//   - sig's signer-app-id must equal ref.Signer.AppID
//   - sig's signer-node-id must equal ref.Signer.NodeID
//   - if ref.Signer.UserID is set, sig's user-id must equal it; if unset,
//     any user-id passes
func MatchSigner(ref *webhookcip.GMSignatureRef, sigAnnotations map[string]string) error {
	if got := sigAnnotations[SigAnnAlg]; got != AlgorithmSM2SM3 {
		return fmt.Errorf("sig annotation %s=%q (expected %q)",
			SigAnnAlg, got, AlgorithmSM2SM3)
	}
	if got := sigAnnotations[SigAnnSignerAppID]; got != ref.Signer.AppID {
		return fmt.Errorf("sig annotation %s=%q does not match GMSignature.signer.appId=%q",
			SigAnnSignerAppID, got, ref.Signer.AppID)
	}
	if got := sigAnnotations[SigAnnSignerNodeID]; got != ref.Signer.NodeID {
		return fmt.Errorf("sig annotation %s=%q does not match GMSignature.signer.nodeId=%q",
			SigAnnSignerNodeID, got, ref.Signer.NodeID)
	}
	if ref.Signer.UserID != "" {
		if got := sigAnnotations[SigAnnUserID]; got != ref.Signer.UserID {
			return fmt.Errorf("sig annotation %s=%q does not match GMSignature.signer.userId=%q",
				SigAnnUserID, got, ref.Signer.UserID)
		}
	}
	return nil
}
