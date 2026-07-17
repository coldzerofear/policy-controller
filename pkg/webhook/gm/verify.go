package gm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
	"knative.dev/pkg/logging"
)

// Verify is the GM entry point called from ValidatePolicySignaturesForAuthority
// when `authority.GMSignature != nil`. Returns the subset of signatures that
// verified — mirroring the contract of validation.valid() / cosign.VerifyImageSignatures.
//
// Flow:
//  1. Fetch all signatures attached to ref via cosign's SDK (Referrers +
//     tag-based fallback, the same discovery upstream uses).
//  2. For each signature:
//     a. Pre-gate: the sig's annotations must declare zjrcu.gm/alg = SM2-with-SM3
//        and match the CIP's expected signer triple. Rejects unauthorized
//        signers before any HSM round-trip.
//     b. Read the SM2 signature bytes (prefer the zjrcu.gm/signature annotation,
//        fall back to the cosign-standard base64 sig — both are written by gmctl).
//     c. Simple Signing replay check: payload's
//        critical.image.docker-manifest-digest must equal the image's digest.
//        Prevents a valid sig from image A being reused on image B.
//     d. Cache lookup before the HSM call (Phase 2 — bounded TTL LRU).
//     e. SM3-hash payload + POST (sm3Hash, sig, signer-triple) to HSM /sm2/verify.
//     f. On positive HSM result, populate the cache and record the sig as verified.
//  3. Return all signatures that survived all five steps. Any one survivor
//     verifies the image.
//
// Returns an error only when no sig verified AND every sig produced an error.
// Partial verify (any one sig OK) is treated as success.
func Verify(
	ctx context.Context,
	ref name.Reference,
	cipGM *webhookcip.GMSignatureRef,
	checkOpts *cosign.CheckOpts,
) ([]oci.Signature, error) {
	logger := logging.FromContext(ctx)

	if err := Validate(cipGM); err != nil {
		return nil, fmt.Errorf("CIP misconfigured: %w", err)
	}

	client := ClientFromContext(ctx)
	if client == nil {
		// This should be impossible in a correctly-built webhook binary: main.go
		// stamps gm.WithClient on the root ctx, and both admission controllers'
		// withContext closures re-inject it into the per-request ctx (see fix
		// commit 5ae181f1). If you see this in production, it's a packaging or
		// deploy regression, NOT a CIP configuration issue.
		//
		// Likely causes (in order of probability):
		//   1. Webhook Deployment is running a pre-5ae181f1 image (rollout
		//      didn't complete, or an old image was pulled). Fix:
		//        kubectl -n cosign-system rollout restart deploy/webhook
		//        kubectl -n cosign-system rollout status deploy/webhook
		//   2. Custom admission controller was added but forgot to bridge
		//      gm.WithClient/WithCache in its withContext closure. See
		//      cmd/webhook/main.go NewValidatingAdmissionController for the pattern.
		//   3. Third-party middleware stripped the ctx values.
		//
		// Report at https://github.com/coldzerofear/policy-controller/issues
		// with the webhook image tag and controller-runtime version.
		return nil, fmt.Errorf("GM verifier: HSM Client missing from admission request context " +
			"(webhook packaging/deploy issue; try `kubectl -n cosign-system rollout restart deploy/webhook`)")
	}
	// cache is optional — nil means "no memoization, every call hits HSM"
	cache := CacheFromContext(ctx)

	sigs, err := fetchSignatures(ref, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("fetch signatures for %s: %w", ref.Name(), err)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signatures found for %s", ref.Name())
	}

	imageDigest := digestString(ref)
	expectedSigner := SignerTriple{
		AppID:  cipGM.Signer.AppID,
		NodeID: cipGM.Signer.NodeID,
		UserID: cipGM.Signer.UserID,
	}

	var verified []oci.Signature
	var lastErr error

	for i, sig := range sigs {
		annotations, err := sig.Annotations()
		if err != nil {
			lastErr = fmt.Errorf("sig[%d] read annotations: %w", i, err)
			logger.Debug(lastErr.Error())
			continue
		}
		// (a) gate on signer triple — fail-fast before any HSM call
		if err := MatchSigner(cipGM, annotations); err != nil {
			lastErr = fmt.Errorf("sig[%d] signer mismatch: %w", i, err)
			logger.Debug(lastErr.Error())
			continue
		}

		// (b) extract SM2 signature bytes
		sigB64 := annotations[SigAnnSignature]
		if sigB64 == "" {
			// fall back to the cosign-standard base64 signature accessor
			sigB64, err = sig.Base64Signature()
			if err != nil || sigB64 == "" {
				lastErr = fmt.Errorf("sig[%d] missing %s annotation and base64 sig", i, SigAnnSignature)
				logger.Debug(lastErr.Error())
				continue
			}
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			lastErr = fmt.Errorf("sig[%d] decode base64 signature: %w", i, err)
			logger.Debug(lastErr.Error())
			continue
		}

		// (c) read payload + replay check (Simple Signing critical.image.docker-manifest-digest)
		payload, err := sig.Payload()
		if err != nil {
			lastErr = fmt.Errorf("sig[%d] read payload: %w", i, err)
			logger.Debug(lastErr.Error())
			continue
		}
		if imageDigest != "" {
			if err := verifyClaim(payload, imageDigest); err != nil {
				lastErr = fmt.Errorf("sig[%d] claim verify: %w", i, err)
				logger.Debug(lastErr.Error())
				continue
			}
		}

		// (d) cache lookup before paying the HSM round-trip
		if cache.Lookup(sigBytes, expectedSigner) {
			verified = append(verified, sig)
			logger.Debugf("GM verify cache hit for %s sig[%d]", ref.Name(), i)
			continue
		}

		// (e) SM3 + HSM verify (cache miss path)
		sm3Hash := SM3(payload)
		ok, err := client.SM2Verify(ctx, VerifyRequest{
			URLTemplate: cipGM.VerifyURL,
			TenantID:    cipGM.TenantID,
			Signer:      expectedSigner,
			SM3Hash:     sm3Hash,
			Signature:   sigBytes,
			TimeoutMS:   cipGM.RequestTimeoutMs,
		})
		if err != nil {
			// Transport / 5xx / business error — DO NOT cache. A cached false
			// would mean a single HSM hiccup blocks legit admissions for the
			// full TTL window.
			lastErr = fmt.Errorf("sig[%d] HSM call: %w", i, err)
			logger.Debug(lastErr.Error())
			continue
		}
		if !ok {
			// Negative verify result — DO NOT cache. Reasoning above.
			lastErr = fmt.Errorf("sig[%d] HSM returned not-verified", i)
			logger.Debug(lastErr.Error())
			continue
		}

		// (f) only positive results are memoized
		cache.Store(sigBytes, expectedSigner)
		verified = append(verified, sig)
		logger.Debugf("GM verify passed for %s sig[%d]", ref.Name(), i)
	}

	if len(verified) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no GM signature verified for %s; last error: %w", ref.Name(), lastErr)
		}
		return nil, fmt.Errorf("no GM signature verified for %s", ref.Name())
	}
	return verified, nil
}

// fetchSignatures uses cosign's SDK to enumerate signatures for ref. cosign
// internally walks Referrers + tag-based fallback, so we get exactly the same
// discovery as the default ECDSA path.
func fetchSignatures(ref name.Reference, checkOpts *cosign.CheckOpts) ([]oci.Signature, error) {
	se, err := ociremote.SignedEntity(ref, checkOpts.RegistryClientOpts...)
	if err != nil {
		return nil, err
	}
	sigSet, err := se.Signatures()
	if err != nil {
		return nil, err
	}
	return sigSet.Get()
}

// digestString returns the digest portion of ref when it's a name.Digest,
// or "" when it's a tag-form reference. policy-controller's webhook flow
// guarantees digest form by the time we get here, but be defensive.
func digestString(ref name.Reference) string {
	if d, ok := ref.(name.Digest); ok {
		return d.DigestStr()
	}
	return ""
}

// verifyClaim enforces the cosign Simple Signing replay protection:
// payload.critical.image.docker-manifest-digest must equal the image's
// resolved digest. Without this, a valid sig from image A could be
// "replayed" against image B if both had been signed by the same key.
func verifyClaim(payload []byte, expectedDigest string) error {
	embedded, err := extractDockerManifestDigest(payload)
	if err != nil {
		return err
	}
	if embedded != expectedDigest {
		return fmt.Errorf("payload digest %s != image digest %s (possible replay)",
			embedded, expectedDigest)
	}
	return nil
}

// extractDockerManifestDigest pulls critical.image.docker-manifest-digest out
// of a Simple Signing payload. Kept minimal — full Simple Signing schema
// parsing would pull a dependency we don't need.
func extractDockerManifestDigest(payload []byte) (string, error) {
	var p struct {
		Critical struct {
			Image struct {
				DockerManifestDigest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("parse Simple Signing payload: %w", err)
	}
	if p.Critical.Image.DockerManifestDigest == "" {
		return "", fmt.Errorf("payload missing critical.image.docker-manifest-digest")
	}
	return p.Critical.Image.DockerManifestDigest, nil
}
