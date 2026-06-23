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
	"knative.dev/pkg/logging"
)

// Verify is the GM entry point that mirrors the shape of validation.valid()'s
// return contract: it returns the subset of signatures that verified.
//
// Flow:
//  1. Fetch all signatures attached to ref via cosign's SDK (Referrers +
//     tag-based fallback, the same discovery upstream uses).
//  2. For each signature:
//     a. Pre-gate: the sig's annotations must declare zjrcu.gm/alg = SM2-with-SM3
//        and match the CIP's expected signer triple (rejects unauthorized
//        signers before any HSM call).
//     b. Read the SM2 signature (prefer zjrcu.gm/signature annotation, fall
//        back to the cosign-standard base64 sig — both are written by gmctl).
//     c. Replay-check: cosign's SimpleClaimVerifier ensures the payload's
//        critical.image.docker-manifest-digest equals the image digest. We
//        let cosign do that piece via SimpleClaimVerifier later, OR we can
//        inline it. For PoC we inline it as cosign's verifier needs the
//        ECDSA key it doesn't have.
//     d. SM3-hash the payload bytes, call HSM /sm2/verify.
//  3. Return all signatures that passed (b) (c) (d).
//
// Returns an error only when no sig verified AND every sig produced an error
// — partial verify (any one sig OK) is treated as success.
func Verify(
	ctx context.Context,
	ref name.Reference,
	cipAnnotations map[string]string,
	checkOpts *cosign.CheckOpts,
) ([]oci.Signature, error) {
	logger := logging.FromContext(ctx)

	client := ClientFromContext(ctx)
	if client == nil {
		return nil, fmt.Errorf("GM verifier requested by CIP but HSM Client not initialized; " +
			"check that cmd/webhook/main.go calls gm.WithClient on startup")
	}

	cfg, err := ParseCIPAnnotations(cipAnnotations)
	if err != nil {
		return nil, fmt.Errorf("GM CIP misconfigured: %w", err)
	}

	sigs, err := fetchSignatures(ref, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("fetch signatures for %s: %w", ref.Name(), err)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no signatures found for %s", ref.Name())
	}

	imageDigest := digestString(ref)
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
		if err := cfg.MatchSigner(annotations); err != nil {
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

		// (d) SM3 + HSM verify
		sm3Hash := SM3(payload)
		ok, err := client.SM2Verify(ctx, VerifyRequest{
			URLTemplate: cfg.URLTemplate,
			TenantID:    cfg.TenantID,
			Signer:      cfg.ExpectedSigner,
			SM3Hash:     sm3Hash,
			Signature:   sigBytes,
			TimeoutMS:   cfg.RequestTimeoutMS,
		})
		if err != nil {
			lastErr = fmt.Errorf("sig[%d] HSM call: %w", i, err)
			logger.Debug(lastErr.Error())
			continue
		}
		if !ok {
			lastErr = fmt.Errorf("sig[%d] HSM returned not-verified", i)
			logger.Debug(lastErr.Error())
			continue
		}

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
// or "" when it's a tag-form reference (the policy-controller flow guarantees
// digest form by the time we get here, but be defensive).
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
