package gm

import (
	"testing"

	webhookcip "github.com/sigstore/policy-controller/pkg/webhook/clusterimagepolicy"
)

func TestValidate(t *testing.T) {
	good := &webhookcip.GMSignatureRef{
		VerifyURL: "http://hsm/{tenantId}/{appId}/sm2/verify",
		TenantID:  "t1",
		Signer:    webhookcip.GMSignerRef{AppID: "app1", NodeID: "node1"},
	}

	t.Run("complete config -> nil", func(t *testing.T) {
		if err := Validate(good); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil ref -> error", func(t *testing.T) {
		if err := Validate(nil); err == nil {
			t.Error("expected error for nil ref")
		}
	})

	t.Run("missing VerifyURL -> error", func(t *testing.T) {
		ref := *good
		ref.VerifyURL = ""
		if err := Validate(&ref); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing TenantID -> error", func(t *testing.T) {
		ref := *good
		ref.TenantID = ""
		if err := Validate(&ref); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing Signer.AppID -> error", func(t *testing.T) {
		ref := *good
		ref.Signer.AppID = ""
		if err := Validate(&ref); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing Signer.NodeID -> error", func(t *testing.T) {
		ref := *good
		ref.Signer.NodeID = ""
		if err := Validate(&ref); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Signer.UserID unset is OK (optional pin)", func(t *testing.T) {
		ref := *good
		ref.Signer.UserID = ""
		if err := Validate(&ref); err != nil {
			t.Errorf("UserID should be optional: %v", err)
		}
	})
}

func TestMatchSigner(t *testing.T) {
	cipPinnedUser := &webhookcip.GMSignatureRef{
		Signer: webhookcip.GMSignerRef{AppID: "app1", NodeID: "node1", UserID: "u1"},
	}
	cipNoUser := &webhookcip.GMSignatureRef{
		Signer: webhookcip.GMSignerRef{AppID: "app1", NodeID: "node1"},
	}

	goodSig := map[string]string{
		SigAnnAlg:          AlgorithmSM2SM3,
		SigAnnSignerAppID:  "app1",
		SigAnnSignerNodeID: "node1",
		SigAnnUserID:       "u1",
	}

	t.Run("matching triple -> nil", func(t *testing.T) {
		if err := MatchSigner(cipPinnedUser, goodSig); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("wrong algorithm -> reject (sig misrouted)", func(t *testing.T) {
		bad := cloneMap(goodSig)
		bad[SigAnnAlg] = "ecdsa"
		if err := MatchSigner(cipPinnedUser, bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("missing algorithm annotation -> reject", func(t *testing.T) {
		bad := cloneMap(goodSig)
		delete(bad, SigAnnAlg)
		if err := MatchSigner(cipPinnedUser, bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("wrong app-id -> reject (pre-HSM gate)", func(t *testing.T) {
		bad := cloneMap(goodSig)
		bad[SigAnnSignerAppID] = "different-app"
		if err := MatchSigner(cipPinnedUser, bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("wrong node-id -> reject", func(t *testing.T) {
		bad := cloneMap(goodSig)
		bad[SigAnnSignerNodeID] = "different-node"
		if err := MatchSigner(cipPinnedUser, bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("CIP pins user-id, sig user-id differs -> reject", func(t *testing.T) {
		bad := cloneMap(goodSig)
		bad[SigAnnUserID] = "different-user"
		if err := MatchSigner(cipPinnedUser, bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("CIP unpinned user-id, any sig user-id passes", func(t *testing.T) {
		anyUser := cloneMap(goodSig)
		anyUser[SigAnnUserID] = "anyone"
		if err := MatchSigner(cipNoUser, anyUser); err != nil {
			t.Errorf("unpinned user-id should accept anything: %v", err)
		}
	})

	t.Run("CIP unpinned user-id, sig also missing user-id passes", func(t *testing.T) {
		noUserSig := cloneMap(goodSig)
		delete(noUserSig, SigAnnUserID)
		if err := MatchSigner(cipNoUser, noUserSig); err != nil {
			t.Errorf("both unpinned should match: %v", err)
		}
	})
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
