package gm

import "testing"

func TestIsGmCIP(t *testing.T) {
	cases := map[string]struct {
		annotations map[string]string
		want        bool
	}{
		"nil map -> false (default cosign path untouched)": {
			annotations: nil, want: false,
		},
		"empty map -> false": {
			annotations: map[string]string{}, want: false,
		},
		"correct algorithm -> true": {
			annotations: map[string]string{AnnAlgorithm: AlgorithmSM2SM3}, want: true,
		},
		"different algorithm name -> false (no fuzzy match)": {
			annotations: map[string]string{AnnAlgorithm: "sm2-sm3"}, want: false,
		},
		"algorithm key present but empty -> false": {
			annotations: map[string]string{AnnAlgorithm: ""}, want: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := IsGmCIP(tc.annotations); got != tc.want {
				t.Errorf("IsGmCIP(%v) = %v, want %v", tc.annotations, got, tc.want)
			}
		})
	}
}

func TestParseCIPAnnotations(t *testing.T) {
	ok := map[string]string{
		AnnAlgorithm: AlgorithmSM2SM3,
		AnnVerifyURL: "http://hsm/{tenantId}/{appId}/sm2/verify",
		AnnTenantID:  "t1",
		AnnAppID:     "app1",
		AnnNodeID:    "node1",
	}

	t.Run("required fields parse OK", func(t *testing.T) {
		cfg, err := ParseCIPAnnotations(ok)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.TenantID != "t1" || cfg.ExpectedSigner.AppID != "app1" ||
			cfg.ExpectedSigner.NodeID != "node1" {
			t.Errorf("parsed cfg = %+v", cfg)
		}
		if cfg.ExpectedSigner.UserID != "" {
			t.Errorf("UserID should default empty, got %q", cfg.ExpectedSigner.UserID)
		}
		if cfg.RequestTimeoutMS != 0 {
			t.Errorf("RequestTimeoutMS should default 0 (uses client default), got %d", cfg.RequestTimeoutMS)
		}
	})

	t.Run("optional fields propagate", func(t *testing.T) {
		annotations := cloneMap(ok)
		annotations[AnnUserID] = "u1"
		annotations[AnnRequestTimeoutMS] = "3500"
		cfg, err := ParseCIPAnnotations(annotations)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ExpectedSigner.UserID != "u1" {
			t.Errorf("UserID = %q, want u1", cfg.ExpectedSigner.UserID)
		}
		if cfg.RequestTimeoutMS != 3500 {
			t.Errorf("RequestTimeoutMS = %d, want 3500", cfg.RequestTimeoutMS)
		}
	})

	t.Run("missing required field -> error", func(t *testing.T) {
		for _, missing := range []string{AnnVerifyURL, AnnTenantID, AnnAppID, AnnNodeID} {
			annotations := cloneMap(ok)
			delete(annotations, missing)
			if _, err := ParseCIPAnnotations(annotations); err == nil {
				t.Errorf("expected error when %s missing", missing)
			}
		}
	})

	t.Run("non-GM CIP -> error (caller should have checked IsGmCIP first)", func(t *testing.T) {
		annotations := map[string]string{AnnAlgorithm: "ecdsa"}
		if _, err := ParseCIPAnnotations(annotations); err == nil {
			t.Error("expected error for non-GM CIP")
		}
	})

	t.Run("invalid timeout -> error", func(t *testing.T) {
		annotations := cloneMap(ok)
		annotations[AnnRequestTimeoutMS] = "not-a-number"
		if _, err := ParseCIPAnnotations(annotations); err == nil {
			t.Error("expected error for malformed timeout")
		}
		annotations[AnnRequestTimeoutMS] = "0"
		if _, err := ParseCIPAnnotations(annotations); err == nil {
			t.Error("expected error for non-positive timeout")
		}
	})
}

func TestMatchSigner(t *testing.T) {
	cfg := &CIPConfig{
		ExpectedSigner: SignerTriple{
			AppID:  "app1",
			NodeID: "node1",
			UserID: "u1",
		},
	}

	good := map[string]string{
		SigAnnAlg:          AlgorithmSM2SM3,
		SigAnnSignerAppID:  "app1",
		SigAnnSignerNodeID: "node1",
		SigAnnUserID:       "u1",
	}

	t.Run("matching triple -> nil", func(t *testing.T) {
		if err := cfg.MatchSigner(good); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("wrong algorithm -> error", func(t *testing.T) {
		bad := cloneMap(good)
		bad[SigAnnAlg] = "ecdsa"
		if err := cfg.MatchSigner(bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("wrong app-id -> error", func(t *testing.T) {
		bad := cloneMap(good)
		bad[SigAnnSignerAppID] = "different-app"
		if err := cfg.MatchSigner(bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("wrong node-id -> error", func(t *testing.T) {
		bad := cloneMap(good)
		bad[SigAnnSignerNodeID] = "different-node"
		if err := cfg.MatchSigner(bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("CIP pins user-id, sig user-id differs -> error", func(t *testing.T) {
		bad := cloneMap(good)
		bad[SigAnnUserID] = "different-user"
		if err := cfg.MatchSigner(bad); err == nil {
			t.Error("expected mismatch error")
		}
	})

	t.Run("CIP doesn't pin user-id -> any sig user-id passes", func(t *testing.T) {
		cfgNoUser := &CIPConfig{
			ExpectedSigner: SignerTriple{AppID: "app1", NodeID: "node1"},
		}
		anyUser := cloneMap(good)
		anyUser[SigAnnUserID] = "anyone"
		if err := cfgNoUser.MatchSigner(anyUser); err != nil {
			t.Errorf("expected nil when CIP user-id unset, got %v", err)
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
