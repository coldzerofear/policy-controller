package gm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeHSM is a minimal in-memory HSM that lets each test decide what response
// shape to send back. It also captures the most recent request so tests can
// assert on the request body / headers / URL we sent.
type fakeHSM struct {
	t              *testing.T
	srv            *httptest.Server
	lastBody       map[string]any
	lastTraceID    string
	lastTenantHdr  string
	lastURL        string
	responseStatus int
	responseJSON   string
}

func newFakeHSM(t *testing.T) *fakeHSM {
	f := &fakeHSM{t: t, responseStatus: 200, responseJSON: `{"code":0,"message":"OK","result":{"verified":true}}`}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastTraceID = r.Header.Get("TRACE_ID")
		f.lastTenantHdr = r.Header.Get("Tenant-Id")
		f.lastURL = r.URL.String()
		body, _ := io.ReadAll(r.Body)
		var parsed struct {
			RequestData map[string]any `json:"requestData"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Errorf("HSM mock got malformed JSON: %v body=%s", err, body)
		}
		f.lastBody = parsed.RequestData
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.responseStatus)
		_, _ = io.WriteString(w, f.responseJSON)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestSM2Verify_HappyPath(t *testing.T) {
	hsm := newFakeHSM(t)
	c := &Client{HTTP: &http.Client{}}

	ok, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hsm.srv.URL + "/fc-api/v3.0/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1", UserID: "u1"},
		SM3Hash:     []byte("32-byte-sm3-hash-stand-in-aaaaaa"),
		Signature:   []byte("a fake sm2 sig"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected verified=true")
	}

	// URL placeholder substitution
	if !strings.Contains(hsm.lastURL, "/t1/app1/sm2/verify") {
		t.Errorf("URL substitution wrong: %s", hsm.lastURL)
	}
	// Tenant-Id header set
	if hsm.lastTenantHdr != "t1" {
		t.Errorf("Tenant-Id header = %q, want t1", hsm.lastTenantHdr)
	}
	// TRACE_ID format: <appId>_<8-digit>
	if !strings.HasPrefix(hsm.lastTraceID, "app1_") {
		t.Errorf("TRACE_ID = %q, want prefix app1_", hsm.lastTraceID)
	}
	// requestData has the right fields
	if hsm.lastBody["appId"] != "app1" || hsm.lastBody["nodeId"] != "node1" ||
		hsm.lastBody["userId"] != "u1" {
		t.Errorf("requestData fields wrong: %+v", hsm.lastBody)
	}
	// data + signature base64-encoded
	wantData := base64.StdEncoding.EncodeToString([]byte("32-byte-sm3-hash-stand-in-aaaaaa"))
	if hsm.lastBody["data"] != wantData {
		t.Errorf("data field = %v, want %v", hsm.lastBody["data"], wantData)
	}
	wantSig := base64.StdEncoding.EncodeToString([]byte("a fake sm2 sig"))
	if hsm.lastBody["signature"] != wantSig {
		t.Errorf("signature field = %v, want %v", hsm.lastBody["signature"], wantSig)
	}
}

func TestSM2Verify_OmitsBlankUserID(t *testing.T) {
	hsm := newFakeHSM(t)
	c := &Client{HTTP: &http.Client{}}
	_, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hsm.srv.URL + "/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1"}, // UserID blank
		SM3Hash:     []byte("hash"),
		Signature:   []byte("sig"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := hsm.lastBody["userId"]; present {
		t.Errorf("blank UserID should be omitted from requestData, got: %+v", hsm.lastBody)
	}
}

func TestSM2Verify_VerifiedFalseShape(t *testing.T) {
	hsm := newFakeHSM(t)
	hsm.responseJSON = `{"code":0,"message":"OK","result":{"verified":false}}`
	c := &Client{HTTP: &http.Client{}}
	ok, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hsm.srv.URL + "/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1"},
		SM3Hash:     []byte("hash"),
		Signature:   []byte("sig"),
	})
	if err != nil {
		t.Errorf("transport-level err should be nil for well-formed not-verified response, got %v", err)
	}
	if ok {
		t.Error("expected verified=false")
	}
}

func TestSM2Verify_SuccessFieldShape(t *testing.T) {
	hsm := newFakeHSM(t)
	// Some platform versions return `success: 0` instead of `verified: bool`.
	// 0 means OK in HSM convention (counterintuitive but documented in 附件1).
	hsm.responseJSON = `{"code":0,"message":"OK","result":{"success":0}}`
	c := &Client{HTTP: &http.Client{}}
	ok, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hsm.srv.URL + "/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1"},
		SM3Hash:     []byte("h"),
		Signature:   []byte("s"),
	})
	if err != nil || !ok {
		t.Errorf("success=0 should map to verified, got ok=%v err=%v", ok, err)
	}
}

func TestSM2Verify_HSMBusinessError(t *testing.T) {
	hsm := newFakeHSM(t)
	hsm.responseJSON = `{"code":-1,"message":"key not found","result":null}`
	c := &Client{HTTP: &http.Client{}}
	ok, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hsm.srv.URL + "/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1"},
		SM3Hash:     []byte("h"),
		Signature:   []byte("s"),
	})
	if err == nil || ok {
		t.Errorf("HSM code != 0 should return (false, err), got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(err.Error(), "key not found") {
		t.Errorf("error should include HSM message, got %v", err)
	}
}

func TestSM2Verify_HTTPNon200(t *testing.T) {
	hsm := newFakeHSM(t)
	hsm.responseStatus = 503
	hsm.responseJSON = "Service Unavailable"
	c := &Client{HTTP: &http.Client{}}
	ok, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hsm.srv.URL + "/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1"},
		SM3Hash:     []byte("h"),
		Signature:   []byte("s"),
	})
	if err == nil || ok {
		t.Errorf("HTTP 5xx should return (false, err), got ok=%v err=%v", ok, err)
	}
}

func TestSM2Verify_ContextTimeout(t *testing.T) {
	// Server that sleeps longer than the client timeout. Using a fixed
	// sleep instead of <-r.Context().Done() because Go's net/http server
	// doesn't propagate client-side connection close to r.Context() across
	// all platforms reliably, which can leave the handler goroutine hung
	// even after the client has timed out and moved on.
	hangSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer hangSrv.Close()

	c := &Client{HTTP: &http.Client{}}
	start := time.Now()
	_, err := c.SM2Verify(context.Background(), VerifyRequest{
		URLTemplate: hangSrv.URL + "/{tenantId}/{appId}/sm2/verify",
		TenantID:    "t1",
		Signer:      SignerTriple{AppID: "app1", NodeID: "node1"},
		SM3Hash:     []byte("h"),
		Signature:   []byte("s"),
		TimeoutMS:   200,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Error("expected timeout error")
	}
	if elapsed > 1*time.Second {
		t.Errorf("call took %v, expected ~200ms (TimeoutMS)", elapsed)
	}
}
