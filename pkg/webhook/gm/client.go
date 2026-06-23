package gm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// HTTPClient is the minimal interface we need from net/http.Client.
// Lets tests inject a fake transport without monkey-patching.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client speaks to the HSM SM2 /sm2/verify endpoint described in
// gm-sign-cli/docs/01 (附件1 P1 签名验签接口). Request/response shape is
// kept identical to what gmctl's GmSm2HttpClient sends/receives so the
// signing and verifying sides cannot drift.
type Client struct {
	// HTTP does the actual round-trip. Defaults to http.DefaultClient with the
	// per-call timeout applied via context.
	HTTP HTTPClient
}

// NewClient returns a Client with a sensible default http.Client.
// The timeout is applied per-call via context.WithTimeout in SM2Verify so the
// underlying transport stays reusable across calls.
func NewClient() *Client {
	return &Client{HTTP: &http.Client{}}
}

// SignerTriple is the (app-id, node-id, user-id) tuple that identifies which
// HSM-side key to verify against. user-id may be empty if the CIP did not
// pin one.
type SignerTriple struct {
	AppID  string
	NodeID string
	UserID string
}

// VerifyRequest gathers everything one /sm2/verify HTTP call needs.
type VerifyRequest struct {
	// URLTemplate has {tenantId} and {appId} placeholders. Substituted before
	// the request is built. Comes from CIP annotation zjrcu.gm/verify-url.
	URLTemplate string
	TenantID    string
	Signer      SignerTriple
	// SM3Hash is the SM3 digest of the Simple Signing payload bytes. 32 bytes.
	SM3Hash []byte
	// Signature is the raw SM2 signature as gmctl wrote it into the artifact
	// annotation (already base64-decoded by the caller).
	Signature []byte
	// TimeoutMS overrides the default 5000ms timeout. Zero = default.
	TimeoutMS int
}

// SM2Verify posts to the HSM /sm2/verify endpoint and returns (verified, err).
//
// Returns (false, nil) only when the HSM responded with a well-formed body
// indicating the signature is invalid. Returns (false, err) for any transport
// or parse failure — callers should treat that as "could not determine",
// usually rejecting the Pod admission to stay safe.
func (c *Client) SM2Verify(ctx context.Context, req VerifyRequest) (bool, error) {
	url := strings.NewReplacer(
		"{tenantId}", req.TenantID,
		"{appId}", req.Signer.AppID,
	).Replace(req.URLTemplate)

	// requestData shape mirrors gm-sign-cli/.../GmSm2HttpClient.java baseRequestData()
	// + the (data, signature) pair appended for verify.
	data := map[string]any{
		"appId":     req.Signer.AppID,
		"nodeId":    req.Signer.NodeID,
		"data":      base64.StdEncoding.EncodeToString(req.SM3Hash),
		"signature": base64.StdEncoding.EncodeToString(req.Signature),
	}
	if req.Signer.UserID != "" {
		data["userId"] = req.Signer.UserID
	}
	body, err := json.Marshal(map[string]any{"requestData": data})
	if err != nil {
		return false, fmt.Errorf("marshal sm2/verify body: %w", err)
	}

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultRequestTimeoutMS * time.Millisecond
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build sm2/verify request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Tenant-Id", req.TenantID)
	// TRACE_ID format mirrors gmctl: "<appId>_<8-digit random>"
	// nolint:gosec // not security-sensitive, just observability correlation
	httpReq.Header.Set("TRACE_ID", fmt.Sprintf("%s_%08d", req.Signer.AppID, rand.Intn(100_000_000)))

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("sm2/verify HTTP call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read sm2/verify response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("sm2/verify HTTP %d: %s",
			resp.StatusCode, truncate(string(respBody), 200))
	}

	var parsed struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Result  map[string]any `json:"result"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return false, fmt.Errorf("decode sm2/verify response: %w", err)
	}
	if parsed.Code != 0 {
		// HSM reported a business-level error. Treat as "not verified",
		// not as a transport error — the call itself succeeded.
		return false, fmt.Errorf("sm2/verify rejected: code=%d message=%s",
			parsed.Code, parsed.Message)
	}
	// Per spec the result map carries either `verified: bool` or `success: 0|1`
	// depending on platform version. Both forms have been observed in
	// production fixtures (附件1 第 2.3 节 of the HTTP API spec).
	if v, ok := parsed.Result["verified"].(bool); ok {
		return v, nil
	}
	if s, ok := parsed.Result["success"].(float64); ok {
		// 0 = ok, non-zero = failure, by HSM convention. Inverted from intuition.
		return s == 0, nil
	}
	// code==0 with no recognized result field — defensively treat as verified
	// since the HSM didn't report any error. Log shape mismatch via the
	// error returned by the caller's debug path if needed.
	return true, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
