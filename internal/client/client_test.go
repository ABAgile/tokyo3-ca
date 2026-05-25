package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/client"
)

// mockCertd stands in for certd: it accepts POST against the X.509
// or SSH user-cert sign endpoints, captures the request body for
// assertions, and returns a canned response. Tests typically hit
// only one endpoint per test, so a single response slot covers both
// paths.
type mockCertd struct {
	server *httptest.Server

	gotReq     client.SignWorkloadRequest
	gotUserReq client.SignUserRequest
	respCode   int
	respBody   []byte
	respDelay  time.Duration
}

func newMockCertd(t *testing.T) *mockCertd {
	t.Helper()
	m := &mockCertd{respCode: http.StatusOK}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/v1/x509/sign-workload":
			if err := json.NewDecoder(r.Body).Decode(&m.gotReq); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "/api/v1/ssh/sign-user":
			if err := json.NewDecoder(r.Body).Decode(&m.gotUserReq); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		if m.respDelay > 0 {
			time.Sleep(m.respDelay)
		}
		w.WriteHeader(m.respCode)
		_, _ = w.Write(m.respBody)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockCertd) respond(t *testing.T, status int, body any) {
	t.Helper()
	m.respCode = status
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal mock response: %v", err)
	}
	m.respBody = b
}

func TestNewClient_RejectsEmptyBaseURL(t *testing.T) {
	_, err := client.NewClient("", nil)
	if err == nil || !strings.Contains(err.Error(), "baseURL is required") {
		t.Errorf("err = %v, want 'baseURL is required'", err)
	}
}

func TestClient_SignWorkloadCert_HappyPath(t *testing.T) {
	m := newMockCertd(t)
	now := time.Date(2026, 5, 25, 13, 0, 0, 0, time.UTC)
	m.respond(t, http.StatusOK, client.SignWorkloadResponse{
		Certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		Serial:      "12345678901234567890",
		SPIFFEURI:   "spiffe://tokyo3.example/host/db-1",
		ValidAfter:  now,
		ValidBefore: now.Add(7 * 24 * time.Hour),
	})

	c, err := client.NewClient(m.server.URL, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req := client.SignWorkloadRequest{
		PublicKey:         "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n",
		SPIFFEURI:         "spiffe://tokyo3.example/host/db-1",
		SubjectCommonName: "db-1.prod",
		TTLSeconds:        24 * 3600,
	}
	resp, err := c.SignWorkloadCert(context.Background(), req)
	if err != nil {
		t.Fatalf("SignWorkloadCert: %v", err)
	}
	if resp.Serial != "12345678901234567890" {
		t.Errorf("Serial = %q", resp.Serial)
	}
	if resp.SPIFFEURI != "spiffe://tokyo3.example/host/db-1" {
		t.Errorf("SPIFFEURI = %q", resp.SPIFFEURI)
	}
	if !strings.HasPrefix(resp.Certificate, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("Certificate = %q", resp.Certificate)
	}

	// Request body that hit certd matches what we sent.
	if m.gotReq.SPIFFEURI != req.SPIFFEURI {
		t.Errorf("server saw SPIFFEURI = %q, want %q", m.gotReq.SPIFFEURI, req.SPIFFEURI)
	}
	if m.gotReq.TTLSeconds != 24*3600 {
		t.Errorf("server saw TTL = %d, want %d", m.gotReq.TTLSeconds, 24*3600)
	}
	if m.gotReq.SubjectCommonName != "db-1.prod" {
		t.Errorf("server saw CN = %q, want db-1.prod", m.gotReq.SubjectCommonName)
	}
}

func TestClient_SignWorkloadCert_PropagatesUpstreamError(t *testing.T) {
	m := newMockCertd(t)
	m.respond(t, http.StatusForbidden, map[string]string{
		"error": "no role matches the caller's groups",
	})

	c, _ := client.NewClient(m.server.URL, nil)
	_, err := c.SignWorkloadCert(context.Background(), client.SignWorkloadRequest{
		PublicKey: "x", SPIFFEURI: "spiffe://td/x",
	})
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "no role matches") {
		t.Errorf("error should surface status+body: %v", err)
	}
}

func TestClient_SignWorkloadCert_RespectsContextCancellation(t *testing.T) {
	m := newMockCertd(t)
	m.respDelay = 200 * time.Millisecond
	m.respond(t, http.StatusOK, client.SignWorkloadResponse{Serial: "1"})

	c, _ := client.NewClient(m.server.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := c.SignWorkloadCert(ctx, client.SignWorkloadRequest{
		PublicKey: "x", SPIFFEURI: "spiffe://td/x",
	})
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error should mention context/deadline: %v", err)
	}
}

func TestClient_SignWorkloadCert_RejectsMalformedResponse(t *testing.T) {
	m := newMockCertd(t)
	m.respCode = http.StatusOK
	m.respBody = []byte("not json")

	c, _ := client.NewClient(m.server.URL, nil)
	_, err := c.SignWorkloadCert(context.Background(), client.SignWorkloadRequest{
		PublicKey: "x", SPIFFEURI: "spiffe://td/x",
	})
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got %v", err)
	}
}

func TestClient_SignUserCert_HappyPath(t *testing.T) {
	m := newMockCertd(t)
	now := time.Date(2026, 5, 26, 13, 0, 0, 0, time.UTC)
	m.respond(t, http.StatusOK, client.SignUserResponse{
		Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA...",
		Serial:      77,
		KeyID:       "user:alice@example.com",
		Principals:  []string{"alice", "deployer"},
		ValidAfter:  now,
		ValidBefore: now.Add(5 * time.Minute),
	})

	c, _ := client.NewClient(m.server.URL, nil)
	req := client.SignUserRequest{
		PublicKey:  "ssh-ed25519 AAAA...",
		KeyID:      "user:alice@example.com",
		Principals: []string{"alice", "deployer"},
		TTLSeconds: 300,
		Extensions: map[string]string{"permit-pty": ""},
	}
	resp, err := c.SignUserCert(context.Background(), req)
	if err != nil {
		t.Fatalf("SignUserCert: %v", err)
	}
	if resp.Serial != 77 {
		t.Errorf("Serial = %d, want 77", resp.Serial)
	}
	if !strings.HasPrefix(resp.Certificate, "ssh-ed25519-cert-v01@openssh.com") {
		t.Errorf("Certificate = %q", resp.Certificate)
	}
	if m.gotUserReq.KeyID != req.KeyID {
		t.Errorf("server saw KeyID = %q, want %q", m.gotUserReq.KeyID, req.KeyID)
	}
	if got := m.gotUserReq.Principals; len(got) != 2 || got[0] != "alice" {
		t.Errorf("server saw principals = %v", got)
	}
	if m.gotUserReq.TTLSeconds != 300 {
		t.Errorf("server saw TTL = %d, want 300", m.gotUserReq.TTLSeconds)
	}
	if m.gotUserReq.Extensions["permit-pty"] != "" {
		t.Errorf("server saw Extensions = %v", m.gotUserReq.Extensions)
	}
}

func TestClient_SignUserCert_PropagatesUpstreamError(t *testing.T) {
	m := newMockCertd(t)
	m.respond(t, http.StatusForbidden, map[string]string{
		"error": "principals denied by role",
	})

	c, _ := client.NewClient(m.server.URL, nil)
	_, err := c.SignUserCert(context.Background(), client.SignUserRequest{
		PublicKey: "x", KeyID: "user:x", Principals: []string{"alice"},
	})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "principals denied") {
		t.Errorf("err = %v", err)
	}
}

func TestClient_SignUserCert_RespectsContextCancellation(t *testing.T) {
	m := newMockCertd(t)
	m.respDelay = 200 * time.Millisecond
	m.respond(t, http.StatusOK, client.SignUserResponse{Serial: 1})

	c, _ := client.NewClient(m.server.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.SignUserCert(ctx, client.SignUserRequest{
		PublicKey: "x", KeyID: "user:x", Principals: []string{"alice"},
	})
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error should mention context/deadline: %v", err)
	}
}
