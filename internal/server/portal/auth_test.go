package portal_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/httpauth"

	"github.com/abagile/tokyo3-ca/internal/server/portal"
)

func TestBasicAuth_DisabledByDefault(t *testing.T) {
	p := newTestPortal(t)
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (auth disabled when unconfigured)", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want empty when disabled", got)
	}
}

func TestBasicAuth_RejectsMissingCreds(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			Password: "secret",
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, `Basic realm="restricted"`) {
		t.Errorf("WWW-Authenticate = %q, want default realm", challenge)
	}
}

func TestBasicAuth_RejectsWrongPassword(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			Password: "secret",
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("admin", "WRONG")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestBasicAuth_RejectsWrongUsername(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			Password: "secret",
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("attacker", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestBasicAuth_AcceptsCorrectCreds(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			Password: "secret",
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("admin", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestBasicAuth_HealthzExempt(t *testing.T) {
	// External watchdogs probe /healthz without sharing admin
	// credentials — the exemption keeps the deployment monitorable.
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			Password: "secret",
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200 even without auth", resp.StatusCode)
	}
}

func TestBasicAuth_PartialConfigDoesNotGate(t *testing.T) {
	// Operator misconfigures: only Username set. The gate must NOT
	// activate — better to fail open with a discoverable 200 than
	// silently lock everyone out with a credential nobody has.
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			// Password intentionally absent.
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (partial config = gate disabled)", resp.StatusCode)
	}
}

func TestBasicAuth_CustomRealm(t *testing.T) {
	p, _ := portal.New(portal.Config{
		Version: "v",
		Now:     time.Now,
		BasicAuth: httpauth.BasicAuthConfig{
			Username: "admin",
			Password: "secret",
			Realm:    "certd-prod-east",
		},
	})
	srv := httptest.NewServer(p.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `realm="certd-prod-east"`) {
		t.Errorf("WWW-Authenticate = %q, want custom realm", got)
	}
}
