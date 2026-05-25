package mtls_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/mtls"
)

// makeCert builds a self-signed leaf cert with the requested URI and
// email SANs. Suitable for use as a peer cert in r.TLS.
func makeCert(t *testing.T, uris []string, emails []string) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "test"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: emails,
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse uri %q: %v", u, err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func reqWithCerts(certs ...*x509.Certificate) *http.Request {
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: certs}}
	return r
}

// ── ExtractSANs ───────────────────────────────────────────────────────────────

func TestExtractSANs_URIsAndEmails(t *testing.T) {
	cert := makeCert(t,
		[]string{"spiffe://corp/host/db-1", "spiffe://corp/host/db-1-alias"},
		[]string{"ops@corp.com"},
	)
	r := reqWithCerts(cert)

	got := mtls.ExtractSANs(r)
	want := []string{
		"spiffe://corp/host/db-1",
		"spiffe://corp/host/db-1-alias",
		"ops@corp.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("ExtractSANs = %v, want %v", got, want)
	}
}

func TestExtractSANs_NoTLS(t *testing.T) {
	r := &http.Request{}
	if got := mtls.ExtractSANs(r); got != nil {
		t.Errorf("ExtractSANs(no TLS) = %v, want nil", got)
	}
}

func TestExtractSANs_NoPeerCerts(t *testing.T) {
	r := &http.Request{TLS: &tls.ConnectionState{}}
	if got := mtls.ExtractSANs(r); got != nil {
		t.Errorf("ExtractSANs(no peer certs) = %v, want nil", got)
	}
}

func TestExtractSANs_OnlyLeafConsidered(t *testing.T) {
	leaf := makeCert(t, []string{"spiffe://corp/leaf"}, nil)
	intermediate := makeCert(t, []string{"spiffe://corp/intermediate-should-be-ignored"}, nil)
	r := reqWithCerts(leaf, intermediate)

	got := mtls.ExtractSANs(r)
	if !slices.Equal(got, []string{"spiffe://corp/leaf"}) {
		t.Errorf("intermediate SAN leaked: got %v", got)
	}
}

func TestExtractSANs_NilRequest(t *testing.T) {
	if got := mtls.ExtractSANs(nil); got != nil {
		t.Errorf("ExtractSANs(nil) = %v, want nil", got)
	}
}

// ── InMemoryStore.Lookup ──────────────────────────────────────────────────────

func TestInMemoryStore_LookupSpiffeURI(t *testing.T) {
	store := mtls.NewInMemoryStore(
		mtls.Principal{
			Name:       "ssh-proxyd-prod",
			MatchedSAN: "spiffe://corp/svc/ssh-proxyd",
			Groups:     []string{"ssh-proxy-service"},
		},
	)

	p, err := store.Lookup([]string{"spiffe://corp/svc/ssh-proxyd"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if p.Name != "ssh-proxyd-prod" {
		t.Errorf("Name = %q", p.Name)
	}
	if !slices.Equal(p.Groups, []string{"ssh-proxy-service"}) {
		t.Errorf("Groups = %v", p.Groups)
	}
	if p.MatchedSAN != "spiffe://corp/svc/ssh-proxyd" {
		t.Errorf("MatchedSAN = %q (should reflect which SAN matched)", p.MatchedSAN)
	}
}

func TestInMemoryStore_LookupEmail(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name:       "ops-bot",
		MatchedSAN: "ops@corp.com",
		Groups:     []string{"ops"},
	})
	p, err := store.Lookup([]string{"ops@corp.com"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if p.Name != "ops-bot" {
		t.Errorf("Name = %q", p.Name)
	}
}

func TestInMemoryStore_LookupFirstMatchWins(t *testing.T) {
	// Two registered principals; cert presents SANs for both — first
	// presented wins (callers control SAN order via ExtractSANs).
	store := mtls.NewInMemoryStore(
		mtls.Principal{Name: "p1", MatchedSAN: "spiffe://corp/a", Groups: []string{"g1"}},
		mtls.Principal{Name: "p2", MatchedSAN: "spiffe://corp/b", Groups: []string{"g2"}},
	)
	p, err := store.Lookup([]string{"spiffe://corp/b", "spiffe://corp/a"})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if p.Name != "p2" {
		t.Errorf("Name = %q, want p2 (first presented SAN)", p.Name)
	}
}

func TestInMemoryStore_LookupUnknownPrincipal(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name: "p1", MatchedSAN: "spiffe://corp/a", Groups: []string{"g1"},
	})
	_, err := store.Lookup([]string{"spiffe://stranger/x"})
	if !errors.Is(err, mtls.ErrUnknownPrincipal) {
		t.Errorf("err = %v, want ErrUnknownPrincipal", err)
	}
	if !strings.Contains(err.Error(), "spiffe://stranger/x") {
		t.Errorf("err = %q, should list the presented SANs", err)
	}
}

func TestInMemoryStore_LookupEmptySANs(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name: "p1", MatchedSAN: "spiffe://corp/a", Groups: []string{"g1"},
	})
	_, err := store.Lookup(nil)
	if !errors.Is(err, mtls.ErrNoClientCert) {
		t.Errorf("err = %v, want ErrNoClientCert", err)
	}
}

func TestInMemoryStore_ReplaceAll(t *testing.T) {
	store := mtls.NewInMemoryStore(mtls.Principal{
		Name: "old", MatchedSAN: "spiffe://corp/a", Groups: []string{"g"},
	})

	store.ReplaceAll([]mtls.Principal{{
		Name: "new", MatchedSAN: "spiffe://corp/b", Groups: []string{"g2"},
	}})

	// Old SAN no longer matches.
	if _, err := store.Lookup([]string{"spiffe://corp/a"}); !errors.Is(err, mtls.ErrUnknownPrincipal) {
		t.Errorf("old SAN: err = %v, want ErrUnknownPrincipal after ReplaceAll", err)
	}
	p, err := store.Lookup([]string{"spiffe://corp/b"})
	if err != nil {
		t.Fatalf("new SAN: %v", err)
	}
	if p.Name != "new" {
		t.Errorf("Name = %q, want new", p.Name)
	}
}

func TestInMemoryStore_IgnoresEntriesWithoutMatchedSAN(t *testing.T) {
	// A Principal without MatchedSAN cannot be registered — it has no
	// key. Ensure it's silently dropped rather than panicking.
	store := mtls.NewInMemoryStore(
		mtls.Principal{Name: "good", MatchedSAN: "spiffe://corp/g", Groups: []string{"g"}},
		mtls.Principal{Name: "no-key", Groups: []string{"g"}}, // dropped
	)
	if _, err := store.Lookup([]string{"spiffe://corp/g"}); err != nil {
		t.Errorf("good entry not registered: %v", err)
	}
}

func TestInMemoryStore_All_ReturnsEveryRegisteredPrincipal(t *testing.T) {
	entries := []mtls.Principal{
		{Name: "ssh-proxyd", MatchedSAN: "spiffe://corp/svc/ssh-proxyd", Groups: []string{"ssh-proxy-service"}},
		{Name: "ops-bot", MatchedSAN: "ops@corp.com", Groups: []string{"ops"}},
	}
	store := mtls.NewInMemoryStore(entries...)

	got := store.All()
	if len(got) != 2 {
		t.Fatalf("All() len = %d, want 2", len(got))
	}
	// Build a quick name → MatchedSAN map for assertion regardless of order.
	bySAN := map[string]mtls.Principal{}
	for _, p := range got {
		bySAN[p.MatchedSAN] = p
	}
	for _, want := range entries {
		got, ok := bySAN[want.MatchedSAN]
		if !ok {
			t.Errorf("All() missing entry %q", want.MatchedSAN)
			continue
		}
		if got.Name != want.Name {
			t.Errorf("Name = %q, want %q", got.Name, want.Name)
		}
	}
}

func TestInMemoryStore_All_EmptyStore(t *testing.T) {
	store := mtls.NewInMemoryStore()
	if got := store.All(); len(got) != 0 {
		t.Errorf("All() = %v, want empty", got)
	}
}
