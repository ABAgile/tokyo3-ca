// Package x509engine builds and signs X.509v3 certificates carrying
// SPIFFE URI SANs — the workload-identity primitive certd issues for
// the platform's mTLS infrastructure. The same [signer.Signer] that
// signs SSH certs also signs X.509 here; one CA key, two cert formats.
//
// CRL publishing is deferred to a later slice; this package focuses
// on issuance.
package x509engine

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// SPIFFEURIScheme is the only URI scheme [WorkloadCertParams] accepts
// for SAN values; rejecting anything else up front catches accidental
// "https://" / "ssh://" / etc. before signing happens.
const SPIFFEURIScheme = "spiffe"

// WorkloadCertParams describes a single workload-cert signing request.
type WorkloadCertParams struct {
	// PublicKey is the workload's public key (RSA, ECDSA, or Ed25519).
	// Provided as a parsed [crypto.PublicKey]; the API layer parses it
	// out of PEM SubjectPublicKeyInfo before calling.
	PublicKey crypto.PublicKey
	// SPIFFEURI is the URI SAN embedded in the cert, in canonical
	// "spiffe://trust-domain/path" form. Required; rejected if the
	// scheme is anything other than [SPIFFEURIScheme].
	SPIFFEURI string
	// SubjectCommonName is the X.509 Subject CN. Optional and
	// generally redundant with the URI SAN — modern verifiers MUST
	// ignore CN as identity and consult only the URI SAN per
	// RFC 6125. We populate it for human-friendly tooling that still
	// shows CN.
	SubjectCommonName string
	// DNSNames are optional DNS SANs for TLS server identities.
	DNSNames []string
	// ValidAfter is the earliest moment the cert is valid (inclusive).
	ValidAfter time.Time
	// ValidBefore is the moment the cert expires (exclusive). Must be
	// strictly after ValidAfter.
	ValidBefore time.Time
	// Serial is the cert serial number; uniqueness across the CA is
	// the caller's responsibility, same as for SSH certs.
	Serial *big.Int
}

// SignWorkloadCert builds an X.509v3 cert per p, signs it with caSigner
// against caCert as the issuer, and returns the parsed certificate.
// Marshalling to PEM is the caller's job (the API handler base64s the
// DER bytes via [pem.Encode]).
//
// The resulting cert carries:
//   - One URI SAN (the SPIFFE URI)
//   - KeyUsage per the subject key's algorithm (see [keyUsageFor])
//   - ExtKeyUsage: clientAuth + serverAuth (workload mTLS is bidirectional)
//   - Subject CN if set, otherwise the SPIFFE URI string
func SignWorkloadCert(rnd io.Reader, caSigner signer.Signer, caCert *x509.Certificate, p WorkloadCertParams) (*x509.Certificate, error) {
	if err := validate(p, caCert); err != nil {
		return nil, err
	}

	uri, err := url.Parse(p.SPIFFEURI)
	if err != nil {
		return nil, fmt.Errorf("parse spiffe uri: %w", err)
	}

	cn := p.SubjectCommonName
	if cn == "" {
		cn = p.SPIFFEURI
	}

	tmpl := &x509.Certificate{
		SerialNumber:          p.Serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             p.ValidAfter,
		NotAfter:              p.ValidBefore,
		KeyUsage:              keyUsageFor(p.PublicKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              p.DNSNames,
		URIs:                  []*url.URL{uri},
	}

	return signTemplate(rnd, caSigner, caCert, p.PublicKey, tmpl)
}

// ServerCertParams describes a TLS *server*-cert signing request — the
// DNS/IP-SAN counterpart to [WorkloadCertParams]. `certd ca issue-server`
// uses it to mint listener certs (NATS, Postgres, …) whose clients verify the
// server by hostname; [SignWorkloadCert] can't, because a SPIFFE SVID carries
// only a URI SAN.
type ServerCertParams struct {
	// PublicKey is the server's public key (RSA, ECDSA, or Ed25519).
	PublicKey crypto.PublicKey
	// DNSNames / IPAddresses are the SANs clients match against. At least
	// one entry across the two is required.
	DNSNames    []string
	IPAddresses []net.IP
	// SPIFFEURI optionally also embeds the server's SPIFFE URI SAN (for
	// SPIFFE-aware peers); empty omits it. Validated as scheme "spiffe".
	SPIFFEURI string
	// SubjectCommonName is the X.509 Subject CN; defaults to the first DNS
	// name when empty.
	SubjectCommonName string
	// ValidAfter / ValidBefore bound validity; ValidBefore must be after.
	ValidAfter  time.Time
	ValidBefore time.Time
	// Serial is the cert serial (caller-unique, like the workload path).
	Serial *big.Int
}

// SignServerCert builds a TLS server cert per p (DNS/IP SANs, ExtKeyUsage
// serverAuth) and signs it with caSigner against caCert. Same one CA key as
// the workload + SSH paths; marshalling to PEM is the caller's job.
func SignServerCert(rnd io.Reader, caSigner signer.Signer, caCert *x509.Certificate, p ServerCertParams) (*x509.Certificate, error) {
	if err := validateServer(p, caCert); err != nil {
		return nil, err
	}
	var uris []*url.URL
	if p.SPIFFEURI != "" {
		uri, err := url.Parse(p.SPIFFEURI)
		if err != nil {
			return nil, fmt.Errorf("parse spiffe uri: %w", err)
		}
		uris = append(uris, uri)
	}
	cn := p.SubjectCommonName
	if cn == "" && len(p.DNSNames) > 0 {
		cn = p.DNSNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          p.Serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             p.ValidAfter,
		NotAfter:              p.ValidBefore,
		KeyUsage:              keyUsageFor(p.PublicKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              p.DNSNames,
		IPAddresses:           p.IPAddresses,
		URIs:                  uris,
	}
	return signTemplate(rnd, caSigner, caCert, p.PublicKey, tmpl)
}

// signTemplate signs tmpl against caCert with caSigner and re-parses the DER
// back to a *x509.Certificate. Shared by the workload + server leaf builders.
func signTemplate(rnd io.Reader, caSigner signer.Signer, caCert *x509.Certificate, pub crypto.PublicKey, tmpl *x509.Certificate) (*x509.Certificate, error) {
	// A leaf must never outlive its issuer: a chain only verifies while every
	// cert in it is inside its validity window, so clamp NotAfter to the
	// issuer's. With a long-lived issuer (a 10y root) this is a no-op; it
	// matters when the issuer is an intermediate nearing its own expiry — the
	// leaf is shortened rather than silently outliving the chain. validate()
	// already rejects an issuer that expires at/before NotBefore, so the clamp
	// can never invert the validity window.
	if tmpl.NotAfter.After(caCert.NotAfter) {
		tmpl.NotAfter = caCert.NotAfter
	}
	der, err := x509.CreateCertificate(rnd, tmpl, caCert, pub, caSigner)
	if err != nil {
		return nil, fmt.Errorf("x509 create cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse signed cert: %w", err)
	}
	return cert, nil
}

// validateServer enforces required-field invariants on a ServerCertParams.
func validateServer(p ServerCertParams, caCert *x509.Certificate) error {
	if caCert == nil {
		return errors.New("ca cert is required")
	}
	if !caCert.IsCA {
		return errors.New("ca cert is not marked as a CA (IsCA=false)")
	}
	if p.PublicKey == nil {
		return errors.New("public key is required")
	}
	if len(p.DNSNames) == 0 && len(p.IPAddresses) == 0 {
		return errors.New("a server cert needs at least one DNS name or IP address")
	}
	if p.SPIFFEURI != "" {
		uri, err := url.Parse(p.SPIFFEURI)
		if err != nil {
			return fmt.Errorf("parse spiffe uri: %w", err)
		}
		if strings.ToLower(uri.Scheme) != SPIFFEURIScheme {
			return fmt.Errorf("spiffe uri must use scheme %q, got %q", SPIFFEURIScheme, uri.Scheme)
		}
	}
	if p.Serial == nil {
		return errors.New("serial is required")
	}
	if p.ValidAfter.IsZero() {
		return errors.New("valid-after is required")
	}
	if !p.ValidBefore.After(p.ValidAfter) {
		return fmt.Errorf("valid-before (%s) must be after valid-after (%s)", p.ValidBefore, p.ValidAfter)
	}
	if !p.ValidAfter.Before(caCert.NotAfter) {
		return fmt.Errorf("issuer expires at %s, at or before the requested valid-after (%s); nothing valid can be issued", caCert.NotAfter, p.ValidAfter)
	}
	return nil
}

// keyUsageFor returns the X.509 KeyUsage bits appropriate to the subject
// key's algorithm. Every workload cert needs DigitalSignature — that is
// the bit a TLS leaf uses to sign the handshake (CertificateVerify),
// which is the only role the key plays in TLS 1.2/1.3 mutual auth. The
// extra bit is algorithm-specific:
//
//   - Ed25519: signature-only. KeyAgreement is meaningless for it (key
//     agreement is X25519, a separate key), so DigitalSignature alone.
//   - ECDSA: the key can also perform (static) ECDH key agreement, so
//     KeyAgreement is valid even though ECDHE TLS never uses it.
//   - RSA: KeyEncipherment for the legacy RSA key-transport handshake;
//     RSA cannot do key agreement, so KeyAgreement would be invalid.
//
// Unknown key types fall back to DigitalSignature only.
func keyUsageFor(pub crypto.PublicKey) x509.KeyUsage {
	switch pub.(type) {
	case ed25519.PublicKey:
		return x509.KeyUsageDigitalSignature
	case *ecdsa.PublicKey:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	case *rsa.PublicKey:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	default:
		return x509.KeyUsageDigitalSignature
	}
}

// validate enforces required-field invariants on p and caCert before
// any signing happens.
func validate(p WorkloadCertParams, caCert *x509.Certificate) error {
	if caCert == nil {
		return errors.New("ca cert is required")
	}
	if !caCert.IsCA {
		return errors.New("ca cert is not marked as a CA (IsCA=false)")
	}
	if p.PublicKey == nil {
		return errors.New("public key is required")
	}
	if p.SPIFFEURI == "" {
		return errors.New("spiffe uri is required")
	}
	uri, err := url.Parse(p.SPIFFEURI)
	if err != nil {
		return fmt.Errorf("parse spiffe uri: %w", err)
	}
	if strings.ToLower(uri.Scheme) != SPIFFEURIScheme {
		return fmt.Errorf("spiffe uri must use scheme %q, got %q", SPIFFEURIScheme, uri.Scheme)
	}
	if uri.Host == "" {
		return errors.New("spiffe uri must include a trust domain (host part)")
	}
	if p.Serial == nil {
		return errors.New("serial is required")
	}
	if p.ValidAfter.IsZero() {
		return errors.New("valid-after is required")
	}
	if !p.ValidBefore.After(p.ValidAfter) {
		return fmt.Errorf("valid-before (%s) must be after valid-after (%s)", p.ValidBefore, p.ValidAfter)
	}
	if !p.ValidAfter.Before(caCert.NotAfter) {
		return fmt.Errorf("issuer expires at %s, at or before the requested valid-after (%s); nothing valid can be issued", caCert.NotAfter, p.ValidAfter)
	}
	return nil
}

// NewSelfSignedCA builds a self-signed CA certificate from caSigner's
// public key, suitable for use as the issuer cert in [SignWorkloadCert].
// Subject CN is the caller-supplied commonName (e.g., "tokyo3-ca");
// validity defaults to ~10 years from now. The returned cert is parsed
// back from DER so callers receive a fully-populated *x509.Certificate.
//
// Production deployments may instead load a CA cert from disk — this
// helper is the convenience path for dev / first-boot bootstrapping.
func NewSelfSignedCA(rnd io.Reader, caSigner signer.Signer, commonName string) (*x509.Certificate, error) {
	return selfSignedCA(rnd, caSigner, commonName, 0)
}

// NewSelfSignedRootCA mints a self-signed root with a path-length budget of 1,
// so it can sign exactly one level of intermediate CA (which then signs leaves).
// Use this — not [NewSelfSignedCA] — for the offline root in a two-tier
// hierarchy: [NewSelfSignedCA]'s path-length-0 cert may not sign any sub-CA, so
// an intermediate beneath it would fail to verify.
func NewSelfSignedRootCA(rnd io.Reader, caSigner signer.Signer, commonName string) (*x509.Certificate, error) {
	return selfSignedCA(rnd, caSigner, commonName, 1)
}

// selfSignedCA mints a self-signed CA cert with the given path-length budget:
// maxPathLen <= 0 ⇒ path-length 0 (MaxPathLenZero — direct leaf issuance only,
// no sub-CAs); maxPathLen >= 1 ⇒ that many sub-CA levels permitted beneath it.
func selfSignedCA(rnd io.Reader, caSigner signer.Signer, commonName string, maxPathLen int) (*x509.Certificate, error) {
	if caSigner == nil {
		return nil, errors.New("ca signer is required")
	}
	if commonName == "" {
		commonName = "tokyo3-ca"
	}
	serial, err := randomSerial(rnd)
	if err != nil {
		return nil, fmt.Errorf("ca cert serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if maxPathLen <= 0 {
		tmpl.MaxPathLenZero = true // direct issuance only; no sub-CAs
	} else {
		tmpl.MaxPathLen = maxPathLen
	}
	der, err := x509.CreateCertificate(rnd, tmpl, tmpl, caSigner.Public(), caSigner)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse self-signed ca: %w", err)
	}
	return cert, nil
}

// IntermediateCertParams describes an intermediate-CA signing request.
type IntermediateCertParams struct {
	// PublicKey is the intermediate's public key — the half certd will sign
	// leaves with. The private half is sealed at the ceremony and unsealed
	// into certd's memory at boot; it never touches the root's host.
	PublicKey crypto.PublicKey
	// SubjectCommonName is the intermediate's Subject CN; defaults to
	// "tokyo3-ca intermediate" when empty.
	SubjectCommonName string
	// ValidAfter / ValidBefore bound validity. ValidBefore must be after
	// ValidAfter; it is additionally clamped to the root's NotAfter (an
	// intermediate must never outlive its root — same chain invariant a leaf
	// has against its issuer).
	ValidAfter  time.Time
	ValidBefore time.Time
	// Serial is the cert serial (caller-unique).
	Serial *big.Int
}

// SignIntermediateCA builds an intermediate-CA cert per p, signed by rootSigner
// against rootCert, and returns the parsed cert. The intermediate is itself a
// CA (it signs leaves) but path-length 0 — it may not mint further sub-CAs. Its
// NotAfter is clamped to the root's by [signTemplate], so the chain never
// outlives the root.
func SignIntermediateCA(rnd io.Reader, rootSigner signer.Signer, rootCert *x509.Certificate, p IntermediateCertParams) (*x509.Certificate, error) {
	if err := validateIntermediate(p, rootCert); err != nil {
		return nil, err
	}
	cn := p.SubjectCommonName
	if cn == "" {
		cn = "tokyo3-ca intermediate"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          p.Serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             p.ValidAfter,
		NotAfter:              p.ValidBefore,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // signs leaves only; no further sub-CAs
	}
	return signTemplate(rnd, rootSigner, rootCert, p.PublicKey, tmpl)
}

// validateIntermediate enforces required-field invariants on an
// IntermediateCertParams before signing. The path-length guard catches the
// common mistake of using a [NewSelfSignedCA] root (path-length 0) where a
// [NewSelfSignedRootCA] (path-length 1) is required.
func validateIntermediate(p IntermediateCertParams, rootCert *x509.Certificate) error {
	if rootCert == nil {
		return errors.New("root cert is required")
	}
	if !rootCert.IsCA {
		return errors.New("root cert is not marked as a CA (IsCA=false)")
	}
	if rootCert.MaxPathLenZero {
		return errors.New("root cert has path length 0 (MaxPathLenZero) and cannot sign an intermediate CA; mint the root with NewSelfSignedRootCA")
	}
	if p.PublicKey == nil {
		return errors.New("public key is required")
	}
	if p.Serial == nil {
		return errors.New("serial is required")
	}
	if p.ValidAfter.IsZero() {
		return errors.New("valid-after is required")
	}
	if !p.ValidBefore.After(p.ValidAfter) {
		return fmt.Errorf("valid-before (%s) must be after valid-after (%s)", p.ValidBefore, p.ValidAfter)
	}
	if !p.ValidAfter.Before(rootCert.NotAfter) {
		return fmt.Errorf("root expires at %s, at or before the requested valid-after (%s); nothing valid can be issued", rootCert.NotAfter, p.ValidAfter)
	}
	return nil
}

// IsSelfSigned reports whether c is self-signed — its own issuer, i.e. a root
// trust anchor — as opposed to an intermediate that a leaf must present in its
// chain so peers can build a path to the root they pin.
func IsSelfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

// ChainPEMForLeaf returns the issuer chain a leaf must carry alongside itself so
// peers can build a path to the trust anchor: the issuer's own PEM when it is
// an intermediate (not self-signed), or "" when the issuer is a self-signed
// root that peers already pin. This is what lets leaf→intermediate→root verify
// without the intermediate being in every verifier's trust store; in a
// single-tier deployment (issuer == root) it is empty and the leaf stands alone.
func ChainPEMForLeaf(issuer *x509.Certificate) string {
	if issuer == nil || IsSelfSigned(issuer) {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}))
}

// RandomSerial returns a positive 128-bit serial, the size NIST
// SP 800-57 recommends for CA-signed certs. Exported so the API
// handler reuses the same generator for issued certs.
func RandomSerial(rnd io.Reader) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rnd, limit)
	if err != nil {
		return nil, fmt.Errorf("serial generation: %w", err)
	}
	// Zero is conventionally avoided.
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n, nil
}

// randomSerial is the internal alias used by [NewSelfSignedCA].
func randomSerial(rnd io.Reader) (*big.Int, error) {
	return RandomSerial(rnd)
}
