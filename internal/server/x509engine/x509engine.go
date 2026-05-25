// Package x509engine builds and signs X.509v3 certificates carrying
// SPIFFE URI SANs — the workload-identity primitive certd issues for
// the platform's mTLS infrastructure. The same [signer.Signer] that
// signs SSH certs also signs X.509 here; one CA key, two cert formats.
//
// CRL publishing is deferred to a later slice; this package focuses
// on issuance.
package x509engine

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
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
//   - KeyUsage: DigitalSignature + KeyAgreement (mTLS handshake roles)
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rnd, tmpl, caCert, p.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("x509 create cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("re-parse signed cert: %w", err)
	}
	return cert, nil
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
		MaxPathLenZero:        true, // direct issuance only; no sub-CAs
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
