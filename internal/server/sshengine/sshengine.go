// Package sshengine builds and signs SSH certificates — User, Host, and
// (later) Session — using a [signer.Signer] for CA key custody.
//
// The OpenSSH cert format is RFC-less (only ever specified in OpenSSH's
// PROTOCOL.certkeys); we lean on golang.org/x/crypto/ssh which matches
// OpenSSH's encoding bit-for-bit.
//
// Session certs and the KRL publisher live in sibling files in this
// package (still to come).
package sshengine

import (
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// UserCertParams describes a single user-cert signing request.
type UserCertParams struct {
	// PublicKey is the subject's SSH public key (whose cert this is).
	PublicKey ssh.PublicKey
	// KeyID is the human-readable identifier embedded in the cert. Used
	// for audit attribution downstream; typically the user's stable ID
	// (e.g., "user:alice@example.com" or "session:UUID" for per-session
	// certs).
	KeyID string
	// Principals are the Unix usernames the bearer may log in as.
	// Empty is rejected.
	Principals []string
	// Extensions are SSH cert extensions applied to the user. Typical
	// keys: "permit-pty", "permit-port-forwarding",
	// "permit-agent-forwarding", "permit-user-rc", "permit-X11-forwarding".
	// Values for these are conventionally empty strings.
	Extensions map[string]string
	// CriticalOptions are enforced strictly by sshd — unknown keys
	// cause the cert to be rejected. Typical keys: "force-command",
	// "source-address", "verify-required".
	CriticalOptions map[string]string
	// ValidAfter is the earliest moment the cert is valid (inclusive).
	// Zero value rejected.
	ValidAfter time.Time
	// ValidBefore is the moment the cert expires (exclusive). Must be
	// strictly after ValidAfter.
	ValidBefore time.Time
	// Serial is the cert's serial number — caller is responsible for
	// uniqueness across the CA so KRL serial-based revocation works.
	Serial uint64
}

// HostCertParams describes a single host-cert signing request.
type HostCertParams struct {
	// PublicKey is the host's SSH public key.
	PublicKey ssh.PublicKey
	// KeyID identifies the host for audit attribution (e.g., "host:db-1.prod.internal").
	KeyID string
	// Principals are the hostnames the certificate is valid for —
	// FQDNs and any short aliases clients reach the host as. Empty rejected.
	Principals []string
	// ValidAfter is the earliest moment the cert is valid (inclusive).
	ValidAfter time.Time
	// ValidBefore is the moment the cert expires (exclusive). Must be
	// strictly after ValidAfter.
	ValidBefore time.Time
	// Serial — see UserCertParams.Serial.
	Serial uint64
}

// SignUserCert builds a User SSH certificate per p, signs it with s,
// and returns the populated *ssh.Certificate (cert.SignatureKey + Signature
// set). The cert is ready to marshal via ssh.MarshalAuthorizedKey or
// equivalent.
func SignUserCert(rnd io.Reader, s signer.Signer, p UserCertParams) (*ssh.Certificate, error) {
	if err := validateCommon(p.PublicKey, p.KeyID, p.Principals, p.ValidAfter, p.ValidBefore); err != nil {
		return nil, err
	}
	return signCert(rnd, s, ssh.UserCert, p.PublicKey, p.KeyID, p.Principals,
		p.Extensions, p.CriticalOptions, p.ValidAfter, p.ValidBefore, p.Serial)
}

// SignHostCert builds a Host SSH certificate per p and signs it with s.
// Host certs carry no extensions or critical options (sshd's host-cert
// validation path doesn't read them), so HostCertParams omits those
// fields.
func SignHostCert(rnd io.Reader, s signer.Signer, p HostCertParams) (*ssh.Certificate, error) {
	if err := validateCommon(p.PublicKey, p.KeyID, p.Principals, p.ValidAfter, p.ValidBefore); err != nil {
		return nil, err
	}
	return signCert(rnd, s, ssh.HostCert, p.PublicKey, p.KeyID, p.Principals,
		nil, nil, p.ValidAfter, p.ValidBefore, p.Serial)
}

// validateCommon enforces fields required for both user and host certs.
func validateCommon(pub ssh.PublicKey, keyID string, principals []string, validAfter, validBefore time.Time) error {
	if pub == nil {
		return errors.New("public key is required")
	}
	if keyID == "" {
		return errors.New("key id is required for audit attribution")
	}
	if len(principals) == 0 {
		return errors.New("principals must contain at least one entry")
	}
	if validAfter.IsZero() {
		return errors.New("valid-after is required")
	}
	if !validBefore.After(validAfter) {
		return fmt.Errorf("valid-before (%s) must be after valid-after (%s)", validBefore, validAfter)
	}
	return nil
}

// signCert is the shared body for SignUserCert / SignHostCert.
func signCert(
	rnd io.Reader,
	s signer.Signer,
	certType uint32,
	pub ssh.PublicKey,
	keyID string,
	principals []string,
	extensions, criticalOpts map[string]string,
	validAfter, validBefore time.Time,
	serial uint64,
) (*ssh.Certificate, error) {
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        certType,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOpts,
			Extensions:      extensions,
		},
	}

	sshSigner, err := ssh.NewSignerFromSigner(s)
	if err != nil {
		return nil, fmt.Errorf("wrap CA signer for SSH: %w", err)
	}

	if err := cert.SignCert(rnd, sshSigner); err != nil {
		return nil, fmt.Errorf("sign SSH cert: %w", err)
	}
	return cert, nil
}
