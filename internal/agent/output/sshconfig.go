package output

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// SSHConfigSnippet builds the ssh_config drop-in that points an
// OpenSSH client at credentials cert-agentd renews. The snippet is
// designed to be Included from the user's main config:
//
//	# in ~/.ssh/config
//	Include /etc/ssh/cert-agentd.conf
//
// Atomic refresh of the underlying file (via [WriteAtomic]) is the
// only signal the SSH client needs — it re-reads its Include on
// every new connection, so renewed certs apply on the next `ssh`
// invocation without any external SIGHUP.
type SSHConfigSnippet struct {
	// HostPattern is the OpenSSH host pattern the directives apply to
	// (e.g., "*.tokyo3.internal", "db-*"). Required.
	HostPattern string

	// CertificateFile is the absolute path to the renewed SSH user
	// certificate (the "*-cert.pub" file). Required.
	CertificateFile string

	// IdentityFile is the absolute path to the matching SSH private
	// key. Required.
	IdentityFile string

	// ProxyJump is the optional ssh-proxyd host pattern (e.g.,
	// "alice@proxy.tokyo3.internal:2222"). When set, every SSH session
	// to HostPattern is routed through it. Empty disables ProxyJump.
	ProxyJump string

	// User overrides the SSH login name. Empty leaves the field
	// unset and the SSH client's normal resolution rules apply.
	User string

	// Extras are additional ssh_config directives keyed by directive
	// name (e.g., {"StrictHostKeyChecking": "yes"}). Emitted in
	// sorted-key order for deterministic output.
	Extras map[string]string
}

// Marshal returns the snippet body. Idempotent and deterministic for
// a given set of inputs (Extras emit in sorted-key order) so a no-op
// re-render doesn't churn the on-disk file.
func (s SSHConfigSnippet) Marshal() (string, error) {
	if s.HostPattern == "" {
		return "", errors.New("HostPattern is required")
	}
	if s.CertificateFile == "" {
		return "", errors.New("CertificateFile is required")
	}
	if s.IdentityFile == "" {
		return "", errors.New("IdentityFile is required")
	}
	var b strings.Builder
	b.WriteString("# Managed by cert-agentd; do not edit.\n")
	fmt.Fprintf(&b, "Host %s\n", s.HostPattern)
	if s.User != "" {
		fmt.Fprintf(&b, "    User %s\n", s.User)
	}
	if s.ProxyJump != "" {
		fmt.Fprintf(&b, "    ProxyJump %s\n", s.ProxyJump)
	}
	fmt.Fprintf(&b, "    CertificateFile %s\n", s.CertificateFile)
	fmt.Fprintf(&b, "    IdentityFile %s\n", s.IdentityFile)

	if len(s.Extras) > 0 {
		keys := make([]string, 0, len(s.Extras))
		for k := range s.Extras {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "    %s %s\n", k, s.Extras[k])
		}
	}
	return b.String(), nil
}

// WriteAtomicTo renders the snippet and writes it to path with mode
// 0644 so the SSH client (running as any user) can read it. Returns
// the rendered body so callers can log it / diff against the previous
// version.
func (s SSHConfigSnippet) WriteAtomicTo(path string) (string, error) {
	body, err := s.Marshal()
	if err != nil {
		return "", err
	}
	if err := WriteAtomic(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return body, nil
}

// KnownHostsCAEntry returns a single @cert-authority line that tells
// the SSH client to trust hostCA for the given hostPattern. Writing
// the result to a file referenced by [SSHConfigSnippet.Extras]
// (e.g., "UserKnownHostsFile") makes the workload's SSH client accept
// host certs issued by certd without per-host known_hosts entries.
//
// hostCAAuthorizedKey is the CA public key in authorized_keys format
// — the same shape `ssh-keygen -e` produces and what ssh-keygen -s
// expects in its signer's public-key file.
func KnownHostsCAEntry(hostPattern, hostCAAuthorizedKey string) (string, error) {
	if hostPattern == "" {
		return "", errors.New("hostPattern is required")
	}
	pub := strings.TrimSpace(hostCAAuthorizedKey)
	if pub == "" {
		return "", errors.New("hostCAAuthorizedKey is required")
	}
	// @cert-authority <pattern> <ca-pubkey...>
	return fmt.Sprintf("@cert-authority %s %s\n", hostPattern, pub), nil
}
