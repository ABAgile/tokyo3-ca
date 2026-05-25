package output_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-ca/internal/agent/output"
)

func TestSSHConfigSnippet_Marshal_MinimumDirectives(t *testing.T) {
	body, err := output.SSHConfigSnippet{
		HostPattern:     "*.tokyo3.internal",
		CertificateFile: "/var/lib/cert-agentd/ssh-user.cert.pub",
		IdentityFile:    "/var/lib/cert-agentd/ssh-user.key",
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []string{
		"Host *.tokyo3.internal",
		"CertificateFile /var/lib/cert-agentd/ssh-user.cert.pub",
		"IdentityFile /var/lib/cert-agentd/ssh-user.key",
		"# Managed by cert-agentd",
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("output missing %q\n--- body ---\n%s", w, body)
		}
	}
	if strings.Contains(body, "ProxyJump") {
		t.Errorf("ProxyJump emitted when unset:\n%s", body)
	}
	if strings.Contains(body, "User ") {
		t.Errorf("User emitted when unset:\n%s", body)
	}
}

func TestSSHConfigSnippet_Marshal_AllDirectives(t *testing.T) {
	body, err := output.SSHConfigSnippet{
		HostPattern:     "db-*",
		CertificateFile: "/c.pub",
		IdentityFile:    "/k",
		ProxyJump:       "alice@proxy.internal:2222",
		User:            "alice",
		Extras: map[string]string{
			"StrictHostKeyChecking": "yes",
			"UserKnownHostsFile":    "/etc/ssh/known_hosts.cert-agentd",
		},
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, w := range []string{
		"Host db-*",
		"User alice",
		"ProxyJump alice@proxy.internal:2222",
		"CertificateFile /c.pub",
		"IdentityFile /k",
		"StrictHostKeyChecking yes",
		"UserKnownHostsFile /etc/ssh/known_hosts.cert-agentd",
	} {
		if !strings.Contains(body, w) {
			t.Errorf("output missing %q\n--- body ---\n%s", w, body)
		}
	}
}

func TestSSHConfigSnippet_Marshal_DeterministicExtras(t *testing.T) {
	// Repeated Marshal of the same input produces identical output —
	// otherwise WriteAtomicTo would churn the file even when nothing
	// has changed, causing pointless inotify wakeups for watchers.
	snippet := output.SSHConfigSnippet{
		HostPattern:     "h",
		CertificateFile: "/c",
		IdentityFile:    "/k",
		Extras: map[string]string{
			"Beta":  "2",
			"Alpha": "1",
			"Gamma": "3",
		},
	}
	a, _ := snippet.Marshal()
	b, _ := snippet.Marshal()
	if a != b {
		t.Errorf("Marshal not deterministic:\na=%q\nb=%q", a, b)
	}
	// Sorted-key ordering: Alpha appears before Beta appears before Gamma.
	if !(strings.Index(a, "Alpha 1") < strings.Index(a, "Beta 2") &&
		strings.Index(a, "Beta 2") < strings.Index(a, "Gamma 3")) {
		t.Errorf("Extras not sorted-key:\n%s", a)
	}
}

func TestSSHConfigSnippet_Marshal_Rejects(t *testing.T) {
	cases := []struct {
		name string
		s    output.SSHConfigSnippet
		want string
	}{
		{"no host pattern", output.SSHConfigSnippet{CertificateFile: "/c", IdentityFile: "/k"}, "HostPattern is required"},
		{"no cert file", output.SSHConfigSnippet{HostPattern: "h", IdentityFile: "/k"}, "CertificateFile is required"},
		{"no identity file", output.SSHConfigSnippet{HostPattern: "h", CertificateFile: "/c"}, "IdentityFile is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.s.Marshal()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSSHConfigSnippet_WriteAtomicTo_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.conf")
	body, err := output.SSHConfigSnippet{
		HostPattern:     "*.tokyo3.internal",
		CertificateFile: "/c.pub",
		IdentityFile:    "/k",
	}.WriteAtomicTo(path)
	if err != nil {
		t.Fatalf("WriteAtomicTo: %v", err)
	}
	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(read) != body {
		t.Errorf("disk body ≠ returned body")
	}
	info, _ := os.Stat(path)
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Errorf("snippet file mode = %o, want 0644", mode)
	}
}

func TestKnownHostsCAEntry_HappyPath(t *testing.T) {
	got, err := output.KnownHostsCAEntry("*.tokyo3.internal",
		"ssh-ed25519 AAAA-host-ca-key cert-agentd-host-ca")
	if err != nil {
		t.Fatalf("KnownHostsCAEntry: %v", err)
	}
	want := "@cert-authority *.tokyo3.internal ssh-ed25519 AAAA-host-ca-key cert-agentd-host-ca\n"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestKnownHostsCAEntry_Rejects(t *testing.T) {
	if _, err := output.KnownHostsCAEntry("", "ssh-ed25519 X"); err == nil {
		t.Error("expected error for empty hostPattern")
	}
	if _, err := output.KnownHostsCAEntry("h", "   "); err == nil {
		t.Error("expected error for whitespace-only CA key")
	}
}
