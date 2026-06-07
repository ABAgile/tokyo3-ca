package api

import (
	"bytes"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
)

// sshCAKeysResponse is the body of GET /api/v1/ssh/ca-keys. TrustedUserCAKeys
// is one or more SSH CA public keys in authorized_keys / TrustedUserCAKeys
// format — multiple lines during a CA-rotation overlap (old⊕new), one in steady
// state.
type sshCAKeysResponse struct {
	TrustedUserCAKeys string `json:"trusted_user_ca_keys"`
}

// handleSSHCAKeys serves the trusted SSH CA key set so verifiers (ssh-proxyd,
// ssh-tunneld, plain sshd via a poller) can pull the current keys instead of
// having them pushed out-of-band — the SSH counterpart to the X.509
// trust-bundle endpoint. The operator-maintained CERTD_SSH_CA_KEYS_FILE (which
// may list old⊕new during a rotation) is served as-is and read per request, so
// an edit is picked up immediately; when it is unset, unreadable, or blank, the
// live CA signing key is derived and served instead — the endpoint never
// returns an empty set, which would empty every verifier's TrustedUserCAKeys
// and lock SSH out.
//
// Deliberately UNAUTHENTICATED, like the X.509 trust bundle: a CA public key is
// public material, and a verifier may need it before it holds any cert.
// Integrity comes from the TLS channel.
func (s *Server) handleSSHCAKeys(w http.ResponseWriter, _ *http.Request) {
	if s.sshCAKeysPath != "" {
		data, err := os.ReadFile(s.sshCAKeysPath)
		switch {
		case err != nil:
			s.log.Error("read ssh ca-keys file; serving live key", "path", s.sshCAKeysPath, "err", err)
		case len(bytes.TrimSpace(data)) == 0:
			s.log.Warn("ssh ca-keys file empty; serving live key", "path", s.sshCAKeysPath)
		default:
			writeJSON(w, http.StatusOK, sshCAKeysResponse{TrustedUserCAKeys: string(data)})
			return
		}
	}
	live, err := sshCAAuthorizedKey(s.caSigner)
	if err != nil {
		s.log.Error("derive ssh ca public key", "err", err)
		writeError(w, http.StatusInternalServerError, "ssh ca key unavailable")
		return
	}
	writeJSON(w, http.StatusOK, sshCAKeysResponse{TrustedUserCAKeys: live})
}

// sshCAAuthorizedKey renders the signer's public half as a single
// authorized_keys / TrustedUserCAKeys line (newline-terminated, as
// ssh.MarshalAuthorizedKey emits).
func sshCAAuthorizedKey(s signer.Signer) (string, error) {
	pub, err := ssh.NewPublicKey(s.Public())
	if err != nil {
		return "", err
	}
	return string(ssh.MarshalAuthorizedKey(pub)), nil
}
