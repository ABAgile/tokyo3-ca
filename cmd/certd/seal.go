package main

// Seal seam — how the intermediate CA private key is wrapped at rest. The
// intermediate is generated and root-signed once at a ceremony
// (`ca issue-intermediate`), its private key Encrypted under a *symmetric* KMS
// key, and the ciphertext shipped as config. At `serve` boot certd Decrypts it
// into memory and signs leaves with it — so the asymmetric root key stays
// offline and the intermediate key never persists in plaintext on the certd
// host. This mirrors the signing kms.Client seam in signer_source.go: a
// registry indirection the deployment KMS binding fills (the AWS binding in
// seal_aws_kms.go registers automatically).

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// sealer wraps and unwraps small blobs (the intermediate key) under a symmetric
// KMS key. Encrypt is used by `ca issue-intermediate`; Decrypt by `serve` at
// boot. The seal key is a different KMS key from the (asymmetric, offline) root
// signing key.
type sealer interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// sealerFactory builds a [sealer] from a scheme-specific key reference.
type sealerFactory func(ctx context.Context, keyRef string) (sealer, error)

// sealerFactories maps a key-reference scheme to its binding. Each binding
// registers from an init(): the AWS KMS binding under "aws", the dev local-file
// binding under "file". The scheme is the prefix before the first ':' in
// CERTD_CA_SEAL_KEY / --seal-key when that prefix is a recognised scheme;
// anything else (a bare KMS alias / uuid, or an "arn:aws:kms:..." ARN) defaults
// to "aws", so existing KMS configs keep working with no scheme prefix.
var sealerFactories = map[string]sealerFactory{}

// RegisterSealerFactory wires a sealer factory for a scheme. Call it once, from
// an init() in the binding file. Exported so those files can reach it.
func RegisterSealerFactory(scheme string, f sealerFactory) {
	sealerFactories[scheme] = f
}

// resolveSealer selects a [sealer] by the scheme of keyRef and builds it. The
// scheme prefix is stripped before the ref reaches the binding (so the AWS
// binding still sees a bare key ref, and the file binding sees a bare path).
func resolveSealer(ctx context.Context, keyRef string) (sealer, error) {
	if keyRef == "" {
		return nil, errors.New("no seal key: set --seal-key / $CERTD_CA_SEAL_KEY (a KMS key ref, or file:<path> for a local dev key)")
	}
	scheme, ref := "aws", keyRef
	if i := strings.IndexByte(keyRef, ':'); i > 0 {
		switch keyRef[:i] {
		case "aws", "file":
			scheme, ref = keyRef[:i], keyRef[i+1:]
		}
	}
	f := sealerFactories[scheme]
	if f == nil {
		return nil, fmt.Errorf("no sealer registered for scheme %q (this build lacks the binding)", scheme)
	}
	return f(ctx, ref)
}
