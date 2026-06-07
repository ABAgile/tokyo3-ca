package main

// Seal seam — how the intermediate CA private key is wrapped at rest. The
// intermediate is generated and root-signed once at a ceremony
// (`ca issue-intermediate`), its private key Encrypted under a *symmetric* KMS
// key, and the ciphertext shipped as config. At `serve` boot certd Decrypts it
// into memory and signs leaves with it — so the asymmetric root key stays
// offline and the intermediate key never persists in plaintext on the certd
// host. This mirrors the signing kms.Client seam in signer_source.go: a
// registry indirection the deployment KMS binding fills (the AWS binding in
// kms_seal_aws.go registers automatically).

import (
	"context"
	"errors"
)

// sealer wraps and unwraps small blobs (the intermediate key) under a symmetric
// KMS key. Encrypt is used by `ca issue-intermediate`; Decrypt by `serve` at
// boot. The seal key is a different KMS key from the (asymmetric, offline) root
// signing key.
type sealer interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// sealerFactory builds a [sealer] from a symmetric KMS key reference. nil in the
// default SDK-free binary; the deployment KMS binding sets it via
// RegisterSealerFactory from an init().
var sealerFactory func(ctx context.Context, keyRef string) (sealer, error)

// RegisterSealerFactory wires a sealer factory into the seal seam. Call it once,
// from an init() in the deployment build that pulls the cloud SDK. Exported so
// that build can reach it.
func RegisterSealerFactory(f func(ctx context.Context, keyRef string) (sealer, error)) {
	sealerFactory = f
}

// resolveSealer builds a [sealer] from a symmetric KMS key reference. Returns a
// clear error when sealing is requested but no binding was compiled into this
// build.
func resolveSealer(ctx context.Context, keyRef string) (sealer, error) {
	if keyRef == "" {
		return nil, errors.New("no seal key: set --seal-kms-key / $CERTD_CA_SEAL_KMS_KEY (the symmetric KMS key that wraps the intermediate key)")
	}
	if sealerFactory == nil {
		return nil, errors.New("KMS sealing requested but no sealer factory is registered in this build (the AWS binding registers automatically)")
	}
	return sealerFactory(ctx, keyRef)
}
