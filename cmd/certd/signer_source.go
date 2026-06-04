package main

// Signer sourcing — the single seam both `certd serve` and `certd ca`
// resolve the CA signing key through. A file key (PKCS#8 PEM) or a KMS
// key reference both work in the default build: the AWS KMS binding
// (kms_aws.go) registers its factory automatically. Other backends
// (GCP, Vault) register the same way (see internal/server/signer/kms/doc.go).
// Keeping one resolver means serve and the ca tooling pick up KMS
// together — no second wiring path to keep in sync.

import (
	"context"
	"errors"
	"fmt"

	"github.com/abagile/tokyo3-ca/internal/server/signer"
	"github.com/abagile/tokyo3-ca/internal/server/signer/kms"
)

// kmsClientFactory builds a [kms.Client] from a key reference (an ARN,
// a GCP resource name, a Vault key path — whatever the binding expects).
// nil in the default SDK-free binary; the deployment KMS binding sets it
// via RegisterKMSClientFactory from an init().
var kmsClientFactory func(ctx context.Context, keyRef string) (kms.Client, error)

// RegisterKMSClientFactory wires a KMS client factory into the signer
// seam. Call it once, from an init() in the deployment build that pulls
// the cloud SDK. Exported so that build can reach it.
func RegisterKMSClientFactory(f func(ctx context.Context, keyRef string) (kms.Client, error)) {
	kmsClientFactory = f
}

// resolveCASigner returns the CA signing primitive from a KMS key
// reference (preferred for production — the key never leaves the HSM) or
// a PKCS#8 file. kmsKeyRef wins when both are set. Returns a clear error
// when KMS is requested but no binding was compiled into this build.
func resolveCASigner(ctx context.Context, keyPath, kmsKeyRef string) (signer.Signer, error) {
	if kmsKeyRef != "" {
		if kmsClientFactory == nil {
			return nil, errors.New("KMS signing requested (--kms-key / $CERTD_CA_KMS_KEY) but no KMS client factory is registered in this build (the AWS binding registers automatically; see internal/server/signer/kms/doc.go and OPERATIONS.md §2.1)")
		}
		client, err := kmsClientFactory(ctx, kmsKeyRef)
		if err != nil {
			return nil, fmt.Errorf("build KMS client for %q: %w", kmsKeyRef, err)
		}
		// signTimeout 0 ⇒ signer.DefaultRemoteSignTimeout.
		return kms.New(ctx, client, "KMS "+kmsKeyRef, 0)
	}
	if keyPath == "" {
		return nil, errors.New("no signing key: set --key / $CERTD_CA_KEY_FILE or --kms-key / $CERTD_CA_KMS_KEY")
	}
	sig, err := signer.LoadEd25519FromPEMFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key %s: %w", keyPath, err)
	}
	return sig, nil
}
