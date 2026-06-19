// AWS KMS binding for the intermediate-key seal seam (seal.go). Wraps the
// intermediate CA private key under a *symmetric* KMS key via Encrypt/Decrypt —
// the counterpart to aws_kms.go's asymmetric signing client. Compiled in by
// default for the same reason: KMS is the primary deployment target. Setting
// A bare CERTD_CA_SEAL_KEY (or --seal-key) — a KMS alias / uuid / arn, with no
// recognised scheme prefix — routes here (the "aws" default in resolveSealer),
// so `ca issue-intermediate` seals and `serve` unseals through this key with
// the symmetric key never leaving the HSM. The dev "file:" scheme routes to the
// local binding (seal_local.go) instead.

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func init() {
	RegisterSealerFactory("aws", func(ctx context.Context, keyRef string) (sealer, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load AWS config: %w", err)
		}
		return &awsKMSSealer{c: awskms.NewFromConfig(cfg), keyID: keyRef}, nil
	})
}

// awsKMSSealer wraps the intermediate key under a symmetric AWS KMS key. keyID
// is any form the SDK accepts (a key id, an alias, or a full ARN).
type awsKMSSealer struct {
	c     *awskms.Client
	keyID string
}

func (a *awsKMSSealer) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	out, err := a.c.Encrypt(ctx, &awskms.EncryptInput{KeyId: &a.keyID, Plaintext: plaintext})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

func (a *awsKMSSealer) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	// KeyId is optional for symmetric Decrypt but pinning it rejects a
	// ciphertext wrapped under a different key — a cheap misconfiguration guard.
	out, err := a.c.Decrypt(ctx, &awskms.DecryptInput{KeyId: &a.keyID, CiphertextBlob: ciphertext})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
