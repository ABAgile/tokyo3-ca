// AWS KMS binding for the CA signing key. KMS is the primary deployment
// target, so this is compiled in by DEFAULT: setting CERTD_CA_KEY
// (or --key) to a KMS key id / ARN (i.e. a non-file: ref) makes both
// `certd serve` and `certd ca` sign through KMS, with the key never leaving the
// HSM. The cost is ~+4.4 MiB of binary (the AWS SDK + credential chain).
//
// This is the ONLY file that imports the AWS SDK, by design: to make KMS
// optional later (a lean non-KMS build), add a `//go:build awskms` line
// at the top of this file — nothing else moves. The registry indirection
// in signer_source.go is what keeps that future split a one-liner.
//
// The init() registers the factory into the signer seam
// (signer_source.go); awsKMSClient is the ~25-line adapter satisfying
// kms.Client. Algorithm strings already match AWS's SigningAlgorithmSpec,
// so the mapping is a cast.

package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/abagile/tokyo3-ca/internal/server/signer/kms"
)

func init() {
	RegisterKMSClientFactory(func(ctx context.Context, keyRef string) (kms.Client, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load AWS config: %w", err)
		}
		return &awsKMSClient{c: awskms.NewFromConfig(cfg), keyID: keyRef}, nil
	})
}

// awsKMSClient adapts the AWS KMS SDK to [kms.Client]. keyID is any form
// the SDK accepts: a key id, an alias (alias/...), or a full ARN.
type awsKMSClient struct {
	c     *awskms.Client
	keyID string
}

func (a *awsKMSClient) PublicKey(ctx context.Context) ([]byte, error) {
	out, err := a.c.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: &a.keyID})
	if err != nil {
		return nil, err
	}
	return out.PublicKey, nil // DER SubjectPublicKeyInfo
}

func (a *awsKMSClient) Sign(ctx context.Context, msg []byte, alg kms.Algorithm, prehashed bool) ([]byte, error) {
	mt := types.MessageTypeRaw
	if prehashed {
		mt = types.MessageTypeDigest
	}
	out, err := a.c.Sign(ctx, &awskms.SignInput{
		KeyId:            &a.keyID,
		Message:          msg,
		MessageType:      mt,
		SigningAlgorithm: types.SigningAlgorithmSpec(alg),
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil // DER ECDSA / PKCS#1 RSA / 64-byte Ed25519 — crypto/x509 verifies as-is
}
