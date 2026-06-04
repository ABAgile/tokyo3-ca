package kms

// Bindings adapt a cloud KMS SDK to [Client]. The AWS KMS binding ships
// in-repo at cmd/certd/kms_aws.go and is compiled in by default (KMS is
// the primary deployment target); it registers itself into certd's
// signer seam so CERTD_CA_KMS_KEY just works on the stock binary. The
// Algorithm string values match AWS SigningAlgorithmSpec, so that
// binding is a cast rather than a mapping table.
//
// Other backends implement the same two-method [Client] the same way:
//
//   - GCP KMS: GetPublicKey returns a PEM-wrapped SPKI — pem.Decode it to
//     DER for PublicKey(); AsymmetricSign takes a Digest oneof for
//     prehashed algorithms. GCP KMS has no Ed25519 key spec — use
//     EC_SIGN_P256_SHA256 and provision an ECDSA P-256 CA key.
//
//   - Vault Transit: read /transit/keys/<k> for the public key and POST
//     /transit/sign/<k> to sign. Supports ed25519 (raw message), so the
//     [Ed25519] path is reachable there.
//
// AWS KMS supports all of [ECDSAP256], [ECDSAP384], [RSAPKCS1SHA256], and
// [Ed25519] (the ECC_NIST_EDWARDS25519 key spec, since 2025-11), so an
// Ed25519 CA key can live in AWS KMS unchanged.
