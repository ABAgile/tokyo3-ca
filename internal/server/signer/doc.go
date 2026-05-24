// Package signer abstracts CA key custody. Two implementations:
//
//   - InMemorySigner: loads the CA private key into mlock'd memory at
//     startup from a file or vault-injected env var. Dev-only.
//   - KMSSigner: delegates each signing operation to AWS/GCP KMS via the
//     asymmetric Sign API. CA key never leaves the HSM. Production.
//
// Both implement the same Signer interface, switched via env config.
package signer
