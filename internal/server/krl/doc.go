// Package krl publishes the SSH Key Revocation List and the X.509 CRL.
// Targets fetch the KRL periodically (sshd reads it via `RevokedKeys`);
// services validating client mTLS fetch the CRL.
package krl
