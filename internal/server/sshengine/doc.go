// Package sshengine builds SSH user, host, and per-session certificates.
// Uses golang.org/x/crypto/ssh.Certificate; embeds policy-derived
// allowed-principals and host-pattern extensions in the cert.
// Publishes the KRL for revocation distribution.
package sshengine
