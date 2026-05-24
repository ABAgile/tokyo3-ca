// Package api hosts the certd HTTP handlers — signing endpoints, role-admin
// API, recording-metadata ingest from ssh-proxyd, and the portal session
// layer. Caller auth is mTLS (workload SPIFFE certs) or OIDC ID token
// (humans driving the CLI).
package api
