// Package output writes renewed credentials to filesystem paths the
// workload's TLS stack / SSH client reads from. Atomic rename, correct
// mode/owner, and SSH client-config snippets (ProxyJump + CertificateFile
// directives) so the consumer picks up new credentials without restart.
package output
