# Multi-stage build for the tokyo3-ca project.
#
# - Stage `builder` compiles all three binaries (certd + cert-agentd +
#   auth-ssh-creds). Building them together amortises `go mod download`
#   across a single cache layer.
#
# - Stage `agent` ships only cert-agentd. The default workload image — runs
#   on every host that needs renewable identity credentials.
#
# - Stage `cli` ships only the auth-ssh-creds helper. Useful for CI runners
#   and dev containers that prefer a containerized binary over `go install`.
#   No ENTRYPOINT — users explicitly invoke the binary:
#     docker run --rm <image> auth-ssh-creds get --certd ... --principals ...
#   Reachable via `docker build --target cli .`.
#
# - Stage `server` (default — last stage) ships only certd. The central
#   CA service. Plain `docker build .` produces this image.
#
# All targets honour TARGETOS / TARGETARCH for cross-builds.

# ── Stage 1: Build Go binaries ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

# VERSION is injected into each binary's `var Version` via -ldflags.
# Defaults to "dev" when callers leave it unset; the in-binary
# resolveVersion() helper then falls back to runtime/debug.BuildInfo
# (vcs.revision + vcs.modified are stamped by the Go toolchain when
# building from a VCS tree). Both compose rigs pass dev-docker by
# default so image-built binaries are trivially distinguishable from
# `go install`-built ones.
ARG VERSION=dev

WORKDIR /src

# Download deps first (cached layer unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

# certd bundles the AWS KMS signer (cmd/certd/kms_aws.go) by default —
# CERTD_CA_KMS_KEY works out of the box; the server stage ships
# ca-certificates so certd can verify TLS to the KMS endpoint. Costs
# ~+4.4 MiB over a non-KMS build. To produce a lean non-KMS image later,
# add `//go:build awskms` to kms_aws.go and build with `-tags awskms`
# here. cert-agentd / auth-ssh-creds do not import it and stay SDK-free.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.Version=${VERSION}" -o /out/certd ./cmd/certd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.Version=${VERSION}" -o /out/cert-agentd ./cmd/cert-agentd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -X main.Version=${VERSION}" -o /out/auth-ssh-creds ./cmd/auth-ssh-creds

# ── Stage 2: Agent image (build with --target agent) ──────────────────────────
FROM alpine:3.21 AS agent

# tini as PID 1 reaps orphaned children (e.g. the ssl_client that
# busybox-wget healthchecks leave behind) and forwards signals so the
# binary still shuts down cleanly. Without it a non-reaping Go PID 1
# accumulates <defunct> processes — cgroup pids.current climbs forever.
RUN apk add --no-cache ca-certificates tini

COPY --from=builder /out/cert-agentd /usr/local/bin/cert-agentd

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/cert-agentd"]
CMD ["run"]

# ── Stage 3: CLI image (build with --target cli) ──────────────────────────────
FROM alpine:3.21 AS cli

# ca-certificates so the helper can verify TLS to the auth issuer and certd.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/auth-ssh-creds /usr/local/bin/auth-ssh-creds

# No ENTRYPOINT — users invoke the binary explicitly so this image can
# grow more CLI tools later without breaking existing invocations.
CMD ["/bin/sh"]

# ── Stage 4: Server runtime image (default target) ────────────────────────────
FROM alpine:3.21 AS server

# tini as PID 1 reaps orphaned children (notably the ssl_client that the
# busybox-wget HTTPS healthcheck orphans every probe) and forwards
# signals so certd shuts down cleanly. Without it a non-reaping Go PID 1
# accumulates <defunct> processes — cgroup pids.current climbs forever.
RUN apk add --no-cache ca-certificates tini

COPY --from=builder /out/certd /usr/local/bin/certd

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/certd"]
CMD ["serve"]
