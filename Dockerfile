# Multi-stage build for the tokyo3-ca project.
#
# - Stage `builder` compiles both binaries (certd + cert-agentd). Building
#   them together amortises `go mod download` across a single cache layer.
#
# - Stage `agent` ships only cert-agentd. The default workload image — runs
#   on every host that needs renewable identity credentials.
#
# - Stage `server` (default — last stage) ships only certd. The central
#   CA service. Plain `docker build .` produces this image.
#
# Both targets honour TARGETOS / TARGETARCH for cross-builds.

# ── Stage 1: Build Go binaries ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

WORKDIR /src

# Download deps first (cached layer unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/certd ./cmd/certd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/cert-agentd ./cmd/cert-agentd

# ── Stage 2: Agent image (build with --target agent) ──────────────────────────
FROM alpine:3.21 AS agent

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/cert-agentd /usr/local/bin/cert-agentd

ENTRYPOINT ["/usr/local/bin/cert-agentd"]
CMD ["run"]

# ── Stage 3: Server runtime image (default target) ────────────────────────────
FROM alpine:3.21 AS server

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/certd /usr/local/bin/certd

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/certd"]
CMD ["serve"]
