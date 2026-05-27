## tokyo3-ca — build targets
##
## Usage:
##   make build              Build certd + cert-agentd + auth-ssh-creds binaries to ./bin/
##   make test               Run all tests
##   make check              Full pre-commit sequence (gofmt + test + vet + staticcheck + gopls + govulncheck)
##   make tidy               Run go mod tidy
##   make docker-build       Build the server Docker image (linux/arm64, default)
##   make docker-build-cli   Build the CLI image (auth-ssh-creds — for CI runners + dev containers)
##   make install            Install certd + cert-agentd to GOPATH/bin
##   make install-cli        Install the auth-ssh-creds helper to GOPATH/bin
##   make clean              Remove ./bin/
##   make help               Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE             := github.com/abagile/tokyo3-ca
CMD_CERTD          := ./cmd/certd
CMD_CERT_AGENTD    := ./cmd/cert-agentd
CMD_AUTH_SSH_CREDS := ./cmd/auth-ssh-creds

BIN_DIR            := bin
CERTD_BIN          := $(BIN_DIR)/certd
CERT_AGENTD_BIN    := $(BIN_DIR)/cert-agentd
AUTH_SSH_CREDS_BIN := $(BIN_DIR)/auth-ssh-creds

GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w -X main.Version=$(VERSION)

GO      := go
GOFLAGS :=

IMAGE_NAME ?= abagile/tokyo3-ca
IMAGE_TAG  ?= $(VERSION)

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        test test-verbose tidy vet lint check \
        docker-build docker-build-amd64 docker-build-cli docker-push \
        install install-cli clean help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile certd + cert-agentd + auth-ssh-creds into ./bin/
build: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CERTD_BIN) $(CMD_CERTD)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CERT_AGENTD_BIN) $(CMD_CERT_AGENTD)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AUTH_SSH_CREDS_BIN) $(CMD_AUTH_SSH_CREDS)
	@echo "  built $(CERTD_BIN) + $(CERT_AGENTD_BIN) + $(AUTH_SSH_CREDS_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## build-linux: Cross-compile for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/certd-linux-arm64 $(CMD_CERTD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/cert-agentd-linux-arm64 $(CMD_CERT_AGENTD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-ssh-creds-linux-arm64 $(CMD_AUTH_SSH_CREDS)
	@echo "  built certd-linux-arm64 + cert-agentd-linux-arm64 + auth-ssh-creds-linux-arm64"

## build-linux-amd64: Cross-compile for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/certd-linux-amd64 $(CMD_CERTD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/cert-agentd-linux-amd64 $(CMD_CERT_AGENTD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-ssh-creds-linux-amd64 $(CMD_AUTH_SSH_CREDS)
	@echo "  built certd-linux-amd64 + cert-agentd-linux-amd64 + auth-ssh-creds-linux-amd64"

## build-darwin: Cross-compile for macOS arm64
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/certd-darwin-arm64 $(CMD_CERTD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/cert-agentd-darwin-arm64 $(CMD_CERT_AGENTD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-ssh-creds-darwin-arm64 $(CMD_AUTH_SSH_CREDS)
	@echo "  built certd-darwin-arm64 + cert-agentd-darwin-arm64 + auth-ssh-creds-darwin-arm64"

# ── Quality ───────────────────────────────────────────────────────────────────

## test: Run all tests
test:
	$(GO) test ./... -count=1

## test-verbose: Run all tests with verbose output
test-verbose:
	$(GO) test ./... -count=1 -v

## tidy: Run go mod tidy
tidy:
	$(GO) mod tidy

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run staticcheck
lint:
	staticcheck ./...

## check: Full pre-commit sequence (gofmt + test + vet + staticcheck + gopls + govulncheck)
check:
	gofmt -s -w .
	$(GO) test ./... -count=1
	$(GO) vet ./...
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the server Docker image (linux/arm64, default)
docker-build:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --target server \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-amd64: Build the server Docker image for linux/amd64
docker-build-amd64:
	docker build \
	  --platform linux/amd64 \
	  --build-arg TARGETARCH=amd64 \
	  --target server \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-amd64 \
	  .

## docker-build-cli: Build a thin image containing the auth-ssh-creds CLI
## helper. The default certd server image deliberately omits this binary —
## developers `go install` it on their laptops rather than running it in
## the cluster. The CLI image is offered for shops that prefer a
## containerized installation path (CI runners, dev containers). No
## ENTRYPOINT; users explicitly invoke the binary:
##   docker run --rm <image> auth-ssh-creds get --certd ... --principals ...
docker-build-cli:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --target cli \
	  -t $(IMAGE_NAME)-cli:$(IMAGE_TAG) \
	  -t $(IMAGE_NAME)-cli:latest \
	  .
	@echo "  built $(IMAGE_NAME)-cli:$(IMAGE_TAG)"

## docker-push: Push image to registry (set IMAGE_NAME to your registry repo)
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

# ── Install / Clean ───────────────────────────────────────────────────────────

## install: Install certd + cert-agentd to GOPATH/bin
install:
	$(GO) install $(CMD_CERTD)
	$(GO) install $(CMD_CERT_AGENTD)

## install-cli: Install the auth-ssh-creds helper to GOPATH/bin.
## Independent target so developers can install just the CLI helper
## without pulling the server's build dependencies into their workflow.
install-cli:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_AUTH_SSH_CREDS)
	@echo "  installed auth-ssh-creds"

## clean: Remove ./bin/
clean:
	rm -rf $(BIN_DIR)

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@grep -h '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
