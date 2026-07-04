## tokyo3-ca — build targets
##
## Usage:
##   make build              Build certd + cert-agentd + auth-ssh-creds binaries to ./bin/
##   make test               Run all tests
##   make check              Full pre-commit sequence (gofmt + test + vet + staticcheck + gopls + govulncheck + deadcode)
##   make tidy               Run go mod tidy
##   make gen-certs          Generate dev TLS material via mkcert + certd ca init-env
##   make docker-build       Build the server Docker image (linux/arm64, default)
##   make docker-build-agent Build the agent image (cert-agentd — for host-level renewal)
##   make docker-build-cli   Build the CLI image (auth-ssh-creds — for CI runners + dev containers)
##   make docker-up          Run gen-certs (if needed) and bring up the compose rig
##   make docker-down        Stop the compose rig (preserves nats-data + ./certs/)
##   make install            Install certd + cert-agentd to GOPATH/bin
##   make install-cli        Install the auth-ssh-creds helper to GOPATH/bin
##   make clean              Remove ./bin/
##   make clean-all          Remove ./bin/ AND ./certs/ (full reset)
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
        gen-certs _sync-shared \
        docker-build docker-build-amd64 docker-build-agent docker-build-cli docker-push \
        docker-up docker-down \
        install install-cli clean clean-all help

# ── shared_data volume ────────────────────────────────────────────────────────
# shared_data is declared `external` in docker-compose.yml because the
# Makefile (not compose) owns it: _sync-shared creates and populates it
# before compose runs. The external volume's name is pinned to
# <project>_shared_data, so COMPOSE_PROJECT_NAME must reach the compose
# subprocess for both project namespacing and the ${COMPOSE_PROJECT_NAME}
# interpolation in the volume `name:` — hence the `export` below. Default
# is "ca" (the directory name); override it if you run with -p.
COMPOSE_PROJECT_NAME ?= ca
export COMPOSE_PROJECT_NAME
SHARED_VOLUME        := $(COMPOSE_PROJECT_NAME)_shared_data
AGENT_STATE_VOLUME   := $(COMPOSE_PROJECT_NAME)_agent_state

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

## check: Full pre-commit sequence (gofmt + test + vet + staticcheck + gopls + govulncheck + deadcode)
check:
	gofmt -s -w .
	$(GO) test ./... -count=1
	$(GO) vet ./...
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...
	@out=$$(deadcode -test ./...); if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found (above)"; exit 1; fi

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

## docker-build-agent: Build the cert-agentd image. Runs on every host that
## needs renewable identity credentials (TLS or SSH host certs). Default
## platform is linux/arm64 (Graviton); override via TARGETARCH.
docker-build-agent:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --target agent \
	  -t $(IMAGE_NAME)-agent:$(IMAGE_TAG) \
	  -t $(IMAGE_NAME)-agent:latest \
	  .
	@echo "  built $(IMAGE_NAME)-agent:$(IMAGE_TAG)"

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

# ── Dev rig (docker compose) ──────────────────────────────────────────────────

## gen-certs: Generate dev TLS material via mkcert + certd ca init-env.
## Pre-flight for `make docker-up`: mkcert mints only the host-facing
## Traefik edge cert; certd ca init-env consumes shared/certs/bootstrap.yaml
## to mint/reuse the internal root, sealed intermediate, SSH CA, and static
## server/workload leaves. Idempotent — re-runs regenerate leaf X.509 certs
## but preserve CA key material unless those files are deleted.
gen-certs:
	@bash shared/certs/gen.sh

## _sync-shared: Tar-pipe ./shared/ into the shared_data named volume.
## Re-running on every docker-up keeps the volume in sync with the
## host tree (templates rendered, certs regenerated, scripts touched).
## Note: this clobbers anything cert-agentd renewed in shared_data, so
## the rig keeps cert-agentd's renewable state on a separate
## agent_state volume — _sync-shared never touches that.
_sync-shared:
	@if [ ! -f shared/certs/traefik-ca.crt ]; then $(MAKE) gen-certs; fi
	@docker volume create $(SHARED_VOLUME) >/dev/null
	@tar -cf - -C shared . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "tar -xf - -C /shared"
	@echo "  synced ./shared/ → docker volume $(SHARED_VOLUME)"

## docker-up: Sync shared/ into shared_data and bring up the compose rig.
docker-up: _sync-shared
	docker compose up -d --build --wait

## docker-down: Stop the compose rig (preserves shared_data + agent_state + nats-data)
docker-down:
	docker compose down

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

## clean-all: Full reset — wipes ./bin/, generated material under
## ./shared/certs/, AND the compose-managed named volumes
## (shared_data, agent_state, nats-data). The next `make docker-up`
## starts from scratch.
clean-all: clean
	docker compose down -v --remove-orphans 2>/dev/null || true
	docker volume rm $(SHARED_VOLUME) $(AGENT_STATE_VOLUME) 2>/dev/null || true
	rm -f shared/certs/*.crt shared/certs/*.key shared/certs/*.pub shared/certs/*.srl shared/certs/*.sealed
	@echo "  removed shared/certs/*.{crt,key,pub,srl,sealed} + named volumes"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@grep -h '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
