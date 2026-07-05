## tokyo3-ca — build targets
##
## Usage: make <target>
##

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

COMPOSE_PROJECT_NAME     ?= ca
TOKYO3_SHARED_VOLUME     ?= tokyo3_shared_data
TOKYO3_BACKPLANE_NETWORK ?= tokyo3_backplane
TOKYO3_IDP_NETWORK       ?= tokyo3_idp
export COMPOSE_PROJECT_NAME TOKYO3_SHARED_VOLUME TOKYO3_BACKPLANE_NETWORK TOKYO3_IDP_NETWORK
SHARED_VOLUME := $(COMPOSE_PROJECT_NAME)_shared_data

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        check \
        gen-certs _sync-shared _sync-tokyo3-certs mesh-networks \
        docker-build docker-build-amd64 docker-build-agent docker-build-cli docker-push \
        docker-up docker-down \
        install install-cli clean clean-all help

# ── shared_data volumes ───────────────────────────────────────────────────────
# CA services use the project-local shared_data volume for full ./shared/.
# Sibling repos get the stable tokyo3_shared_data volume containing only certs/.

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

## check: Full pre-commit sequence (gofmt + tidy + test + vet + staticcheck + gopls + govulncheck + deadcode)
check:
	gofmt -s -w .
	$(GO) mod tidy
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

## docker-build-agent: Build the cert-agentd image
# Runs on every host that needs renewable identity credentials (TLS or SSH
# host certs). Default platform is linux/arm64 (Graviton); override via
# TARGETARCH.
docker-build-agent:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --target agent \
	  -t $(IMAGE_NAME)-agent:$(IMAGE_TAG) \
	  -t $(IMAGE_NAME)-agent:latest \
	  .
	@echo "  built $(IMAGE_NAME)-agent:$(IMAGE_TAG)"

## docker-build-cli: Build a thin image containing the auth-ssh-creds CLI helper
# The default certd server image deliberately omits this binary — developers
# `go install` it on their laptops rather than running it in the cluster. The
# CLI image is offered for shops that prefer a containerized installation path
# (CI runners, dev containers). No ENTRYPOINT; users explicitly invoke it:
#   docker run --rm <image> auth-ssh-creds get --certd ... --principals ...
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

## gen-certs: Generate dev TLS material via mkcert + certd ca init-env
# Pre-flight for `make docker-up`: mkcert mints only the host-facing Traefik
# edge cert; certd ca init-env consumes shared/certs/bootstrap.yaml to
# mint/reuse the internal root, sealed intermediate, SSH CA, and static
# server/workload leaves. Idempotent — re-runs regenerate leaf X.509 certs but
# preserve CA key material unless those files are deleted.
gen-certs:
	@bash shared/certs/gen.sh

# _sync-shared: Tar-pipe full ./shared/ into CA's local shared_data volume.
_sync-shared:
	@$(MAKE) gen-certs
	@docker volume create $(SHARED_VOLUME) >/dev/null
	@tar -cf - -C shared . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "tar -xf - -C /shared"
	@echo "  synced ./shared/ → docker volume $(SHARED_VOLUME)"

# _sync-tokyo3-certs: Export only certs/ into the downstream shared volume.
_sync-tokyo3-certs:
	@docker volume create $(TOKYO3_SHARED_VOLUME) >/dev/null
	@docker run --rm -v $(TOKYO3_SHARED_VOLUME):/tokyo3 alpine:3.21 sh -c "rm -rf /tokyo3/* /tokyo3/.[!.]* /tokyo3/..?* 2>/dev/null || true"
	@tar -cf - -C shared certs | docker run --rm -i -v $(TOKYO3_SHARED_VOLUME):/tokyo3 alpine:3.21 sh -c "tar -xf - -C /tokyo3"
	@echo "  synced ./shared/certs/ → docker volume $(TOKYO3_SHARED_VOLUME)/certs"

# mesh-networks: Create shared external Docker networks for tokyo3 integrations.
mesh-networks:
	@docker network create $(TOKYO3_BACKPLANE_NETWORK) >/dev/null 2>&1 || true
	@docker network create $(TOKYO3_IDP_NETWORK) >/dev/null 2>&1 || true
	@echo "  ensured networks $(TOKYO3_BACKPLANE_NETWORK), $(TOKYO3_IDP_NETWORK)"

## docker-up: Sync shared CA material and bring up the shared tokyo3 mesh rig.
docker-up: _sync-shared _sync-tokyo3-certs mesh-networks
	docker compose up -d --build --wait

## docker-down: Stop the shared tokyo3 mesh rig (preserves volumes).
docker-down:
	docker compose down

# ── Install / Clean ───────────────────────────────────────────────────────────

## install: Install certd + cert-agentd to GOPATH/bin
install:
	$(GO) install $(CMD_CERTD)
	$(GO) install $(CMD_CERT_AGENTD)

## install-cli: Install the auth-ssh-creds helper to GOPATH/bin
# Independent target so developers can install just the CLI helper without
# pulling the server's build dependencies into their workflow.
install-cli:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_AUTH_SSH_CREDS)
	@echo "  installed auth-ssh-creds"

## clean: Remove ./bin/
clean:
	rm -rf $(BIN_DIR)

## clean-all: Full reset — remove ./bin/, generated certs, and compose volumes
# The next `make docker-up` starts from scratch.
clean-all: clean
	docker compose down -v --remove-orphans 2>/dev/null || true
	docker volume rm $(SHARED_VOLUME) $(TOKYO3_SHARED_VOLUME) 2>/dev/null || true
	rm -f shared/certs/*.crt shared/certs/*.key shared/certs/*.pub shared/certs/*.srl shared/certs/*.sealed
	@echo "  removed shared/certs/*.{crt,key,pub,srl,sealed} + named volumes"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@awk '/^##/ { \
	  line=$$0; sub(/^## ?/, "", line); \
	  if (line ~ /^[a-z0-9_.-]+:/) { \
	    target=line; sub(/:.*/, "", target); \
	    desc=line; sub(/^[^:]+:[[:space:]]*/, "", desc); \
	    names[++n]=target; docs[target]=desc; \
	  } else header[++h]=line; \
	} END { \
	  for (i=1; i<=h; i++) print header[i]; \
	  for (i=1; i<=n; i++) for (j=i+1; j<=n; j++) if (names[j] < names[i]) { tmp=names[i]; names[i]=names[j]; names[j]=tmp } \
	  for (i=1; i<=n; i++) printf "  %-22s %s\n", names[i], docs[names[i]]; \
	}' $(MAKEFILE_LIST)
