# ─── SFTPGo Docker Build Makefile ─────────────────────────────────────────────
#
# Mirrors the GitHub Actions docker.yml workflow for local builds.
#
# Usage:
#   make docker-debian          # Debian full (with optional packages)
#   make docker-debian-slim     # Debian slim (no optional packages)
#   make docker-alpine          # Alpine full
#   make docker-alpine-slim     # Alpine slim
#   make docker-distroless      # Distroless (always slim, no SQLite)
#   make docker-plugins         # Debian + plugins
#   make docker-plugins-slim    # Debian + plugins, slim
#   make docker-all             # Build everything
#
# Override the image name / tag prefix:
#   make docker-debian IMAGE=my-registry/sftpgo TAG_PREFIX=dev
# ──────────────────────────────────────────────────────────────────────────────

IMAGE        ?= sftpgo
TAG_PREFIX   ?= local
COMMIT_SHA   ?= $(shell git describe --always --abbrev=8 --dirty)
PLATFORM     ?= linux/$(shell go env GOARCH 2>/dev/null || uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

# Common build-args shared by every variant
COMMON_ARGS  = --build-arg COMMIT_SHA=$(COMMIT_SHA)

# ── Debian (full) ─────────────────────────────────────────────────────────────
.PHONY: docker-debian
docker-debian:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=true \
		--build-arg DOWNLOAD_PLUGINS=false \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules,unixcrypt" \
		--platform $(PLATFORM) \
		-f Dockerfile \
		-t $(IMAGE):$(TAG_PREFIX) \
		-t $(IMAGE):$(TAG_PREFIX)-debian \
		.

# ── Debian (slim) ────────────────────────────────────────────────────────────
.PHONY: docker-debian-slim
docker-debian-slim:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=false \
		--build-arg DOWNLOAD_PLUGINS=false \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules,unixcrypt" \
		--platform $(PLATFORM) \
		-f Dockerfile \
		-t $(IMAGE):$(TAG_PREFIX)-slim \
		-t $(IMAGE):$(TAG_PREFIX)-debian-slim \
		.

# ── Alpine (full) ────────────────────────────────────────────────────────────
.PHONY: docker-alpine
docker-alpine:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=true \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules" \
		--platform $(PLATFORM) \
		-f Dockerfile.alpine \
		-t $(IMAGE):$(TAG_PREFIX)-alpine \
		.

# ── Alpine (slim) ────────────────────────────────────────────────────────────
.PHONY: docker-alpine-slim
docker-alpine-slim:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=false \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules" \
		--platform $(PLATFORM) \
		-f Dockerfile.alpine \
		-t $(IMAGE):$(TAG_PREFIX)-alpine-slim \
		.

# ── Distroless (no CGO / no SQLite) ──────────────────────────────────────────
.PHONY: docker-distroless
docker-distroless:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=false \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules,nosqlite" \
		--platform $(PLATFORM) \
		-f Dockerfile.distroless \
		-t $(IMAGE):$(TAG_PREFIX)-distroless \
		.

# ── Debian + Plugins (full) ──────────────────────────────────────────────────
.PHONY: docker-plugins
docker-plugins:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=true \
		--build-arg DOWNLOAD_PLUGINS=true \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules,unixcrypt" \
		--platform $(PLATFORM) \
		-f Dockerfile \
		-t $(IMAGE):$(TAG_PREFIX)-plugins \
		.

# ── Debian + Plugins (slim) ──────────────────────────────────────────────────
.PHONY: docker-plugins-slim
docker-plugins-slim:
	docker build \
		$(COMMON_ARGS) \
		--build-arg INSTALL_OPTIONAL_PACKAGES=false \
		--build-arg DOWNLOAD_PLUGINS=true \
		--build-arg FEATURES="nopgxregisterdefaulttypes,disable_grpc_modules,unixcrypt" \
		--platform $(PLATFORM) \
		-f Dockerfile \
		-t $(IMAGE):$(TAG_PREFIX)-plugins-slim \
		.

# ── Build all variants ───────────────────────────────────────────────────────
.PHONY: docker-all
docker-all: docker-debian docker-debian-slim docker-alpine docker-alpine-slim docker-distroless docker-plugins docker-plugins-slim

# ── Helpers ───────────────────────────────────────────────────────────────────
.PHONY: docker-run
docker-run:
	@echo "Starting $(IMAGE):$(TAG_PREFIX) ..."
	docker run --rm -it \
		-p 8080:8080 \
		-p 2022:2022 \
		$(IMAGE):$(TAG_PREFIX)

.PHONY: help
help:
	@echo ""
	@echo "SFTPGo Docker build targets (mirrors CI docker.yml):"
	@echo ""
	@echo "  docker-debian          Debian full (jq installed)"
	@echo "  docker-debian-slim     Debian slim"
	@echo "  docker-alpine          Alpine full (jq installed)"
	@echo "  docker-alpine-slim     Alpine slim"
	@echo "  docker-distroless      Distroless (no SQLite)"
	@echo "  docker-plugins         Debian + official plugins"
	@echo "  docker-plugins-slim    Debian + official plugins, slim"
	@echo "  docker-all             Build every variant above"
	@echo "  docker-run             Run the default debian image"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE=$(IMAGE)"
	@echo "  TAG_PREFIX=$(TAG_PREFIX)"
	@echo "  COMMIT_SHA=$(COMMIT_SHA)"
	@echo "  PLATFORM=$(PLATFORM)"
	@echo ""
