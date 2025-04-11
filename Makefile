GO_FILES ?= $$(find . -name '*.go' | grep -v generated)
SHELL := /bin/bash

$(TARGETS): .dapper docker.sock
	./.dapper $@

.PHONY: deps
deps:
	go mod tidy

release:
	./scripts/release.sh

build/data:
	mkdir -p $@

.PHONY: binary-size-check
binary-size-check:
	scripts/binary_size_check.sh

.PHONY: image-scan
image-scan:
	scripts/image_scan.sh $(IMAGE)

format:
	gofmt -s -l -w $(GO_FILES)
	goimports -w $(GO_FILES)


.PHONY: local-validate
local-validate:
	DOCKER_BUILDKIT=1 docker build \
		--build-arg="SKIP_VALIDATE=$(SKIP_VALIDATE)" \
		--build-arg="DEBUG=$(DEBUG)" \
		--progress=plain \
		-f Dockerfile.local --target=validate .

.PHONY: local-binary
local-binary:
	@echo "INFO: Building K3s binaries and assets..."
	. ./scripts/git_version.sh && \
	DOCKER_BUILDKIT=1 docker build \
		--build-arg "GIT_TAG=$$GIT_TAG" \
		--build-arg "TREE_STATE=$$TREE_STATE" \
		--build-arg "COMMIT=$$COMMIT" \
		--build-arg "DIRTY=$$DIRTY" \
		--build-arg="GOCOVER=$(GOCOVER)" \
		--build-arg="GOOS=$(GOOS)" \
		--build-arg="DEBUG=$(DEBUG)" \
		-f Dockerfile.local --target=result --output=. .

.PHONY: local-image
local-image: local-binary
	@echo "INFO: Building K3s image..."
	./scripts/package-image

.PHONY: local-airgap
local-airgap: 
	@echo "INFO: Building K3s airgap tarball..."
	./scripts/package-airgap

.PHONY: local-ci
local-ci:  local-binary local-image local-airgap