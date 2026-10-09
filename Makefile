# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build fmt fmt-check lint lint-ci vet vuln test coverage cover bench fuzz check clean interop test-interop
help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Parent otfabric/go.work does not list this module; isolate toolchain commands.
export GOWORK := off

# CI formats and lints with the Go version from go.mod, not with the toolchain installed here.
# gofmt's output changes between Go releases (comment alignment, for one), so formatting is
# done with that version, and `fmt-check` also requires the local gofmt to agree: a file that
# two versions format differently fails CI on one side or the other.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

# Output directory for generated binaries
BIN_DIR := bin
# Library packages: tests and coverage (exclude examples and test helpers)
TEST_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/internal/testutil')

# Build tag of the interop package (excluded from default ./... builds).
INTEROP_TAGS := interop

# Reference implementations for 'make interop': otfabric/iec104-interop v0.1.0
# (lib60870-C v2.4.1, OpenMUC j60870 1.7.2), pinned by multi-arch index digest.
# Keep in step with interop/harness.go. Override to test other builds, e.g.
#   make interop IEC104_INTEROP_OPENMUC_IMAGE=ghcr.io/otfabric/iec104-interop-openmuc:dev
IEC104_INTEROP_LIB60870_IMAGE ?= ghcr.io/otfabric/iec104-interop-lib60870@sha256:a1fbb44a16da39d5aa3f387456d1f2931811556e5a4298797a6b4ea64c4ef248
IEC104_INTEROP_OPENMUC_IMAGE  ?= ghcr.io/otfabric/iec104-interop-openmuc@sha256:e1d15745d5e2005692f2844fb91c477826930b23fb772de14beb07da1942aa1a

all: build ## Default target: build the examples

build: ## Build the example client and server into ./bin
	@echo "Building examples"
	@mkdir -p $(BIN_DIR)
	@for dir in examples/*/; do \
		name="$$(basename "$$dir")"; \
		go build -o "$(BIN_DIR)/example-$$name" "./$$dir"; \
	done

fmt: ## Format Go code with the gofmt of the Go version in go.mod (what CI uses)
	@echo "Running gofmt (go$(GO_MOD_VERSION))"
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if the go.mod-version gofmt or the local gofmt would change any file
	@echo "Checking formatting (gofmt go$(GO_MOD_VERSION) and local $$(go env GOVERSION))"
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then \
		[ -z "$$ci" ] || { echo "Not formatted for gofmt go$(GO_MOD_VERSION) (CI):"; echo "$$ci"; }; \
		[ -z "$$loc" ] || { echo "Not formatted for the local gofmt:"; echo "$$loc"; }; \
		echo "Files must be stable under both. Run 'make fmt'; if the two versions still disagree,"; \
		echo "restructure the code they format differently (e.g. move trailing comments onto their own lines)."; \
		exit 1; \
	fi

lint: ## Run staticcheck (includes -tags=interop for ./interop)
	@echo "Running staticcheck"
	@staticcheck -tags=$(INTEROP_TAGS) ./...

lint-ci: ## Run golangci-lint (build-tags include interop; see .golangci.yml)
	@echo "Running golangci-lint"
	@golangci-lint run ./...

vet: ## Run go vet (includes -tags=interop compile of ./interop)
	@echo "Running go vet"
	@go vet -tags=$(INTEROP_TAGS) ./...

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...

test: ## Run the library tests with the race detector
	@echo "Running tests"
	@go test -count=1 -race $(TEST_PKGS)

coverage: ## Run tests with coverage on the library packages (writes coverage.out)
	@echo "Running coverage"
	@go test -count=1 -race -coverprofile=coverage.out -covermode=atomic $(TEST_PKGS)

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

bench: ## Run the codec benchmarks
	@echo "Running benchmarks"
	@go test -count=1 -run='^$$' -bench=. -benchmem ./apci ./asdu

# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 30s
fuzz: ## Run the codec fuzz targets for FUZZTIME each (default 30s)
	@echo "Fuzzing (FUZZTIME=$(FUZZTIME))"
	@go test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./apci
	@go test -run='^$$' -fuzz='^FuzzDecode$$' -fuzztime=$(FUZZTIME) ./asdu

test-interop: ## Run the interop suite against the lib60870 and OpenMUC reference images (needs Docker)
	@echo "Running interop tests against $(IEC104_INTEROP_LIB60870_IMAGE) and $(IEC104_INTEROP_OPENMUC_IMAGE)"
	@IEC104_INTEROP_LIB60870_IMAGE="$(IEC104_INTEROP_LIB60870_IMAGE)" \
		IEC104_INTEROP_OPENMUC_IMAGE="$(IEC104_INTEROP_OPENMUC_IMAGE)" \
		go test -tags=$(INTEROP_TAGS) -count=1 -timeout=20m ./interop/...

interop: test-interop ## Alias for test-interop

check: fmt fmt-check lint lint-ci vet vuln test coverage ## Run format + lint + vet + vuln + test

clean: ## Remove generated binaries and coverage artifacts
	@echo "Cleaning up"
	@rm -rf $(BIN_DIR) coverage.out coverage.html
