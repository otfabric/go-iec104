# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build examples fmt fmt-check lint lint-ci vet vuln test e2e coverage coverage-check coverage-pkg-check coverpkg-check cover bench fuzz chaos cross check clean interop test-interop
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
TEST_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/internal/testutil' | grep -v '/internal/station')

# Coverage counts these production packages, measured together, so that the
# e2e suite counts for the packages it exercises. Exclusions: TESTING.md.
COVER_PKGS := $(shell go list ./... | grep -v -e '/examples' -e '/internal/testutil' -e '/internal/station' -e '/e2e' -e '/interop' | paste -sd, -)

# Build tag of the interop package (excluded from default ./... builds).
INTEROP_TAGS := interop

# Reference implementations for 'make interop': otfabric/iec104-interop v0.3.1
# (lib60870-C v2.4.1, OpenMUC j60870 1.8.0, wendy512/iec104 v1.0.4 on
# go-iecp5 v1.2.6, cB-Sigma/iec60870 v0.3.0 with IEC 62351-5), pinned by
# multi-arch index digest.
# Keep in step with interop/harness.go. Override to test other builds, e.g.
#   make interop IEC104_INTEROP_OPENMUC_IMAGE=ghcr.io/otfabric/iec104-interop-openmuc:dev
IEC104_INTEROP_LIB60870_IMAGE ?= ghcr.io/otfabric/iec104-interop-lib60870@sha256:70585582d81d84fda35cc6d9099b39f783e4afd5ef639116778eac8c6c8395c4
IEC104_INTEROP_OPENMUC_IMAGE  ?= ghcr.io/otfabric/iec104-interop-openmuc@sha256:7db0fb30ad3ed456b1fa006387920d35ebd804293da1489531a04cafaa600000
IEC104_INTEROP_WENDY512_IMAGE ?= ghcr.io/otfabric/iec104-interop-wendy512@sha256:8269dcbbd5e994bf8adf8de25f9c422df68d6c1bc2e54218ad2802103cb56640
IEC104_INTEROP_CBSIGMA_IMAGE  ?= ghcr.io/otfabric/iec104-interop-cbsigma@sha256:4c05e091ef8fc41d6b24ff58edac0493d78452dc0d509f20416fde0908d250a2

all: build ## Default target: build the examples

build: ## Build the example client and server into ./bin
	@echo "Building examples"
	@mkdir -p $(BIN_DIR)
	@for dir in examples/*/; do \
		name="$$(basename "$$dir")"; \
		go build -o "$(BIN_DIR)/example-$$name" "./$$dir"; \
	done

# The self-contained examples: each starts both sides and exits by itself.
RUN_EXAMPLES := quickstart commands files events redundancy tls secure observability

examples: ## Run the self-contained examples (each must exit successfully)
	@for e in $(RUN_EXAMPLES); do \
		echo "Running example $$e"; \
		go run ./examples/$$e >/dev/null || { echo "example $$e failed"; exit 1; }; \
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

e2e: ## Run the end-to-end suite: go-iec104 client against go-iec104 server on loopback
	@echo "Running end-to-end tests"
	@go test -count=1 -race ./e2e/...

coverage: ## Run tests with coverage on the library packages (writes coverage.out)
	@echo "Running coverage"
	@go test -count=1 -race -coverprofile=coverage.out -covermode=atomic -coverpkg=$(COVER_PKGS) $(TEST_PKGS)

# Same floor as coverage-min in .github/workflows/ci.yml.
COVER_MIN := 90
# Per-package floor (TEST-012): the lowest package measures 94.6 %. Needs the
# -coverpkg coverage.out of `make coverage`.
COVER_PKG_MIN := 90
coverage-check: coverage ## Fail if total coverage of the library packages is below COVER_MIN
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t+0 < m+0) { printf "coverage %.1f%% < %s%%\n", t, m; exit 1 } else printf "coverage %.1f%% >= %s%%\n", t, m }'

coverage-pkg-check: coverage ## Fail when a package is below COVER_PKG_MIN
	@awk -v m="$(COVER_PKG_MIN)" 'NR > 1 { n[$$1] = $$2; if ($$3 > 0) h[$$1] = 1 } \
	END { for (k in n) { p = k; sub(/\/[^\/]*$$/, "", p); s[p] += n[k]; if (k in h) c[p] += n[k] } \
	for (p in s) { v = 100 * c[p] / s[p]; if (v < m) { printf "%s: %.1f%% < %s%%\n", p, v, m; bad = 1 } } exit bad }' coverage.out

coverpkg-check: ## Fail if CI's coverpkg differs from COVER_PKGS
	@ci=$$(sed -nE 's/^ *coverpkg: *"?([^"]*)"?/\1/p' .github/workflows/ci.yml | head -1); \
	[ "$$ci" = "$(COVER_PKGS)" ] || { echo "ci.yml coverpkg differs from COVER_PKGS"; exit 1; }

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

bench: ## Run the codec benchmarks
	@echo "Running benchmarks"
	@go test -count=1 -run='^$$' -bench=. -benchmem ./apci ./asdu

# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 30s
fuzz: ## Run every Fuzz target for FUZZTIME (targets discovered, never listed)
	@echo "Fuzzing (FUZZTIME=$(FUZZTIME))"
	@for pkg in $(TEST_PKGS); do \
		for t in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "fuzz $$pkg $$t"; \
			go test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

# Seconds of each chaos seed and number of seeds. The defaults are the nightly run's.
CHAOS_SECONDS ?= 30
CHAOS_SEEDS ?= 20
chaos: ## Run the chaos test for CHAOS_SEEDS seeds of CHAOS_SECONDS each
	@E2E_CHAOS_SECONDS=$(CHAOS_SECONDS) E2E_CHAOS_SEEDS=$(CHAOS_SEEDS) go test -count=1 -race -timeout=60m -run '^TestChaos$$' ./e2e/

cross: ## Cross-compile without cgo (build only, the tests do not run there)
	@for p in linux/amd64 linux/arm64 linux/arm darwin/arm64 windows/amd64; do \
		echo "Building $$p"; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go build ./... || exit 1; \
	done

test-interop: ## Run the interop suite against the lib60870, OpenMUC, wendy512 and cB-Sigma reference images (needs Docker)
	@echo "Running interop tests against $(IEC104_INTEROP_LIB60870_IMAGE), $(IEC104_INTEROP_OPENMUC_IMAGE), $(IEC104_INTEROP_WENDY512_IMAGE) and $(IEC104_INTEROP_CBSIGMA_IMAGE)"
	@IEC104_INTEROP_LIB60870_IMAGE="$(IEC104_INTEROP_LIB60870_IMAGE)" \
		IEC104_INTEROP_OPENMUC_IMAGE="$(IEC104_INTEROP_OPENMUC_IMAGE)" \
		IEC104_INTEROP_WENDY512_IMAGE="$(IEC104_INTEROP_WENDY512_IMAGE)" \
		IEC104_INTEROP_CBSIGMA_IMAGE="$(IEC104_INTEROP_CBSIGMA_IMAGE)" \
		go test -tags=$(INTEROP_TAGS) -count=1 -timeout=20m ./interop/...

interop: test-interop ## Alias for test-interop

test-cbsigma: ## Run the IEC 62351-5 differential tests against cB-Sigma/iec60870 (a module of its own, needs Go 1.26)
	@echo "Running the application-layer security tests against cB-Sigma/iec60870"
	@cd interop/cbsigma && go test -count=1 -race ./...

check: fmt fmt-check lint lint-ci vet vuln test coverpkg-check coverage-pkg-check examples ## Run format + lint + vet + vuln + test + per-package coverage

clean: ## Remove generated binaries and coverage artifacts
	@echo "Cleaning up"
	@rm -rf $(BIN_DIR) coverage.out coverage.html
