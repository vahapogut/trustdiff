include tools.mk

MODULE   := github.com/vahapogut/trustdiff
BIN      := trustdiff
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)
LDFLAGS  := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

export CGO_ENABLED = 0

.PHONY: build test test-integration lint vet vuln sec snapshot fixture demo clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/trustdiff

test:
	go test ./...

test-integration:
	go test -tags integration ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

vuln:
	govulncheck ./...

sec:
	gosec -quiet ./...

snapshot:
	goreleaser release --snapshot --clean --skip=sign,publish,sbom

# Record one live response into testdata: make fixture URL=https://... OUT=internal/.../testdata/x.json
fixture:
	go run ./scripts/record-fixture $(URL) $(OUT)

# Run the tool on testdata/demo-repo, whose head lockfile adds a young package with
# a postinstall script, and print the human report (docs/demo-repo.md explains it).
# The run never touches the network and says the same thing on every machine on
# every day: --offline forbids every request, TRUSTDIFF_NOW pins the clock, and the
# one registry answer the demo needs is seeded from testdata/demo-repo/cache into a
# throwaway cache directory, which is also why TRUSTDIFF_CACHE_DIR never points at
# the developer's own cache. Findings are what the demo is for, so its exit code is
# reported rather than inherited: a blocking finding must not fail make.
demo:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT INT TERM && \
	cp testdata/demo-repo/cache/* "$$tmp/" && \
	TRUSTDIFF_NOW=2026-09-09T12:00:00Z TRUSTDIFF_CACHE_DIR="$$tmp" \
	  go run ./cmd/trustdiff diff \
	    --base-file testdata/demo-repo/base/package-lock.json \
	    testdata/demo-repo/head/package-lock.json \
	    --policy testdata/demo-repo/.trustdiff.yaml \
	    --offline --format human; \
	code=$$?; \
	echo; \
	echo "trustdiff exited $$code (0 nothing blocking, 1 blocking findings, 2 usage, 3 data unavailable)"

clean:
	rm -rf bin dist
