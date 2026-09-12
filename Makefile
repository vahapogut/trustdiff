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

# Every target that runs a pinned tool names it through tools.mk rather than
# through PATH, so "make tools" is the whole of the setup: a machine that has run
# it can lint, scan and build a release snapshot without touching its PATH. vet and
# the test targets call the go tool itself, which is already there by definition.
lint:
	"$(TOOLS_BIN)/golangci-lint" run ./...

vet:
	go vet ./...

vuln:
	"$(TOOLS_BIN)/govulncheck" ./...

sec:
	"$(TOOLS_BIN)/gosec" -quiet ./...

snapshot:
	"$(TOOLS_BIN)/goreleaser" release --snapshot --clean --skip=sign,publish,sbom

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
#
# The binary is built on its own line rather than run with "go run", for two
# reasons: "go run" exits 1 for every non-zero status of the program it runs, so
# the line below would report 1 for trustdiff's 1, 2 and 3 alike, and it exits 1
# for a build failure too, which would be reported as a finding of a run that
# never happened. A build failure now stops the recipe before anything is
# reported, and the code printed is the tool's own.
demo:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT INT TERM && \
	mkdir -p "$$tmp/cache" && \
	go build -o "$$tmp/$(BIN)" ./cmd/trustdiff && \
	cp testdata/demo-repo/cache/* "$$tmp/cache/" && \
	{ TRUSTDIFF_NOW=2026-09-09T12:00:00Z TRUSTDIFF_CACHE_DIR="$$tmp/cache" \
	    "$$tmp/$(BIN)" diff \
	      --base-file testdata/demo-repo/base/package-lock.json \
	      testdata/demo-repo/head/package-lock.json \
	      --policy testdata/demo-repo/.trustdiff.yaml \
	      --offline --format human; \
	  code=$$?; \
	  echo; \
	  echo "trustdiff exited $$code (0 nothing blocking, 1 blocking findings, 2 usage, 3 data unavailable)"; }

clean:
	rm -rf bin dist
