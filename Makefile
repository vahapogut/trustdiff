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

.PHONY: build test test-integration lint vet vuln sec snapshot clean

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
	goreleaser release --snapshot --clean --skip=sign,publish

clean:
	rm -rf bin dist
