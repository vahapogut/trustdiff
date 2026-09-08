# Pinned developer tools. Versions checked against upstream releases on 2026-09-09.
# `make tools` installs them into $(go env GOPATH)/bin; add that directory to PATH.

GOLANGCI_LINT_VERSION ?= v2.13.2
GORELEASER_VERSION    ?= v2.18.1
COSIGN_VERSION        ?= v3.1.3
GOVULNCHECK_VERSION   ?= v1.8.0
GOSEC_VERSION         ?= v2.29.0
STATICCHECK_VERSION   ?= 2026.2.1

.PHONY: tools
tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)
	go install github.com/sigstore/cosign/v3/cmd/cosign@$(COSIGN_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
