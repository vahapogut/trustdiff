// Package integration holds the live tests: the registry clients (npm, PyPI,
// crates.io), the advisory clients (OSV.dev, deps.dev) and the check runner end
// to end, run against the public services instead of the recorded fixtures the
// unit tests use. They exist to notice when a service changes shape under the
// code, which a fixture cannot, so they assert on shape only (a list is there, a
// count is above zero, a time is set, a name was encoded the way the registry
// wants) and never on values that drift from one week to the next.
//
// Every test file carries the integration build tag, so go test ./... never
// reaches the network. Run them deliberately with
//
//	go test -tags integration ./internal/integration/...
//
// or with make test-integration; the integration job in .github/workflows/ci.yml
// runs them on the weekly schedule and on manual dispatch. Setting
// TRUSTDIFF_INTEGRATION_OFFLINE to a non-empty value skips every test. Each test
// runs under a 60 second deadline with a cache directory of its own under
// t.TempDir(), and nothing outside that directory is written.
//
// This file carries no build tag so that the package exists for go vet ./...
// and golangci-lint without one.
package integration
