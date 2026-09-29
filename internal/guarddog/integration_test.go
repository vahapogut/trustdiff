//go:build integration

package guarddog

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// This is an opt-in real sandboxed scan of a small, established npm release.
// It downloads package source and metadata, but never installs the target or
// executes its code. The enabled test must fail if the actual sandbox is absent.
func TestIntegrationRealGuardDogSandbox(t *testing.T) {
	if os.Getenv("TRUSTDIFF_GUARDDOG_INTEGRATION") != "1" {
		t.Skip("set TRUSTDIFF_GUARDDOG_INTEGRATION=1 to run the real sandboxed scanner")
	}
	if !supportedHost() {
		t.Skip("real GuardDog handoff requires Linux or macOS")
	}
	if os.Getenv("TRUSTDIFF_INTEGRATION_OFFLINE") != "" {
		t.Skip("live registry integration is disabled")
	}
	client, err := New(Options{Binary: os.Getenv("TRUSTDIFF_GUARDDOG_BIN")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), DefaultTimeout+5*time.Second)
	defer cancel()
	ref := model.MustParseRef("npm:is-number@7.0.0")
	start := time.Now()
	got, err := client.Scan(ctx, ref)
	if err != nil {
		t.Fatalf("real GuardDog scan: %v; status=%s, reported errors=%v", err, got.Status, got.Errors)
	}
	if got.Status != "completed" || got.Ref != ref || got.ToolVersion != SupportedVersion || got.Source != SourceURL || len(got.Errors) != 0 {
		t.Fatalf("real GuardDog identity or coverage mismatch: %+v", got)
	}
	if time.Since(start) > DefaultTimeout+5*time.Second {
		t.Fatal("real scanner exceeded the configured deadline and cleanup allowance")
	}
	data, err := json.Marshal(got)
	if err != nil || len(data) > maxStdout+4096 {
		t.Fatalf("invalid or unbounded result: bytes=%d, error=%v", len(data), err)
	}
	if strings.Contains(string(data), "trustdiff-guarddog-") {
		t.Fatal("real scanner result leaked a volatile working-directory prefix")
	}
	// Rule findings can change with metadata and installed rule data. Assert the
	// contract and coverage rather than assuming even a benign package has zero.
	t.Logf("GuardDog %s completed %s with %d reported issue(s), %d matched rules and %d risks", got.ToolVersion, ref, got.Issues, len(got.Results), len(got.Risks))
}
