//go:build integration

package integration

import (
	"errors"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/pypi"
)

// TestPyPIRequests reads the project and the latest release of requests, a
// project with many releases whose latest one declares dependencies, and checks
// that download counts are reported as unsupported, which is what the JSON API
// offers (every count is -1).
func TestPyPIRequests(t *testing.T) {
	ctx, l := start(t)
	client := pypi.New(l.http, pypi.WithLogger(l.log))

	list, err := client.Versions(ctx, "requests")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Ecosystem != model.PyPI || list.Name != "requests" {
		t.Errorf("list is %s:%s, want pypi:requests", list.Ecosystem, list.Name)
	}
	if len(list.Versions) == 0 {
		t.Fatal("no releases listed")
	}
	if list.Latest == "" {
		t.Fatal("info.version is empty")
	}
	latest := registry.Find(list, list.Latest)
	if latest == nil {
		t.Fatalf("latest %s is not in the release list", list.Latest)
	}
	if latest.PublishedAt.IsZero() {
		t.Errorf("requests %s has no upload time", list.Latest)
	}

	info, err := client.VersionInfo(ctx, latest.Ref)
	if err != nil {
		t.Fatalf("VersionInfo(%s): %v", latest.Ref, err)
	}
	if info.Ref != latest.Ref {
		t.Errorf("VersionInfo returned %s, want %s", info.Ref, latest.Ref)
	}
	if len(info.Dependencies) == 0 {
		t.Errorf("requests %s has an empty requires_dist", list.Latest)
	}

	if _, err := client.Downloads(ctx, "requests"); !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("Downloads error = %v, want registry.ErrUnsupported", err)
	}
}
