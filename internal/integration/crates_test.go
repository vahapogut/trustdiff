//go:build integration

package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/crates"
)

// TestCratesSerde reads the crate document, the owners, the latest version with
// its dependencies and the 90-day download figure of serde.
func TestCratesSerde(t *testing.T) {
	ctx, l := start(t)
	client := crates.New(l.http, crates.WithLogger(l.log))

	list, err := client.Versions(ctx, "serde")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Ecosystem != model.Cargo || list.Name != "serde" {
		t.Errorf("list is %s:%s, want cargo:serde", list.Ecosystem, list.Name)
	}
	if len(list.Versions) == 0 {
		t.Fatal("no versions listed")
	}
	if list.Latest == "" {
		t.Fatal("max_stable_version is empty")
	}
	latest := registry.Find(list, list.Latest)
	if latest == nil {
		t.Fatalf("latest %s is not in the version list", list.Latest)
	}
	if latest.PublishedAt.IsZero() {
		t.Errorf("serde %s has no publish time", list.Latest)
	}

	owners, err := client.Owners(ctx, "serde")
	if err != nil {
		t.Fatalf("Owners: %v", err)
	}
	if len(owners) == 0 {
		t.Error("owners list is empty")
	}

	// The archive inspection can fail on its own (size cap, checksum, a static
	// host hiccup) and still return the version; that is a diagnostic here, not
	// a failure, since the shape under test is the dependencies list.
	info, err := client.VersionInfo(ctx, latest.Ref)
	if err != nil && !errors.Is(err, crates.ErrNotInspected) {
		t.Fatalf("VersionInfo(%s): %v", latest.Ref, err)
	}
	if err != nil {
		t.Logf("archive not inspected: %v", err)
	}
	if info == nil {
		t.Fatalf("VersionInfo(%s) returned no version", latest.Ref)
	}
	if info.Ref != latest.Ref {
		t.Errorf("VersionInfo returned %s, want %s", info.Ref, latest.Ref)
	}
	if len(info.Dependencies) == 0 {
		t.Errorf("serde %s lists no normal dependencies", list.Latest)
	}

	downloads, err := client.Downloads(ctx, "serde")
	if err != nil {
		t.Fatalf("Downloads: %v", err)
	}
	if downloads <= 0 {
		t.Errorf("weekly downloads = %d, want above zero", downloads)
	}
}

// TestCratesRateLimit checks that two requests to crates.io leave the client at
// least 900 ms apart. The limiter lives in internal/httpcache (one request per
// second for the host crates.io, burst one), and the recorder behind the client
// timestamps each request as it enters the transport, so the gap is measured on
// the client before anything goes on the wire. The two calls read different
// documents, since a second read of the same one would be a cache hit and never
// reach the limiter.
func TestCratesRateLimit(t *testing.T) {
	ctx, l := start(t)
	client := crates.New(l.http, crates.WithLogger(l.log))

	if _, err := client.Versions(ctx, "serde"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if _, err := client.Owners(ctx, "serde"); err != nil {
		t.Fatalf("Owners: %v", err)
	}
	sent := l.rec.toHost("crates.io")
	if len(sent) < 2 {
		t.Fatalf("%d requests reached crates.io, want at least 2", len(sent))
	}
	const minGap = 900 * time.Millisecond
	if gap := sent[1].at.Sub(sent[0].at); gap < minGap {
		t.Errorf("second crates.io request left %v after the first, want at least %v", gap, minGap)
	}
}
