//go:build integration

package integration

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
)

// TestNPMExpress reads the packument and the download count of express, a
// package with hundreds of releases whose latest version always carries a
// publish time and an _npmUser.
func TestNPMExpress(t *testing.T) {
	ctx, l := start(t)
	client := npm.New(l.http, npm.WithLogger(l.log))

	list, err := client.Versions(ctx, "express")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Ecosystem != model.NPM || list.Name != "express" {
		t.Errorf("list is %s:%s, want npm:express", list.Ecosystem, list.Name)
	}
	if n := len(list.Versions); n < 100 {
		t.Errorf("express lists %d versions, want at least 100", n)
	}
	if list.Latest == "" {
		t.Fatal("dist-tags.latest is empty")
	}
	latest := registry.Find(list, list.Latest)
	if latest == nil {
		t.Fatalf("latest %s is not in the version list", list.Latest)
	}
	if latest.PublishedAt.IsZero() {
		t.Errorf("express@%s has no publish time", list.Latest)
	}
	if latest.Publisher == nil || latest.Publisher.Name == "" {
		t.Errorf("express@%s has no publisher (_npmUser)", list.Latest)
	}

	info, err := client.VersionInfo(ctx, latest.Ref)
	if err != nil {
		t.Fatalf("VersionInfo(%s): %v", latest.Ref, err)
	}
	if info.Ref != latest.Ref {
		t.Errorf("VersionInfo returned %s, want %s", info.Ref, latest.Ref)
	}
	if len(info.Dependencies) == 0 {
		t.Errorf("express@%s declares no dependencies", list.Latest)
	}

	downloads, err := client.Downloads(ctx, "express")
	if err != nil {
		t.Fatalf("Downloads: %v", err)
	}
	if downloads <= 0 {
		t.Errorf("weekly downloads = %d, want above zero", downloads)
	}
}

// TestNPMScopedPackage resolves a scoped name and checks the encoding on the
// wire: the registry wants the scope separator as %2F, the downloads API wants
// it as a plain slash (both documented, both re-verified live on 2026-09-09 in
// the npm client).
func TestNPMScopedPackage(t *testing.T) {
	ctx, l := start(t)
	client := npm.New(l.http, npm.WithLogger(l.log))
	const name = "@types/node"

	list, err := client.Versions(ctx, name)
	if err != nil {
		t.Fatalf("Versions(%s): %v", name, err)
	}
	if list.Name != name {
		t.Errorf("list name = %q, want %q", list.Name, name)
	}
	if len(list.Versions) == 0 {
		t.Error("no versions listed")
	}
	if list.Latest == "" {
		t.Error("dist-tags.latest is empty")
	} else if registry.Find(list, list.Latest) == nil {
		t.Errorf("latest %s is not in the version list", list.Latest)
	}
	sent := l.rec.toHost("registry.npmjs.org")
	if len(sent) == 0 {
		t.Fatal("no request reached registry.npmjs.org")
	}
	if got, want := sent[0].path, "/@types%2Fnode"; got != want {
		t.Errorf("packument path = %q, want %q", got, want)
	}

	downloads, err := client.Downloads(ctx, name)
	if err != nil {
		t.Fatalf("Downloads(%s): %v", name, err)
	}
	if downloads <= 0 {
		t.Errorf("weekly downloads = %d, want above zero", downloads)
	}
	sent = l.rec.toHost("api.npmjs.org")
	if len(sent) == 0 {
		t.Fatal("no request reached api.npmjs.org")
	}
	if got, want := sent[0].path, "/downloads/point/last-week/@types/node"; got != want {
		t.Errorf("downloads path = %q, want %q", got, want)
	}
}
