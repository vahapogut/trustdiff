//go:build integration

package integration

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
)

// TestDepsDevVersionBatch resolves the latest express from the registry and asks
// deps.dev about that exact version: it must be known there with a publish
// time. deps.dev indexes with a small lag, so a failure in the hours after an
// express release means the lag, not a shape change; rerun before digging.
func TestDepsDevVersionBatch(t *testing.T) {
	ctx, l := start(t)
	reg := npm.New(l.http, npm.WithLogger(l.log))
	list, err := reg.Versions(ctx, "express")
	if err != nil {
		t.Fatalf("npm Versions: %v", err)
	}
	if list.Latest == "" {
		t.Fatal("dist-tags.latest is empty")
	}
	ref := model.PackageRef{Ecosystem: model.NPM, Name: "express", Version: list.Latest}

	client := depsdev.New(l.http, depsdev.WithLogger(l.log))
	facts, err := client.Versions(ctx, []model.PackageRef{ref})
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	f, ok := facts[ref]
	if !ok {
		t.Fatalf("no entry for %s in %d answers", ref, len(facts))
	}
	if !f.Found {
		t.Fatalf("%s is not known to deps.dev", ref)
	}
	if f.PublishedAt.IsZero() {
		t.Errorf("%s has no publishedAt", ref)
	}
}
