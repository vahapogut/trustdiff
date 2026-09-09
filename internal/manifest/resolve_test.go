package manifest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// errRegistryDown is what a registry that could not be consulted answers, as
// against ErrNotFound, which is an answer.
var errRegistryDown = errors.New("connection refused")

// published is one version a fake registry lists.
type published struct {
	version string
	yanked  bool
}

// fakeSource is a registry that answers from a table and never touches the network.
// A name it does not hold is not found; a name in errs fails the way an outage does.
type fakeSource struct {
	lists map[string]*registry.VersionList
	errs  map[string]error
}

func (f *fakeSource) Versions(_ context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	if err, ok := f.errs[name]; ok {
		return nil, err
	}
	list, ok := f.lists[name]
	if !ok {
		return nil, registry.ErrNotFound
	}
	if list.Ecosystem == "" {
		list.Ecosystem = eco
	}
	return list, nil
}

// newSource builds a fake registry from a table of package to versions.
func newSource(eco model.Ecosystem, packages map[string][]published) *fakeSource {
	lists := make(map[string]*registry.VersionList, len(packages))
	for name, versions := range packages {
		list := &registry.VersionList{Ecosystem: eco, Name: name}
		for _, v := range versions {
			list.Versions = append(list.Versions, model.VersionInfo{
				Ref:             model.PackageRef{Ecosystem: eco, Name: name, Version: v.version},
				Yanked:          v.yanked,
				WeeklyDownloads: -1,
			})
		}
		lists[name] = list
	}
	return &fakeSource{lists: lists, errs: map[string]error{}}
}

// declare builds one declaration by hand, the way a reader would.
func declare(eco model.Ecosystem, name string, syntax Syntax, text string) Declaration {
	return Declaration{
		Ref:    model.PackageRef{Ecosystem: eco, Name: name},
		Range:  text,
		Syntax: syntax,
		Table:  TableDependencies,
	}
}

// npmVersions is the history the resolution tests below are asked about: releases,
// a prerelease newer than all of them, and a yanked release at the top of the 5.x
// line, which is the case a resolver must not walk into.
var npmVersions = map[string][]published{
	"lib": {
		{version: "1.0.0"},
		{version: "1.2.3"},
		{version: "1.9.9"},
		{version: "2.0.0"},
		{version: "2.1.0"},
		{version: "3.0.0-rc.1"},
	},
	"yanked-lib": {
		{version: "0.3.0"},
		{version: "0.4.0", yanked: true},
	},
	"prerelease-lib": {
		{version: "1.0.0-alpha.1"},
		{version: "1.0.0-alpha.2"},
	},
	"empty-lib": {},
}

func TestResolvePicksTheHighestSatisfyingVersion(t *testing.T) {
	src := newSource(model.NPM, npmVersions)
	tests := []struct {
		name  string
		text  string
		want  string
		skip  string
		outer bool
	}{
		{name: "a caret range takes the top of its major", text: "^1.0.0", want: "1.9.9"},
		{name: "a tilde range takes the top of its minor", text: "~1.2.0", want: "1.2.3"},
		{name: "an open range takes the newest release", text: "*", want: "2.1.0"},
		{name: "an exact version takes that version", text: "1.2.3", want: "1.2.3"},
		{name: "a prerelease is left out when the range does not name one", text: ">=2.0.0", want: "2.1.0"},
		{name: "a prerelease is taken when the range names one", text: ">=3.0.0-0", want: "3.0.0-rc.1"},
		{name: "a range that matches nothing resolves to nothing", text: "^9.0.0", skip: "no version the registry lists satisfies it"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := declare(model.NPM, "lib", SyntaxNPM, tt.text)
			resolved, skipped := Resolve(t.Context(), src, []Declaration{d}, 1)
			if tt.skip != "" {
				if len(resolved) != 0 || len(skipped) != 1 {
					t.Fatalf("resolved %d and skipped %d, want nothing resolved", len(resolved), len(skipped))
				}
				if !strings.Contains(skipped[0].Reason, tt.skip) {
					t.Fatalf("skipped for %q, want it to say %q", skipped[0].Reason, tt.skip)
				}
				return
			}
			if len(resolved) != 1 || len(skipped) != 0 {
				t.Fatalf("resolved %d and skipped %d, want one resolved: %v", len(resolved), len(skipped), skipped)
			}
			if resolved[0].Ref.Version != tt.want {
				t.Fatalf("%q resolved to %s, want %s", tt.text, resolved[0].Ref.Version, tt.want)
			}
			if resolved[0].Ref.Ecosystem != model.NPM || resolved[0].Ref.Name != "lib" {
				t.Fatalf("ref = %v, want the npm package lib", resolved[0].Ref)
			}
		})
	}
}

// The reasons a declaration comes back unresolved. Each of them sends a reader
// somewhere: a yanked match and a range that matches nothing are different
// problems, and a registry that could not be asked is a third.
func TestResolveExplainsWhatItCouldNotResolve(t *testing.T) {
	src := newSource(model.NPM, npmVersions)
	src.errs["down"] = errRegistryDown
	tests := []struct {
		name        string
		pkg         string
		text        string
		syntax      Syntax
		reason      string
		unavailable bool
	}{
		{name: "the only match is yanked", pkg: "yanked-lib", text: "^0.4.0", reason: "is yanked"},
		{name: "every version is a prerelease", pkg: "prerelease-lib", text: "^1.0.0", reason: "every version the registry lists is a prerelease"},
		{name: "the registry lists no version", pkg: "empty-lib", text: "*", reason: "the registry lists no version of it"},
		{name: "the package is not in the registry", pkg: "missing-lib", text: "*", reason: "not found in the registry"},
		{name: "the registry could not be asked", pkg: "down", text: "*", reason: "connection refused", unavailable: true},
		{name: "the range cannot be read", pkg: "lib", text: "latest", reason: "not a version range this reader parses"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syntax := tt.syntax
			if syntax == "" {
				syntax = SyntaxNPM
			}
			d := declare(model.NPM, tt.pkg, syntax, tt.text)
			resolved, skipped := Resolve(t.Context(), src, []Declaration{d}, 1)
			if len(resolved) != 0 || len(skipped) != 1 {
				t.Fatalf("resolved %d and skipped %d, want one skipped", len(resolved), len(skipped))
			}
			if !strings.Contains(skipped[0].Reason, tt.reason) {
				t.Fatalf("skipped for %q, want it to say %q", skipped[0].Reason, tt.reason)
			}
			if skipped[0].Unavailable != tt.unavailable {
				t.Errorf("unavailable = %v, want %v: an answer and an outage are not the same thing",
					skipped[0].Unavailable, tt.unavailable)
			}
			if skipped[0].Name != tt.pkg || skipped[0].Range != tt.text || skipped[0].Table != TableDependencies {
				t.Errorf("skipped = %+v, want it to name the declaration it came from", skipped[0])
			}
		})
	}
}

// A yanked release is left out even when a lower version of the same range is fine,
// which is the difference between "nothing matches" and "do not install that one".
func TestResolveSkipsYankedAndTakesTheNextBest(t *testing.T) {
	src := newSource(model.NPM, npmVersions)
	d := declare(model.NPM, "yanked-lib", SyntaxNPM, "^0")
	resolved, skipped := Resolve(t.Context(), src, []Declaration{d}, 1)
	if len(resolved) != 1 || len(skipped) != 0 {
		t.Fatalf("resolved %d and skipped %d, want one resolved: %v", len(resolved), len(skipped), skipped)
	}
	if resolved[0].Ref.Version != "0.3.0" {
		t.Fatalf("resolved to %s, want 0.3.0: the newer 0.4.0 is yanked", resolved[0].Ref.Version)
	}
}

// The registry's own spelling of a name wins, because every other source the run
// asks about the package has to be asked under the name the registry uses.
func TestResolveAdoptsTheRegistrySpellingOfTheName(t *testing.T) {
	src := newSource(model.Cargo, map[string][]published{"serde_json": {{version: "1.0.0"}}})
	src.lists["serde-json"] = src.lists["serde_json"]
	d := declare(model.Cargo, "serde-json", SyntaxCargo, "1")
	resolved, _ := Resolve(t.Context(), src, []Declaration{d}, 1)
	if len(resolved) != 1 {
		t.Fatalf("resolved %d declarations, want 1", len(resolved))
	}
	want := model.PackageRef{Ecosystem: model.Cargo, Name: "serde_json", Version: "1.0.0"}
	if resolved[0].Ref != want {
		t.Fatalf("ref = %v, want %v", resolved[0].Ref, want)
	}
	if resolved[0].Declaration.Ref.Name != "serde-json" {
		t.Errorf("the declaration must keep the name the manifest wrote, got %q", resolved[0].Declaration.Ref.Name)
	}
}

// Every ecosystem resolves through its own grammar and its own version scheme, and
// the resolved versions come back in the order the manifest declared them however
// the lookups finish.
func TestResolveKeepsDeclarationOrderAcrossEcosystems(t *testing.T) {
	npm := newSource(model.NPM, npmVersions)
	pypi := newSource(model.PyPI, map[string][]published{
		"requests": {{version: "2.30.0"}, {version: "2.31.0"}, {version: "3.0.0"}},
	})
	cargo := newSource(model.Cargo, map[string][]published{
		"serde": {{version: "1.0.100"}, {version: "1.0.203"}, {version: "2.0.0"}},
	})
	src := &fakeSource{lists: map[string]*registry.VersionList{}, errs: map[string]error{}}
	for _, from := range []*fakeSource{npm, pypi, cargo} {
		for name, list := range from.lists {
			src.lists[name] = list
		}
	}

	declarations := []Declaration{
		declare(model.NPM, "lib", SyntaxNPM, "^1.0.0"),
		declare(model.PyPI, "requests", SyntaxPEP440, ">=2.31,<3"),
		declare(model.Cargo, "serde", SyntaxCargo, "1.0"),
		declare(model.PyPI, "requests", SyntaxPoetry, "^2.30"),
	}
	// More jobs than declarations, so every lookup runs at once and the order of
	// the answers is the resolver's doing rather than the schedule's.
	resolved, skipped := Resolve(t.Context(), src, declarations, 8)
	if len(skipped) != 0 {
		t.Fatalf("skipped %v, want nothing skipped", skipped)
	}
	want := []string{"lib@1.9.9", "requests@2.31.0", "serde@1.0.203", "requests@2.31.0"}
	for i, w := range want {
		got := resolved[i].Ref.Name + "@" + resolved[i].Ref.Version
		if got != w {
			t.Errorf("resolved %d = %s, want %s", i, got, w)
		}
	}
}

// Nothing to resolve is not an error: a manifest that declares no dependencies is a
// run with no subjects, which the report says in its own words.
func TestResolveWithNothingToDo(t *testing.T) {
	resolved, skipped := Resolve(t.Context(), newSource(model.NPM, nil), nil, 0)
	if len(resolved) != 0 || len(skipped) != 0 {
		t.Fatalf("resolved %d and skipped %d, want neither", len(resolved), len(skipped))
	}
}
