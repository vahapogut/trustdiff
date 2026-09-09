package gitdiff

import (
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// entry builds a locked entry: a registry download under a hash, which is the
// ordinary case, unless an option says otherwise.
func entry(ref, integrity string, opts ...func(*lockfile.Entry)) lockfile.Entry {
	e := lockfile.Entry{Ref: model.MustParseRef(ref), Source: lockfile.SourceRegistry, Integrity: integrity}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

func fromGit(remote string) func(*lockfile.Entry) {
	return func(e *lockfile.Entry) {
		e.Source = lockfile.SourceGit
		e.Resolved = remote
	}
}

func resolvedAt(url string) func(*lockfile.Entry) {
	return func(e *lockfile.Entry) { e.Resolved = url }
}

func onLine(n int) func(*lockfile.Entry) {
	return func(e *lockfile.Entry) { e.Line = n }
}

func asDirect(e *lockfile.Entry) { e.Direct = true }

// withoutEcosystem is what a single-ecosystem format may leave to the file.
func withoutEcosystem(e *lockfile.Entry) { e.Ref.Ecosystem = "" }

// file wraps entries the way a parser returns them.
func file(eco model.Ecosystem, entries []lockfile.Entry) *lockfile.Lockfile {
	return &lockfile.Lockfile{Path: "Cargo.lock", Format: "Cargo.lock", Ecosystem: eco, Entries: entries}
}

// refs and pairs summarize the result so a table can state it in one line.
func refs(entries []lockfile.Entry) []string {
	out := make([]string, 0, len(entries))
	for i := range entries {
		out = append(out, entries[i].Ref.String())
	}
	return out
}

func pairs(changes []Change) []string {
	out := make([]string, 0, len(changes))
	for i := range changes {
		out = append(out, changes[i].Base.Ref.String()+" -> "+changes[i].Head.Ref.String())
	}
	return out
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name        string
		ecosystem   model.Ecosystem
		base        []lockfile.Entry
		head        []lockfile.Entry
		wantAdded   []string
		wantChanged []string
		wantRemoved []string
	}{
		{
			name:      "an entry the change adds",
			base:      []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad")},
			head:      []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad"), entry("npm:plain-crypto-js@1.0.0", "sha512-new")},
			wantAdded: []string{"npm:plain-crypto-js@1.0.0"},
		},
		{
			name:        "an entry the change removes",
			base:        []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad"), entry("npm:colors@1.4.0", "sha512-col")},
			head:        []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad")},
			wantRemoved: []string{"npm:colors@1.4.0"},
		},
		{
			name:        "a version bump is one change, not an addition and a removal",
			base:        []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-old")},
			head:        []lockfile.Entry{entry("npm:left-pad@1.3.1", "sha512-new")},
			wantChanged: []string{"npm:left-pad@1.3.0 -> npm:left-pad@1.3.1"},
		},
		{
			name: "an untouched entry is not reported",
			base: []lockfile.Entry{entry("cargo:serde@1.0.210", "sha256-ser"), entry("cargo:memchr@2.7.4", "sha256-mem")},
			head: []lockfile.Entry{entry("cargo:serde@1.0.210", "sha256-ser"), entry("cargo:memchr@2.7.4", "sha256-mem")},
		},
		{
			name:        "the same version without its hash",
			base:        []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad")},
			head:        []lockfile.Entry{entry("npm:left-pad@1.3.0", "")},
			wantChanged: []string{"npm:left-pad@1.3.0 -> npm:left-pad@1.3.0"},
		},
		{
			name:        "the same version fetched from a git remote",
			base:        []lockfile.Entry{entry("cargo:serde@1.0.210", "sha256-ser")},
			head:        []lockfile.Entry{entry("cargo:serde@1.0.210", "sha256-ser", fromGit("https://github.com/example/serde#deadbeef"))},
			wantChanged: []string{"cargo:serde@1.0.210 -> cargo:serde@1.0.210"},
		},
		{
			name: "the same version from another registry host is not a change",
			base: []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad", resolvedAt("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"))},
			head: []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad", resolvedAt("https://npm.example.com/left-pad/-/left-pad-1.3.0.tgz"))},
		},
		{
			name:        "a name locked twice reports only the version that moved",
			base:        []lockfile.Entry{entry("npm:semver@6.3.1", "sha512-six"), entry("npm:semver@7.6.0", "sha512-seven")},
			head:        []lockfile.Entry{entry("npm:semver@7.6.0", "sha512-seven"), entry("npm:semver@7.6.3", "sha512-newer")},
			wantChanged: []string{"npm:semver@6.3.1 -> npm:semver@7.6.3"},
		},
		{
			name:        "a name locked twice where one version goes away",
			base:        []lockfile.Entry{entry("npm:semver@6.3.1", "sha512-six"), entry("npm:semver@7.6.0", "sha512-seven")},
			head:        []lockfile.Entry{entry("npm:semver@7.6.0", "sha512-seven")},
			wantRemoved: []string{"npm:semver@6.3.1"},
		},
		{
			name:        "the same name in two ecosystems is two packages",
			base:        []lockfile.Entry{entry("npm:requests@1.0.0", "sha512-npm")},
			head:        []lockfile.Entry{entry("pypi:requests@1.0.0", "sha256-pypi")},
			wantAdded:   []string{"pypi:requests@1.0.0"},
			wantRemoved: []string{"npm:requests@1.0.0"},
		},
		{
			name:        "an entry takes the ecosystem from its file",
			ecosystem:   model.Cargo,
			base:        []lockfile.Entry{entry("cargo:serde@1.0.210", "sha256-old", withoutEcosystem)},
			head:        []lockfile.Entry{entry("cargo:serde@1.0.216", "sha256-new")},
			wantChanged: []string{"cargo:serde@1.0.210 -> cargo:serde@1.0.216"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Diff(file(tt.ecosystem, tt.base), file(tt.ecosystem, tt.head))
			if added := refs(got.Added); !slices.Equal(added, tt.wantAdded) {
				t.Errorf("Added = %q, want %q", added, tt.wantAdded)
			}
			if changed := pairs(got.Changed); !slices.Equal(changed, tt.wantChanged) {
				t.Errorf("Changed = %q, want %q", changed, tt.wantChanged)
			}
			if removed := refs(got.Removed); !slices.Equal(removed, tt.wantRemoved) {
				t.Errorf("Removed = %q, want %q", removed, tt.wantRemoved)
			}
			wantEmpty := len(tt.wantAdded)+len(tt.wantChanged)+len(tt.wantRemoved) == 0
			if got.Empty() != wantEmpty {
				t.Errorf("Empty() = %v, want %v", got.Empty(), wantEmpty)
			}
		})
	}
}

func TestDiffWithOnlyOneFile(t *testing.T) {
	entries := []lockfile.Entry{entry("npm:left-pad@1.3.0", "sha512-pad"), entry("npm:colors@1.4.0", "sha512-col")}
	want := []string{"npm:left-pad@1.3.0", "npm:colors@1.4.0"}

	t.Run("a lockfile the change adds has no base", func(t *testing.T) {
		got := Diff(nil, file(model.NPM, entries))
		if added := refs(got.Added); !slices.Equal(added, want) {
			t.Errorf("Added = %q, want %q", added, want)
		}
		if len(got.Changed) != 0 || len(got.Removed) != 0 {
			t.Errorf("Changed = %q and Removed = %q, want neither", pairs(got.Changed), refs(got.Removed))
		}
	})

	t.Run("a lockfile the change deletes has no head", func(t *testing.T) {
		got := Diff(file(model.NPM, entries), nil)
		if removed := refs(got.Removed); !slices.Equal(removed, want) {
			t.Errorf("Removed = %q, want %q", removed, want)
		}
		if len(got.Added) != 0 || len(got.Changed) != 0 {
			t.Errorf("Added = %q and Changed = %q, want neither", refs(got.Added), pairs(got.Changed))
		}
	})
}

// TestDiffCollapsesAnEntryThatAppearsTwice covers the lockfiles that list one
// version in several places: a package-lock.json names a hoisted package once
// per path it was installed at. The change is one entry to evaluate, reported on
// the first line that mentions it, and it counts as direct if any of the places
// is a direct dependency.
func TestDiffCollapsesAnEntryThatAppearsTwice(t *testing.T) {
	head := file(model.NPM, []lockfile.Entry{
		entry("npm:left-pad@1.3.0", "sha512-pad", onLine(12)),
		entry("npm:left-pad@1.3.0", "sha512-pad", onLine(340), asDirect),
	})

	got := Diff(nil, head)
	if len(got.Added) != 1 {
		t.Fatalf("Added = %q, want one entry", refs(got.Added))
	}
	added := got.Added[0]
	if added.Line != 12 {
		t.Errorf("Added[0].Line = %d, want 12, the first line the file mentions it on", added.Line)
	}
	if !added.Direct {
		t.Error("Added[0].Direct = false, want true: one of the two places is a direct dependency")
	}
}
