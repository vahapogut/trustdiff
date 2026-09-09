package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

func TestExoticSourceRegistered(t *testing.T) {
	c := exoticSource{}
	for _, key := range []string{"TD013", "exotic-source"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.Level != model.LevelBlock {
		t.Errorf("default setting = %+v, %v; want block", def, ok)
	}
	if eco := c.Ecosystems(); eco != nil {
		t.Errorf("Ecosystems() = %v, want nil (every ecosystem)", eco)
	}
	for _, eco := range model.Ecosystems() {
		if !AppliesTo(c, eco) {
			t.Errorf("AppliesTo(%s) = false, want true", eco)
		}
	}
}

func TestExoticSource(t *testing.T) {
	c := exoticSource{}
	tests := []struct {
		name    string
		ref     string
		entry   func(t *testing.T) *lockfile.Entry
		opts    []func(*Subject)
		skipped string
		want    int
		verify  func(t *testing.T, f *model.Finding)
	}{
		{
			name: "registry entry passes",
			ref:  "npm:left-pad@1.3.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:left-pad@1.3.0", lockfile.SourceRegistry,
					resolvedC("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
					integrityC("sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="))
			},
			want: 0,
		},
		{
			name: "git entry on a moving ref",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceGit,
					resolvedC("git+ssh://git@github.com/acme/lib.git#main"))
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "resolved from a git repository instead of the npm registry" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourceGit) {
					t.Errorf("source = %s, want git", got)
				}
				if got := evidenceC(t, f, "resolved"); got != "git+ssh://git@github.com/acme/lib.git#main" {
					t.Errorf("resolved = %s", got)
				}
				if got := evidenceC(t, f, "lockfile"); got != "package-lock.json" {
					t.Errorf("lockfile = %s", got)
				}
				assertContainsC(t, "explanation", f.Explanation,
					"package-lock.json resolves npm:lib@2.0.0 from a git repository (git+ssh://git@github.com/acme/lib.git#main) rather than from the npm registry",
					"the release cannot be yanked",
					"pins no commit sha")
			},
		},
		{
			name: "git entry pinned to a commit sha is still not the registry",
			ref:  "cargo:lib@0.4.1",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "cargo:lib@0.4.1", lockfile.SourceGit,
					resolvedC("git+https://github.com/acme/lib?rev="+pinnedShaC+"#"+pinnedShaC))
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "resolved from a git repository instead of crates.io" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsC(t, "explanation", f.Explanation,
					"The revision "+pinnedShaC+" is a full commit sha, so at least the content is pinned")
			},
		},
		{
			name: "tarball URL",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL,
					resolvedC("https://files.example.com/lib-2.0.0.tgz"))
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "resolved from a URL instead of the npm registry" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourceURL) {
					t.Errorf("source = %s, want url", got)
				}
				assertContainsC(t, "explanation", f.Explanation,
					"Whoever controls that URL can replace what it serves")
			},
		},
		{
			name: "workspace member resolved from a path",
			ref:  "npm:@acme/ui@1.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:@acme/ui@1.0.0", lockfile.SourcePath, resolvedC("packages/ui"))
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "resolved from a local directory instead of the npm registry" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourcePath) {
					t.Errorf("source = %s, want path", got)
				}
				assertContainsC(t, "explanation", f.Explanation,
					"A path entry is a local directory",
					"allow entry for exotic-source with a package glob")
			},
		},
		{
			name: "origin the file does not state",
			ref:  "pypi:lib@1.2.3",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "pypi:lib@1.2.3", lockfile.SourceUnknown)
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "the lockfile does not say where this version was resolved from" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourceUnknown) {
					t.Errorf("source = %s, want unknown", got)
				}
				assertNoEvidenceC(t, f, "resolved")
				if got := evidenceC(t, f, "lockfile"); got != "uv.lock" {
					t.Errorf("lockfile = %s", got)
				}
				assertContainsC(t, "explanation", f.Explanation,
					"uv.lock does not say where pypi:lib@1.2.3 was resolved from, so the entry cannot be read as a release from PyPI")
			},
		},
		{
			name: "a source the parser left empty is read as unknown",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", "")
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourceUnknown) {
					t.Errorf("source = %s, want unknown", got)
				}
			},
		},
		{
			name: "an entry the parser could not place names no lockfile",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL, resolvedC("https://files.example.com/lib.tgz"))
			},
			opts: []func(*Subject){withoutLocationC},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				assertNoEvidenceC(t, f, "lockfile")
				assertContainsC(t, "explanation", f.Explanation, "the lockfile resolves npm:lib@2.0.0 from a URL")
			},
		},
		{
			name: "git entry the file records no location for",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceGit)
			},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				assertNoEvidenceC(t, f, "resolved")
				assertContainsC(t, "explanation", f.Explanation,
					"package-lock.json resolves npm:lib@2.0.0 from a git repository rather than from the npm registry",
					"pins no commit sha")
			},
		},
		{
			name: "policy level applies",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceGit, resolvedC("git+https://github.com/acme/lib.git#main"))
			},
			opts: []func(*Subject){withSettingC("exotic-source", policy.CheckSetting{Level: model.LevelInfo})},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Level != model.LevelInfo {
					t.Errorf("level = %s, want info", f.Level)
				}
			},
		},
		{
			name:    "a ref named on the command line has no entry",
			ref:     "npm:lib@2.0.0",
			skipped: "no lockfile entry for npm:lib@2.0.0: the ref was named directly, not read from a lockfile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry *lockfile.Entry
			if tt.entry != nil {
				entry = tt.entry(t)
			}
			s := subjectC(t, tt.ref, entry, tt.opts...)
			res := resultC(t, c, s)
			if tt.skipped != "" {
				assertSkippedC(t, c, res, tt.skipped)
				return
			}
			assertFindingsC(t, c, s, res, tt.want)
			if tt.verify != nil && len(res.Findings) > 0 {
				tt.verify(t, &res.Findings[0])
			}
		})
	}
}

func TestSourceNoun(t *testing.T) {
	tests := []struct {
		source lockfile.Source
		want   string
	}{
		{source: lockfile.SourceGit, want: "a git repository"},
		{source: lockfile.SourceURL, want: "a URL"},
		{source: lockfile.SourcePath, want: "a local directory"},
		{source: lockfile.SourceUnknown, want: "an unstated source"},
		{source: lockfile.SourceRegistry, want: "an unstated source"},
		{source: "something a later parser adds", want: "an unstated source"},
	}
	for _, tt := range tests {
		t.Run(string(tt.source), func(t *testing.T) {
			if got := sourceNoun(tt.source); got != tt.want {
				t.Errorf("sourceNoun(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestPinnedCommit(t *testing.T) {
	tests := []struct {
		name     string
		resolved string
		want     string
	}{
		{name: "empty"},
		{name: "npm git fragment", resolved: "git+ssh://git@github.com/acme/lib.git#" + pinnedShaC, want: pinnedShaC},
		{name: "cargo rev query", resolved: "git+https://github.com/acme/lib?rev=" + pinnedShaC + "#" + pinnedShaC, want: pinnedShaC},
		{name: "uppercase sha", resolved: "git+https://github.com/acme/lib.git#3F7B9C1D2E4A5B6C7D8E9F0A1B2C3D4E5F60718A", want: "3F7B9C1D2E4A5B6C7D8E9F0A1B2C3D4E5F60718A"},
		// The two spellings below are copied from the committed lockfile fixtures.
		{
			name:     "package-lock.json fragment",
			resolved: "git+ssh://git@github.com/dmapper/dom-to-image.git#a7c386a8ea813930f05449ac71ab4be0c262dff3",
			want:     "a7c386a8ea813930f05449ac71ab4be0c262dff3",
		},
		{
			name:     "pnpm codeload tarball",
			resolved: "https://codeload.github.com/kevva/is-negative/tar.gz/1d7e288222b53a0cab90a331f1865220ec29560c",
			want:     "1d7e288222b53a0cab90a331f1865220ec29560c",
		},
		{name: "branch name", resolved: "git+ssh://git@github.com/acme/lib.git#main"},
		{name: "short revision", resolved: "git+ssh://git@github.com/acme/lib.git#3f7b9c1"},
		{name: "thirty nine characters", resolved: "git+ssh://git@github.com/acme/lib.git#" + pinnedShaC[:39]},
		{name: "forty one characters", resolved: "git+ssh://git@github.com/acme/lib.git#" + pinnedShaC + "0"},
		{name: "a longer hash a sha sits inside", resolved: "sha256:" + pinnedShaC + "0011223344556677"},
		{name: "a letter runs into the sha", resolved: "git+ssh://git@github.com/acme/lib.git#z" + pinnedShaC},
		{name: "the sha runs into a letter", resolved: "git+ssh://git@github.com/acme/lib.git#" + pinnedShaC + "z"},
		{name: "no revision at all", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := pinnedCommit(tt.resolved)
			if ok != (tt.want != "") || got != tt.want {
				t.Errorf("pinnedCommit(%q) = %q, %v; want %q, %v", tt.resolved, got, ok, tt.want, tt.want != "")
			}
		})
	}
}
