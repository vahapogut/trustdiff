package checks

import (
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// npmIntegrityC is an integrity hash in the spelling npm lockfiles use.
const npmIntegrityC = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="

func TestIntegrityMissingRegistered(t *testing.T) {
	c := integrityMissing{}
	for _, key := range []string{"TD014", "integrity-missing"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.Level != model.LevelWarn {
		t.Errorf("default setting = %+v, %v; want warn", def, ok)
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

func TestIntegrityMissing(t *testing.T) {
	c := integrityMissing{}
	tests := []struct {
		name    string
		ref     string
		entry   func(t *testing.T) *lockfile.Entry
		opts    []func(*Subject)
		skipped string
		want    int
		verify  func(t *testing.T, findings []model.Finding)
	}{
		{
			name: "registry entry with a hash over https passes",
			ref:  "npm:left-pad@1.3.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:left-pad@1.3.0", lockfile.SourceRegistry,
					resolvedC("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
					integrityC(npmIntegrityC))
			},
			want: 0,
		},
		{
			name: "registry entry without a hash",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceRegistry,
					resolvedC("https://registry.npmjs.org/lib/-/lib-2.0.0.tgz"))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[0]
				if f.Title != "no integrity hash in the lockfile" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceC(t, f, "signal"); got != "missing-hash" {
					t.Errorf("signal = %s", got)
				}
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourceRegistry) {
					t.Errorf("source = %s, want registry", got)
				}
				if got := evidenceC(t, f, "resolved"); got != "https://registry.npmjs.org/lib/-/lib-2.0.0.tgz" {
					t.Errorf("resolved = %s", got)
				}
				if got := evidenceC(t, f, "lockfile"); got != "package-lock.json" {
					t.Errorf("lockfile = %s", got)
				}
				assertNoEvidenceC(t, f, "integrity")
				assertContainsC(t, "explanation", f.Explanation,
					"package-lock.json records no integrity hash for npm:lib@2.0.0, resolved from https://registry.npmjs.org/lib/-/lib-2.0.0.tgz",
					"a replaced archive or a compromised mirror is installed without complaint")
			},
		},
		{
			name: "a hash of only whitespace is no hash",
			ref:  "cargo:lib@0.4.1",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "cargo:lib@0.4.1", lockfile.SourceRegistry, integrityC("   "))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "signal"); got != "missing-hash" {
					t.Errorf("signal = %s", got)
				}
				assertNoEvidenceC(t, &findings[0], "resolved")
			},
		},
		{
			name: "plain http with a hash",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL,
					resolvedC("http://files.example.com/lib-2.0.0.tgz"), integrityC(npmIntegrityC))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[0]
				if f.Title != "resolved over plain http" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceC(t, f, "signal"); got != "plain-http" {
					t.Errorf("signal = %s", got)
				}
				if got := evidenceC(t, f, "source"); got != string(lockfile.SourceURL) {
					t.Errorf("source = %s, want url", got)
				}
				if got := evidenceC(t, f, "integrity"); got != npmIntegrityC {
					t.Errorf("integrity = %s", got)
				}
				assertContainsC(t, "explanation", f.Explanation,
					"package-lock.json resolves npm:lib@2.0.0 over plain http (http://files.example.com/lib-2.0.0.tgz)",
					"The entry does record "+npmIntegrityC,
					"the location should still be https")
			},
		},
		{
			name: "plain http and no hash report both signals",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL, resolvedC("http://files.example.com/lib-2.0.0.tgz"))
			},
			want: 2,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "signal"); got != "missing-hash" {
					t.Errorf("first signal = %s, want missing-hash", got)
				}
				if got := evidenceC(t, &findings[1], "signal"); got != "plain-http" {
					t.Errorf("second signal = %s, want plain-http", got)
				}
				assertNoEvidenceC(t, &findings[1], "integrity")
				assertContainsC(t, "explanation", findings[1].Explanation,
					"The entry records no hash either, so nothing would catch the substitution")
			},
		},
		{
			name: "an uppercase scheme is still plain http",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL,
					resolvedC("HTTP://files.example.com/lib-2.0.0.tgz"), integrityC(npmIntegrityC))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "signal"); got != "plain-http" {
					t.Errorf("signal = %s", got)
				}
			},
		},
		{
			name: "https is not plain http",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL,
					resolvedC("https://files.example.com/lib-2.0.0.tgz"), integrityC(npmIntegrityC))
			},
			want: 0,
		},
		{
			name: "git entry pinned to a commit sha needs no hash",
			ref:  "cargo:lib@0.4.1",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "cargo:lib@0.4.1", lockfile.SourceGit,
					resolvedC("git+https://github.com/acme/lib?rev="+pinnedShaC+"#"+pinnedShaC))
			},
			want: 0,
		},
		{
			name: "git entry on a branch is reported",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceGit, resolvedC("git+ssh://git@github.com/acme/lib.git#main"))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				assertContainsC(t, "explanation", findings[0].Explanation,
					"A git entry needs no hash when its location pins a full forty character commit sha",
					"this one pins a branch or a tag instead")
			},
		},
		{
			name: "git entry with a short revision is reported",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceGit, resolvedC("git+ssh://git@github.com/acme/lib.git#3f7b9c1"))
			},
			want: 1,
		},
		{
			name: "a pinned sha outside a git entry is no substitute for a hash",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL, resolvedC("https://files.example.com/lib-"+pinnedShaC+".tgz"))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "signal"); got != "missing-hash" {
					t.Errorf("signal = %s", got)
				}
			},
		},
		{
			name: "a git entry pinned to a sha over plain http keeps the transport signal",
			ref:  "cargo:lib@0.4.1",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "cargo:lib@0.4.1", lockfile.SourceGit, resolvedC("git+http://git.example.com/acme/lib#"+pinnedShaC))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "signal"); got != "plain-http" {
					t.Errorf("signal = %s, want plain-http only", got)
				}
			},
		},
		{
			name: "workspace member resolved from a path",
			ref:  "npm:@acme/ui@1.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:@acme/ui@1.0.0", lockfile.SourcePath, resolvedC("packages/ui"))
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "source"); got != string(lockfile.SourcePath) {
					t.Errorf("source = %s, want path", got)
				}
				assertContainsC(t, "explanation", findings[0].Explanation,
					"The entry is a local directory, which has nothing to download and so nothing to hash",
					"allow entry for integrity-missing with a package glob")
				if strings.Contains(findings[0].Explanation, "a compromised mirror is installed without complaint") {
					t.Errorf("a local directory is explained as a download: %q", findings[0].Explanation)
				}
			},
		},
		{
			// npm writes a bundled dependency with no location and no hash: its bytes
			// ship inside the archive of the package that carries it, so the entry
			// says what a maintainer needs instead of claiming nothing guards it.
			name: "an npm entry with neither a location nor a hash",
			ref:  "npm:bundled-helper@3.0.1",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:bundled-helper@3.0.1", lockfile.SourceUnknown)
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceC(t, &findings[0], "source"); got != string(lockfile.SourceUnknown) {
					t.Errorf("source = %s, want unknown", got)
				}
				assertNoEvidenceC(t, &findings[0], "resolved")
				assertContainsC(t, "explanation", findings[0].Explanation,
					"usually a bundled dependency, whose bytes travel inside the archive of the package that carries it and are covered by that package's hash")
				if strings.Contains(findings[0].Explanation, "a compromised mirror is installed without complaint") {
					t.Errorf("an entry with nothing to download is explained as a download: %q", findings[0].Explanation)
				}
			},
		},
		{
			name: "an entry with no source and no hash",
			ref:  "pypi:lib@1.2.3",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "pypi:lib@1.2.3", lockfile.SourceUnknown)
			},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				assertContainsC(t, "explanation", findings[0].Explanation,
					"uv.lock records no integrity hash for pypi:lib@1.2.3.",
					"The entry does not say where it comes from either")
				if strings.Contains(findings[0].Explanation, "npm") {
					t.Errorf("a uv.lock entry is explained with npm's bundling: %q", findings[0].Explanation)
				}
			},
		},
		{
			name: "an entry the parser could not place names no lockfile",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceRegistry)
			},
			opts: []func(*Subject){withoutLocationC},
			want: 1,
			verify: func(t *testing.T, findings []model.Finding) {
				assertNoEvidenceC(t, &findings[0], "lockfile")
				assertContainsC(t, "explanation", findings[0].Explanation, "the lockfile records no integrity hash for npm:lib@2.0.0")
			},
		},
		{
			name: "policy level applies to both signals",
			ref:  "npm:lib@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:lib@2.0.0", lockfile.SourceURL, resolvedC("http://files.example.com/lib-2.0.0.tgz"))
			},
			opts: []func(*Subject){withSettingC("integrity-missing", policy.CheckSetting{Level: model.LevelBlock})},
			want: 2,
			verify: func(t *testing.T, findings []model.Finding) {
				for i := range findings {
					if findings[i].Level != model.LevelBlock {
						t.Errorf("finding %d: level = %s, want block", i, findings[i].Level)
					}
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
				tt.verify(t, res.Findings)
			}
		})
	}
}

func TestInsecureTransport(t *testing.T) {
	tests := []struct {
		resolved string
		want     bool
	}{
		{resolved: ""},
		{resolved: "http://files.example.com/lib.tgz", want: true},
		{resolved: "HTTP://files.example.com/lib.tgz", want: true},
		{resolved: "git+http://git.example.com/acme/lib#main", want: true},
		{resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
		{resolved: "git+https://github.com/acme/lib.git#main"},
		{resolved: "git+ssh://git@github.com/acme/lib.git#main"},
		{resolved: "file:packages/ui"},
		{resolved: "packages/ui"},
		{resolved: "https://example.com/redirect?to=http://files.example.com/lib.tgz"},
	}
	for _, tt := range tests {
		t.Run(tt.resolved, func(t *testing.T) {
			if got := insecureTransport(tt.resolved); got != tt.want {
				t.Errorf("insecureTransport(%q) = %v, want %v", tt.resolved, got, tt.want)
			}
		})
	}
}
