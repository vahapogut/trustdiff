package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

func TestVersionDowngradedRegistered(t *testing.T) {
	c := versionDowngraded{}
	for _, key := range []string{"TD017", "version-downgraded"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.Level != model.LevelInfo {
		t.Errorf("default setting = %+v, %v; want info", def, ok)
	}
	if eco := c.Ecosystems(); eco != nil {
		t.Errorf("Ecosystems() = %v, want nil (every ecosystem)", eco)
	}
	if !readsLockOnly(c) {
		t.Error("ReadsLockOnly() = false: the two entries are the whole evidence")
	}
}

// withBaseLockC gives the subject the entry the base lockfile held, which is what
// diff hands a check for every entry it classified as changed.
func withBaseLockC(ref, version string) func(*Subject) {
	return func(s *Subject) {
		parsed := model.MustParseRef(ref)
		parsed.Version = version
		s.BaseLock = &lockfile.Entry{Ref: parsed, Source: lockfile.SourceRegistry}
	}
}

func TestVersionDowngraded(t *testing.T) {
	c := versionDowngraded{}
	tests := []struct {
		name    string
		ref     string
		entry   func(t *testing.T) *lockfile.Entry
		opts    []func(*Subject)
		skipped string
		fires   bool
		title   string
	}{
		{
			name:  "a major version that went backwards",
			ref:   "npm:left-pad@1.3.0",
			entry: func(t *testing.T) *lockfile.Entry { return entryC(t, "npm:left-pad@1.3.0", lockfile.SourceRegistry) },
			opts:  []func(*Subject){withBaseLockC("npm:left-pad", "2.0.0")},
			fires: true, title: "Downgraded from 2.0.0 to 1.3.0",
		},
		{
			name:  "a patch that went backwards",
			ref:   "cargo:serde@1.0.209",
			entry: func(t *testing.T) *lockfile.Entry { return entryC(t, "cargo:serde@1.0.209", lockfile.SourceRegistry) },
			opts:  []func(*Subject){withBaseLockC("cargo:serde", "1.0.210")},
			fires: true, title: "Downgraded from 1.0.210 to 1.0.209",
		},
		{
			// PEP 440 orders a post-release above the release it follows, and the
			// two spellings of one release are one release.
			name:  "a pypi post release that was dropped",
			ref:   "pypi:requests@2.31.0",
			entry: func(t *testing.T) *lockfile.Entry { return entryC(t, "pypi:requests@2.31.0", lockfile.SourceRegistry) },
			opts:  []func(*Subject){withBaseLockC("pypi:requests", "2.31.0.post1")},
			fires: true, title: "Downgraded from 2.31.0.post1 to 2.31.0",
		},
		{
			name:  "1.0 and 1.0.0 are one release for pypi",
			ref:   "pypi:requests@1.0.0",
			entry: func(t *testing.T) *lockfile.Entry { return entryC(t, "pypi:requests@1.0.0", lockfile.SourceRegistry) },
			opts:  []func(*Subject){withBaseLockC("pypi:requests", "1.0")},
		},
		{
			name:  "an upgrade is not this check's business",
			ref:   "npm:left-pad@2.0.0",
			entry: func(t *testing.T) *lockfile.Entry { return entryC(t, "npm:left-pad@2.0.0", lockfile.SourceRegistry) },
			opts:  []func(*Subject){withBaseLockC("npm:left-pad", "1.3.0")},
		},
		{
			name:  "the same version is not a move at all",
			ref:   "npm:left-pad@1.3.0",
			entry: func(t *testing.T) *lockfile.Entry { return entryC(t, "npm:left-pad@1.3.0", lockfile.SourceRegistry) },
			opts:  []func(*Subject){withBaseLockC("npm:left-pad", "1.3.0")},
		},
		{
			// A bun.lock line for a git or a workspace dependency records the
			// specifier where the version goes, and neither scheme orders it. The
			// check says so rather than passing.
			name: "a pair no scheme can order",
			ref:  "npm:gh-dep@github:example/gh-dep",
			entry: func(t *testing.T) *lockfile.Entry {
				return entryC(t, "npm:gh-dep@github:example/gh-dep", lockfile.SourceRegistry)
			},
			opts:    []func(*Subject){withBaseLockC("npm:gh-dep", "workspace:packages/gh-dep")},
			skipped: "cannot order",
		},
		{
			name:    "a ref named on the command line",
			ref:     "npm:left-pad@1.3.0",
			skipped: "no lockfile entry",
		},
		{
			name:    "an entry the base lockfile did not hold",
			ref:     "npm:left-pad@1.3.0",
			entry:   func(t *testing.T) *lockfile.Entry { return entryC(t, "npm:left-pad@1.3.0", lockfile.SourceRegistry) },
			skipped: "no entry in the base lockfile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry *lockfile.Entry
			if tt.entry != nil {
				entry = tt.entry(t)
			}
			s := subjectC(t, tt.ref, entry, tt.opts...)
			res := c.Run(context.Background(), s)
			if tt.skipped != "" {
				if res.Skipped == nil || !strings.Contains(res.Skipped.Reason, tt.skipped) {
					t.Fatalf("skipped = %+v, want a reason containing %q", res.Skipped, tt.skipped)
				}
				return
			}
			if res.Skipped != nil {
				t.Fatalf("skipped with %q, want a verdict", res.Skipped.Reason)
			}
			if !tt.fires {
				if len(res.Findings) != 0 {
					t.Fatalf("findings = %+v, want none", res.Findings)
				}
				return
			}
			if len(res.Findings) != 1 {
				t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
			}
			f := res.Findings[0]
			if f.Title != tt.title {
				t.Errorf("title = %q, want %q", f.Title, tt.title)
			}
			if f.Level != model.LevelInfo {
				t.Errorf("level = %s, want info", f.Level)
			}
			if got := f.Evidence["version"]; got != s.Lock.Ref.Version {
				t.Errorf("evidence[version] = %v, want %s", got, s.Lock.Ref.Version)
			}
			if got := f.Evidence["base_version"]; got != s.BaseLock.Ref.Version {
				t.Errorf("evidence[base_version] = %v, want %s", got, s.BaseLock.Ref.Version)
			}
		})
	}
}
