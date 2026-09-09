package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

func TestDeprecatedOrYankedRegistered(t *testing.T) {
	c := deprecatedOrYanked{}
	for _, key := range []string{"TD011", "deprecated-or-yanked"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.Level != model.LevelWarn {
		t.Errorf("default setting = %+v, %v; want warn", def, ok)
	}
}

func TestDeprecatedOrYanked(t *testing.T) {
	const ref = "npm:foo@1.2.3"
	parsed := model.MustParseRef(ref)
	versionInfo := func(yanked bool, deprecated string) *model.VersionInfo {
		return &model.VersionInfo{Ref: parsed, PublishedAt: dayB(1), Yanked: yanked, Deprecated: deprecated, WeeklyDownloads: -1}
	}
	deprecatedPackage := func(msg string) *registry.VersionList {
		list := packageB(model.NPM, "foo", releaseB{Version: "1.2.3", Published: dayB(1)})
		list.Deprecated = msg
		return list
	}
	withPackageOnlyB := func(list *registry.VersionList) func(*Subject) {
		return func(s *Subject) { s.Package = list }
	}

	c := deprecatedOrYanked{}
	tests := []struct {
		name    string
		opts    []func(*Subject)
		skipped string
		want    int
		title   string
		signals string
		verify  func(t *testing.T, f *model.Finding)
	}{
		{
			name:    "yanked version",
			opts:    []func(*Subject){withVersionB(versionInfo(true, ""))},
			want:    1,
			title:   "1.2.3 is yanked",
			signals: "[yanked]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "yanked"); got != "true" {
					t.Errorf("yanked = %s", got)
				}
				assertContainsB(t, "explanation", f.Explanation, "the registry yanked npm:foo@1.2.3")
				for _, key := range []string{"version_deprecated", "package_deprecated", "deps_dev_deprecated", "unavailable"} {
					assertNoEvidenceB(t, f, key)
				}
			},
		},
		{
			name:    "deprecated version with a message",
			opts:    []func(*Subject){withVersionB(versionInfo(false, "  use foo-next instead  "))},
			want:    1,
			title:   "1.2.3 is deprecated",
			signals: "[version-deprecated]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "version_deprecated"); got != "use foo-next instead" {
					t.Errorf("version_deprecated = %q", got)
				}
				assertContainsB(t, "explanation", f.Explanation, `the registry deprecated version 1.2.3: "use foo-next instead"`)
				assertNoEvidenceB(t, f, "yanked")
			},
		},
		{
			name:    "deprecated package",
			opts:    []func(*Subject){withPackageB(deprecatedPackage("archived by its author"))},
			want:    1,
			title:   "package foo is deprecated",
			signals: "[package-deprecated]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "package_deprecated"); got != "archived by its author" {
					t.Errorf("package_deprecated = %q", got)
				}
				assertContainsB(t, "explanation", f.Explanation, `the registry deprecated the whole package foo: "archived by its author"`)
			},
		},
		{
			name:    "deps.dev version facts",
			opts:    []func(*Subject){withVersionB(versionInfo(false, "")), withDepsDevB(&depsdev.VersionFacts{Found: true, IsDeprecated: true})},
			want:    1,
			title:   "1.2.3 is deprecated",
			signals: "[deps-dev-deprecated]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "deps_dev_deprecated"); got != "true" {
					t.Errorf("deps_dev_deprecated = %s", got)
				}
				assertNoEvidenceB(t, f, "deps_dev_reason")
				assertContainsB(t, "explanation", f.Explanation, "deps.dev marks the version deprecated")
			},
		},
		{
			name: "deps.dev finding with a reason",
			opts: []func(*Subject){withVersionB(versionInfo(false, "")), withDepsDevB(&depsdev.VersionFacts{Found: true},
				depsdev.Finding{Type: "DEPRECATED", Risk: "RISK_MEDIUM", Detail: "use String.prototype.padStart()"})},
			want:    1,
			title:   "1.2.3 is deprecated",
			signals: "[deps-dev-deprecated]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "deps_dev_reason"); got != "use String.prototype.padStart()" {
					t.Errorf("deps_dev_reason = %q", got)
				}
				assertContainsB(t, "explanation", f.Explanation, `deps.dev marks the version deprecated: "use String.prototype.padStart()"`)
			},
		},
		{
			name: "everything at once",
			opts: []func(*Subject){withPackageB(deprecatedPackage("archived")), withVersionB(versionInfo(true, "gone")),
				withDepsDevB(&depsdev.VersionFacts{Found: true, IsDeprecated: true})},
			want:    1,
			title:   "1.2.3 is yanked and deprecated",
			signals: "[yanked version-deprecated package-deprecated deps-dev-deprecated]",
		},
		{
			name: "clean version",
			opts: []func(*Subject){withPackageB(packageB(model.NPM, "foo", releaseB{Version: "1.2.3", Published: dayB(1)})),
				withDepsDevB(&depsdev.VersionFacts{Found: true}, depsdev.Finding{Type: "LOW_USAGE", Risk: "RISK_LOW"})},
			want: 0,
		},
		{
			name: "whitespace-only deprecation is not a deprecation",
			opts: []func(*Subject){withVersionB(versionInfo(false, "   "))},
			want: 0,
		},
		{
			name:    "nothing to look at",
			opts:    []func(*Subject){withUnavailableB(SourceRegistry, "boom")},
			skipped: "registry unavailable: boom; no deps.dev data for npm:foo@1.2.3",
		},
		{
			name:    "both sources down",
			opts:    []func(*Subject){withUnavailableB(SourceRegistry, "boom"), withUnavailableB(SourceDepsDev, "timeout")},
			skipped: "registry unavailable: boom; deps.dev unavailable: timeout",
		},
		{
			name:    "registry data is ignored when the registry is marked unavailable",
			opts:    []func(*Subject){withUnavailableB(SourceRegistry, "boom"), withVersionB(versionInfo(true, ""))},
			skipped: "registry unavailable: boom",
		},
		{
			name:    "registry down, deps.dev answers",
			opts:    []func(*Subject){withUnavailableB(SourceRegistry, "boom"), withDepsDevB(&depsdev.VersionFacts{Found: true, IsDeprecated: true})},
			want:    1,
			title:   "1.2.3 is deprecated",
			signals: "[deps-dev-deprecated]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "unavailable"); got != SourceRegistry {
					t.Errorf("unavailable = %s", got)
				}
				assertContainsB(t, "explanation", f.Explanation, "the registry could not be consulted (registry unavailable: boom)")
			},
		},
		{
			name:    "deps.dev down, registry answers",
			opts:    []func(*Subject){withUnavailableB(SourceDepsDev, "timeout"), withVersionB(versionInfo(true, ""))},
			want:    1,
			title:   "1.2.3 is yanked",
			signals: "[yanked]",
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "unavailable"); got != SourceDepsDev {
					t.Errorf("unavailable = %s", got)
				}
				assertContainsB(t, "explanation", f.Explanation, "deps.dev could not be consulted (deps.dev unavailable: timeout)")
			},
		},
		{
			name:    "package list without the version still reports package deprecation",
			opts:    []func(*Subject){withPackageOnlyB(deprecatedPackage("archived"))},
			want:    1,
			title:   "package foo is deprecated",
			signals: "[package-deprecated]",
		},
		{
			name: "policy level applies",
			opts: []func(*Subject){withVersionB(versionInfo(true, "")), withSettingB("deprecated-or-yanked", policy.CheckSetting{Level: model.LevelBlock})},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Level != model.LevelBlock {
					t.Errorf("level = %s, want block", f.Level)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectB(t, ref, tt.opts...)
			res := resultB(t, c, s)
			if tt.skipped != "" {
				assertSkippedB(t, c, res, tt.skipped)
				return
			}
			assertFindingsB(t, c, s, res, tt.want)
			if tt.want == 0 {
				return
			}
			f := &res.Findings[0]
			if tt.title != "" && f.Title != tt.title {
				t.Errorf("title = %q, want %q", f.Title, tt.title)
			}
			if tt.signals != "" {
				if got := evidenceB(t, f, "signals"); got != tt.signals {
					t.Errorf("signals = %s, want %s", got, tt.signals)
				}
			}
			if tt.verify != nil {
				tt.verify(t, f)
			}
		})
	}
}
