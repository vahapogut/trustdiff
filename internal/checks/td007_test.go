package checks

import (
	"errors"
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// dependencySubjectA builds an evaluated version 1.3.0 that adds the given
// dependencies to the "a" dependency of 1.2.0.
func dependencySubjectA(eco model.Ecosystem, added map[string]string) *Subject {
	s := subjectA(eco, "lib", "1.3.0")
	s.Version.Dependencies = map[string]string{"a": "^1.0.0"}
	for name, req := range added {
		s.Version.Dependencies[name] = req
	}
	withPreviousA(s, "1.2.0").Dependencies = map[string]string{"a": "^1.0.0"}
	return s
}

// healthyListA is a dependency with an old first release and an old latest version.
func healthyListA(eco model.Ecosystem, name string) *registry.VersionList {
	list := listA(eco, name,
		versionA(eco, name, "1.0.0", agoA(400*dayA)),
		versionA(eco, name, "1.0.1", agoA(200*dayA)))
	list.Created = agoA(400 * dayA)
	return list
}

func TestTD007NewDependencyIntroduced(t *testing.T) {
	const dep = "plain-crypto-js"
	tests := []struct {
		name      string
		eco       model.Ecosystem
		added     map[string]string
		loader    func(eco model.Ecosystem) *loaderA
		nilLoader bool
		threshold int64
		want      outcomeA
		level     model.Level
		reasons   []string
		evidence  map[string]any
		absent    []string
		text      []string
	}{
		{
			name:  "young, low usage and unknown to deps.dev raises the level to block",
			eco:   model.NPM,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				list := listA(eco, dep,
					versionA(eco, dep, "1.0.0", agoA(3*dayA)),
					versionA(eco, dep, "1.0.1", agoA(2*dayA)))
				list.Created = agoA(3 * dayA)
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): list},
					downloads: map[string]int64{keyA(eco, dep): 12},
					depsDev:   map[string]*depsdev.VersionFacts{"npm:" + dep + "@1.0.1": {Found: false}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelBlock,
			reasons:   []string{"young", "low-usage", "unknown-to-deps.dev"},
			evidence: map[string]any{
				"previous_version":     "1.2.0",
				"dependency":           dep,
				"requirement":          "^1.0.0",
				"escalated":            true,
				"resolved_version":     "1.0.1",
				"published_at":         "2026-09-07T12:00:00Z",
				"first_published_at":   "2026-09-06T12:00:00Z",
				"weekly_downloads":     int64(12),
				"min_weekly_downloads": int64(500),
				"deps_dev_found":       false,
			},
			text: []string{
				"1.2.0 declared 1 runtime dependency; 1.3.0 adds plain-crypto-js (^1.0.0)",
				"The newest stable version is plain-crypto-js@1.0.1, published on 2026-09-07T12:00:00Z (2d ago)",
				"the package's first release dates from 2026-09-06T12:00:00Z (3d ago)",
				"it has 12 weekly downloads, below the low-usage threshold of 500",
				"deps.dev has no record of plain-crypto-js@1.0.1",
				"The finding is raised to block because the dependency is young, has low usage and is unknown to deps.dev",
			},
		},
		{
			name:  "an established dependency keeps the policy level",
			eco:   model.NPM,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): healthyListA(eco, dep)},
					downloads: map[string]int64{keyA(eco, dep): 4_000_000},
					depsDev:   map[string]*depsdev.VersionFacts{"npm:" + dep + "@1.0.1": {Found: true}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			evidence:  map[string]any{"escalated": false, "weekly_downloads": int64(4_000_000), "deps_dev_found": true},
			absent:    []string{"inspection_errors"},
			text:      []string{"it has 4000000 weekly downloads;", "deps.dev knows plain-crypto-js@1.0.1", "Nothing raises the finding above the configured level"},
		},
		{
			name:  "a young dependency alone is enough",
			eco:   model.Cargo,
			added: map[string]string{dep: "^1"},
			loader: func(eco model.Ecosystem) *loaderA {
				list := listA(eco, dep, versionA(eco, dep, "1.0.0", agoA(6*dayA)))
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): list},
					downloads: map[string]int64{keyA(eco, dep): 10_000},
					depsDev:   map[string]*depsdev.VersionFacts{"cargo:" + dep + "@1.0.0": {Found: true}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelBlock,
			reasons:   []string{"young"},
			evidence:  map[string]any{"first_published_at": "2026-09-03T12:00:00Z", "resolved_version": "1.0.0"},
			text:      []string{"raised to block because the dependency is young"},
		},
		{
			name:  "seven days is no longer young",
			eco:   model.Cargo,
			added: map[string]string{dep: "^1"},
			loader: func(eco model.Ecosystem) *loaderA {
				list := listA(eco, dep, versionA(eco, dep, "1.0.0", agoA(youngDependencyAge)))
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): list},
					downloads: map[string]int64{keyA(eco, dep): 10_000},
					depsDev:   map[string]*depsdev.VersionFacts{"cargo:" + dep + "@1.0.0": {Found: true}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
		},
		{
			name:  "an exact requirement resolves to that version, not the latest",
			eco:   model.NPM,
			added: map[string]string{dep: "1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				list := listA(eco, dep,
					versionA(eco, dep, "1.0.0", agoA(400*dayA)),
					versionA(eco, dep, "1.0.1", agoA(dayA)))
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): list},
					downloads: map[string]int64{keyA(eco, dep): 10_000},
					depsDev:   map[string]*depsdev.VersionFacts{"npm:" + dep + "@1.0.0": {Found: true}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			evidence:  map[string]any{"resolved_version": "1.0.0", "published_at": "2025-08-05T12:00:00Z"},
		},
		{
			name:  "a cargo exact requirement with = resolves the same way",
			eco:   model.Cargo,
			added: map[string]string{dep: "=1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				list := listA(eco, dep,
					versionA(eco, dep, "1.0.0", agoA(400*dayA)),
					versionA(eco, dep, "1.0.1", agoA(dayA)))
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): list},
					downloads: map[string]int64{keyA(eco, dep): 10_000},
					depsDev:   map[string]*depsdev.VersionFacts{"cargo:" + dep + "@1.0.0": {Found: true}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			evidence:  map[string]any{"resolved_version": "1.0.0"},
		},
		{
			name:  "a pypi exact requirement with == resolves the same way",
			eco:   model.PyPI,
			added: map[string]string{dep: "==1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				list := listA(eco, dep,
					versionA(eco, dep, "1.0.0", agoA(400*dayA)),
					versionA(eco, dep, "1.0.1", agoA(dayA)))
				return &loaderA{
					versions:     map[string]*registry.VersionList{keyA(eco, dep): list},
					downloadsErr: map[string]error{keyA(eco, dep): registry.ErrUnsupported},
					depsDev:      map[string]*depsdev.VersionFacts{"pypi:" + dep + "@1.0.0": {Found: true}},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			evidence:  map[string]any{"resolved_version": "1.0.0"},
			absent:    []string{"weekly_downloads", "inspection_errors"},
			text:      []string{"PyPI has no download counts"},
		},
		{
			name:  "a loader error never escalates and is reported",
			eco:   model.NPM,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{
					versionsErr:  map[string]error{keyA(eco, dep): errors.New("GET https://registry.npmjs.org/plain-crypto-js: offline and not in the cache")},
					downloadsErr: map[string]error{keyA(eco, dep): errors.New("GET https://api.npmjs.org/downloads/point/last-week/plain-crypto-js: offline and not in the cache")},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			absent:    []string{"resolved_version", "published_at", "weekly_downloads", "deps_dev_found"},
			text: []string{
				"The dependency could not be fully inspected: the version list of plain-crypto-js could not be fetched: GET https://registry.npmjs.org/plain-crypto-js: offline",
				"the weekly downloads of plain-crypto-js could not be fetched",
				"No version could be resolved for the deps.dev lookup",
				"although the failed lookups leave that unconfirmed",
			},
		},
		{
			name:  "a deps.dev error does not count as unknown",
			eco:   model.NPM,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{
					versions:   map[string]*registry.VersionList{keyA(eco, dep): healthyListA(eco, dep)},
					downloads:  map[string]int64{keyA(eco, dep): 10_000},
					depsDevErr: map[string]error{"npm:" + dep + "@1.0.1": errors.New("POST https://api.deps.dev/v3alpha/versionbatch: unexpected status 503")},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			absent:    []string{"deps_dev_found"},
			text:      []string{"deps.dev could not be queried for npm:plain-crypto-js@1.0.1: POST https://api.deps.dev/v3alpha/versionbatch"},
		},
		{
			name:  "a dependency missing from the registry is reported without escalation",
			eco:   model.NPM,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{downloadsErr: map[string]error{keyA(eco, dep): registry.ErrNotFound}}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			text:      []string{"plain-crypto-js is not in the registry", "the npm registry has no download counts for plain-crypto-js"},
		},
		{
			name:  "no low-usage threshold means no download lookup",
			eco:   model.NPM,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{
					versions:  map[string]*registry.VersionList{keyA(eco, dep): healthyListA(eco, dep)},
					downloads: map[string]int64{keyA(eco, dep): 1},
					depsDev:   map[string]*depsdev.VersionFacts{"npm:" + dep + "@1.0.1": {Found: true}},
				}
			},
			threshold: 0,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			absent:    []string{"weekly_downloads", "min_weekly_downloads"},
		},
		{
			name:  "deps.dev is not consulted for an ecosystem it does not index",
			eco:   model.JSR,
			added: map[string]string{dep: "^1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{
					versions:     map[string]*registry.VersionList{keyA(eco, dep): healthyListA(eco, dep)},
					downloadsErr: map[string]error{keyA(eco, dep): registry.ErrUnsupported},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			absent:    []string{"deps_dev_found"},
			text:      []string{"deps.dev does not index jsr"},
		},
		{
			name:      "without a loader the dependency is reported but not inspected",
			eco:       model.NPM,
			added:     map[string]string{dep: "^1.0.0"},
			nilLoader: true,
			threshold: 500,
			want:      outcomeA{findings: 1},
			level:     model.LevelWarn,
			reasons:   []string{},
			text:      []string{"The dependency was not inspected (no loader)"},
		},
		{
			name:  "one finding per new dependency, sorted by name",
			eco:   model.NPM,
			added: map[string]string{"zeta": "^2.0.0", "beta": "~1.0.0"},
			loader: func(eco model.Ecosystem) *loaderA {
				return &loaderA{
					versions: map[string]*registry.VersionList{
						keyA(eco, "zeta"): healthyListA(eco, "zeta"),
						keyA(eco, "beta"): healthyListA(eco, "beta"),
					},
					downloads: map[string]int64{keyA(eco, "zeta"): 10_000, keyA(eco, "beta"): 10_000},
					depsDev: map[string]*depsdev.VersionFacts{
						"npm:zeta@1.0.1": {Found: true},
						"npm:beta@1.0.1": {Found: true},
					},
				}
			},
			threshold: 500,
			want:      outcomeA{findings: 2},
			level:     model.LevelWarn,
			reasons:   []string{},
			evidence:  map[string]any{"dependency": "beta", "requirement": "~1.0.0"},
			text:      []string{"1.3.0 adds beta (~1.0.0), one of 2 new dependencies (beta, zeta)"},
		},
		{
			name:  "does not fire when no dependency was added",
			eco:   model.NPM,
			added: map[string]string{},
			want:  outcomeA{},
		},
		{
			name:  "compares names in the registry's canonical spelling",
			eco:   model.PyPI,
			added: map[string]string{"Foo_Bar": ">=1"},
			loader: func(model.Ecosystem) *loaderA {
				return &loaderA{}
			},
			threshold: 500,
			want:      outcomeA{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := dependencySubjectA(tt.eco, tt.added)
			if tt.eco == model.PyPI {
				s.Previous.Dependencies["foo-bar"] = ">=1"
			}
			if tt.loader != nil && !tt.nilLoader {
				s.Loader = tt.loader(tt.eco)
			}
			s.Settings.Checks["low-usage"] = policy.CheckSetting{Level: model.LevelInfo, MinWeeklyDownloads: tt.threshold}
			res := runA(t, "TD007", s, tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			if f.Level != tt.level {
				t.Errorf("level = %s, want %s", f.Level, tt.level)
			}
			if got := stringsA(t, f.Evidence, "escalation_reasons"); !equalA(got, tt.reasons) {
				t.Errorf("escalation_reasons = %v, want %v", got, tt.reasons)
			}
			if got := f.Evidence["escalated"]; got != (len(tt.reasons) > 0) {
				t.Errorf("escalated = %v, want %v", got, len(tt.reasons) > 0)
			}
			for key, want := range tt.evidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q] = %v (%T), want %v (%T)", key, got, got, want, want)
				}
			}
			for _, key := range tt.absent {
				if _, ok := f.Evidence[key]; ok {
					t.Errorf("evidence carries %q although nothing is known for it: %v", key, f.Evidence[key])
				}
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
			if len(res.Findings) == 2 && res.Findings[1].Evidence["dependency"] != "zeta" {
				t.Errorf("second finding is about %v, want zeta", res.Findings[1].Evidence["dependency"])
			}
		})
	}
}

func TestTD007TitleNamesTheEscalation(t *testing.T) {
	const dep = "plain-crypto-js"
	s := dependencySubjectA(model.NPM, map[string]string{dep: "^1.0.0"})
	list := listA(model.NPM, dep, versionA(model.NPM, dep, "1.0.0", agoA(dayA)))
	s.Loader = &loaderA{
		versions:  map[string]*registry.VersionList{keyA(model.NPM, dep): list},
		downloads: map[string]int64{keyA(model.NPM, dep): 3},
	}
	f := runA(t, "TD007", s, outcomeA{findings: 1}).Findings[0]
	want := "New dependency plain-crypto-js (^1.0.0), not declared by 1.2.0: young, low usage and unknown to deps.dev"
	if f.Title != want {
		t.Errorf("title = %q, want %q", f.Title, want)
	}
	if !equalA(stringsA(t, f.Evidence, "new_dependencies"), []string{dep}) {
		t.Errorf("new_dependencies = %v", f.Evidence["new_dependencies"])
	}
	if errs, ok := f.Evidence["inspection_errors"]; ok {
		t.Errorf("unexpected inspection_errors: %v", errs)
	}
}

func TestTD007EscalationRespectsAnOffLevel(t *testing.T) {
	const dep = "plain-crypto-js"
	s := dependencySubjectA(model.NPM, map[string]string{dep: "^1.0.0"})
	s.Settings.Checks["new-dependency-introduced"] = policy.CheckSetting{Level: model.LevelOff}
	s.Loader = &loaderA{versions: map[string]*registry.VersionList{
		keyA(model.NPM, dep): listA(model.NPM, dep, versionA(model.NPM, dep, "1.0.0", agoA(dayA))),
	}}
	f := runA(t, "TD007", s, outcomeA{findings: 1}).Findings[0]
	if f.Level != model.LevelOff {
		t.Errorf("level = %s, want off to stay off for the runner to drop", f.Level)
	}
}

func TestTD007Skips(t *testing.T) {
	tests := []struct {
		name    string
		subject func() *Subject
		skip    string
	}{
		{
			name: "no previous version",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.0.0")
				s.Version.Dependencies = map[string]string{"a": "^1"}
				return s
			},
			skip: "no earlier release",
		},
		{
			name: "registry unavailable",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version = nil
				unavailableA(s, SourceRegistry, errors.New("offline and not in the cache"))
				return s
			},
			skip: "registry unavailable: offline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runA(t, "TD007", tt.subject(), outcomeA{skip: tt.skip})
		})
	}
}

func TestTD007LoaderCallsAreScopedToTheNewDependency(t *testing.T) {
	const dep = "plain-crypto-js"
	s := dependencySubjectA(model.NPM, map[string]string{dep: "^1.0.0"})
	l := &loaderA{
		versions:  map[string]*registry.VersionList{keyA(model.NPM, dep): healthyListA(model.NPM, dep)},
		downloads: map[string]int64{keyA(model.NPM, dep): 10_000},
		depsDev:   map[string]*depsdev.VersionFacts{"npm:" + dep + "@1.0.1": {Found: true}},
	}
	s.Loader = l
	runA(t, "TD007", s, outcomeA{findings: 1})
	want := []string{"versions npm:" + dep, "downloads npm:" + dep, "depsdev npm:" + dep + "@1.0.1"}
	if !equalA(l.calls, want) {
		t.Errorf("loader calls = %v, want %v", l.calls, want)
	}
}

// A bump usually crosses more than one release, so the second comparison is with
// the version the base lockfile had. A dependency the release before this one
// already declared is still new to a project upgrading from further back, and while
// only that release was consulted the check returned a pass. Finding F7 of
// docs/review-2026-09-10.md.
func TestTD007ComparesWithTheVersionTheProjectHad(t *testing.T) {
	tests := []struct {
		name     string
		base     map[string]string
		previous map[string]string
		current  map[string]string
		fires    bool
		named    string
		evidence map[string]any
		text     []string
	}{
		{
			name:     "the dependency arrived in the release between the two",
			base:     map[string]string{},
			previous: map[string]string{"left-pad": "^1.3.0"},
			current:  map[string]string{"left-pad": "^1.3.0"},
			fires:    true, named: "1.0.0",
			evidence: map[string]any{
				"previous_version":      "1.2.0",
				"base_version":          "1.0.0",
				"introduced_since_base": true,
			},
			text: []string{
				"1.0.0 declared 0 runtime dependencies; 1.3.0 adds left-pad (^1.3.0)",
				"the release before this one, 1.2.0, already declared it, but the version this change replaces, 1.0.0, did not",
			},
		},
		{
			name:     "new against both is still named against the previous release",
			base:     map[string]string{},
			previous: map[string]string{},
			current:  map[string]string{"left-pad": "^1.3.0"},
			fires:    true, named: "1.2.0",
			evidence: map[string]any{"base_version": "1.0.0", "introduced_since_base": true},
			text:     []string{"the version this change replaces, 1.0.0, declared none of it either"},
		},
		{
			name:     "a dependency both predecessors declared is not new",
			base:     map[string]string{"left-pad": "^1.3.0"},
			previous: map[string]string{"left-pad": "^1.3.0"},
			current:  map[string]string{"left-pad": "^1.3.0"},
			fires:    false,
		},
		{
			name:     "new against the previous release but not against the base",
			base:     map[string]string{"left-pad": "^1.3.0"},
			previous: map[string]string{},
			current:  map[string]string{"left-pad": "^1.3.0"},
			fires:    true, named: "1.2.0",
			evidence: map[string]any{"introduced_since_base": false},
			text:     []string{"the version this change replaces, 1.0.0, already declared it"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			s.Version.Dependencies = tt.current
			withPreviousA(s, "1.2.0").Dependencies = tt.previous
			withBaseA(s, "1.0.0").Dependencies = tt.base
			want := outcomeA{}
			if tt.fires {
				want.findings = 1
			}
			res := runA(t, "TD007", s, want)
			if !tt.fires {
				return
			}
			f := res.Findings[0]
			wantTextA(t, "title", f.Title, "not declared by "+tt.named)
			for key, want := range tt.evidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q] = %v, want %v", key, got, want)
				}
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}
