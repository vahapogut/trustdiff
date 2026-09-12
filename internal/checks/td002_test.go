package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/model"
)

// historyA builds a subject whose package history is the given (version,
// publisher, age in days) triples, oldest first, and whose evaluated version is
// the last one.
func historyA(eco model.Ecosystem, releases ...releaseA) *Subject {
	name := "lib"
	versions := make([]model.VersionInfo, 0, len(releases))
	for _, r := range releases {
		v := versionA(eco, name, r.version, agoA(time.Duration(r.daysAgo)*dayA))
		if r.publisher != "" {
			v.Publisher = &model.Publisher{Name: r.publisher}
		}
		v.Prerelease, v.Yanked = r.prerelease, r.yanked
		versions = append(versions, v)
	}
	last := versions[len(versions)-1]
	s := subjectA(eco, name, last.Ref.Version)
	s.Version = &last
	s.Package = listA(eco, name, versions...)
	return s
}

type releaseA struct {
	version    string
	publisher  string
	daysAgo    int
	prerelease bool
	yanked     bool
}

func TestTD002PublisherChanged(t *testing.T) {
	tests := []struct {
		name    string
		subject func() *Subject
		want    outcomeA
		// when a finding fires
		publisher  string // the evaluated version's publisher; bob-ci when empty
		publishers []string
		versions   []string
		window     int
		kind       string // publisher_kind; account when empty
		// level is what the finding must carry; block when the row does not say.
		level    model.Level
		evidence map[string]any
		text     []string
	}{
		{
			name: "fires when the publisher is new",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.0.1", "alice", 30, false, false},
					releaseA{"1.1.0", "alice", 20, false, false},
					releaseA{"1.2.0", "alice", 10, false, false},
					releaseA{"1.3.0", "bob-ci", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"alice"},
			versions:   []string{"1.2.0", "1.1.0", "1.0.1", "1.0.0"},
			window:     5,
			text: []string{
				"the previous 4 versions (1.2.0, 1.1.0, 1.0.1, 1.0.0) were published by alice",
				"1.3.0 was published by bob-ci, an account that published none of them",
			},
		},
		{
			name: "does not fire for a returning publisher",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "carol", 20, false, false},
					releaseA{"1.2.0", "alice", 1, false, false})
			},
			want: outcomeA{},
		},
		{
			name: "compares account names without regard to case",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"1.0.0", "Alice", 40, false, false},
					releaseA{"1.1.0", "alice", 1, false, false})
			},
			want: outcomeA{},
		},
		{
			name: "looks back only as far as the window",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "bob-ci", 40, false, false},
					releaseA{"1.1.0", "carol", 30, false, false},
					releaseA{"1.2.0", "carol", 20, false, false},
					releaseA{"1.3.0", "bob-ci", 1, false, false})
				s.Settings.PreviousVersionsWindow = 2
				return s
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"carol"},
			versions:   []string{"1.2.0", "1.1.0"},
			window:     2,
		},
		{
			name: "falls back to the built-in window when the settings are empty",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "bob-ci", 70, false, false},
					releaseA{"1.1.0", "carol", 60, false, false},
					releaseA{"1.2.0", "carol", 50, false, false},
					releaseA{"1.3.0", "carol", 40, false, false},
					releaseA{"1.4.0", "carol", 30, false, false},
					releaseA{"1.5.0", "carol", 20, false, false},
					releaseA{"1.6.0", "bob-ci", 1, false, false})
				s.Settings.PreviousVersionsWindow = 0
				return s
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"carol"},
			versions:   []string{"1.5.0", "1.4.0", "1.3.0", "1.2.0", "1.1.0"},
			window:     5,
		},
		{
			name: "ignores yanked versions and prereleases in the history",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.0.1", "bob-ci", 30, false, true},
					releaseA{"1.1.0-rc.1", "bob-ci", 20, true, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"alice"},
			versions:   []string{"1.0.0"},
			window:     5,
			text:       []string{"the previous version (1.0.0) was published by alice; 1.1.0 was published by bob-ci, a different account"},
		},
		{
			name: "lists several previous publishers with their versions",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "carol", 40, false, false},
					releaseA{"1.1.0", "alice", 20, false, false},
					releaseA{"1.2.0", "", 10, false, false},
					releaseA{"1.3.0", "bob-ci", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"alice", "carol"},
			versions:   []string{"1.2.0", "1.1.0", "1.0.0"},
			window:     5,
			text: []string{
				"the previous 3 versions were published by alice (1.1.0) and carol (1.0.0), with no publisher recorded for 1.2.0",
			},
		},
		{
			name: "crates.io trusted publishing from another repository is a change",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"0.9.0", "github:rust-random/core", 40, false, false},
					releaseA{"0.10.0", "github:rust-random/core", 20, false, false},
					releaseA{"0.10.1", "github:attacker/rand_core", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publisher:  "github:attacker/rand_core",
			publishers: []string{"github:rust-random/core"},
			versions:   []string{"0.10.0", "0.9.0"},
			window:     5,
			kind:       "trusted-publisher",
			evidence:   map[string]any{"trusted_publisher_provider": "github", "trusted_publisher_repository": "attacker/rand_core"},
			text: []string{
				"the previous 2 versions (0.10.0, 0.9.0) were published by trusted publishing from the github repository rust-random/core",
				"0.10.1 was published by trusted publishing from the github repository attacker/rand_core, a publishing identity that published none of them",
			},
		},
		{
			name: "crates.io trusted publishing from the same repository is no change",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"0.10.0", "github:rust-random/rand_core", 20, false, false},
					releaseA{"0.10.1", "github:rust-random/rand_core", 1, false, false})
			},
			want: outcomeA{},
		},
		{
			name: "npm trusted publishing through the same configuration is no change",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"4.0.0", "github-trusted-publisher:oidc:87d8bb4c", 20, false, false},
					releaseA{"5.0.0", "github-trusted-publisher:oidc:87d8bb4c", 1, false, false})
			},
			want: outcomeA{},
		},
		{
			name: "npm trusted publishing through a reconfigured publisher is a change",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"4.0.0", "github-trusted-publisher:oidc:87d8bb4c", 20, false, false},
					releaseA{"5.0.0", "github-trusted-publisher:oidc:87d8bb4c", 10, false, false},
					releaseA{"6.0.0", "github-trusted-publisher:oidc:5e2f01aa", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publisher:  "github-trusted-publisher:oidc:5e2f01aa",
			publishers: []string{"github-trusted-publisher:oidc:87d8bb4c"},
			versions:   []string{"5.0.0", "4.0.0"},
			window:     5,
			kind:       "trusted-publisher",
			evidence:   map[string]any{"trusted_publisher_provider": "github", "trusted_publisher_configuration": "oidc:5e2f01aa"},
			text: []string{
				"were published by the github trusted publisher configuration oidc:87d8bb4c",
				"6.0.0 was published by the github trusted publisher configuration oidc:5e2f01aa, a publishing identity that published none of them",
			},
		},
		{
			name: "migration from an account to npm trusted publishing names the configuration",
			// Nothing says where either release was built, which is where almost every
			// real migration lands, so the finding reports at warn rather than block.
			level: model.LevelWarn,
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"2.3.2", "bdehamer", 40, false, false},
					releaseA{"3.0.0", "bdehamer", 30, false, false},
					releaseA{"3.1.0", "bdehamer", 20, false, false},
					releaseA{"4.0.0", "github-trusted-publisher:oidc:87d8bb4c", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publisher:  "github-trusted-publisher:oidc:87d8bb4c",
			publishers: []string{"bdehamer"},
			versions:   []string{"3.1.0", "3.0.0", "2.3.2"},
			window:     5,
			kind:       "trusted-publisher",
			text: []string{
				"the previous 3 versions (3.1.0, 3.0.0, 2.3.2) were published by bdehamer",
				"4.0.0 was published by the github trusted publisher configuration oidc:87d8bb4c, a publishing identity that published none of them",
				"either a migration to trusted publishing or a trusted publisher registered by whoever holds the account",
			},
		},
		{
			name: "a single trusted publishing predecessor reads as a different identity",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"0.10.0", "github:rust-random/core", 20, false, false},
					releaseA{"0.10.1", "github:rust-random/rand_core", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publisher:  "github:rust-random/rand_core",
			publishers: []string{"github:rust-random/core"},
			versions:   []string{"0.10.0"},
			window:     5,
			kind:       "trusted-publisher",
			text:       []string{"0.10.1 was published by trusted publishing from the github repository rust-random/rand_core, a different publishing identity"},
		},
		{
			name: "skipped when the version has no publisher",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "", 1, false, false})
			},
			want: outcomeA{skip: "no publishing account recorded for 1.1.0"},
		},
		{
			name: "skipped when no previous release has a publisher",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "", 40, false, false},
					releaseA{"1.0.1", "", 30, false, false},
					releaseA{"1.1.0", "alice", 1, false, false})
			},
			want: outcomeA{skip: "no publishing account recorded for the previous 2 releases"},
		},
		{
			name: "skipped for a first release",
			subject: func() *Subject {
				return historyA(model.NPM, releaseA{"1.0.0", "alice", 1, false, false})
			},
			want: outcomeA{skip: "no earlier release"},
		},
		{
			name: "skipped when the history was not loaded",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Package = nil
				unavailableA(s, SourceRegistry, errors.New("status 503"))
				return s
			},
			want: outcomeA{skip: "registry unavailable: status 503"},
		},
		{
			name: "skipped when the evaluated version is not in the list",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Package.Versions = s.Package.Versions[:1]
				return s
			},
			want: outcomeA{skip: "1.1.0 is not in the registry's version list"},
		},
		{
			name: "skipped when the evaluated version has no publish time",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Package.Versions[1].PublishedAt = time.Time{}
				return s
			},
			want: outcomeA{skip: "publish time of 1.1.0 is unknown"},
		},
		{
			name: "skipped when the version details are missing",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Version = nil
				return s
			},
			want: outcomeA{skip: "version details unavailable"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runA(t, "TD002", tt.subject(), tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			wantLevel := tt.level
			if wantLevel == model.LevelOff {
				wantLevel = model.LevelBlock
			}
			if f.Level != wantLevel {
				t.Errorf("level = %s, want %s", f.Level, wantLevel)
			}
			if got := stringsA(t, f.Evidence, "previous_publishers"); !equalA(got, tt.publishers) {
				t.Errorf("previous_publishers = %v, want %v", got, tt.publishers)
			}
			if got := stringsA(t, f.Evidence, "previous_versions"); !equalA(got, tt.versions) {
				t.Errorf("previous_versions = %v, want %v", got, tt.versions)
			}
			if got := f.Evidence["window"]; got != tt.window {
				t.Errorf("window = %v, want %d", got, tt.window)
			}
			publisher, kind := tt.publisher, tt.kind
			if publisher == "" {
				publisher = "bob-ci"
			}
			if kind == "" {
				kind = "account"
			}
			if got := f.Evidence["publisher"]; got != publisher {
				t.Errorf("publisher = %v, want %s", got, publisher)
			}
			if got := f.Evidence["publisher_kind"]; got != kind {
				t.Errorf("publisher_kind = %v, want %s", got, kind)
			}
			for key, want := range tt.evidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q] = %v, want %v", key, got, want)
				}
			}
			if kind == "account" {
				for _, key := range []string{"trusted_publisher_provider", "trusted_publisher_repository", "trusted_publisher_configuration"} {
					if v, ok := f.Evidence[key]; ok {
						t.Errorf("evidence carries %s = %v for an account", key, v)
					}
				}
			}
			releases, ok := f.Evidence["previous_releases"].([]map[string]any)
			if !ok || len(releases) != len(tt.versions) {
				t.Errorf("previous_releases = %v, want %d entries", f.Evidence["previous_releases"], len(tt.versions))
			}
			wantTextA(t, "title", f.Title, "Published by "+parsePublisher(publisher).text())
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

func TestTD002UsesTheRegistryRefWhenTheSubjectRefIsBare(t *testing.T) {
	s := historyA(model.NPM,
		releaseA{"1.0.0", "alice", 40, false, false},
		releaseA{"1.1.0", "bob-ci", 1, false, false})
	s.Ref = s.Ref.Package()
	s.ResolvedLatest = true
	f := runA(t, "TD002", s, outcomeA{findings: 1}).Findings[0]
	if f.Ref != s.Ref {
		t.Errorf("finding ref = %s, want the subject's bare ref %s", f.Ref, s.Ref)
	}
	wantTextA(t, "explanation", f.Explanation, "1.1.0 was published by bob-ci")
}

// PyPI is answered through the baseline from milestone M4 on. The registry names
// no uploader, so the only publishing identity there is the one the release's
// attestation carries, and the check compares it with the identity the project
// recorded.
func TestTD002AppliesToPyPIThroughTheBaseline(t *testing.T) {
	c, _ := Lookup("TD002")
	if !AppliesTo(c, model.PyPI) {
		t.Fatal("TD002 does not apply to pypi; the brief routes PyPI through the baseline")
	}

	// Without a record there is nothing to compare with, and the reason names both
	// halves of the answer rather than passing the release.
	bare := runA(t, "TD002", subjectA(model.PyPI, "requests", "2.32.0"), outcomeA{skip: "pypi records no publisher per version"})
	if !strings.Contains(bare.Skipped.Reason, "the run read no baseline") {
		t.Errorf("reason = %q, want the baseline's half too", bare.Skipped.Reason)
	}
}

// attestedA gives the evaluated version a verified PEP 740 attestation naming a
// repository, which is what a PyPI release published from a workflow carries.
func attestedA(s *Subject, identity string) *Subject {
	s.Version.Provenance = model.Provenance{Kind: model.ProvenanceAttestation, Verified: true, Identity: identity}
	return s
}

func TestTD002FromTheBaselineForPyPI(t *testing.T) {
	const was = "github:psf/requests/publish.yml"
	const now = "github:mallory/requests/publish.yml"

	// A release built somewhere else than the one that was recorded is the finding
	// this exists for.
	s := attestedA(subjectA(model.PyPI, "requests", "2.32.0"), now)
	withBaselineT(s, publishedByT(entryT("pypi:requests@2.31.0", 20, "alice"), was, baseline.FromProvenance))
	f := runA(t, "TD002", s, outcomeA{findings: 1}).Findings[0]
	if f.Level != model.LevelBlock {
		t.Errorf("level = %s, want block", f.Level)
	}
	if f.Evidence["baseline_publisher"] != was || f.Evidence["publisher"] != now {
		t.Errorf("evidence = %v, want both identities", f.Evidence)
	}
	if f.Evidence["publisher_source"] != string(baseline.FromProvenance) {
		t.Errorf("publisher_source = %v, want provenance", f.Evidence["publisher_source"])
	}
	if f.Evidence["baseline_version"] != "2.31.0" || f.Evidence["baseline_age_days"] != 20 {
		t.Errorf("evidence = %v, want the record's version and age", f.Evidence)
	}
	// The identity is rendered the way the check renders every trusted publishing
	// identity, so a PyPI attestation reads like a crates.io trustpub entry.
	wantTextA(t, "explanation", f.Explanation, "when it was observed, 20 days ago", "mallory/requests/publish.yml")

	// The same identity is a pass.
	same := attestedA(subjectA(model.PyPI, "requests", "2.32.0"), was)
	withBaselineT(same, publishedByT(entryT("pypi:requests@2.31.0", 20, "alice"), was, baseline.FromProvenance))
	runA(t, "TD002", same, outcomeA{})
}

// A release with no attestation has no publishing identity of any kind on PyPI,
// and that is a skip with a reason, never a pass.
func TestTD002BaselineSkipsAReleaseWithoutAnIdentity(t *testing.T) {
	s := subjectA(model.PyPI, "requests", "2.32.0")
	withBaselineT(s, publishedByT(entryT("pypi:requests@2.31.0", 4, "alice"), "github:psf/requests/publish.yml", baseline.FromProvenance))
	runA(t, "TD002", s, outcomeA{skip: "2.32.0 carries no publishing identity to compare with the baseline"})
}

// An account name and the repository an attestation names are different kinds of
// thing, so a record made from one is never compared with the other.
func TestTD002BaselineRefusesToMixIdentitySources(t *testing.T) {
	s := attestedA(subjectA(model.PyPI, "requests", "2.32.0"), "github:psf/requests/publish.yml")
	withBaselineT(s, publishedByT(entryT("pypi:requests@2.31.0", 4, "alice"), "alice", baseline.FromRegistry))
	runA(t, "TD002", s, outcomeA{skip: "which are not comparable"})
}

// The record the base revision holds is what a pull request is measured against,
// because the change under review may have written the record itself.
func TestTD002ComparesTheBaseRevisionWhenTheChangeRewroteTheEntry(t *testing.T) {
	const was = "github:psf/requests/publish.yml"
	const now = "github:mallory/requests/publish.yml"
	s := attestedA(subjectA(model.PyPI, "requests", "2.32.0"), now)
	withRewrittenBaselineT(s,
		[]*baseline.Entry{publishedByT(entryT("pypi:requests@2.32.0", 0, "alice"), now, baseline.FromProvenance)},
		[]*baseline.Entry{publishedByT(entryT("pypi:requests@2.31.0", 30, "alice"), was, baseline.FromProvenance)})

	f := runA(t, "TD002", s, outcomeA{findings: 1}).Findings[0]
	if f.Evidence["baseline_publisher"] != was || f.Evidence["baseline_rewritten"] != true {
		t.Errorf("evidence = %v, want the base revision's record and the rewrite", f.Evidence)
	}
	if f.Evidence["baseline_rewritten_publisher"] != now {
		t.Errorf("baseline_rewritten_publisher = %v, want %q", f.Evidence["baseline_rewritten_publisher"], now)
	}
	wantTextA(t, "explanation", f.Explanation, "the change under review rewrote this package's baseline entry")
}

// npm and crates.io keep a publisher per version, so the release history answers
// and the baseline is not consulted at all.
func TestTD002PrefersTheRegistryHistory(t *testing.T) {
	s := historyA(model.NPM,
		releaseA{"1.0.0", "alice", 40, false, false},
		releaseA{"1.1.0", "bob-ci", 1, false, false})
	withBaselineT(s, publishedByT(entryT("npm:lib@1.1.0", 1, "alice"), "bob-ci", baseline.FromRegistry))
	f := runA(t, "TD002", s, outcomeA{findings: 1}).Findings[0]
	if _, ok := f.Evidence["baseline_publisher"]; ok {
		t.Errorf("evidence = %v, want the release history and not the baseline", f.Evidence)
	}
}

func TestParsePublisher(t *testing.T) {
	tests := []struct {
		name     string
		trusted  bool
		text     string
		provider string
	}{
		{name: "bob-ci", text: "bob-ci"},
		{name: "GitHub Actions", text: "GitHub Actions"},
		{name: "github:rust-random/rand_core", trusted: true, provider: "github", text: "trusted publishing from the github repository rust-random/rand_core"},
		{name: "github-trusted-publisher:oidc:87d8bb4c-1", trusted: true, provider: "github", text: "the github trusted publisher configuration oidc:87d8bb4c-1"},
		{name: "odd:name", text: "odd:name"},
		{name: ":", text: ":"},
		{name: "a b:c/d", text: "a b:c/d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := parsePublisher(tt.name)
			if id.trusted() != tt.trusted || id.provider != tt.provider || id.text() != tt.text {
				t.Errorf("parsePublisher(%q) = trusted %v provider %q text %q; want %v %q %q",
					tt.name, id.trusted(), id.provider, id.text(), tt.trusted, tt.provider, tt.text)
			}
		})
	}
}

// A package that moved to trusted publishing and is still built from the
// repository it was always built from has become harder to compromise, not easier.
// Blocking that teaches people to turn the check off, and the packages doing it
// right now are the ones everybody depends on: five of fifty entries of npm's own
// lockfile were in the middle of that migration on 2026-09-09.
func TestTD002MigrationToTrustedPublishingFromTheSameRepository(t *testing.T) {
	const repo = "https://github.com/example/lib"
	build := func(before, after string) *Subject {
		s := historyA(model.NPM,
			releaseA{"1.0.0", "alice", 40, false, false},
			releaseA{"1.1.0", "alice", 20, false, false},
			releaseA{"1.2.0", "github-trusted-publisher:0dd1c2e3", 1, false, false})
		s.DepsDev = &depsdev.VersionFacts{Found: true, AttestationVerified: true, SourceRepositories: []string{after}}
		s.Loader = &loaderA{depsDev: map[string]*depsdev.VersionFacts{
			"npm:lib@1.1.0": {Found: true, AttestationVerified: true, SourceRepositories: []string{before}},
		}}
		return s
	}

	// The same repository on both sides: the change is worth seeing and is not a
	// reason to fail a gate.
	f := runA(t, "TD002", build(repo, repo), outcomeA{findings: 1}).Findings[0]
	if f.Level != model.LevelInfo {
		t.Errorf("level = %s, want info for a migration that kept its repository", f.Level)
	}
	if f.Evidence["attested_repository"] != repo {
		t.Errorf("evidence = %v, want the repository named", f.Evidence)
	}
	wantTextA(t, "explanation", f.Explanation, "the repository the previous release was built from")

	// A different repository is what a stolen account with a trusted publisher of
	// its own looks like, and it keeps the level the policy sets.
	other := runA(t, "TD002", build(repo, "https://github.com/attacker/lib"), outcomeA{findings: 1}).Findings[0]
	if other.Level != model.LevelBlock {
		t.Errorf("level = %s, want block when the attestation names another repository", other.Level)
	}
	if _, ok := other.Evidence["attested_repository"]; ok {
		t.Errorf("evidence names a repository although the two disagree: %v", other.Evidence)
	}

	// No verified attestation at all is the ordinary state of a package whose earlier
	// releases nobody attested, and it is where almost every real migration lands:
	// 44 of the 81 block findings of a scan of npm/cli's lockfile on 2026-09-12 were
	// this shape, every one of them a package adopting trusted publishing. Blocking
	// them teaches people to turn the check off, so the finding stays and reports at
	// warn. A stolen account could look like this too, which is why it is still a
	// finding and why a run that fails on warnings still fails.
	none := historyA(model.NPM,
		releaseA{"1.0.0", "alice", 40, false, false},
		releaseA{"1.2.0", "github-trusted-publisher:0dd1c2e3", 1, false, false})
	none.Loader = &loaderA{}
	if got := runA(t, "TD002", none, outcomeA{findings: 1}).Findings[0]; got.Level != model.LevelWarn {
		t.Errorf("level = %s, want warn with no attestation to compare", got.Level)
	}
}

// npm's trusted publishing replaces the account that published a release with a
// synthetic identity, so the first release published that way is a publisher change
// by any reading, and it is also the change this tool exists to encourage: the
// package stopped being published from somebody's laptop. Measured on 2026-09-12 on
// npm/cli's lockfile: 44 of the 81 block findings of one scan were exactly this.
// A migration whose publishing evidence did not weaken is reported at warn, so it
// is still seen and no longer fails a gate. One whose evidence weakened keeps the
// level the policy set, because that is also what a stolen account with a trusted
// publisher of its own looks like.
func TestTD002MigrationToTrustedPublishingDoesNotBlock(t *testing.T) {
	const trusted = "github-trusted-publisher:oidc:11607fbf-b2d2-4ab1-98ba-a91b9aa036a0"
	build := func(now, before model.Provenance) *Subject {
		s := historyA(model.NPM,
			releaseA{version: "1.0.0", publisher: "alice", daysAgo: 40},
			releaseA{version: "1.1.0", publisher: trusted, daysAgo: 10})
		s.Version.Provenance = now
		for i := range s.Package.Versions {
			if s.Package.Versions[i].Ref.Version == "1.0.0" {
				s.Package.Versions[i].Provenance = before
			}
		}
		return s
	}
	attested := model.Provenance{Kind: model.ProvenanceAttestation, Verified: true}
	signature := model.Provenance{Kind: model.ProvenanceSignature}

	t.Run("evidence no weaker is a warning", func(t *testing.T) {
		out := runA(t, "TD002", build(attested, signature), outcomeA{findings: 1})
		if got := out.Findings[0].Level; got != model.LevelWarn {
			t.Errorf("level = %s, want warn: a package that moved to trusted publishing without losing evidence must not fail a gate", got)
		}
	})

	t.Run("evidence weaker keeps the level", func(t *testing.T) {
		out := runA(t, "TD002", build(signature, attested), outcomeA{findings: 1})
		if got := out.Findings[0].Level; got != model.LevelBlock {
			t.Errorf("level = %s, want block: the identity changed and the evidence got weaker", got)
		}
	})
}
