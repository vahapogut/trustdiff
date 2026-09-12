package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
)

func TestTD004TrustDowngrade(t *testing.T) {
	verifiedAttestation := model.Provenance{Kind: model.ProvenanceAttestation, Verified: true, Identity: "github.com/org/lib/.github/workflows/release.yml"}
	unverifiedAttestation := model.Provenance{Kind: model.ProvenanceAttestation}
	signature := model.Provenance{Kind: model.ProvenanceSignature, Verified: true}
	trusted := model.Provenance{Kind: model.ProvenanceTrustedPublisher, Verified: true, Identity: "github.com/org/lib"}
	none := model.Provenance{}

	tests := []struct {
		name     string
		eco      model.Ecosystem
		previous model.Provenance
		current  model.Provenance
		depsDev  *depsdev.VersionFacts
		fires    bool
		evidence map[string]any
		text     []string
	}{
		{
			name: "verified attestation to nothing", eco: model.NPM,
			previous: verifiedAttestation, current: none, fires: true,
			evidence: map[string]any{
				"previous_version":  "1.2.0",
				"previous_kind":     "attestation",
				"previous_verified": true,
				"previous_identity": "github.com/org/lib/.github/workflows/release.yml",
				"kind":              "none",
				"verified":          false,
			},
			text: []string{
				"1.2.0 was published with a verified build attestation for github.com/org/lib/.github/workflows/release.yml",
				"1.3.0 was published with no provenance evidence",
			},
		},
		{
			name: "verified attestation to unverified attestation", eco: model.NPM,
			previous: verifiedAttestation, current: unverifiedAttestation, fires: true,
			evidence: map[string]any{"kind": "attestation", "verified": false},
			text:     []string{"1.3.0 was published with an unverified build attestation"},
		},
		{
			name: "trusted publishing to attestation", eco: model.PyPI,
			previous: trusted, current: verifiedAttestation, fires: true,
			evidence: map[string]any{"previous_kind": "trusted-publisher", "verified_by": "registry"},
			text:     []string{"a verified trusted publishing record for github.com/org/lib", "a verified build attestation"},
		},
		{
			name: "attestation to registry signature", eco: model.NPM,
			previous: verifiedAttestation, current: signature, fires: true,
			evidence: map[string]any{"kind": "signature", "verified": true},
			text:     []string{"a verified registry signature"},
		},
		{
			name: "unverified to verified is an upgrade", eco: model.NPM,
			previous: unverifiedAttestation, current: verifiedAttestation, fires: false,
		},
		{
			name: "nothing to nothing", eco: model.Cargo,
			previous: none, current: none, fires: false,
		},
		{
			name: "same evidence on both sides", eco: model.Cargo,
			previous: trusted, current: trusted, fires: false,
		},
		{
			name: "deps.dev verification of the attestation prevents a false downgrade", eco: model.NPM,
			previous: verifiedAttestation, current: unverifiedAttestation,
			depsDev: &depsdev.VersionFacts{Found: true, AttestationVerified: true}, fires: false,
		},
		{
			name: "deps.dev verification is credited but does not hide a real downgrade", eco: model.PyPI,
			previous: trusted, current: unverifiedAttestation,
			depsDev: &depsdev.VersionFacts{Found: true, SLSAVerified: true}, fires: true,
			evidence: map[string]any{"kind": "attestation", "verified": true, "verified_by": "deps.dev"},
			text:     []string{"the attestation was verified by deps.dev, not by the registry"},
		},
		{
			name: "deps.dev verification does not apply to a version it has not seen", eco: model.NPM,
			previous: verifiedAttestation, current: unverifiedAttestation,
			depsDev: &depsdev.VersionFacts{Found: false, AttestationVerified: true}, fires: true,
		},
		{
			name: "deps.dev verification does not upgrade a bare signature", eco: model.NPM,
			previous: verifiedAttestation, current: model.Provenance{Kind: model.ProvenanceSignature},
			depsDev: &depsdev.VersionFacts{Found: true, AttestationVerified: true}, fires: true,
			evidence: map[string]any{"kind": "signature", "verified": false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectA(tt.eco, "lib", "1.3.0")
			s.Version.Provenance = tt.current
			withPreviousA(s, "1.2.0").Provenance = tt.previous
			s.DepsDev = tt.depsDev
			want := outcomeA{}
			if tt.fires {
				want.findings = 1
			}
			res := runA(t, "TD004", s, want)
			if !tt.fires {
				return
			}
			f := res.Findings[0]
			if f.Level != model.LevelBlock {
				t.Errorf("level = %s, want block", f.Level)
			}
			for key, want := range tt.evidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q] = %v, want %v", key, got, want)
				}
			}
			wantTextA(t, "title", f.Title, "Provenance weaker than 1.2.0")
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

func TestTD004OptionalEvidenceKeys(t *testing.T) {
	s := subjectA(model.NPM, "lib", "1.3.0")
	withPreviousA(s, "1.2.0").Provenance = model.Provenance{Kind: model.ProvenanceSignature}
	f := runA(t, "TD004", s, outcomeA{findings: 1}).Findings[0]
	for _, key := range []string{"previous_identity", "identity", "verified_by"} {
		if _, ok := f.Evidence[key]; ok {
			t.Errorf("evidence carries %q although nothing is known for it", key)
		}
	}
	wantTextA(t, "explanation", f.Explanation, "an unverified registry signature", "no provenance evidence")
}

func TestTD004Skips(t *testing.T) {
	tests := []struct {
		name    string
		subject func() *Subject
		skip    string
	}{
		{
			name: "no previous version",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.0.0")
				s.Version.Provenance = model.Provenance{Kind: model.ProvenanceNone}
				return s
			},
			skip: "no earlier release",
		},
		{
			name: "version details missing",
			subject: func() *Subject {
				s := subjectA(model.Cargo, "serde", "1.0.200")
				s.Version = nil
				return s
			},
			skip: "version details unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runA(t, "TD004", tt.subject(), outcomeA{skip: tt.skip})
		})
	}
}

// The version the project actually had is the second comparison, and the finding is
// about how much evidence this release gives up, so the version compared with is
// whichever predecessor carried the most. A trusted publishing record the release
// before this one had already dropped is still a record the project is losing, and
// while only the previous release was consulted that loss was reported as nothing at
// all. Finding F7 of docs/review-2026-09-10.md, the half of it about TD004.
func TestTD004ComparesWithTheVersionTheProjectHad(t *testing.T) {
	trusted := model.Provenance{Kind: model.ProvenanceTrustedPublisher, Verified: true, Identity: "github.com/org/lib"}
	signature := model.Provenance{Kind: model.ProvenanceSignature, Verified: true}
	none := model.Provenance{}

	tests := []struct {
		name     string
		base     model.Provenance
		previous model.Provenance
		current  model.Provenance
		fires    bool
		named    string
		evidence map[string]any
		text     []string
	}{
		{
			name: "the record was dropped before the release this change locks",
			base: trusted, previous: none, current: none, fires: true, named: "1.0.0",
			evidence: map[string]any{
				"previous_version":      "1.2.0",
				"previous_kind":         "none",
				"compared_version":      "1.0.0",
				"base_version":          "1.0.0",
				"base_kind":             "trusted-publisher",
				"base_verified":         true,
				"downgraded_since_base": true,
			},
			text: []string{
				"1.0.0 was published with a verified trusted publishing record for github.com/org/lib",
				"weaker than for the version this change replaces",
				"the release before this one, 1.2.0, was published with no provenance evidence",
			},
		},
		{
			name: "the previous release carried more, so it is the comparison",
			base: signature, previous: trusted, current: none, fires: true, named: "1.2.0",
			evidence: map[string]any{
				"compared_version":      "1.2.0",
				"base_version":          "1.0.0",
				"base_kind":             "signature",
				"downgraded_since_base": true,
			},
			text: []string{"weaker than for the previous one"},
		},
		{
			name: "neither predecessor carried more than this release",
			base: none, previous: none, current: signature, fires: false,
		},
		{
			// The two are equally strong, so the rule degenerates to the previous
			// release, which is the closer comparison.
			name: "equal strength names the previous release",
			base: trusted, previous: trusted, current: none, fires: true, named: "1.2.0",
			evidence: map[string]any{"compared_version": "1.2.0", "downgraded_since_base": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			s.Version.Provenance = tt.current
			withPreviousA(s, "1.2.0").Provenance = tt.previous
			withBaseA(s, "1.0.0").Provenance = tt.base
			want := outcomeA{}
			if tt.fires {
				want.findings = 1
			}
			res := runA(t, "TD004", s, want)
			if !tt.fires {
				return
			}
			f := res.Findings[0]
			wantTextA(t, "title", f.Title, "Provenance weaker than "+tt.named)
			for key, want := range tt.evidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q] = %v, want %v", key, got, want)
				}
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

// The release published before this one is not always an earlier version of it. A
// maintenance release on an older line goes out after the newer line has moved on,
// and comparing the two says nothing about what the project gave up: it says that
// 9.x carries less than 10.x, which is a fact about the two lines and not about
// this release. Measured on 2026-09-12 on npm/cli's lockfile, both trust-downgrade
// block findings of that scan were this shape, @octokit/endpoint 9.0.6 against
// 10.1.3 and semver 5.7.2 against 7.5.4. The check now says it has nothing to
// compare with, so it reports at warn and says so.
func TestTD004SkipsAMaintenanceReleaseOnAnOlderLine(t *testing.T) {
	s := subjectA(model.NPM, "endpoint", "9.0.6")
	s.Version.Provenance = model.Provenance{Kind: model.ProvenanceSignature}
	previous := versionA(model.NPM, "endpoint", "10.1.3", agoA(30*dayA))
	previous.Provenance = model.Provenance{Kind: model.ProvenanceAttestation, Verified: true}
	s.Previous = &previous

	f := runA(t, "TD004", s, outcomeA{findings: 1}).Findings[0]
	if f.Level != model.LevelWarn {
		t.Errorf("level = %s, want warn: the comparison is across release lines, not a loss this release made", f.Level)
	}
	if f.Evidence["maintenance_release"] != true {
		t.Errorf("evidence = %v, want it to say this is a maintenance release", f.Evidence)
	}
}
