package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
)

func TestTD004UnknownBaseProvenanceCannotHideDowngrade(t *testing.T) {
	for _, tc := range []struct {
		name     string
		previous model.Provenance
		current  model.Provenance
		findings int
		skipped  bool
	}{
		{"unverified base could be stronger", model.Provenance{}, model.Provenance{}, 0, true},
		{"readable predecessor already proves downgrade", model.Provenance{Kind: model.ProvenanceAttestation, Verified: true, VerifiedBy: "cosign"}, model.Provenance{}, 1, false},
		{"nothing can be stronger than verified trusted publishing", model.Provenance{}, model.Provenance{Kind: model.ProvenanceTrustedPublisher, Verified: true}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			s.Version.Provenance = tc.current
			withPreviousA(s, "1.2.0").Provenance = tc.previous
			base := withBaseA(s, "1.0.0")
			base.Provenance = model.Provenance{Kind: model.ProvenanceAttestation}
			base.SetUnknown(model.FacetProvenance, "local Sigstore verification unavailable: invalid signature")
			s.DepsDev = &depsdev.VersionFacts{Found: true, AttestationVerified: true, AttestationsListed: true}
			want := outcomeA{findings: tc.findings}
			if tc.skipped {
				want.skip = "base version 1.0.0 unavailable"
			}
			res := runA(t, "TD004", s, want)
			if tc.skipped && !res.Unavailable {
				t.Fatal("base verification failure does not reach on_data_unavailable")
			}
		})
	}
}

func TestTD004LocalVerifierKeepsAttributionWhenDepsDevAlsoVerified(t *testing.T) {
	local := model.Provenance{Kind: model.ProvenanceAttestation, Verified: true, VerifiedBy: "cosign"}
	trusted := model.Provenance{Kind: model.ProvenanceTrustedPublisher, Verified: true}
	for _, side := range []string{"current", "previous", "base"} {
		t.Run(side, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			previous := withPreviousA(s, "1.2.0")
			key := "verified_by"
			switch side {
			case "current":
				s.Version.Provenance, previous.Provenance = local, trusted
			case "previous":
				previous.Provenance = local
				key = "previous_verified_by"
			case "base":
				withBaseA(s, "1.0.0").Provenance = local
				key = "base_verified_by"
			}
			s.DepsDev = &depsdev.VersionFacts{Found: true, AttestationVerified: true, AttestationsListed: true}
			f := runA(t, "TD004", s, outcomeA{findings: 1}).Findings[0]
			if f.Evidence[key] != "cosign" {
				t.Fatalf("lost local attribution for %s: %+v", side, f.Evidence)
			}
		})
	}
}

func TestTD004LocalVerificationFailureIsNotRescuedByDepsDev(t *testing.T) {
	for _, side := range []string{"current", "previous"} {
		t.Run(side, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			previous := withPreviousA(s, "1.2.0")
			previous.Provenance = model.Provenance{Kind: model.ProvenanceAttestation, Verified: true, VerifiedBy: "cosign"}
			s.Version.Provenance = model.Provenance{Kind: model.ProvenanceAttestation}
			broken := s.Version
			if side == "previous" {
				broken = previous
			}
			broken.SetUnknown(model.FacetProvenance, "local Sigstore verification unavailable: invalid signature")
			s.DepsDev = &depsdev.VersionFacts{Found: true, AttestationVerified: true, AttestationsListed: true}
			runA(t, "TD004", s, outcomeA{skip: "local Sigstore verification unavailable"})
		})
	}
}
