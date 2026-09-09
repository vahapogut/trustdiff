package checks

import (
	"context"
	"fmt"

	"github.com/vahapogut/trustdiff/internal/model"
)

// TD004 trust-downgrade reports a version whose publishing evidence is weaker than
// the previous version's (brief section 4, the pnpm trustPolicy no-downgrade idea):
// a verified attestation or trusted publishing record before, a bare signature or
// nothing now. It applies to npm, PyPI and crates.io. The comparison uses
// model.Provenance.Strength, which orders none, signature, attestation and
// trusted-publisher and ranks a verified record above an unverified one of the same
// kind. When the registry reports an attestation it did not verify, a deps.dev
// verification of the same version (attestations[].verified or
// slsaProvenances[].verified) counts as verified, so a registry that only stores
// the bundle does not produce a downgrade by itself. The check is skipped without a
// previous version.
//
// Evidence keys:
//
//	previous_version    the previous release compared with
//	previous_kind       its provenance kind: none, signature, attestation or trusted-publisher
//	previous_verified   whether that evidence was verified
//	previous_identity   the workflow or repository it names, when known
//	kind                the evaluated version's provenance kind
//	verified            whether its evidence was verified
//	verified_by         registry or deps.dev, when verified
//	identity            the workflow or repository it names, when known
type td004 struct{}

func init() { Register(td004{}) }

func (td004) ID() string   { return "TD004" }
func (td004) Name() string { return "trust-downgrade" }
func (td004) Ecosystems() []model.Ecosystem {
	return []model.Ecosystem{model.NPM, model.PyPI, model.Cargo}
}

// Run compares the strength of the two versions' provenance.
func (c td004) Run(_ context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	if s.Previous == nil {
		return Skip(c.ID(), "no earlier release to compare with")
	}
	previous := s.Previous.Provenance
	current := s.Version.Provenance
	verifiedBy := ""
	if current.Verified {
		verifiedBy = SourceRegistry
	} else if current.Kind == model.ProvenanceAttestation && s.DepsDev != nil && s.DepsDev.Found &&
		(s.DepsDev.AttestationVerified || s.DepsDev.SLSAVerified) {
		current.Verified = true
		verifiedBy = SourceDepsDev
	}
	if previous.Strength() <= current.Strength() {
		return Result{}
	}

	ref := evaluatedRef(s)
	title := fmt.Sprintf("Provenance weaker than %s: %s before, %s now",
		s.Previous.Ref.Version, provenanceText(previous, false), provenanceText(current, false))
	explanation := fmt.Sprintf("%s was published with %s; %s was published with %s, so the evidence tying this release to its source is weaker than for the previous one",
		s.Previous.Ref.Version, provenanceText(previous, true), ref.Version, provenanceText(current, true))
	if verifiedBy == SourceDepsDev {
		explanation += " (the attestation was verified by deps.dev, not by the registry)"
	}
	evidence := map[string]any{
		"previous_version":  s.Previous.Ref.Version,
		"previous_kind":     string(kindOrNone(previous.Kind)),
		"previous_verified": previous.Verified,
		"kind":              string(kindOrNone(current.Kind)),
		"verified":          current.Verified,
	}
	if previous.Identity != "" {
		evidence["previous_identity"] = previous.Identity
	}
	if current.Identity != "" {
		evidence["identity"] = current.Identity
	}
	if verifiedBy != "" {
		evidence["verified_by"] = verifiedBy
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// kindOrNone spells an unset kind as none, which is what an empty kind means.
func kindOrNone(k model.ProvenanceKind) model.ProvenanceKind {
	if k == "" {
		return model.ProvenanceNone
	}
	return k
}

// provenanceText describes provenance in prose: "a verified build attestation",
// "an unverified registry signature", "no provenance evidence". With identity the
// workflow or repository the record names is appended.
func provenanceText(p model.Provenance, identity bool) string {
	var noun string
	switch p.Kind {
	case model.ProvenanceSignature:
		noun = "registry signature"
	case model.ProvenanceAttestation:
		noun = "build attestation"
	case model.ProvenanceTrustedPublisher:
		noun = "trusted publishing record"
	case model.ProvenanceNone, "":
		return "no provenance evidence"
	default:
		noun = string(p.Kind) + " record"
	}
	text := "an unverified " + noun
	if p.Verified {
		text = "a verified " + noun
	}
	if identity && p.Identity != "" {
		text += " for " + p.Identity
	}
	return text
}
