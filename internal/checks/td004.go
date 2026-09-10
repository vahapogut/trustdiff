package checks

import (
	"context"
	"fmt"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TD004 trust-downgrade reports a version whose publishing evidence is weaker than
// the previous version's (brief section 4, the pnpm trustPolicy no-downgrade idea):
// a verified attestation or trusted publishing record before, a bare signature or
// nothing now. It applies to npm, PyPI and crates.io. The comparison uses
// model.Provenance.Strength, which orders none, signature, attestation and
// trusted-publisher and ranks a verified record above an unverified one of the same
// kind.
//
// Who verifies. The npm and PyPI clients store the attestation bundle a version
// carries but never verify it, so an attestation counts as verified only when
// deps.dev verified it (attestations[].verified or slsaProvenances[].verified).
// The check consults the deps.dev facts of both versions: the evaluated version's
// from the Subject, the previous version's through the Loader when its
// attestation is not verified by the registry. verified_by names the verifier
// for each side, deps.dev whenever deps.dev verified an attestation, whatever the
// runner wrote into the Provenance beforehand. The previous version's deps.dev
// verification is applied only when deps.dev has indexed the evaluated version
// too: a fresh release that deps.dev has not seen yet compares by kind only, so
// indexing lag never produces a downgrade. The check is skipped without a
// previous version, when the previous version's details could not be fetched,
// and when a registry could not gather the provenance of either version.
//
// Two comparisons, when diff knows both: the release before the evaluated version,
// and the version the base lockfile locked, which is the version the project
// actually had. A bump usually crosses more than one release, so a trusted
// publishing record the release before this one had already dropped is still
// evidence the project is losing. The version compared with is whichever of the two
// carried the most, because the finding is about how much of it this release gives
// up, and it degenerates to the previous release when the two are equally strong.
// The base version is ignored when the registry client could not gather its
// provenance.
//
// Evidence keys:
//
//	previous_version      the previous release, whether or not it is the version
//	                      the finding names
//	previous_kind         its provenance kind: none, signature, attestation or trusted-publisher
//	previous_verified     whether that evidence was verified
//	previous_verified_by  registry or deps.dev, when verified
//	previous_identity     the workflow or repository it names, when known
//	compared_version      the version the finding names: the stronger of the two
//	base_version          the version the base lockfile locked, when diff knows one
//	                      and it is not the previous release (diff only)
//	base_kind             its provenance kind (diff only)
//	base_verified         whether that evidence was verified (diff only)
//	base_verified_by      registry or deps.dev, when verified (diff only)
//	downgraded_since_base whether that version's evidence was stronger than this
//	                      one's (diff only)
//	kind                  the evaluated version's provenance kind
//	verified              whether its evidence was verified
//	verified_by           registry or deps.dev, when verified
//	identity              the workflow or repository it names, when known
type td004 struct{}

func init() { Register(td004{}) }

func (td004) ID() string   { return "TD004" }
func (td004) Name() string { return "trust-downgrade" }
func (td004) Ecosystems() []model.Ecosystem {
	return []model.Ecosystem{model.NPM, model.PyPI, model.Cargo}
}

// Run compares the strength of the two versions' provenance.
func (c td004) Run(ctx context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	if res, skipped := previousUnavailableSkip(c, s); skipped {
		return res
	}
	if s.Previous == nil {
		return Skip(c.ID(), "no earlier release to compare with")
	}
	ref := evaluatedRef(s)
	if reason, unknown := unknownFacet(s.Version, model.FacetProvenance); unknown {
		return Skip(c.ID(), fmt.Sprintf("provenance of %s unavailable: %s", ref.Version, reason))
	}
	if reason, unknown := unknownFacet(s.Previous, model.FacetProvenance); unknown {
		return Skip(c.ID(), fmt.Sprintf("provenance of the previous version %s unavailable: %s", s.Previous.Ref.Version, reason))
	}

	current := s.Version.Provenance
	var verifiedBy string
	current.Verified, verifiedBy = verification(current, s.DepsDev)
	previous, previousBy := predecessorProvenance(ctx, s, s.Previous)

	// Two comparisons, when diff knows both: the release before this one, and the
	// version the project actually had. The finding is about how much evidence this
	// release lost, so the version to compare with is whichever of the two carried
	// the most of it; a record the release before this one had already dropped is
	// still evidence the project is losing.
	base := comparableBase(s, model.FacetProvenance)
	var baseProvenance model.Provenance
	baseBy := ""
	if base != nil {
		baseProvenance, baseBy = predecessorProvenance(ctx, s, base)
	}
	compared, comparedBy, with := previous, previousBy, s.Previous
	if base != nil && baseProvenance.Strength() > previous.Strength() {
		compared, comparedBy, with = baseProvenance, baseBy, base
	}
	if compared.Strength() <= current.Strength() {
		return Result{}
	}

	title := fmt.Sprintf("Provenance weaker than %s: %s before, %s now",
		with.Ref.Version, provenanceText(compared, false), provenanceText(current, false))
	// The tail names what the comparison was against. It stays "the previous one"
	// wherever the previous release is the version compared with, which is every
	// run but a diff whose base carried more than that release did.
	against := "the previous one"
	if with != s.Previous {
		against = "the version this change replaces"
	}
	explanation := fmt.Sprintf("%s was published with %s; %s was published with %s, so the evidence tying this release to its source is weaker than for %s",
		with.Ref.Version, provenanceText(compared, true), ref.Version, provenanceText(current, true), against)
	if with != s.Previous {
		explanation += fmt.Sprintf("; the release before this one, %s, was published with %s, so the loss is only visible against the version the project actually had",
			s.Previous.Ref.Version, provenanceText(previous, true))
	}
	var notes []string
	if verifiedBy == SourceDepsDev {
		notes = append(notes, "the attestation was verified by deps.dev, not by the registry")
	}
	if comparedBy == SourceDepsDev {
		if with == s.Previous {
			notes = append(notes, "the previous version's attestation was verified by deps.dev, not by the registry")
		} else {
			notes = append(notes, fmt.Sprintf("%s's attestation was verified by deps.dev, not by the registry", with.Ref.Version))
		}
	}
	if len(notes) > 0 {
		explanation += " (" + joinAnd(notes) + ")"
	}
	evidence := map[string]any{
		"previous_version":  s.Previous.Ref.Version,
		"previous_kind":     string(kindOrNone(previous.Kind)),
		"previous_verified": previous.Verified,
		"compared_version":  with.Ref.Version,
		"kind":              string(kindOrNone(current.Kind)),
		"verified":          current.Verified,
	}
	if base != nil {
		evidence["base_version"] = base.Ref.Version
		evidence["base_kind"] = string(kindOrNone(baseProvenance.Kind))
		evidence["base_verified"] = baseProvenance.Verified
		evidence["downgraded_since_base"] = baseProvenance.Strength() > current.Strength()
	}
	if previous.Identity != "" {
		evidence["previous_identity"] = previous.Identity
	}
	if current.Identity != "" {
		evidence["identity"] = current.Identity
	}
	if previousBy != "" {
		evidence["previous_verified_by"] = previousBy
	}
	if base != nil && baseBy != "" {
		evidence["base_verified_by"] = baseBy
	}
	if verifiedBy != "" {
		evidence["verified_by"] = verifiedBy
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// predecessorProvenance reads what an earlier version was published with, and who
// vouched for it. It reads deliberately differently from verification, which judges
// the evaluated version: here a registry that verified the record settles it, and
// only an attestation the registry left unverified is taken to deps.dev, and only
// when deps.dev has indexed the evaluated version too. That last condition is what
// keeps indexing lag from inventing a downgrade out of a predecessor deps.dev knows
// and an evaluated version it has not seen yet.
func predecessorProvenance(ctx context.Context, s *Subject, v *model.VersionInfo) (model.Provenance, string) {
	p := v.Provenance
	if p.Verified {
		return p, SourceRegistry
	}
	if p.Kind == model.ProvenanceAttestation && s.Loader != nil && s.DepsDev != nil && s.DepsDev.Found {
		if facts, err := s.Loader.DepsDev(ctx, v.Ref); err == nil && depsDevVerified(facts) {
			p.Verified = true
			return p, SourceDepsDev
		}
	}
	return p, ""
}

// verification decides whether provenance counts as verified and by whom. An
// attestation that deps.dev verified is credited to deps.dev even when the
// Provenance already says verified: no registry client verifies attestations,
// so that flag came from deps.dev through the runner. Anything else verified is
// the registry's own word (a trusted publishing record, a registry signature).
func verification(p model.Provenance, facts *depsdev.VersionFacts) (verified bool, by string) {
	if p.Kind == model.ProvenanceAttestation && depsDevVerified(facts) {
		return true, SourceDepsDev
	}
	if p.Verified {
		return true, SourceRegistry
	}
	return false, ""
}

// depsDevVerified reports whether deps.dev has the version and verified a build
// attestation or SLSA provenance for it.
func depsDevVerified(facts *depsdev.VersionFacts) bool {
	return facts != nil && facts.Found && (facts.AttestationVerified || facts.SLSAVerified)
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

// previousUnavailableSkip is the skip every check that compares with the
// previous version returns when the runner could not fetch that version's
// details (Subject.Unavailable[SourcePrevious]): the version-list entry it kept
// carries the publish time and publisher but not the dependencies, scripts or
// provenance, so comparing against it would report every fact as new.
func previousUnavailableSkip(c Check, s *Subject) (Result, bool) {
	if reason, ok := s.Skipped(SourcePrevious); ok {
		return Skip(c.ID(), reason), true
	}
	return Result{}, false
}
