package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// TD002 publisher-changed reports a version whose publishing identity is not among
// the identities that published the previous N versions, N being the policy's
// previous_versions_window (brief section 4). The history is the window of
// registry.Window: earlier releases by publish time, without prereleases and yanked
// versions. Identities are compared case-insensitively. The check is skipped
// when the version or its predecessors carry no publisher, or when there is no
// earlier release, and it then falls back to the baseline described below.
//
// The registry way applies to npm and crates.io, which record a publisher per
// version (npm _npmUser and crates.io published_by, both re-verified live on
// 2026-09-09). PyPI records none, and there the only publishing identity the
// registry exposes is the one the release's PEP 740 attestation or trusted
// publisher carries; the baseline way compares that identity with the one
// .trustdiff/baseline.json recorded for the package (internal/baseline), which is
// how a release published from another repository than the last one that was
// observed is reported. A PyPI release with no attestation still has no publishing
// identity of any kind, and the check says so as a skip rather than a pass.
//
// The two ways are never mixed: an account name and the repository an attestation
// names are different kinds of thing, so a record made from one is not compared
// with the other, and the check reports why instead. A baseline entry older than
// the window a project refreshes in is still an answer, and the finding says how
// old the record is.
//
// A version published through trusted publishing has no account: the registry
// clients render the identity the registry recorded instead, and this check
// compares it like an account name. crates.io trustpub_data becomes
// "<provider>:<owner>/<repository>" (github:rust-random/rand_core), so a release
// from another repository is a publisher change; npm _npmUser.trustedPublisher
// becomes "<id>-trusted-publisher:<oidcConfigId>", so a release through a
// reconfigured trusted publisher is one too. The first release through trusted
// publishing after releases by accounts is reported as well: it is what a
// migration looks like, and also what a trusted publisher registered by whoever
// holds the account looks like, and the explanation says so.
//
// A migration to trusted publishing is the one case this reports below its
// configured level. When the evaluated version and the release before it both carry
// a verified attestation naming the same source repository, the package is still
// built where it was always built and has become harder to compromise rather than
// easier; the finding stays, at info, because the change is worth seeing.
//
// Where nothing says where either release was built, a migration whose publishing
// evidence did not weaken is reported at warn rather than at the configured level.
// Two attestations that name different repositories are not that case and keep the
// level: that is what a trusted publisher of somebody else's looks like. Scanning npm/cli's
// lockfile on 2026-09-12 produced 81 block findings and 44 of them were this: an
// ordinary package adopting trusted publishing, which is the direction this tool
// argues for, failing a gate for it. A stolen account can register a trusted
// publisher of its own, so the finding stays and stays visible; what it no longer
// does is stop a build over the one change that makes a package harder to
// compromise. A migration that also weakened the evidence keeps its level, and so
// does a release through a trusted publisher configuration that is not the one the
// previous release used.
//
// Evidence keys of the registry way:
//
//	publisher            identity that published the evaluated version
//	publisher_kind       account, or trusted-publisher for a trusted publishing identity
//	trusted_publisher_provider       the provider of a trusted publishing identity (github)
//	trusted_publisher_repository     the repository of a crates.io trusted publishing identity
//	trusted_publisher_configuration  the configuration id of an npm trusted publishing identity
//	previous_publishers  distinct identities of the previous releases, newest first
//	previous_versions    the previous releases that were compared, newest first
//	previous_releases    one object per previous release: version, publisher
//	                     (empty when not recorded) and published_at (RFC 3339)
//	attested_repository  the repository a verified attestation names for both this
//	                     version and the one before it, present only for a migration
//	                     to trusted publishing that kept building from it
//	window               the configured lookback (previous_versions_window)
//
// Evidence keys of the baseline way:
//
//	publisher            identity that published the evaluated version
//	publisher_kind       account, or trusted-publisher for a trusted publishing identity
//	publisher_source     registry for an account the registry recorded, provenance
//	                     for the identity of an attestation or a trusted publisher
//	baseline_publisher   the identity the baseline recorded
//	baseline_version     the release the record was taken from
//	baseline_observed_at when the record was made (RFC 3339)
//	baseline_age_days    how many whole days ago that was
//	baseline_rewritten   true when the change under review edited or deleted the
//	                     record, in which case the base revision's record was compared
//	baseline_rewritten_publisher    what the working tree's record now claims
//	baseline_rewritten_maintainers  the maintainer set that record now claims
//	baseline_deleted     true when the change deleted the record altogether
type td002 struct{}

func init() { Register(td002{}) }

func (td002) ID() string   { return "TD002" }
func (td002) Name() string { return "publisher-changed" }

// Ecosystems includes PyPI from milestone M4 on. PyPI records no publisher per
// version, so the check answers there only through the baseline, and for a
// release with neither a record nor an attestation it reports itself as skipped.
// Naming the ecosystem and skipping is the honest answer; leaving it out would
// have read as a check that had nothing to say about PyPI.
func (td002) Ecosystems() []model.Ecosystem {
	return []model.Ecosystem{model.NPM, model.PyPI, model.Cargo}
}

// Run looks the publisher up in the window of previous releases and falls back to
// the baseline when the registry keeps no publisher to look up. Each way returns
// the reason it could not answer, and a check that could answer neither way
// reports both reasons rather than a pass.
func (c td002) Run(ctx context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	res, registryReason := c.fromHistory(ctx, s)
	if registryReason == "" {
		return res
	}
	res, baselineReason := c.fromBaseline(s)
	if baselineReason == "" {
		return res
	}
	return Skip(c.ID(), registryReason+"; "+baselineReason)
}

// fromHistory compares the publisher of the evaluated version with the publishers
// of the previous releases. The reason it returns is empty when it answered,
// whether with a finding or with a pass.
func (c td002) fromHistory(ctx context.Context, s *Subject) (Result, string) {
	ref := evaluatedRef(s)
	if s.Version.Publisher == nil || s.Version.Publisher.Name == "" {
		if s.Ref.Ecosystem == model.PyPI {
			// Verified live on 2026-09-09: the PyPI JSON API names no uploader for
			// a release, so there is no account here to look up, ever.
			return Result{}, "pypi records no publisher per version"
		}
		return Result{}, fmt.Sprintf("no publishing account recorded for %s", ref.Version)
	}
	if s.Package == nil {
		return Result{}, noVersionReason(s)
	}
	current := registry.Find(s.Package, ref.Version)
	switch {
	case current == nil:
		return Result{}, fmt.Sprintf("%s is not in the registry's version list", ref.Version)
	case current.PublishedAt.IsZero():
		return Result{}, fmt.Sprintf("publish time of %s is unknown, so earlier releases cannot be identified", ref.Version)
	}
	window := s.Settings.PreviousVersionsWindow
	if window <= 0 {
		window = policy.DefaultPreviousVersionsWindow
	}
	history := registry.Window(s.Package, ref, window)
	if len(history) == 0 {
		return Result{}, "no earlier release to compare with"
	}

	publisher := s.Version.Publisher.Name
	identity := parsePublisher(publisher)
	versions := make([]string, 0, len(history))
	releases := make([]map[string]any, 0, len(history))
	var publishers []string
	trustedBefore := false
	for i := range history {
		h := &history[i]
		name := ""
		if h.Publisher != nil {
			name = h.Publisher.Name
		}
		versions = append(versions, h.Ref.Version)
		releases = append(releases, map[string]any{
			"version":      h.Ref.Version,
			"publisher":    name,
			"published_at": whenText(h.PublishedAt),
		})
		if name != "" && !containsFold(publishers, name) {
			publishers = append(publishers, name)
		}
		if name != "" && parsePublisher(name).trusted() {
			trustedBefore = true
		}
	}
	if len(publishers) == 0 {
		return Result{}, fmt.Sprintf("no publishing account recorded for the previous %d releases", len(history))
	}
	if containsFold(publishers, publisher) {
		return Result{}, ""
	}

	title := fmt.Sprintf("Published by %s, which published none of the previous %d versions", identity.text(), len(history))
	explanation := fmt.Sprintf("%s; %s was published by %s, %s that published none of them",
		publisherHistoryText(history), ref.Version, identity.text(), identity.noun())
	if len(history) == 1 {
		title = fmt.Sprintf("Published by %s, which did not publish the previous version", identity.text())
		explanation = fmt.Sprintf("%s; %s was published by %s, %s",
			publisherHistoryText(history), ref.Version, identity.text(), identity.different())
	}
	migration := identity.trusted() && !trustedBefore
	sameRepository := ""
	evidenceKept := false
	if migration {
		explanation += "; the earlier releases were published by accounts, so this is either a migration to trusted publishing or a trusted publisher registered by whoever holds the account"
		repo, compared := sameAttestedRepository(ctx, s, &history[0])
		if repo != "" {
			sameRepository = repo
			explanation += "; the verified attestation names " + repo + ", the repository the previous release was built from, which is what a migration looks like and not what a stolen account looks like"
		}
		if compared && repo == "" {
			explanation += "; the two releases name different repositories, which is what a trusted publisher of somebody else's looks like"
		}
		if !compared && s.Version != nil && s.Version.Provenance.Strength() >= history[0].Provenance.Strength() {
			evidenceKept = true
			explanation += "; the publishing evidence is no weaker than the previous release's, so this is reported at warn rather than at the configured level"
		}
	}
	evidence := map[string]any{
		"publisher":           publisher,
		"publisher_kind":      identity.kind(),
		"previous_publishers": publishers,
		"previous_versions":   versions,
		"previous_releases":   releases,
		"window":              window,
	}
	identity.evidence(evidence)
	if sameRepository != "" {
		evidence["attested_repository"] = sameRepository
	}
	if evidenceKept {
		evidence["evidence_kept"] = true
	}
	finding := NewFinding(c, s, title, explanation, evidence)
	switch {
	case sameRepository != "":
		// A package that moved to trusted publishing and is still built from the
		// repository it was always built from has become harder to compromise, not
		// easier, and blocking it teaches people to turn this check off. The row
		// stays, because the change is worth seeing, and it stays at info.
		finding.Level = min(finding.Level, model.LevelInfo)
	case evidenceKept:
		// The same argument with less to stand on: the identity changed to a trusted
		// publisher and the evidence did not weaken. That is what a migration looks
		// like on a package whose earlier attestation nobody verified, which is most
		// of them, and it is not worth a block on its own.
		finding.Level = min(finding.Level, model.LevelWarn)
	}
	return Result{Findings: []model.Finding{finding}}, ""
}

// fromBaseline compares the publishing identity of the evaluated release with the
// identity the project recorded for the package. The reason it returns is empty
// when it answered.
//
// The two identities have to come from the same place: an account the registry
// named and the repository an attestation names are different kinds of thing, and
// a difference between them would say nothing about who published what.
func (c td002) fromBaseline(s *Subject) (Result, string) {
	record, reason := baselineRecord(s)
	if reason != "" {
		return Result{}, reason
	}
	pkg := s.Ref.Package()
	recorded, recordedSource := record.Observed.Publisher, record.Observed.PublisherSource
	if recorded == "" {
		return Result{}, fmt.Sprintf("the baseline entry for %s records no publishing identity", pkg)
	}
	publisher, source := baseline.PublisherOf(s.Version)
	ref := evaluatedRef(s)
	if publisher == "" {
		return Result{}, fmt.Sprintf("%s carries no publishing identity to compare with the baseline", ref.Version)
	}
	if source != recordedSource {
		return Result{}, fmt.Sprintf("the baseline recorded the publisher of %s from the %s and %s carries only a %s identity, which are not comparable",
			record.Observed.Version, recordedSource, ref.Version, source)
	}
	if strings.EqualFold(publisher, recorded) {
		return Result{}, ""
	}

	identity, was := parsePublisher(publisher), parsePublisher(recorded)
	title := fmt.Sprintf("Published by %s, and the baseline recorded %s", identity.text(), was.text())
	explanation := fmt.Sprintf("the baseline recorded %s as the publisher of %s when it was observed, %s; %s was published by %s",
		was.text(), record.Observed.Version, baselineAgeText(&record.Observed, runClock(s)), ref.Version, identity.text())
	if record.Observed.Version == s.Ref.Version {
		explanation += "; this is the same release, so the registry itself changed what it says about who published it"
	}
	evidence := map[string]any{
		"publisher":          publisher,
		"publisher_kind":     identity.kind(),
		"publisher_source":   string(source),
		"baseline_publisher": recorded,
	}
	identity.evidence(evidence)
	explanation += baselineEvidence(evidence, &record, runClock(s))
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}, ""
}

// noVersionReason is the wording of noVersionSkip as a bare reason, for the ways
// of answering that return one instead of a Result.
func noVersionReason(s *Subject) string {
	if reason, recorded := s.Skipped(SourceRegistry); recorded {
		return reason
	}
	return "version details unavailable"
}

// sameAttestedRepository returns the repository a verified attestation names for
// both the evaluated version and the release before it, and "" when there is no
// such repository or the two disagree.
//
// It is what separates the two readings of a publisher change to a trusted
// publisher. A project that moved to trusted publishing keeps building from its own
// repository, and deps.dev has verified the attestation that says so. Somebody who
// took an account over and registered a trusted publisher of their own is building
// from somewhere else, and either has no verified attestation or has one naming a
// repository this package has never been built from.
func sameAttestedRepository(ctx context.Context, s *Subject, previous *model.VersionInfo) (repository string, compared bool) {
	if s.DepsDev == nil || len(s.DepsDev.SourceRepositories) == 0 || s.Loader == nil || previous == nil {
		return "", false
	}
	before, err := s.Loader.DepsDev(ctx, previous.Ref)
	if err != nil || before == nil || len(before.SourceRepositories) == 0 {
		return "", false
	}
	for _, now := range s.DepsDev.SourceRepositories {
		for _, then := range before.SourceRepositories {
			if strings.EqualFold(now, then) {
				return now, true
			}
		}
	}
	return "", true
}

// publisherIdentity is a publisher name taken apart: an account, or one of the
// trusted publishing identities the registry clients render (see the check's
// doc comment). Only the trusted publishing forms carry a provider.
type publisherIdentity struct {
	name          string
	provider      string
	repository    string
	configuration string
}

// Suffix the npm client puts after the provider id of a trusted publishing identity.
const trustedPublisherSuffix = "-trusted-publisher"

// parsePublisher recognizes the trusted publishing identities. An account name
// never contains ":" on npm or crates.io (GitHub logins), so a colon is the marker.
func parsePublisher(name string) publisherIdentity {
	id := publisherIdentity{name: name}
	prefix, rest, ok := strings.Cut(name, ":")
	if !ok || prefix == "" || rest == "" || strings.ContainsAny(name, " \t") {
		return id
	}
	switch {
	case strings.HasSuffix(prefix, trustedPublisherSuffix):
		id.provider = strings.TrimSuffix(prefix, trustedPublisherSuffix)
		id.configuration = rest
	case strings.Contains(rest, "/"):
		id.provider = prefix
		id.repository = rest
	}
	return id
}

func (p publisherIdentity) trusted() bool { return p.provider != "" }

func (p publisherIdentity) kind() string {
	if p.trusted() {
		return "trusted-publisher"
	}
	return "account"
}

// text names the identity in prose: "bob-ci", "trusted publishing from the
// github repository rust-random/rand_core", "the github trusted publisher
// configuration oidc:87d8bb4c".
func (p publisherIdentity) text() string {
	switch {
	case p.repository != "":
		return fmt.Sprintf("trusted publishing from the %s repository %s", p.provider, p.repository)
	case p.configuration != "":
		return fmt.Sprintf("the %s trusted publisher configuration %s", p.provider, p.configuration)
	default:
		return p.name
	}
}

// noun is what the identity is called after "an": "an account", "a publishing
// identity".
func (p publisherIdentity) noun() string {
	if p.trusted() {
		return "a publishing identity"
	}
	return "an account"
}

// different words the single-predecessor case.
func (p publisherIdentity) different() string {
	if p.trusted() {
		return "a different publishing identity"
	}
	return "a different account"
}

// evidence adds the parts of a trusted publishing identity.
func (p publisherIdentity) evidence(evidence map[string]any) {
	if !p.trusted() {
		return
	}
	evidence["trusted_publisher_provider"] = p.provider
	if p.repository != "" {
		evidence["trusted_publisher_repository"] = p.repository
	}
	if p.configuration != "" {
		evidence["trusted_publisher_configuration"] = p.configuration
	}
}

// publisherHistoryText renders the previous releases grouped by publisher, newest
// first: "the previous 4 versions (1.2.0, 1.1.0, 1.0.1, 1.0.0) were published by
// alice", or with several accounts "the previous 4 versions were published by alice
// (1.2.0, 1.1.0) and carol (1.0.1, 1.0.0)"; a single release reads "the previous
// version (1.0.0) was published by alice". Trusted publishing identities are
// spelled out the way the finding spells the evaluated version's.
func publisherHistoryText(history []model.VersionInfo) string {
	type group struct {
		name     string
		versions []string
	}
	var groups []*group
	var unknown []string
	for i := range history {
		h := &history[i]
		if h.Publisher == nil || h.Publisher.Name == "" {
			unknown = append(unknown, h.Ref.Version)
			continue
		}
		var g *group
		for _, candidate := range groups {
			if strings.EqualFold(candidate.name, h.Publisher.Name) {
				g = candidate
				break
			}
		}
		if g == nil {
			g = &group{name: h.Publisher.Name}
			groups = append(groups, g)
		}
		g.versions = append(g.versions, h.Ref.Version)
	}
	count, verb := fmt.Sprintf("the previous %d versions", len(history)), "were"
	if len(history) == 1 {
		count, verb = "the previous version", "was"
	}
	var text string
	if len(groups) == 1 && len(unknown) == 0 {
		text = fmt.Sprintf("%s (%s) %s published by %s", count, strings.Join(groups[0].versions, ", "), verb, parsePublisher(groups[0].name).text())
	} else {
		parts := make([]string, 0, len(groups))
		for _, g := range groups {
			parts = append(parts, fmt.Sprintf("%s (%s)", parsePublisher(g.name).text(), strings.Join(g.versions, ", ")))
		}
		text = fmt.Sprintf("%s %s published by %s", count, verb, joinAnd(parts))
	}
	if len(unknown) > 0 {
		text += fmt.Sprintf(", with no publisher recorded for %s", joinAnd(unknown))
	}
	return text
}

// containsFold reports whether names contains name, ignoring case.
func containsFold(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// joinAnd joins items for prose: "a", "a and b", "a, b and c".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}

// plural returns the suffix that makes a noun agree with n.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
