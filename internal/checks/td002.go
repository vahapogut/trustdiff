package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// TD002 publisher-changed reports a version whose publishing identity is not among
// the identities that published the previous N versions, N being the policy's
// previous_versions_window (brief section 4). It applies to npm and crates.io, the
// registries that record a publisher per version (npm _npmUser and crates.io
// published_by, both re-verified live on 2026-09-09); PyPI has no per-version
// publisher and is covered by the baseline in M4. The history is the window of
// registry.Window: earlier releases by publish time, without prereleases and yanked
// versions. Identities are compared case-insensitively. The check is skipped
// when the version or its predecessors carry no publisher, or when there is no
// earlier release.
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
// Evidence keys:
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
//	window               the configured lookback (previous_versions_window)
type td002 struct{}

func init() { Register(td002{}) }

func (td002) ID() string                    { return "TD002" }
func (td002) Name() string                  { return "publisher-changed" }
func (td002) Ecosystems() []model.Ecosystem { return []model.Ecosystem{model.NPM, model.Cargo} }

// Run looks the publisher up in the window of previous releases.
func (c td002) Run(_ context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	ref := evaluatedRef(s)
	if s.Version.Publisher == nil || s.Version.Publisher.Name == "" {
		return Skip(c.ID(), fmt.Sprintf("no publishing account recorded for %s", ref.Version))
	}
	if s.Package == nil {
		return noVersionSkip(c, s)
	}
	current := registry.Find(s.Package, ref.Version)
	switch {
	case current == nil:
		return Skip(c.ID(), fmt.Sprintf("%s is not in the registry's version list", ref.Version))
	case current.PublishedAt.IsZero():
		return Skip(c.ID(), fmt.Sprintf("publish time of %s is unknown, so earlier releases cannot be identified", ref.Version))
	}
	window := s.Settings.PreviousVersionsWindow
	if window <= 0 {
		window = policy.DefaultPreviousVersionsWindow
	}
	history := registry.Window(s.Package, ref, window)
	if len(history) == 0 {
		return Skip(c.ID(), "no earlier release to compare with")
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
		return Skip(c.ID(), fmt.Sprintf("no publishing account recorded for the previous %d releases", len(history)))
	}
	if containsFold(publishers, publisher) {
		return Result{}
	}

	title := fmt.Sprintf("Published by %s, which published none of the previous %d versions", identity.text(), len(history))
	explanation := fmt.Sprintf("%s; %s was published by %s, %s that published none of them",
		publisherHistoryText(history), ref.Version, identity.text(), identity.noun())
	if len(history) == 1 {
		title = fmt.Sprintf("Published by %s, which did not publish the previous version", identity.text())
		explanation = fmt.Sprintf("%s; %s was published by %s, %s",
			publisherHistoryText(history), ref.Version, identity.text(), identity.different())
	}
	if identity.trusted() && !trustedBefore {
		explanation += "; the earlier releases were published by accounts, so this is either a migration to trusted publishing or a trusted publisher registered by whoever holds the account"
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
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
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
