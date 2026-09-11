package checks

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// TD007 new-dependency-introduced reports every runtime dependency the evaluated
// version declares and the previous version did not (brief section 4, the Axios
// to plain-crypto-js pattern). Applies to every ecosystem; one finding per new
// dependency, so each one is explained and escalated on its own. An allow entry is
// matched against the subject, so it covers every dependency that version added
// rather than one of them, and a pattern naming a dependency matches nothing. Each
// new dependency is
// inspected through the Loader and the finding is raised to block when the
// dependency is young, has low usage or is unknown to deps.dev:
//
//   - young: the package's first release was published less than 7 days before
//     the run; when the requirement pins an exact version, that version's own
//     publish time counts as well. The newest release of an established package
//     is not judged, because a range such as ^18.0.0 does not install it;
//   - low usage: the weekly downloads are below the min_weekly_downloads of the
//     low-usage check (no escalation where the registry has no counts, PyPI);
//   - unknown to deps.dev: deps.dev has no record of the resolved version, and
//     none of the package's first release either, so a few hours of indexing lag
//     on a fresh release of a known package cannot escalate.
//
// Two kinds of new dependency are reported without escalation, with the reasons
// that would have applied listed as waived: a PyPI requirement whose marker
// names an extra (pip installs it only when the extra is requested), and a
// dependency that shares its origin with the evaluated package (same npm scope
// as the package, a scope named after the package, or the same publishing
// account), which is the shape of a platform package split out of its parent
// (@esbuild/linux-x64 introduced by esbuild) rather than of an unrelated
// package pulled in. A loader error never escalates; the explanation says what
// could not be checked. The check is skipped without a previous version, when
// the previous version's details could not be fetched (a version-list entry
// carries no dependencies, so comparing against it would report every
// dependency as new), and when the registry could not gather the dependencies
// of either version. A base version nobody could reach is not ignored quietly:
// where it would have decided the answer the check reports itself as skipped
// naming it. A base version the registry no longer has, which is what an
// unpublished release looks like, is an answer, and the check goes on with the
// release before this one alone.
//
// Evidence keys (present in every finding unless marked):
//
//	previous_version      the previous release, whether or not it is the version
//	                      the finding names
//	dependency            the new dependency's name
//	requirement           the version requirement the evaluated version declares
//	optional              true for a PyPI requirement behind an extra marker
//	extra                 the extra that enables it (when optional)
//	new_dependencies      every dependency the evaluated version added, sorted
//	escalated             whether the level was raised to block
//	escalation_reasons    young, low-usage and unknown-to-deps.dev, those that apply
//	waived_reasons        reasons that applied but did not escalate (when any)
//	same_origin           scope or publisher, why the reasons were waived (when they were)
//	pinned                whether the requirement pins one exact version
//	resolved_version      the pinned version, or the newest stable one otherwise (when resolved)
//	published_at          its RFC 3339 publish time (when known)
//	first_published_at    RFC 3339 time of the package's first release (when known)
//	weekly_downloads      the dependency's weekly downloads (when the registry has them)
//	min_weekly_downloads  the low-usage threshold applied (when one is configured)
//	deps_dev_found        whether deps.dev knows the resolved version (when looked up)
//	deps_dev_first_release        the first release asked about when the resolved
//	                              version was unknown (when asked)
//	deps_dev_first_release_found  whether deps.dev knows that release (when asked)
//	inspection_errors     loader errors, one sentence each (when any)
type td007 struct{}

func init() { Register(td007{}) }

func (td007) ID() string                    { return "TD007" }
func (td007) Name() string                  { return "new-dependency-introduced" }
func (td007) Ecosystems() []model.Ecosystem { return nil }

// youngDependencyAge is the age under which a new dependency escalates the finding
// (brief section 4: "young (<7 d)").
const youngDependencyAge = 7 * 24 * time.Hour

// Escalation reasons, as spelled in evidence.
const (
	reasonYoung    = "young"
	reasonLowUsage = "low-usage"
	reasonUnknown  = "unknown-to-deps.dev"
)

// Values of the same_origin evidence key.
const (
	originScope     = "scope"
	originPublisher = "publisher"
)

// Run reports each dependency the previous version did not declare.
func (c td007) Run(ctx context.Context, s *Subject) Result {
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
	eco := ref.Ecosystem
	if reason, unknown := unknownFacet(s.Version, model.FacetDependencies); unknown {
		return Skip(c.ID(), fmt.Sprintf("dependencies of %s unavailable: %s", ref.Version, reason))
	}
	if reason, unknown := unknownFacet(s.Previous, model.FacetDependencies); unknown {
		return Skip(c.ID(), fmt.Sprintf("dependencies of the previous version %s unavailable: %s", s.Previous.Ref.Version, reason))
	}
	previous := declaredDependencies(eco, s.Previous)
	current := declaredDependencies(eco, s.Version)
	// Two comparisons, when diff knows both: the release before this one, and the
	// version the project actually had. A dependency the previous release already
	// declared is still new to a project upgrading from further back, which is the
	// axios shape this check is named for once the bump crosses the release that
	// added it.
	base := comparableBase(s, model.FacetDependencies)
	var inBase map[string]requirement
	if base != nil {
		inBase = declaredDependencies(eco, base)
	}
	var added []string
	since := make(map[string]*introduction, len(current))
	for key, req := range current {
		fromPrevious := newRuntimeDependency(previous, key, req)
		fromBase := base != nil && newRuntimeDependency(inBase, key, req)
		if !fromPrevious && !fromBase {
			continue
		}
		intro := &introduction{fromPrevious: fromPrevious, fromBase: fromBase, base: base}
		// The version to name is the one that declared none of it; when neither
		// did, the previous release is the closer comparison.
		if fromPrevious {
			intro.had, intro.declared = s.Previous, previous
		} else {
			intro.had, intro.declared = base, inBase
		}
		added = append(added, req.name)
		since[key] = intro
	}
	if len(added) == 0 {
		// Nothing new against the versions that were read. A base version nobody
		// could reach leaves the other half of the question open, because a
		// dependency the release before this one already declared may still be new
		// to this project.
		return cleanOrSkip(c, s, SourceBase)
	}
	sort.Strings(added)

	threshold := s.Setting("low-usage").MinWeeklyDownloads
	now := runClock(s)
	findings := make([]model.Finding, 0, len(added))
	for _, name := range added {
		key := model.NormalizeName(eco, name)
		facts := inspectDependency(ctx, s, eco, name, current[key], threshold)
		facts.settle(ctx, s, ref, name, now, threshold)
		findings = append(findings, c.finding(s, ref, name, added, facts, since[key], threshold))
	}
	return Result{Findings: findings}
}

// requirement is one declared dependency requirement taken apart.
type requirement struct {
	// name is the dependency's name as the version spells it.
	name string
	text string
	// optional is true for a dependency a plain install does not pull in: one
	// recorded in VersionInfo.OptionalDependencies, or a PyPI requirement whose
	// marker needs an extra.
	optional bool
	// extra is the extra the marker names, when known.
	extra string
}

// declaredDependencies merges a version's runtime and optional dependencies,
// keyed by canonical name; a runtime declaration wins over an optional one of
// the same name.
func declaredDependencies(eco model.Ecosystem, v *model.VersionInfo) map[string]requirement {
	out := make(map[string]requirement, len(v.Dependencies)+len(v.OptionalDependencies))
	for name, text := range v.OptionalDependencies {
		req := parseRequirement(eco, text)
		req.name, req.optional = name, true
		out[model.NormalizeName(eco, name)] = req
	}
	for name, text := range v.Dependencies {
		req := parseRequirement(eco, text)
		req.name = name
		out[model.NormalizeName(eco, name)] = req
	}
	return out
}

// introduction is why one dependency counts as new: which of the two versions the
// check compares with declared none of it, and the version the finding names and
// counts the declarations of.
type introduction struct {
	// fromPrevious is true when the release before the evaluated one declared none
	// of it, fromBase when the version the base lockfile had declared none.
	fromPrevious bool
	fromBase     bool
	// had is the version that declared none of it and declared what it did declare.
	// It is the previous release whenever that release lacked the dependency, the
	// closer of the two comparisons.
	had      *model.VersionInfo
	declared map[string]requirement
	// base is the version the base lockfile had, nil unless diff knows one and it
	// is not the previous release.
	base *model.VersionInfo
}

// baseText words the second comparison for the explanation, saying which of the two
// versions declared the dependency and which did not. Empty when diff knows no base
// version of its own.
func (i *introduction) baseText(previousVersion string) string {
	if i.base == nil {
		return ""
	}
	switch {
	case i.fromPrevious && i.fromBase:
		return fmt.Sprintf("; the version this change replaces, %s, declared none of it either", i.base.Ref.Version)
	case i.fromBase:
		return fmt.Sprintf("; the release before this one, %s, already declared it, but the version this change replaces, %s, did not, so the dependency is new to this project",
			previousVersion, i.base.Ref.Version)
	default:
		return fmt.Sprintf("; the version this change replaces, %s, already declared it", i.base.Ref.Version)
	}
}

// newRuntimeDependency reports whether a version's declarations lack the
// requirement as a runtime dependency: it declared nothing of that name, or
// declared it only behind an extra while the evaluated version declares it
// outright.
func newRuntimeDependency(declared map[string]requirement, key string, req requirement) bool {
	before, ok := declared[key]
	return !ok || (before.optional && !req.optional)
}

// extraMarkers match the two spellings of an extra clause in a PEP 508 marker:
// extra == 'name' and 'name' == extra. Other markers (python_version,
// sys_platform) describe runtime conditions and keep the requirement a runtime one.
var extraMarkers = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|[^A-Za-z0-9_])extra\s*==\s*['"]([^'"]*)['"]`),
	regexp.MustCompile(`['"]([^'"]*)['"]\s*==\s*extra(?:$|[^A-Za-z0-9_])`),
}

// parseRequirement reads a requirement as the registry client recorded it. For
// PyPI the marker after ";" is inspected for an extra clause; other ecosystems
// record runtime dependencies only.
func parseRequirement(eco model.Ecosystem, text string) requirement {
	req := requirement{text: text}
	if eco != model.PyPI {
		return req
	}
	_, marker, ok := strings.Cut(text, ";")
	if !ok {
		return req
	}
	for _, re := range extraMarkers {
		if m := re.FindStringSubmatch(marker); m != nil {
			req.optional, req.extra = true, strings.TrimSpace(m[1])
			return req
		}
	}
	return req
}

// dependencyFacts is what the Loader could tell about one new dependency.
type dependencyFacts struct {
	requirement requirement
	// resolved is the pinned version, or the newest stable one; pinned says which.
	resolved       *model.VersionInfo
	pinned         bool
	firstPublished time.Time
	downloads      int64
	downloadsKnown bool
	// depsDevKnown is true when deps.dev answered for the resolved version;
	// depsDevFound whether it knows that version. When it does not, the
	// package's first release is asked about: firstRelease names it and
	// firstReleaseFound says whether deps.dev knows it; packageUnknown is the
	// escalating conclusion.
	depsDevFound      bool
	depsDevKnown      bool
	firstRelease      string
	firstReleaseFound bool
	packageUnknown    bool
	// reasons escalate the finding; waived are reasons that applied but were
	// set aside, sameOrigin says why (scope or publisher) unless the
	// requirement is optional.
	reasons    []string
	waived     []string
	sameOrigin string
	// notes say why a signal does not apply (no counts for the ecosystem);
	// problems are loader errors. Neither escalates.
	notes    []string
	problems []string
}

// applicable lists the escalation reasons that apply to the facts.
func (f *dependencyFacts) applicable(now time.Time, threshold int64) []string {
	reasons := []string{}
	if f.isYoung(now) {
		reasons = append(reasons, reasonYoung)
	}
	if f.downloadsKnown && threshold > 0 && f.downloads < threshold {
		reasons = append(reasons, reasonLowUsage)
	}
	if f.packageUnknown {
		reasons = append(reasons, reasonUnknown)
	}
	return reasons
}

// isYoung judges the package by its first release, and by the pinned version's
// own publish time when the requirement pins one.
func (f *dependencyFacts) isYoung(now time.Time) bool {
	if f.pinned && f.resolved != nil && !f.resolved.PublishedAt.IsZero() && now.Sub(f.resolved.PublishedAt) < youngDependencyAge {
		return true
	}
	return !f.firstPublished.IsZero() && now.Sub(f.firstPublished) < youngDependencyAge
}

// settle decides the escalation: the applicable reasons, minus the waivers for an
// optional requirement or a dependency of the same origin as the package.
func (f *dependencyFacts) settle(ctx context.Context, s *Subject, ref model.PackageRef, name string, now time.Time, threshold int64) {
	reasons := f.applicable(now, threshold)
	f.reasons = reasons
	if len(reasons) == 0 {
		return
	}
	switch {
	case f.requirement.optional:
		f.waived, f.reasons = reasons, []string{}
	default:
		if origin := sameOrigin(ctx, s, ref, name, f); origin != "" {
			f.sameOrigin = origin
			f.waived, f.reasons = reasons, []string{}
		}
	}
}

// inspectDependency gathers the facts about one new dependency through the Loader.
func inspectDependency(ctx context.Context, s *Subject, eco model.Ecosystem, name string, req requirement, threshold int64) *dependencyFacts {
	facts := &dependencyFacts{requirement: req}
	if s.Loader == nil {
		facts.notes = append(facts.notes, "the dependency was not inspected (no loader)")
		return facts
	}
	list, err := s.Loader.Versions(ctx, eco, name)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		facts.problems = append(facts.problems, fmt.Sprintf("%s is not in the registry", name))
	case err != nil:
		facts.problems = append(facts.problems, fmt.Sprintf("the version list of %s could not be fetched: %v", name, err))
	case list == nil:
		facts.problems = append(facts.problems, fmt.Sprintf("the registry returned no version list for %s", name))
	default:
		facts.resolved, facts.pinned = resolveRequirement(eco, list, facts.requirement.text)
		facts.firstPublished = firstPublished(list)
	}

	if threshold > 0 {
		n, err := s.Loader.Downloads(ctx, eco, name)
		switch {
		case errors.Is(err, registry.ErrUnsupported):
			facts.notes = append(facts.notes, fmt.Sprintf("%s has no download counts", registryName(eco)))
		case errors.Is(err, registry.ErrNotFound):
			facts.problems = append(facts.problems, fmt.Sprintf("%s has no download counts for %s", registryName(eco), name))
		case err != nil:
			facts.problems = append(facts.problems, fmt.Sprintf("the weekly downloads of %s could not be fetched: %v", name, err))
		default:
			facts.downloads, facts.downloadsKnown = n, true
		}
	}

	switch {
	case depsdev.System(eco) == "":
		facts.notes = append(facts.notes, fmt.Sprintf("deps.dev does not index %s", eco))
	case facts.resolved == nil:
		facts.notes = append(facts.notes, "no version could be resolved for the deps.dev lookup")
	default:
		inspectDepsDev(ctx, s, list, name, facts)
	}
	return facts
}

// inspectDepsDev asks deps.dev about the resolved version and, when that is
// unknown and not pinned, about the package's first release, so that a package
// deps.dev knows is never escalated for a release it has not indexed yet.
func inspectDepsDev(ctx context.Context, s *Subject, list *registry.VersionList, name string, facts *dependencyFacts) {
	eco := list.Ecosystem
	depRef := model.PackageRef{Ecosystem: eco, Name: name, Version: facts.resolved.Ref.Version}
	dd, err := s.Loader.DepsDev(ctx, depRef)
	switch {
	case errors.Is(err, depsdev.ErrUnsupported):
		facts.notes = append(facts.notes, fmt.Sprintf("deps.dev does not index %s", eco))
		return
	case err != nil:
		facts.problems = append(facts.problems, fmt.Sprintf("deps.dev could not be queried for %s: %v", depRef, err))
		return
	case dd == nil:
		facts.problems = append(facts.problems, fmt.Sprintf("deps.dev returned no facts for %s", depRef))
		return
	}
	facts.depsDevFound, facts.depsDevKnown = dd.Found, true
	facts.packageUnknown = !dd.Found
	if dd.Found || facts.pinned {
		return
	}
	first := firstRelease(list)
	if first == nil || first.Ref.Version == facts.resolved.Ref.Version {
		return
	}
	firstRef := depRef.WithVersion(first.Ref.Version)
	dd, err = s.Loader.DepsDev(ctx, firstRef)
	switch {
	case err != nil:
		facts.problems = append(facts.problems, fmt.Sprintf("deps.dev could not be queried for %s: %v", firstRef, err))
		facts.packageUnknown = false
	case dd == nil:
		facts.problems = append(facts.problems, fmt.Sprintf("deps.dev returned no facts for %s", firstRef))
		facts.packageUnknown = false
	default:
		facts.firstRelease, facts.firstReleaseFound = first.Ref.Version, dd.Found
		facts.packageUnknown = !dd.Found
	}
}

// sameOrigin reports why a dependency belongs with the evaluated package: scope
// when it lives in the package's own npm scope or in a scope named after the
// package, publisher when the version it resolves to was published by the same
// account as the evaluated version. Empty when neither holds or nothing is known.
func sameOrigin(ctx context.Context, s *Subject, ref model.PackageRef, name string, facts *dependencyFacts) string {
	if ref.Ecosystem == model.NPM {
		if scope := npmScope(name); scope != "" && (scope == npmScope(ref.Name) || scope == "@"+ref.Name) {
			return originScope
		}
	}
	if s.Version.Publisher == nil || s.Version.Publisher.Name == "" || facts.resolved == nil {
		return ""
	}
	publisher := facts.resolved.Publisher
	if publisher == nil && s.Loader != nil {
		if info, err := s.Loader.VersionInfo(ctx, facts.resolved.Ref); err == nil && info != nil {
			publisher = info.Publisher
		}
	}
	if publisher != nil && publisher.Name != "" && strings.EqualFold(publisher.Name, s.Version.Publisher.Name) {
		return originPublisher
	}
	return ""
}

// npmScope returns the scope of a scoped npm name ("@esbuild" for
// @esbuild/linux-x64), or "" for an unscoped one.
func npmScope(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	scope, _, ok := strings.Cut(name, "/")
	if !ok {
		return ""
	}
	return scope
}

// finding builds the finding for one new dependency and escalates it when a
// reason applies.
func (c td007) finding(s *Subject, ref model.PackageRef, name string, added []string, facts *dependencyFacts, intro *introduction, threshold int64) model.Finding {
	now := runClock(s)
	reasons := facts.reasons
	if reasons == nil {
		reasons = []string{}
	}
	escalated := len(reasons) > 0

	kind := "dependency"
	if facts.requirement.optional {
		kind = "optional dependency"
	}
	title := fmt.Sprintf("New %s %s (%s), not declared by %s", kind, name, facts.requirement.text, intro.had.Ref.Version)
	if escalated {
		title += ": " + joinAnd(reasonTexts(reasons))
	}
	explanation := dependencyText(s, ref, name, added, facts, intro, now, threshold)

	evidence := map[string]any{
		"previous_version":   s.Previous.Ref.Version,
		"dependency":         name,
		"requirement":        facts.requirement.text,
		"optional":           facts.requirement.optional,
		"new_dependencies":   added,
		"escalated":          escalated,
		"escalation_reasons": reasons,
	}
	if facts.requirement.optional {
		evidence["extra"] = facts.requirement.extra
	}
	if len(facts.waived) > 0 {
		evidence["waived_reasons"] = facts.waived
	}
	if facts.sameOrigin != "" {
		evidence["same_origin"] = facts.sameOrigin
	}
	if facts.resolved != nil {
		evidence["pinned"] = facts.pinned
		evidence["resolved_version"] = facts.resolved.Ref.Version
		if !facts.resolved.PublishedAt.IsZero() {
			evidence["published_at"] = whenText(facts.resolved.PublishedAt)
		}
	}
	if !facts.firstPublished.IsZero() {
		evidence["first_published_at"] = whenText(facts.firstPublished)
	}
	if facts.downloadsKnown {
		evidence["weekly_downloads"] = facts.downloads
	}
	if threshold > 0 {
		evidence["min_weekly_downloads"] = threshold
	}
	if facts.depsDevKnown {
		evidence["deps_dev_found"] = facts.depsDevFound
	}
	if facts.firstRelease != "" {
		evidence["deps_dev_first_release"] = facts.firstRelease
		evidence["deps_dev_first_release_found"] = facts.firstReleaseFound
	}
	if len(facts.problems) > 0 {
		evidence["inspection_errors"] = facts.problems
	}
	if intro.base != nil {
		evidence["base_version"] = intro.base.Ref.Version
		evidence["introduced_since_base"] = intro.fromBase
	}

	f := NewFinding(c, s, title, explanation, evidence)
	if escalated && f.Level != model.LevelOff && !f.Level.AtLeast(model.LevelBlock) {
		f.Level = model.LevelBlock
	}
	return f
}

// dependencyText writes the explanation: what changed, what is known about the
// dependency, and why the level was or was not raised.
func dependencyText(s *Subject, ref model.PackageRef, name string, added []string, facts *dependencyFacts, intro *introduction, now time.Time, threshold int64) string {
	var b strings.Builder
	runtime := runtimeDependencies(intro.declared)
	fmt.Fprintf(&b, "%s declared %d runtime dependenc%s; %s adds %s (%s)",
		intro.had.Ref.Version, runtime, pluralY(runtime), ref.Version, name, facts.requirement.text)
	if len(added) > 1 {
		fmt.Fprintf(&b, ", one of %d new dependencies (%s)", len(added), strings.Join(added, ", "))
	}
	b.WriteString(intro.baseText(s.Previous.Ref.Version))
	b.WriteString(". ")

	var known []string
	if v := facts.resolved; v != nil {
		take := "the newest stable version is"
		if facts.pinned {
			take = "a fresh install would take the pinned"
		}
		if v.PublishedAt.IsZero() {
			known = append(known, fmt.Sprintf("%s %s@%s, whose publish time is unknown", take, name, v.Ref.Version))
		} else {
			known = append(known, fmt.Sprintf("%s %s@%s, published on %s (%s)", take, name, v.Ref.Version, whenText(v.PublishedAt), sinceText(now, v.PublishedAt)))
		}
	}
	if !facts.firstPublished.IsZero() {
		known = append(known, fmt.Sprintf("the package's first release dates from %s (%s)", whenText(facts.firstPublished), sinceText(now, facts.firstPublished)))
	}
	if facts.downloadsKnown {
		text := fmt.Sprintf("it has %d weekly downloads", facts.downloads)
		if threshold > 0 && facts.downloads < threshold {
			text += fmt.Sprintf(", below the low-usage threshold of %d", threshold)
		}
		known = append(known, text)
	}
	if facts.depsDevKnown {
		resolved := name + "@" + facts.resolved.Ref.Version
		switch {
		case facts.depsDevFound:
			known = append(known, "deps.dev knows "+resolved)
		case facts.firstRelease != "" && facts.firstReleaseFound:
			known = append(known, fmt.Sprintf("deps.dev has not indexed %s yet but knows the package's first release %s@%s", resolved, name, facts.firstRelease))
		case facts.firstRelease != "":
			known = append(known, fmt.Sprintf("deps.dev has no record of %s or of the package's first release %s@%s", resolved, name, facts.firstRelease))
		default:
			known = append(known, "deps.dev has no record of "+resolved)
		}
	}
	if len(known) > 0 {
		b.WriteString(upperFirst(strings.Join(known, "; ")))
		b.WriteString(". ")
	}
	if len(facts.problems) > 0 {
		fmt.Fprintf(&b, "The dependency could not be fully inspected: %s. ", strings.Join(facts.problems, "; "))
	}
	if len(facts.notes) > 0 {
		b.WriteString(upperFirst(strings.Join(facts.notes, "; ")))
		b.WriteString(". ")
	}
	switch {
	case len(facts.reasons) > 0:
		fmt.Fprintf(&b, "The finding is raised to block because the dependency %s", joinAnd(reasonClauses(facts.reasons)))
	case facts.requirement.optional:
		if len(facts.waived) > 0 {
			fmt.Fprintf(&b, "It %s, which would raise the finding for a runtime dependency, but it ", joinAnd(reasonClauses(facts.waived)))
		} else {
			b.WriteString("It ")
		}
		if facts.requirement.extra != "" {
			fmt.Fprintf(&b, "is declared under the extra %q, which pip installs only when that extra is requested", facts.requirement.extra)
		} else {
			b.WriteString("is an optional dependency that a plain install does not pull in")
		}
		b.WriteString(", so the level stays at the configured one")
	case facts.sameOrigin != "":
		fmt.Fprintf(&b, "It %s, which would raise the finding for an unrelated package, but %s, the pattern of a platform package split out of its parent, so the level stays at the configured one",
			joinAnd(reasonClauses(facts.waived)), sameOriginText(s, ref, facts.sameOrigin))
	default:
		b.WriteString("Nothing raises the finding above the configured level")
		if len(facts.problems) > 0 {
			b.WriteString(", although the failed lookups leave that unconfirmed")
		}
	}
	return b.String()
}

// sameOriginText words the same_origin evidence for the explanation.
func sameOriginText(s *Subject, ref model.PackageRef, origin string) string {
	if origin == originScope {
		return fmt.Sprintf("it is in %s's own npm scope", ref.Name)
	}
	return fmt.Sprintf("it is published by the same account as %s (%s)", ref.Name, s.Version.Publisher.Name)
}

// runtimeDependencies counts the declared dependencies that are not optional.
func runtimeDependencies(declared map[string]requirement) int {
	n := 0
	for _, req := range declared {
		if !req.optional {
			n++
		}
	}
	return n
}

// reasonTexts spells escalation reasons for a title.
func reasonTexts(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		switch r {
		case reasonYoung:
			out = append(out, "young")
		case reasonLowUsage:
			out = append(out, "low usage")
		case reasonUnknown:
			out = append(out, "unknown to deps.dev")
		}
	}
	return out
}

// reasonClauses spells escalation reasons after "the dependency".
func reasonClauses(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		switch r {
		case reasonYoung:
			out = append(out, "is young")
		case reasonLowUsage:
			out = append(out, "has low usage")
		case reasonUnknown:
			out = append(out, "is unknown to deps.dev")
		}
	}
	return out
}

// resolveRequirement picks the version to inspect: the exact version when the
// requirement pins one (1.2.3 or v1.2.3 for npm, =1.2.3 for Cargo, ==1.2.3 for
// PyPI), otherwise the newest stable version, which a range does not always
// install but is what the registry is asked about. pinned says which. nil when
// neither exists.
func resolveRequirement(eco model.Ecosystem, list *registry.VersionList, requirement string) (v *model.VersionInfo, pinned bool) {
	if ver, ok := pinnedVersion(eco, requirement); ok {
		if v := registry.Find(list, ver); v != nil {
			return v, true
		}
	}
	return registry.LatestStable(list), false
}

// pinnedVersion extracts the version a requirement pins, per ecosystem syntax:
// Cargo pins with a leading "=" (a bare 1.2.3 is a caret requirement there),
// PyPI with "==", and npm, JSR and Deno with the bare version. ok is false when
// the requirement is not of that form; whether the version exists is for Find.
func pinnedVersion(eco model.Ecosystem, requirement string) (string, bool) {
	req := strings.TrimSpace(requirement)
	switch eco {
	case model.Cargo:
		after, ok := strings.CutPrefix(req, "=")
		if !ok || strings.HasPrefix(after, "=") {
			return "", false
		}
		return strings.TrimSpace(after), true
	case model.PyPI:
		after, ok := strings.CutPrefix(req, "==")
		if !ok || strings.HasPrefix(after, "=") {
			return "", false
		}
		if i := strings.IndexAny(after, ",;"); i >= 0 {
			after = after[:i]
		}
		return strings.TrimSpace(after), true
	default:
		return strings.TrimPrefix(req, "v"), req != ""
	}
}

// firstPublished is when the package first appeared: the registry's created time,
// or the earliest publish time among its versions. Zero when unknown.
func firstPublished(list *registry.VersionList) time.Time {
	if !list.Created.IsZero() {
		return list.Created
	}
	if first := firstRelease(list); first != nil && !first.PublishedAt.IsZero() {
		return first.PublishedAt
	}
	return time.Time{}
}

// firstRelease is the earliest published version of the list, or the first listed
// one when no version has a publish time. nil for an empty list.
func firstRelease(list *registry.VersionList) *model.VersionInfo {
	var first *model.VersionInfo
	for i := range list.Versions {
		v := &list.Versions[i]
		if v.PublishedAt.IsZero() {
			continue
		}
		if first == nil || v.PublishedAt.Before(first.PublishedAt) {
			first = v
		}
	}
	if first == nil && len(list.Versions) > 0 {
		first = &list.Versions[0]
	}
	return first
}

// registryName names the registry of an ecosystem for prose.
func registryName(eco model.Ecosystem) string {
	switch eco {
	case model.NPM:
		return "the npm registry"
	case model.PyPI:
		return "PyPI"
	case model.Cargo:
		return "crates.io"
	case model.JSR:
		return "JSR"
	case model.Deno:
		return "the Deno registry"
	default:
		return "the registry"
	}
}

// pluralY returns the ending of "dependency" that agrees with n.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// upperFirst capitalizes the first letter of a sentence.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
