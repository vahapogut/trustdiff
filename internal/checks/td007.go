package checks

import (
	"context"
	"errors"
	"fmt"
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
// dependency, so an allow entry can cover a reviewed one. Each new dependency is
// inspected through the Loader and the finding is raised to block when the
// dependency is young, has low usage or is unknown to deps.dev:
//
//   - young: the version a fresh install would take (the exact version when the
//     requirement pins one, otherwise the latest stable version) was published
//     less than 7 days before the run, or the package's first release was;
//   - low usage: the weekly downloads are below the min_weekly_downloads of the
//     low-usage check (no escalation where the registry has no counts, PyPI);
//   - unknown to deps.dev: deps.dev has no record of the resolved version.
//
// A loader error never escalates; the explanation says what could not be checked.
// The check is skipped without a previous version.
//
// Evidence keys (present in every finding unless marked):
//
//	previous_version      the previous release compared with
//	dependency            the new dependency's name
//	requirement           the version requirement the evaluated version declares
//	new_dependencies      every dependency the evaluated version added, sorted
//	escalated             whether the level was raised to block
//	escalation_reasons    young, low-usage and unknown-to-deps.dev, those that apply
//	resolved_version      the version a fresh install would take (when resolved)
//	published_at          its RFC 3339 publish time (when known)
//	first_published_at    RFC 3339 time of the package's first release (when known)
//	weekly_downloads      the dependency's weekly downloads (when the registry has them)
//	min_weekly_downloads  the low-usage threshold applied (when one is configured)
//	deps_dev_found        whether deps.dev knows the resolved version (when looked up)
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

// Run reports each dependency the previous version did not declare.
func (c td007) Run(ctx context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	if s.Previous == nil {
		return Skip(c.ID(), "no earlier release to compare with")
	}
	ref := evaluatedRef(s)
	eco := ref.Ecosystem
	previous := make(map[string]bool, len(s.Previous.Dependencies))
	for name := range s.Previous.Dependencies {
		previous[model.NormalizeName(eco, name)] = true
	}
	var added []string
	for name := range s.Version.Dependencies {
		if !previous[model.NormalizeName(eco, name)] {
			added = append(added, name)
		}
	}
	if len(added) == 0 {
		return Result{}
	}
	sort.Strings(added)

	threshold := s.Setting("low-usage").MinWeeklyDownloads
	findings := make([]model.Finding, 0, len(added))
	for _, name := range added {
		facts := inspectDependency(ctx, s, eco, name, threshold)
		findings = append(findings, c.finding(s, ref, name, added, facts, threshold))
	}
	return Result{Findings: findings}
}

// dependencyFacts is what the Loader could tell about one new dependency.
type dependencyFacts struct {
	requirement    string
	resolved       *model.VersionInfo
	firstPublished time.Time
	downloads      int64
	downloadsKnown bool
	depsDevFound   bool
	depsDevKnown   bool
	// notes say why a signal does not apply (no counts for the ecosystem);
	// problems are loader errors. Neither escalates.
	notes    []string
	problems []string
}

// reasons lists the escalation reasons that apply.
func (f *dependencyFacts) reasons(now time.Time, threshold int64) []string {
	reasons := []string{}
	if f.isYoung(now) {
		reasons = append(reasons, reasonYoung)
	}
	if f.downloadsKnown && threshold > 0 && f.downloads < threshold {
		reasons = append(reasons, reasonLowUsage)
	}
	if f.depsDevKnown && !f.depsDevFound {
		reasons = append(reasons, reasonUnknown)
	}
	return reasons
}

func (f *dependencyFacts) isYoung(now time.Time) bool {
	if f.resolved != nil && !f.resolved.PublishedAt.IsZero() && now.Sub(f.resolved.PublishedAt) < youngDependencyAge {
		return true
	}
	return !f.firstPublished.IsZero() && now.Sub(f.firstPublished) < youngDependencyAge
}

// inspectDependency gathers the facts about one new dependency through the Loader.
func inspectDependency(ctx context.Context, s *Subject, eco model.Ecosystem, name string, threshold int64) *dependencyFacts {
	facts := &dependencyFacts{requirement: s.Version.Dependencies[name]}
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
		facts.resolved = resolveRequirement(list, facts.requirement)
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
		depRef := model.PackageRef{Ecosystem: eco, Name: name, Version: facts.resolved.Ref.Version}
		dd, err := s.Loader.DepsDev(ctx, depRef)
		switch {
		case errors.Is(err, depsdev.ErrUnsupported):
			facts.notes = append(facts.notes, fmt.Sprintf("deps.dev does not index %s", eco))
		case err != nil:
			facts.problems = append(facts.problems, fmt.Sprintf("deps.dev could not be queried for %s: %v", depRef, err))
		case dd == nil:
			facts.problems = append(facts.problems, fmt.Sprintf("deps.dev returned no facts for %s", depRef))
		default:
			facts.depsDevFound, facts.depsDevKnown = dd.Found, true
		}
	}
	return facts
}

// finding builds the finding for one new dependency and escalates it when a
// reason applies.
func (c td007) finding(s *Subject, ref model.PackageRef, name string, added []string, facts *dependencyFacts, threshold int64) model.Finding {
	now := runClock(s)
	reasons := facts.reasons(now, threshold)
	escalated := len(reasons) > 0

	title := fmt.Sprintf("New dependency %s (%s), not declared by %s", name, facts.requirement, s.Previous.Ref.Version)
	if escalated {
		title += ": " + joinAnd(reasonTexts(reasons))
	}
	explanation := dependencyText(s, ref, name, added, facts, now, threshold, reasons)

	evidence := map[string]any{
		"previous_version":   s.Previous.Ref.Version,
		"dependency":         name,
		"requirement":        facts.requirement,
		"new_dependencies":   added,
		"escalated":          escalated,
		"escalation_reasons": reasons,
	}
	if facts.resolved != nil {
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
	if len(facts.problems) > 0 {
		evidence["inspection_errors"] = facts.problems
	}

	f := NewFinding(c, s, title, explanation, evidence)
	if escalated && f.Level != model.LevelOff && !f.Level.AtLeast(model.LevelBlock) {
		f.Level = model.LevelBlock
	}
	return f
}

// dependencyText writes the explanation: what changed, what is known about the
// dependency, and why the level was or was not raised.
func dependencyText(s *Subject, ref model.PackageRef, name string, added []string, facts *dependencyFacts, now time.Time, threshold int64, reasons []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s declared %d runtime dependenc%s; %s adds %s (%s)",
		s.Previous.Ref.Version, len(s.Previous.Dependencies), pluralY(len(s.Previous.Dependencies)), ref.Version, name, facts.requirement)
	if len(added) > 1 {
		fmt.Fprintf(&b, ", one of %d new dependencies (%s)", len(added), strings.Join(added, ", "))
	}
	b.WriteString(". ")

	var known []string
	if facts.resolved != nil {
		v := facts.resolved
		if v.PublishedAt.IsZero() {
			known = append(known, fmt.Sprintf("a fresh install would take %s@%s, whose publish time is unknown", name, v.Ref.Version))
		} else {
			known = append(known, fmt.Sprintf("a fresh install would take %s@%s, published on %s (%s)", name, v.Ref.Version, whenText(v.PublishedAt), sinceText(now, v.PublishedAt)))
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
		if facts.depsDevFound {
			known = append(known, fmt.Sprintf("deps.dev knows %s@%s", name, facts.resolved.Ref.Version))
		} else {
			known = append(known, fmt.Sprintf("deps.dev has no record of %s@%s", name, facts.resolved.Ref.Version))
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
	if len(reasons) > 0 {
		fmt.Fprintf(&b, "The finding is raised to block because the dependency %s", joinAnd(reasonClauses(reasons)))
	} else {
		b.WriteString("Nothing raises the finding above the configured level")
		if len(facts.problems) > 0 {
			b.WriteString(", although the failed lookups leave that unconfirmed")
		}
	}
	return b.String()
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

// resolveRequirement picks the version a fresh install would take: the exact
// version when the requirement pins one (1.2.3, =1.2.3 for Cargo, ==1.2.3 for
// PyPI), otherwise the latest stable version. nil when neither exists.
func resolveRequirement(list *registry.VersionList, requirement string) *model.VersionInfo {
	req := strings.TrimSpace(requirement)
	for _, candidate := range []string{req, strings.TrimPrefix(req, "=="), strings.TrimPrefix(req, "="), strings.TrimPrefix(req, "v")} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if v := registry.Find(list, candidate); v != nil {
			return v
		}
	}
	return registry.LatestStable(list)
}

// firstPublished is when the package first appeared: the registry's created time,
// or the earliest publish time among its versions. Zero when unknown.
func firstPublished(list *registry.VersionList) time.Time {
	if !list.Created.IsZero() {
		return list.Created
	}
	var first time.Time
	for i := range list.Versions {
		t := list.Versions[i].PublishedAt
		if t.IsZero() {
			continue
		}
		if first.IsZero() || t.Before(first) {
			first = t
		}
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
