package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// TD005 install-script-introduced reports an npm version that declares an
// install-time script while the previous version declared none (brief section 4).
// The scripts are the ones the npm client records in VersionInfo.Scripts from the
// packument's versions[<v>].scripts: preinstall, install and postinstall, the three
// npm runs on every install of a dependency it fetched from the registry. prepare
// is not among them, because npm runs a dependency's prepare only for a git or a
// local dependency, so a release that adds one has added nothing an install will
// run; internal/registry/npm.installScriptNames carries the sources for that. A
// package that ships a binding.gyp without an install or preinstall script gets
// npm's default install command, node-gyp rebuild; when the client records that
// implicit command under install the finding says so. The check is skipped
// without a previous version, when the previous version's details could not be
// fetched, and when the registry could not gather the scripts of either version.
// npm only: crates.io and PyPI have no per-version script list to compare, and
// TD006 covers their install-time code.
//
// Two comparisons, when diff knows both: the release before the evaluated version,
// and the version the base lockfile locked, which is the version the project
// actually had. A bump usually crosses more than one release, and a script the
// release before this one already carried is still new to a project upgrading from
// further back. The finding names the version that declared none, the previous
// release when neither did, and the base version is ignored when the registry
// client could not gather its scripts.
//
// A base version nobody could reach is not ignored quietly: where it would have
// decided the answer the check reports itself as skipped naming it. A base version
// the registry no longer has, which is what an unpublished release looks like, is
// an answer, and the check goes on with the release before this one alone.
//
// Evidence keys:
//
//	previous_version  the previous release
//	script_names      the install-time scripts of the evaluated version, in
//	                  lifecycle order (preinstall, install, postinstall)
//	scripts           the scripts by name, with the command each one runs
//	base_version      the version the base lockfile locked, when diff knows one
//	                  and it is not the previous release (diff only)
//	introduced_since_base  whether that version declared no install-time script (diff only)
type td005 struct{}

func init() { Register(td005{}) }

func (td005) ID() string                    { return "TD005" }
func (td005) Name() string                  { return "install-script-introduced" }
func (td005) Ecosystems() []model.Ecosystem { return []model.Ecosystem{model.NPM} }

// Run reports install-time scripts that the previous version did not have.
func (c td005) Run(_ context.Context, s *Subject) Result {
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
	if reason, unknown := unknownFacet(s.Version, model.FacetScripts); unknown {
		return Skip(c.ID(), fmt.Sprintf("install scripts of %s unavailable: %s", ref.Version, reason))
	}
	if !s.Version.HasInstallScript() {
		return Result{}
	}
	if reason, unknown := unknownFacet(s.Previous, model.FacetScripts); unknown {
		return Skip(c.ID(), fmt.Sprintf("install scripts of the previous version %s unavailable: %s", s.Previous.Ref.Version, reason))
	}
	// Two comparisons, when diff knows both: the release before this one, and the
	// version the project actually had. A script the previous release already
	// carried is still new to a project upgrading from further back.
	base := comparableBase(s, model.FacetScripts)
	fromPrevious := !s.Previous.HasInstallScript()
	fromBase := base != nil && !base.HasInstallScript()
	if !fromPrevious && !fromBase {
		// Nothing new as far as the versions that were read go. If the base version
		// was not one of them the question is only half answered: a script the
		// release before this one already carried may still be new to this project.
		return cleanOrSkip(c, s, SourceBase)
	}

	// The version to name is the one that had no script; when both did, the
	// previous release is the closer comparison.
	had := s.Previous
	if !fromPrevious {
		had = base
	}
	names := scriptNames(s.Version.Scripts)
	title := fmt.Sprintf("Install script introduced: %s (%s had none)", strings.Join(names, ", "), had.Ref.Version)
	explanation := fmt.Sprintf("%s declared no install-time script; %s declares %s, which npm runs with the installing user's permissions on every install of the package",
		had.Ref.Version, ref.Version, scriptsText(s.Version.Scripts))
	if base != nil {
		switch {
		case fromPrevious && fromBase:
			explanation += fmt.Sprintf("; the version this change replaces, %s, declared none either", base.Ref.Version)
		case fromBase:
			explanation += fmt.Sprintf("; the release before this one, %s, already declared it, but the version this change replaces, %s, did not, so the script is new to this project",
				s.Previous.Ref.Version, base.Ref.Version)
		default:
			explanation += fmt.Sprintf("; the version this change replaces, %s, already declared one", base.Ref.Version)
		}
	}
	if implicitInstall(s.Version.Scripts) {
		explanation += "; the install command is not declared in package.json but is npm's default for a package that ships a binding.gyp"
	}
	evidence := map[string]any{
		"previous_version": s.Previous.Ref.Version,
		"script_names":     names,
		"scripts":          copyScripts(s.Version.Scripts),
	}
	if base != nil {
		evidence["base_version"] = base.Ref.Version
		evidence["introduced_since_base"] = fromBase
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// comparableBase is the version the base lockfile had, when there is one a check
// can compare against: a release of its own rather than the one the registry calls
// previous, and one whose facet the registry client actually gathered. It is nil
// for scan, for a ref named on the command line, for an added entry and for a bump
// of one release, which leaves the check with the single comparison it made before
// diff learned to name the version the project actually had.
//
// TD004, TD005 and TD007 read it, and it is the one place that decides what the
// second comparison is. The version guard repeats internal/checks/runner.go's own
// rule for loadBase, because a Subject built by hand in a test can set the field
// directly.
func comparableBase(s *Subject, facet string) *model.VersionInfo {
	base := s.PreviousInBase
	if base == nil || (s.Previous != nil && base.Ref.Version == s.Previous.Ref.Version) {
		return nil
	}
	if _, unknown := unknownFacet(base, facet); unknown {
		return nil
	}
	return base
}

// lifecycleOrder is the order in which npm runs the install-time scripts; other
// keys (build.rs, proc-macro, setup.py) follow alphabetically.
var lifecycleOrder = map[string]int{"preinstall": 1, "install": 2, "postinstall": 3}

// scriptNames returns the script names in lifecycle order, then alphabetically.
func scriptNames(scripts map[string]string) []string {
	names := make([]string, 0, len(scripts))
	for name := range scripts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		ri, ok := lifecycleOrder[names[i]]
		if !ok {
			ri = len(lifecycleOrder) + 1
		}
		rj, ok := lifecycleOrder[names[j]]
		if !ok {
			rj = len(lifecycleOrder) + 1
		}
		if ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	return names
}

// scriptsText renders scripts for prose: "postinstall (node scripts/setup.js) and
// preinstall (node check.js)"; a script without a recorded command is named only.
func scriptsText(scripts map[string]string) string {
	names := scriptNames(scripts)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if cmd := strings.TrimSpace(scripts[name]); cmd != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", name, cmd))
		} else {
			parts = append(parts, name)
		}
	}
	return joinAnd(parts)
}

// copyScripts returns the scripts as a fresh map, so the finding does not alias
// the version's data.
func copyScripts(scripts map[string]string) map[string]string {
	out := make(map[string]string, len(scripts))
	for name, cmd := range scripts {
		out[name] = cmd
	}
	return out
}
