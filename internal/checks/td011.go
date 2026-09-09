package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// TD011 deprecated-or-yanked reports a version the registry yanked or deprecated, a
// package deprecated or archived as a whole, or a version deps.dev marks deprecated.
// It applies to every ecosystem and warns by default.
//
// The registry and deps.dev are consulted independently, like TD009: the check is
// skipped only when neither delivered anything; with one of them missing it runs on
// the other and the explanation says so.
//
// Evidence keys:
//
//	signals              which signals fired, in this order: yanked, version-deprecated,
//	                     package-deprecated, deps-dev-deprecated
//	yanked               true when the registry yanked the version
//	version_deprecated   the registry's deprecation message for the version, when set
//	package_deprecated   the registry's deprecation or archival message for the package, when set
//	deps_dev_deprecated  true when deps.dev marks the version deprecated
//	deps_dev_reason      the reason deps.dev gives, when it gives one
//	unavailable          the source that could not be consulted, when one was: registry or deps.dev
//
// Registry fields, verified 2026-09-09: npm carries a per-version "deprecated"
// message (GET https://registry.npmjs.org/request/2.88.2); PyPI a per-release and
// per-file "yanked" flag with "yanked_reason" (GET https://pypi.org/pypi/requests/2.32.0/json);
// crates.io a per-version "yanked" flag and "yank_message" (GET https://crates.io/api/v1/crates/serde/versions).
// The registry clients map those onto model.VersionInfo.Yanked and .Deprecated and
// onto registry.VersionList.Deprecated for the package as a whole.
//
// deps.dev, verified 2026-09-09: GET https://api.deps.dev/v3alpha/systems/npm/packages/request/versions/2.88.2
// returns "isDeprecated": true with "deprecatedReason", and POST /v3alpha/findingsbatch
// returns a DEPRECATED finding with deprecatedContext.reason; the deps.dev client maps
// those onto depsdev.VersionFacts.IsDeprecated and a depsdev.Finding of type
// DEPRECATED whose Detail is the reason.

// deprecatedOrYankedFindingType is the deps.dev finding type this check looks for.
const deprecatedOrYankedFindingType = "DEPRECATED"

type deprecatedOrYanked struct{}

func init() { Register(deprecatedOrYanked{}) }

// ID implements Check.
func (deprecatedOrYanked) ID() string { return "TD011" }

// Name implements Check.
func (deprecatedOrYanked) Name() string { return "deprecated-or-yanked" }

// Ecosystems implements Check; nil means every ecosystem.
func (deprecatedOrYanked) Ecosystems() []model.Ecosystem { return nil }

// Run implements Check.
func (c deprecatedOrYanked) Run(_ context.Context, s *Subject) Result {
	registryReason, registryDown := s.Skipped(SourceRegistry)
	haveRegistry := !registryDown && (s.Version != nil || s.Package != nil)
	depsDevReason, depsDevDown := s.Skipped(SourceDepsDev)
	haveDepsDev := !depsDevDown && (s.DepsDev != nil || len(s.DepsDevFindings) > 0)
	if !haveRegistry && !haveDepsDev {
		if registryReason == "" {
			registryReason = "no registry data for " + s.Ref.String()
		}
		if depsDevReason == "" {
			depsDevReason = "no deps.dev data for " + s.Ref.String()
		}
		return Skip(c.ID(), registryReason+"; "+depsDevReason)
	}

	evidence := map[string]any{}
	var signals, parts []string
	var yanked, deprecated bool
	if haveRegistry && s.Version != nil {
		if s.Version.Yanked {
			yanked = true
			signals = append(signals, "yanked")
			evidence["yanked"] = true
			parts = append(parts, fmt.Sprintf("the registry yanked %s", s.Ref))
		}
		if msg := strings.TrimSpace(s.Version.Deprecated); msg != "" {
			deprecated = true
			signals = append(signals, "version-deprecated")
			evidence["version_deprecated"] = msg
			parts = append(parts, fmt.Sprintf("the registry deprecated version %s: %q", s.Ref.Version, msg))
		}
	}
	// A registry that serves the package record from another host can answer the
	// version list and not the deprecation state. That is not "not deprecated",
	// and a check that read it as such would be answering from an outage.
	archivedUnknown := ""
	if s.Package != nil {
		archivedUnknown = s.Package.Unknown[model.FacetDeprecated]
	}
	packageDeprecated := false
	if haveRegistry && s.Package != nil {
		if msg := strings.TrimSpace(s.Package.Deprecated); msg != "" {
			packageDeprecated = true
			signals = append(signals, "package-deprecated")
			evidence["package_deprecated"] = msg
			parts = append(parts, fmt.Sprintf("the registry deprecated the whole package %s: %q", s.Ref.Name, msg))
		}
	}
	if haveDepsDev {
		if flagged, reason := c.depsDevDeprecated(s); flagged {
			deprecated = true
			signals = append(signals, "deps-dev-deprecated")
			evidence["deps_dev_deprecated"] = true
			text := "deps.dev marks the version deprecated"
			if reason != "" {
				evidence["deps_dev_reason"] = reason
				text += ": " + fmt.Sprintf("%q", reason)
			}
			parts = append(parts, text)
		}
	}
	if len(signals) == 0 {
		if archivedUnknown != "" && !haveDepsDev {
			// Nothing fired, and the one source that could have said the package is
			// deprecated was not reachable. Reporting a pass here is the one thing
			// this tool never does.
			return Skip(c.ID(), archivedUnknown)
		}
		return Result{}
	}
	evidence["signals"] = signals
	switch {
	case !haveRegistry:
		evidence["unavailable"] = SourceRegistry
		if registryReason == "" {
			registryReason = "no registry data for " + s.Ref.String()
		}
		parts = append(parts, "the registry could not be consulted ("+registryReason+")")
	case !haveDepsDev && depsDevDown:
		evidence["unavailable"] = SourceDepsDev
		parts = append(parts, "deps.dev could not be consulted ("+depsDevReason+")")
	case archivedUnknown != "":
		evidence["unavailable"] = SourceRegistry
		parts = append(parts, "whether the package as a whole is deprecated could not be read ("+archivedUnknown+")")
	}

	var title string
	switch {
	case yanked && deprecated:
		title = s.Ref.Version + " is yanked and deprecated"
	case yanked:
		title = s.Ref.Version + " is yanked"
	case deprecated:
		title = s.Ref.Version + " is deprecated"
	case packageDeprecated:
		title = "package " + s.Ref.Name + " is deprecated"
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, strings.Join(parts, "; "), evidence)}}
}

// depsDevDeprecated reports whether deps.dev marks the version deprecated, through
// the version facts or a DEPRECATED finding, and the reason when one was given.
func (deprecatedOrYanked) depsDevDeprecated(s *Subject) (flagged bool, reason string) {
	if s.DepsDev != nil && s.DepsDev.IsDeprecated {
		flagged = true
	}
	for _, f := range s.DepsDevFindings {
		if f.Type != deprecatedOrYankedFindingType {
			continue
		}
		flagged = true
		if reason == "" {
			reason = strings.TrimSpace(f.Detail)
		}
	}
	return flagged, reason
}
