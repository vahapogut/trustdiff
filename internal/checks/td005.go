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
// packument's versions[<v>].scripts: preinstall, install and postinstall, which
// npm runs on every install, and prepare, which runs on a local install of the
// package's own checkout and on git dependencies (lifecycle order re-verified on
// 2026-09-09 against https://docs.npmjs.com/cli/v11/using-npm/scripts). A
// package that ships a binding.gyp without an install or preinstall script gets
// npm's default install command, node-gyp rebuild; when the client records that
// implicit command under install the finding says so. The check is skipped
// without a previous version, when the previous version's details could not be
// fetched, and when the registry could not gather the scripts of either version.
// npm only: crates.io and PyPI have no per-version script list to compare, and
// TD006 covers their install-time code.
//
// Evidence keys:
//
//	previous_version  the previous release, which declared no install-time script
//	script_names      the install-time scripts of the evaluated version, in
//	                  lifecycle order (preinstall, install, postinstall, prepare)
//	scripts           the scripts by name, with the command each one runs
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
	if s.Previous.HasInstallScript() {
		return Result{}
	}
	names := scriptNames(s.Version.Scripts)
	title := fmt.Sprintf("Install script introduced: %s (%s had none)", strings.Join(names, ", "), s.Previous.Ref.Version)
	explanation := fmt.Sprintf("%s declared no install-time script; %s declares %s, which npm runs with the installing user's permissions on every install of the package",
		s.Previous.Ref.Version, ref.Version, scriptsText(s.Version.Scripts))
	if implicitInstall(s.Version.Scripts) {
		explanation += "; the install command is not declared in package.json but is npm's default for a package that ships a binding.gyp"
	}
	evidence := map[string]any{
		"previous_version": s.Previous.Ref.Version,
		"script_names":     names,
		"scripts":          copyScripts(s.Version.Scripts),
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// lifecycleOrder is the order in which npm runs the install-time scripts; other
// keys (build.rs, proc-macro, setup.py) follow alphabetically.
var lifecycleOrder = map[string]int{"preinstall": 1, "install": 2, "postinstall": 3, "prepare": 4}

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
