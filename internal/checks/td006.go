package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// TD006 install-script-present reports a version that runs code at install time
// at all (brief section 4). Applies to every ecosystem; the registry clients record
// the evidence in VersionInfo.Scripts under ecosystem-specific keys:
//
//   - npm: preinstall, install and postinstall from the packument's
//     versions[<v>].scripts, the three npm runs when it installs the package as a
//     dependency from the registry (prepare is left out because npm runs a
//     dependency's prepare only for git and local dependencies;
//     internal/registry/npm.installScriptNames carries the sources), and install
//     with npm's default command when the version ships a binding.gyp without
//     declaring an install or preinstall script (the packument marks such
//     versions with gypfile: true and npm runs node-gyp rebuild for them);
//   - crates.io: build.rs when the crate ships a build script, which cargo
//     compiles and runs before building the crate (re-verified 2026-09-09 against
//     https://doc.rust-lang.org/cargo/reference/build-scripts.html), and
//     proc-macro when Cargo.toml declares [lib] proc-macro = true, whose code runs
//     inside the compiler of every dependent;
//   - PyPI: setup.py for a release published as a source distribution only, which
//     pip must build, running the project's setup.py, because no wheel exists.
//
// Names are reported as recorded; the explanation describes what each one means
// for the ecosystem. The check is skipped when the version details are
// unavailable and when the registry could not gather the scripts (for example a
// crate archive that could not be inspected): VersionInfo.Unknown["scripts"]
// carries the reason, and an uninspected version is never reported as clean.
//
// Evidence keys:
//
//	script_names  the install-time scripts or markers of the version, in
//	              lifecycle order for npm (preinstall, install, postinstall),
//	              alphabetically otherwise
//	scripts       the same by name, with the command each one runs when the
//	              registry records one (empty for build.rs, proc-macro, setup.py)
type td006 struct{}

func init() { Register(td006{}) }

func (td006) ID() string                    { return "TD006" }
func (td006) Name() string                  { return "install-script-present" }
func (td006) Ecosystems() []model.Ecosystem { return nil }

// Run reports every install-time script of the evaluated version.
func (c td006) Run(_ context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	ref := evaluatedRef(s)
	if reason, unknown := unknownFacet(s.Version, model.FacetScripts); unknown {
		return Skip(c.ID(), fmt.Sprintf("install scripts of %s unavailable: %s", ref.Version, reason))
	}
	if !s.Version.HasInstallScript() {
		return Result{}
	}
	names := scriptNames(s.Version.Scripts)
	title := "Runs code at install time: " + strings.Join(names, ", ")
	explanation := installScriptText(ref, s.Version.Scripts)
	evidence := map[string]any{
		"script_names": names,
		"scripts":      copyScripts(s.Version.Scripts),
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// Keys the crates.io and PyPI clients use in VersionInfo.Scripts.
const (
	scriptBuildRS   = "build.rs"
	scriptProcMacro = "proc-macro"
	scriptSetupPy   = "setup.py"
)

// ImplicitInstallCommand is the command the npm client records under the install
// script of a version that ships a binding.gyp without declaring an install or
// preinstall script: npm runs node-gyp rebuild for it by default, without any
// scripts entry. TD005 and TD006 word such a finding as implicit.
const ImplicitInstallCommand = "node-gyp rebuild (npm default for binding.gyp)"

// implicitInstall reports whether the install script is npm's implicit default.
func implicitInstall(scripts map[string]string) bool {
	return strings.TrimSpace(scripts["install"]) == ImplicitInstallCommand
}

// unknownFacetReason stands in when a registry client recorded a facet it could
// not gather without saying why. Subject.outageReasons words it the same way, so
// the runner can match the skip it produces.
const unknownFacetReason = "not gathered by the registry client"

// unknownFacet reports why a registry could not gather one facet of a version
// (VersionInfo.Unknown keyed by model.FacetScripts, model.FacetProvenance or
// model.FacetDependencies): the crate archive was too large or not cached
// offline, the PyPI integrity API failed. A check that needs the facet skips with
// the reason instead of reading the zero value as a fact.
func unknownFacet(v *model.VersionInfo, facet string) (reason string, unknown bool) {
	if v == nil {
		return "", false
	}
	reason, unknown = v.Unknown[facet]
	if unknown && reason == "" {
		reason = unknownFacetReason
	}
	return reason, unknown
}

// installScriptText explains, per ecosystem, what the recorded scripts mean.
func installScriptText(ref model.PackageRef, scripts map[string]string) string {
	ver := ref.Version
	switch ref.Ecosystem {
	case model.NPM:
		text := fmt.Sprintf("%s declares %s, which npm runs with the installing user's permissions on every install of the package",
			ver, scriptsText(scripts))
		if implicitInstall(scripts) {
			text += "; the install command is not declared in package.json but is npm's default for a package that ships a binding.gyp"
		}
		return text
	case model.Cargo:
		var parts []string
		var other map[string]string
		for _, name := range scriptNames(scripts) {
			switch name {
			case scriptBuildRS:
				parts = append(parts, "ships a build script (build.rs), which cargo compiles and runs before building the crate")
			case scriptProcMacro:
				parts = append(parts, "is a procedural macro crate, whose code runs inside the compiler of every dependent")
			default:
				if other == nil {
					other = map[string]string{}
				}
				other[name] = scripts[name]
			}
		}
		if len(other) > 0 {
			parts = append(parts, "declares "+scriptsText(other))
		}
		return ver + " " + joinAnd(parts)
	case model.PyPI:
		if _, ok := scripts[scriptSetupPy]; ok && len(scripts) == 1 {
			return fmt.Sprintf("%s is published as a source distribution only, with no wheel; pip has to build it on install, which runs the project's setup.py", ver)
		}
		return fmt.Sprintf("%s runs code at install time: %s", ver, scriptsText(scripts))
	default:
		return fmt.Sprintf("%s runs code at install time: %s", ver, scriptsText(scripts))
	}
}
