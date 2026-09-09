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
//   - npm: preinstall, install, postinstall and prepare from the packument's
//     versions[<v>].scripts, which npm runs on install (re-verified 2026-09-09
//     against https://docs.npmjs.com/cli/v11/using-npm/scripts);
//   - crates.io: build.rs when the crate ships a build script, which cargo
//     compiles and runs before building the crate (re-verified 2026-09-09 against
//     https://doc.rust-lang.org/cargo/reference/build-scripts.html), and
//     proc-macro when Cargo.toml declares [lib] proc-macro = true, whose code runs
//     inside the compiler of every dependent;
//   - PyPI: setup.py for a release published as a source distribution only, which
//     pip must build, running the project's setup.py, because no wheel exists.
//
// Names are reported as recorded; the explanation describes what each one means
// for the ecosystem. The check is skipped when the version details are unavailable.
//
// Evidence keys:
//
//	script_names  the install-time scripts or markers of the version, in
//	              lifecycle order for npm (preinstall, install, postinstall,
//	              prepare), alphabetically otherwise
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
	if !s.Version.HasInstallScript() {
		return Result{}
	}
	ref := evaluatedRef(s)
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

// installScriptText explains, per ecosystem, what the recorded scripts mean.
func installScriptText(ref model.PackageRef, scripts map[string]string) string {
	ver := ref.Version
	switch ref.Ecosystem {
	case model.NPM:
		return fmt.Sprintf("%s declares %s, which npm runs with the installing user's permissions on every install of the package",
			ver, scriptsText(scripts))
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
