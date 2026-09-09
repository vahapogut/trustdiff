package checks

import (
	"errors"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestTD006InstallScriptPresent(t *testing.T) {
	tests := []struct {
		name    string
		eco     model.Ecosystem
		scripts map[string]string
		want    outcomeA
		names   []string
		title   string
		text    []string
	}{
		{
			name:    "npm postinstall",
			eco:     model.NPM,
			scripts: map[string]string{"postinstall": "node scripts/setup.js"},
			want:    outcomeA{findings: 1},
			names:   []string{"postinstall"},
			title:   "Runs code at install time: postinstall",
			text:    []string{"1.3.0 declares postinstall (node scripts/setup.js)", "npm runs"},
		},
		{
			name:    "npm several scripts in lifecycle order",
			eco:     model.NPM,
			scripts: map[string]string{"prepare": "husky", "preinstall": "node check.js"},
			want:    outcomeA{findings: 1},
			names:   []string{"preinstall", "prepare"},
			title:   "Runs code at install time: preinstall, prepare",
			text:    []string{"declares preinstall (node check.js) and prepare (husky)"},
		},
		{
			name:    "cargo build script",
			eco:     model.Cargo,
			scripts: map[string]string{"build.rs": ""},
			want:    outcomeA{findings: 1},
			names:   []string{"build.rs"},
			title:   "Runs code at install time: build.rs",
			text:    []string{"1.3.0 ships a build script (build.rs), which cargo compiles and runs before building the crate"},
		},
		{
			name:    "cargo procedural macro",
			eco:     model.Cargo,
			scripts: map[string]string{"proc-macro": ""},
			want:    outcomeA{findings: 1},
			names:   []string{"proc-macro"},
			title:   "Runs code at install time: proc-macro",
			text:    []string{"1.3.0 is a procedural macro crate, whose code runs inside the compiler"},
		},
		{
			name:    "cargo build script and procedural macro",
			eco:     model.Cargo,
			scripts: map[string]string{"proc-macro": "", "build.rs": ""},
			want:    outcomeA{findings: 1},
			names:   []string{"build.rs", "proc-macro"},
			title:   "Runs code at install time: build.rs, proc-macro",
			text:    []string{"ships a build script (build.rs)", " and is a procedural macro crate"},
		},
		{
			name:    "pypi sdist only",
			eco:     model.PyPI,
			scripts: map[string]string{"setup.py": ""},
			want:    outcomeA{findings: 1},
			names:   []string{"setup.py"},
			title:   "Runs code at install time: setup.py",
			text:    []string{"1.3.0 is published as a source distribution only, with no wheel", "runs the project's setup.py"},
		},
		{
			name:    "unknown ecosystem keys are still reported",
			eco:     model.JSR,
			scripts: map[string]string{"postinstall": "deno run setup.ts"},
			want:    outcomeA{findings: 1},
			names:   []string{"postinstall"},
			title:   "Runs code at install time: postinstall",
			text:    []string{"1.3.0 runs code at install time: postinstall (deno run setup.ts)"},
		},
		{
			name: "does not fire without scripts",
			eco:  model.NPM,
			want: outcomeA{},
		},
		{
			name:    "does not fire for an empty script map",
			eco:     model.Cargo,
			scripts: map[string]string{},
			want:    outcomeA{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectA(tt.eco, "lib", "1.3.0")
			s.Version.Scripts = tt.scripts
			res := runA(t, "TD006", s, tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			if f.Level != model.LevelWarn {
				t.Errorf("level = %s, want warn", f.Level)
			}
			if got := stringsA(t, f.Evidence, "script_names"); !equalA(got, tt.names) {
				t.Errorf("script_names = %v, want %v", got, tt.names)
			}
			if scripts, ok := f.Evidence["scripts"].(map[string]string); !ok || len(scripts) != len(tt.scripts) {
				t.Errorf("scripts = %v, want %v", f.Evidence["scripts"], tt.scripts)
			}
			if f.Title != tt.title {
				t.Errorf("title = %q, want %q", f.Title, tt.title)
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

func TestTD006SkippedWhenRegistryUnavailable(t *testing.T) {
	s := subjectA(model.Cargo, "serde", "1.0.200")
	s.Version = nil
	unavailableA(s, SourceRegistry, errors.New("GET https://crates.io/api/v1/crates/serde: unexpected status 503 Service Unavailable"))
	runA(t, "TD006", s, outcomeA{skip: "registry unavailable: GET https://crates.io/api/v1/crates/serde"})
}

func TestTD006DoesNotNeedAPreviousVersion(t *testing.T) {
	s := subjectA(model.NPM, "lib", "1.0.0")
	s.Version.Scripts = map[string]string{"install": "node-gyp rebuild"}
	runA(t, "TD006", s, outcomeA{findings: 1})
}
