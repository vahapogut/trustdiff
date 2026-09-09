package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestTD005InstallScriptIntroduced(t *testing.T) {
	tests := []struct {
		name     string
		current  map[string]string
		previous map[string]string
		noPrev   bool
		want     outcomeA
		names    []string
		title    string
		text     []string
	}{
		{
			name:    "fires when the previous version had no install script",
			current: map[string]string{"postinstall": "node scripts/setup.js"},
			want:    outcomeA{findings: 1},
			names:   []string{"postinstall"},
			title:   "Install script introduced: postinstall (1.2.0 had none)",
			text:    []string{"1.2.0 declared no install-time script", "1.3.0 declares postinstall (node scripts/setup.js)", "on every install"},
		},
		{
			name:    "lists several scripts in lifecycle order",
			current: map[string]string{"prepare": "husky", "preinstall": "node check.js", "postinstall": "node build.js"},
			want:    outcomeA{findings: 1},
			names:   []string{"preinstall", "postinstall", "prepare"},
			title:   "Install script introduced: preinstall, postinstall, prepare (1.2.0 had none)",
			text:    []string{"declares preinstall (node check.js), postinstall (node build.js) and prepare (husky)"},
		},
		{
			name:    "names a script without a recorded command",
			current: map[string]string{"install": ""},
			want:    outcomeA{findings: 1},
			names:   []string{"install"},
			title:   "Install script introduced: install (1.2.0 had none)",
			text:    []string{"1.3.0 declares install,"},
		},
		{
			name:     "does not fire when the previous version already had one",
			current:  map[string]string{"postinstall": "node scripts/setup.js"},
			previous: map[string]string{"install": "node-gyp rebuild"},
			want:     outcomeA{},
		},
		{
			name: "does not fire without an install script",
			want: outcomeA{},
		},
		{
			name:     "does not fire when the script was removed",
			previous: map[string]string{"postinstall": "node scripts/setup.js"},
			want:     outcomeA{},
		},
		{
			name:    "skipped without a previous version",
			current: map[string]string{"postinstall": "node scripts/setup.js"},
			noPrev:  true,
			want:    outcomeA{skip: "no earlier release"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			s.Version.Scripts = tt.current
			if !tt.noPrev {
				withPreviousA(s, "1.2.0").Scripts = tt.previous
			}
			res := runA(t, "TD005", s, tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			if f.Level != model.LevelBlock {
				t.Errorf("level = %s, want block", f.Level)
			}
			if got := stringsA(t, f.Evidence, "script_names"); !equalA(got, tt.names) {
				t.Errorf("script_names = %v, want %v", got, tt.names)
			}
			scripts, ok := f.Evidence["scripts"].(map[string]string)
			if !ok || len(scripts) != len(tt.current) {
				t.Errorf("scripts = %v, want %v", f.Evidence["scripts"], tt.current)
			}
			if got := f.Evidence["previous_version"]; got != "1.2.0" {
				t.Errorf("previous_version = %v, want 1.2.0", got)
			}
			if f.Title != tt.title {
				t.Errorf("title = %q, want %q", f.Title, tt.title)
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

// When diff knows the version the project actually had, the check compares
// against it as well: a script the release before this one already carried is
// still new to a project upgrading from further back.
func TestTD005ComparesWithTheBaseVersionToo(t *testing.T) {
	script := map[string]string{"postinstall": "node scripts/setup.js"}
	tests := []struct {
		name          string
		previous      map[string]string
		base          map[string]string
		wantFinding   bool
		wantSinceBase bool
		text          []string
	}{
		{
			name:          "the previous release already had it but the locked version did not",
			previous:      script,
			base:          nil,
			wantFinding:   true,
			wantSinceBase: true,
			text:          []string{"1.2.0, already declared it", "1.0.0, did not", "new to this project"},
		},
		{
			name:          "neither had it",
			previous:      nil,
			base:          nil,
			wantFinding:   true,
			wantSinceBase: true,
			text:          []string{"the version this change replaces, 1.0.0, declared none either"},
		},
		{
			name:          "the locked version had it and the previous release did not",
			previous:      nil,
			base:          script,
			wantFinding:   true,
			wantSinceBase: false,
			text:          []string{"the version this change replaces, 1.0.0, already declared one"},
		},
		{
			name:        "both had it, nothing was introduced",
			previous:    script,
			base:        script,
			wantFinding: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectA(model.NPM, "lib", "1.3.0")
			s.Version.Scripts = script
			withPreviousA(s, "1.2.0").Scripts = tt.previous
			basev := versionA(model.NPM, "lib", "1.0.0", agoA(90*dayA))
			basev.Scripts = tt.base
			s.PreviousInBase = &basev

			want := outcomeA{}
			if tt.wantFinding {
				want.findings = 1
			}
			res := runA(t, "TD005", s, want)
			if !tt.wantFinding {
				return
			}
			f := res.Findings[0]
			if got := f.Evidence["base_version"]; got != "1.0.0" {
				t.Errorf("base_version = %v, want 1.0.0", got)
			}
			if got := f.Evidence["introduced_since_base"]; got != tt.wantSinceBase {
				t.Errorf("introduced_since_base = %v, want %v", got, tt.wantSinceBase)
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

func TestTD005EvidenceDoesNotAliasTheVersion(t *testing.T) {
	s := subjectA(model.NPM, "lib", "1.3.0")
	s.Version.Scripts = map[string]string{"postinstall": "node scripts/setup.js"}
	withPreviousA(s, "1.2.0")
	f := runA(t, "TD005", s, outcomeA{findings: 1}).Findings[0]
	s.Version.Scripts["postinstall"] = "changed"
	if got := f.Evidence["scripts"].(map[string]string)["postinstall"]; got != "node scripts/setup.js" {
		t.Errorf("evidence changed with the version data: %q", got)
	}
}

func TestTD005SkippedWhenVersionMissing(t *testing.T) {
	s := subjectA(model.NPM, "lib", "1.3.0")
	s.Version = nil
	withPreviousA(s, "1.2.0")
	runA(t, "TD005", s, outcomeA{skip: "version details unavailable"})
}

func TestTD005AppliesToNPMOnly(t *testing.T) {
	c, _ := Lookup("TD005")
	for _, eco := range model.Ecosystems() {
		if AppliesTo(c, eco) != (eco == model.NPM) {
			t.Errorf("AppliesTo(%s) = %v", eco, AppliesTo(c, eco))
		}
	}
}
