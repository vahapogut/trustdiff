package policy

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// doctorYAML is the section as the documentation shows it.
const doctorYAML = `version: 1
doctor:
  ci_min_severity: block
  rules:
    actions-sha-pin: off
    npm-strict-npmrc: info
    pnpm-minimum-release-age: block
  pin_exceptions:
    - "myorg/*"
    - "otherorg/actions"
`

// knownRules stands in for doctor.Rules(): this package cannot import internal/doctor,
// which imports it, so the names come from the caller. These are real rule names.
var knownRules = []string{
	"actions-sha-pin",
	"bun-minimum-release-age",
	"deno-frozen-lockfile",
	"npm-min-release-age",
	"npm-strict-allow-scripts",
	"npm-strict-npmrc",
	"pnpm-minimum-release-age",
	"yarn-hardened-mode",
}

func TestParseDoctorSection(t *testing.T) {
	p := mustParse(t, doctorYAML)
	if p.Doctor == nil {
		t.Fatal("doctor section was not decoded")
	}
	if p.Doctor.CIMinSeverity == nil || *p.Doctor.CIMinSeverity != model.LevelBlock {
		t.Errorf("ci_min_severity = %v, want block", p.Doctor.CIMinSeverity)
	}
	wantLines := map[string]int{"actions-sha-pin": 5, "npm-strict-npmrc": 6, "pnpm-minimum-release-age": 7}
	for name, line := range wantLines {
		if got := p.Doctor.Rules[name].Line; got != line {
			t.Errorf("rules[%q].Line = %d, want %d", name, got, line)
		}
	}

	s := p.EffectiveDoctor()
	if s.CIMinSeverity != model.LevelBlock {
		t.Errorf("EffectiveDoctor().CIMinSeverity = %s, want block", s.CIMinSeverity)
	}
	wantLevels := map[string]model.Level{
		"actions-sha-pin":          model.LevelOff,
		"npm-strict-npmrc":         model.LevelInfo,
		"pnpm-minimum-release-age": model.LevelBlock,
	}
	if !reflect.DeepEqual(s.Levels, wantLevels) {
		t.Errorf("EffectiveDoctor().Levels = %v, want %v", s.Levels, wantLevels)
	}
	if got, ok := s.Level("actions-sha-pin"); !ok || got != model.LevelOff {
		t.Errorf("Level(actions-sha-pin) = %s, %v; want off, true", got, ok)
	}
	if _, ok := s.Level("npm-min-release-age"); ok {
		t.Error("Level reported a level for a rule the policy never named")
	}
	if want := []string{"myorg/*", "otherorg/actions"}; !slices.Equal(s.PinExceptions, want) {
		t.Errorf("PinExceptions = %v, want %v", s.PinExceptions, want)
	}
	// The settings are a copy: a run that sorts or appends must not reach the policy.
	s.Levels["actions-sha-pin"] = model.LevelBlock
	s.PinExceptions[0] = "elsewhere/*"
	if again := p.EffectiveDoctor(); again.Levels["actions-sha-pin"] != model.LevelOff || again.PinExceptions[0] != "myorg/*" {
		t.Error("EffectiveDoctor shares its map or its list with the policy")
	}
	if err := p.ValidateDoctorRules(knownRules); err != nil {
		t.Errorf("ValidateDoctorRules(real names) = %v, want nil", err)
	}
}

// A policy without the section behaves exactly as it did before the section existed.
func TestDoctorDefaultsWithoutTheSection(t *testing.T) {
	if DefaultDoctorCIMinSeverity != model.LevelWarn {
		t.Fatalf("DefaultDoctorCIMinSeverity = %s, want warn", DefaultDoctorCIMinSeverity)
	}
	var none *Policy
	for _, doc := range []string{"version: 1\n", "version: 1\ndoctor:\n", "version: 1\ndoctor:\n  rules:\n  pin_exceptions:\n  ci_min_severity:\n"} {
		p := mustParse(t, doc)
		if doc == "version: 1\ndoctor:\n" && p.Doctor != nil {
			t.Errorf("%q left a doctor section behind: %+v", doc, p.Doctor)
		}
		for _, s := range []DoctorSettings{p.EffectiveDoctor(), none.EffectiveDoctor()} {
			if s.CIMinSeverity != DefaultDoctorCIMinSeverity {
				t.Errorf("%q: CIMinSeverity = %s, want the built-in default", doc, s.CIMinSeverity)
			}
			if len(s.Levels) != 0 {
				t.Errorf("%q: Levels = %v, want empty", doc, s.Levels)
			}
			if len(s.PinExceptions) != 0 {
				t.Errorf("%q: PinExceptions = %v, want empty", doc, s.PinExceptions)
			}
		}
		if err := p.ValidateDoctorRules(knownRules); err != nil {
			t.Errorf("%q: ValidateDoctorRules = %v, want nil", doc, err)
		}
		// Nothing else about the policy changed.
		for _, eco := range model.Ecosystems() {
			if got, want := p.Effective(eco), none.Effective(eco); !reflect.DeepEqual(got, want) {
				t.Errorf("%q: Effective(%s) = %+v, want the built-in defaults", doc, eco, got)
			}
		}
	}
}

func TestParseRejectsDoctorSection(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name:    "unknown key",
			doc:     "version: 1\ndoctor:\n  ci_min_sevrity: warn\n",
			wantErr: `line 3: unknown key "ci_min_sevrity" in the doctor section`,
		},
		{
			name:    "unknown key next to a good one",
			doc:     "version: 1\ndoctor:\n  ci_min_severity: warn\n  rulez:\n    actions-sha-pin: off\n",
			wantErr: `line 4: unknown key "rulez"`,
		},
		{
			name:    "repeated key",
			doc:     "version: 1\ndoctor:\n  ci_min_severity: warn\n  ci_min_severity: block\n",
			wantErr: `line 4: doctor: key "ci_min_severity" already defined`,
		},
		{
			name:    "bad level",
			doc:     "version: 1\ndoctor:\n  rules:\n    actions-sha-pin: loud\n",
			wantErr: "line 4: rules.actions-sha-pin: unknown level",
		},
		{
			name:    "level in the wrong case",
			doc:     "version: 1\ndoctor:\n  rules:\n    actions-sha-pin: Off\n",
			wantErr: `line 4: rules.actions-sha-pin: level "Off" must be written in lowercase as off`,
		},
		{
			name:    "bad ci_min_severity",
			doc:     "version: 1\ndoctor:\n  ci_min_severity: panic\n",
			wantErr: "line 3: ci_min_severity: unknown level",
		},
		{
			name:    "ci_min_severity off",
			doc:     "version: 1\ndoctor:\n  ci_min_severity: off\n",
			wantErr: "line 3: ci_min_severity must be block, warn or info, got off",
		},
		{
			name:    "ci_min_severity is a list",
			doc:     "version: 1\ndoctor:\n  ci_min_severity: [warn]\n",
			wantErr: "line 3: ci_min_severity: want block, warn or info, got a list",
		},
		{
			name:    "rule name of the wrong shape",
			doc:     "version: 1\ndoctor:\n  rules:\n    Actions SHA Pin: off\n",
			wantErr: `line 4: rules: "Actions SHA Pin" is not a rule name`,
		},
		{
			name:    "rules is a list",
			doc:     "version: 1\ndoctor:\n  rules:\n    - actions-sha-pin\n",
			wantErr: "line 4: rules: want a map of rule name to level",
		},
		{
			name:    "rule level is a map",
			doc:     "version: 1\ndoctor:\n  rules:\n    actions-sha-pin: { level: off }\n",
			wantErr: "line 4: rules.actions-sha-pin: want a level such as off, got a map",
		},
		{
			name:    "doctor is a scalar",
			doc:     "version: 1\ndoctor: off\n",
			wantErr: "line 2: doctor: want a map with ci_min_severity, rules or pin_exceptions",
		},
		{
			name:    "pin_exceptions is a scalar",
			doc:     "version: 1\ndoctor:\n  pin_exceptions: myorg/*\n",
			wantErr: "line 3: pin_exceptions: want a list of globs",
		},
		{
			name:    "pin exception with whitespace",
			doc:     "version: 1\ndoctor:\n  pin_exceptions:\n    - \"my org/*\"\n",
			wantErr: "line 4: pin_exceptions: reference \"my org/*\": whitespace is not allowed",
		},
		{
			name:    "malformed pin exception glob",
			doc:     "version: 1\ndoctor:\n  pin_exceptions:\n    - \"myorg/[a-\"\n",
			wantErr: "line 4: pin_exceptions: reference \"myorg/[a-\": malformed glob",
		},
		{
			name:    "empty pin exception",
			doc:     "version: 1\ndoctor:\n  pin_exceptions:\n    -\n",
			wantErr: "line 4: pin_exceptions: an entry with no value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("Parse accepted:\n%s\nwant an error containing %q", tt.doc, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// The schema and the typed decoder must agree about the section, so an editor with
// the published file says what the binary says.
func TestDoctorSchemaAgreesWithTheDecoder(t *testing.T) {
	if err := ValidateSchema([]byte(doctorYAML)); err != nil {
		t.Fatalf("the schema rejects the documented section: %v", err)
	}
	rejected := []struct{ name, doc string }{
		{name: "unknown key", doc: "version: 1\ndoctor:\n  ci_min_sevrity: warn\n"},
		{name: "bad level", doc: "version: 1\ndoctor:\n  rules:\n    actions-sha-pin: loud\n"},
		{name: "ci_min_severity off", doc: "version: 1\ndoctor:\n  ci_min_severity: off\n"},
		{name: "rule name of the wrong shape", doc: "version: 1\ndoctor:\n  rules:\n    Actions SHA Pin: off\n"},
		{name: "rules is a list", doc: "version: 1\ndoctor:\n  rules:\n    - actions-sha-pin\n"},
		{name: "pin exception with whitespace", doc: "version: 1\ndoctor:\n  pin_exceptions:\n    - \"my org/*\"\n"},
		{name: "empty pin exception", doc: "version: 1\ndoctor:\n  pin_exceptions:\n    - \"\"\n"},
	}
	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSchema([]byte(tt.doc)); err == nil {
				t.Fatalf("the schema accepted:\n%s", tt.doc)
			}
		})
	}
}

// The commented block "policy init" writes has to be an example that works: strip the
// comment markers and the section it leaves behind must parse and mean what it says.
func TestDefaultYAMLDoctorBlock(t *testing.T) {
	text := string(DefaultYAML())
	if !strings.Contains(text, "\n# doctor:\n") {
		t.Fatal("default.yaml lacks the commented doctor block")
	}
	for _, key := range []string{"ci_min_severity", "rules", "pin_exceptions"} {
		if !strings.Contains(text, key) {
			t.Errorf("default.yaml does not explain %q", key)
		}
	}
	p := mustParse(t, text)
	if p.Doctor != nil {
		t.Errorf("the block must stay commented out: %+v", p.Doctor)
	}

	doc := "version: 1\n" + uncommentDoctorBlock(text)
	uncommented := mustParse(t, doc)
	if uncommented.Doctor == nil {
		t.Fatalf("the uncommented block decoded to nothing:\n%s", doc)
	}
	s := uncommented.EffectiveDoctor()
	if s.CIMinSeverity != model.LevelWarn {
		t.Errorf("the block's ci_min_severity = %s, want warn, the default it documents", s.CIMinSeverity)
	}
	if len(s.Levels) == 0 || len(s.PinExceptions) == 0 {
		t.Errorf("the block leaves rules or pin_exceptions empty: %+v", s)
	}
	for name := range s.Levels {
		if !doctorRuleName.MatchString(name) {
			t.Errorf("the block names %q, which is not shaped like a rule name", name)
		}
	}
}

// uncommentDoctorBlock returns the commented doctor block of the init template with
// one level of comment marker removed, which is what a reader who wants the section
// does by hand.
func uncommentDoctorBlock(text string) string {
	var out []string
	started := false
	for _, line := range strings.Split(text, "\n") {
		if line == "# doctor:" {
			started = true
		}
		if !started {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break
		}
		out = append(out, strings.TrimPrefix(strings.TrimPrefix(line, "# "), "#"))
	}
	return strings.Join(out, "\n") + "\n"
}

func TestValidateDoctorRulesNamesTheLineAndTheClosestNames(t *testing.T) {
	doc := "version: 1\ndoctor:\n  rules:\n    npm-strict-npmrc: info\n    npm-strict-nprmc: off\n    completely-made-up-rule: off\n"
	p := mustParse(t, doc)
	err := p.ValidateDoctorRules(knownRules)
	if err == nil {
		t.Fatal("ValidateDoctorRules accepted a rule no rule defines")
	}
	got := err.Error()
	for _, want := range []string{
		`line 6: doctor.rules: unknown rule "completely-made-up-rule"`,
		`line 5: doctor.rules: unknown rule "npm-strict-nprmc" (did you mean npm-strict-npmrc?)`,
		"want one of actions-sha-pin, bun-minimum-release-age",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ValidateDoctorRules error =\n%s\nwant it to contain %q", got, want)
		}
	}
	if strings.Contains(got, `unknown rule "npm-strict-npmrc"`) {
		t.Errorf("a real rule name was reported as unknown:\n%s", got)
	}
}

func TestDidYouMean(t *testing.T) {
	tests := []struct {
		name  string
		known []string
		want  string
	}{
		{name: "npm-strict-nprmc", known: knownRules, want: "did you mean npm-strict-npmrc?"},
		{name: "actions-sha-pins", known: knownRules, want: "did you mean actions-sha-pin?"},
		{name: "nothing-like-this-at-all", known: knownRules, want: "want one of actions-sha-pin"},
		{name: "anything", known: nil, want: "this build knows no doctor rules"},
		{name: "aa", known: []string{"ab", "ac", "ad", "ae"}, want: "did you mean ab or ac or ad?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := didYouMean(tt.name, tt.known); !strings.HasPrefix(got, tt.want) {
				t.Errorf("didYouMean(%q) = %q, want it to start with %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestNameDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{a: "", b: "", want: 0},
		{a: "", b: "abc", want: 3},
		{a: "abc", b: "", want: 3},
		{a: "npmrc", b: "nprmc", want: 2},
		{a: "npm-min-release-age", b: "npm-min-release-age", want: 0},
		{a: "kitten", b: "sitting", want: 3},
	}
	for _, tt := range tests {
		if got := nameDistance(tt.a, tt.b); got != tt.want {
			t.Errorf("nameDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// A section built in Go rather than read from a file is checked too, without the
// lines it never had.
func TestValidateRejectsAHandBuiltDoctorSection(t *testing.T) {
	off := model.LevelOff
	p := &Policy{
		Version: 1,
		Doctor: &DoctorConfig{
			CIMinSeverity: &off,
			Rules:         map[string]DoctorRule{"Not A Rule": {Level: model.LevelInfo}},
			PinExceptions: []string{"my org/*"},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted a doctor section that cannot work")
	}
	for _, want := range []string{
		"doctor.ci_min_severity must be block, warn or info, got off",
		`doctor.rules: "Not A Rule" is not a rule name`,
		"doctor.pin_exceptions[0]",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate error =\n%v\nwant it to contain %q", err, want)
		}
	}
	good := &Policy{Version: 1, Doctor: &DoctorConfig{Rules: map[string]DoctorRule{"npm-strict-npmrc": {Level: model.LevelInfo}}}}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate(good doctor section) = %v, want nil", err)
	}
}
