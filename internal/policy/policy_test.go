package policy

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// exampleYAML is the policy from the project brief, section 5, without comments.
const exampleYAML = `version: 1
cooldown: 3d
cooldown_exclude:
  - "npm:@myorg/*"
  - "pypi:myorg-*"
previous_versions_window: 5
checks:
  young-version: warn
  publisher-changed: block
  maintainers-changed: warn
  trust-downgrade: block
  install-script-introduced: block
  install-script-present: warn
  new-dependency-introduced: warn
  typosquat-suspect: block
  malicious-advisory: block
  vulnerability: { level: block, min_severity: high }
  deprecated-or-yanked: warn
  low-usage: { level: info, min_weekly_downloads: 500 }
  exotic-source: block
  integrity-missing: warn
  version-anomaly: info
  lockfile-entry-changed: block
  version-downgraded: info
allow:
  - check: install-script-present
    package: "npm:esbuild"
    reason: "downloads a native binary; reviewed by @vahap 2026-09-08"
    expires: 2027-03-01
on_data_unavailable: warn
ecosystems:
  cargo:
    cooldown: 7d
`

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse:\n%s\nerror: %v", doc, err)
	}
	return p
}

func TestDefaultMatchesTheBrief(t *testing.T) {
	d := Default()
	if d.Version != 1 {
		t.Errorf("Version = %d, want 1", d.Version)
	}
	if time.Duration(d.Cooldown) != 3*day {
		t.Errorf("Cooldown = %v, want 3d", time.Duration(d.Cooldown))
	}
	if d.PreviousVersionsWindow != 5 {
		t.Errorf("PreviousVersionsWindow = %d, want 5", d.PreviousVersionsWindow)
	}
	if d.OnDataUnavailable != OnDataUnavailableWarn {
		t.Errorf("OnDataUnavailable = %q, want warn", d.OnDataUnavailable)
	}
	if got := []string{d.CooldownExclude[0].String(), d.CooldownExclude[1].String()}; !slices.Equal(got, []string{"npm:@myorg/*", "pypi:myorg-*"}) {
		t.Errorf("CooldownExclude = %v", got)
	}
	if len(d.Checks) != 17 {
		t.Errorf("len(Checks) = %d, want 17", len(d.Checks))
	}
	wantLevels := map[string]model.Level{
		"young-version":             model.LevelWarn,
		"publisher-changed":         model.LevelBlock,
		"maintainers-changed":       model.LevelWarn,
		"trust-downgrade":           model.LevelBlock,
		"install-script-introduced": model.LevelBlock,
		"install-script-present":    model.LevelWarn,
		"new-dependency-introduced": model.LevelWarn,
		"typosquat-suspect":         model.LevelBlock,
		"malicious-advisory":        model.LevelBlock,
		"vulnerability":             model.LevelBlock,
		"deprecated-or-yanked":      model.LevelWarn,
		"low-usage":                 model.LevelInfo,
		"exotic-source":             model.LevelBlock,
		"integrity-missing":         model.LevelWarn,
		"version-anomaly":           model.LevelInfo,
		"lockfile-entry-changed":    model.LevelBlock,
		"version-downgraded":        model.LevelInfo,
	}
	for name, want := range wantLevels {
		cfg, ok := d.Checks[name]
		if !ok || cfg.Level == nil {
			t.Errorf("Checks[%q] has no level", name)
			continue
		}
		if *cfg.Level != want {
			t.Errorf("Checks[%q].Level = %s, want %s", name, *cfg.Level, want)
		}
	}
	if sev := d.Checks["vulnerability"].MinSeverity; sev == nil || *sev != SeverityHigh {
		t.Errorf("vulnerability.min_severity = %v, want high", sev)
	}
	if dl := d.Checks["low-usage"].MinWeeklyDownloads; dl == nil || *dl != 500 {
		t.Errorf("low-usage.min_weekly_downloads = %v, want 500", dl)
	}
	if d.Checks["young-version"].MinSeverity != nil || d.Checks["young-version"].MinWeeklyDownloads != nil {
		t.Error("young-version must carry no options")
	}
	if len(d.Allow) != 1 {
		t.Fatalf("len(Allow) = %d, want 1", len(d.Allow))
	}
	a := d.Allow[0]
	if a.Check != "install-script-present" || a.Package.String() != "npm:esbuild" || a.Reason != "downloads a native binary; reviewed by @vahap 2026-09-08" || a.Expires.String() != "2027-03-01" {
		t.Errorf("Allow[0] = %+v", a)
	}
	if got := time.Duration(d.Ecosystems[model.Cargo].Cooldown); got != 7*day {
		t.Errorf("Ecosystems[cargo].Cooldown = %v, want 7d", got)
	}
	if got := CheckNames(); len(got) != 17 || got[0] != "young-version" || got[16] != "version-downgraded" {
		t.Errorf("CheckNames() = %v", got)
	}
}

func TestParseExampleEqualsDefault(t *testing.T) {
	got := mustParse(t, exampleYAML)
	want := Default()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse(example) differs from Default()\n got: %+v\nwant: %+v", got, want)
	}
}

func TestParseMinimalUsesDefaults(t *testing.T) {
	p := mustParse(t, "version: 1\n")
	for _, eco := range model.Ecosystems() {
		s := p.Effective(eco)
		if s.Ecosystem != eco {
			t.Errorf("Effective(%s).Ecosystem = %s", eco, s.Ecosystem)
		}
		if s.Cooldown != DefaultCooldown || s.PreviousVersionsWindow != DefaultPreviousVersionsWindow || s.OnDataUnavailable != DefaultOnDataUnavailable {
			t.Errorf("Effective(%s) = %+v, want the built-in defaults", eco, s)
		}
		if len(s.Checks) != 17 {
			t.Errorf("Effective(%s) has %d checks, want 17", eco, len(s.Checks))
		}
		for _, name := range CheckNames() {
			want, _ := DefaultCheck(name)
			if got, ok := s.Check(name); !ok || got != want {
				t.Errorf("Effective(%s).Check(%s) = %+v, %v; want %+v", eco, name, got, ok, want)
			}
		}
	}
	if _, ok := p.Effective(model.NPM).Check("nope"); ok {
		t.Error("Check(nope) reported a setting")
	}
	if p.CooldownExcluded(model.MustParseRef("npm:@myorg/x")) {
		t.Error("a minimal policy must exclude nothing from the cooldown")
	}
	if _, ok := p.Allowed("install-script-present", model.MustParseRef("npm:esbuild"), time.Now()); ok {
		t.Error("a minimal policy must allow nothing")
	}
}

func TestNilPolicyBehavesLikeDefaults(t *testing.T) {
	var p *Policy
	s := p.Effective(model.Cargo)
	if s.Cooldown != DefaultCooldown || len(s.Checks) != 17 {
		t.Fatalf("nil Effective = %+v", s)
	}
	if p.CooldownExcluded(model.MustParseRef("cargo:serde")) {
		t.Error("nil CooldownExcluded = true")
	}
	if _, ok := p.Allowed("vulnerability", model.MustParseRef("cargo:serde"), time.Now()); ok {
		t.Error("nil Allow found an entry")
	}
	if got := p.ExpiredAllows(time.Now()); len(got) != 0 {
		t.Errorf("nil ExpiredAllows = %v", got)
	}
}

func TestEffectivePrecedence(t *testing.T) {
	doc := `version: 1
cooldown: 2d
previous_versions_window: 8
on_data_unavailable: fail
checks:
  vulnerability: { level: warn, min_severity: medium }
  low-usage: warn
  young-version: { level: info }
ecosystems:
  cargo:
    cooldown: 7d
    checks:
      vulnerability: { min_severity: critical }
      low-usage: { level: off, min_weekly_downloads: 50 }
      young-version: block
  pypi:
    checks:
      trust-downgrade: warn
`
	p := mustParse(t, doc)

	npm := p.Effective(model.NPM)
	if npm.Cooldown != 2*day || npm.PreviousVersionsWindow != 8 || npm.OnDataUnavailable != OnDataUnavailableFail {
		t.Errorf("npm settings = %+v", npm)
	}
	if got := npm.Checks["vulnerability"]; got != (CheckSetting{Level: model.LevelWarn, MinSeverity: SeverityMedium}) {
		t.Errorf("npm vulnerability = %+v", got)
	}
	// A bare level keeps the option defaults.
	if got := npm.Checks["low-usage"]; got != (CheckSetting{Level: model.LevelWarn, MinWeeklyDownloads: 500}) {
		t.Errorf("npm low-usage = %+v", got)
	}
	// An object without a level keeps the default level.
	if got := npm.Checks["young-version"]; got != (CheckSetting{Level: model.LevelInfo}) {
		t.Errorf("npm young-version = %+v", got)
	}
	if got := npm.Checks["trust-downgrade"]; got != (CheckSetting{Level: model.LevelBlock}) {
		t.Errorf("npm trust-downgrade = %+v", got)
	}

	cargo := p.Effective(model.Cargo)
	if cargo.Cooldown != 7*day || cargo.PreviousVersionsWindow != 8 {
		t.Errorf("cargo settings = %+v", cargo)
	}
	// The override changes min_severity only; the level stays the policy value.
	if got := cargo.Checks["vulnerability"]; got != (CheckSetting{Level: model.LevelWarn, MinSeverity: SeverityCritical}) {
		t.Errorf("cargo vulnerability = %+v", got)
	}
	if got := cargo.Checks["low-usage"]; got != (CheckSetting{Level: model.LevelOff, MinWeeklyDownloads: 50}) {
		t.Errorf("cargo low-usage = %+v", got)
	}
	if got := cargo.Checks["young-version"]; got != (CheckSetting{Level: model.LevelBlock}) {
		t.Errorf("cargo young-version = %+v", got)
	}

	pypi := p.Effective(model.PyPI)
	if pypi.Cooldown != 2*day {
		t.Errorf("pypi cooldown = %v, want the policy value", pypi.Cooldown)
	}
	if got := pypi.Checks["trust-downgrade"]; got != (CheckSetting{Level: model.LevelWarn}) {
		t.Errorf("pypi trust-downgrade = %+v", got)
	}
	if got := pypi.Checks["vulnerability"]; got != (CheckSetting{Level: model.LevelWarn, MinSeverity: SeverityMedium}) {
		t.Errorf("pypi vulnerability = %+v", got)
	}

	// Effective returns a copy; changing it must not change the policy.
	npm.Checks["vulnerability"] = CheckSetting{Level: model.LevelOff}
	if got := p.Effective(model.NPM).Checks["vulnerability"].Level; got != model.LevelWarn {
		t.Errorf("Effective shares state: level became %s", got)
	}
}

func TestAllowAndExpiry(t *testing.T) {
	doc := `version: 1
allow:
  - check: install-script-present
    package: "npm:esbuild"
    reason: "downloads a native binary"
    expires: 2027-03-01
  - check: vulnerability
    package: "pypi:requests@2.*"
    reason: "no fix released yet"
  - check: low-usage
    package: "@myorg/*"
    reason: "internal packages"
`
	p := mustParse(t, doc)
	esbuild := model.MustParseRef("npm:esbuild@0.20.0")
	before := time.Date(2027, time.March, 1, 23, 59, 59, 0, time.UTC)
	after := time.Date(2027, time.March, 2, 0, 0, 0, 0, time.UTC)

	if entry, ok := p.Allowed("install-script-present", esbuild, before); !ok || entry.Package.String() != "npm:esbuild" {
		t.Errorf("Allow on the expiry day = %v, %v; want the entry", entry, ok)
	}
	if entry, ok := p.Allowed("install-script-present", esbuild, after); ok {
		t.Errorf("Allow after the expiry day = %v, want none", entry)
	}
	if _, ok := p.Allowed("install-script-introduced", esbuild, before); ok {
		t.Error("Allow matched a different check")
	}
	if _, ok := p.Allowed("install-script-present", model.MustParseRef("pypi:esbuild"), before); ok {
		t.Error("Allow matched a different ecosystem")
	}
	if _, ok := p.Allowed("vulnerability", model.MustParseRef("pypi:requests@2.32.3"), after); !ok {
		t.Error("Allow without expiry must never expire")
	}
	if _, ok := p.Allowed("vulnerability", model.MustParseRef("pypi:requests@3.0.0"), after); ok {
		t.Error("Allow matched a version outside the pattern")
	}
	if _, ok := p.Allowed("low-usage", model.MustParseRef("jsr:@myorg/thing"), after); !ok {
		t.Error("Allow without an ecosystem prefix must match every ecosystem")
	}

	if got := p.ExpiredAllows(before); len(got) != 0 {
		t.Errorf("ExpiredAllows before expiry = %v", got)
	}
	expired := p.ExpiredAllows(after)
	if len(expired) != 1 || expired[0].Check != "install-script-present" {
		t.Fatalf("ExpiredAllows after expiry = %v", expired)
	}
	if !expired[0].Expired(after) || expired[0].Expired(before) {
		t.Error("Expired disagrees with ExpiredAllows")
	}
	// The expiry day is a UTC day, whatever zone the clock reports in.
	west := time.Date(2027, time.March, 1, 20, 0, 0, 0, time.FixedZone("UTC-5", -5*3600))
	if !p.Allow[0].Expired(west) {
		t.Error("20:00 UTC-5 on the expiry day is 01:00 UTC the next day and must count as expired")
	}
	east := time.Date(2027, time.March, 2, 13, 0, 0, 0, time.FixedZone("UTC+14", 14*3600))
	if p.Allow[0].Expired(east) {
		t.Error("13:00 UTC+14 on the day after is still 23:00 UTC on the expiry day")
	}

	f := ExpiredAllowFinding(&expired[0], esbuild, after)
	if f.ID != "TD000" || ExpiredAllowID != "TD000" || f.Name != "expired-allow" || ExpiredAllowName != "expired-allow" || f.Level != model.LevelWarn {
		t.Errorf("finding identity = %+v", f)
	}
	if f.Ref != esbuild {
		t.Errorf("finding ref = %v, want %v", f.Ref, esbuild)
	}
	for _, want := range []string{"install-script-present", "npm:esbuild", "2027-03-01"} {
		if !strings.Contains(f.Title, want) {
			t.Errorf("title %q lacks %q", f.Title, want)
		}
	}
	for _, want := range []string{"downloads a native binary", "2027-03-01", "2027-03-02"} {
		if !strings.Contains(f.Explanation, want) {
			t.Errorf("explanation %q lacks %q", f.Explanation, want)
		}
	}
	if f.Evidence["check"] != "install-script-present" || f.Evidence["package"] != "npm:esbuild" || f.Evidence["reason"] != "downloads a native binary" || f.Evidence["expires"] != "2027-03-01" {
		t.Errorf("evidence = %v", f.Evidence)
	}
}

func TestCooldownExcluded(t *testing.T) {
	p := mustParse(t, "version: 1\ncooldown_exclude:\n  - \"npm:@myorg/*\"\n  - pypi:myorg-*\n  - internal-tool\n")
	tests := []struct {
		ref  string
		want bool
	}{
		{ref: "npm:@myorg/ui@1.0.0", want: true},
		{ref: "npm:@other/ui", want: false},
		{ref: "pypi:MyOrg_Tools", want: true},
		{ref: "cargo:myorg-tools", want: false},
		{ref: "cargo:internal-tool@0.1.0", want: true},
		{ref: "npm:express", want: false},
	}
	for _, tt := range tests {
		if got := p.CooldownExcluded(model.MustParseRef(tt.ref)); got != tt.want {
			t.Errorf("CooldownExcluded(%s) = %v, want %v", tt.ref, got, tt.want)
		}
	}
}

func TestDate(t *testing.T) {
	d, err := ParseDate("2027-03-01")
	if err != nil || d != (Date{Year: 2027, Month: time.March, Day: 1}) || d.String() != "2027-03-01" || d.IsZero() {
		t.Fatalf("ParseDate = %+v, %v", d, err)
	}
	if got := d.Time(); got != time.Date(2027, time.March, 1, 0, 0, 0, 0, time.UTC) {
		t.Errorf("Time() = %v", got)
	}
	for _, bad := range []string{"", "2027-3-1", "2027-02-30", "01/03/2027", "2027-03-01T00:00:00Z", "tomorrow"} {
		if _, err := ParseDate(bad); err == nil {
			t.Errorf("ParseDate(%q) accepted", bad)
		}
	}
	if !(Date{}).IsZero() {
		t.Error("zero Date is not zero")
	}
	var fromYAML Date
	if err := fromYAML.UnmarshalYAML(scalarNode("2027-03-01")); err != nil || fromYAML != d {
		t.Errorf("UnmarshalYAML = %+v, %v", fromYAML, err)
	}
	if err := fromYAML.UnmarshalYAML(sequenceNode("2027-03-01")); err == nil || !strings.Contains(err.Error(), "want a date") {
		t.Errorf("UnmarshalYAML(list) error = %v", err)
	}
	if out, err := d.MarshalYAML(); err != nil || out != "2027-03-01" {
		t.Errorf("MarshalYAML = %v, %v", out, err)
	}
}

func TestValidateRejects(t *testing.T) {
	base := Default()
	tests := []struct {
		name    string
		mutate  func(p *Policy)
		wantErr string
	}{
		{name: "version 2", mutate: func(p *Policy) { p.Version = 2 }, wantErr: "version must be 1"},
		{name: "negative window", mutate: func(p *Policy) { p.PreviousVersionsWindow = -1 }, wantErr: "previous_versions_window"},
		{name: "unknown check", mutate: func(p *Policy) { p.Checks["bogus"] = CheckConfig{Level: ptr(model.LevelWarn)} }, wantErr: `unknown check "bogus"`},
		{name: "option on wrong check", mutate: func(p *Policy) { p.Checks["young-version"] = CheckConfig{MinSeverity: ptr("high")} }, wantErr: "min_severity applies to vulnerability only"},
		{name: "bad severity", mutate: func(p *Policy) { p.Checks["vulnerability"] = CheckConfig{MinSeverity: ptr("extreme")} }, wantErr: `min_severity must be one of low, medium, high, critical, got "extreme"`},
		{name: "negative downloads", mutate: func(p *Policy) { p.Checks["low-usage"] = CheckConfig{MinWeeklyDownloads: ptr(int64(-1))} }, wantErr: "min_weekly_downloads must not be negative"},
		{name: "allow without reason", mutate: func(p *Policy) { p.Allow[0].Reason = "  " }, wantErr: "allow[0]: reason is required"},
		{name: "allow without check", mutate: func(p *Policy) { p.Allow[0].Check = "" }, wantErr: "allow[0]: check is required"},
		{name: "allow unknown check", mutate: func(p *Policy) { p.Allow[0].Check = "nope" }, wantErr: `allow[0]: unknown check "nope"`},
		{name: "allow without package", mutate: func(p *Policy) { p.Allow[0].Package = Pattern{} }, wantErr: "allow[0]: package is required"},
		{name: "bad on_data_unavailable", mutate: func(p *Policy) { p.OnDataUnavailable = "panic" }, wantErr: `on_data_unavailable must be warn or fail, got "panic"`},
		{name: "unknown ecosystem", mutate: func(p *Policy) { p.Ecosystems["gem"] = EcosystemOverride{} }, wantErr: `ecosystems: unknown ecosystem "gem"`},
		{name: "ecosystem wrong case", mutate: func(p *Policy) { p.Ecosystems["NPM"] = EcosystemOverride{} }, wantErr: `ecosystems: unknown ecosystem "NPM"`},
		{name: "override unknown check", mutate: func(p *Policy) {
			p.Ecosystems[model.NPM] = EcosystemOverride{Checks: map[string]CheckConfig{"nope": {}}}
		}, wantErr: `ecosystems.npm.checks: unknown check "nope"`},
		{name: "override bad option", mutate: func(p *Policy) {
			p.Ecosystems[model.NPM] = EcosystemOverride{Checks: map[string]CheckConfig{"low-usage": {MinSeverity: ptr("high")}}}
		}, wantErr: "ecosystems.npm.checks.low-usage: min_severity applies to vulnerability only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := clonePolicy(base)
			tt.mutate(p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate accepted the policy, want an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v", err)
	}
}

// Validate reports every problem at once.
func TestValidateReportsEverything(t *testing.T) {
	p := &Policy{Version: 3, OnDataUnavailable: "maybe", Allow: []AllowEntry{{Check: "nope"}}}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted the policy")
	}
	for _, want := range []string{"version must be 1", "on_data_unavailable", `unknown check "nope"`, "reason is required", "package is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func clonePolicy(p *Policy) *Policy {
	out := *p
	out.CooldownExclude = slices.Clone(p.CooldownExclude)
	out.Allow = slices.Clone(p.Allow)
	out.Checks = map[string]CheckConfig{}
	for k, v := range p.Checks {
		out.Checks[k] = v
	}
	out.Ecosystems = map[model.Ecosystem]EcosystemOverride{}
	for k, v := range p.Ecosystems {
		out.Ecosystems[k] = v
	}
	return &out
}
