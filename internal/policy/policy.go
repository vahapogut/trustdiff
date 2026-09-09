package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Built-in defaults, applied wherever the policy file is silent.
const (
	DefaultCooldown               = 3 * unitDay
	DefaultPreviousVersionsWindow = 5
	DefaultOnDataUnavailable      = OnDataUnavailableWarn
)

// OnDataUnavailable says what a run does when a required data source cannot be reached.
type OnDataUnavailable string

// Values of on_data_unavailable.
const (
	// OnDataUnavailableWarn reports the affected checks as skipped and keeps the exit code.
	OnDataUnavailableWarn OnDataUnavailable = "warn"
	// OnDataUnavailableFail reports them as skipped and exits with code 3.
	OnDataUnavailableFail OnDataUnavailable = "fail"
)

// Severities accepted by vulnerability.min_severity, from least to most severe.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severities = []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Identity of the finding emitted for an expired allow entry.
const (
	ExpiredAllowID   = "TD000"
	ExpiredAllowName = "expired-allow"
)

// Window is the previous_versions_window value: how many previous versions
// publisher-changed looks back at. Like Duration it refuses zero in the file, where a
// zero window would be indistinguishable from an absent one, which means the default.
type Window int

// UnmarshalYAML accepts a whole number of at least 1.
func (w *Window) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: previous_versions_window: want a whole number, got a %s", n.Line, yamlKind(n))
	}
	var v int
	// The tag check refuses 5.5, which yaml would otherwise truncate to 5.
	if n.ShortTag() != "!!int" || n.Decode(&v) != nil {
		return fmt.Errorf("line %d: previous_versions_window: want a whole number, got %q", n.Line, n.Value)
	}
	if v < 1 {
		return fmt.Errorf("line %d: previous_versions_window must be at least 1, got %d", n.Line, v)
	}
	*w = Window(v)
	return nil
}

// Policy is the .trustdiff.yaml file as written. Zero values mean "not set": Effective
// fills in the built-in defaults, so callers should go through it rather than read the
// fields directly.
type Policy struct {
	Version                int                                   `yaml:"version"`
	Cooldown               Duration                              `yaml:"cooldown,omitempty"`
	CooldownExclude        []Pattern                             `yaml:"cooldown_exclude,omitempty"`
	PreviousVersionsWindow Window                                `yaml:"previous_versions_window,omitempty"`
	Checks                 map[string]CheckConfig                `yaml:"checks,omitempty"`
	Allow                  []AllowEntry                          `yaml:"allow,omitempty"`
	OnDataUnavailable      OnDataUnavailable                     `yaml:"on_data_unavailable,omitempty"`
	Ecosystems             map[model.Ecosystem]EcosystemOverride `yaml:"ecosystems,omitempty"`
}

// CheckConfig is one entry of the checks map. In YAML it is either a bare level
// ("warn") or an object ({level: block, min_severity: high}). Nil fields were not
// written and keep their default.
type CheckConfig struct {
	Level              *model.Level
	MinSeverity        *string
	MinWeeklyDownloads *int64
}

// UnmarshalYAML accepts the bare level and the object form. Unknown and repeated keys
// inside the object are errors, like everywhere else in the file.
func (c *CheckConfig) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		level, err := parseLevel(n.Value)
		if err != nil {
			return fmt.Errorf("line %d: %w", n.Line, err)
		}
		*c = CheckConfig{Level: &level}
		return nil
	case yaml.MappingNode:
		out := CheckConfig{}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if seen[key.Value] {
				return fmt.Errorf("line %d: key %q already defined in this check entry", key.Line, key.Value)
			}
			seen[key.Value] = true
			if value.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: %s: want a scalar, got a %s", value.Line, key.Value, yamlKind(value))
			}
			switch key.Value {
			case "level":
				level, err := parseLevel(value.Value)
				if err != nil {
					return fmt.Errorf("line %d: level: %w", value.Line, err)
				}
				out.Level = &level
			case "min_severity":
				s := value.Value
				out.MinSeverity = &s
			case "min_weekly_downloads":
				var v int64
				if err := value.Decode(&v); err != nil {
					return fmt.Errorf("line %d: min_weekly_downloads: want a whole number, got %q", value.Line, value.Value)
				}
				out.MinWeeklyDownloads = &v
			default:
				return fmt.Errorf("line %d: unknown key %q in a check entry (want level, min_severity or min_weekly_downloads)", key.Line, key.Value)
			}
		}
		*c = out
		return nil
	default:
		return fmt.Errorf("line %d: want a level such as warn or an object such as {level: block, min_severity: high}, got a %s", n.Line, yamlKind(n))
	}
}

// parseLevel accepts a level spelled exactly as the published schema lists it.
// model.ParseLevel folds case for the command line, but a file that says "Warn" would
// pass the typed decoder and then fail the schema's enum without a line number, so
// it is rejected here first.
func parseLevel(value string) (model.Level, error) {
	level, err := model.ParseLevel(value)
	if err != nil {
		return 0, err
	}
	if level.String() != value {
		return 0, fmt.Errorf("level %q must be written in lowercase as %s", value, level)
	}
	return level, nil
}

// MarshalYAML writes the shortest form: a bare level when no option is set.
func (c CheckConfig) MarshalYAML() (any, error) {
	if c.MinSeverity == nil && c.MinWeeklyDownloads == nil {
		if c.Level == nil {
			return nil, nil
		}
		return c.Level.String(), nil
	}
	out := map[string]any{}
	if c.Level != nil {
		out["level"] = c.Level.String()
	}
	if c.MinSeverity != nil {
		out["min_severity"] = *c.MinSeverity
	}
	if c.MinWeeklyDownloads != nil {
		out["min_weekly_downloads"] = *c.MinWeeklyDownloads
	}
	return out, nil
}

// AllowEntry is a reviewed exception: the named check is not reported for packages
// matching the pattern until the entry expires.
type AllowEntry struct {
	Check   string  `yaml:"check"`
	Package Pattern `yaml:"package"`
	Reason  string  `yaml:"reason"`
	Expires Date    `yaml:"expires,omitempty"`
}

// Expired reports whether the entry has passed its expiry date. An entry stays valid
// for the whole of its expiry day, in UTC; an entry without a date never expires.
func (a *AllowEntry) Expired(now time.Time) bool {
	if a.Expires.IsZero() {
		return false
	}
	return !now.UTC().Before(a.Expires.Time().Add(unitDay))
}

// EcosystemOverride carries the keys a single ecosystem may override.
type EcosystemOverride struct {
	Cooldown Duration               `yaml:"cooldown,omitempty"`
	Checks   map[string]CheckConfig `yaml:"checks,omitempty"`
}

// checkDefault is the built-in level and options of one check, from brief section 4.
type checkDefault struct {
	name    string
	setting CheckSetting
}

// checkDefaults lists every check in the order of the brief. It is the source of
// CheckNames and DefaultCheck.
var checkDefaults = []checkDefault{
	{"young-version", CheckSetting{Level: model.LevelWarn}},
	{"publisher-changed", CheckSetting{Level: model.LevelBlock}},
	{"maintainers-changed", CheckSetting{Level: model.LevelWarn}},
	{"trust-downgrade", CheckSetting{Level: model.LevelBlock}},
	{"install-script-introduced", CheckSetting{Level: model.LevelBlock}},
	{"install-script-present", CheckSetting{Level: model.LevelWarn}},
	{"new-dependency-introduced", CheckSetting{Level: model.LevelWarn}},
	{"typosquat-suspect", CheckSetting{Level: model.LevelBlock}},
	{"malicious-advisory", CheckSetting{Level: model.LevelBlock}},
	{"vulnerability", CheckSetting{Level: model.LevelBlock, MinSeverity: SeverityHigh}},
	{"deprecated-or-yanked", CheckSetting{Level: model.LevelWarn}},
	{"low-usage", CheckSetting{Level: model.LevelInfo, MinWeeklyDownloads: 500}},
	{"exotic-source", CheckSetting{Level: model.LevelBlock}},
	{"integrity-missing", CheckSetting{Level: model.LevelWarn}},
	{"version-anomaly", CheckSetting{Level: model.LevelInfo}},
}

// CheckNames lists the policy names of every check in the order of the brief.
func CheckNames() []string {
	out := make([]string, len(checkDefaults))
	for i, d := range checkDefaults {
		out[i] = d.name
	}
	return out
}

// DefaultCheck returns the built-in setting of a check.
func DefaultCheck(name string) (CheckSetting, bool) {
	for _, d := range checkDefaults {
		if d.name == name {
			return d.setting, true
		}
	}
	return CheckSetting{}, false
}

func knownCheck(name string) bool {
	_, ok := DefaultCheck(name)
	return ok
}

// Default returns the policy the brief shows as its example, which is also what
// "policy init" writes.
func Default() *Policy {
	checks := make(map[string]CheckConfig, len(checkDefaults))
	for _, d := range checkDefaults {
		level := d.setting.Level
		cfg := CheckConfig{Level: &level}
		if d.setting.MinSeverity != "" {
			s := d.setting.MinSeverity
			cfg.MinSeverity = &s
		}
		if d.setting.MinWeeklyDownloads != 0 {
			n := d.setting.MinWeeklyDownloads
			cfg.MinWeeklyDownloads = &n
		}
		checks[d.name] = cfg
	}
	return &Policy{
		Version:  1,
		Cooldown: Duration(DefaultCooldown),
		CooldownExclude: []Pattern{
			MustParsePattern("npm:@myorg/*"),
			MustParsePattern("pypi:myorg-*"),
		},
		PreviousVersionsWindow: DefaultPreviousVersionsWindow,
		Checks:                 checks,
		Allow: []AllowEntry{{
			Check:   "install-script-present",
			Package: MustParsePattern("npm:esbuild"),
			Reason:  "downloads a native binary; reviewed by @vahap 2026-09-08",
			Expires: Date{Year: 2027, Month: time.March, Day: 1},
		}},
		OnDataUnavailable: OnDataUnavailableWarn,
		Ecosystems: map[model.Ecosystem]EcosystemOverride{
			model.Cargo: {Cooldown: Duration(7 * unitDay)},
		},
	}
}

// Validate checks everything the YAML types cannot: the version, check names, option
// placement and values, allow entries, on_data_unavailable and ecosystem overrides.
// Every problem is reported, joined into one error.
func (p *Policy) Validate() error {
	var errs []error
	if p.Version != 1 {
		errs = append(errs, fmt.Errorf("version must be 1, got %d", p.Version))
	}
	if p.PreviousVersionsWindow < 0 {
		errs = append(errs, fmt.Errorf("previous_versions_window must not be negative, got %d", p.PreviousVersionsWindow))
	}
	errs = append(errs, validateChecks("checks", p.Checks)...)
	for i := range p.Allow {
		errs = append(errs, validateAllow(i, &p.Allow[i])...)
	}
	switch p.OnDataUnavailable {
	case "", OnDataUnavailableWarn, OnDataUnavailableFail:
	default:
		errs = append(errs, fmt.Errorf("on_data_unavailable must be warn or fail, got %q", p.OnDataUnavailable))
	}
	known := model.Ecosystems()
	ecosystems := make([]model.Ecosystem, 0, len(p.Ecosystems))
	for eco := range p.Ecosystems {
		ecosystems = append(ecosystems, eco)
	}
	slices.Sort(ecosystems)
	for _, eco := range ecosystems {
		if !slices.Contains(known, eco) {
			errs = append(errs, fmt.Errorf("ecosystems: unknown ecosystem %q", eco))
			continue
		}
		errs = append(errs, validateChecks("ecosystems."+string(eco)+".checks", p.Ecosystems[eco].Checks)...)
	}
	return errors.Join(errs...)
}

func validateChecks(where string, checks map[string]CheckConfig) []error {
	var errs []error
	names := make([]string, 0, len(checks))
	for name := range checks {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		cfg := checks[name]
		if !knownCheck(name) {
			errs = append(errs, fmt.Errorf("%s: unknown check %q (want one of %s)", where, name, strings.Join(CheckNames(), ", ")))
			continue
		}
		if cfg.MinSeverity != nil {
			if name != "vulnerability" {
				errs = append(errs, fmt.Errorf("%s.%s: min_severity applies to vulnerability only", where, name))
			} else if !slices.Contains(severities, *cfg.MinSeverity) {
				errs = append(errs, fmt.Errorf("%s.%s: min_severity must be one of %s, got %q", where, name, strings.Join(severities, ", "), *cfg.MinSeverity))
			}
		}
		if cfg.MinWeeklyDownloads != nil {
			if name != "low-usage" {
				errs = append(errs, fmt.Errorf("%s.%s: min_weekly_downloads applies to low-usage only", where, name))
			} else if *cfg.MinWeeklyDownloads < 0 {
				errs = append(errs, fmt.Errorf("%s.%s: min_weekly_downloads must not be negative, got %d", where, name, *cfg.MinWeeklyDownloads))
			}
		}
	}
	return errs
}

func validateAllow(i int, a *AllowEntry) []error {
	var errs []error
	where := fmt.Sprintf("allow[%d]", i)
	switch {
	case strings.TrimSpace(a.Check) == "":
		errs = append(errs, fmt.Errorf("%s: check is required", where))
	case !knownCheck(a.Check):
		errs = append(errs, fmt.Errorf("%s: unknown check %q (want one of %s)", where, a.Check, strings.Join(CheckNames(), ", ")))
	}
	if a.Package.String() == "" {
		errs = append(errs, fmt.Errorf("%s: package is required", where))
	}
	if strings.TrimSpace(a.Reason) == "" {
		errs = append(errs, fmt.Errorf("%s: reason is required (say why the exception exists and who reviewed it)", where))
	}
	return errs
}
