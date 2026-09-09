package policy

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/model"
)

// DefaultDoctorCIMinSeverity is the level a missing or wrong setting has to reach
// for "doctor --ci" to exit 1 when the policy does not say. It is warn, because the
// settings doctor reads are the ones a project meant to have and mostly does not,
// and a team that wants a stricter or a softer gate writes ci_min_severity.
const DefaultDoctorCIMinSeverity = model.LevelWarn

// doctorRuleName is the shape of a doctor rule name: lowercase words joined by
// hyphens, such as npm-min-release-age. This package cannot compare a name against
// the real list, because internal/doctor imports this package and importing it back
// would be a cycle, so a name is checked for shape while the file is read and the
// command that holds both packages checks the names themselves through
// ValidateDoctorRules.
var doctorRuleName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// DoctorConfig is the optional doctor: section of the policy file as written. Every
// key in it is optional, and so is the section: a file without it reports every rule
// at the level the rule itself carries, which is what a project that has not
// disagreed with one of them wants. Nil fields were not written and keep their
// default, like everywhere else in the file.
type DoctorConfig struct {
	// CIMinSeverity is the lowest level a missing or wrong setting has to reach for
	// "doctor --ci" to exit 1.
	CIMinSeverity *model.Level `yaml:"ci_min_severity,omitempty"`
	// Rules is the level each named rule is reported at, off to turn it off. The
	// keys are doctor's rule names, such as npm-min-release-age, and not the check
	// names the rest of the file uses.
	Rules map[string]DoctorRule `yaml:"rules,omitempty"`
	// PinExceptions are the workflow references this project has decided may keep a
	// tag, as globs over owner/repo.
	PinExceptions []string `yaml:"pin_exceptions,omitempty"`
}

// DoctorRule is one entry of doctor.rules.
type DoctorRule struct {
	// Level is the level the rule is reported at; off turns the rule off.
	Level model.Level
	// Line is the line of the policy file the entry was written on, so that a name
	// no rule defines can be reported with its line the way every other mistake in
	// the file is. It is zero for an entry that was not read from a file.
	Line int
}

// MarshalYAML writes the entry as the bare level it was written as.
func (r DoctorRule) MarshalYAML() (any, error) { return r.Level.String(), nil }

// UnmarshalYAML reads the section key by key so that every value can be reported
// with the line it was written on. Unknown and repeated keys are errors, as
// everywhere else in the file, and a key with no value at all is read as "not set",
// which is what an example commented out by hand leaves behind.
func (d *DoctorConfig) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: doctor: want a map with ci_min_severity, rules or pin_exceptions, got a %s", n.Line, yamlKind(n))
	}
	out := DoctorConfig{}
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		if seen[key.Value] {
			return fmt.Errorf("line %d: doctor: key %q already defined in this section", key.Line, key.Value)
		}
		seen[key.Value] = true
		if value.ShortTag() == nullTag {
			continue
		}
		var err error
		switch key.Value {
		case "ci_min_severity":
			err = out.decodeCIMinSeverity(value)
		case "rules":
			out.Rules, err = decodeDoctorRules(value)
		case "pin_exceptions":
			out.PinExceptions, err = decodePinExceptions(value)
		default:
			err = fmt.Errorf("line %d: unknown key %q in the doctor section (want ci_min_severity, rules or pin_exceptions)", key.Line, key.Value)
		}
		if err != nil {
			return err
		}
	}
	*d = out
	return nil
}

// decodeCIMinSeverity reads ci_min_severity, which takes the levels a finding can be
// reported at and not off: a gate that fails on nothing is what leaving the key out
// of the file already gives.
func (d *DoctorConfig) decodeCIMinSeverity(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: ci_min_severity: want block, warn or info, got a %s", n.Line, yamlKind(n))
	}
	level, err := parseLevel(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: ci_min_severity: %w", n.Line, err)
	}
	if level == model.LevelOff {
		return fmt.Errorf("line %d: ci_min_severity must be block, warn or info, got off; to fail on nothing, leave the key out and do not pass --ci", n.Line)
	}
	d.CIMinSeverity = &level
	return nil
}

// decodeDoctorRules reads the rules map, one rule name to one level.
func decodeDoctorRules(n *yaml.Node) (map[string]DoctorRule, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: rules: want a map of rule name to level such as {actions-sha-pin: off}, got a %s", n.Line, yamlKind(n))
	}
	out := make(map[string]DoctorRule, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		name := key.Value
		if _, ok := out[name]; ok {
			return nil, fmt.Errorf("line %d: rules: rule %q already defined", key.Line, name)
		}
		if key.Kind != yaml.ScalarNode || !doctorRuleName.MatchString(name) {
			return nil, fmt.Errorf("line %d: rules: %q is not a rule name (a rule name is lowercase words joined by hyphens, such as npm-min-release-age)", key.Line, name)
		}
		if value.ShortTag() == nullTag {
			continue
		}
		if value.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: rules.%s: want a level such as off, got a %s", value.Line, name, yamlKind(value))
		}
		level, err := parseLevel(value.Value)
		if err != nil {
			return nil, fmt.Errorf("line %d: rules.%s: %w", value.Line, name, err)
		}
		out[name] = DoctorRule{Level: level, Line: key.Line}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// decodePinExceptions reads pin_exceptions, the references allowed to stay on a tag.
func decodePinExceptions(n *yaml.Node) ([]string, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("line %d: pin_exceptions: want a list of globs over owner/repo such as myorg/*, got a %s", n.Line, yamlKind(n))
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		switch {
		case item.ShortTag() == nullTag:
			return nil, fmt.Errorf("line %d: pin_exceptions: an entry with no value; write a glob over owner/repo such as myorg/*, or remove the entry", item.Line)
		case item.Kind != yaml.ScalarNode:
			return nil, fmt.Errorf("line %d: pin_exceptions: want a glob over owner/repo such as myorg/*, got a %s", item.Line, yamlKind(item))
		}
		if err := validatePinException(item.Value); err != nil {
			return nil, fmt.Errorf("line %d: pin_exceptions: %w", item.Line, err)
		}
		out = append(out, item.Value)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// validatePinException checks one entry of pin_exceptions. The entry is matched
// against "owner/repo" as a path glob, so whitespace or a malformed glob would
// quietly match nothing, which is the one outcome nobody writing an exception wants.
func validatePinException(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("empty reference (want a glob over owner/repo, for example myorg/* or myorg/actions)")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("reference %q: whitespace is not allowed", s)
	}
	if _, err := path.Match(s, ""); err != nil {
		return fmt.Errorf("reference %q: malformed glob: %w", s, err)
	}
	return nil
}

// validate checks what a section built in Go rather than read from a file could
// still get wrong. A section read from a file was already checked value by value
// while it was decoded, with the lines these messages cannot carry.
func (d *DoctorConfig) validate() []error {
	var errs []error
	if d.CIMinSeverity != nil {
		switch *d.CIMinSeverity {
		case model.LevelBlock, model.LevelWarn, model.LevelInfo:
		default:
			errs = append(errs, fmt.Errorf("doctor.ci_min_severity must be block, warn or info, got %s", *d.CIMinSeverity))
		}
	}
	names := make([]string, 0, len(d.Rules))
	for name := range d.Rules {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if !doctorRuleName.MatchString(name) {
			errs = append(errs, fmt.Errorf("doctor.rules: %q is not a rule name (a rule name is lowercase words joined by hyphens, such as npm-min-release-age)", name))
		}
	}
	for i, ref := range d.PinExceptions {
		if err := validatePinException(ref); err != nil {
			errs = append(errs, fmt.Errorf("doctor.pin_exceptions[%d]: %w", i, err))
		}
	}
	return errs
}

// DoctorSettings are the resolved doctor settings, after the policy was applied to
// the built-in defaults. It is what a run needs and nothing else: the level of every
// rule the policy spoke about, the level --ci fails at, and the references allowed
// to stay on a tag.
type DoctorSettings struct {
	// CIMinSeverity is the lowest level a missing or wrong setting has to reach for
	// "doctor --ci" to exit 1.
	CIMinSeverity model.Level
	// Levels is the level of each rule the policy named. A rule that is absent from
	// the map keeps the level the rule itself carries, so the map is empty for a
	// policy that disagrees with none of them.
	Levels map[string]model.Level
	// PinExceptions are the workflow references allowed to stay on a tag, as globs
	// over owner/repo. The one published workflow that cannot be pinned at all is
	// known to doctor itself and needs no entry here.
	PinExceptions []string
}

// Level returns the level the policy set for a rule, and whether it set one.
func (s DoctorSettings) Level(rule string) (model.Level, bool) {
	level, ok := s.Levels[rule]
	return level, ok
}

// EffectiveDoctor resolves the doctor settings the way Effective resolves the check
// settings. A nil policy, or a policy whose file left the section out, yields the
// built-in defaults. The result is a copy; changing it does not change the policy.
func (p *Policy) EffectiveDoctor() DoctorSettings {
	s := DoctorSettings{
		CIMinSeverity: DefaultDoctorCIMinSeverity,
		Levels:        map[string]model.Level{},
	}
	if p == nil || p.Doctor == nil {
		return s
	}
	if p.Doctor.CIMinSeverity != nil {
		s.CIMinSeverity = *p.Doctor.CIMinSeverity
	}
	for name, rule := range p.Doctor.Rules {
		s.Levels[name] = rule.Level
	}
	if len(p.Doctor.PinExceptions) > 0 {
		s.PinExceptions = slices.Clone(p.Doctor.PinExceptions)
	}
	return s
}

// ValidateDoctorRules reports every entry of doctor.rules that names a rule the tool
// does not have, with the line it was written on and the names closest to it.
//
// It takes the names rather than reading them itself because internal/doctor imports
// this package, so an import back would be a cycle. The command holds both packages
// and passes doctor.Rules() here, which keeps the message in the voice of the rest
// of the file. A policy loaded without that check keeps every name that has the
// shape of a rule name, and a name that matches no rule then changes nothing.
func (p *Policy) ValidateDoctorRules(known []string) error {
	if p == nil || p.Doctor == nil {
		return nil
	}
	names := make([]string, 0, len(p.Doctor.Rules))
	for name := range p.Doctor.Rules {
		names = append(names, name)
	}
	slices.Sort(names)
	var errs []error
	for _, name := range names {
		if slices.Contains(known, name) {
			continue
		}
		errs = append(errs, fmt.Errorf("line %d: doctor.rules: unknown rule %q (%s)", p.Doctor.Rules[name].Line, name, didYouMean(name, known)))
	}
	return errors.Join(errs...)
}

// maxSuggestions is how many names an unknown name error offers before the list
// stops being a hint and starts being noise.
const maxSuggestions = 3

// didYouMean is the parenthesis of an unknown name error: the known names closest to
// what was written, or the whole list when nothing written is close to any of them.
func didYouMean(name string, known []string) string {
	sorted := slices.Clone(known)
	slices.Sort(sorted)
	best := -1
	var near []string
	for _, candidate := range sorted {
		// A name more than three edits away is a different name, not a typo of this
		// one, and offering it would only send the reader down the wrong path.
		d := nameDistance(name, candidate)
		if d > 3 || (best >= 0 && d > best) {
			continue
		}
		if best < 0 || d < best {
			best, near = d, nil
		}
		near = append(near, candidate)
	}
	switch {
	case len(near) > maxSuggestions:
		near = near[:maxSuggestions]
	case len(near) == 0 && len(sorted) > 0:
		return "want one of " + strings.Join(sorted, ", ")
	case len(near) == 0:
		return "this build knows no doctor rules"
	}
	return "did you mean " + strings.Join(near, " or ") + "?"
}

// nameDistance is the Levenshtein distance between two rule names: how many single
// character insertions, deletions and substitutions turn one into the other. Rule
// names are ASCII, so bytes are counted. The package keeps this small version rather
// than reaching for internal/typosquat, which is about package names fetched from a
// registry and has no business in the loader of a configuration file.
func nameDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
