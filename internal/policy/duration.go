package policy

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	unitSecond = time.Second
	unitMinute = time.Minute
	unitHour   = time.Hour
	unitDay    = 24 * time.Hour
	unitWeek   = 7 * unitDay
)

// Duration is a time.Duration that reads and writes the spellings a policy file
// accepts, see ParseDuration. Convert with time.Duration(d) for arithmetic.
type Duration time.Duration

// String renders the duration the way FormatDuration does.
func (d Duration) String() string { return FormatDuration(time.Duration(d)) }

// UnmarshalYAML accepts a scalar in any spelling ParseDuration accepts, except zero:
// in a policy a duration is always a cooldown, and a zero cooldown would be
// indistinguishable from an absent one, which means the default.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a duration such as 3d, 12h or P3D, got a %s", n.Line, yamlKind(n))
	}
	parsed, err := ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	if parsed == 0 {
		return fmt.Errorf("line %d: duration %q must be positive; to disable the cooldown check set young-version: off", n.Line, n.Value)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML writes the duration in the shortest policy spelling.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// ParseDuration parses the three spellings a policy accepts: Go durations with
// hours, minutes and seconds (12h, 90m, 1h30m), the same form extended with day and
// week units (3d, 1w, 1w3d, 3d12h), and ISO 8601 durations (P3D, PT12H, P1W,
// P1DT12H). Units in the plain form are lowercase and each may appear once; ISO
// designators are uppercase. Fractions are allowed (1.5h, PT0.5H).
//
// Rejected: empty input, negative values, a number without a unit (3 could be days
// or hours), sub-second units, ISO months and years (they have no fixed length), and
// anything mixing the forms.
func ParseDuration(s string) (time.Duration, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		return 0, errors.New("empty duration (want a value such as 12h, 3d, 1w or P3D)")
	}
	if strings.HasPrefix(text, "-") {
		return 0, fmt.Errorf("duration %q is negative", text)
	}
	var (
		d   time.Duration
		err error
	)
	if strings.HasPrefix(text, "P") {
		d, err = parseISODuration(text[1:])
	} else {
		d, err = parsePlainDuration(text)
	}
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", text, err)
	}
	return d, nil
}

var plainUnits = map[string]time.Duration{
	"w": unitWeek,
	"d": unitDay,
	"h": unitHour,
	"m": unitMinute,
	"s": unitSecond,
}

// parsePlainDuration handles 12h, 90m, 3d, 1w and combinations such as 1w3d12h.
func parsePlainDuration(text string) (time.Duration, error) {
	var total float64
	seen := map[string]bool{}
	for i := 0; i < len(text); {
		start := i
		for i < len(text) && (isDigit(text[i]) || text[i] == '.') {
			i++
		}
		value, err := parseNumber(text[start:i])
		if err != nil {
			return 0, fmt.Errorf("want a number before %q: %w", text[start:], err)
		}
		start = i
		for i < len(text) && isLetter(text[i]) {
			i++
		}
		unitText := text[start:i]
		if unitText == "" {
			return 0, fmt.Errorf("missing unit after %q (want w, d, h, m or s)", text[:i])
		}
		unit, ok := plainUnits[unitText]
		if !ok {
			return 0, fmt.Errorf("unknown unit %q (want w for weeks, d for days, h, m or s)", unitText)
		}
		if seen[unitText] {
			return 0, fmt.Errorf("repeated unit %q", unitText)
		}
		seen[unitText] = true
		total += value * float64(unit)
		if total > math.MaxInt64 {
			return 0, errors.New("too large")
		}
	}
	return time.Duration(math.Round(total)), nil
}

// parseISODuration handles the part after the leading P: nW, or nD optionally
// followed by T and nH, nM, nS in that order.
func parseISODuration(rest string) (time.Duration, error) {
	const want = "not a valid ISO 8601 duration (want P3D, PT12H, P1W or P1DT12H)"
	if rest == "" {
		return 0, errors.New(want)
	}
	if strings.HasSuffix(rest, "W") {
		value, err := parseNumber(strings.TrimSuffix(rest, "W"))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", want, err)
		}
		return isoTotal(value * float64(unitWeek))
	}
	datePart, timePart, hasT := strings.Cut(rest, "T")
	if hasT && timePart == "" {
		return 0, fmt.Errorf("%s: nothing follows T", want)
	}
	var total float64
	if datePart != "" {
		components, err := isoComponents(datePart)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", want, err)
		}
		for _, c := range components {
			switch c.designator {
			case 'D':
				total += c.value * float64(unitDay)
			case 'M':
				return 0, errors.New("months have no fixed length in an ISO 8601 duration; use days or weeks")
			case 'Y':
				return 0, errors.New("years have no fixed length in an ISO 8601 duration; use days or weeks")
			default:
				return 0, fmt.Errorf("%s: %q is not allowed before T", want, string(c.designator))
			}
		}
		if len(components) > 1 {
			return 0, fmt.Errorf("%s: repeated D", want)
		}
	}
	if hasT {
		components, err := isoComponents(timePart)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", want, err)
		}
		order := map[byte]int{'H': 1, 'M': 2, 'S': 3}
		units := map[byte]time.Duration{'H': unitHour, 'M': unitMinute, 'S': unitSecond}
		last := 0
		for _, c := range components {
			rank, ok := order[c.designator]
			if !ok {
				return 0, fmt.Errorf("%s: %q is not allowed after T", want, string(c.designator))
			}
			if rank <= last {
				return 0, fmt.Errorf("%s: %q is out of order or repeated", want, string(c.designator))
			}
			last = rank
			total += c.value * float64(units[c.designator])
		}
	}
	return isoTotal(total)
}

type isoComponent struct {
	value      float64
	designator byte
}

// isoComponents splits "1D" or "1H30M" into number and designator pairs.
func isoComponents(text string) ([]isoComponent, error) {
	var out []isoComponent
	for i := 0; i < len(text); {
		start := i
		for i < len(text) && (isDigit(text[i]) || text[i] == '.') {
			i++
		}
		value, err := parseNumber(text[start:i])
		if err != nil {
			return nil, err
		}
		if i == len(text) {
			return nil, fmt.Errorf("missing designator after %q", text[start:i])
		}
		if !isLetter(text[i]) {
			return nil, fmt.Errorf("unexpected %q", string(text[i]))
		}
		out = append(out, isoComponent{value: value, designator: text[i]})
		i++
	}
	return out, nil
}

func isoTotal(total float64) (time.Duration, error) {
	if total > math.MaxInt64 {
		return 0, errors.New("too large")
	}
	return time.Duration(math.Round(total)), nil
}

// parseNumber accepts digits with an optional fraction: 3, 12, 1.5. It is stricter
// than strconv.ParseFloat, which would also take "1." or "1e3".
func parseNumber(s string) (float64, error) {
	if s == "" || !isDigit(s[0]) || !isDigit(s[len(s)-1]) || strings.Count(s, ".") > 1 {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	value, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	return value, nil
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// FormatDuration renders a duration for the human report in the spelling
// ParseDuration accepts: whole weeks as 1w, otherwise days, hours, minutes and
// seconds joined without separators (3d, 3d12h, 1h30m). A duration that is not a
// whole number of seconds, or a negative one, falls back to time.Duration.String.
func FormatDuration(d time.Duration) string {
	if d < 0 || d%time.Second != 0 {
		return d.String()
	}
	if d == 0 {
		return "0s"
	}
	if d%unitWeek == 0 {
		return fmt.Sprintf("%dw", d/unitWeek)
	}
	parts := []struct {
		unit   time.Duration
		suffix string
	}{
		{unitDay, "d"},
		{unitHour, "h"},
		{unitMinute, "m"},
		{unitSecond, "s"},
	}
	var b strings.Builder
	for _, p := range parts {
		if n := d / p.unit; n > 0 {
			fmt.Fprintf(&b, "%d%s", n, p.suffix)
			d -= n * p.unit
		}
	}
	return b.String()
}

// yamlKind names a node kind for error messages.
func yamlKind(n *yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		return "scalar"
	case yaml.SequenceNode:
		return "list"
	case yaml.MappingNode:
		return "map"
	case yaml.AliasNode:
		return "alias"
	case yaml.DocumentNode:
		return "document"
	}
	return "unknown node"
}
