package policy

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Date is a calendar day such as 2027-03-01, used for allow-list expiry. It carries no
// time zone: an entry is valid for the whole day in UTC.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

const dateLayout = "2006-01-02"

// ParseDate accepts exactly YYYY-MM-DD.
func ParseDate(s string) (Date, error) {
	t, err := time.Parse(dateLayout, s)
	if err != nil || len(s) != len(dateLayout) {
		return Date{}, fmt.Errorf("want a date such as 2027-03-01, got %q", s)
	}
	return Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}, nil
}

// IsZero reports whether the date was never set.
func (d Date) IsZero() bool { return d == Date{} }

// Time returns midnight UTC of the day.
func (d Date) Time() time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
}

// String renders YYYY-MM-DD, or an empty string for the zero date.
func (d Date) String() string {
	if d.IsZero() {
		return ""
	}
	return d.Time().Format(dateLayout)
}

// UnmarshalYAML accepts a scalar in the form ParseDate accepts. YAML parses an
// unquoted 2027-03-01 as a timestamp, so the raw scalar text is used, not the
// decoded value.
func (d *Date) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a date such as 2027-03-01, got a %s", n.Line, yamlKind(n))
	}
	parsed, err := ParseDate(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = parsed
	return nil
}

// MarshalYAML writes YYYY-MM-DD.
func (d Date) MarshalYAML() (any, error) { return d.String(), nil }
