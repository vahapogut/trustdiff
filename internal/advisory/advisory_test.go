package advisory

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestSeverityFromScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		score float64
		want  Severity
	}{
		{-1, SeverityUnknown},
		{0, SeverityNone},
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10, SeverityCritical},
	}
	for _, tt := range tests {
		if got := SeverityFromScore(tt.score); got != tt.want {
			t.Errorf("SeverityFromScore(%v) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"none", SeverityNone, false},
		{"NONE", SeverityNone, false},
		{"low", SeverityLow, false},
		{"MODERATE", SeverityMedium, false},
		{"medium", SeverityMedium, false},
		{" high ", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"", SeverityUnknown, false},
		{"unknown", SeverityUnknown, false},
		{"extreme", SeverityUnknown, true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseSeverity(%q) = %s, %v; want %s, error %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

// TestSeverityOrderAndEffective pins the order a threshold relies on and the
// rule that only an unknown severity counts as medium.
func TestSeverityOrderAndEffective(t *testing.T) {
	t.Parallel()
	order := []Severity{SeverityUnknown, SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Errorf("%s does not sort below %s", order[i-1], order[i])
		}
	}
	for _, s := range order {
		want := s
		if s == SeverityUnknown {
			want = SeverityMedium
		}
		if got := s.Effective(); got != want {
			t.Errorf("%s.Effective() = %s, want %s", s, got, want)
		}
	}
	if SeverityNone.Effective() >= SeverityLow {
		t.Error("a None rating reaches a threshold of low")
	}
	for _, s := range order {
		if parsed, err := ParseSeverity(s.String()); err != nil || parsed != s {
			t.Errorf("ParseSeverity(%q) = %s, %v; want the same severity", s.String(), parsed, err)
		}
	}
	if got := Severity(42).String(); got != "severity(42)" {
		t.Errorf("String of an unknown value = %q", got)
	}
}

func TestPartialError(t *testing.T) {
	t.Parallel()
	cause := errors.New("boom")
	refs := map[model.PackageRef]error{}
	for i := range 7 {
		refs[model.PackageRef{Ecosystem: model.NPM, Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"}] = cause
	}
	err := error(&PartialError{Source: "osv", Refs: refs, Cause: cause})
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(%v, cause) is false", err)
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "osv: no answer for 7 of the refs (") || !strings.Contains(msg, "npm:pkg-0@1.0.0, ") || !strings.HasSuffix(msg, " and 2 more): boom") {
		t.Errorf("message = %q, want the count, the first five refs in order and the cause", msg)
	}
	short := &PartialError{Source: "osv", Refs: map[model.PackageRef]error{model.MustParseRef("npm:a@1.0.0"): cause}, Cause: cause}
	if got := short.Error(); got != "osv: no answer for 1 of the refs (npm:a@1.0.0): boom" {
		t.Errorf("message = %q", got)
	}
}
