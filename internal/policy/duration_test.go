package policy

import (
	"strings"
	"testing"
	"time"
)

const day = 24 * time.Hour

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		// Go spellings.
		{in: "12h", want: 12 * time.Hour},
		{in: "90m", want: 90 * time.Minute},
		{in: "1h30m", want: 90 * time.Minute},
		{in: "45s", want: 45 * time.Second},
		{in: "1.5h", want: 90 * time.Minute},
		{in: "0s", want: 0},
		// Day and week suffixes.
		{in: "3d", want: 3 * day},
		{in: "1w", want: 7 * day},
		{in: "1w3d", want: 10 * day},
		{in: "3d12h", want: 84 * time.Hour},
		{in: "0.5d", want: 12 * time.Hour},
		{in: " 3d ", want: 3 * day},
		// ISO 8601.
		{in: "P3D", want: 3 * day},
		{in: "PT12H", want: 12 * time.Hour},
		{in: "P1W", want: 7 * day},
		{in: "P1DT12H", want: 36 * time.Hour},
		{in: "PT90M", want: 90 * time.Minute},
		{in: "PT1H30M", want: 90 * time.Minute},
		{in: "PT0.5H", want: 30 * time.Minute},
		{in: "PT30S", want: 30 * time.Second},
		{in: "P0D", want: 0},
		{in: "P2DT3H4M5S", want: 2*day + 3*time.Hour + 4*time.Minute + 5*time.Second},
		{in: "PT1H5S", want: time.Hour + 5*time.Second},
		// Just below the int64 limit.
		{in: "2562047h", want: 2562047 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDuration(tt.in)
			if err != nil {
				t.Fatalf("ParseDuration(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseDuration(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDurationRejects(t *testing.T) {
	tests := []struct {
		in      string
		wantErr string
	}{
		{in: "", wantErr: "empty"},
		{in: "   ", wantErr: "empty"},
		{in: "-3d", wantErr: "negative"},
		{in: "+3d", wantErr: "number"},
		{in: "3", wantErr: "missing unit"},
		{in: "0", wantErr: "missing unit"},
		{in: "3 d", wantErr: "unit"},
		{in: "3D", wantErr: "unit"},
		{in: "p3d", wantErr: "number"},
		{in: "d", wantErr: "number"},
		{in: "1x", wantErr: `unit "x"`},
		{in: "1ms", wantErr: `unit "ms"`},
		{in: "1.h", wantErr: "number"},
		{in: "1e3h", wantErr: "unit"},
		{in: "1w1w", wantErr: "repeated"},
		{in: "3d3d", wantErr: "repeated"},
		{in: "3d-1h", wantErr: "number"},
		{in: "P", wantErr: "ISO 8601"},
		{in: "PT", wantErr: "ISO 8601"},
		{in: "P1M", wantErr: "month"},
		{in: "P1Y", wantErr: "year"},
		{in: "P3D12h", wantErr: "ISO 8601"},
		{in: "P1WT1H", wantErr: "ISO 8601"},
		{in: "PT1S1H", wantErr: "ISO 8601"},
		{in: "P1DT", wantErr: "ISO 8601"},
		{in: "P1.5.5D", wantErr: "ISO 8601"},
		{in: "-P3D", wantErr: "negative"},
		{in: "999999999999w", wantErr: "too large"},
		{in: "P999999999999W", wantErr: "too large"},
		// These round to exactly 2^63, which float64(math.MaxInt64) is as well, so a
		// guard written with > lets them through and the conversion wraps negative.
		{in: "9223372036.854776s", wantErr: "too large"},
		{in: "PT9223372036.854776S", wantErr: "too large"},
		{in: "153722867.280912936m", wantErr: "too large"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDuration(tt.in)
			if err == nil {
				t.Fatalf("ParseDuration(%q) = %v, want an error containing %q", tt.in, got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseDuration(%q) error = %q, want it to contain %q", tt.in, err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), strings.TrimSpace(tt.in)) && strings.TrimSpace(tt.in) != "" {
				t.Fatalf("ParseDuration(%q) error = %q, want it to quote the input", tt.in, err)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 0, want: "0s"},
		{in: 45 * time.Second, want: "45s"},
		{in: 90 * time.Second, want: "1m30s"},
		{in: 90 * time.Minute, want: "1h30m"},
		{in: 12 * time.Hour, want: "12h"},
		{in: 36 * time.Hour, want: "1d12h"},
		{in: 3 * day, want: "3d"},
		{in: 84 * time.Hour, want: "3d12h"},
		{in: 7 * day, want: "1w"},
		{in: 10 * day, want: "10d"},
		{in: 14 * day, want: "2w"},
		{in: 2*day + 3*time.Hour + 4*time.Minute + 5*time.Second, want: "2d3h4m5s"},
		{in: 1500 * time.Millisecond, want: "1.5s"},
		{in: -time.Hour, want: "-1h0m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := FormatDuration(tt.in); got != tt.want {
				t.Fatalf("FormatDuration(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// Whatever the spelling, formatting and parsing again must give the same duration.
func TestDurationRoundTrip(t *testing.T) {
	for _, in := range []string{"12h", "90m", "3d", "1w", "1w3d", "3d12h", "P3D", "PT12H", "P1W", "P1DT12H", "PT1H30M", "45s"} {
		want, err := ParseDuration(in)
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", in, err)
		}
		text := FormatDuration(want)
		got, err := ParseDuration(text)
		if err != nil {
			t.Fatalf("ParseDuration(FormatDuration(%q) = %q): %v", in, text, err)
		}
		if got != want {
			t.Fatalf("round trip of %q through %q = %v, want %v", in, text, got, want)
		}
	}
}

func TestDurationYAML(t *testing.T) {
	var d Duration
	if err := d.UnmarshalYAML(scalarNode("3d")); err != nil {
		t.Fatalf("UnmarshalYAML(3d): %v", err)
	}
	if time.Duration(d) != 3*day {
		t.Fatalf("UnmarshalYAML(3d) = %v", time.Duration(d))
	}
	if d.String() != "3d" {
		t.Fatalf("String() = %q, want 3d", d.String())
	}
	out, err := d.MarshalYAML()
	if err != nil || out != "3d" {
		t.Fatalf("MarshalYAML() = %v, %v", out, err)
	}
	err = d.UnmarshalYAML(scalarNode("-3d"))
	if err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("UnmarshalYAML(-3d) error = %v, want a negative duration error", err)
	}
	err = d.UnmarshalYAML(scalarNode("0s"))
	if err == nil || !strings.Contains(err.Error(), "must be positive") || !strings.Contains(err.Error(), "young-version: off") {
		t.Fatalf("UnmarshalYAML(0s) error = %v, want a positive duration error that names the alternative", err)
	}
	err = d.UnmarshalYAML(sequenceNode("3d"))
	if err == nil || !strings.Contains(err.Error(), "want a duration") {
		t.Fatalf("UnmarshalYAML(sequence) error = %v, want a kind error", err)
	}
}
