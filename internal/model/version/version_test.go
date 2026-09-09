package version

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// pep440Ordering is the example list from the PEP's "Summary of permitted
// suffixes and relative ordering" section, ascending (verified 2026-09-09).
var pep440Ordering = []string{
	"1.dev0",
	"1.0.dev456",
	"1.0a1",
	"1.0a2.dev456",
	"1.0a12.dev456",
	"1.0a12",
	"1.0b1.dev456",
	"1.0b2",
	"1.0b2.post345.dev456",
	"1.0b2.post345",
	"1.0rc1.dev456",
	"1.0rc1",
	"1.0",
	"1.0+abc.5",
	"1.0+abc.7",
	"1.0+5",
	"1.0.post456.dev34",
	"1.0.post456",
	"1.0.15",
	"1.1.dev1",
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		eco        model.Ecosystem
		in         string
		canonical  string
		prerelease bool
		wantErr    bool
	}{
		{eco: model.NPM, in: "1.2.3", canonical: "v1.2.3"},
		{eco: model.NPM, in: "v1.2.3", canonical: "v1.2.3"},
		{eco: model.NPM, in: "0.0.1", canonical: "v0.0.1"},
		{eco: model.NPM, in: "10.20.30", canonical: "v10.20.30"},
		{eco: model.NPM, in: "  1.2.3  ", canonical: "v1.2.3"},
		{eco: model.NPM, in: "1.2.3-beta.1", canonical: "v1.2.3-beta.1", prerelease: true},
		{eco: model.NPM, in: "1.2.3-alpha", canonical: "v1.2.3-alpha", prerelease: true},
		{eco: model.NPM, in: "1.2.3-0", canonical: "v1.2.3-0", prerelease: true},
		{eco: model.NPM, in: "1.2.3-x.7.z.92", canonical: "v1.2.3-x.7.z.92", prerelease: true},
		{eco: model.NPM, in: "1.2.3+build.5", canonical: "v1.2.3"},
		{eco: model.NPM, in: "1.2.3-rc.1+build.5", canonical: "v1.2.3-rc.1", prerelease: true},
		{eco: model.Cargo, in: "1.0.210", canonical: "v1.0.210"},
		{eco: model.Cargo, in: "0.1.0-alpha.1", canonical: "v0.1.0-alpha.1", prerelease: true},
		{eco: model.Cargo, in: "1.0.0+20130313144700", canonical: "v1.0.0"},
		{eco: model.JSR, in: "1.0.0", canonical: "v1.0.0"},
		// x/mod/semver accepts the short forms; registries never publish them, so
		// accepting them is harmless.
		{eco: model.NPM, in: "1.0", canonical: "v1.0.0"},
		{eco: model.NPM, in: "1", canonical: "v1.0.0"},

		{eco: model.NPM, in: "", wantErr: true},
		{eco: model.NPM, in: "   ", wantErr: true},
		{eco: model.NPM, in: "abc", wantErr: true},
		{eco: model.NPM, in: "latest", wantErr: true},
		{eco: model.NPM, in: "1.2.3.4", wantErr: true},
		{eco: model.NPM, in: "01.2.3", wantErr: true},
		{eco: model.NPM, in: "1.2.3-", wantErr: true},
		{eco: model.NPM, in: "1.2.3+", wantErr: true},
		{eco: model.NPM, in: "1.2.3-01", wantErr: true},
		{eco: model.NPM, in: "1.2.3-beta..1", wantErr: true},
		{eco: model.NPM, in: "V1.2.3", wantErr: true},
		{eco: model.NPM, in: "vv1.2.3", wantErr: true},
		{eco: model.NPM, in: "=1.2.3", wantErr: true},
		{eco: model.NPM, in: "^1.2.3", wantErr: true},
		{eco: model.NPM, in: "~1.2.3", wantErr: true},
		{eco: model.NPM, in: "1.2.x", wantErr: true},
		{eco: model.Cargo, in: "1.2.3 4", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(string(tt.eco)+" "+tt.in, func(t *testing.T) {
			got, err := Parse(tt.eco, tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error", tt.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Parse(%q) error = %v, want ErrInvalid", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.in, err)
			}
			want := Version{Ecosystem: tt.eco, Raw: strings.TrimSpace(tt.in), Canonical: tt.canonical, Prerelease: tt.prerelease}
			if got != want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.in, got, want)
			}
		})
	}
}

func TestParsePEP440(t *testing.T) {
	tests := []struct {
		in         string
		canonical  string
		prerelease bool
		wantErr    bool
	}{
		// Release segment, epoch, leading v, whitespace, integer normalization.
		{in: "1.0", canonical: "1.0"},
		{in: "1.0.0", canonical: "1.0.0"},
		{in: "1", canonical: "1"},
		{in: "2024.9.9", canonical: "2024.9.9"},
		{in: "1.2.3.4.5.6", canonical: "1.2.3.4.5.6"},
		{in: "01.02.03", canonical: "1.2.3"},
		{in: "1.0.09000", canonical: "1.0.9000"},
		{in: "1!1.0", canonical: "1!1.0"},
		{in: "0!1.0", canonical: "1.0"},
		{in: "00!1", canonical: "1"},
		{in: "v1.0", canonical: "1.0"},
		{in: "V1.0", canonical: "1.0"},
		{in: "  1.0  ", canonical: "1.0"},
		{in: "\t1.0\n", canonical: "1.0"},
		{in: "123456789012345678901234567890.1", canonical: "123456789012345678901234567890.1"},

		// Pre-release segment: separators, spellings, implicit number, case.
		{in: "1.0a1", canonical: "1.0a1", prerelease: true},
		{in: "1.0b2", canonical: "1.0b2", prerelease: true},
		{in: "1.0rc3", canonical: "1.0rc3", prerelease: true},
		{in: "1.0alpha1", canonical: "1.0a1", prerelease: true},
		{in: "1.0beta2", canonical: "1.0b2", prerelease: true},
		{in: "1.0c1", canonical: "1.0rc1", prerelease: true},
		{in: "1.0pre1", canonical: "1.0rc1", prerelease: true},
		{in: "1.0preview1", canonical: "1.0rc1", prerelease: true},
		{in: "1.0.a1", canonical: "1.0a1", prerelease: true},
		{in: "1.0-a1", canonical: "1.0a1", prerelease: true},
		{in: "1.0_a1", canonical: "1.0a1", prerelease: true},
		{in: "1.0a.1", canonical: "1.0a1", prerelease: true},
		{in: "1.0a", canonical: "1.0a0", prerelease: true},
		{in: "1.1RC1", canonical: "1.1rc1", prerelease: true},
		{in: "1.0-ALPHA-01", canonical: "1.0a1", prerelease: true},
		{in: "1.0.0rc1", canonical: "1.0.0rc1", prerelease: true},
		{in: "1.0.0-beta.1+build.5", canonical: "1.0.0b1+build.5", prerelease: true},

		// Post-release segment: separators, spellings, implicit forms.
		{in: "1.0.post1", canonical: "1.0.post1"},
		{in: "1.0post1", canonical: "1.0.post1"},
		{in: "1.0-post1", canonical: "1.0.post1"},
		{in: "1.0_post1", canonical: "1.0.post1"},
		{in: "1.0.post", canonical: "1.0.post0"},
		{in: "1.0.post01", canonical: "1.0.post1"},
		{in: "1.0.rev1", canonical: "1.0.post1"},
		{in: "1.0.r1", canonical: "1.0.post1"},
		{in: "1.0-1", canonical: "1.0.post1"},
		{in: "1.0.POST1", canonical: "1.0.post1"},
		{in: "1.0a1.post2", canonical: "1.0a1.post2", prerelease: true},

		// Dev-release segment.
		{in: "1.0.dev1", canonical: "1.0.dev1", prerelease: true},
		{in: "1.0dev1", canonical: "1.0.dev1", prerelease: true},
		{in: "1.0-dev1", canonical: "1.0.dev1", prerelease: true},
		{in: "1.0.dev", canonical: "1.0.dev0", prerelease: true},
		{in: "1.0.DEV.1", canonical: "1.0.dev1", prerelease: true},
		{in: "1.0.post1.dev2", canonical: "1.0.post1.dev2", prerelease: true},
		{in: "1.0a1.post2.dev3", canonical: "1.0a1.post2.dev3", prerelease: true},
		{in: "1.0-1.dev2", canonical: "1.0.post1.dev2", prerelease: true},

		// Local version segment.
		{in: "1.0+local", canonical: "1.0+local"},
		{in: "1.0+ubuntu-1", canonical: "1.0+ubuntu.1"},
		{in: "1.0+ubuntu_1", canonical: "1.0+ubuntu.1"},
		{in: "1.0+Ubuntu.01", canonical: "1.0+ubuntu.1"},
		{in: "1.0+abc.5", canonical: "1.0+abc.5"},
		{in: "1.0+2024.09.09", canonical: "1.0+2024.9.9"},
		{in: "1.0a1.post2.dev3+local.4", canonical: "1.0a1.post2.dev3+local.4", prerelease: true},
		{in: "1!2.0rc1.post1.dev1+g1234abc", canonical: "1!2.0rc1.post1.dev1+g1234abc", prerelease: true},

		// Invalid forms.
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "v", wantErr: true},
		{in: "vv1.0", wantErr: true},
		{in: "-1.0", wantErr: true},
		{in: "1.0.x", wantErr: true},
		{in: "1..0", wantErr: true},
		{in: ".1", wantErr: true},
		{in: "1.", wantErr: true},
		{in: "1.0-", wantErr: true},
		{in: "1.0+", wantErr: true},
		{in: "1.0+abc+def", wantErr: true},
		{in: "1.0+abc_", wantErr: true},
		{in: "1.0 .0", wantErr: true},
		{in: "1.0 rc1", wantErr: true},
		{in: "1!", wantErr: true},
		{in: "!1", wantErr: true},
		{in: "1.0alpha.beta", wantErr: true},
		{in: "1.0a1b1", wantErr: true},
		{in: "1.0rc1-rc2", wantErr: true},
		{in: "1.0.post1.post2", wantErr: true},
		{in: "1.0-1.0", wantErr: true},
		{in: "1.0.dev1.dev2", wantErr: true},
		{in: "1.0.dev1a1", wantErr: true},
		{in: "1.0.post1a1", wantErr: true},
		{in: "1.0.0-x", wantErr: true},
		{in: "==1.0", wantErr: true},
		{in: "1.0,2.0", wantErr: true},
		{in: "\u0661.\u0660", wantErr: true},    // Arabic-Indic digits are not [0-9]
		{in: "1.0+\u00fcnicode", wantErr: true}, // local labels are ASCII only
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(model.PyPI, tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error", tt.in, got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Parse(%q) error = %v, want ErrInvalid", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.in, err)
			}
			want := Version{Ecosystem: model.PyPI, Raw: strings.TrimSpace(tt.in), Canonical: tt.canonical, Prerelease: tt.prerelease}
			if got != want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.in, got, want)
			}
			// The normal form is a fixed point of normalization.
			again, err := Parse(model.PyPI, got.Canonical)
			if err != nil {
				t.Fatalf("Parse(%q) of the canonical form failed: %v", got.Canonical, err)
			}
			if again.Canonical != got.Canonical || again.Prerelease != got.Prerelease {
				t.Fatalf("Parse(%q) of the canonical form = %+v, want the same canonical and prerelease", got.Canonical, again)
			}
		})
	}
}

func TestComparePEP440(t *testing.T) {
	type pair struct {
		a, b string
		want int
	}
	pairs := []pair{
		// Rules named by the PEP.
		{"1.0", "1.0.0", 0},
		{"1.0", "1", 0},
		{"1.0.0.0", "1", 0},
		{"1.0.post1", "1.0", 1},
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0.dev0", "1.0a1", -1},
		{"1.0", "1.0+local", -1},
		{"1!1.0", "2.0", 1},
		{"0!1.0", "1.0", 0},
		{"1!0.1", "999.9", 1},
		// Local labels: numeric beats lexicographic, prefixes sort lower, case is ignored.
		{"1.0+abc.5", "1.0+abc.7", -1},
		{"1.0+abc.7", "1.0+5", -1},
		{"1.0+abc", "1.0+abc.1", -1},
		{"1.0+ABC", "1.0+abc", 0},
		{"1.0+abc.01", "1.0+abc.1", 0},
		{"1.0+ubuntu-1", "1.0+ubuntu.1", 0},
		{"1.0+a", "1.0+b", -1},
		{"1.0+5", "1.0+10", -1},
		{"1.0rc1", "1.0rc1+local", -1},
		{"1.0+local", "1.0.dev1", 1},
		{"1.0.post1", "1.0+local", 1},
		// Normalization pairs compare equal.
		{"1.0RC1", "1.0rc1", 0},
		{"1.0alpha1", "1.0a1", 0},
		{"1.0c1", "1.0rc1", 0},
		{"1.0-1", "1.0.post1", 0},
		{"v1.0", "1.0", 0},
		{"01.0", "1.0", 0},
		// Suffix combinations and numeric (not lexical) ordering of numbers.
		{"1.0.post1.dev1", "1.0.post1", -1},
		{"1.0.post1.dev1", "1.0", 1},
		{"1.0.dev1", "1.0.post1.dev1", -1},
		{"1.0a1.dev1", "1.0a1", -1},
		{"1.0a1", "1.0a1.post1", -1},
		{"1.0a1.post1", "1.0b1", -1},
		{"1.0a2", "1.0a10", -1},
		{"1.0.post2", "1.0.post10", -1},
		{"1.0.dev2", "1.0.dev10", -1},
		{"1.0.2", "1.0.10", -1},
		{"1.0.0.1", "1.0", 1},
		{"20230101", "20230102", -1},
		{"1.0.99999999999999999999", "1.0.100000000000000000000", -1},
	}
	for i := 0; i+1 < len(pep440Ordering); i++ {
		pairs = append(pairs, pair{pep440Ordering[i], pep440Ordering[i+1], -1})
	}
	for _, tt := range pairs {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			got, err := Compare(model.PyPI, tt.a, tt.b)
			if err != nil {
				t.Fatalf("Compare(%q, %q) unexpected error: %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			back, err := Compare(model.PyPI, tt.b, tt.a)
			if err != nil {
				t.Fatalf("Compare(%q, %q) unexpected error: %v", tt.b, tt.a, err)
			}
			if back != -tt.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, back, -tt.want)
			}
		})
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0+a", "1.0.0+b", 0},
		{"1.0.0-rc.1+build.1", "1.0.0-rc.1+build.2", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.2.3", "1.2.10", -1},
		{"2.0.0", "10.0.0", -1},
		{"0.9.9", "1.0.0", -1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			got, err := Compare(model.NPM, tt.a, tt.b)
			if err != nil {
				t.Fatalf("Compare(%q, %q) unexpected error: %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			back, err := Compare(model.NPM, tt.b, tt.a)
			if err != nil {
				t.Fatalf("Compare(%q, %q) unexpected error: %v", tt.b, tt.a, err)
			}
			if back != -tt.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, back, -tt.want)
			}
		})
	}
}

func TestCompareRejectsUnparsable(t *testing.T) {
	tests := []struct {
		eco  model.Ecosystem
		a, b string
	}{
		{model.NPM, "bad", "1.0.0"},
		{model.NPM, "1.0.0", "bad"},
		{model.PyPI, "1.0.x", "1.0"},
		{model.PyPI, "1.0", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.eco)+" "+tt.a+" vs "+tt.b, func(t *testing.T) {
			if _, err := Compare(tt.eco, tt.a, tt.b); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Compare(%q, %q) error = %v, want ErrInvalid", tt.a, tt.b, err)
			}
		})
	}
}

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		eco  model.Ecosystem
		in   string
		want bool
	}{
		{model.NPM, "1.0.0", false},
		{model.NPM, "1.0.0-rc.1", true},
		{model.NPM, "1.0.0+build", false},
		{model.NPM, "not a version", false},
		{model.PyPI, "1.0", false},
		{model.PyPI, "1.0a1", true},
		{model.PyPI, "1.0.dev1", true},
		{model.PyPI, "1.0.post1", false},
		{model.PyPI, "1.0.post1.dev1", true},
		{model.PyPI, "1.0+local", false},
		{model.PyPI, "1!1.0", false},
		{model.PyPI, "not a version", false},
	}
	for _, tt := range tests {
		t.Run(string(tt.eco)+" "+tt.in, func(t *testing.T) {
			if got := IsPrerelease(tt.eco, tt.in); got != tt.want {
				t.Fatalf("IsPrerelease(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLatestStable(t *testing.T) {
	tests := []struct {
		name string
		eco  model.Ecosystem
		in   []string
		want string
		ok   bool
	}{
		{
			name: "npm skips prereleases and garbage and keeps the raw spelling",
			eco:  model.NPM,
			in:   []string{"1.0.0", "2.0.0-beta.1", "1.5.0", "garbage", "v1.9.9", "1.9.9-rc.1"},
			want: "v1.9.9",
			ok:   true,
		},
		{
			name: "npm build metadata does not win a tie",
			eco:  model.NPM,
			in:   []string{"1.0.0", "1.0.0+b"},
			want: "1.0.0",
			ok:   true,
		},
		{
			name: "npm only prereleases",
			eco:  model.NPM,
			in:   []string{"1.0.0-rc.1", "2.0.0-alpha"},
		},
		{
			name: "npm only garbage",
			eco:  model.NPM,
			in:   []string{"latest", "", "x"},
		},
		{
			name: "empty",
			eco:  model.PyPI,
			in:   nil,
		},
		{
			name: "pypi post release beats the release and pre and dev are skipped",
			eco:  model.PyPI,
			in:   []string{"1.0", "1.1a1", "1.0.post1", "1.1.dev1", "0.9", "bogus", "1.1rc1"},
			want: "1.0.post1",
			ok:   true,
		},
		{
			name: "pypi local version outranks the bare release",
			eco:  model.PyPI,
			in:   []string{"1.0+local", "1.0"},
			want: "1.0+local",
			ok:   true,
		},
		{
			name: "pypi epoch wins",
			eco:  model.PyPI,
			in:   []string{"2024.1", "1!0.1", "2025.1"},
			want: "1!0.1",
			ok:   true,
		},
		{
			name: "pypi equal spellings keep the first",
			eco:  model.PyPI,
			in:   []string{"1.0.0", "1.0", "1"},
			want: "1.0.0",
			ok:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := LatestStable(tt.eco, tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("LatestStable(%v) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSort(t *testing.T) {
	scrambledPEP := scramble(pep440Ordering)
	scrambledPEP = slices.Insert(scrambledPEP, 0, "not a version")
	scrambledPEP = slices.Insert(scrambledPEP, 7, "also bad")
	wantPEP := append([]string{"not a version", "also bad"}, pep440Ordering...)

	tests := []struct {
		name string
		eco  model.Ecosystem
		in   []string
		want []string
	}{
		{
			name: "npm with unparsable entries first in their original order",
			eco:  model.NPM,
			in:   []string{"1.10.0", "bad", "1.2.0", "1.9.0-rc.1", "x", "1.9.0", "v0.1.0"},
			want: []string{"bad", "x", "v0.1.0", "1.2.0", "1.9.0-rc.1", "1.9.0", "1.10.0"},
		},
		{
			name: "npm equal versions keep their order",
			eco:  model.NPM,
			in:   []string{"1.0.0+b", "1.0.0+a", "1.0.0"},
			want: []string{"1.0.0+b", "1.0.0+a", "1.0.0"},
		},
		{
			name: "pypi ordering example from the PEP",
			eco:  model.PyPI,
			in:   scrambledPEP,
			want: wantPEP,
		},
		{
			name: "pypi equal spellings keep their order",
			eco:  model.PyPI,
			in:   []string{"1.0.0", "1.0", "1"},
			want: []string{"1.0.0", "1.0", "1"},
		},
		{
			name: "pypi epochs first",
			eco:  model.PyPI,
			in:   []string{"1!0.1", "2.0", "1.0"},
			want: []string{"1.0", "2.0", "1!0.1"},
		},
		{
			name: "empty",
			eco:  model.PyPI,
			in:   []string{},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Clone(tt.in)
			Sort(tt.eco, got)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Sort(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestCompareProperties checks that Compare is a total preorder over a fixed
// corpus: reflexive, antisymmetric and transitive.
func TestCompareProperties(t *testing.T) {
	corpora := map[model.Ecosystem][]string{
		model.PyPI: append(slices.Clone(pep440Ordering),
			"1.0.0", "1", "1.0+ABC", "1.0-1", "1.0c1", "1.0alpha1", "1!0.5", "0!1.0",
			"1.0.post1.dev1", "1.0a1.post1", "1.0+abc.01", "1.0+10", "2.0", "1.0.0.1",
			"v1.0", "1.0rc1+local", "1.0.post1+local", "0.9", "1.0a0", "1.0.dev0",
		),
		model.NPM: {
			"1.0.0", "1.0.0+a", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
			"1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "v1.0.0",
			"1.2.3", "1.2.10", "2.0.0", "10.0.0", "0.0.1", "1.0.0-0",
		},
	}
	for eco, corpus := range corpora {
		t.Run(string(eco), func(t *testing.T) {
			parsedCorpus := make([]Version, len(corpus))
			for i, s := range corpus {
				v, err := Parse(eco, s)
				if err != nil {
					t.Fatalf("Parse(%q) unexpected error: %v", s, err)
				}
				parsedCorpus[i] = v
			}
			cmp := func(i, j int) int { return sign(parsedCorpus[i].Compare(parsedCorpus[j])) }
			for i := range parsedCorpus {
				if c := cmp(i, i); c != 0 {
					t.Errorf("Compare(%q, %q) = %d, want 0", corpus[i], corpus[i], c)
				}
				for j := range parsedCorpus {
					if cmp(i, j) != -cmp(j, i) {
						t.Errorf("Compare(%q, %q) = %d but Compare(%q, %q) = %d", corpus[i], corpus[j], cmp(i, j), corpus[j], corpus[i], cmp(j, i))
					}
					for k := range parsedCorpus {
						ab, bc, ac := cmp(i, j), cmp(j, k), cmp(i, k)
						if ab > 0 || bc > 0 {
							continue
						}
						if ac > 0 || ((ab < 0 || bc < 0) && ac >= 0) {
							t.Errorf("not transitive: %q <= %q <= %q but Compare(%q, %q) = %d", corpus[i], corpus[j], corpus[k], corpus[i], corpus[k], ac)
						}
					}
				}
			}
		})
	}
}

func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	default:
		return 0
	}
}

// scramble returns a deterministic reordering of s that is far from sorted:
// elements are taken alternately from the end and the start.
func scramble(s []string) []string {
	out := make([]string, 0, len(s))
	for lo, hi := 0, len(s)-1; lo <= hi; lo, hi = lo+1, hi-1 {
		out = append(out, s[hi])
		if lo != hi {
			out = append(out, s[lo])
		}
	}
	return out
}
