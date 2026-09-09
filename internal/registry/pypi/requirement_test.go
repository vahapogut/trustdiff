package pypi

import (
	"log/slog"
	"strings"
	"testing"
)

func TestSplitRequirement(t *testing.T) {
	tests := []struct {
		raw      string
		wantName string
		wantRest string
		wantOK   bool
	}{
		// Shapes seen in the recorded fixtures.
		{"peppercorn", "peppercorn", "", true},
		{`check-manifest; extra == "dev"`, "check-manifest", `; extra == "dev"`, true},
		{"coverage ; extra == 'test'", "coverage", "; extra == 'test'", true},
		{"charset_normalizer<4,>=2", "charset-normalizer", "<4,>=2", true},
		{"charset-normalizer<4,>=2", "charset-normalizer", "<4,>=2", true},
		{`PySocks!=1.5.7,>=1.5.6; extra == "socks"`, "pysocks", `!=1.5.7,>=1.5.6; extra == "socks"`, true},
		{"certifi>=2017.4.17", "certifi", ">=2017.4.17", true},
		// Other PEP 508 forms.
		{"requests[security] >=2.8.1", "requests", "[security] >=2.8.1", true},
		{"Zope.Interface (>=4.0)", "zope-interface", "(>=4.0)", true},
		{"pip @ https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4bbb3c72346a6de940a148ea686", "pip", "@ https://github.com/pypa/pip/archive/1.3.1.zip#sha1=da9234ee9982d4bbb3c72346a6de940a148ea686", true},
		{`importlib-metadata>=1.0; python_version < "3.8"`, "importlib-metadata", `>=1.0; python_version < "3.8"`, true},
		{"  numpy>=1.20  ", "numpy", ">=1.20", true},
		{"A", "a", "", true},
		// Not requirements.
		{"", "", "", false},
		{"   ", "", "", false},
		{">=1.0", "", "", false},
		{"-not-a-name", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			name, rest, ok := splitRequirement(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if name != tc.wantName || rest != tc.wantRest {
				t.Errorf("split = (%q, %q), want (%q, %q)", name, rest, tc.wantName, tc.wantRest)
			}
		})
	}
}

func TestSplitMarker(t *testing.T) {
	tests := []struct {
		rest       string
		wantSpec   string
		wantMarker string
	}{
		{"", "", ""},
		{"<4,>=2", "<4,>=2", ""},
		{`; extra == "dev"`, "", `extra == "dev"`},
		{"<5,>=4; extra == 'h2'", "<5,>=4", "extra == 'h2'"},
		{`>=1.0; python_version < "3.8"`, ">=1.0", `python_version < "3.8"`},
		{"(>=0.6) ; extra == 'standard'", "(>=0.6)", "extra == 'standard'"},
		{"@ https://example.com/a.zip#sha1=abc;x=1", "@ https://example.com/a.zip#sha1=abc;x=1", ""},
		{"@ https://example.com/a.zip#sha1=abc;x=1 ; extra == 'x'", "@ https://example.com/a.zip#sha1=abc;x=1", "extra == 'x'"},
		{"[security] >=2.8.1", "[security] >=2.8.1", ""},
	}
	for _, tc := range tests {
		t.Run(tc.rest, func(t *testing.T) {
			spec, marker := splitMarker(tc.rest)
			if spec != tc.wantSpec || marker != tc.wantMarker {
				t.Errorf("splitMarker = (%q, %q), want (%q, %q)", spec, marker, tc.wantSpec, tc.wantMarker)
			}
		})
	}
}

func TestIsExtra(t *testing.T) {
	tests := []struct {
		marker string
		want   bool
	}{
		{"", false},
		{`extra == "dev"`, true},
		{"extra=='h2'", true},
		{"'socks' == extra", true},
		{`python_version < "3.8"`, false},
		{`python_version < "3.8" and extra == "dev"`, true},
		{`sys_platform == "win32"`, false},
		// A marker variable that merely contains the word is not the extra marker.
		{`myextra == "x"`, false},
		{`extra_thing == "x"`, false},
	}
	for _, tc := range tests {
		if got := isExtra(tc.marker); got != tc.want {
			t.Errorf("isExtra(%q) = %v, want %v", tc.marker, got, tc.want)
		}
	}
}

func TestDependencies(t *testing.T) {
	tests := []struct {
		name         string
		requires     []string
		want         map[string]string
		wantOptional map[string]string
		wantLog      string
	}{
		{name: "nil", requires: nil, want: nil},
		{name: "empty", requires: []string{}, want: nil},
		{
			// sampleproject 4.0.0: the two extras are not runtime dependencies.
			name:         "fixture shape",
			requires:     []string{"peppercorn", `check-manifest; extra == "dev"`, `coverage; extra == "test"`},
			want:         map[string]string{"peppercorn": ""},
			wantOptional: map[string]string{"check-manifest": `; extra == "dev"`, "coverage": `; extra == "test"`},
		},
		{
			// urllib3 2.2.0 added h2 under an extra (verified live 2026-09-09);
			// a python_version marker keeps a requirement at runtime.
			name:         "extra marker versus python_version marker",
			requires:     []string{"h2<5,>=4; extra == 'h2'", `importlib-metadata>=1.0; python_version < "3.8"`},
			want:         map[string]string{"importlib-metadata": `>=1.0; python_version < "3.8"`},
			wantOptional: map[string]string{"h2": "<5,>=4; extra == 'h2'"},
		},
		{
			name:         "only extras",
			requires:     []string{"watchfiles (>=0.13) ; extra == 'standard'", "'socks' == extra"},
			want:         nil,
			wantOptional: map[string]string{"watchfiles": "(>=0.13) ; extra == 'standard'"},
			wantLog:      "requirement without a project name dropped",
		},
		{
			name:     "same project under two markers",
			requires: []string{`foo>=1; python_version < "3.8"`, `foo>=2; python_version >= "3.8"`},
			want:     map[string]string{"foo": `>=1; python_version < "3.8" || >=2; python_version >= "3.8"`},
		},
		{
			name:         "same project at runtime and under an extra",
			requires:     []string{"foo>=1", `foo[fast]>=2; extra == "fast"`},
			want:         map[string]string{"foo": ">=1"},
			wantOptional: map[string]string{"foo": `[fast]>=2; extra == "fast"`},
		},
		{
			name:     "spelling variants collapse",
			requires: []string{"Charset_Normalizer<4", "charset-normalizer>=2"},
			want:     map[string]string{"charset-normalizer": "<4 || >=2"},
		},
		{
			name:     "malformed line dropped and logged",
			requires: []string{">=1.0", "idna<4,>=2.5"},
			want:     map[string]string{"idna": "<4,>=2.5"},
			wantLog:  "requirement without a project name dropped",
		},
		{
			name:     "only malformed lines",
			requires: []string{">=1.0"},
			want:     nil,
			wantLog:  "requirement without a project name dropped",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			got, optional := dependencies(tc.requires, logger)
			if (got == nil) != (tc.want == nil) || !equalMaps(got, tc.want) {
				t.Errorf("dependencies = %#v, want %#v", got, tc.want)
			}
			if (optional == nil) != (tc.wantOptional == nil) || !equalMaps(optional, tc.wantOptional) {
				t.Errorf("optional dependencies = %#v, want %#v", optional, tc.wantOptional)
			}
			if tc.wantLog != "" && !strings.Contains(buf.String(), tc.wantLog) {
				t.Errorf("log = %q, want %q", buf.String(), tc.wantLog)
			}
			if tc.wantLog == "" && buf.Len() != 0 {
				t.Errorf("unexpected log output: %q", buf.String())
			}
		})
	}
}
