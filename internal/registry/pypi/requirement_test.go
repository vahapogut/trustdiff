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

func TestDependencies(t *testing.T) {
	tests := []struct {
		name     string
		requires []string
		want     map[string]string
		wantLog  string
	}{
		{name: "nil", requires: nil, want: nil},
		{name: "empty", requires: []string{}, want: nil},
		{
			name:     "fixture shape",
			requires: []string{"peppercorn", `check-manifest; extra == "dev"`, `coverage; extra == "test"`},
			want:     map[string]string{"peppercorn": "", "check-manifest": `; extra == "dev"`, "coverage": `; extra == "test"`},
		},
		{
			name:     "same project under two markers",
			requires: []string{`foo>=1; python_version < "3.8"`, `foo>=2; python_version >= "3.8"`},
			want:     map[string]string{"foo": `>=1; python_version < "3.8" || >=2; python_version >= "3.8"`},
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
			got := dependencies(tc.requires, logger)
			if (got == nil) != (tc.want == nil) || !equalMaps(got, tc.want) {
				t.Errorf("dependencies = %#v, want %#v", got, tc.want)
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
