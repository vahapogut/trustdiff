package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Regenerate the golden files with: go test ./internal/report/ -update
var update = flag.Bool("update", false, "rewrite the golden files under testdata/")

// fixtureSubjects is the input every golden test renders: a subject with a block and a
// warn finding that came from a lockfile line, a subject where nothing could be
// evaluated, and a clean subject. The values are invented; no real package is described.
func fixtureSubjects() []Subject {
	lib := model.MustParseRef("npm:example-lib@4.19.3")
	loc := &model.Location{Path: "package-lock.json", Line: 42}
	return []Subject{
		{
			Ref:       lib,
			Location:  loc,
			Direct:    true,
			Evaluated: []string{"TD006", "TD001", "TD009", "TD002"},
			Findings: []model.Finding{
				{
					ID:          "TD001",
					Name:        "young-version",
					Level:       model.LevelWarn,
					Ref:         lib,
					Title:       "Version is 6 hours old",
					Explanation: "4.19.3 was published on 2026-09-08T18:00:00Z, 6 hours before this run; the cooldown is 3d",
					Evidence:    map[string]any{"published_at": "2026-09-08T18:00:00Z", "age": "6h", "cooldown": "3d"},
					Location:    loc,
				},
				{
					ID:          "TD002",
					Name:        "publisher-changed",
					Level:       model.LevelBlock,
					Ref:         lib,
					Title:       "Publisher of 4.19.3 is not among the previous publishers",
					Explanation: "previous 5 versions were published by alice; 4.19.3 was published by bob-ci, an account that has published nothing else",
					Evidence:    map[string]any{"previous_publishers": []string{"alice"}, "publisher": "bob-ci", "window": 5},
					Location:    loc,
				},
			},
		},
		{
			Ref:     model.MustParseRef("pypi:example-tool@2.0.0"),
			Skipped: []model.Skipped{{Check: "TD001", Reason: "pypi.org unavailable in offline mode and no cached response"}},
		},
		{
			Ref:       model.MustParseRef("cargo:example-crate@1.0.0"),
			Evaluated: []string{"TD001", "TD006", "TD009"},
		},
	}
}

func fixtureReport() *Report {
	return Build(fixtureSubjects(), testTool(), testPolicy(), model.LevelBlock)
}

// normalizeNewlines maps CRLF to LF so goldens written on Windows and Linux compare equal.
func normalizeNewlines(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

func TestGolden(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		writer Writer
	}{
		{name: "json", golden: "report.json.golden", writer: JSON{}},
		{name: "human", golden: "report.human.golden", writer: Human{Color: false, Width: 80}},
		{name: "human-color", golden: "report.human-color.golden", writer: Human{Color: true, Width: 80}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.writer.Write(&buf, fixtureReport()); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got := normalizeNewlines(buf.Bytes())
			path := filepath.Join("testdata", tt.golden)
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}
			want = normalizeNewlines(want)
			if !bytes.Equal(got, want) {
				t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
			}
		})
	}
}
