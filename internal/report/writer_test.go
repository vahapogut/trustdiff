package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestNew(t *testing.T) {
	opts := Options{Color: true, Width: 120}
	tests := []struct {
		format  string
		want    Writer
		wantErr bool
	}{
		{format: "human", want: Human{Color: true, Width: 120}},
		{format: "json", want: JSON{}},
		{format: "sarif", want: SARIF{}},
		{format: "markdown", want: Markdown{}},
		{format: "yaml", wantErr: true},
		{format: "SARIF", wantErr: true},
		{format: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got, err := New(tt.format, opts)
			if tt.wantErr {
				if !errors.Is(err, ErrUnsupportedFormat) {
					t.Fatalf("New(%q) error = %v, want ErrUnsupportedFormat", tt.format, err)
				}
				if !strings.Contains(err.Error(), tt.format) && tt.format != "" {
					t.Fatalf("New(%q) error %q does not name the format", tt.format, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) unexpected error: %v", tt.format, err)
			}
			if got != tt.want {
				t.Fatalf("New(%q) = %#v, want %#v", tt.format, got, tt.want)
			}
		})
	}
}

func TestJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSON{}).Write(&buf, fixtureReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()

	if !json.Valid(buf.Bytes()) {
		t.Fatal("output is not valid JSON")
	}
	if !strings.HasPrefix(out, "{\n  \"schema\": \"trustdiff.report/1\",\n  \"tool\": {\n    \"name\": \"trustdiff\",\n") {
		t.Errorf("output does not start with the schema and tool keys, two-space indented:\n%s", out)
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Error("output must end with a closing brace and one newline")
	}
	for _, key := range []string{`"policy": {`, `"subjects": [`, `"summary": {`} {
		if !strings.Contains(out, key) {
			t.Errorf("output lacks %s", key)
		}
	}
	if !strings.Contains(out, `"skipped": []`) || !strings.Contains(out, `"findings": []`) || !strings.Contains(out, `"evaluated": []`) {
		t.Errorf("empty lists must render as [] not null:\n%s", out)
	}
	if strings.Contains(out, "null") {
		t.Errorf("output must not contain null:\n%s", out)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	summary, _ := decoded["summary"].(map[string]any)
	if summary["exit_code"] != float64(1) || summary["exit_meaning"] != "blocking findings" {
		t.Errorf("summary = %v", summary)
	}
}

func TestJSONEmptyReportAndNoHTMLEscaping(t *testing.T) {
	subject := Subject{
		Ref:       model.MustParseRef("npm:example-lib@1.0.0"),
		Evaluated: []string{"TD007"},
		Findings: []model.Finding{{
			ID: "TD007", Name: "new-dependency-introduced", Level: model.LevelWarn,
			Ref: model.MustParseRef("npm:example-lib@1.0.0"), Title: "t",
			Explanation: "dependency set changed: <none> -> plain-crypto-js & friends",
		}},
	}
	var buf bytes.Buffer
	if err := (JSON{}).Write(&buf, Build([]Subject{subject}, testTool(), testPolicy(), model.LevelBlock)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), `"explanation": "dependency set changed: <none> -> plain-crypto-js & friends"`) {
		t.Errorf("angle brackets and ampersands must not be escaped:\n%s", buf.String())
	}

	buf.Reset()
	if err := (JSON{}).Write(&buf, Build(nil, testTool(), testPolicy(), model.LevelBlock)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), `"subjects": []`) {
		t.Errorf("empty report must render subjects as []:\n%s", buf.String())
	}
}

// assertGolden renders the fixture report with w and compares the bytes with the
// golden file of that name under testdata, after normalizing CRLF so that a file
// written on Windows and one written on Linux compare equal. It returns what was
// rendered, for a test that has more to say about it than that it did not change.
// Regenerate the golden files with: go test ./internal/report/ -update
func assertGolden(t *testing.T, name string, w Writer) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := w.Write(&buf, fixtureReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := normalizeNewlines(buf.Bytes())
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if want = normalizeNewlines(want); !bytes.Equal(got, want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
	return got
}
