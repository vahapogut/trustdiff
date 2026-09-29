package guarddog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Synthetic reports follow the Apache-2.0 upstream CLI/JSON reporter at
// DataDog/guarddog 3da172679cb58b1c9a780f9f5d640f855be016dc, verified 2026-09-29.
const cleanReport = `{"package":"example","package_version":"1.2.3","issues":0,"errors":{},"results":{"metadata-rule":null,"source-rule":{}},"risks":[]}`

func TestParseReport(t *testing.T) {
	ref := model.PackageRef{Ecosystem: model.NPM, Name: "example", Version: "1.2.3"}
	for _, tt := range []struct {
		name, body, status string
		wantErr            bool
	}{
		{"clean", cleanReport, "completed", false},
		{"findings", strings.Replace(cleanReport, `"metadata-rule":null`, `"metadata-rule":"suspicious release"`, 1), "completed", false},
		{"partial", strings.Replace(cleanReport, `"errors":{}`, `"errors":{"metadata-rule":"timeout"}`, 1), "partial", true},
		{"download failure", `{"package":"example","issues":0,"errors":{"download-package":"not found"}}`, "unavailable", true},
		{"wrong name", strings.Replace(cleanReport, `"example"`, `"other"`, 1), "unavailable", true},
		{"wrong version", strings.Replace(cleanReport, `"1.2.3"`, `"1.2.4"`, 1), "unavailable", true},
		{"missing issues", strings.Replace(cleanReport, `"issues":0,`, "", 1), "unavailable", true},
		{"negative issues", strings.Replace(cleanReport, `"issues":0`, `"issues":-1`, 1), "unavailable", true},
		{"missing results", strings.Replace(cleanReport, `"results":{"metadata-rule":null,"source-rule":{}},`, "", 1), "unavailable", true},
		{"missing errors", strings.Replace(cleanReport, `"errors":{},`, "", 1), "unavailable", true},
		{"null errors", strings.Replace(cleanReport, `"errors":{}`, `"errors":null`, 1), "unavailable", true},
		{"missing risks", strings.Replace(cleanReport, `,"risks":[]`, "", 1), "unavailable", true},
		{"null risk", strings.Replace(cleanReport, `"risks":[]`, `"risks":[null]`, 1), "unavailable", true},
		{"empty risk", strings.Replace(cleanReport, `"risks":[]`, `"risks":[{}]`, 1), "unavailable", true},
		{"mistyped errors", strings.Replace(cleanReport, `"errors":{}`, `"errors":{"rule":false}`, 1), "unavailable", true},
		{"mistyped rule", strings.Replace(cleanReport, `"metadata-rule":null`, `"metadata-rule":true`, 1), "unavailable", true},
		{"malformed", `{`, "unavailable", true},
		{"trailing report", cleanReport + cleanReport, "unavailable", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseReport(ref, []byte(tt.body))
			if (err != nil) != tt.wantErr || got.Status != tt.status {
				t.Fatalf("status=%q, err=%v; want status=%q, error=%v", got.Status, err, tt.status, tt.wantErr)
			}
			if got.Ref != ref || got.Source != SourceURL || got.ToolVersion != SupportedVersion {
				t.Fatalf("missing attribution: %+v", got)
			}
		})
	}
}

func TestReportPreservesFindingsAndPartialErrors(t *testing.T) {
	ref := model.PackageRef{Ecosystem: model.PyPI, Name: "example", Version: "1.2.3"}
	body := `{"package":"example","package_version":"1.2.3","issues":2,"errors":{"unavailable-rule":"network unavailable"},"results":{"empty":{},"null":null,"empty-list":[],"empty-message":"","source-rule":[{"code":"eval(data)","location":"example.py:3"}],"metadata-rule":"suspicious"},"risks":[{"name":"Suspicious execution","category":"threat","severity":"high","threat_rule":"source-rule","threat_description":"Executes data","file_path":"example.py","threat_code":"excluded duplicated code"}]}`
	got, err := parseReport(ref, []byte(body))
	if err == nil || got.Status != "partial" || got.Issues != 2 || len(got.Results) != 2 || len(got.Risks) != 1 || got.Errors["unavailable-rule"] != "network unavailable" {
		t.Fatalf("partial evidence lost: %+v, %v", got, err)
	}
	encoded, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(encoded), "eval(data)") || strings.Contains(string(encoded), "excluded duplicated code") {
		t.Fatalf("unexpected evidence: %s, %v", encoded, err)
	}
}

func TestValidateRef(t *testing.T) {
	for _, tt := range []struct {
		ref  model.PackageRef
		want bool
	}{
		{model.PackageRef{Ecosystem: model.NPM, Name: "@scope/example", Version: "1.2.3-beta.1+build"}, true},
		{model.PackageRef{Ecosystem: model.NPM, Name: "JSONStream", Version: "1.2.3"}, true},
		{model.PackageRef{Ecosystem: model.PyPI, Name: "example-package", Version: "1!2.3rc1.post2+local"}, true},
		{model.PackageRef{Ecosystem: model.Cargo, Name: "example_crate", Version: "1.2.3"}, true},
		{model.PackageRef{Ecosystem: model.NPM, Name: "example", Version: "latest"}, false},
		{model.PackageRef{Ecosystem: model.NPM, Name: "example", Version: "1.2"}, false},
		{model.PackageRef{Ecosystem: model.NPM, Name: "example", Version: "^1.2.3"}, false},
		{model.PackageRef{Ecosystem: model.NPM, Name: "example", Version: "1.2.3\n"}, false},
		{model.PackageRef{Ecosystem: model.PyPI, Name: "--help", Version: "1.0"}, false},
		{model.PackageRef{Ecosystem: model.PyPI, Name: "../example", Version: "1.0"}, false},
		{model.PackageRef{Ecosystem: model.PyPI, Name: "https://example.test", Version: "1.0"}, false},
		{model.PackageRef{Ecosystem: model.PyPI, Name: "example;echo", Version: "1.0"}, false},
		{model.PackageRef{Ecosystem: model.PyPI, Name: "example", Version: ""}, false},
		{model.PackageRef{Ecosystem: model.Cargo, Name: "./example", Version: "1.2.3"}, false},
		{model.PackageRef{Ecosystem: model.JSR, Name: "@scope/example", Version: "1.2.3"}, false},
	} {
		t.Run(tt.ref.String(), func(t *testing.T) {
			if err := validateRef(tt.ref); (err == nil) != tt.want {
				t.Fatalf("validateRef(%+v)=%v, want valid=%v", tt.ref, err, tt.want)
			}
		})
	}
}

func TestOfflineRefusesBeforeExecutableLookup(t *testing.T) {
	_, err := New(Options{Offline: true, Binary: "does-not-exist"})
	if err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline error=%v", err)
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, timeout := range []time.Duration{-time.Second, 31 * time.Minute} {
		if _, err := New(Options{Timeout: timeout}); err == nil {
			t.Fatal("accepted invalid timeout", timeout)
		}
	}
}

func TestTemporaryPathsRemainStableAcrossScans(t *testing.T) {
	ref := model.MustParseRef("npm:example@1.2.3")
	var previous string
	for _, root := range []string{"/tmp/trustdiff-first", "/tmp/trustdiff-second"} {
		path := root + "/scratch/tmp" + strings.TrimPrefix(root, "/tmp/trustdiff-") + "/package"
		body := `{"package":"example","package_version":"1.2.3","issues":1,"errors":{"rule":"failed to read ` + path + `/example.js"},"path":"` + path + `","results":{"source-rule":[{"location":"` + path + `/example.js:3","code":"original code"}]},"risks":[]}`
		got, err := parseReport(ref, []byte(normalizeTempPaths(body, root)))
		if err == nil || got.Status != "partial" || got.Errors["rule"] != "failed to read example.js" {
			t.Fatalf("path normalization: %+v, %v", got, err)
		}
		encoded, err := json.Marshal(got)
		if err != nil || !strings.Contains(string(encoded), `"location":"example.js:3"`) || !strings.Contains(string(encoded), "original code") {
			t.Fatalf("relative source evidence: %s, %v", encoded, err)
		}
		if previous != "" && previous != string(encoded) {
			t.Fatalf("scan paths changed fingerprint:\n%s\n%s", previous, encoded)
		}
		previous = string(encoded)
		message := normalizeTempPaths("download failed in "+path, root)
		if message != "download failed in <guarddog-temp>/scratch/<scan>/package" {
			t.Fatalf("download diagnostic remains volatile: %q", message)
		}
	}
}
