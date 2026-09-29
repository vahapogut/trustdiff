package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
)

func TestExternalAnalysisAllFormatsAndSchema(t *testing.T) {
	r := Build(nil, CurrentTool(), Policy{Cooldown: "3d", FailOn: "block"}, model.LevelBlock)
	r.GuardDogRequested = true
	r.GuardDog = []model.Analysis{{Ref: model.PackageRef{Ecosystem: model.NPM, Name: "foo", Version: "1.0.0"}, Source: "https://github.com/DataDog/guarddog", Status: "partial", Issues: 1, Message: "bad\x1b[31m\n~~~~\n<script>"}}
	for _, format := range []string{"json", "human", "markdown", "sarif"} {
		w, err := New(format, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := w.Write(&out, r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "\x1b") {
			t.Fatalf("bad %s supplement: %s", format, &out)
		}
		if format == "json" {
			schema, err := jsonschema.Compile(SchemaJSON)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(out.Bytes()); err != nil {
				t.Fatal(err)
			}
		}
		if format == "sarif" {
			var doc map[string]any
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
		}
	}
}
