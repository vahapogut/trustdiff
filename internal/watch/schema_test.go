package watch

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

func TestWatchSchemaPublishedCopyIsIdentical(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "schema", "watch.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(published, SchemaJSON) || bytes.Contains(SchemaJSON, []byte("\r")) {
		t.Fatal("published and embedded watch schemas differ or contain CRLF")
	}
}

// The public schema references its sibling instead of duplicating its evolving
// definitions. The in-house validator resolves only local references, so bundle
// that one known schema for tests. No arbitrary reference is fetched or accepted.
func watchSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	var envelope, nested map[string]any
	if err := json.Unmarshal(SchemaJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(report.SchemaJSON, &nested); err != nil {
		t.Fatal(err)
	}
	properties := envelope["properties"].(map[string]any)
	reference := properties["report"].(map[string]any)
	if reference["$ref"] != "report.v1.json" {
		t.Fatal("watch report reference no longer names its known sibling schema")
	}
	reference["$ref"] = "#/definitions/report"
	delete(nested, "$id")
	delete(nested, "$schema")
	var relocate func(any)
	relocate = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "$ref" {
					ref, ok := child.(string)
					if !ok || !strings.HasPrefix(ref, "#/") {
						t.Fatalf("unexpected reference in report schema: %v", child)
					}
					v[key] = "#/definitions/report" + strings.TrimPrefix(ref, "#")
				} else {
					relocate(child)
				}
			}
		case []any:
			for _, child := range v {
				relocate(child)
			}
		}
	}
	relocate(nested)
	envelope["definitions"].(map[string]any)["report"] = nested
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.Compile(data)
	if err != nil {
		t.Fatal(err)
	}
	if unsupported := schema.UnsupportedKeywords(); len(unsupported) > 0 {
		t.Fatalf("unsupported schema keywords: %v", unsupported)
	}
	return schema
}

func TestWatchSchemaValidatesEmittedEventsAndEmbeddedReport(t *testing.T) {
	malicious := finding("TD009", map[string]any{"advisories": []string{"MAL-2026-1"}})
	malicious.Name, malicious.Title, malicious.Explanation = "malicious-package", "Listed as malicious", "Recorded fixture advisory"
	reports := []*report.Report{
		observation(nil), observation([]model.Finding{malicious}),
		observation(nil, model.Skipped{Check: "TD009", Reason: "source unavailable"}),
	}
	for _, rep := range reports {
		rep.Tool = report.CurrentTool()
		rep.Policy = report.Policy{Cooldown: "3d", FailOn: "warn"}
	}
	reports[1].GuardDogRequested = true
	reports[1].GuardDog = []model.Analysis{{Ref: testRef, Source: "https://github.com/DataDog/guarddog", Status: "partial", Errors: map[string]string{"rule": "unavailable"}}}
	schema := watchSchema(t)
	events := runObservations(t, reports...)
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(data); err != nil {
			t.Fatalf("event fails schema: %v\n%s", err, data)
		}
	}
	valid, err := json.Marshal(events[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong schema", func(v map[string]any) { v["schema"] = "trustdiff.watch/2" }},
		{"invalid event time", func(v map[string]any) { v["observed_at"] = "yesterday" }},
		{"empty change event", func(v map[string]any) { v["changes"] = []any{} }},
		{"initial with changes", func(v map[string]any) { v["kind"] = "initial" }},
		{"unknown change", func(v map[string]any) { v["changes"].([]any)[0].(map[string]any)["kind"] = "resolved" }},
		{"missing pinned version", func(v map[string]any) {
			delete(v["changes"].([]any)[0].(map[string]any)["ref"].(map[string]any), "version")
		}},
		{"invalid embedded report", func(v map[string]any) { delete(v["report"].(map[string]any), "summary") }},
		{"invalid external analysis", func(v map[string]any) {
			v["report"].(map[string]any)["guarddog"].([]any)[0].(map[string]any)["status"] = "clean"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bad map[string]any
			if err := json.Unmarshal(valid, &bad); err != nil {
				t.Fatal(err)
			}
			tc.edit(bad)
			encoded, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(encoded); err == nil {
				t.Fatalf("invalid event accepted: %s", encoded)
			}
		})
	}
}
