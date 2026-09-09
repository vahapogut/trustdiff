package baseline

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The published schema at the repository root and the embedded copy must never drift.
func TestSchemaPublishedCopyIsIdentical(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "schema", "baseline.v1.json"))
	if err != nil {
		t.Fatalf("read published schema: %v", err)
	}
	if !bytes.Equal(published, SchemaJSON) {
		t.Fatal("schema/baseline.v1.json and internal/baseline/baseline.v1.json differ; copy one over the other")
	}
	if len(SchemaJSON) == 0 || !json.Valid(SchemaJSON) {
		t.Fatal("embedded schema is not valid JSON")
	}
	if bytes.Contains(SchemaJSON, []byte("\r")) {
		t.Fatal("schema must use LF line endings")
	}
}

// The schema must stay inside the keyword subset internal/jsonschema enforces, and
// everything the writer produces must validate against it. An ignored keyword makes
// a schema silently more permissive, which would let the writer drift from the
// document other tools read.
func TestSchemaValidatesWhatTheWriterProduces(t *testing.T) {
	schema, err := jsonschema.Compile(SchemaJSON)
	if err != nil {
		t.Fatalf("compile schema/baseline.v1.json: %v", err)
	}
	if unsupported := schema.UnsupportedKeywords(); len(unsupported) != 0 {
		t.Fatalf("schema uses keywords the validator does not enforce: %v", unsupported)
	}

	written, err := Bytes(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(written); err != nil {
		t.Errorf("the written baseline does not match the schema:\n%v\n%s", err, written)
	}

	empty, err := Bytes(New(now))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(empty); err != nil {
		t.Errorf("an empty baseline does not match the schema:\n%v\n%s", err, empty)
	}

	golden, err := os.ReadFile(filepath.Join("testdata", goldenPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(golden); err != nil {
		t.Errorf("testdata/%s does not match the schema:\n%v", goldenPath, err)
	}
}

// The schema is hand written, so the parts that mirror Go constants are checked here.
func TestSchemaMatchesConstants(t *testing.T) {
	var schema struct {
		Schema     string `json:"$schema"`
		Required   []string
		Properties struct {
			Schema struct {
				Const string `json:"const"`
			} `json:"schema"`
		} `json:"properties"`
		Definitions struct {
			Package struct {
				Properties struct {
					Ecosystem struct {
						Enum []string `json:"enum"`
					} `json:"ecosystem"`
					PublisherSource struct {
						Enum []string `json:"enum"`
					} `json:"publisher_source"`
				} `json:"properties"`
			} `json:"package"`
			Provenance struct {
				Properties struct {
					Kind struct {
						Enum []string `json:"enum"`
					} `json:"kind"`
				} `json:"properties"`
			} `json:"provenance"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(SchemaJSON, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if schema.Schema != "http://json-schema.org/draft-07/schema#" {
		t.Errorf("$schema = %q, want draft-07", schema.Schema)
	}
	if schema.Properties.Schema.Const != SchemaID {
		t.Errorf("properties.schema.const = %q, want %q", schema.Properties.Schema.Const, SchemaID)
	}
	ecosystems := make([]string, 0, len(model.Ecosystems()))
	for _, e := range model.Ecosystems() {
		ecosystems = append(ecosystems, e.String())
	}
	if got := schema.Definitions.Package.Properties.Ecosystem.Enum; !slices.Equal(got, ecosystems) {
		t.Errorf("package.ecosystem enum = %v, want %v", got, ecosystems)
	}
	if got, want := schema.Definitions.Package.Properties.PublisherSource.Enum, []string{string(FromRegistry), string(FromProvenance)}; !slices.Equal(got, want) {
		t.Errorf("package.publisher_source enum = %v, want %v", got, want)
	}
	kinds := []string{
		string(model.ProvenanceNone), string(model.ProvenanceSignature),
		string(model.ProvenanceAttestation), string(model.ProvenanceTrustedPublisher),
	}
	if got := schema.Definitions.Provenance.Properties.Kind.Enum; !slices.Equal(got, kinds) {
		t.Errorf("provenance.kind enum = %v, want %v", got, kinds)
	}
}

// Every field carries a description and no object accepts a field it does not
// describe. Both are house style for a published schema, and both are what makes
// the file readable by someone who never reads the Go.
func TestSchemaDescribesEveryFieldAndRefusesTheRest(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(SchemaJSON, &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(where string, node map[string]any)
	walk = func(where string, node map[string]any) {
		if _, isRef := node["$ref"]; !isRef && where != "" {
			if text, ok := node["description"].(string); !ok || strings.TrimSpace(text) == "" {
				t.Errorf("%s has no description", where)
			}
		}
		if node["type"] == "object" {
			if allowed, ok := node["additionalProperties"].(bool); !ok || allowed {
				t.Errorf("%s does not set additionalProperties to false", where)
			}
		}
		if props, ok := node["properties"].(map[string]any); ok {
			for name, child := range props {
				if sub, ok := child.(map[string]any); ok {
					walk(where+"/"+name, sub)
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(where+"/items", items)
		}
	}
	walk("", doc)
	for name, raw := range doc["definitions"].(map[string]any) {
		walk("definitions/"+name, raw.(map[string]any))
	}
}
