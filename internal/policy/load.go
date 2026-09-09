package policy

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
)

// SchemaJSON is the embedded copy of schema/policy.v1.json. A test keeps the two
// files byte-identical so the published schema cannot drift from the one enforced.
//
//go:embed policy.v1.json
var SchemaJSON []byte

// Load reads and parses a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the policy path is chosen by the user on the command line
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Parse decodes a policy document. It runs three checks and stops at the first that
// fails: the strict typed decode (unknown keys and wrong shapes, with line numbers),
// Validate (names, option placement, values), and the JSON Schema (the same rules as
// the published schema/policy.v1.json, so editors and this binary agree).
func Parse(doc []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty policy file (want at least \"version: 1\")")
		}
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy:\n%w", err)
	}
	if err := ValidateSchema(doc); err != nil {
		return nil, fmt.Errorf("policy does not match schema/policy.v1.json:\n%w", err)
	}
	return &p, nil
}

// ValidateSchema checks a YAML policy document against the embedded JSON Schema
// without decoding it into Policy, so it reports exactly what an editor with the
// published schema would.
func ValidateSchema(doc []byte) error {
	schema, err := compiledSchema()
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	value, err := nodeToValue(&root)
	if err != nil {
		return err
	}
	return schema.ValidateValue(value)
}

var (
	schemaOnce   sync.Once
	schemaCached *jsonschema.Schema
	errSchema    error
)

func compiledSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		schemaCached, errSchema = jsonschema.Compile(SchemaJSON)
		if errSchema != nil {
			errSchema = fmt.Errorf("compile embedded policy schema: %w", errSchema)
		}
	})
	return schemaCached, errSchema
}

// nodeToValue converts a YAML tree into the JSON-compatible values the schema
// validator understands. Scalars are typed by their resolved YAML tag, except that
// timestamps stay strings (the schema describes expires as a date string) and any
// quoted scalar stays a string.
func nodeToValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, errors.New("empty policy file (want at least \"version: 1\")")
		}
		return nodeToValue(n.Content[0])
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: mapping keys must be plain strings", key.Line)
			}
			v, err := nodeToValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[key.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			v, err := nodeToValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.AliasNode:
		return nodeToValue(n.Alias)
	case yaml.ScalarNode:
		return scalarToValue(n), nil
	}
	return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
}

func scalarToValue(n *yaml.Node) any {
	if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return n.Value
	}
	switch strings.TrimPrefix(n.Tag, "!!") {
	case "int":
		if v, err := strconv.ParseInt(n.Value, 0, 64); err == nil {
			return float64(v)
		}
	case "float":
		if v, err := strconv.ParseFloat(n.Value, 64); err == nil {
			return v
		}
	case "bool":
		if v, err := strconv.ParseBool(strings.ToLower(n.Value)); err == nil {
			return v
		}
	case "null":
		return nil
	}
	return n.Value
}
