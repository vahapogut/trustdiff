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
// the published schema/policy.v1.json, so editors and this binary agree). The file
// must hold exactly one YAML document; a second one would otherwise be ignored
// together with any mistake in it.
func Parse(doc []byte) (*Policy, error) {
	var p Policy
	if err := decodeDocument(doc, &p); err != nil {
		return nil, err
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
	if err := decodeDocument(doc, &root); err != nil {
		return err
	}
	value, err := nodeToValue(&root)
	if err != nil {
		return err
	}
	return schema.ValidateValue(value)
}

var errEmpty = errors.New("empty policy file (want at least \"version: 1\")")

// decodeDocument decodes the single YAML document of a policy file into out with the
// strict settings both decoders share: unknown fields are errors, an empty file is
// errEmpty, and a second document is an error rather than silently skipped.
func decodeDocument(doc []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errEmpty
		}
		return fmt.Errorf("parse: %w", err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return fmt.Errorf("line %d: policy file must contain a single YAML document", extra.Line)
	case !errors.Is(err, io.EOF):
		return fmt.Errorf("parse: %w", err)
	}
	return nil
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

// YAML tags that nodeToValue treats specially, in the short form yaml.Node reports.
const (
	nullTag  = "!!null"
	mergeTag = "!!merge"
)

// nodeToValue converts a YAML tree into the JSON-compatible values the schema
// validator understands, so that the schema sees the same document the typed decoder
// does. Scalars are typed by their resolved YAML tag, except that timestamps stay
// strings (the schema describes expires as a date string) and any quoted scalar stays
// a string. A key whose value is null is left out, because the typed decoder reads it
// as "not set" (this is what "allow:" with every entry commented out looks like), and
// merge keys (<<) are applied the way the typed decoder applies them.
func nodeToValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, errEmpty
		}
		return nodeToValue(n.Content[0])
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		var merges []*yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if key.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: mapping keys must be plain strings", key.Line)
			}
			if key.ShortTag() == mergeTag {
				merges = append(merges, value)
				continue
			}
			if value.ShortTag() == nullTag {
				continue
			}
			v, err := nodeToValue(value)
			if err != nil {
				return nil, err
			}
			out[key.Value] = v
		}
		for _, merge := range merges {
			if err := mergeInto(out, merge); err != nil {
				return nil, err
			}
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

// mergeInto applies one merge key (<<) to a mapping with YAML merge semantics, which
// are also the typed decoder's: the value is a map or a list of maps, a key the
// mapping wrote itself always wins, and among the merged maps the first one to carry
// a key wins. The merge is shallow.
func mergeInto(out map[string]any, merge *yaml.Node) error {
	value, err := nodeToValue(merge)
	if err != nil {
		return err
	}
	var maps []any
	switch v := value.(type) {
	case map[string]any:
		maps = []any{v}
	case []any:
		maps = v
	default:
		return fmt.Errorf("line %d: a merge key (<<) needs a map or a list of maps", merge.Line)
	}
	for _, m := range maps {
		fields, ok := m.(map[string]any)
		if !ok {
			return fmt.Errorf("line %d: a merge key (<<) needs a map or a list of maps", merge.Line)
		}
		for k, v := range fields {
			if _, exists := out[k]; !exists {
				out[k] = v
			}
		}
	}
	return nil
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
