// Package jsonschema validates JSON documents against the subset of JSON Schema that
// the trustdiff schemas use: schema/policy.v1.json, schema/report.v1.json and the
// vendored SARIF 2.1.0 schema. It exists because the dependency policy leaves no room
// for a validator module (ADR 0001).
//
// Supported keywords:
//
//   - $schema, $id, id: accepted and ignored.
//   - type: a type name or an array of type names; "integer" accepts any number
//     without a fractional part, so 3.0 is an integer and 3.5 is not; "null" is a type.
//   - enum, const: compared by JSON value equality (object key order is irrelevant,
//     1 and 1.0 are equal).
//   - required, properties, additionalProperties (boolean or schema),
//     patternProperties.
//   - items (a single schema; the array form is a compile error), minItems, maxItems,
//     uniqueItems.
//   - minimum, maximum, exclusiveMinimum, exclusiveMaximum, in both the draft-04
//     boolean form (exclusiveMinimum: true modifies minimum) and the draft-06 numeric
//     form.
//   - minLength, maxLength (counted in Unicode code points), pattern (Go regexp
//     syntax, RE2; not implicitly anchored).
//   - format, leniently: "date" must parse as YYYY-MM-DD, "date-time" as RFC 3339,
//     "uri" must parse and carry a scheme, "uri-reference" must parse; every other
//     format is accepted without a check. Formats apply to strings only.
//   - oneOf, anyOf, allOf, not.
//   - $ref into the same document: "#", "#/definitions/<name>", "#/$defs/<name>" or
//     any other JSON pointer into the schema. A reference to another document is a
//     compile error. Keywords next to $ref are applied as well. A $ref cycle that
//     would recurse without consuming input (for example a definition whose allOf
//     references itself) is a compile error; a definition that references itself
//     through properties or items is ordinary recursion and works.
//   - title, description, default, examples, $comment, definitions, $defs: accepted
//     as annotations or containers and never validated against.
//
// Every other keyword is ignored, as the JSON Schema specifications require for
// unknown keywords. Because an ignored validation keyword makes a schema silently
// more permissive, (*Schema).UnsupportedKeywords reports the keywords a schema uses
// outside this list so a test can assert that the project schemas use none.
//
// Instances are decoded with encoding/json into any, so numbers are float64 unless
// the caller decoded with UseNumber, which is supported too. Validation reports
// every failure at once: Validate returns an errors.Join of *ValidationError values,
// each carrying the JSON pointer (RFC 6901) of the failing instance location and the
// keyword that failed.
package jsonschema

import (
	"errors"
	"fmt"
)

// Schema is a compiled JSON Schema. It is immutable after Compile and safe for
// concurrent use.
type Schema struct {
	root        *node
	unsupported []string
}

// ValidationError is one failed keyword at one instance location.
type ValidationError struct {
	// Pointer is the RFC 6901 JSON pointer of the failing instance location, empty
	// for the document root, for example "/runs/0/results/0/level".
	Pointer string
	// Keyword is the schema keyword that failed, for example "enum" or "required".
	// A boolean "false" schema reports the keyword "false".
	Keyword string
	// Message says what was expected and what was found.
	Message string
}

// Error renders the location as a URI fragment ("#" for the root) followed by the
// keyword and the message, for example
// "#/runs/0/results/0/level: enum: value "fatal" is not one of [...]".
func (e *ValidationError) Error() string {
	return "#" + e.Pointer + ": " + e.Keyword + ": " + e.Message
}

// Compile parses and checks a schema document. It returns an error for malformed
// JSON, a root that is not an object, a keyword with a value of the wrong shape, an
// invalid regular expression, a $ref to another document, a $ref that does not
// resolve, and a $ref cycle that would never consume input. Definitions under
// "definitions" and "$defs" are compiled even when nothing references them.
func Compile(schema []byte) (*Schema, error) {
	c, err := newCompiler(schema)
	if err != nil {
		return nil, fmt.Errorf("jsonschema: %w", err)
	}
	root, err := c.compileRoot()
	if err != nil {
		return nil, fmt.Errorf("jsonschema: %w", err)
	}
	return &Schema{root: root, unsupported: c.unsupportedKeywords()}, nil
}

// Validate decodes the instance with encoding/json and validates it. The result is
// nil when the instance is valid, otherwise an errors.Join of every *ValidationError
// found, so a caller sees every problem at once.
func (s *Schema) Validate(instance []byte) error {
	v, err := decodeInstance(instance)
	if err != nil {
		return fmt.Errorf("jsonschema: decode instance: %w", err)
	}
	return s.ValidateValue(v)
}

// ValidateValue validates an already decoded document. The value must be what
// encoding/json produces when decoding into any: map[string]any, []any, string,
// bool, nil and float64 (or json.Number). Go integer and float types are accepted as
// numbers as a convenience; anything else fails with a "type" error at its location.
func (s *Schema) ValidateValue(v any) error {
	var errs []error
	s.root.validate(v, "", &errs)
	return errors.Join(errs...)
}

// UnsupportedKeywords lists, sorted and without duplicates, the keywords the schema
// uses that this package neither enforces nor recognizes as annotations. A schema
// written for this project should report none.
func (s *Schema) UnsupportedKeywords() []string {
	out := make([]string, len(s.unsupported))
	copy(out, s.unsupported)
	return out
}
