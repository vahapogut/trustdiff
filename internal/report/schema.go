package report

import _ "embed"

// SchemaJSON is the JSON Schema for the document JSON writes. It is a byte-identical
// copy of schema/report.v1.json at the repository root; the test in schema_test.go
// fails when the two drift. Callers that validate output or serve the schema to
// editors use this copy so the binary needs no file next to it.
//
// The schema uses the draft-07 dialect; its $schema value is the meta-schema id
// http://json-schema.org/draft-07/schema#, checked against the live meta-schema on
// 2026-09-09. Only the keywords internal/jsonschema implements are used: type, enum,
// const, required, properties, additionalProperties, items, pattern, minimum and local $ref
// into definitions.
//
//go:embed report.v1.json
var SchemaJSON []byte
