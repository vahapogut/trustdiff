package watch

import _ "embed"

// SchemaJSON is identical to schema/watch.v1.json. Its report.v1.json reference
// names the existing report contract; consumers resolve that sibling schema.
// Tests bundle the known local report schema without making a network request.
//
//go:embed watch.v1.json
var SchemaJSON []byte
