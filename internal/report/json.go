package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSON writes the report as the document described by schema/report.v1.json:
// two-space indentation, keys in struct field order, a trailing newline, and no
// HTML escaping so that explanations stay readable.
type JSON struct{}

// Write renders r to w.
func (JSON) Write(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode json report: %w", err)
	}
	return nil
}
