package report

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnsupportedFormat is returned by New for a format no writer implements yet.
var ErrUnsupportedFormat = errors.New("unsupported report format")

// Writer renders a report. Implementations write the whole document in one call and
// never write anything else to w, because w is usually stdout.
type Writer interface {
	Write(w io.Writer, r *Report) error
}

// Options are the terminal settings a writer may honor.
type Options struct {
	// Color allows ANSI escape sequences. The caller decides from --no-color,
	// NO_COLOR and whether stdout is a terminal.
	Color bool
	// Width is the terminal width in columns; zero or less selects a default.
	Width int
}

// New returns the writer for a --format value: "human" for a terminal, "json" for
// the document schema/report.v1.json describes, "sarif" for a code scanning service
// and "markdown" for a pull request comment. Any other name, the empty one included,
// reports ErrUnsupportedFormat and names what it was given.
//
// Only Human reads opts; the three document formats render the same bytes wherever
// they are written.
func New(format string, opts Options) (Writer, error) {
	switch format {
	case "human":
		return Human(opts), nil
	case "json":
		return JSON{}, nil
	case "sarif":
		return SARIF{}, nil
	case "markdown":
		return Markdown{}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
}
