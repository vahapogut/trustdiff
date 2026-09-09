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

// New returns the writer for a --format value. "human" and "json" are available;
// "sarif" and "markdown" arrive in milestone M2 and report ErrUnsupportedFormat
// until then, as does any unknown name.
func New(format string, opts Options) (Writer, error) {
	switch format {
	case "human":
		return Human(opts), nil
	case "json":
		return JSON{}, nil
	case "sarif", "markdown":
		return nil, fmt.Errorf("%w: %q is planned for a later release", ErrUnsupportedFormat, format)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
}
