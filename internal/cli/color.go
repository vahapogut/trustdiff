package cli

import (
	"io"
	"os"

	"golang.org/x/term"
)

// colorEnabled decides whether human output may use ANSI colors.
// The --no-color flag wins, then the NO_COLOR convention (any value, even empty,
// disables color, see https://no-color.org), then whether stdout is a terminal.
func colorEnabled(noColorFlag bool, lookupEnv func(string) (string, bool), isTerminal bool) bool {
	if noColorFlag {
		return false
	}
	if _, set := lookupEnv("NO_COLOR"); set {
		return false
	}
	return isTerminal
}

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// terminalWidth returns the width of w when it is a terminal, otherwise the fallback.
func terminalWidth(w io.Writer, fallback int) int {
	f, ok := w.(*os.File)
	if !ok {
		return fallback
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil || width <= 0 {
		return fallback
	}
	return width
}
