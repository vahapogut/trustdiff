package cli

import "fmt"

// Exit codes are part of the public contract; scripts and CI rely on them.
const (
	// ExitOK means no blocking findings.
	ExitOK = 0
	// ExitFindings means at least one finding at or above the --fail-on level.
	ExitFindings = 1
	// ExitUsage means a usage or configuration error.
	ExitUsage = 2
	// ExitUnavailable means a required data source was unavailable and the policy says to fail.
	ExitUnavailable = 3
)

// ExitError carries a process exit code out of a command. Main unwraps it.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// Exit wraps err with the given exit code.
func Exit(code int, err error) error { return &ExitError{Code: code, Err: err} }

// Usagef reports a usage or configuration error (exit code 2).
func Usagef(format string, args ...any) error {
	return Exit(ExitUsage, fmt.Errorf(format, args...))
}
