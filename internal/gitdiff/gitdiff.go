// Package gitdiff answers the three questions the diff command asks of a git
// repository, without linking a git library: which lockfiles the repository
// tracks, what one of them held at a base revision, and which locked entries
// changed since.
//
// The base revision arrives from a CI event payload and from the command line,
// so it is treated as hostile input. Every invocation runs the git binary
// through exec.CommandContext with a fixed argument vector and never through a
// shell, passes --end-of-options so a ref beginning with a dash cannot be read
// as an option, and resolves a ref with
// "git rev-parse --verify --end-of-options <ref>^{commit}", where the ^{commit}
// suffix makes git insist on a commit so a ref carrying a colon cannot address a
// blob or a path instead. The answer is accepted only as forty lowercase
// hexadecimal characters, and every later command carries that revision rather
// than text a caller supplied. Directories are set as the command's working
// directory instead of being interpolated into arguments, and every call runs
// under a timeout.
package gitdiff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	// commandTimeout bounds one git invocation. Every command here reads local
	// objects, so seconds are generous; the timeout is there so that a git which
	// stops for a prompt or a lock cannot stall a CI job forever.
	commandTimeout = 30 * time.Second
	// shaLen is the length of a full sha-1 object name. trustdiff accepts only
	// these: a repository using another object format is reported rather than
	// half handled.
	shaLen = 40
)

// The errors callers distinguish. Everything else is wrapped and reported as is.
var (
	// ErrNoGit means the git binary is not on PATH.
	ErrNoGit = errors.New("git not found on PATH")
	// ErrNotRepository means the directory is not inside a git working tree.
	ErrNotRepository = errors.New("not a git repository")
	// ErrNotAtRev means the path does not exist at the revision, which is what a
	// lockfile added by the change under review looks like. Callers test for it
	// with errors.Is and take the base side as empty rather than as a failure.
	ErrNotAtRev = errors.New("path does not exist at revision")
	// ErrBadRevision means a revision is not a full object name.
	ErrBadRevision = errors.New("not a full object name")
	// ErrNoBase means no base revision could be determined and the caller has to
	// name one.
	ErrNoBase = errors.New("no base revision")
)

// CommandError reports a git invocation that failed. It carries the arguments
// and what git wrote to stderr, because git states exactly what was wrong
// ("unknown revision", "does not exist in") and repeating it saves the reader a
// second run.
type CommandError struct {
	// Args is the argument vector, without the binary.
	Args []string
	// Stderr is what git wrote to standard error.
	Stderr string
	// Err is the failure from os/exec, an exit status in the usual case.
	Err error
}

func (e *CommandError) Error() string {
	msg := "git " + strings.Join(e.Args, " ") + ": " + e.Err.Error()
	if s := firstLine(e.Stderr); s != "" {
		msg += ": " + s
	}
	return msg
}

// Unwrap exposes the exec failure, so a caller can reach exec.ExitError or the
// context error behind a timeout.
func (e *CommandError) Unwrap() error { return e.Err }

// Repo is a git working tree trustdiff reads. Open finds it. The methods run one
// git command each and never write, so a Repo is safe to use from several
// goroutines.
type Repo struct {
	git  string
	root string
}

// Open finds the repository that contains dir and returns a handle on its root.
// dir may be relative to the process working directory, and the empty string
// means that directory. It fails with ErrNotRepository when dir is outside a
// working tree and with ErrNoGit when git is not installed.
func Open(ctx context.Context, dir string) (*Repo, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoGit, err)
	}
	if dir == "" {
		dir = "."
	}
	out, err := runGit(ctx, git, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		if isNotRepository(err) {
			return nil, fmt.Errorf("%s: %w", dir, ErrNotRepository)
		}
		return nil, fmt.Errorf("find the repository root of %s: %w", dir, err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return nil, fmt.Errorf("%s: %w", dir, ErrNotRepository)
	}
	// git prints the root with forward slashes on every platform.
	return &Repo{git: git, root: filepath.Clean(filepath.FromSlash(root))}, nil
}

// Root is the absolute path of the repository's top directory. Every path this
// package returns is relative to it and separated by forward slashes, the way
// git prints paths.
func (r *Repo) Root() string { return r.root }

// Abs turns one of those repository-relative paths into a path on this machine.
func (r *Repo) Abs(rel string) string { return filepath.Join(r.root, filepath.FromSlash(rel)) }

// run executes one git command at the repository root.
func (r *Repo) run(ctx context.Context, args ...string) ([]byte, error) {
	return runGit(ctx, r.git, r.root, args...)
}

// runGit executes one git command in dir and returns its standard output. It is
// the only place in trustdiff that starts a process.
func runGit(ctx context.Context, git, dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// #nosec G204 -- git is the absolute path exec.LookPath resolved, no shell is
	// involved, dir is passed as the working directory rather than as part of the
	// command line, and args are literals plus values this package validated: a
	// revision is checked to be forty hexadecimal characters, and a ref a caller
	// supplied reaches git only as the argument of rev-parse behind
	// --end-of-options.
	cmd := exec.CommandContext(ctx, git, args...)
	cmd.Dir = dir
	cmd.Env = commandEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = errors.Join(ctx.Err(), err)
		}
		return stdout.Bytes(), &CommandError{Args: slices.Clone(args), Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// commandEnv keeps git predictable. It must never stop to ask for credentials,
// never take a lock while reading, never start a pager, and must report its
// errors in English, because ErrNotAtRev is recognized from the message. The
// rest of the environment is inherited: HOME and the repository's own
// configuration are how a machine says which directories are safe to read.
func commandEnv() []string {
	return append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_PAGER=cat",
		"LC_ALL=C",
		"LANG=C",
	)
}

// validSHA reports whether s is a full object name as git prints one. Every
// revision this package hands to a later command passes through here first, so a
// revision can never carry a dash, a colon or a path.
func validSHA(s string) bool {
	if len(s) != shaLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// checkRev rejects a revision that is not a full object name.
func checkRev(sha string) error {
	if !validSHA(sha) {
		return fmt.Errorf("revision %q: %w (want %d lowercase hexadecimal characters, as ResolveBase returns)", sha, ErrBadRevision, shaLen)
	}
	return nil
}

// commitSHA reads git's answer to a revision query and refuses anything that is
// not a full object name, so a surprising answer stops the run instead of
// traveling into the next command line.
func commitSHA(out []byte) (string, error) {
	s := strings.TrimSpace(string(out))
	if err := checkRev(s); err != nil {
		return "", err
	}
	return s, nil
}

// stderrContains reports whether a failed git command said s.
func stderrContains(err error, s string) bool {
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		return false
	}
	return strings.Contains(cmdErr.Stderr, s)
}

// isNotRepository reports whether git refused because there is no repository.
// git states that in its message and in no other way, and commandEnv pins the
// language so the message stays English.
func isNotRepository(err error) bool {
	return stderrContains(err, "not a git repository")
}

// firstLine keeps a message to its first line, so a git error spanning several
// lines does not spread across a report.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// splitNUL splits the output of a git command run with -z, which terminates
// every path with a null byte.
func splitNUL(out []byte) []string {
	fields := bytes.Split(out, []byte{0})
	paths := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) == 0 {
			continue
		}
		paths = append(paths, string(f))
	}
	return paths
}
