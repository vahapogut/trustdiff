package gitdiff

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
)

// FileAt returns the bytes the revision recorded for path. sha must be a full
// object name, which is what ResolveBase returns.
//
// When the revision has no such path, which is exactly what a lockfile the
// change adds looks like, the error wraps ErrNotAtRev and the caller takes the
// base side as empty. The bytes are the ones the commit holds: git applies no
// working-tree conversion to them, so a file committed with LF endings comes
// back with LF endings on Windows too.
func (r *Repo) FileAt(ctx context.Context, sha, path string) ([]byte, error) {
	if err := checkRev(sha); err != nil {
		return nil, err
	}
	rel, err := r.relative(path)
	if err != nil {
		return nil, err
	}
	// The argument begins with the revision, which this package has checked to be
	// hexadecimal, so it can never be read as an option whatever the path holds.
	out, err := r.run(ctx, "show", "--end-of-options", sha+":"+rel)
	if err != nil {
		if isNotAtRev(err) {
			return nil, fmt.Errorf("%s at %s: %w", rel, sha, ErrNotAtRev)
		}
		return nil, fmt.Errorf("read %s at %s: %w", rel, sha, err)
	}
	return out, nil
}

// ChangedFiles lists the paths whose content differs between the revision and
// the working tree, the ones the change added and the ones it deleted included.
// Paths are relative to the repository root and use forward slashes.
//
// Only files git tracks are compared, staged ones included; a lockfile that has
// been created but never added is invisible to git and therefore to this.
// UntrackedLockfiles finds those, and the diff command says so rather than
// reporting the file as unchanged. Renames are not detected, so a lockfile that
// moved appears under both of its paths.
func (r *Repo) ChangedFiles(ctx context.Context, sha string) ([]string, error) {
	if err := checkRev(sha); err != nil {
		return nil, err
	}
	out, err := r.run(ctx, "diff", "--name-only", "--no-renames", "-z", "--end-of-options", sha, "--")
	if err != nil {
		return nil, fmt.Errorf("list the files changed since %s: %w", sha, err)
	}
	return splitNUL(out), nil
}

// Lockfiles lists the lockfiles the repository tracks, as repository-relative
// paths, in the order git lists them. It asks git rather than walking the tree,
// so the copies inside node_modules, vendor directories and anything else
// .gitignore covers stay out of an audit.
//
// A file counts as a lockfile when a parser registered with internal/lockfile
// recognizes its name, so a program that imports no format package gets an empty
// list rather than a wrong one.
func (r *Repo) Lockfiles(ctx context.Context) ([]string, error) {
	out, err := r.run(ctx, "ls-files", "-z", "--end-of-options")
	if err != nil {
		return nil, fmt.Errorf("list the tracked files of %s: %w", r.root, err)
	}
	return onlyLockfiles(splitNUL(out)), nil
}

// UntrackedLockfiles lists the lockfiles the working tree holds that git does not
// track, as repository-relative paths with forward slashes. A file that was
// created and never added is invisible to a comparison against a revision, so the
// diff command names these instead of passing the change as unchanged. What
// .gitignore covers is left out, the way Lockfiles leaves the installed copies
// under node_modules out.
func (r *Repo) UntrackedLockfiles(ctx context.Context) ([]string, error) {
	out, err := r.run(ctx, "ls-files", "-z", "--others", "--exclude-standard", "--end-of-options")
	if err != nil {
		return nil, fmt.Errorf("list the untracked files of %s: %w", r.root, err)
	}
	return onlyLockfiles(splitNUL(out)), nil
}

// onlyLockfiles keeps the paths a registered parser recognizes, in the order git
// listed them.
func onlyLockfiles(paths []string) []string {
	found := make([]string, 0, 8)
	for _, path := range paths {
		if _, ok := lockfile.For(path); ok {
			found = append(found, path)
		}
	}
	return found
}

// relative turns a path the caller names, absolute or relative to the repository
// root, into the root-relative slash-separated form git expects.
func (r *Repo) relative(path string) (string, error) {
	p := path
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(r.root, p)
		if err != nil {
			return "", fmt.Errorf("path %s is not inside %s: %w", path, r.root, err)
		}
		p = rel
	}
	p = filepath.ToSlash(filepath.Clean(p))
	switch {
	case p == ".":
		return "", fmt.Errorf("path %q names no file", path)
	case p == ".." || strings.HasPrefix(p, "../"):
		return "", fmt.Errorf("path %s is outside the repository", path)
	}
	return p, nil
}

// isNotAtRev reports whether git refused because the revision has no such path.
// Verified against git 2.49.0 on 2026-09-09: "git show <sha>:<path>" answers
// "fatal: path 'p' does not exist in '<sha>'" for a path the revision never had,
// and "fatal: path 'p' exists on disk, but not in '<sha>'" for one the working
// tree has and the revision does not.
func isNotAtRev(err error) bool {
	return stderrContains(err, "does not exist in") ||
		stderrContains(err, "exists on disk, but not in")
}
