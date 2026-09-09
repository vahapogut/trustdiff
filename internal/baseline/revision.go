package baseline

import (
	"context"
	"fmt"
	"strings"
)

// RevisionReader is the part of *gitdiff.Repo this package needs: the bytes a
// revision recorded for a repository-relative path.
//
// It is an interface rather than the type itself so that internal/baseline keeps
// its imports to internal/model and the standard library. internal/checks reads a
// baseline, and a check must not pull in a package that starts a git process.
type RevisionReader interface {
	FileAt(ctx context.Context, sha, path string) ([]byte, error)
}

// AtRevision reads the baseline a revision recorded at path, which is relative to
// the repository root with forward slashes.
//
// This is what makes a pull request gate honest. The baseline in the working tree
// is a file like any other, and a change under review may have edited it; a check
// that compared a release with a record the same change rewrote would report the
// pass whoever wrote it wanted. The base revision's copy is the record as it stood
// before, and Set.Lookup prefers it whenever the two disagree.
//
// The reader's error is wrapped and passed on, so a caller recognizes
// gitdiff.ErrNotAtRev with errors.Is and takes a revision without a baseline as an
// empty one, which is what a change that adds the file looks like.
//
// Expected call site: (*App).baselineSet in internal/cli/baseline.go, which
// internal/cli/diff.go reaches through (*App).evaluateWithBaseline.
func AtRevision(ctx context.Context, r RevisionReader, sha, path string) (*File, error) {
	// Backslashes are replaced whatever the platform, rather than through
	// filepath.ToSlash, which does nothing off Windows: the path may have been
	// built on Windows and handed here in a test or a document, and git speaks in
	// forward slashes everywhere. A file whose name really contains a backslash,
	// which only a Unix filesystem allows, is not a path this reads.
	path = strings.ReplaceAll(path, "\\", "/")
	data, err := r.FileAt(ctx, sha, path)
	if err != nil {
		return nil, fmt.Errorf("read %s at %s: %w", path, short(sha), err)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s at %s: %w", path, short(sha), err)
	}
	return f, nil
}

// short abbreviates an object name for a message the way the diff command's notes
// do, so a reader sees twelve characters rather than forty.
func short(sha string) string {
	const shortSHA = 12
	if len(sha) <= shortSHA || strings.ContainsAny(sha, "/\\") {
		return sha
	}
	return sha[:shortSHA]
}
