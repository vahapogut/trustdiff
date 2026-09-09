package gitdiff

import (
	"context"
	"fmt"
	"strings"
)

// The refs the default base is looked for in, in this order.
const (
	// originMain is the usual default branch of the fork point a pull request is
	// measured against.
	originMain = "origin/main"
	// originHEAD is what the remote itself calls its default branch, for the
	// repositories that never renamed master or that release from another branch.
	originHEAD = "origin/HEAD"
	// headParent is the last resort, for a clone with no remote at all: a git
	// hook on a laptop compares against the commit before this one.
	headParent = "HEAD~1"
)

// ResolveBase turns the base the caller asked for into the commit to compare
// against.
//
// A named ref is resolved as given, so a branch, a tag, a remote-tracking ref
// and a raw object name all work; this is the form a CI job uses, where the
// event payload names the base commit of the pull request.
//
// With no ref, the base is the fork point: the merge base with origin/main, or
// with origin/HEAD when the default branch goes by another name, or HEAD~1 in a
// clone that has no remote. When none of the three exists the error names all
// three and wraps ErrNoBase, so the reader learns what was looked for rather
// than only that something was missing.
func (r *Repo) ResolveBase(ctx context.Context, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref != "" {
		// git refs cannot hold control characters, and a command line cannot carry
		// a null byte, so this rejects nothing a repository could name.
		if strings.ContainsAny(ref, "\x00\n\r") {
			return "", fmt.Errorf("resolve base %q: a ref may not contain a newline or a null byte", ref)
		}
		sha, err := r.revision(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("resolve base %q: %w", ref, err)
		}
		return sha, nil
	}

	tried := make([]string, 0, 3)
	for _, remote := range []string{originMain, originHEAD} {
		sha, err := r.mergeBase(ctx, remote)
		if err == nil {
			return sha, nil
		}
		tried = append(tried, fmt.Sprintf("merge base with %s (%s)", remote, firstLine(err.Error())))
	}
	sha, err := r.revision(ctx, headParent)
	if err == nil {
		return sha, nil
	}
	tried = append(tried, fmt.Sprintf("%s (%s)", headParent, firstLine(err.Error())))
	return "", fmt.Errorf("%w: tried the %s; name one with --base or --base-file", ErrNoBase, strings.Join(tried, ", the "))
}

// mergeBase returns the commit where HEAD and remote last agreed. Both sides are
// resolved to object names first, so the merge base itself is computed from
// values this package validated rather than from a ref.
func (r *Repo) mergeBase(ctx context.Context, remote string) (string, error) {
	remoteSHA, err := r.revision(ctx, remote)
	if err != nil {
		return "", err
	}
	head, err := r.revision(ctx, "HEAD")
	if err != nil {
		return "", err
	}
	out, err := r.run(ctx, "merge-base", "--end-of-options", remoteSHA, head)
	if err != nil {
		return "", err
	}
	return commitSHA(out)
}

// revision resolves a ref to the commit it names. --end-of-options keeps a ref
// that begins with a dash from being read as an option, and the ^{commit}
// suffix makes git insist on a commit, so a ref carrying a colon cannot name a
// blob or a path in some other tree.
func (r *Repo) revision(ctx context.Context, ref string) (string, error) {
	out, err := r.run(ctx, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return commitSHA(out)
}
