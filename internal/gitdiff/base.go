package gitdiff

import (
	"context"
	"fmt"
	"os"
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

// shallowNote is what a clone made with a depth limit needs to hear. It is the
// default of actions/checkout, and then neither the merge base nor the commit a
// pull request event names is in the object store.
const shallowNote = "this clone is shallow, so the commits to compare against were never fetched (check out with fetch-depth: 0)"

// ResolveBase turns the base the caller asked for into the commit to compare
// against.
//
// A named ref is resolved as given, so a branch, a tag, a remote-tracking ref and
// a raw object name all work; this is the form a CI job uses, where the event
// payload names the base commit of the pull request. What is returned is the fork
// point of that commit with HEAD, the way "git diff <base>...HEAD" reads it: the
// base branch keeps moving while a pull request is open, and every change merged
// into it since the fork would otherwise be read, reversed, as a change of the
// pull request. When the two share no history, which is what an unrelated line
// and a shallow clone look like, the named commit itself is the base.
//
// With no ref, the base is the fork point too: the merge base with origin/main,
// or with origin/HEAD when the default branch goes by another name, or HEAD~1 in
// a clone that has no remote. When none of the three exists the error names all
// three and wraps ErrNoBase, so the reader learns what was looked for rather than
// only that something was missing.
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
			return "", fmt.Errorf("resolve base %q: %w%s", ref, err, r.baseHint(ctx, ref))
		}
		head, err := r.revision(ctx, "HEAD")
		if err != nil {
			return "", fmt.Errorf("resolve base %q: read HEAD: %w", ref, err)
		}
		fork, err := r.mergeBaseOf(ctx, sha, head)
		if err != nil {
			r.debug("no merge base with the named base, comparing against the commit itself",
				"ref", ref, "base", sha, "reason", firstLine(err.Error()))
			return sha, nil
		}
		r.debug("comparing against the fork point of the named base", "ref", ref, "base", sha, "fork", fork)
		return fork, nil
	}

	tried := make([]string, 0, 3)
	for _, remote := range []string{originMain, originHEAD} {
		sha, err := r.mergeBase(ctx, remote)
		if err == nil {
			r.debug("comparing against the merge base", "remote", remote, "base", sha)
			return sha, nil
		}
		tried = append(tried, fmt.Sprintf("merge base with %s (%s)", remote, firstLine(err.Error())))
	}
	sha, err := r.revision(ctx, headParent)
	if err == nil {
		r.debug("comparing against the parent of HEAD", "base", sha)
		return sha, nil
	}
	tried = append(tried, fmt.Sprintf("%s (%s)", headParent, firstLine(err.Error())))
	shallow := ""
	if r.shallow(ctx) {
		shallow = "; " + shallowNote
	}
	return "", fmt.Errorf("%w: tried the %s%s; name one with --base or --base-file",
		ErrNoBase, strings.Join(tried, ", the "), shallow)
}

// baseHint says what a base that would not resolve usually is: a commit a shallow
// clone never fetched, or a lockfile path typed into --base instead of
// --base-file. It is appended to the error, so the reader is told what to do
// rather than only what git said.
func (r *Repo) baseHint(ctx context.Context, ref string) string {
	hints := make([]string, 0, 2)
	if r.shallow(ctx) {
		hints = append(hints, shallowNote)
	}
	if fi, err := os.Stat(ref); err == nil && !fi.IsDir() {
		hints = append(hints, fmt.Sprintf("%s is a file, did you mean --base-file?", ref))
	}
	if len(hints) == 0 {
		return ""
	}
	return " (" + strings.Join(hints, "; ") + ")"
}

// shallow reports whether the clone was made with a depth limit, so most of the
// history is missing. It answers false when git cannot say, because the hint it
// feeds must never turn a real failure into a wrong explanation.
func (r *Repo) shallow(ctx context.Context) bool {
	out, err := r.run(ctx, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
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
	return r.mergeBaseOf(ctx, remoteSHA, head)
}

// mergeBaseOf returns the commit two object names last had in common. Both
// arguments have to be full object names, which is what revision returns.
func (r *Repo) mergeBaseOf(ctx context.Context, a, b string) (string, error) {
	if err := checkRev(a); err != nil {
		return "", err
	}
	if err := checkRev(b); err != nil {
		return "", err
	}
	out, err := r.run(ctx, "merge-base", "--end-of-options", a, b)
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
