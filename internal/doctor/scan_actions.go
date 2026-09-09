package doctor

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// actionsScanner reads every workflow file and reports each uses: reference that
// is not pinned to a full commit sha.
//
// A workflow step is a dependency with no lockfile: "uses: some/action@v4" runs
// whatever that tag points at the moment the job starts, and a tag can be moved.
// It is also the dependency with the most access, because it runs inside the job
// that holds the repository's tokens. GitHub's own guidance is that a full length
// commit sha is the only immutable reference, and that is what this checks.
//
// Nothing here writes. Replacing a tag with a sha means resolving it against
// GitHub, which is a network call this tool will not make behind the user's back,
// and choosing which commit to trust is a decision that belongs to a person.
type actionsScanner struct{}

// usesLine matches a step's uses: value. A workflow writes it as one scalar on one
// line, so a line scan gives the right answer and the right line number, and a
// value that is quoted or that carries a trailing comment is trimmed below.
var usesLine = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*(\S+)`)

// fullSHA is a git object name written in full, which is the only form that
// cannot be moved. Forty hexadecimal characters today, and sixty four when git
// finishes moving to sha-256, so both lengths are accepted.
var fullSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)

// tagPinnedByDesign are the published workflows that must be referenced by tag.
// The SLSA generator is the one such case: its verifier checks the reference of
// the workflow that built an artifact, so a sha reference makes verification fail.
// Its own documentation says the builders must be referenced by tag, and adds that
// this conflicts with GitHub's pinning advice.
var tagPinnedByDesign = []string{
	"slsa-framework/slsa-github-generator",
}

// Scan walks the workflow files and judges every reference in them.
func (actionsScanner) Scan(root string, m *Manager, p Params) ([]Result, error) {
	files := workflowFiles(m)
	results := make([]Result, 0, len(files))
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- the path is one this run found under the directory the user named
		if err != nil {
			results = append(results, Result{
				Status: StatusUnreadable,
				Detail: fmt.Sprintf("could not be read: %v", err),
				File:   rel,
			})
			continue
		}
		results = append(results, scanWorkflow(rel, string(data), p)...)
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// scanWorkflow judges one file. A reference that is not pinned gets a line of its
// own, because that is what somebody has to go and fix. A file where every
// reference is pinned gets one line saying so rather than one line per step: a
// repository with five workflows and thirty steps would otherwise fill a scorecard
// with thirty lines that say nothing is wrong.
func scanWorkflow(rel, text string, p Params) []Result {
	var problems []Result
	pinned := 0
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		match := usesLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		ref := strings.Trim(match[1], `"'`)
		if ref == "" || strings.HasPrefix(ref, "#") {
			continue
		}
		status, detail := judgeUses(ref, p)
		if status == StatusSet {
			pinned++
			continue
		}
		problems = append(problems, Result{
			Status:  status,
			Detail:  detail,
			File:    rel,
			Line:    i + 1,
			Current: ref,
		})
	}
	switch {
	case len(problems) > 0:
		return problems
	case pinned == 1:
		return []Result{{Status: StatusSet, Detail: "the one action it uses is pinned", File: rel}}
	case pinned > 1:
		return []Result{{
			Status: StatusSet,
			Detail: fmt.Sprintf("all %d of the actions it uses are pinned", pinned),
			File:   rel,
		}}
	}
	// A workflow that uses no action at all has nothing to pin, and saying so would
	// be a line about nothing.
	return nil
}

// judgeUses decides what one reference is worth.
func judgeUses(ref string, p Params) (Status, string) {
	switch {
	case strings.HasPrefix(ref, "./"), strings.HasPrefix(ref, "../"):
		// An action in this repository is reviewed with the repository, and there
		// is no other version of it to pin to.
		return StatusSet, fmt.Sprintf("%s is in this repository", ref)
	case strings.HasPrefix(ref, "docker://"):
		return StatusSet, fmt.Sprintf("%s is a container image, which its own digest pins", ref)
	}
	repo, version, ok := strings.Cut(ref, "@")
	if !ok {
		return StatusWrong, fmt.Sprintf("%s names no version at all, so the job runs whatever the default branch holds", ref)
	}
	if fullSHA.MatchString(version) {
		return StatusSet, ""
	}
	if owner := byDesign(repo); owner != "" {
		if fullVersionTag(version) {
			return StatusSet, fmt.Sprintf("%s is pinned by design: %s verifies the reference of the workflow that built an artifact, so a commit sha there would fail verification", ref, owner)
		}
		return StatusWrong, fmt.Sprintf("%s must carry a full version tag such as @v2.1.0, because %s verifies the reference and refuses a shortened one", ref, owner)
	}
	if allowed(repo, p.PinExceptions) {
		return StatusSet, fmt.Sprintf("%s is on the policy's list of references allowed to stay on a tag", ref)
	}
	return StatusWrong, fmt.Sprintf("%s is a tag, which can be moved to another commit without the workflow changing", ref)
}

// byDesign returns the repository a reference belongs to when it is one of the
// published workflows that must stay on a tag, and "" otherwise.
func byDesign(repo string) string {
	for _, owner := range tagPinnedByDesign {
		if repo == owner || strings.HasPrefix(repo, owner+"/") {
			return owner
		}
	}
	return ""
}

// fullVersionTag reports whether a tag names a whole version, vX.Y.Z, which is
// what the SLSA generator requires: a shortened @v2 fails its verification.
func fullVersionTag(version string) bool {
	rest := strings.TrimPrefix(version, "v")
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// allowed reports whether a policy exception covers the repository. The patterns
// are globs over "owner/repo" or "owner/repo/path", matched the way a path is, so
// "myorg/*" covers an organization's own actions and nothing else.
func allowed(repo string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == repo {
			return true
		}
		if ok, err := path.Match(pattern, repo); err == nil && ok {
			return true
		}
	}
	return false
}

// workflowFiles are the files detection found for this manager, sorted, which is
// every .yml and .yaml under .github/workflows.
func workflowFiles(m *Manager) []string {
	out := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		lower := strings.ToLower(f)
		if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}
