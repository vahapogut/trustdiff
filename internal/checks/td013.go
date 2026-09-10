package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TD013 exotic-source reports a lockfile entry resolved from somewhere other than
// the ecosystem's registry: a git repository, a URL, a directory on the machine, or
// an origin the file does not state. It applies to every ecosystem. It reads
// Subject.Lock and nothing else, so a ref named on the command line, which has no
// lockfile entry behind it, is reported as skipped.
//
// A git or URL entry is reported at the level the policy sets, block by default.
// What the registry does for a published release it does not do for these: the
// release cannot be yanked, advisories are not matched against it, and the
// publisher, the provenance and the download history that the other checks compare
// are simply absent. The version number the lockfile records is then whatever the
// fetched manifest claimed rather than a version anyone published. On top of that a
// git reference that pins no commit sha, and any URL, can serve different bytes
// tomorrow without the lockfile changing.
//
// A bundled entry is not reported at all. npm writes "inBundle": true for a
// dependency whose bytes ship inside the archive of the package that carries it, so
// it has no source of its own and the question belongs to that package's entry.
// npm's own lockfile bundles 677 of its 1009 entries, and a line for each would bury
// everything else in the report.
//
// A directory and an unstated origin are reported at info instead, whatever level
// the policy sets for the check. Neither is the signal this check exists for. A path
// entry is what a monorepo writes for its own packages: ripgrep 14.1.1's Cargo.lock
// carries ten of them and Superset's package-lock.json twenty five, so blocking
// there fails the gate on unmodified upstream code and teaches people to turn the
// check off, which is the worst outcome available. An
// entry with no stated origin is usually an npm bundled dependency, whose bytes
// travel inside the archive of the package that carries them and are covered by that
// package's hash. Both stay in the report, because an entry that does not come from
// the registry is worth seeing in a diff and the source evidence key says which it
// is; neither fails a gate on its own. A project that wants them out of the report
// altogether uses an allow entry (check: exotic-source with a package glob).
//
// Evidence keys:
//
//	source    where the entry was resolved from: git, url, path or unknown
//	resolved  the location as the lockfile records it, absent when the file states none
//	lockfile  the lockfile the entry came from, absent when the subject carries no location

type exoticSource struct{}

func init() { Register(exoticSource{}) }

// ID implements Check.
func (exoticSource) ID() string { return "TD013" }

// Name implements Check.
func (exoticSource) Name() string { return "exotic-source" }

// Ecosystems implements Check; nil means every ecosystem.
func (exoticSource) Ecosystems() []model.Ecosystem { return nil }

// ReadsLockOnly implements LockfileCheck. The entry is the whole evidence here, so
// this runs for a package the registry does not know, which is the case it exists
// for: a git or a URL dependency is a name no registry answers.
func (exoticSource) ReadsLockOnly() bool { return true }

// Run implements Check.
func (c exoticSource) Run(_ context.Context, s *Subject) Result {
	if s.Lock == nil {
		return Skip(c.ID(), lockEntryMissing(s))
	}
	if s.Lock.Bundled {
		// A bundled dependency has no source of its own: its bytes travel inside the
		// archive of the package that carries it, and that package's entry is where
		// the question belongs. npm's own lockfile bundles two thirds of its
		// entries, and a line for each of them would bury everything else.
		return Result{}
	}
	source := entrySource(s.Lock)
	if source == lockfile.SourceRegistry {
		return Result{}
	}

	evidence := map[string]any{"source": string(source)}
	addLockEvidence(evidence, s)
	f := NewFinding(c, s, c.title(s, source), c.explain(s, source), evidence)
	if reportedAtInfo(source) {
		// Never above info for these two, whatever the policy sets for the check: a
		// workspace member and a bundled dependency are reported so that they are
		// visible, not so that they fail a gate. A policy that turned the check off
		// keeps it off, because the runner never reaches a check set to off.
		f.Level = min(f.Level, model.LevelInfo)
	}
	return Result{Findings: []model.Finding{f}}
}

// reportedAtInfo reports whether a source is one of the two this check states
// rather than judges: a directory on the machine and an origin the file does not
// state. See the package comment above for why.
func reportedAtInfo(source lockfile.Source) bool {
	return source == lockfile.SourcePath || source == lockfile.SourceUnknown
}

// title names the source the entry came from and the registry it did not come from.
func (exoticSource) title(s *Subject, source lockfile.Source) string {
	if source == lockfile.SourceUnknown {
		return "the lockfile does not say where this version was resolved from"
	}
	return fmt.Sprintf("resolved from %s instead of %s", sourceNoun(source), registryName(s.Ref.Ecosystem))
}

// explain states where the entry comes from, what the registry is therefore not
// doing for it, and what that means for this particular kind of source.
func (exoticSource) explain(s *Subject, source lockfile.Source) string {
	from := registryName(s.Ref.Ecosystem)
	var b strings.Builder
	if source == lockfile.SourceUnknown {
		fmt.Fprintf(&b, "%s does not say where %s was resolved from, so the entry cannot be read as a release from %s.",
			lockfileNoun(s), s.Ref, from)
	} else {
		fmt.Fprintf(&b, "%s resolves %s from %s%s rather than from %s.",
			lockfileNoun(s), s.Ref, sourceNoun(source), inParentheses(s.Lock.Resolved), from)
	}
	manifest := "the fetched manifest claimed"
	if source == lockfile.SourcePath {
		manifest = "the manifest in that directory says"
	}
	fmt.Fprintf(&b, " None of the registry's protections apply to it: the release cannot be yanked, advisories are not matched against it, and there is no publisher, provenance or download history to compare with the previous version. The version number the lockfile records is what %s, not a version anyone published.", manifest)

	switch source {
	case lockfile.SourceGit:
		if rev, ok := pinnedCommit(s.Lock.Resolved); ok {
			fmt.Fprintf(&b, " The revision %s is a full commit sha, so at least the content is pinned.", rev)
		} else {
			b.WriteString(" The entry pins no commit sha, so the branch or tag it names can move and install different code tomorrow.")
		}
	case lockfile.SourceURL:
		b.WriteString(" Whoever controls that URL can replace what it serves, and the lockfile would not change.")
	case lockfile.SourcePath:
		b.WriteString(" A path entry is a local directory: nothing was fetched, so there is nothing to check. A workspace member looks exactly like this.")
	case lockfile.SourceUnknown:
		if s.Ref.Ecosystem == model.NPM {
			b.WriteString(" npm records neither a location nor a hash for a dependency bundled inside another package's archive, which is the usual reason for an entry with no stated origin; those bytes travel with the package that carries them and are covered by its hash.")
		}
	}
	if reportedAtInfo(source) {
		b.WriteString(" This is reported at info rather than at the level the policy sets for exotic-source, because that level is meant for a version fetched from a git repository or a URL, which is what a pull request can repoint under review, and not for an entry a monorepo or a bundling package manager writes for itself. An allow entry for exotic-source with a package glob takes it out of the report altogether.")
	}
	return b.String()
}

// sourceNoun names a source in prose. Only the sources this check reports reach
// it; anything else, including a source a later parser adds, is named as unstated
// rather than described wrongly.
func sourceNoun(source lockfile.Source) string {
	switch source {
	case lockfile.SourceGit:
		return "a git repository"
	case lockfile.SourceURL:
		return "a URL"
	case lockfile.SourcePath:
		return "a local directory"
	default:
		return "an unstated source"
	}
}

// The helpers below are shared by the checks that judge the lockfile entry rather
// than the registry: TD013 and TD014 read the head entry, TD016 and TD017 read both
// sides of a diff.

// lockEntryMissing words the skip of a lockfile check for a subject with no entry
// behind it, which is every ref named on the command line.
func lockEntryMissing(s *Subject) string {
	return fmt.Sprintf("no lockfile entry for %s: the ref was named directly, not read from a lockfile", s.Ref)
}

// baseEntryMissing words the skip of a check that needs both sides of a diff and
// was given one. It says the same thing for TD016 and TD017, which is what the demo
// output and the README sample both print, so it is said once.
func baseEntryMissing() string {
	return "no entry in the base lockfile to compare with: the entry is new, or the run compared against no base"
}

// entrySource reads an entry's source and takes the zero value for unknown: a
// parser that did not state where an entry came from has not vouched for the
// registry, and the check would rather ask than assume.
func entrySource(e *lockfile.Entry) lockfile.Source {
	if e.Source == "" {
		return lockfile.SourceUnknown
	}
	return e.Source
}

// lockfilePath returns the lockfile the subject's entry was read from, empty when
// the subject carries no location. The entry itself does not hold the path; the
// runner puts it on Subject.Location together with the entry's line.
func lockfilePath(s *Subject) string {
	if s.Location == nil {
		return ""
	}
	return s.Location.Path
}

// lockfileNoun names the lockfile in prose, falling back to "the lockfile" when the
// subject carries no location.
func lockfileNoun(s *Subject) string {
	if path := lockfilePath(s); path != "" {
		return path
	}
	return "the lockfile"
}

// inParentheses wraps a value for prose, or returns nothing for an empty one.
func inParentheses(value string) string {
	if value == "" {
		return ""
	}
	return " (" + value + ")"
}

// addLockEvidence adds the entry's resolved location and the lockfile path, each
// only when there is one: an evidence key is present when the lockfile records a
// value for it, the way TD011 and TD012 handle their optional keys.
func addLockEvidence(evidence map[string]any, s *Subject) {
	if s.Lock != nil && s.Lock.Resolved != "" {
		evidence["resolved"] = s.Lock.Resolved
	}
	if path := lockfilePath(s); path != "" {
		evidence["lockfile"] = path
	}
}

// commitShaLen is the length of a git commit sha written in full hexadecimal.
const commitShaLen = 40

// pinnedCommit returns the full commit sha a resolved location pins, when it pins
// one. Lockfiles write the revision next to the remote rather than in a field of
// its own, so the sha is looked for as a run of exactly forty hexadecimal
// characters (the length of a git commit sha) that no letter or digit runs into,
// which keeps a longer hash and a word that happens to be hexadecimal out.
//
// Spellings read from the committed fixtures on 2026-09-09: package-lock.json
// writes the fragment form "git+ssh://git@github.com/dmapper/dom-to-image.git#a7c386a8ea813930f05449ac71ab4be0c262dff3"
// (internal/lockfile/npm/testdata/superset-frontend-package-lock.json) and
// pnpm-lock.yaml a codeload tarball ending in the revision
// (internal/lockfile/pnpm/testdata/git-protocol-v9.yaml); Cargo.lock puts the
// revision in the fragment of its git source, after an optional "?rev=" or
// "?branch=" query.
func pinnedCommit(resolved string) (string, bool) {
	for i := 0; i < len(resolved); {
		if !isHexDigit(resolved[i]) {
			i++
			continue
		}
		start := i
		for i < len(resolved) && isHexDigit(resolved[i]) {
			i++
		}
		if i-start != commitShaLen {
			continue
		}
		if start > 0 && isAlphanumeric(resolved[start-1]) {
			continue
		}
		if i < len(resolved) && isAlphanumeric(resolved[i]) {
			continue
		}
		return resolved[start:i], true
	}
	return "", false
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func isAlphanumeric(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
