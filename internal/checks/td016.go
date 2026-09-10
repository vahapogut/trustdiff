package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TD016 lockfile-entry-changed reports a lockfile entry that changed without its
// version changing. Four signals, one finding, block by default:
//
//   - integrity-changed: the entry records another hash for the version it already
//     locked.
//   - integrity-removed: the hash that guarded the version is gone.
//   - source-changed: the same version now installs from somewhere else, a registry
//     install becoming a git or a URL one.
//   - resolved-changed: the same version resolves from another location, for an
//     entry that is not a registry install.
//
// Every other check is about a version. This one is about the case where the version
// is the one thing that did not move, and that case is invisible to all of them. A
// published release is immutable on every registry this tool reads, so one version
// under two hashes does not mean the registry served two things: it means the
// lockfile was written against bytes that were not that release. The diff has always
// classified such an entry as changed and evaluated it, and every check then agreed
// the version was fine, because it was.
//
// The comparison only ever happens between the two sides of a diff. A ref named on
// the command line has no entry, an added entry has no base entry, and a scan reads
// one file with nothing to compare it to; in each case the check skips itself and
// says which of those it was.
//
// Two moves are stated rather than judged, and capped at info whatever the policy
// sets: an entry that moved onto the registry, which is what a project does when it
// stops vendoring a dependency, and a directory that moved to another directory,
// which is a workspace being rearranged.
//
// A registry entry's resolved location is not compared at all. It names the mirror
// the artifact was fetched through, and moving a project to a mirror rewrites every
// one of them without changing a byte of what is installed. internal/gitdiff ignores
// it for that reason and this check has to agree, or a mirror migration reports the
// whole file.
//
// Evidence keys:
//
//	signal          integrity-changed, integrity-removed, source-changed or resolved-changed
//	base_integrity  the hash the base lockfile recorded, for the two hash signals
//	integrity       the hash the head lockfile records, for integrity-changed
//	base_source     the source the base entry named, for source-changed
//	source          the source the head entry names, for source-changed
//	base_resolved   the location the base entry named, for resolved-changed
//	resolved        the location the head entry names, when it names one
//	lockfile        the lockfile the head entry came from, absent when it carries no location

type lockfileEntryChanged struct{}

func init() { Register(lockfileEntryChanged{}) }

// ID implements Check.
func (lockfileEntryChanged) ID() string { return "TD016" }

// Name implements Check.
func (lockfileEntryChanged) Name() string { return "lockfile-entry-changed" }

// Ecosystems implements Check; nil means every ecosystem.
func (lockfileEntryChanged) Ecosystems() []model.Ecosystem { return nil }

// ReadsLockOnly implements LockfileCheck. The two entries are the whole evidence, so
// this runs for a package the registry does not know, which is where an entry that
// was repointed is least likely to be caught by anything else.
func (lockfileEntryChanged) ReadsLockOnly() bool { return true }

// Run implements Check.
func (c lockfileEntryChanged) Run(_ context.Context, s *Subject) Result {
	if s.Lock == nil {
		return Skip(c.ID(), lockEntryMissing(s))
	}
	if s.BaseLock == nil {
		return Skip(c.ID(), baseEntryMissing())
	}
	if s.BaseLock.Ref.Version != s.Lock.Ref.Version {
		// The version moved, which is what every other check is about.
		return Result{}
	}

	signal, evidence := c.compare(s)
	if signal == "" {
		return Result{}
	}
	evidence["signal"] = signal
	addLockEvidence(evidence, s)
	f := NewFinding(c, s, c.title(signal), c.explain(s, signal), evidence)
	if c.statedRatherThanJudged(s) {
		f.Level = min(f.Level, model.LevelInfo)
	}
	return Result{Findings: []model.Finding{f}}
}

// compare returns the one signal worth reporting and the evidence for it, or an
// empty signal when the two entries install the same bytes from the same place. The
// order is the order of severity: a hash that changed says the most.
func (c lockfileEntryChanged) compare(s *Subject) (string, map[string]any) {
	base, head := s.BaseLock, s.Lock
	baseHash, headHash := strings.TrimSpace(base.Integrity), strings.TrimSpace(head.Integrity)
	switch {
	case baseHash != "" && headHash == "":
		return "integrity-removed", map[string]any{"base_integrity": baseHash}
	case hashesDisagree(baseHash, headHash):
		return "integrity-changed", map[string]any{"base_integrity": baseHash, "integrity": headHash}
	}
	baseSource, headSource := entrySource(base), entrySource(head)
	if baseSource != headSource {
		return "source-changed", map[string]any{"base_source": string(baseSource), "source": string(headSource)}
	}
	if headSource != lockfile.SourceRegistry && base.Resolved != head.Resolved {
		return "resolved-changed", map[string]any{"base_resolved": base.Resolved, "resolved": head.Resolved}
	}
	return "", nil
}

// statedRatherThanJudged reports the two moves this check states rather than judges.
func (lockfileEntryChanged) statedRatherThanJudged(s *Subject) bool {
	baseSource, headSource := entrySource(s.BaseLock), entrySource(s.Lock)
	if baseSource == lockfile.SourcePath && headSource == lockfile.SourcePath {
		return true
	}
	return baseSource != lockfile.SourceRegistry && headSource == lockfile.SourceRegistry
}

// hashesDisagree reports whether two integrity strings name one algorithm in common
// and give it different digests.
//
// Comparing the strings themselves would be wrong. A lockfile rewritten by a newer
// installer carries the same artifact under a stronger algorithm, which is what npm
// did when it moved from sha1 to sha512, so two integrity strings that share no
// algorithm are a re-encoding and say nothing about the bytes. Two that share one
// and disagree on its digest are two different artifacts under one version.
func hashesDisagree(base, head string) bool {
	if base == "" || head == "" {
		return false
	}
	baseDigests, headDigests := integrityDigests(base), integrityDigests(head)
	for algorithm, digest := range baseDigests {
		if other, both := headDigests[algorithm]; both && other != digest {
			return true
		}
	}
	return false
}

// integrityDigests splits an integrity string into one digest per algorithm. It
// reads the three spellings the parsers record: npm's subresource integrity, which
// separates the algorithm with a dash and may carry several of them, the
// "sha256:hex" a requirements file writes, and the bare checksum of a Cargo.lock,
// which names no algorithm and is keyed by the empty string.
func integrityDigests(integrity string) map[string]string {
	out := map[string]string{}
	for _, field := range strings.Fields(integrity) {
		algorithm, digest := "", field
		if name, rest, found := strings.Cut(field, "-"); found {
			algorithm, digest = name, rest
		} else if name, rest, found := strings.Cut(field, ":"); found {
			algorithm, digest = name, rest
		}
		out[strings.ToLower(algorithm)] = digest
	}
	return out
}

// title is one line naming what moved.
func (lockfileEntryChanged) title(signal string) string {
	switch signal {
	case "integrity-removed":
		return "Same version, and the integrity hash that guarded it is gone"
	case "integrity-changed":
		return "Same version, another integrity hash"
	case "source-changed":
		return "Same version, another source"
	default:
		return "Same version, another resolved location"
	}
}

// explain gives both values and says why one version under two of them matters.
func (lockfileEntryChanged) explain(s *Subject, signal string) string {
	switch signal {
	case "integrity-removed":
		return fmt.Sprintf("%s stays at %s and the hash that guarded it, %s, is gone, so nothing verifies the bytes an install fetches for it",
			s.Ref.Name, s.Ref.Version, strings.TrimSpace(s.BaseLock.Integrity))
	case "integrity-changed":
		return fmt.Sprintf("%s stays at %s under a different hash: %s became %s. A published release is immutable, so one version cannot have two hashes unless the file was written against bytes that were not that release",
			s.Ref.Name, s.Ref.Version, strings.TrimSpace(s.BaseLock.Integrity), strings.TrimSpace(s.Lock.Integrity))
	case "source-changed":
		return fmt.Sprintf("%s stays at %s and now installs from %s where it installed from %s",
			s.Ref.Name, s.Ref.Version, entrySource(s.Lock), entrySource(s.BaseLock))
	default:
		return fmt.Sprintf("%s stays at %s and now resolves from %s where it resolved from %s",
			s.Ref.Name, s.Ref.Version, s.Lock.Resolved, s.BaseLock.Resolved)
	}
}
