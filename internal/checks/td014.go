package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TD014 integrity-missing reports a lockfile entry nothing guards. Two signals,
// each its own finding, both warn by default:
//
//   - missing-hash: the entry records no integrity hash, so an install has no way
//     to tell the bytes it downloaded from any other bytes the host serves.
//   - plain-http: the entry was resolved over plain http, so the download is
//     neither authenticated nor encrypted and anyone on the way can replace it.
//
// The check applies to every ecosystem and reads Subject.Lock and nothing else; a
// ref named on the command line has no lockfile entry behind it and is reported as
// skipped.
//
// One entry is exempt from missing-hash: a git entry whose resolved location pins a
// full forty character commit sha. The sha is the integrity there, because git
// addresses a commit by the hash of its content, and every ecosystem writes the
// revision into the location rather than into an integrity field. A git entry that
// pins a branch or a tag instead is reported, and its explanation states the rule it
// missed.
//
// A bundled entry is exempt too, and this one the lockfile states outright. npm
// writes "inBundle": true for a dependency whose bytes ship inside the archive of
// the package that carries it: there is nothing separate to fetch, and the parent's
// own hash covers those bytes. Reporting it would be reporting the same artifact
// twice, and it is not a rare shape. npm's own lockfile bundles 677 of its 1009
// entries, which is 677 warnings about hashes that are exactly where they belong.
//
// A local directory is not exempt: it has no artifact to hash either, but nothing in
// the lockfile says the bytes are covered by something else, and a workspace member
// is the shape a repository can silence with an allow entry. The explanation says
// which case it is rather than claiming that nothing guards it, and the source
// evidence key is there so that telling them apart does not mean opening the
// lockfile.
//
// Evidence keys:
//
//	signal     missing-hash or plain-http
//	source     where the entry was resolved from: registry, git, url, path or unknown
//	integrity  the hash the entry records, absent when it records none
//	resolved   the location as the lockfile records it, absent when the file states none
//	lockfile   the lockfile the entry came from, absent when the subject carries no location

type integrityMissing struct{}

func init() { Register(integrityMissing{}) }

// ID implements Check.
func (integrityMissing) ID() string { return "TD014" }

// Name implements Check.
func (integrityMissing) Name() string { return "integrity-missing" }

// Ecosystems implements Check; nil means every ecosystem.
func (integrityMissing) Ecosystems() []model.Ecosystem { return nil }

// ReadsLockOnly implements LockfileCheck. The entry is the whole evidence here, so
// an entry nothing guards is reported whether or not the registry has ever heard of
// the package.
func (integrityMissing) ReadsLockOnly() bool { return true }

// Run implements Check.
func (c integrityMissing) Run(_ context.Context, s *Subject) Result {
	if s.Lock == nil {
		return Skip(c.ID(), lockEntryMissing(s))
	}
	var findings []model.Finding
	if f, fired := c.missingHash(s); fired {
		findings = append(findings, f)
	}
	if f, fired := c.plainHTTP(s); fired {
		findings = append(findings, f)
	}
	return Result{Findings: findings}
}

// missingHash reports an entry with no integrity hash, except a git entry that
// pins a full commit sha.
func (c integrityMissing) missingHash(s *Subject) (model.Finding, bool) {
	if strings.TrimSpace(s.Lock.Integrity) != "" {
		return model.Finding{}, false
	}
	if s.Lock.Bundled {
		// The lockfile says these bytes ship inside another package's archive, so
		// the hash that guards them is that package's, and its own entry carries it.
		return model.Finding{}, false
	}
	source := entrySource(s.Lock)
	if source == lockfile.SourceGit {
		if _, pinned := pinnedCommit(s.Lock.Resolved); pinned {
			return model.Finding{}, false
		}
	}

	evidence := map[string]any{"signal": "missing-hash", "source": string(source)}
	addLockEvidence(evidence, s)

	var b strings.Builder
	fmt.Fprintf(&b, "%s records no integrity hash for %s", lockfileNoun(s), s.Ref)
	if s.Lock.Resolved != "" {
		fmt.Fprintf(&b, ", resolved from %s", s.Lock.Resolved)
	}
	// What is missing depends on what the entry would fetch, so the sentence after
	// the first one does too: an artifact downloaded from somewhere is unguarded, a
	// directory has nothing to guard, and an entry that states no origin says
	// neither where the bytes come from nor what would check them.
	const unguarded = ". Nothing ties the entry to the bytes an install downloads, so a replaced archive or a compromised mirror is installed without complaint and the lockfile still looks unchanged."
	switch source {
	case lockfile.SourceGit:
		b.WriteString(unguarded)
		b.WriteString(" A git entry needs no hash when its location pins a full forty character commit sha, because the sha is the integrity; this one pins a branch or a tag instead.")
	case lockfile.SourcePath:
		b.WriteString(". The entry is a local directory, which has nothing to download and so nothing to hash, so there is nothing here for an install to verify against; a workspace member is silenced with an allow entry for integrity-missing with a package glob.")
	case lockfile.SourceUnknown:
		b.WriteString(". Nothing in the entry ties it to the bytes an install downloads.")
		if s.Ref.Ecosystem == model.NPM {
			b.WriteString(" An npm entry with neither a location nor a hash is usually a bundled dependency, whose bytes travel inside the archive of the package that carries it and are covered by that package's hash; the lockfile does not say so, which is why this is reported rather than assumed.")
		} else {
			b.WriteString(" The entry does not say where it comes from either, so what an install would fetch, and what would check it, are both unstated.")
		}
	default:
		b.WriteString(unguarded)
	}
	return NewFinding(c, s, "no integrity hash in the lockfile", b.String(), evidence), true
}

// plainHTTP reports an entry resolved over plain http.
func (c integrityMissing) plainHTTP(s *Subject) (model.Finding, bool) {
	if !insecureTransport(s.Lock.Resolved) {
		return model.Finding{}, false
	}

	hash := strings.TrimSpace(s.Lock.Integrity)
	evidence := map[string]any{"signal": "plain-http", "source": string(entrySource(s.Lock))}
	if hash != "" {
		evidence["integrity"] = s.Lock.Integrity
	}
	addLockEvidence(evidence, s)

	var b strings.Builder
	fmt.Fprintf(&b, "%s resolves %s over plain http (%s). The download is neither authenticated nor encrypted, so anyone between the machine and that host can read it and can serve something else in its place.",
		lockfileNoun(s), s.Ref, s.Lock.Resolved)
	if hash != "" {
		fmt.Fprintf(&b, " The entry does record %s, which the package manager verifies after the download, so a substitution would be caught; the location should still be https.", hash)
	} else {
		b.WriteString(" The entry records no hash either, so nothing would catch the substitution.")
	}
	return NewFinding(c, s, "resolved over plain http", b.String(), evidence), true
}

// insecureTransport reports whether a resolved location was fetched over plain
// http. A git source carries the scheme behind a "git+" prefix (Cargo.lock writes
// "git+https://github.com/acme/lib?rev=..."), and RFC 3986 makes schemes case
// insensitive, so the prefix is trimmed and the comparison is made in lower case.
func insecureTransport(resolved string) bool {
	scheme := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(resolved)), "git+")
	return strings.HasPrefix(scheme, "http://")
}
