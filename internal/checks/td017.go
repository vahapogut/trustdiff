package checks

import (
	"context"
	"fmt"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

// TD017 version-downgraded reports a lockfile entry whose version went backwards:
// the head file locks a release that sorts below the one the base file locked. Info
// by default, every ecosystem.
//
// Every other check reads the version in front of it. A downgrade is two releases
// that both exist and both check out, so each of them says the version is fine, and
// it is: the change is the direction, and the direction is the one thing none of
// them looks at. TD010 still reports the older release where OSV knows it is
// vulnerable, and that is the case a downgrade is usually noticed by; a package with
// no advisory against it goes back a release without a word.
//
// The two lockfile entries are the whole evidence, as they are for TD016. The
// comparison only ever happens between the two sides of a diff: a ref named on the
// command line has no entry, an added entry has no base entry, and a scan reads one
// file with nothing to compare it to; in each case the check skips itself and says
// which of those it was.
//
// The order is the ecosystem's own, through internal/model/version: PEP 440 for
// PyPI and semantic versions everywhere else, which is what each registry requires
// of a published release. Read 2026-09-10: npm, "Version must be parseable by
// node-semver, which is bundled with npm as a dependency"
// (https://docs.npmjs.com/cli/v11/configuring-npm/package-json); cargo, "Versions
// must have three numeric parts, the major version, the minor version, and the
// patch version" (https://doc.rust-lang.org/cargo/reference/manifest.html); JSR,
// the version field must be a valid SemVer version
// (https://jsr.io/docs/package-configuration); PyPI, the version specifiers
// specification, under which 1.0 and 1.0.0 are one release and every version of a
// later epoch sorts after every version of an earlier one
// (https://packaging.python.org/en/latest/specifications/version-specifiers/).
//
// A lockfile can still hold a version string none of those schemes orders, because
// an entry that installs from somewhere other than the registry records the
// specifier where the version goes: of the entries in this repository's lockfile
// fixtures, the ones that do not parse are all bun.lock lines with a git, path or
// url source ("github:example/gh-dep#9f8e7d6c...", "workspace:packages/bun-types",
// "file:./vendor/local-folder"). A pair the ecosystem's scheme cannot order is
// reported as skipped naming both spellings, never as a pass: it is a question this
// check did not answer, and TD013 and TD016 are the ones that judge such an entry.
//
// Going back a release is a legitimate operation, which is why the default is info
// and not a block. The finding says the project is running an older release than it
// was, and asks for the sentence in the pull request that says why.
//
// Evidence keys:
//
//	base_version  the version the base lockfile locked
//	version       the version the head lockfile locks
//	resolved      the location the head entry names, when it names one
//	lockfile      the lockfile the head entry came from, absent when it carries no location

type versionDowngraded struct{}

func init() { Register(versionDowngraded{}) }

// ID implements Check.
func (versionDowngraded) ID() string { return "TD017" }

// Name implements Check.
func (versionDowngraded) Name() string { return "version-downgraded" }

// Ecosystems implements Check; nil means every ecosystem.
func (versionDowngraded) Ecosystems() []model.Ecosystem { return nil }

// ReadsLockOnly implements LockfileCheck. The two entries are the whole evidence, so
// this runs for a package the registry does not know, which is where a version that
// went backwards has nothing else to report it.
func (versionDowngraded) ReadsLockOnly() bool { return true }

// Run implements Check.
func (c versionDowngraded) Run(_ context.Context, s *Subject) Result {
	if s.Lock == nil {
		return Skip(c.ID(), lockEntryMissing(s))
	}
	if s.BaseLock == nil {
		return Skip(c.ID(), baseEntryMissing())
	}
	base, head := s.BaseLock.Ref.Version, s.Lock.Ref.Version
	order, err := version.Compare(s.Ref.Ecosystem, base, head)
	if err != nil {
		return Skip(c.ID(), fmt.Sprintf("cannot order %q against %q as %s versions: %v", base, head, s.Ref.Ecosystem, err))
	}
	if order <= 0 {
		return Result{}
	}
	evidence := map[string]any{"base_version": base, "version": head}
	addLockEvidence(evidence, s)
	f := NewFinding(c, s, c.title(base, head), c.explain(s, base, head), evidence)
	return Result{Findings: []model.Finding{f}}
}

// title is one line naming both versions in the order they moved.
func (versionDowngraded) title(base, head string) string {
	return fmt.Sprintf("Downgraded from %s to %s", base, head)
}

// explain says which release the project left and what going back costs it.
func (versionDowngraded) explain(s *Subject, base, head string) string {
	return fmt.Sprintf("%s was locked at %s and is now locked at %s, which sorts below it, so every change the releases in between carried, fixes included, is no longer installed. Both releases are real, which is why every other check reads this as an ordinary version",
		s.Ref.Name, base, head)
}
