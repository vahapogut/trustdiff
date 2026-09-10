// Package lockfile reads the lockfiles a project commits and turns them into the
// entries the checks evaluate: which package version is pinned, where it was
// resolved from, what hash guards it, whether the project depends on it directly,
// and the line it sits on so a finding can point at it.
//
// Each ecosystem's format lives in its own subpackage and registers a Parser here,
// so adding a format is one file plus its registration. A parser reads only what
// the checks need and never fails a whole file for one unreadable entry: an entry
// it cannot make sense of is dropped with a reason on the Lockfile, because a
// lockfile that half parses is still worth evaluating.
package lockfile

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vahapogut/trustdiff/internal/model"
)

// ErrUnsupported means no parser recognizes the file.
var ErrUnsupported = errors.New("no parser for this lockfile")

// Source is where a lockfile entry says the package came from.
type Source string

// The sources an entry can name. Anything but SourceRegistry is what TD013
// exotic-source reports.
const (
	// SourceRegistry is the ecosystem's own registry.
	SourceRegistry Source = "registry"
	// SourceGit is a git repository.
	SourceGit Source = "git"
	// SourceURL is a tarball or archive fetched over http or https.
	SourceURL Source = "url"
	// SourcePath is a directory on the machine (a workspace member or a local override).
	SourcePath Source = "path"
	// SourceUnknown is an entry whose origin the file does not state.
	SourceUnknown Source = "unknown"
)

// Entry is one locked package version.
type Entry struct {
	// Ref is the ecosystem, name and version. Names carry the ecosystem's
	// canonical spelling, as model.NormalizeName defines it.
	Ref model.PackageRef
	// Source says where the version comes from.
	Source Source
	// Resolved is the location the file records, as written: a registry URL, a git
	// remote with its revision, a file path. Empty when the file states none.
	Resolved string
	// Integrity is the hash the file records, as written ("sha512-...", "sha256:..."),
	// empty when the entry carries none.
	Integrity string
	// Direct is true when the project itself depends on the package, as opposed to
	// a dependency pulled in by another. "The project" is the whole workspace: a
	// dependency a workspace member declares is direct too, because a member's
	// manifest is a file of the repository like the root's, and every parser here
	// reads it that way. A parser that cannot tell leaves it false and says so.
	Direct bool
	// Dev is true when the entry is only needed to develop or test the project.
	Dev bool
	// Optional is true when an install may leave the entry out.
	Optional bool
	// Bundled is true when the entry ships inside another package's archive, so it
	// has no artifact of its own: nothing is fetched for it and the parent's hash
	// is what guards its bytes.
	Bundled bool
	// Line is the 1-based line the entry starts on, for the SARIF location. Zero
	// when the parser could not place it.
	Line int
}

// Lockfile is one parsed file.
type Lockfile struct {
	// Path is the file as the caller named it.
	Path string
	// Format is the parser's name, for example "package-lock.json".
	Format string
	// Ecosystem is the ecosystem the entries belong to. A format that mixes them
	// (deno.lock holds both npm and JSR entries) leaves this empty and the entries
	// carry their own.
	Ecosystem model.Ecosystem
	// Version is the format version the file declares, when it has one.
	Version string
	// Entries are the locked versions, in the order the file lists them.
	Entries []Entry
	// Dropped records entries the parser could not read, one line each, so a
	// partial parse is visible rather than silent.
	Dropped []string
}

// Add appends an entry.
func (l *Lockfile) Add(e Entry) { //nolint:gocritic // an Entry is small and the call sites read better by value
	l.Entries = append(l.Entries, e)
}

// Drop records an entry the parser could not read.
func (l *Lockfile) Drop(format string, args ...any) {
	l.Dropped = append(l.Dropped, fmt.Sprintf(format, args...))
}

// Refs returns the refs of every entry, deduplicated, in first-seen order. This is
// the coarser of the two rules in this file, and deliberately so: it says what the
// run has to fetch, and one registry answer serves every line that locks a version,
// however many of them there are and whatever they install. Installs is the one that
// decides what gets evaluated, and it keeps two lines apart when they disagree.
func (l *Lockfile) Refs() []model.PackageRef {
	seen := make(map[model.PackageRef]bool, len(l.Entries))
	out := make([]model.PackageRef, 0, len(l.Entries))
	for _, e := range l.Entries {
		if seen[e.Ref] {
			continue
		}
		seen[e.Ref] = true
		out = append(out, e.Ref)
	}
	return out
}

// artifactKey identifies what one entry installs: the exact version, where it comes
// from, the hash that guards it and, for everything the ecosystem's own registry does
// not serve, the location itself. A registry entry's location is left out because
// moving a project to a mirror rewrites every one of them without changing a byte of
// what is installed, which is the exemption internal/gitdiff and TD016 both make.
//
// The hash is compared as written, which is stricter than TD016's hashesDisagree, and
// deliberately so. This key decides whether two lines are one thing to evaluate:
// keeping a copy that turns out to be the same artifact costs one card in the report,
// and folding one that is not hides whatever that line installs. TD016 reports rather
// than groups, and a false block is expensive, so it errs the other way.
//
// An Entry field that belongs to the artifact belongs in here too, or two lines that
// disagree about it quietly become one.
type artifactKey struct {
	ref       model.PackageRef
	source    Source
	integrity string
	resolved  string
}

func (e *Entry) artifactKey() artifactKey {
	k := artifactKey{ref: e.Ref, source: e.Source, integrity: e.Integrity}
	if k.source == "" {
		// A parser that stated no source has not vouched for the registry, which is
		// how the checks read an empty one too.
		k.source = SourceUnknown
	}
	if k.source != SourceRegistry {
		k.resolved = e.Resolved
	}
	return k
}

// SameArtifact reports whether two entries install the same thing. It is the question
// behind both readers of this package: whether two lines of one file are one install
// to evaluate, and whether the entry a change left behind and the entry it wrote are
// the same artifact under one version.
func SameArtifact(a, b *Entry) bool {
	return a.artifactKey() == b.artifactKey()
}

// statesItsArtifact reports whether the entry says anything about what it installs. A
// bundled entry never does: npm records neither a location nor a hash for a dependency
// whose bytes ship inside the archive of the package that carries it, and npm's own
// lockfile bundles two thirds of its entries. Nor does a line with no location, no
// hash and no stated source, which is the same thing written by a parser that has no
// flag for it.
func (e *Entry) statesItsArtifact() bool {
	if e.Bundled {
		return false
	}
	return e.Resolved != "" || e.Integrity != "" || (e.Source != "" && e.Source != SourceUnknown)
}

// Installs returns the entries of the file, with the ecosystem of a format that states
// it once filled in and the lines that install one artifact collapsed into one entry,
// in the order the file first mentions them.
//
// A lockfile names a version once per place it is installed at: npm writes the hoisted
// package and every nested copy of it, which is one thing to evaluate however many
// lines it takes. What decides whether two lines are one thing is not the version but
// the artifact. A copy repointed at another archive installs other bytes under the
// same version, and folding it into the clean copy above it is how that goes unseen.
//
// A line that states nothing about its artifact is not a disagreement, and folds into
// whatever the file does state for that version wherever in the file it says it. It
// speaks for the version only when nothing else does. Reading npm's bundled lines as
// separate installs would be one subject per line for lines that say nothing.
//
// The entry kept for a version is the first line that states its artifact, or the
// first line of all when none does, and it counts as direct if any line of the group
// is. A nil receiver returns nothing: that is the side a change which adds or deletes
// a lockfile has.
func (l *Lockfile) Installs() []Entry {
	if l == nil {
		return nil
	}
	// at holds the entry kept for one artifact. first holds the entry kept for a
	// version, which a line that states nothing folds into and which the first line
	// that does state something takes over.
	at := make(map[artifactKey]int, len(l.Entries))
	first := make(map[model.PackageRef]int, len(l.Entries))
	out := make([]Entry, 0, len(l.Entries))
	for i := range l.Entries {
		e := l.Entries[i]
		if e.Ref.Ecosystem == "" {
			e.Ref.Ecosystem = l.Ecosystem
		}
		if !e.statesItsArtifact() {
			if j, seen := first[e.Ref]; seen {
				out[j].Direct = out[j].Direct || e.Direct
				continue
			}
			first[e.Ref] = len(out)
			out = append(out, e)
			continue
		}
		k := e.artifactKey()
		if j, seen := at[k]; seen {
			out[j].Direct = out[j].Direct || e.Direct
			continue
		}
		if j, seen := first[e.Ref]; seen && !out[j].statesItsArtifact() {
			// The version was first met on a line that says nothing about where it
			// comes from. This one does, so this is the line to report it at.
			e.Direct = e.Direct || out[j].Direct
			out[j] = e
			at[k] = j
			continue
		}
		if _, seen := first[e.Ref]; !seen {
			first[e.Ref] = len(out)
		}
		at[k] = len(out)
		out = append(out, e)
	}
	return out
}

// Parser reads one lockfile format.
type Parser interface {
	// Name is the format's name, which is also the file name it looks for.
	Name() string
	// Detect reports whether the parser handles a file with this name. The name is
	// the base name, lower cased, and For asks a second time with the parent
	// directory in front of it ("requirements/dev.txt") for the one format that
	// cannot be recognized without it. A parser that only knows fixed file names
	// compares the whole string and answers false for the second form.
	Detect(name string) bool
	// Parse reads the file. path is used for messages and for Lockfile.Path only.
	Parse(path string, r io.Reader) (*Lockfile, error)
}

var (
	parsersMu sync.Mutex
	parsers   []Parser
)

// Register adds a parser; each format's package calls it from init. Registering
// the same name twice is a programming error and panics.
func Register(p Parser) {
	parsersMu.Lock()
	defer parsersMu.Unlock()
	for _, existing := range parsers {
		if existing.Name() == p.Name() {
			panic("lockfile: duplicate parser " + p.Name())
		}
	}
	parsers = append(parsers, p)
	sort.Slice(parsers, func(i, j int) bool { return parsers[i].Name() < parsers[j].Name() })
}

// Parsers returns every registered parser, ordered by name.
func Parsers() []Parser {
	parsersMu.Lock()
	defer parsersMu.Unlock()
	out := make([]Parser, len(parsers))
	copy(out, parsers)
	return out
}

// For returns the parser that handles the file.
//
// Every parser is asked about the base name first, which is what all but one
// format is identified by. A parser that recognizes none of them is then asked
// about the name with its parent directory, because pip's requirements are the one
// format whose base name can say nothing at all: a requirements directory holding
// main.txt and dev.txt is as common as requirements.txt, and accepting every .txt
// file would swallow the repository. Passing the whole path is therefore worth
// more than passing the base name, and a caller that has one should.
func For(path string) (Parser, bool) {
	slashed := filepath.ToSlash(path)
	base := strings.ToLower(filepath.Base(slashed))
	parsers := Parsers()
	for _, p := range parsers {
		if p.Detect(base) {
			return p, true
		}
	}
	dir := filepath.ToSlash(filepath.Dir(slashed))
	if dir == "." || dir == "" || dir == slashed {
		return nil, false
	}
	withParent := strings.ToLower(filepath.Base(dir)) + "/" + base
	for _, p := range parsers {
		if p.Detect(withParent) {
			return p, true
		}
	}
	return nil, false
}

// Parse reads a lockfile with the parser that recognizes its name.
func Parse(path string, r io.Reader) (*Lockfile, error) {
	p, ok := For(path)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, filepath.Base(path))
	}
	lf, err := p.Parse(path, r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return lf, nil
}
