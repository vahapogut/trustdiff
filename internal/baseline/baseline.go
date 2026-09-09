// Package baseline reads and writes .trustdiff/baseline.json, the record a project
// keeps of the trust signals it has seen for the packages it locks: who maintained
// each package, who published the release that was looked at, what provenance that
// release carried, and when the observation was made.
//
// It exists because a registry answers about now. PyPI records no publisher per
// version and crates.io keeps no maintainer history, so TD002 for PyPI and TD003
// for PyPI and crates.io have nothing to compare a release with unless the project
// itself remembers what it saw. One shape serves every ecosystem: an npm package
// and a crate carry the same fields, because a check must not have to know which
// registry an entry came from.
//
// The document is schema/baseline.v1.json, published beside the report and policy
// schemas and embedded here as SchemaJSON. Entries are sorted by ecosystem and
// name and times are written in UTC with second precision, and an entry whose
// signals a rerun found unchanged keeps the observation time it already carries,
// so a rerun that saw nothing new rewrites the file's own updated_at line and not
// one line per package. Write replaces the file atomically, so a reader never
// sees half a document; see Write for what that promises and what it does not.
//
// The package imports internal/model and the standard library only. It must not
// import internal/checks or internal/gitdiff: internal/checks reads a baseline, and
// the git side is reached through the small RevisionReader interface instead, so
// that a check never pulls in a package that starts a process.
package baseline

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// SchemaID identifies the baseline document format. It changes only with a
// breaking change to the shape; fields are added within a version, never renamed
// or removed.
const SchemaID = "trustdiff.baseline/1"

const (
	// DirName is the project directory the baseline lives in. It sits beside the
	// policy file rather than in it, because a policy is written by a person and
	// this file is written by a program.
	DirName = ".trustdiff"
	// FileName is the baseline's name inside DirName.
	FileName = "baseline.json"
)

// SchemaJSON is the JSON Schema of the document Write produces. It is a
// byte-identical copy of schema/baseline.v1.json at the repository root; the test
// in schema_test.go fails when the two drift. It is embedded so that a binary
// which validates or serves the schema needs no file next to it.
//
// The schema uses the draft-07 dialect and only the keywords internal/jsonschema
// implements, so a test can validate what the writer produces against it.
//
//go:embed baseline.v1.json
var SchemaJSON []byte

// PublisherSource says where a recorded publishing identity came from. A check
// compares only identities of the same source, because an account name and the
// repository an attestation names are different kinds of thing and a difference
// between them says nothing.
type PublisherSource string

const (
	// FromRegistry means the registry itself named the account that published the
	// release (npm _npmUser, crates.io published_by).
	FromRegistry PublisherSource = "registry"
	// FromProvenance means the registry names no publisher and the identity is the
	// one the release's attestation or trusted publisher carries. It is the only
	// publishing identity PyPI exposes.
	FromProvenance PublisherSource = "provenance"
)

// Provenance is the publishing evidence an observed release carried. A nil
// *Provenance means the evidence could not be read, which is not the same as a
// release that carried none: a check that finds it nil reports itself as skipped.
type Provenance struct {
	// Kind is the strongest kind of evidence, in the spelling of model.ProvenanceKind.
	Kind model.ProvenanceKind `json:"kind"`
	// Verified is true when the registry or deps.dev verified the evidence.
	Verified bool `json:"verified"`
	// Identity is the workflow or repository the evidence names, when it names one.
	Identity string `json:"identity,omitempty"`
}

// signal is a half of what observing a package reads. The maintainer set belongs
// to the package and the publisher and the provenance belong to one release, and
// a run reads them with separate requests, so one lookup that answered must not
// be thrown away because the other did not.
type signal uint8

const (
	// signalMaintainers is the maintainer or owner set the registry lists.
	signalMaintainers signal = 1 << iota
	// signalRelease is everything read from the release itself: the version the
	// record is taken from, the publisher, its source and the provenance.
	signalRelease
	// signalProvenance is the provenance alone, for a release that was read while
	// the registry could not answer for its publishing evidence.
	signalProvenance
	// everySignal is what an observation that read nothing at all is missing.
	// signalProvenance is not part of it: a release nobody could read carries no
	// provenance either, so signalRelease already covers it.
	everySignal = signalMaintainers | signalRelease
)

// Entry is what one package's record holds. Every field but the identity and the
// time may be absent, and absent always means "was not read" rather than "is
// empty": a check reads an absent field as no answer, never as a change.
type Entry struct {
	Ecosystem model.Ecosystem `json:"ecosystem"`
	Name      string          `json:"name"`
	// Version is the release the observation was taken from.
	Version string `json:"version"`
	// ObservedAt is when the signals below were first seen, in UTC with second
	// precision. A rerun that finds them unchanged leaves it alone, so that a
	// project which observed nothing new rewrites no entry; the file's UpdatedAt
	// says when the record was last confirmed.
	ObservedAt time.Time `json:"observed_at"`
	// Maintainers is the maintainer or owner set the registry showed, sorted and
	// without repeats.
	Maintainers []string `json:"maintainers,omitempty"`
	// Publisher is the identity that published Version.
	Publisher string `json:"publisher,omitempty"`
	// PublisherSource says where Publisher came from; it is set whenever Publisher is.
	PublisherSource PublisherSource `json:"publisher_source,omitempty"`
	// Provenance is the evidence Version carried.
	Provenance *Provenance `json:"provenance,omitempty"`

	// missing says which signals the observation behind this entry could not read.
	// It is unexported and never written to the file, because it describes one
	// observation and not the record: Put keeps what the file already holds for
	// every signal it names. A gap written over a record would erase the only
	// answer TD002 and TD003 have for PyPI and crates.io, and a rate limit, a 5xx
	// or a package the registry has removed is not a reason to forget who
	// maintained it.
	missing signal
	// outage is the subset of missing a data source did not answer for at all, as
	// against answering with nothing. It is kept apart because only an outage is
	// what a policy's on_data_unavailable is about: a registry that lists no
	// maintainer has answered the question, and a run that reports it has
	// consulted everything it was asked to.
	outage signal
}

// Ref returns the ref of the release the entry was observed at. The receiver is a
// pointer because an entry is a wide struct and every reader of a baseline walks
// a lot of them.
func (e *Entry) Ref() model.PackageRef {
	return model.PackageRef{Ecosystem: e.Ecosystem, Name: e.Name, Version: e.Version}
}

// Package returns the entry's package, without the version. It is the key an
// entry is looked up by: the record is about the package, and the version only
// says which release the publisher and the provenance were read from.
func (e *Entry) Package() model.PackageRef {
	return model.PackageRef{Ecosystem: e.Ecosystem, Name: e.Name}
}

// Age is how long ago the observation was made, measured against the run's clock.
// A negative age, which a repository with a clock skew or a hand-edited file can
// produce, is reported as zero so that a finding never says an entry was recorded
// in the future.
func (e *Entry) Age(now time.Time) time.Duration {
	if d := now.Sub(e.ObservedAt); d > 0 {
		return d
	}
	return 0
}

// SameSignals reports whether two entries record the same observation, ignoring
// when it was made. It is what tells an entry a change under review rewrote from
// one that was only observed again.
func (e *Entry) SameSignals(other *Entry) bool {
	if e.Ecosystem != other.Ecosystem || e.Name != other.Name || e.Version != other.Version ||
		e.Publisher != other.Publisher || e.PublisherSource != other.PublisherSource {
		return false
	}
	if !slices.Equal(e.Maintainers, other.Maintainers) {
		return false
	}
	switch {
	case e.Provenance == nil && other.Provenance == nil:
		return true
	case e.Provenance == nil || other.Provenance == nil:
		return false
	default:
		return *e.Provenance == *other.Provenance
	}
}

// normalize puts an entry in the shape the file is written in: the registry's
// canonical name, UTC times truncated to the second so that two runs of the same
// minute write the same bytes, and a sorted maintainer set without repeats. It
// changes the entry in place, so every path into a file goes through it and no
// caller can forget the result.
func (e *Entry) normalize() {
	// The ecosystem is canonicalized first, because the name is normalized for the
	// ecosystem it belongs to: "PyPI" would leave a PyPI name in whatever spelling
	// it arrived in and no lookup would ever match it.
	if eco, err := model.ParseEcosystem(string(e.Ecosystem)); err == nil {
		e.Ecosystem = eco
	}
	e.Name = model.NormalizeName(e.Ecosystem, e.Name)
	e.ObservedAt = e.ObservedAt.UTC().Truncate(time.Second)
	e.Maintainers = normalizeNames(e.Maintainers)
	if e.Publisher == "" {
		e.PublisherSource = ""
	}
}

// validate reports what is wrong with an entry read from a file. It is the check
// the JSON schema makes for a consumer, made again here so that a hand-edited
// file fails with a sentence rather than with a wrong comparison later.
func (e *Entry) validate(i int) error {
	where := fmt.Sprintf("packages[%d]", i)
	eco, err := model.ParseEcosystem(string(e.Ecosystem))
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	// The canonical spelling is kept, not only checked. An entry left saying "NPM"
	// would match no lookup, be dropped as no longer locked while the package is
	// locked, let Put record the same package a second time, and fail the enum the
	// published schema states.
	e.Ecosystem = eco
	switch {
	case strings.TrimSpace(e.Name) == "":
		return fmt.Errorf("%s: empty package name", where)
	case strings.TrimSpace(e.Version) == "":
		return fmt.Errorf("%s (%s): empty version", where, e.Name)
	case e.ObservedAt.IsZero():
		return fmt.Errorf("%s (%s): missing observed_at", where, e.Name)
	case e.Publisher != "" && e.PublisherSource != FromRegistry && e.PublisherSource != FromProvenance:
		return fmt.Errorf("%s (%s): publisher_source is %q, want %q or %q", where, e.Name, e.PublisherSource, FromRegistry, FromProvenance)
	}
	return nil
}

// normalizeNames sorts names, drops the empty ones and removes repeats that
// differ only in case, keeping the first spelling. Registries treat account names
// case-insensitively, and a set that differs only in case is the same set.
func normalizeNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !slices.ContainsFunc(out, func(seen string) bool { return strings.EqualFold(seen, name) }) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// File is a whole baseline document, in the shape of schema/baseline.v1.json.
// Build one with New, or read one with Load, Parse or AtRevision.
type File struct {
	// Schema is always SchemaID.
	Schema string `json:"schema"`
	// UpdatedAt is when the file was last written, in UTC with second precision.
	UpdatedAt time.Time `json:"updated_at"`
	// Packages holds one entry per package, sorted by ecosystem and then name.
	Packages []Entry `json:"packages"`
}

// New returns an empty baseline stamped with the run's clock.
func New(now time.Time) *File {
	return &File{Schema: SchemaID, UpdatedAt: now.UTC().Truncate(time.Second)}
}

// Lookup returns the entry recorded for a package. The ref's version is ignored:
// a baseline holds one record per package. A nil *File answers false, so a
// project without a baseline needs no special case at the call sites.
func (f *File) Lookup(ref model.PackageRef) (Entry, bool) {
	if f == nil {
		return Entry{}, false
	}
	name := model.NormalizeName(ref.Ecosystem, ref.Name)
	for i := range f.Packages {
		e := &f.Packages[i]
		if e.Ecosystem == ref.Ecosystem && e.Name == name {
			return *e, true
		}
	}
	return Entry{}, false
}

// Put records an observation of a package, merging it into the entry the file
// already holds. The file stays sorted, so the caller may put entries in any
// order. The entry is normalized in place first, which is why it is taken by
// pointer: every path into a file goes through the same shaping, and the caller
// sees its observation in the shape the file gives it.
//
// A signal the observation could not read keeps the value the record holds
// rather than erasing it, and an observation that read nothing at all changes
// nothing at all: absent means "was not read", and a run that was rate limited,
// answered with a 5xx or interrupted must not delete what an earlier run saw. An
// observation of a package the file does not hold yet, which read nothing, is
// not recorded either, because an entry carrying only a name and a timestamp
// claims an observation that never happened.
func (f *File) Put(e *Entry) {
	e.normalize()
	for i := range f.Packages {
		if f.Packages[i].Ecosystem == e.Ecosystem && f.Packages[i].Name == e.Name {
			f.Packages[i] = merge(&f.Packages[i], e)
			return
		}
	}
	if e.missing&everySignal == everySignal {
		// Nothing was read and nothing was recorded before, so there is nothing to
		// record.
		return
	}
	stored := *e
	stored.missing, stored.outage = 0, 0
	f.Packages = append(f.Packages, stored)
	f.sort()
}

// merge is what a package the file already holds records after an observation:
// the fresh signals, with the recorded value kept for every signal the run could
// not read, and the recorded time kept when nothing about the signals moved.
func merge(was, now *Entry) Entry {
	if now.missing&everySignal == everySignal {
		// Nothing was read, so nothing was observed and nothing moves, not even
		// observed_at: the record still says when the signals it holds were seen.
		return *was
	}
	out := *now
	out.missing, out.outage = 0, 0
	if now.missing&signalMaintainers != 0 {
		out.Maintainers = was.Maintainers
	}
	switch {
	case now.missing&signalRelease != 0:
		// The publisher and the provenance were read from the release in Version,
		// so the release half of a record moves together or not at all. Carrying a
		// publisher over to another version would say that account published a
		// release nobody was able to look at.
		out.Version, out.Publisher, out.PublisherSource, out.Provenance =
			was.Version, was.Publisher, was.PublisherSource, was.Provenance
	case now.missing&signalProvenance != 0 && was.Version == out.Version:
		// The release was read and its evidence was not, so what the record holds
		// for that same release stands.
		out.Provenance = was.Provenance
	}
	if was.SameSignals(&out) {
		// A rerun that saw nothing new leaves the line alone, so a project of five
		// hundred packages rewrites one line and not five hundred. The time an
		// entry carries is therefore when its signals were first seen, and the
		// file's updated_at is when they were last confirmed.
		out.ObservedAt = was.ObservedAt
	}
	return out
}

// Keep drops every entry whose package is not in refs and returns what it
// dropped, sorted like the file. It is what a full snapshot does: a project that
// no longer locks a package has no reason to keep saying who used to maintain it,
// and a file that only ever grows is a file nobody rewrites. A partial run
// (diff and scan with --update-baseline see only what the change touched) must
// not call it.
func (f *File) Keep(refs []model.PackageRef) []Entry {
	locked := make(map[model.PackageRef]bool, len(refs))
	for _, ref := range refs {
		locked[model.PackageRef{Ecosystem: ref.Ecosystem, Name: model.NormalizeName(ref.Ecosystem, ref.Name)}] = true
	}
	kept := make([]Entry, 0, len(f.Packages))
	var dropped []Entry
	for i := range f.Packages {
		e := &f.Packages[i]
		if locked[e.Package()] {
			kept = append(kept, *e)
			continue
		}
		dropped = append(dropped, *e)
	}
	f.Packages = kept
	return dropped
}

// sort orders the entries the way the file is written: by ecosystem, then by
// name. The order is the file's contract, not a detail: a stable order is what
// keeps a rewrite from touching lines nothing changed in.
func (f *File) sort() {
	slices.SortFunc(f.Packages, func(a, b Entry) int {
		if c := strings.Compare(string(a.Ecosystem), string(b.Ecosystem)); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// Record is one package's baseline as a run sees it.
type Record struct {
	// Observed is the observation a check compares a release with. It is the entry
	// the base revision recorded whenever the change under review edited or
	// deleted that entry, and the working tree's entry otherwise. The older record
	// wins on purpose: rewriting the record of who used to maintain a package is
	// exactly what an attacker with commit access would do, and a check that
	// compared with the rewritten record would report the pass the attacker wrote.
	Observed Entry
	// Rewritten is true when the change under review edited or deleted the entry
	// the base revision recorded. A finding reports it as evidence.
	Rewritten bool
	// Added is true when the entry is one the change under review invented: the
	// working tree records it and the base revision recorded nothing for the
	// package. There is no record from before the change to compare with, so a
	// check reports itself as skipped rather than passing on a record the same
	// change supplied. It is false for a run that compares against no revision,
	// where the working tree's record is the only one there has ever been.
	Added bool
	// Current is the entry the working tree's baseline holds when Rewritten is
	// true, and nil when the change deleted the entry altogether.
	Current *Entry
}

// Set is the baseline as one run sees it: the file the working tree holds and,
// when the run is a diff against a git revision, the file that revision held.
// Both may be nil, which is a project that keeps no baseline yet.
type Set struct {
	// Head is the baseline of the working tree.
	Head *File
	// Base is the baseline the base revision recorded, read through AtRevision.
	// It is nil for every run that compares against no revision.
	Base *File
}

// Lookup returns the record of a package, and false when neither side has one.
// See Record for which of the two sides wins.
func (s *Set) Lookup(ref model.PackageRef) (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	head, inHead := s.Head.Lookup(ref)
	base, inBase := s.Base.Lookup(ref)
	switch {
	case !inBase && !inHead:
		return Record{}, false
	case !inBase:
		// A run with a base revision that records nothing for the package is
		// looking at an entry the change under review wrote, and an entry a change
		// wrote about itself answers nothing: it is reported as added so that the
		// checks skip rather than pass. A run comparing against no revision has
		// only ever had the working tree's record, and that is not the same thing.
		return Record{Observed: head, Added: s.Base != nil}, true
	case inHead && head.SameSignals(&base):
		// The change left the record alone. The working tree's entry is used so
		// that a re-observation which only moved observed_at is not read as a
		// rewrite.
		return Record{Observed: head}, true
	case inHead:
		current := head
		return Record{Observed: base, Rewritten: true, Current: &current}, true
	default:
		return Record{Observed: base, Rewritten: true}, true
	}
}
