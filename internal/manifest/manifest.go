// Package manifest reads the direct dependencies a project's manifest declares and
// resolves each one to the version its registry serves for it today. It is what
// "trustdiff check package.json" evaluates: not what a lockfile pinned some time
// ago, but what an install run now would bring in.
//
// Three files are read, one per ecosystem: package.json for npm, pyproject.toml for
// PyPI and Cargo.toml for crates.io. A reader takes the file at its word and reads
// nothing else. It does not open a lockfile beside it, it does not follow a
// workspace glob into another file, and it never guesses a version: a declaration
// with no registry version behind it, and a range this package cannot parse, comes
// back in Manifest.Skipped with the text as written and the reason, which the
// command prints beside the report. That is the rule the whole tool follows, and it
// is why a monorepo full of workspace dependencies reports them rather than
// resolving something plausible.
//
// # What each file declares
//
// package.json: "dependencies", "devDependencies" and "optionalDependencies". A
// workspace member's package.json carries the same three maps and is read the same
// way, so pointing check at packages/ui/package.json evaluates that member; a
// root's "workspaces" globs are not expanded, because every member is a file of its
// own and this package reads one file. An alias, "d3v3": "npm:d3@^3", resolves to
// the package that is really installed, d3, because that is what a registry, an
// advisory database and the checks are asked about; the alias the manifest wrote is
// kept on the declaration. A value naming a git repository, a tarball URL, a file
// path, a link or a portal, the workspace protocol or a patch is skipped with that
// reason, and so is a bare word such as "latest", which names a dist-tag rather
// than a range.
//
// pyproject.toml: PEP 621's "project.dependencies" and
// "project.optional-dependencies", and, where the file uses them, Poetry's
// "tool.poetry.dependencies", "tool.poetry.dev-dependencies" and
// "tool.poetry.group.<name>.dependencies". A requirement with a URL ("pkg @
// https://host/pkg.whl") or a Poetry table naming git, path or url is skipped with
// that reason. An environment marker is read and recorded on the declaration but
// never excludes it: the checks want to know what could be installed, not what this
// machine would install today. Extras are recorded for the same reason and change
// nothing about which version is resolved, because a distribution's extras ship in
// the distribution. Poetry's "python" key names the interpreter rather than a
// distribution and is skipped saying so.
//
// Cargo.toml: "dependencies", "dev-dependencies", "build-dependencies" and, for a
// workspace root, "workspace.dependencies". A dependency written as a table is read
// from its "version" key, its "package" key renames it the way an npm alias does,
// and "workspace = true" takes the requirement from this file's own
// "workspace.dependencies" when it has one. A git or path dependency is skipped
// with that reason, and so is one pinned to an alternate registry, whose index this
// tool does not know how to ask. Target specific tables
// ("target.'cfg(unix)'.dependencies") are not read.
//
// # The range grammars
//
// A declaration resolves to the highest version the registry lists that satisfies
// it, leaving out yanked releases always and prereleases unless the declaration
// itself names one. Deciding what satisfies a range is a grammar per ecosystem, and
// each one is written here rather than taken from a dependency:
//
// npm, the node-semver range grammar. A range set is ranges joined by "||"; a range
// is comparators joined by whitespace, all of which must hold. A comparator is a
// version with the pieces it leaves out written as "x", "X", "*" or simply missing:
//
//	1.2.3            exactly that version
//	=1.2.3           the same
//	>1.2.3 >=1.2.3   ordered comparisons, with the partial forms node-semver
//	<1.2.3 <=1.2.3   rewrites: ">1.2" is ">=1.3.0", "<=0.7.x" is "<0.8.0"
//	^1.2.3           >=1.2.3 <2.0.0, and the leftmost non-zero piece is what is
//	                 held: ^0.2.3 is >=0.2.3 <0.3.0, ^0.0.3 is >=0.0.3 <0.0.4
//	~1.2.3           >=1.2.3 <1.3.0, and ~1.2 is >=1.2.0 <1.3.0, ~1 is >=1.0.0 <2.0.0
//	1.2.x  1.x  *    an x-range: >=1.2.0 <1.3.0, >=1.0.0 <2.0.0, everything
//	1.2.3 - 2.3.4    a hyphen range, >=1.2.3 <=2.3.4, with the missing pieces of
//	                 the low side read as 0 and of the high side widened, so
//	                 "1.2.3 - 2.3" is >=1.2.3 <2.4.0
//	""               an empty range, which npm reads as "any version"
//
// A prerelease satisfies a range only when some comparator of the range names a
// prerelease of the same major.minor.patch, which is node-semver's rule and the
// reason "^1.0.0" never installs "2.0.0-rc.1". Build metadata is dropped before
// comparing, as the semantic versioning specification says.
//
// crates.io, Cargo's own requirement syntax: comma separated comparators, all of
// which must hold, with a caret assumed when no operator is written. "1.2.3" is
// therefore "^1.2.3" and "1.2" is "^1.2", while an explicit wildcard is an x-range:
// "1.2.*" is >=1.2.0 <1.3.0 and "*" is any version. The caret, tilde and partial
// comparison rules are the ones above, which is not a coincidence: Cargo's
// semantics for ">1.2", "<=1.2" and "=1.2" agree with node-semver's piece for
// piece. Prereleases follow the same rule as npm's.
//
// PyPI, PEP 440 version specifiers: comma separated clauses, all of which must
// hold, spelled "==", "!=", "<=", ">=", "<", ">", "~=" and "===", with the ".*"
// prefix form accepted on "==" and "!=". "~=1.4.2" is ">=1.4.2, ==1.4.*" as the PEP
// defines it, "===" compares the two spellings as text, and the two exclusion rules
// the PEP states are applied: ">1.7" does not accept a post release of 1.7 and
// "<1.7" does not accept a prerelease of 1.7. Prereleases are left out unless a
// clause of the specifier names one, which is pip's rule. Ordering and
// normalization are internal/model/version's PEP 440 parser, not this package's.
//
// Poetry writes its constraints in a grammar of its own, and a declaration read
// from a Poetry table is parsed with the PEP 440 clauses above plus four forms
// Poetry adds: "^1.2.3" and "~1.2.3" with the same meanings they have in npm,
// "1.2.*" as a prefix, a bare "1.2.3" meaning "==1.2.3", and "||" between
// alternatives, any one of which may hold.
//
// # What was deliberately left out
//
// npm dist-tags ("latest", "next") are not resolved: a tag is a pointer the
// registry moves, not a range, and a declaration naming one is skipped saying so.
// node-semver's "loose" and "includePrerelease" options have no spelling in a
// manifest and are not implemented. A comparator set that mixes a hyphen range with
// other comparators, which node-semver also rejects, is skipped with the text.
//
// Cargo's target specific dependency tables are not read, so a crate a project
// builds only on one platform is not evaluated; neither are the "features",
// "default-features" or "optional" keys, none of which change which version
// resolves. A requirement pinned to an alternate registry is skipped rather than
// looked up on crates.io, because it is a different index and might hold a
// different crate under the name.
//
// For PyPI, an environment marker is recorded and never evaluated, so a dependency
// that only Windows or only Python 3.8 would install is still evaluated here. PEP
// 508 direct references (a URL in place of a specifier) are skipped, as are PEP 735
// dependency groups, which are not part of what the brief asks for. A "==" or "!="
// prefix match whose own operand carries a pre, post or dev segment is not
// implemented and is skipped with the text rather than answered approximately.
package manifest

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// The manifest formats this package reads, one per ecosystem. The value is the
// file's name as its ecosystem spells it, which is also what Manifest.Format
// reports and what the command prints when it says a path is none of them.
const (
	FormatPackageJSON = "package.json"
	FormatPyproject   = "pyproject.toml"
	FormatCargoToml   = "Cargo.toml"
)

// Syntax names the grammar a declaration's range is written in. It travels on the
// declaration rather than being derived from the ecosystem because one ecosystem
// has two: a pyproject.toml can state a PEP 440 specifier under [project] and a
// Poetry constraint under [tool.poetry] in the same file, and the two grammars
// disagree about what a bare "1.2.3" means.
type Syntax string

// The grammars, one per spelling. The package comment states each of them.
const (
	// SyntaxNPM is the node-semver range grammar.
	SyntaxNPM Syntax = "npm"
	// SyntaxPEP440 is a PEP 440 version specifier set.
	SyntaxPEP440 Syntax = "pep440"
	// SyntaxPoetry is Poetry's constraint grammar, PEP 440's clauses plus the
	// caret, tilde, wildcard and alternative forms Poetry adds.
	SyntaxPoetry Syntax = "poetry"
	// SyntaxCargo is Cargo's requirement syntax.
	SyntaxCargo Syntax = "cargo"
)

// The tables a declaration can be read from, as Declaration.Table records them.
// They are spelled the way the file spells them, so that a note beside the report
// sends a reader to the line they came from. A Poetry group and a PEP 621 extra
// carry their own name, so those are built rather than named here.
const (
	TableDependencies         = "dependencies"
	TableDevDependencies      = "devDependencies"
	TableOptionalDependencies = "optionalDependencies"
	TableCargoDev             = "dev-dependencies"
	TableCargoBuild           = "build-dependencies"
	TableCargoWorkspace       = "workspace.dependencies"
	TableProjectDependencies  = "project.dependencies"
	TablePoetryDependencies   = "tool.poetry.dependencies"
	TablePoetryDev            = "tool.poetry.dev-dependencies"
)

// Declaration is one direct dependency a manifest declares, at the range it
// declares rather than at a version: what version that range means today is the
// registry's answer, which Resolve asks for.
type Declaration struct {
	// Ref names the package the declaration is about, without a version. The name
	// is the package that is really installed, so an alias and a Cargo rename are
	// resolved before the ref is built, and it carries the ecosystem's canonical
	// spelling as model.NormalizeName defines it.
	Ref model.PackageRef
	// Alias is the name the manifest wrote when it differs from the package that is
	// really installed ("d3v3": "npm:d3@^3", or Cargo's package key), empty
	// otherwise. It is what a reader of the manifest will search for.
	Alias string
	// Range is the version range exactly as the manifest wrote it, which is what a
	// skipped declaration's reason quotes.
	Range string
	// Syntax is the grammar Range is written in.
	Syntax Syntax
	// Table names the table the declaration was read from.
	Table string
	// Dev is true when the dependency is only needed to develop or test the project.
	Dev bool
	// Optional is true when an install may leave the dependency out: npm's
	// optionalDependencies, a PEP 621 extra, a Poetry or Cargo dependency marked
	// optional.
	Optional bool
	// Extras are the PEP 508 extras the requirement asks for, recorded because they
	// say what the project uses the distribution for. They change no version: a
	// distribution's extras ship inside the distribution.
	Extras []string
	// Marker is the PEP 508 environment marker as written, empty when there is
	// none. It is recorded and never evaluated; the package comment says why.
	Marker string
}

// Skipped is a declaration nothing was resolved for, with the reason. It is the
// only other thing a reader or the resolver can produce: a version is never
// invented, so everything that is not a resolved version is here, in words.
type Skipped struct {
	// Name is the dependency as the manifest names it, which for an alias is the
	// alias, because that is the spelling a reader will find in the file.
	Name string
	// Range is what the manifest wrote for it, as written, empty when the file
	// wrote nothing a range could be read from.
	Range string
	// Table names the table it was declared in.
	Table string
	// Reason says in plain words why nothing was resolved.
	Reason string
	// Unavailable is true when the reason is an outage rather than an answer: the
	// registry could not be consulted and a later run may resolve the declaration.
	// A git dependency, by contrast, will never resolve however often it is asked.
	// It is what the command's exit code reacts to under on_data_unavailable: fail.
	Unavailable bool
}

// String words one skipped declaration for a note beside the report.
func (s Skipped) String() string {
	if s.Range == "" {
		return fmt.Sprintf("%s: %s", s.Name, s.Reason)
	}
	return fmt.Sprintf("%s %q: %s", s.Name, s.Range, s.Reason)
}

// Manifest is one parsed manifest file.
type Manifest struct {
	// Path is the file as the caller named it, which is what the report calls it.
	Path string
	// Format is the reader's name, one of the Format constants.
	Format string
	// Ecosystem is the ecosystem every declaration in the file belongs to.
	Ecosystem model.Ecosystem
	// Name is the project's own name when the file states one, for the note that
	// says whose dependencies these are.
	Name string
	// Dependencies are the direct dependencies the file declares, in a stable
	// order: by table as the reader visits them, and by name within a table, so
	// that two runs over one file report the same subjects in the same order.
	Dependencies []Declaration
	// Skipped records the declarations with no version to resolve, one line each,
	// so that a partial read is visible rather than silent.
	Skipped []Skipped
}

// add appends a declaration whose range parses. A range that does not parse is not
// a declaration: it is skipped with its text, because a range nobody can read is
// exactly the case where guessing a version would be worst.
func (m *Manifest) add(d *Declaration) {
	if _, err := parseConstraint(d.Syntax, d.Range); err != nil {
		m.skip(d.Alias, d.Range, d.Table, "%v", err)
		return
	}
	m.Dependencies = append(m.Dependencies, *d)
}

// skip records a declaration nothing can be resolved for.
func (m *Manifest) skip(name, text, table, format string, args ...any) {
	m.Skipped = append(m.Skipped, Skipped{
		Name:   name,
		Range:  text,
		Table:  table,
		Reason: fmt.Sprintf(format, args...),
	})
}

// Formats lists the manifest names this package reads, for the message that says a
// path is none of them.
func Formats() []string {
	return []string{FormatPackageJSON, FormatPyproject, FormatCargoToml}
}

// For returns the format that reads the file at path, by its base name, and whether
// there is one. Names are compared case insensitively because Cargo.toml is written
// with a capital and package.json without one, and a checkout on a case insensitive
// filesystem can hand back either spelling.
//
// The backslashes are replaced rather than passed to filepath.ToSlash, which does
// nothing anywhere but Windows: a path is as likely to have been written on one
// platform and read on another, and a name is worth recognizing wherever it was
// spelled. A file whose name really does contain a backslash is opened by the string
// that was given, so nothing is lost by reading the name more liberally than that.
func For(path string) (string, bool) {
	switch strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/"))) {
	case strings.ToLower(FormatPackageJSON):
		return FormatPackageJSON, true
	case strings.ToLower(FormatPyproject):
		return FormatPyproject, true
	case strings.ToLower(FormatCargoToml):
		return FormatCargoToml, true
	}
	return "", false
}

// Read reads one manifest. path decides which reader runs and is what the returned
// Manifest and every message name the file by; r is the file's bytes.
//
// It fails only when the file cannot be read at all: not the format it claims to
// be, or a dependency table that is not a table. A single declaration it cannot
// make sense of is skipped with a reason and the rest of the file is kept, because
// a manifest with one git dependency in it still declares everything else.
func Read(path string, r io.Reader) (*Manifest, error) {
	format, ok := For(path)
	if !ok {
		return nil, fmt.Errorf("%s: no manifest reader for this file name, trustdiff reads %s", path, strings.Join(Formats(), ", "))
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var m *Manifest
	switch format {
	case FormatPackageJSON:
		m, err = readPackageJSON(path, data)
	case FormatPyproject:
		m, err = readPyproject(path, data)
	default:
		m, err = readCargoToml(path, data)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}
