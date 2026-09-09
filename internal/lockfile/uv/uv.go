// Package uv reads uv.lock, the file uv writes to pin the Python distributions a
// project installs.
//
// The file declares its format version as an integer ("version = 1"), which the
// entry set records as Lockfile.Version. A newer uv also writes a "revision", which
// changes none of the fields read here.
//
// Every package is a [[package]] table with a name, a version and a "source" table
// whose key names the origin:
//
//	{ registry = "https://pypi.org/simple" }    an index                   registry
//	{ git = "https://host/repo?rev=..#<sha>" }  a git repository           git
//	{ url = "https://host/pkg-1.0.tar.gz" }     an archive fetched by URL  url
//	{ path = "vendor/pkg-1.0.whl" }             a file on the machine      path
//	{ directory = "libs/pkg" }                  a directory                path
//	{ editable = "." }                          a directory, installed in  path
//	                                            place
//	{ virtual = "." }                           the project itself         dropped
//
// A virtual package is the project uv locked rather than something it installs, so
// it is dropped with a reason instead of being reported as a path dependency nobody
// can act on. A source spelled some other way is an origin this parser does not
// know, and the entry says so rather than claiming the registry.
//
// Integrity and Resolved come from the artifact the entry pins: the [package.sdist]
// table when the package has one, otherwise the first of the wheels. Both carry a
// "url" (or a "path", for an artifact already on the machine) and a "hash" that uv
// writes as "sha256:<hex>", which the entry records as written. A package with
// neither artifact, a git or directory source for instance, records its source
// location as Resolved and carries no hash.
//
// Direct dependencies are the ones the project asks for itself, which the file
// states in two places:
//
//   - [manifest], whose "requirements" and "dependency-groups" hold what is
//     attached to the project rather than to a workspace member. uv writes them for
//     a lock without a project of its own, a PEP 723 script for instance.
//   - the project's own package: the one uv marks virtual or editable, or names in
//     [manifest] members. Its "dependencies" are the project's runtime
//     dependencies, its "optional-dependencies" are its extras, and its
//     "dev-dependencies" (written "dependency-groups" by a newer uv) are its
//     dependency groups.
//
// Dev and Optional describe that same table: a package the project asks for only in
// a dependency group is dev, one it asks for only under an extra is optional.
// uv.lock does not partition the transitive closure, so a package pulled in by a
// dev dependency is not itself marked dev.
//
// PyPI names are compared and recorded normalized, as model.NormalizeName defines
// it, because uv.lock and a project's own requirements need not spell a name the
// same way.
//
// The TOML decoder reports no positions, so an entry is placed by its
// "[[package]]" header, matched in file order.
package uv

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Format is the name the parser registers under, which is also the file name it
// reads.
const Format = "uv.lock"

// packageHeader starts every entry. The decoder keeps the tables in file order, so
// the nth header in the file belongs to the nth package.
const packageHeader = "[[package]]"

func init() { lockfile.Register(Parser{}) }

// Parser reads uv.lock files. The zero value is ready to use.
type Parser struct{}

// Name returns the format name, "uv.lock".
func (Parser) Name() string { return Format }

// Detect reports whether the base name is a uv.lock. lockfile.For lowercases the
// name before asking, so the comparison is against the lowercase spelling.
func (Parser) Detect(base string) bool { return base == "uv.lock" }

// Parse reads a uv.lock. It fails only when the file is not TOML; a package table
// it cannot make sense of is dropped with a reason and the rest is kept.
func (Parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", Format, err)
	}
	var raw lockFile
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", Format, err)
	}

	lf := &lockfile.Lockfile{
		Path:      path,
		Format:    Format,
		Ecosystem: model.PyPI,
		Version:   formatVersion(raw.Version),
	}
	packages := decodePackages(&md, raw.Packages, data, lf)
	asked := requested(&raw.Manifest, packages)
	for i := range packages {
		p := &packages[i]
		if p.Source.Virtual != "" {
			lf.Drop("line %d: %q is the project itself (%s), not an installed package", p.line, p.Name, p.Source.describe())
			continue
		}
		kind, location := p.Source.kind()
		place, hash := p.artifact()
		if place == "" {
			place = location
		}
		lf.Add(lockfile.Entry{
			Ref:       model.PackageRef{Ecosystem: model.PyPI, Name: p.Name, Version: p.Version},
			Source:    kind,
			Resolved:  place,
			Integrity: hash,
			Direct:    asked.direct(p.Name, p.Version),
			Dev:       asked.devOnly(p.Name, p.Version),
			Optional:  asked.optionalOnly(p.Name, p.Version),
			Line:      p.line,
		})
	}
	return lf, nil
}

// lockFile is the shape of the file the parser reads. Packages stay undecoded so
// that one unreadable table costs one entry rather than the whole file.
type lockFile struct {
	Version  any              `toml:"version"`
	Manifest manifest         `toml:"manifest"`
	Packages []toml.Primitive `toml:"package"`
}

// manifest is the [manifest] table: what was asked of the resolver outside the
// workspace members.
type manifest struct {
	Members          []string                `toml:"members"`
	Requirements     []dependency            `toml:"requirements"`
	DependencyGroups map[string][]dependency `toml:"dependency-groups"`
}

// packageTable is one [[package]] table. Only the fields the checks need are read.
type packageTable struct {
	Name                 string                  `toml:"name"`
	Version              string                  `toml:"version"`
	Source               source                  `toml:"source"`
	Sdist                *artifact               `toml:"sdist"`
	Wheels               []artifact              `toml:"wheels"`
	Dependencies         []dependency            `toml:"dependencies"`
	OptionalDependencies map[string][]dependency `toml:"optional-dependencies"`
	// DevDependencies is what a newer uv writes as "dependency-groups"; both
	// spellings mean the project's dependency groups.
	DevDependencies  map[string][]dependency `toml:"dev-dependencies"`
	DependencyGroups map[string][]dependency `toml:"dependency-groups"`
}

// source is the "source" table. uv writes exactly one of these keys.
type source struct {
	Registry  string `toml:"registry"`
	Git       string `toml:"git"`
	URL       string `toml:"url"`
	Path      string `toml:"path"`
	Directory string `toml:"directory"`
	Editable  string `toml:"editable"`
	Virtual   string `toml:"virtual"`
}

// artifact is an [package.sdist] table or one of [[package.wheels]].
type artifact struct {
	URL  string `toml:"url"`
	Path string `toml:"path"`
	Hash string `toml:"hash"`
}

// dependency is one entry of a dependency or requirement list. uv writes the
// version only when the lockfile holds more than one of the package.
type dependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// decodedPackage is a package table, its normalized name and the line its header
// sits on.
type decodedPackage struct {
	packageTable
	line int
}

// decodePackages reads the package tables in file order, recording the ones it has
// to drop on the lockfile. Names come back normalized, so every later comparison is
// between normalized names.
func decodePackages(md *toml.MetaData, primitives []toml.Primitive, data []byte, lf *lockfile.Lockfile) []decodedPackage {
	finder := lockfile.NewLineFinder(data)
	packages := make([]decodedPackage, 0, len(primitives))
	for i := range primitives {
		line := finder.Find(packageHeader)
		var table packageTable
		if err := md.PrimitiveDecode(primitives[i], &table); err != nil {
			lf.Drop("line %d: unreadable [[package]] table: %v", line, err)
			continue
		}
		table.Name = model.NormalizeName(model.PyPI, table.Name)
		switch {
		case table.Name == "":
			lf.Drop("line %d: [[package]] without a name", line)
		case table.Version == "":
			lf.Drop("line %d: package %q without a version", line, table.Name)
		default:
			packages = append(packages, decodedPackage{packageTable: table, line: line})
		}
	}
	return packages
}

// formatVersion renders the "version" key, the integer uv writes for the format it
// wrote. A file without one reports an empty string.
func formatVersion(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case int64:
		return strconv.FormatInt(n, 10)
	case string:
		return n
	default:
		return fmt.Sprint(n)
	}
}

// kind classifies the source table and returns the location it names, as written.
// A virtual source is the project itself and is handled before this is called.
func (s *source) kind() (kind lockfile.Source, location string) {
	switch {
	case s.Registry != "":
		return lockfile.SourceRegistry, s.Registry
	case s.Git != "":
		return lockfile.SourceGit, s.Git
	case s.URL != "":
		return lockfile.SourceURL, s.URL
	case s.Path != "":
		return lockfile.SourcePath, s.Path
	case s.Directory != "":
		return lockfile.SourcePath, s.Directory
	case s.Editable != "":
		return lockfile.SourcePath, s.Editable
	default:
		return lockfile.SourceUnknown, ""
	}
}

// describe names the source the way the file spells it, for a dropped entry's
// reason.
func (s *source) describe() string {
	if s.Virtual != "" {
		return "virtual = " + strconv.Quote(s.Virtual)
	}
	kind, location := s.kind()
	if location == "" {
		return string(kind)
	}
	return string(kind) + " = " + strconv.Quote(location)
}

// project reports whether the package is the project uv locked or one of its
// workspace members, whose dependencies are the project's own.
func (p *decodedPackage) project(members map[string]bool) bool {
	return p.Source.Virtual != "" || p.Source.Editable != "" || members[p.Name]
}

// artifact returns the location and hash of what the entry pins: the sdist when the
// package has one, otherwise the first wheel. Either may be missing, and a package
// built from a directory or a git repository has neither.
func (p *decodedPackage) artifact() (location, hash string) {
	a := p.Sdist
	if a == nil && len(p.Wheels) > 0 {
		a = &p.Wheels[0]
	}
	if a == nil {
		return "", ""
	}
	location = a.URL
	if location == "" {
		location = a.Path
	}
	return location, a.Hash
}

// selection is what the project asks for itself, split by the table it asked in.
type selection struct {
	runtime  dependencySet
	optional dependencySet
	dev      dependencySet
}

// requested reads the project's own dependencies, from the [manifest] table and
// from the packages that are the project or one of its workspace members.
func requested(m *manifest, packages []decodedPackage) *selection {
	s := &selection{runtime: dependencySet{}, optional: dependencySet{}, dev: dependencySet{}}
	s.runtime.addAll(m.Requirements)
	s.dev.addGroups(m.DependencyGroups)

	members := make(map[string]bool, len(m.Members))
	for _, name := range m.Members {
		members[model.NormalizeName(model.PyPI, name)] = true
	}
	for i := range packages {
		p := &packages[i]
		if !p.project(members) {
			continue
		}
		s.runtime.addAll(p.Dependencies)
		s.optional.addGroups(p.OptionalDependencies)
		s.dev.addGroups(p.DevDependencies)
		s.dev.addGroups(p.DependencyGroups)
	}
	return s
}

// direct reports whether the project asks for the package in any of its tables.
func (s *selection) direct(name, version string) bool {
	return s.runtime.has(name, version) || s.optional.has(name, version) || s.dev.has(name, version)
}

// devOnly reports whether the project asks for the package only in a dependency
// group.
func (s *selection) devOnly(name, version string) bool {
	return s.dev.has(name, version) && !s.runtime.has(name, version) && !s.optional.has(name, version)
}

// optionalOnly reports whether the project asks for the package only under an
// extra.
func (s *selection) optionalOnly(name, version string) bool {
	return s.optional.has(name, version) && !s.runtime.has(name, version)
}

// dependencySet holds dependency names, and names with a version when the file
// pins one, so that a lockfile carrying two versions of a package marks the one
// that is really asked for and not both.
type dependencySet map[string]bool

// addAll records a list of dependencies.
func (s dependencySet) addAll(deps []dependency) {
	for _, dep := range deps {
		name := model.NormalizeName(model.PyPI, dep.Name)
		if name == "" {
			continue
		}
		s[dependencyKey(name, dep.Version)] = true
	}
}

// addGroups records every dependency of every group.
func (s dependencySet) addGroups(groups map[string][]dependency) {
	for _, deps := range groups {
		s.addAll(deps)
	}
}

// has reports whether the package is in the set, by name or at this version.
func (s dependencySet) has(name, version string) bool {
	return s[dependencyKey(name, "")] || s[dependencyKey(name, version)]
}

// dependencyKey is the set key for a name and an optional version.
func dependencyKey(name, version string) string {
	if version == "" {
		return name
	}
	return name + " " + version
}
