// Package cargo reads Cargo.lock, the file Cargo writes to pin the crate versions
// a Rust project builds against.
//
// Format versions 3 and 4 are what Cargo writes today, and they differ only in how
// they spell a git source URL, so one reader serves both. The older versions parse
// too: every version of the format lists its crates as [[package]] tables with a
// name, a version and an optional source, and the first two versions keep their
// hashes in a [metadata] table instead of on the package.
//
// What the parser reads from a [[package]] table:
//
//   - name and version. A crates.io name keeps its case and its hyphens, so the ref
//     carries the name as the file writes it.
//   - source. A "registry+" or "sparse+" prefix is the registry, "git+" is a git
//     repository and "path+" is a directory on the machine; anything else is an
//     origin this parser does not know. The source is recorded as written.
//   - checksum, a bare sha256 hex string, which the entry records as "sha256:<hex>"
//     so the hash names its algorithm the way every other ecosystem's does. Format
//     versions 1 and 2 keep the same hashes under a [metadata] key spelled
//     "checksum <name> <version> (<source>)", and those are read too. A package with
//     no checksum, and one whose metadata checksum is "<none>", carries no hash.
//
// A package without a source is the project itself or one of its workspace members:
// Cargo names those by the workspace rather than by an origin. They are path
// entries, and everything such a package lists in "dependencies" is a direct
// dependency of the project, which is how Direct is decided. Cargo.lock records
// nothing about a dependency's kind, so entries are never marked dev or optional
// even when a crate is only ever built for tests.
//
// The TOML decoder reports no positions, so an entry is placed by its
// "[[package]]" header, matched in file order and confirmed against the name the
// table declares, which is what lockfile.TableFinder does. A header spelled inside
// a string value is neither counted nor matched, and an entry the finder cannot
// place carries no line rather than another package's.
package cargo

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Format is the name the parser registers under, which is also the file name it
// reads.
const Format = "Cargo.lock"

// packageHeader starts every entry. The decoder keeps the tables in file order, so
// the nth header in the file belongs to the nth package.
const packageHeader = "[[package]]"

// noChecksum is what format versions 1 and 2 write for a package the workspace
// builds itself.
const noChecksum = "<none>"

func init() { lockfile.Register(Parser{}) }

// Parser reads Cargo.lock files. The zero value is ready to use.
type Parser struct{}

// Name returns the format name, "Cargo.lock".
func (Parser) Name() string { return Format }

// Detect reports whether the base name is a Cargo.lock. lockfile.For lowercases the
// name before asking, so the comparison is against the lowercase spelling.
func (Parser) Detect(base string) bool { return base == "cargo.lock" }

// Parse reads a Cargo.lock. It fails only when the file is not TOML; a package
// table it cannot make sense of is dropped with a reason and the rest is kept.
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
		Ecosystem: model.Cargo,
		Version:   formatVersion(raw.Version),
	}
	packages := decodePackages(&md, raw.Packages, data, lf)
	direct := directDependencies(packages)
	for i := range packages {
		p := &packages[i]
		if p.Source == "" {
			// The root package and every workspace member, which Cargo writes with
			// no source and no checksum because it builds them from the directory it
			// found them in. They are the repository being scanned, not something it
			// installs, and reporting them gave a clean checkout of a workspace one
			// warning per crate of its own. directDependencies has already read
			// their dependency lists, which is what makes the rest direct.
			lf.Drop("%s: %q is this workspace, not an installed crate", lockfile.At(p.line), p.Name)
			continue
		}
		lf.Add(lockfile.Entry{
			// NormalizeName leaves a crates.io name alone; it is called so the
			// identity rule lives in one place.
			Ref:       model.PackageRef{Ecosystem: model.Cargo, Name: model.NormalizeName(model.Cargo, p.Name), Version: p.Version},
			Source:    sourceKind(p.Source),
			Resolved:  p.Source,
			Integrity: integrity(p, raw.Metadata),
			Direct:    direct.has(p.Name, p.Version),
			Line:      p.line,
		})
	}
	return lf, nil
}

// lockFile is the shape of the file the parser reads. Packages stay undecoded so
// that one unreadable table costs one entry rather than the whole file.
type lockFile struct {
	Version  any              `toml:"version"`
	Packages []toml.Primitive `toml:"package"`
	Metadata map[string]any   `toml:"metadata"`
}

// packageTable is one [[package]] table.
type packageTable struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

// decodedPackage is a package table and the line its header sits on.
type decodedPackage struct {
	packageTable
	line int
}

// decodePackages reads the package tables in file order, recording the ones it has
// to drop on the lockfile.
func decodePackages(md *toml.MetaData, primitives []toml.Primitive, data []byte, lf *lockfile.Lockfile) []decodedPackage {
	finder := lockfile.NewTableFinder(data, packageHeader)
	packages := make([]decodedPackage, 0, len(primitives))
	for i := range primitives {
		var table packageTable
		if err := md.PrimitiveDecode(primitives[i], &table); err != nil {
			lf.Drop("%s: unreadable [[package]] table: %v", lockfile.At(finder.Next("")), err)
			continue
		}
		// The name is what the finder confirms a header with, so the entry is
		// placed on the header of its own table and not on a header a value spells.
		line := finder.Next(table.Name)
		switch {
		case table.Name == "":
			lf.Drop("%s: [[package]] without a name", lockfile.At(line))
		case table.Version == "":
			lf.Drop("%s: package %q without a version", lockfile.At(line), table.Name)
		default:
			packages = append(packages, decodedPackage{packageTable: table, line: line})
		}
	}
	return packages
}

// formatVersion renders the "version" key. Cargo writes an integer, 3 or 4 today;
// the first two format versions wrote no version key at all, which reports as an
// empty string.
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

// sourceKind classifies the "source" string. An empty source is the project or one
// of its workspace members, which Cargo builds from the directory it found it in.
func sourceKind(source string) lockfile.Source {
	switch {
	case source == "":
		return lockfile.SourcePath
	case strings.HasPrefix(source, "registry+"), strings.HasPrefix(source, "sparse+"):
		return lockfile.SourceRegistry
	case strings.HasPrefix(source, "git+"):
		return lockfile.SourceGit
	case strings.HasPrefix(source, "path+"):
		return lockfile.SourcePath
	default:
		return lockfile.SourceUnknown
	}
}

// integrity returns the package's hash as "sha256:<hex>", from the package's own
// checksum or, for the first two format versions, from the [metadata] table.
func integrity(p *decodedPackage, metadata map[string]any) string {
	sum := p.Checksum
	if sum == "" {
		sum = metadataChecksum(metadata, p)
	}
	if sum == "" || sum == noChecksum {
		return ""
	}
	return "sha256:" + sum
}

// metadataChecksum reads a checksum written the way format versions 1 and 2 wrote
// them, under a key naming the package and its source.
func metadataChecksum(metadata map[string]any, p *decodedPackage) string {
	if len(metadata) == 0 {
		return ""
	}
	sum, _ := metadata[fmt.Sprintf("checksum %s %s (%s)", p.Name, p.Version, p.Source)].(string)
	return sum
}

// directDependencies collects what the project depends on itself. A package without
// a source is the project or one of its workspace members, so everything it lists
// in "dependencies" is direct.
func directDependencies(packages []decodedPackage) dependencySet {
	direct := dependencySet{}
	for i := range packages {
		if packages[i].Source != "" {
			continue
		}
		for _, dep := range packages[i].Dependencies {
			direct.add(splitDependency(dep))
		}
	}
	return direct
}

// splitDependency reads one entry of a "dependencies" list, which is a name,
// optionally followed by a version and the source in parentheses: "memchr",
// "memchr 2.7.4", or "memchr 2.7.4 (registry+https://github.com/rust-lang/crates.io-index)".
// Cargo writes the version only when the lockfile holds more than one of the crate.
func splitDependency(dep string) (name, version string) {
	fields := strings.Fields(dep)
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return fields[0], ""
	default:
		return fields[0], fields[1]
	}
}

// dependencySet holds dependency names, and names with a version when the file
// pins one, so that a lockfile carrying two versions of a crate marks the one that
// is really depended on and not both.
type dependencySet map[string]bool

// add records one dependency.
func (s dependencySet) add(name, version string) {
	if name == "" {
		return
	}
	s[dependencyKey(name, version)] = true
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
