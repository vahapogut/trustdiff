// Package poetry reads poetry.lock, the file Poetry writes to pin the Python
// distributions a project installs.
//
// The current format is what Poetry 2 writes, "lock-version" 2.0 or 2.1, and it is
// shaped like Cargo.lock: an array of [[package]] tables, then a [metadata] table
// holding the lock version, the Python versions the lock was solved for and a hash
// of the pyproject.toml it was solved from. The lock version is what the entry set
// records as Lockfile.Version, and a file that spells it as a number rather than as
// a string states it just as well; a metadata value nothing can be made of costs
// that one field and a dropped reason, because the packages the file pins are worth
// evaluating whatever its metadata says. Older files parse too, because every
// version of the format has written the same name, version and source keys.
//
// What the parser reads from a [[package]] table:
//
//   - name and version. PyPI names are compared and recorded PEP 503 normalized, as
//     model.NormalizeName defines it, because poetry.lock spells a name the way the
//     distribution's author wrote it and a project's own requirements need not agree.
//   - "optional", which is true when the package is only installed with an extra.
//   - which dependency groups need the package. Poetry 2 writes "groups", the list
//     of groups whose resolution reached the package, and the runtime group is
//     called "main"; Poetry 1 wrote "category", one group name, with the same
//     meaning for "main". Either way an entry is Dev when the file says a group
//     needs it and none of them is "main", which is the honest reading of both
//     spellings: a package the runtime needs is not a development dependency even
//     when the test group needs it as well.
//   - the "source" table, whose "type" names the origin, described below.
//   - "files", the artifacts the version may be installed from, each with a name and
//     a hash Poetry writes as "sha256:<hex>". Entry.Integrity holds one hash and the
//     file gives no way to say which artifact an install will pick, so the entry
//     records the sdist's hash when the version has an sdist and the first file's
//     otherwise. The sdist is preferred because it is the one artifact a
//     distribution publishes at most once, whichever platform installs it, and
//     because internal/lockfile/uv makes the same choice: the same distribution
//     pinned by uv and by Poetry then reports the same hash. Poetry 1 kept the same
//     lists in a [metadata.files] table keyed by package name, and those are read
//     too.
//
// The "source" table is written only when the package does not come from the index
// Poetry was configured with, and its "type" says where it did come from:
//
//	type = "legacy"     an index other than the default   registry
//	type = "git"        a git repository                  git
//	type = "url"        an archive fetched by URL         url
//	type = "file"       an archive on the machine         path
//	type = "directory"  a directory on the machine        path
//
// A package with no source table came from the default index, which is what Source
// records; Resolved stays empty for it, because the file never names that index and
// a project pointed at a mirror would otherwise be reported as installing from PyPI.
// A "type" spelled some other way is an origin this parser does not know, and the
// entry says so rather than claiming the index. For a git source Resolved is the
// remote with the commit Poetry resolved appended, "https://host/repo.git#<sha>",
// because the two are separate keys in the file and Entry.Resolved holds one
// location. The source's "subdirectory" is not part of it: it names a folder inside
// the checkout rather than where the checkout came from.
//
// Direct is left false on every entry, which Entry.Direct documents as what a parser
// that cannot tell does. poetry.lock records the resolved graph and nothing else:
// the packages the project itself asks for live in its pyproject.toml, which is a
// different file, and "groups" says which group's resolution reached a package
// rather than whether the project named it. Poetry's own "develop" flag is not read
// for the same reason: it says a directory or git source is installed in place, not
// that the project depends on it directly.
//
// The TOML decoder reports no positions, so an entry is placed by its
// "[[package]]" header, matched in file order and confirmed against the name the
// table declares, which is what lockfile.TableFinder does. A header spelled inside
// a string value is neither counted nor matched, and an entry the finder cannot
// place carries no line rather than another package's. A name written with a TOML
// escape is one the decoder reads and no header spells, so it is placed nowhere and
// carries the same zero: a package that cannot be pointed at is still a package,
// and it is evaluated with the rest.
//
// Format verified against Poetry's locker on 2026-09-09:
// https://github.com/python-poetry/poetry/blob/main/src/poetry/packages/locker.py
package poetry

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Format is the name the parser registers under, which is also the file name it
// reads.
const Format = "poetry.lock"

// packageHeader starts every entry. The decoder keeps the tables in file order, so
// the nth header in the file belongs to the nth package.
const packageHeader = "[[package]]"

// runtimeGroup is what Poetry calls the dependencies an install needs to run, as
// opposed to the groups a developer adds. Both spellings of the field use the name.
const runtimeGroup = "main"

// wheelSuffix ends the file name of a built distribution. Anything else in a
// "files" list is a source distribution.
const wheelSuffix = ".whl"

// The [metadata] table and the two keys the parser reads out of it, named here
// because a reason a value is not read has to name the key a reader must look at.
const (
	metadataTable  = "metadata"
	lockVersionKey = "lock-version"
	filesKey       = "files"
)

// tomlTable is what the decoder calls a table when it is asked what type a key was
// written with.
const tomlTable = "Hash"

func init() { lockfile.Register(Parser{}) }

// Parser reads poetry.lock files. The zero value is ready to use.
type Parser struct{}

// Name returns the format name, "poetry.lock".
func (Parser) Name() string { return Format }

// Detect reports whether the base name is a poetry.lock. lockfile.For lowercases
// the name before asking, so the comparison is against the lowercase spelling.
func (Parser) Detect(base string) bool { return base == Format }

// Parse reads a poetry.lock. It fails only when the file is not TOML; a package
// table or a metadata value it cannot make sense of is dropped with a reason and
// the rest is kept.
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
	}
	packages := decodePackages(&md, raw.Packages, data, lf)
	// The metadata is read after the packages so that the reasons come out in file
	// order, [metadata] being the table Poetry writes last.
	meta := readMetadata(&md, raw.Metadata, lf)
	lf.Version = meta.lockVersion
	legacy := normalizedFiles(meta.files)
	for i := range packages {
		p := &packages[i]
		kind, location := p.Source.kind()
		lf.Add(lockfile.Entry{
			Ref:       model.PackageRef{Ecosystem: model.PyPI, Name: p.Name, Version: p.Version},
			Source:    kind,
			Resolved:  location,
			Integrity: integrity(p.files(legacy)),
			Dev:       p.dev(),
			Optional:  p.Optional,
			Line:      p.line,
		})
	}
	return lf, nil
}

// lockFile is the shape of the file the parser reads. The package tables and the
// metadata values stay undecoded so that one of them the parser cannot read costs
// that one table or that one value rather than the whole file.
type lockFile struct {
	Packages []toml.Primitive          `toml:"package"`
	Metadata map[string]toml.Primitive `toml:"metadata"`
}

// metadata is what the parser reads out of the [metadata] table. The content hash
// and the Python versions say what the lock was solved from and for, neither of
// which is a package fact, so only the lock version and the first format's file
// lists are read.
type metadata struct {
	lockVersion string
	// files is where the first format versions kept the artifact hashes, keyed by
	// package name, before they moved onto the package table.
	files map[string][]file
}

// readMetadata reads [metadata] one key at a time. Poetry writes the table, but a
// merge or a hand edit rewrites it, and a lock version spelled as a number instead
// of a string is the usual way it comes back wrong: the packages that file pins are
// worth evaluating all the same, so a value this parser cannot use costs that one
// field and a reason rather than the file.
func readMetadata(md *toml.MetaData, table map[string]toml.Primitive, lf *lockfile.Lockfile) metadata {
	var meta metadata
	if value, ok := table[lockVersionKey]; ok {
		version, stated := lockVersion(md, value)
		if !stated {
			lf.Drop("[%s]: %q is %s, not a version, so the file states none", metadataTable, lockVersionKey, describeType(md, metadataTable, lockVersionKey))
		}
		meta.lockVersion = version
	}
	if value, ok := table[filesKey]; ok {
		files, err := legacyFiles(md, value)
		if err != nil {
			lf.Drop("[%s]: %q is not the table of artifact lists this format writes (%v), so the hashes it holds are not read", metadataTable, filesKey, err)
		}
		meta.files = files
	}
	return meta
}

// lockVersion reads the "lock-version" value however the file spelled it. Poetry
// writes a string; a file somebody edited spells the same version as a number,
// which states it just as plainly, and a whole one keeps the fraction a TOML float
// carries so that 2.0 does not come back as "2". Anything else is not a version.
func lockVersion(md *toml.MetaData, value toml.Primitive) (string, bool) {
	var text string
	if err := md.PrimitiveDecode(value, &text); err == nil {
		return text, true
	}
	var whole int64
	if err := md.PrimitiveDecode(value, &whole); err == nil {
		return strconv.FormatInt(whole, 10), true
	}
	var number float64
	// A lock version that is not a finite number names no format version, and
	// "NaN" in a report would send a reader looking for a release that never was.
	if err := md.PrimitiveDecode(value, &number); err == nil && !math.IsInf(number, 0) && !math.IsNaN(number) {
		text := strconv.FormatFloat(number, 'f', -1, 64)
		if !strings.Contains(text, ".") {
			text += ".0"
		}
		return text, true
	}
	return "", false
}

// legacyFiles decodes the [metadata.files] table of the first format versions. A
// value that is not a table at all is passed over by the decoder rather than
// refused, so the type is read first: a file list nothing was read from is a set of
// hashes silently missing from the entries, which is worth a reason of its own.
func legacyFiles(md *toml.MetaData, value toml.Primitive) (map[string][]file, error) {
	if md.Type(metadataTable, filesKey) != tomlTable {
		return nil, fmt.Errorf("it is %s", describeType(md, metadataTable, filesKey))
	}
	var files map[string][]file
	if err := md.PrimitiveDecode(value, &files); err != nil {
		return nil, err
	}
	return files, nil
}

// describeType names the type the file wrote a key with, so that a reason says what
// to go and look at. The decoder knows every key's type whether or not the value
// was decoded into anything.
func describeType(md *toml.MetaData, key ...string) string {
	switch name := md.Type(key...); name {
	case "":
		return "of a type the decoder does not name"
	case tomlTable:
		return "a table"
	case "ArrayHash":
		return "an array of tables"
	case "Array", "Integer":
		return "an " + strings.ToLower(name)
	default:
		return "a " + strings.ToLower(name)
	}
}

// packageTable is one [[package]] table. Only the fields the checks need are read;
// the description, the Python versions, the dependency graph and the extras all
// describe the package rather than the version that is pinned.
type packageTable struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Optional bool   `toml:"optional"`
	// Category is Poetry 1's spelling: the one group that needed the package.
	Category string `toml:"category"`
	// Groups is Poetry 2's spelling: every group whose resolution reached it.
	Groups []string `toml:"groups"`
	Source source   `toml:"source"`
	Files  []file   `toml:"files"`
}

// source is the "source" table, written only for a package that does not come from
// the default index.
type source struct {
	Type              string `toml:"type"`
	URL               string `toml:"url"`
	Reference         string `toml:"reference"`
	ResolvedReference string `toml:"resolved_reference"`
}

// file is one artifact of a version: the file name and the hash of its bytes.
type file struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
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
	finder := lockfile.NewTableFinder(data, packageHeader)
	packages := make([]decodedPackage, 0, len(primitives))
	for i := range primitives {
		var table packageTable
		if err := md.PrimitiveDecode(primitives[i], &table); err != nil {
			lf.Drop("%s: unreadable [[package]] table: %v", lockfile.At(finder.Next("")), err)
			continue
		}
		// The finder confirms a header against the name the table writes, so the
		// name is read before it is normalized and the entry is placed on the
		// header of its own table.
		line := finder.Next(table.Name)
		table.Name = model.NormalizeName(model.PyPI, table.Name)
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

// dev reports whether the package is needed only to develop or test the project.
// Poetry 2 lists every group that reached it and Poetry 1 named the one that did;
// either way the package is a development dependency when a group is named and the
// runtime group is not among them.
func (p *decodedPackage) dev() bool {
	if len(p.Groups) > 0 {
		for _, group := range p.Groups {
			if group == runtimeGroup {
				return false
			}
		}
		return true
	}
	return p.Category != "" && p.Category != runtimeGroup
}

// files returns the artifacts of the version: the package's own list, or the one
// the first format versions kept in [metadata.files] under its name.
func (p *decodedPackage) files(legacy map[string][]file) []file {
	if len(p.Files) > 0 {
		return p.Files
	}
	return legacy[p.Name]
}

// normalizedFiles indexes a [metadata.files] table by normalized package name, so
// that a lookup does not depend on how the file spelled the name.
func normalizedFiles(byName map[string][]file) map[string][]file {
	if len(byName) == 0 {
		return nil
	}
	files := make(map[string][]file, len(byName))
	for name, list := range byName {
		files[model.NormalizeName(model.PyPI, name)] = list
	}
	return files
}

// integrity returns the hash the entry records: the sdist's when the version has
// one, and otherwise the first file's. The package comment says why the sdist wins.
func integrity(files []file) string {
	for _, f := range files {
		if !strings.HasSuffix(strings.ToLower(f.File), wheelSuffix) {
			return f.Hash
		}
	}
	if len(files) > 0 {
		return files[0].Hash
	}
	return ""
}

// kind classifies the source table and returns the location it names. A package
// with no source table came from the default index, which the file does not name,
// so it reports the index with no location.
func (s *source) kind() (kind lockfile.Source, location string) {
	switch s.Type {
	case "":
		return lockfile.SourceRegistry, ""
	case "legacy":
		return lockfile.SourceRegistry, s.URL
	case "git":
		return lockfile.SourceGit, s.gitLocation()
	case "url":
		return lockfile.SourceURL, s.URL
	case "file", "directory":
		return lockfile.SourcePath, s.URL
	default:
		return lockfile.SourceUnknown, s.URL
	}
}

// gitLocation joins the remote and the revision, which the file keeps in separate
// keys, into the one location Entry.Resolved holds. Poetry writes
// "resolved_reference" once it has locked a commit and "reference" is what the
// project asked for, so the resolved one wins and the asked for one is the fallback
// for a lock written before Poetry recorded it.
func (s *source) gitLocation() string {
	revision := s.ResolvedReference
	if revision == "" {
		revision = s.Reference
	}
	if revision == "" {
		return s.URL
	}
	return s.URL + "#" + revision
}
