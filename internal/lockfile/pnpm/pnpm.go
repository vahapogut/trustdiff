// Package pnpm reads pnpm-lock.yaml, in the two shapes still found in
// repositories: lockfileVersion 6, written by pnpm 8, and lockfileVersion 9,
// written by pnpm 9 and later.
//
// The two differ in how they key the "packages" map. Version 6 keys it by the path
// pnpm resolves a dependency to, "/name@version" or "/@scope/name@version", with the
// peer dependencies it resolved for that copy appended to the key,
// "/vue@3.4.0(typescript@5.4.2)", and it marks development and optional dependencies
// on the package itself with "dev: true" and "optional: true". Version 9 drops the
// leading slash and the suffix, keying "packages" by "name@version" alone, and moves
// the dependency graph, with the suffixed spellings and the optional flags, into a
// separate "snapshots" map. Either version keys a package the registry does not host
// by where it came from instead of by a version, and then states the name and the
// version on the entry, which is what this parser believes over the key.
//
// A key is read by cutting anything from the first "(" and splitting the rest at its
// last "@", which leaves a scoped name the "@" it starts with.
//
// That "snapshots" map is not read. It says which package depends on which, and
// the checks evaluate one package version at a time, so none of it is needed. The
// price is that in a version 9 file a transitive entry's Dev and Optional flags
// are unknown and stay false, where a version 6 file states them on the package.
//
// Direct dependencies come from "importers": one section per project in the
// workspace, the project itself being ".", each listing its "dependencies",
// "devDependencies" and "optionalDependencies" with the specifier from package.json
// and the version pnpm resolved it to. A version 6 file for a single project writes
// those three sections at the top level and no "importers" at all; both spellings
// are read. An importer entry resolved to "link:..." names a directory rather than
// a package version and has no entry in "packages", so it is skipped.
//
// A current pnpm writes the file as more than one yaml document: a lockfile for
// the package manager the project pins, then the project's own lockfile, joined by
// a "---" separator. Every document is read and its entries are kept, because the
// package manager's own downloads are code the repository installs too, and
// because reading only the first would report those nine entries and silently drop
// the thousands the project locks. The version the entry set reports is the one the
// last document declares, which is the project's.
//
// Where an entry came from is read from its resolution, with one case that needs
// care: a tarball URL is not by itself a package from outside the registry. pnpm
// keeps the URL whenever the registry's download URL is not the canonical
// <registry>/<name>/-/<file>.tgz, which is the case for GitHub Packages and npm
// Enterprise, and for every package when lockfile-include-tarball-url is set. Such
// an entry is a registry install and is recorded as one, with the URL as its
// resolved location; what makes a tarball a URL dependency is the key stating the
// URL instead of a version, a resolution pnpm flagged as hosted by a git forge, or
// a host the rest of the file does not install from.
//
// Line numbers come from the yaml node of each "packages" key, which is what the
// node API reports, so a finding points at the line the entry starts on. yaml.v3
// counts lines across the whole stream, so an entry in the second document carries
// the line it really sits on.
package pnpm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// formatName is the file this parser reads, and the name it registers under.
const formatName = "pnpm-lock.yaml"

// minLockfileVersion is the oldest format read here. Version 5, written by pnpm 7,
// keys packages "/name/version" and separates the specifiers from the resolved
// versions; saying that a file is too old is more use than dropping every entry of
// it. A file that declares no version, or one that does not begin with a number, is
// read anyway: the shapes below are recognized per entry, not per version.
const minLockfileVersion = 6

func init() { lockfile.Register(parser{}) }

// parser reads pnpm-lock.yaml. It registers itself, so importing this package for
// its side effect is all a caller needs.
type parser struct{}

func (parser) Name() string { return formatName }

func (parser) Detect(base string) bool { return base == formatName }

func (parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", formatName, err)
	}
	roots, err := documents(data)
	if err != nil && len(roots) == 0 {
		return nil, err
	}

	lf := &lockfile.Lockfile{Path: path, Format: formatName, Ecosystem: model.NPM}
	if err != nil {
		// One document read and the next one unreadable: the documents already
		// read are still worth evaluating, and the rest is said out loud.
		lf.Drop("the file stops being valid yaml after %s, so the rest of it was not read: %v", documentCount(len(roots)), err)
	}
	mappings := make([]*yaml.Node, 0, len(roots))
	for _, root := range roots {
		if root.Kind != yaml.MappingNode {
			lf.Drop("the document on line %d is not a mapping, nothing was read from it", root.Line)
			continue
		}
		mappings = append(mappings, root)
	}
	if len(mappings) == 0 {
		return nil, fmt.Errorf("%s: want a mapping of lockfileVersion, importers and packages at the top level", formatName)
	}

	hosts := countRegistryHosts(mappings)
	for _, root := range mappings {
		// Every document states its own version, and the project's is the last, so
		// the one the entry set reports is the one the entries came from.
		if version := scalar(root, "lockfileVersion"); version != "" {
			if err := checkVersion(version); err != nil {
				return nil, err
			}
			lf.Version = version
		}
		direct := collectImporters(root)
		packages := mapValue(root, "packages")
		switch {
		case packages == nil:
			// A project that locks no dependency at all writes no packages map.
			continue
		case packages.Kind != yaml.MappingNode:
			lf.Drop("packages on line %d is not a mapping, no entry was read", packages.Line)
			continue
		}
		for _, pkg := range fields(packages) {
			addPackage(lf, direct, pkg, hosts)
		}
	}
	return lf, nil
}

// documents returns the root node of every yaml document in the file. pnpm writes
// more than one: a lockfile of its own for the package manager the project pins,
// then the project's lockfile, joined by a document separator. Reading only the
// first would report the nine entries of the package manager and silently drop the
// several thousand the project locks.
//
// A stream that stops being yaml part way through returns the documents read so
// far together with the error, so that the caller can keep what it has and say
// what it could not read.
func documents(data []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var roots []*yaml.Node
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return roots, nil
		}
		if err != nil {
			return roots, fmt.Errorf("%s is not valid yaml: %w", formatName, err)
		}
		if root := documentRoot(&doc); root != nil {
			roots = append(roots, root)
		}
	}
}

// documentCount words a number of yaml documents for a dropped reason.
func documentCount(n int) string {
	if n == 1 {
		return "one document"
	}
	return strconv.Itoa(n) + " documents"
}

// countRegistryHosts weighs the hosts the file downloads from, so that the registry
// a project installs through can be told from a host one entry points at alone. A
// tarball that is a URL dependency in its own right is not counted, because it says
// nothing about where the project's packages come from.
func countRegistryHosts(roots []*yaml.Node) *lockfile.RegistryHosts {
	hosts := lockfile.NPMRegistryHosts()
	for _, root := range roots {
		for _, pkg := range fields(mapValue(root, "packages")) {
			resolution := mapValue(pkg.val, "resolution")
			tarball := scalar(resolution, "tarball")
			if tarball == "" || fetchedByURL(pkg.key.Value, tarball, resolution) {
				continue
			}
			if u, err := url.Parse(tarball); err == nil {
				hosts.Count(u.Hostname())
			}
		}
	}
	return hosts
}

// checkVersion rejects a format older than this parser reads. A file that declares
// no version, or one that does not begin with a number, is read anyway.
func checkVersion(version string) error {
	major, _, _ := strings.Cut(version, ".")
	if n, err := strconv.Atoi(major); err == nil && n < minLockfileVersion {
		return fmt.Errorf("%s: lockfileVersion %s is not supported, this parser reads version %d and later (pnpm 8 and later)", formatName, version, minLockfileVersion)
	}
	return nil
}

// addPackage reads one entry of the packages map onto the lockfile.
func addPackage(lf *lockfile.Lockfile, direct map[string]*importerRef, pkg field, hosts *lockfile.RegistryHosts) {
	key := pkg.key.Value
	if pkg.val.Kind != yaml.MappingNode {
		lf.Drop("package %q on line %d has no metadata", key, pkg.key.Line)
		return
	}

	// A package the npm registry does not host, a git checkout or a tarball, states
	// its own name and version, because its key states where it came from instead of
	// a version. What the entry states wins over what the key implies.
	name, version := splitKey(key)
	if stated := scalar(pkg.val, "name"); stated != "" {
		name = stated
	}
	if stated := scalar(pkg.val, "version"); stated != "" {
		version = stated
	}
	if name == "" || version == "" {
		lf.Drop("package %q on line %d names no package version", key, pkg.key.Line)
		return
	}

	resolution := mapValue(pkg.val, "resolution")
	source, resolved := classify(key, resolution, hosts)
	entry := lockfile.Entry{
		Ref: model.PackageRef{
			Ecosystem: model.NPM,
			Name:      model.NormalizeName(model.NPM, name),
			Version:   version,
		},
		Source:    source,
		Resolved:  resolved,
		Integrity: scalar(resolution, "integrity"),
		Dev:       boolean(pkg.val, "dev"),
		Optional:  boolean(pkg.val, "optional"),
		Line:      pkg.key.Line,
	}
	if ref := direct[normalizeKey(key)]; ref != nil {
		entry.Direct = true
		// A package every importer section calls a development dependency is one;
		// a package any project needs at runtime is not. Optional reads the same way,
		// because an install may leave out only what no section requires.
		entry.Dev = entry.Dev || ref.sections == ref.dev
		entry.Optional = entry.Optional || ref.sections == ref.optional
	}
	lf.Add(entry)
}

// classify reads where a resolution says the version came from. pnpm writes one
// shape per origin: a directory names it and says so, a git checkout carries the
// remote and the commit, a tarball carries its URL, and a package from the registry
// carries the integrity hash alone. An entry with no resolution at all states no
// origin, which is not the same as coming from the registry and is not reported as
// one.
func classify(key string, resolution *yaml.Node, hosts *lockfile.RegistryHosts) (lockfile.Source, string) {
	if resolution == nil {
		return lockfile.SourceUnknown, ""
	}
	kind := scalar(resolution, "type")
	tarball := scalar(resolution, "tarball")
	switch {
	case kind == "directory" || scalar(resolution, "directory") != "":
		return lockfile.SourcePath, scalar(resolution, "directory")
	case kind == "git" || scalar(resolution, "repo") != "":
		repo, commit := scalar(resolution, "repo"), scalar(resolution, "commit")
		if commit != "" {
			repo += "#" + commit
		}
		return lockfile.SourceGit, repo
	case strings.HasPrefix(tarball, "file:"):
		// A tarball already on the machine, which is a path and not a download.
		return lockfile.SourcePath, tarball
	case tarball != "":
		if fetchedByURL(key, tarball, resolution) || !registryHost(tarball, hosts) {
			return lockfile.SourceURL, tarball
		}
		// A registry whose download URL is not the canonical one, which is why
		// pnpm wrote the URL down. The entry records it, so that TD014 can see a
		// registry reached over plain http.
		return lockfile.SourceRegistry, tarball
	default:
		// The registry resolution is the one that names nothing but its hash, and
		// pnpm records no URL for it because the registry is a setting, not a fact
		// about the package. A missing hash here is what TD014 reports.
		return lockfile.SourceRegistry, ""
	}
}

// fetchedByURL reports whether a resolution that carries a tarball is a dependency
// on that URL rather than an install from a registry that spells its downloads
// unusually. pnpm keeps the tarball URL for GitHub Packages and npm Enterprise,
// whose paths are not the canonical <registry>/<name>/-/<file>.tgz, and for every
// package when lockfile-include-tarball-url is set, so the URL alone says nothing.
// What marks a real URL dependency is the key, which states the URL where a version
// would be, or a resolution pnpm flagged as hosted by a git forge, which is what
// "github:owner/repo#ref" resolves to.
func fetchedByURL(key, tarball string, resolution *yaml.Node) bool {
	return boolean(resolution, "gitHosted") || gitHostTarball(tarball) || statesURL(key)
}

// gitHostTarball reports whether the URL is a git forge's source archive: GitHub's
// codeload, a GitLab repository archive or a Bitbucket "get" archive. An older pnpm
// wrote these without the gitHosted flag.
func gitHostTarball(tarball string) bool {
	u, err := url.Parse(tarball)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "codeload.github.com":
		return true
	case host == "github.com" && (strings.Contains(u.Path, "/archive/") || strings.Contains(u.Path, "/tarball/")):
		return true
	case strings.Contains(u.Path, "/repository/archive.tar"):
		return true
	case strings.Contains(host, "bitbucket") && strings.Contains(u.Path, "/get/"):
		return true
	default:
		return false
	}
}

// statesURL reports whether the packages key states where the package came from
// instead of a version, which is how pnpm keys a dependency on a URL. Version 9
// writes "name@<url>" and version 6 writes the URL alone, so both halves are asked.
func statesURL(key string) bool {
	k := normalizeKey(key)
	if isURL(k) {
		return true
	}
	_, version := splitKey(key)
	return isURL(version)
}

// isURL reports whether the text names a host over a scheme, which no version does.
func isURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// registryHost reports whether the tarball's host is the registry this project
// installs from: a known one, or one the rest of the file agrees on. A host a
// single entry names on its own is not, so a pull request cannot turn a package
// into a download from somewhere else and still read as a registry install.
func registryHost(tarball string, hosts *lockfile.RegistryHosts) bool {
	u, err := url.Parse(tarball)
	if err != nil {
		return false
	}
	return hosts.Known(u.Hostname()) || hosts.Serves(u.Hostname())
}

// importerRef is how the importers name one package: how many sections name it at
// all, and how many of those were devDependencies or optionalDependencies.
type importerRef struct {
	sections int
	dev      int
	optional int
}

// collectImporters indexes every package the projects depend on directly, by the
// key the packages map would use for it.
func collectImporters(root *yaml.Node) map[string]*importerRef {
	direct := make(map[string]*importerRef)
	importers := mapValue(root, "importers")
	if importers == nil {
		// A version 6 file for a single project writes the sections at the top level.
		addImporter(direct, root)
		return direct
	}
	for _, importer := range fields(importers) {
		addImporter(direct, importer.val)
	}
	return direct
}

func addImporter(direct map[string]*importerRef, block *yaml.Node) {
	addSection(direct, mapValue(block, "dependencies"), false, false)
	addSection(direct, mapValue(block, "devDependencies"), true, false)
	addSection(direct, mapValue(block, "optionalDependencies"), false, true)
	// The package manager the project pins in package.json's "packageManager"
	// field, which a current pnpm locks in a document of its own. The repository
	// asks for it by name like any other dependency.
	addSection(direct, mapValue(block, "packageManagerDependencies"), false, false)
}

func addSection(direct map[string]*importerRef, section *yaml.Node, dev, optional bool) {
	for _, dep := range fields(section) {
		name := dep.key.Value
		// Every version this parser reads writes {specifier, version} under the
		// dependency name; a bare version is accepted because older files wrote one.
		version := dep.val.Value
		if dep.val.Kind == yaml.MappingNode {
			version = scalar(dep.val, "version")
		}
		if name == "" || version == "" || strings.HasPrefix(version, "link:") {
			continue
		}
		for _, key := range packageKeys(name, version) {
			ref := direct[key]
			if ref == nil {
				ref = &importerRef{}
				direct[key] = ref
			}
			ref.sections++
			if dev {
				ref.dev++
			}
			if optional {
				ref.optional++
			}
		}
	}
}

// packageKeys returns the keys the packages map could hold a dependency under.
// Usually the key is the name and the resolved version joined, "vitest@4.1.9". An
// aliased dependency ("positive: npm:is-positive@1.0.0") and one fetched from a URL
// record the whole key as the version, so that spelling is a candidate too.
func packageKeys(name, version string) []string {
	version = normalizeKey(version)
	keys := []string{name + "@" + version}
	if strings.ContainsAny(version, "@/:") {
		keys = append(keys, version)
	}
	return keys
}

// normalizeKey reduces a packages key, or a key an importer implies, to the one
// spelling both versions of the format agree on: no leading slash, and no peer
// suffix. Version 6 writes both on the key, version 9 writes neither there and
// keeps the suffixed spelling for its snapshots map, and an importer records the
// suffixed version in either.
func normalizeKey(key string) string {
	return cutPeerSuffix(strings.TrimPrefix(key, "/"))
}

// cutPeerSuffix drops the peer dependencies pnpm appends to a resolved version,
// "vue@3.4.0(typescript@5.4.2)" and the nested "vitest@4.1.9(vite@8.1.3(jiti@2.7.0))".
func cutPeerSuffix(s string) string {
	if i := strings.IndexByte(s, '('); i >= 0 {
		return s[:i]
	}
	return s
}

// splitKey reads the package name and version out of a packages key. The version
// is whatever follows the last "@", so a scoped name keeps its own leading "@", and
// a key that states a URL or a directory instead of a version yields that text for
// the entry to state as written.
func splitKey(key string) (name, version string) {
	k := normalizeKey(key)
	at := strings.LastIndex(k, "@")
	if at <= 0 {
		return "", ""
	}
	return k[:at], k[at+1:]
}

// field is one key and value pair of a yaml mapping.
type field struct {
	key *yaml.Node
	val *yaml.Node
}

// fields returns the pairs of a mapping in file order. Anything that is not a
// mapping has none, which lets a caller walk a node it did not check. Values are
// dereferenced, so an alias reads as what it points at.
func fields(n *yaml.Node) []field {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]field, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, field{key: n.Content[i], val: deref(n.Content[i+1])})
	}
	return out
}

// maxAliasDepth bounds how far deref follows a chain of aliases, so that a file
// whose anchor points at itself costs a dropped entry rather than the process.
const maxAliasDepth = 100

// deref follows yaml aliases to the node they name. yaml.v3 leaves them unresolved
// when a document is decoded into a yaml.Node, so a resolution written as "*tar"
// would otherwise read as an empty mapping and the entry would be called a registry
// install with no hash and no location, hiding what the alias says. A chain that
// does not end is no node at all, which reads as a missing field.
func deref(n *yaml.Node) *yaml.Node {
	for range maxAliasDepth {
		if n == nil || n.Kind != yaml.AliasNode {
			return n
		}
		n = n.Alias
	}
	return nil
}

// mapValue returns the value of one key of a mapping, or nil.
func mapValue(n *yaml.Node, key string) *yaml.Node {
	for _, f := range fields(n) {
		if f.key.Value == key {
			return f.val
		}
	}
	return nil
}

// scalar returns the text of a scalar field, or "" when the field is absent, null
// or not a scalar. The text is what the file wrote, so a quoted "9.0" and a bare
// 9.0 read the same.
func scalar(n *yaml.Node, key string) string {
	v := deref(mapValue(n, key))
	if v == nil || v.Kind != yaml.ScalarNode || v.Tag == "!!null" {
		return ""
	}
	return v.Value
}

// boolean reports whether a field is written true.
func boolean(n *yaml.Node, key string) bool {
	b, err := strconv.ParseBool(scalar(n, key))
	return err == nil && b
}

// documentRoot unwraps the document node yaml.Unmarshal fills in. An empty file
// leaves the node as it was and so has no root.
func documentRoot(n *yaml.Node) *yaml.Node {
	if n.Kind != yaml.DocumentNode || len(n.Content) == 0 {
		return nil
	}
	return n.Content[0]
}
