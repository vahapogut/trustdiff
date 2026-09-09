// Package yarn reads the yarn.lock that Yarn 2 and later write, which the project
// calls Yarn Berry, and registers itself with the lockfile parser registry.
//
// The file is yaml: a mapping one of whose keys is "__metadata", which states the
// format version, and whose every other key is one resolved package. The key is
// the list of descriptors that resolve to it, separated by ", ", and each
// descriptor is a package name and the range that asked for it, joined by "@":
//
//	"@ampproject/remapping@npm:^2.2.0, @ampproject/remapping@npm:^2.3.0":
//	  version: 2.3.0
//	  resolution: "@ampproject/remapping@npm:2.3.0"
//	  checksum: 10c0/de8c59d1...
//	  languageName: node
//	  linkType: hard
//
// What each field becomes:
//
//   - The name is read from "resolution" and not from the key, because for an
//     aliased dependency the key is the alias and the resolution names the package
//     that is really installed: "string-width-cjs@npm:string-width@^4.2.0" resolves
//     to "string-width@npm:4.2.2". Every lookup a check makes, a registry, an
//     advisory database, a typosquat neighbor, wants the installed name. The key's
//     first descriptor is the fallback for an entry that states no resolution.
//   - The version is the "version" field. An entry without one has nothing to
//     evaluate and is dropped with a reason.
//   - The integrity is the "checksum" field, which a current Yarn writes as
//     "<cacheKey>/<hex>" and an older one as the bare hex. It is recorded as
//     written, because what the checks compare is what the file says.
//   - The source is the protocol of the resolution's range. "npm:" is the
//     registry; "workspace:", "link:", "portal:" and "file:" are a directory in the
//     repository; "git:", "git+ssh:", "ssh:", "github:", "gitlab:" and "bitbucket:"
//     are a repository, as is an http URL whose path ends in ".git" or that carries
//     Yarn's "commit=" parameter; "http:" and "https:" otherwise are a download.
//     Anything else, "exec:" and the protocols a Yarn plugin adds among them, is
//     unknown rather than guessed at.
//   - A "patch:" entry is the package it patches with a patch file applied, so its
//     source is read from the locator inside the patch and it is marked bundled:
//     nothing of its own is fetched for it, and where it carries no checksum that
//     is not a hash the file is missing but a hash it never had. It stays in the
//     entries because a builtin patch can be the only entry a package has, which is
//     what Yarn writes for fsevents.
//
// Direct is true for a package a workspace asks for. Yarn does not record the root
// project's dependencies anywhere else: the root is itself a workspace, written
// with the resolution "<name>@workspace:.", and its entry carries the dependency
// map. So the descriptors every workspace entry declares are collected first and an
// entry is direct when one of the descriptors on its key is among them. The root's
// own entry is the project rather than a package and is not recorded; a member's
// entry is, with SourcePath, the way the other parsers here keep a workspace member.
//
// Two things the format does not hold, which the entries therefore do not carry:
//
//   - Dev is false for every file a Yarn released so far has written. Yarn writes a
//     workspace's dependencies and its devDependencies into one "dependencies" map,
//     checked against slate-react's package.json on 2026-09-09 and against three
//     real lockfiles that hold not one "devDependencies" key between them, so
//     nothing in the file says which of them is only needed to develop. A
//     "devDependencies" map is read all the same, for the day a Yarn writes one.
//   - There is no registry URL to weigh, so lockfile.RegistryHosts has no work to
//     do here. Yarn records the registry it installs from in .yarnrc.yml and never
//     in the lockfile, so a registry entry states a version and nothing else, and an
//     http resolution is a dependency on that URL written in a manifest rather than
//     a registry download that could be repointed.
//
// Optional comes from the "dependenciesMeta" map of the workspace that asks for the
// package, which is where Yarn keeps the optionalDependencies it folded into the
// dependency map. A package is optional only when every workspace that names it
// marks it so, because an install may leave out only what nothing requires.
//
// Line numbers come from the yaml node of each key, which is what the node API
// reports, so a finding points at the line the entry starts on.
//
// Format versions: the entry shapes above are recognized per entry and not per
// version, so the "__metadata" version is reported and never rejected. Verified
// against the recorded fixtures on 2026-09-09: version 8, which Yarn 4 writes, and
// version 6, which Yarn 3 writes and which differs only in leaving the "npm:"
// protocol off the ranges it records. A yarn.lock from Yarn 1 is not this format at
// all, states no "__metadata", and is an error that says so.
package yarn

import (
	"bytes"
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
const formatName = "yarn.lock"

// metadataKey is the block that states the format version. It is the one top level
// key that is not a package.
const metadataKey = "__metadata"

// rootWorkspace is the resolution range of the workspace that is the repository
// itself. Yarn writes every workspace with the path it sits at, and the root sits
// at ".".
const rootWorkspace = "workspace:."

func init() { lockfile.Register(parser{}) }

// parser reads yarn.lock. It registers itself, so importing this package for its
// side effect is all a caller needs.
type parser struct{}

// Name returns the format's name, which is also the file name it reads.
func (parser) Name() string { return formatName }

// Detect reports whether the file is a yarn.lock. The caller has already lowered
// the base name, so a plain comparison answers it.
func (parser) Detect(base string) bool { return base == formatName }

// locked is one entry as read, with the line its key sits on. The entries are
// collected first and turned into lockfile entries afterwards, because a workspace
// entry that decides Direct may come after the entries it asks for.
type locked struct {
	// descriptors are the name and range pairs the key lists, as written. An entry
	// is direct when a workspace asked for one of them.
	descriptors []string
	// name and version are what the entry resolves to.
	name    string
	version string
	// rang is the range of the resolution, which is everything after the name: the
	// protocol and the location or version that follows it.
	rang string
	// checksum is the integrity as written, empty when the entry carries none.
	checksum string
	// asks is what a workspace entry declares, nil for an installed package.
	asks []request
	line int
}

// request is one dependency a workspace declares: the descriptor it spells, and
// which map it sits in.
type request struct {
	descriptor string
	dev        bool
	optional   bool
}

// Parse reads the lockfile. path names the file in messages and in Lockfile.Path
// only.
func (parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", formatName, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, unreadable(data, err)
	}
	root := documentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, unreadable(data, nil)
	}
	meta := mapValue(root, metadataKey)
	if meta == nil {
		return nil, unreadable(data, nil)
	}

	lf := &lockfile.Lockfile{Path: path, Format: formatName, Ecosystem: model.NPM, Version: scalar(meta, "version")}
	var locks []locked
	for _, f := range fields(root) {
		if f.key.Value == metadataKey {
			continue
		}
		if l, ok := read(lf, f); ok {
			locks = append(locks, l)
		}
	}
	direct := requested(locks)
	for i := range locks {
		add(lf, &locks[i], direct)
	}
	return lf, nil
}

// unreadable explains a file this parser cannot read. A yarn.lock from Yarn 1 is a
// format of its own that only looks like yaml, so it is named as what it is rather
// than reported as a yaml error nobody can act on. err is the yaml error when there
// was one, and nil when the file parsed but holds none of what this format holds.
func unreadable(data []byte, err error) error {
	if !bytes.Contains(data, []byte(metadataKey)) {
		return fmt.Errorf("%s states no %s block: this is the yarn.lock Yarn 1 wrote, and running an install with Yarn 2 or later rewrites it in the format read here", formatName, metadataKey)
	}
	if err != nil {
		return fmt.Errorf("%s is not valid yaml: %w", formatName, err)
	}
	return fmt.Errorf("%s: want a mapping of %s and one entry per resolved descriptor at the top level", formatName, metadataKey)
}

// read reads one top level entry, or drops it with a reason and reports false.
func read(lf *lockfile.Lockfile, f field) (locked, bool) {
	key := f.key.Value
	if f.val.Kind != yaml.MappingNode {
		lf.Drop("%q on line %d has no metadata", key, f.key.Line)
		return locked{}, false
	}
	l := locked{
		descriptors: descriptors(key),
		version:     scalar(f.val, "version"),
		checksum:    scalar(f.val, "checksum"),
		line:        f.key.Line,
	}
	// The resolution names the package that is really installed, which for an
	// aliased dependency is not what the key says. An entry that states none is
	// read through its first descriptor, which is the best the file offers.
	l.name, l.rang = splitDescriptor(scalar(f.val, "resolution"))
	if l.name == "" && len(l.descriptors) > 0 {
		l.name, l.rang = splitDescriptor(l.descriptors[0])
	}
	switch {
	case l.name == "":
		lf.Drop("%q on line %d names no package", key, f.key.Line)
		return locked{}, false
	case l.version == "":
		lf.Drop("%q on line %d has no version, nothing to evaluate", key, f.key.Line)
		return locked{}, false
	}
	if strings.HasPrefix(l.rang, "workspace:") {
		l.asks = declared(f.val)
	}
	return l, true
}

// add turns one read entry into a lockfile entry.
func add(lf *lockfile.Lockfile, l *locked, direct map[string]*asked) {
	if l.rang == rootWorkspace {
		// The repository itself, which is a project and not a package it installs.
		// Its dependency map was read above, which is the whole of what it is for.
		return
	}
	source := sourceOf(l.rang, 0)
	entry := lockfile.Entry{
		Ref: model.PackageRef{
			Ecosystem: model.NPM,
			Name:      model.NormalizeName(model.NPM, l.name),
			Version:   l.version,
		},
		Source:    source,
		Resolved:  resolvedOf(l.rang),
		Integrity: l.checksum,
		// A patched package is built from the entry it patches rather than fetched,
		// so the artifact and the hash that guards it belong to that entry, which is
		// what Bundled says about an entry npm unpacks out of its parent's tarball.
		Bundled: strings.HasPrefix(l.rang, "patch:"),
		Line:    l.line,
	}
	for _, d := range l.descriptors {
		ref := lookup(direct, d)
		if ref == nil {
			continue
		}
		entry.Direct = true
		// A package a workspace requires at runtime is not optional however another
		// workspace lists it, and the same reading decides Dev for the day Yarn
		// writes a devDependencies map of its own.
		entry.Dev = entry.Dev || ref.sections == ref.dev
		entry.Optional = entry.Optional || ref.sections == ref.optional
		break
	}
	lf.Add(entry)
}

// asked is how the workspaces name one descriptor: how many maps name it at all,
// and how many of those were devDependencies or marked it optional.
type asked struct {
	sections int
	dev      int
	optional int
}

// requested indexes every descriptor a workspace asks for. Both spellings of a
// descriptor are indexed, because a version 6 file writes a range without its
// "npm:" protocol where a version 8 file writes it with one, and a workspace's map
// and a package's key need not agree on which.
func requested(locks []locked) map[string]*asked {
	direct := make(map[string]*asked)
	for i := range locks {
		for _, req := range locks[i].asks {
			for _, spelling := range spellings(req.descriptor) {
				ref := direct[spelling]
				if ref == nil {
					ref = &asked{}
					direct[spelling] = ref
				}
				ref.sections++
				if req.dev {
					ref.dev++
				}
				if req.optional {
					ref.optional++
				}
			}
		}
	}
	return direct
}

// lookup finds what the workspaces said about a descriptor, under either spelling
// of it. A version 6 file mixes the two within one key, "resolve@^1.10.1,
// resolve@npm:^1.10.1", so neither side can be normalized alone.
func lookup(direct map[string]*asked, descriptor string) *asked {
	for _, spelling := range spellings(descriptor) {
		if ref := direct[spelling]; ref != nil {
			return ref
		}
	}
	return nil
}

// spellings returns the ways the file may write one descriptor: as it stands, and
// with the "npm:" protocol dropped from its range, which is how Yarn 3 wrote a
// range that Yarn 4 writes with one.
func spellings(descriptor string) []string {
	name, rang := splitDescriptor(descriptor)
	if bare, ok := strings.CutPrefix(rang, "npm:"); ok && name != "" {
		return []string{descriptor, name + "@" + bare}
	}
	return []string{descriptor}
}

// declared reads the dependency maps of a workspace entry. Yarn folds a
// workspace's devDependencies into "dependencies", so "devDependencies" is read
// for a future Yarn that writes one rather than because a current one does, and
// the optionalDependencies it folded in the same way are recovered from
// "dependenciesMeta". Peer dependencies are not read: the package that asks for
// one is what installs it, so it is not a dependency of the project.
func declared(node *yaml.Node) []request {
	optional := optionalNames(mapValue(node, "dependenciesMeta"))
	var out []request
	for _, section := range []struct {
		key string
		dev bool
	}{{key: "dependencies"}, {key: "devDependencies", dev: true}, {key: "optionalDependencies"}} {
		for _, dep := range fields(mapValue(node, section.key)) {
			name, rang := dep.key.Value, dep.val.Value
			if name == "" || rang == "" {
				continue
			}
			out = append(out, request{
				descriptor: name + "@" + rang,
				dev:        section.dev,
				optional:   section.key == "optionalDependencies" || optional[name],
			})
		}
	}
	return out
}

// optionalNames reads the names a workspace's dependenciesMeta marks optional.
func optionalNames(meta *yaml.Node) map[string]bool {
	names := make(map[string]bool)
	for _, f := range fields(meta) {
		if boolean(f.val, "optional") {
			names[f.key.Value] = true
		}
	}
	return names
}

// descriptors splits an entry's key into the descriptors it lists. Yarn joins them
// with ", ", and no descriptor holds that pair, so the split is exact.
func descriptors(key string) []string {
	if key == "" {
		return nil
	}
	return strings.Split(key, ", ")
}

// splitDescriptor reads a descriptor into the package name and the range that
// follows it. Yarn's own rule is used: an optional "@scope/" prefix, then a name
// that holds neither "/" nor "@", then "@" and everything after it. Splitting at
// the last "@" instead would read the alias
// "string-width-cjs@npm:string-width@^4.2.0" as the package "string-width" at the
// range "^4.2.0", which is a different package from the one the key names.
//
// Text that does not follow the rule names no package and yields an empty name: a
// scope with no name after it is not something Yarn writes, and reporting it as the
// package "@scope" would invent a package the file does not hold.
func splitDescriptor(descriptor string) (name, rang string) {
	from := 0
	if strings.HasPrefix(descriptor, "@") {
		slash := strings.IndexByte(descriptor, '/')
		if slash < 1 {
			return "", ""
		}
		from = slash
	}
	at := strings.IndexByte(descriptor[from:], '@')
	if at < 0 {
		return descriptor, ""
	}
	return descriptor[:from+at], descriptor[from+at+1:]
}

// maxPatchDepth bounds how far sourceOf unwraps a patch of a patch, so that a file
// whose patch names itself costs an unknown source rather than the process.
const maxPatchDepth = 10

// sourceOf reads where a resolution's range says the version came from, by the
// protocol it starts with. A range that starts with none is a bare version, which
// is what a Yarn 3 file writes for a registry install.
func sourceOf(rang string, depth int) lockfile.Source {
	if rang == "" {
		// An entry whose key is a bare name and that states no resolution. It says
		// nothing about where it came from, which is not the same as the registry.
		return lockfile.SourceUnknown
	}
	proto, rest, ok := strings.Cut(rang, ":")
	if !ok {
		return lockfile.SourceRegistry
	}
	switch proto {
	case "npm":
		return lockfile.SourceRegistry
	case "workspace", "link", "portal", "file":
		// A directory of the repository, whichever of the four ways it is reached.
		return lockfile.SourcePath
	case "patch":
		if depth >= maxPatchDepth {
			return lockfile.SourceUnknown
		}
		// A patch is the package it names with a patch file applied, so where the
		// bytes come from is what the locator inside it says.
		return sourceOf(patched(rest), depth+1)
	case "git", "git+ssh", "git+http", "git+https", "git+file", "ssh", "github", "gitlab", "bitbucket":
		return lockfile.SourceGit
	case "http", "https":
		if gitRemote(rang) {
			return lockfile.SourceGit
		}
		return lockfile.SourceURL
	default:
		// "exec:" and whatever protocol a plugin adds. Saying unknown is what
		// Entry.Source is for, and is not the same as calling it a registry install.
		return lockfile.SourceUnknown
	}
}

// patched reads the locator a patch is applied to out of the rest of a "patch:"
// range, which is written up to the first "#" with the locator's own ":" escaped:
// "resolve@npm%3A1.22.1#~builtin<compat/resolve>". The range of that locator is
// what says where the package really comes from.
func patched(rest string) string {
	locator, _, _ := strings.Cut(rest, "#")
	if decoded, err := url.PathUnescape(locator); err == nil {
		locator = decoded
	}
	_, rang := splitDescriptor(locator)
	return rang
}

// gitRemote reports whether an http range names a repository rather than a file to
// download. Yarn writes a git dependency over http as the remote with the commit it
// resolved to in the fragment, "https://github.com/o/r.git#commit=<sha>", and a
// remote that carries no ".git" still carries that parameter.
func gitRemote(rang string) bool {
	u, err := url.Parse(rang)
	if err != nil {
		return false
	}
	return strings.HasSuffix(u.Path, ".git") || strings.Contains(u.Fragment, "commit=")
}

// resolvedOf is the location the entry records, as written. A registry install
// records none: Yarn keeps the registry it installs from in .yarnrc.yml, so the
// range states a version and nothing about where it was fetched. Every other
// protocol states a path, a remote or a URL, and that is the range itself.
func resolvedOf(rang string) string {
	if proto, _, ok := strings.Cut(rang, ":"); !ok || proto == "npm" {
		return ""
	}
	return rang
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
// when a document is decoded into a yaml.Node, so a resolution written as "*evil"
// would otherwise read as no resolution at all and the entry would be reported
// with a source nothing in the file supports. A chain that does not end is no node,
// which reads as a missing field.
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
// or not a scalar. The text is what the file wrote, so a quoted "8" and a bare 8
// read the same.
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
