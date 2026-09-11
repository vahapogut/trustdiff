// Package npm reads npm's package-lock.json, lockfileVersion 2 and 3, and
// registers itself with the lockfile parser registry.
//
// The "packages" map is the whole of the format we read. Its keys are install
// paths: "" for the project itself, "node_modules/foo" for a top level install,
// "node_modules/a/node_modules/b" for a nested one and "packages/ui" for a
// workspace member. lockfileVersion 2 also carries the lockfileVersion 1
// "dependencies" tree for npm 6 to read; npm treats "packages" as authoritative
// when both are present, so this parser walks past the legacy tree without
// looking at it. A lockfileVersion 1 file has no "packages" at all and is an
// error: npm 7 and later write 2 or 3, and an install with a current npm
// upgrades the file.
//
// What the entries become:
//
//   - The "" entry is the project, not a package. Its "dependencies",
//     "devDependencies" and "optionalDependencies" name the packages the project
//     asks for itself, which is how a top level "node_modules/<name>" entry earns
//     Direct. A workspace member's entry, whose key holds no "node_modules/",
//     carries the same three maps and is read the same way, because a member's
//     package.json is a file of the repository like the root's and the other three
//     parsers count a member's dependencies as direct. A peer dependency of the
//     project is not counted, because npm installs those through the package that
//     asks for them.
//   - An entry with "link": true is a symbolic link into the workspace rather
//     than an install, and an entry with no version has nothing to evaluate.
//     Both are dropped with a reason, so a partial parse stays visible.
//   - The name is the entry's own "name" field when it has one, and otherwise the
//     part of the key after the last "node_modules/", which gives the right name
//     for a nested entry and keeps a scoped name's slash and its case. npm names
//     are case sensitive (JSONStream and jsonstream are two packages), so the name
//     is recorded as written. npm writes "name" for exactly the two cases where
//     the key is not the name: a workspace member installed in a directory of its
//     own, and an alias ("d3v3": "npm:d3@^3"), where the key is the alias and the
//     name is the package that is really installed. The ref carries the installed
//     name, because that is what a registry, an advisory database or a typosquat
//     neighbor is looked up under; Direct is still decided by the alias, which is
//     how the dependency maps spell it.
//   - A workspace member stays in the entries, with SourcePath, because the link
//     entry that points at it was dropped and it would otherwise disappear from a
//     monorepo's lockfile entirely.
//   - An entry marked "extraneous", installed but reached from nothing in the
//     tree, is kept like any other install: it is code the project unpacked, and
//     the flag changes none of the fields the checks read.
//
// A "packages" key written twice is a file npm did not write, and the two objects
// are merged rather than one overwriting the other, which is what the deno and yarn
// parsers do with their own duplicates. Parse says why at the key it merges.
//
// Line numbers come from encoding/json: the decoder reports the byte offset it
// has reached, and lockfile.LineIndex turns that into the line the package key
// sits on, which is where a SARIF finding points.
//
// Format verified against npm's documentation and the recorded fixtures on
// 2026-09-09: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json
package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// formatName is the parser's name and the file name it reads.
const formatName = "package-lock.json"

// nodeModules is the path segment that separates the install path from the name.
const nodeModules = "node_modules/"

func init() { lockfile.Register(parser{}) }

// parser reads package-lock.json.
type parser struct{}

// Name returns the format's name.
func (parser) Name() string { return formatName }

// Detect reports whether the file is a package-lock.json.
func (parser) Detect(base string) bool { return strings.EqualFold(base, formatName) }

// jsonPackage is the part of one "packages" entry the checks need.
type jsonPackage struct {
	// Name is written when the key is not the package name: a workspace member
	// installed in a directory of its own, and an alias, where the key is the
	// alias and this is the package that is really installed.
	Name        string `json:"name"`
	Version     string `json:"version"`
	Resolved    string `json:"resolved"`
	Integrity   string `json:"integrity"`
	Dev         bool   `json:"dev"`
	Optional    bool   `json:"optional"`
	DevOptional bool   `json:"devOptional"`
	Link        bool   `json:"link"`
	// InBundle marks a dependency whose bytes ship inside its parent's tarball,
	// which is why it has neither a "resolved" nor an "integrity" of its own.
	InBundle bool `json:"inBundle"`
}

// jsonRoot is what a manifest asks for: the "" entry, the project itself, and a
// workspace member's entry, which npm writes the same three maps on. Only the
// names matter, so the values stay raw and are never decoded.
type jsonRoot struct {
	Dependencies         map[string]json.RawMessage `json:"dependencies"`
	DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
	OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
}

// jsonMember is a workspace member's entry: an install like any other, plus the
// dependency maps it declares. Only the entries whose key holds no "node_modules/"
// are decoded into this, because the dependency map of an installed package is
// large, is not read, and would cost as much memory again on a big lockfile.
type jsonMember struct {
	jsonPackage
	jsonRoot
}

// locked is one entry as read, with the line its key sits on. The entries are
// collected first and turned into lockfile entries afterwards, because the
// project entry that decides Direct may come after them in the file.
type locked struct {
	key  string
	line int
	pkg  jsonPackage
	// asks is what a workspace member declares, empty for an installed package.
	asks jsonRoot
}

// Parse reads the lockfile. path names the file in messages only.
func (parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", formatName, err)
	}
	lines := lockfile.NewLineIndex(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	lf := &lockfile.Lockfile{Path: path, Format: formatName, Ecosystem: model.NPM}

	if err := openObject(dec, "lockfile"); err != nil {
		return nil, err
	}
	var (
		version int
		// roots is one project entry per "packages" object, which is one entry in
		// every file npm writes.
		roots       []jsonRoot
		locks       []locked
		hasPackages bool
	)
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "lockfileVersion":
			if err := dec.Decode(&version); err != nil {
				return nil, fmt.Errorf("lockfileVersion: %w", err)
			}
		case "packages":
			hasPackages = true
			// A repeated key is merged rather than allowed to overwrite what the
			// first one held. npm writes "packages" once, so a file with two of them
			// was not written by npm, and JSON leaves which one wins to the reader:
			// JavaScript's own parser, which npm uses, keeps the last, a Go decoder
			// that read into a map would too, and neither is a safe reading for a
			// tool that has to say what a file could install. An object's worth of
			// installs that vanished with no entry and no reason would be the one
			// failure nobody sees; the union is a superset of whatever npm picks, so
			// no pinned version escapes the checks. The deno and yarn parsers keep
			// duplicates for the same reason.
			more, root, err := decodePackages(dec, lines, lf)
			if err != nil {
				return nil, err
			}
			locks = append(locks, more...)
			roots = append(roots, root)
		default:
			// Everything else, the lockfileVersion 1 "dependencies" tree included.
			if err := skipValue(dec); err != nil {
				return nil, fmt.Errorf("%q: %w", key, err)
			}
		}
	}
	if err := closeObject(dec, "lockfile"); err != nil {
		return nil, err
	}
	if version > 0 {
		lf.Version = strconv.Itoa(version)
	}
	if !hasPackages {
		return nil, noPackagesError(version)
	}

	direct := directNames(roots, locks)
	hosts := countRegistryHosts(locks)
	for i := range locks {
		addEntry(lf, &locks[i], direct, hosts)
	}
	return lf, nil
}

// noPackagesError explains a file this parser cannot read, which is in practice
// always a lockfileVersion 1 file written by npm 5 or npm 6.
func noPackagesError(version int) error {
	if version > 0 {
		return fmt.Errorf("lockfileVersion %d has no \"packages\" object: npm 7 and later write lockfileVersion 2 or 3, so running an install with npm 7 or later upgrades this file", version)
	}
	return errors.New("no lockfileVersion and no \"packages\" object: this is not a package-lock.json that npm 7 or later wrote")
}

// decodePackages reads the "packages" map, in file order, and returns the entries
// together with the project entry. An entry whose value is not an object is
// dropped rather than failing the file.
func decodePackages(dec *json.Decoder, lines *lockfile.LineIndex, lf *lockfile.Lockfile) ([]locked, jsonRoot, error) {
	var root jsonRoot
	if err := openObject(dec, `"packages"`); err != nil {
		return nil, root, err
	}
	var locks []locked
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, root, err
		}
		// The offset now sits just past the key's closing quote, on the key's own line.
		line := lines.Line(dec.InputOffset())
		if key == "" {
			if err := dec.Decode(&root); err != nil {
				return nil, root, fmt.Errorf("the project entry: %w", err)
			}
			continue
		}
		entry := locked{key: key, line: line}
		if strings.Contains(key, nodeModules) {
			err = dec.Decode(&entry.pkg)
		} else {
			// A workspace member: its dependency maps are read as well, because
			// what a member asks for the project asks for.
			var member jsonMember
			if err = dec.Decode(&member); err == nil {
				entry.pkg, entry.asks = member.jsonPackage, member.jsonRoot
			}
		}
		if err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				lf.Drop("%s: entry is %s, not an object", key, typeErr.Value)
				continue
			}
			return nil, root, fmt.Errorf("%s: %w", key, err)
		}
		locks = append(locks, entry)
	}
	if err := closeObject(dec, `"packages"`); err != nil {
		return nil, root, err
	}
	return locks, root, nil
}

// addEntry turns one read entry into a lockfile entry, or drops it with a reason.
func addEntry(lf *lockfile.Lockfile, l *locked, direct map[string]bool, hosts *lockfile.RegistryHosts) {
	switch {
	case l.pkg.Link:
		target := l.pkg.Resolved
		if target == "" {
			target = "the workspace"
		}
		lf.Drop("%s: a link to %s, not an install", l.key, target)
		return
	case l.pkg.Version == "":
		lf.Drop("%s: no version, nothing to evaluate", l.key)
		return
	}
	// The key names the dependency as the manifests spell it, which for an alias
	// is the alias; the entry's "name" names the package that is really installed.
	// Every lookup wants the installed name, and Direct wants the spelling the
	// dependency maps use.
	asked := installPath(l.key)
	installed := asked
	if l.pkg.Name != "" {
		installed = l.pkg.Name
	}
	if installed == "" {
		lf.Drop("%s: no package name in the path and none declared", l.key)
		return
	}
	// devOptional does not mean dev. npm sets it on a package reached both through
	// the dev tree and through an optional edge of a dependency that is not dev,
	// which is why omitting dev alone leaves it installed: arborist removes such a
	// node only when dev and optional are both pruned. npm's package-lock.json
	// documentation says an optional dependency of a dev dependency gets dev and
	// optional instead, so the three never overlap. Dev here means only needed to
	// develop or test the project, which is false for such a package, and Optional
	// is true because an install may still leave it out.
	lf.Add(lockfile.Entry{
		Ref: model.PackageRef{
			Ecosystem: model.NPM,
			Name:      model.NormalizeName(model.NPM, installed),
			Version:   l.pkg.Version,
		},
		Source:    sourceOf(l.key, l.pkg.Resolved, hosts),
		Resolved:  l.pkg.Resolved,
		Integrity: l.pkg.Integrity,
		Direct:    topLevel(l.key) && direct[asked],
		Dev:       l.pkg.Dev,
		Optional:  l.pkg.Optional || l.pkg.DevOptional,
		Bundled:   l.pkg.InBundle,
		Line:      l.line,
	})
}

// installPath is the part of the install path after the last "node_modules/",
// which is the name the manifest that asked for the entry wrote: the package name,
// or the alias for an aliased dependency. A key that holds no "node_modules/" is a
// workspace member, whose directory is the fallback.
func installPath(key string) string {
	if i := strings.LastIndex(key, nodeModules); i >= 0 {
		return key[i+len(nodeModules):]
	}
	if i := strings.LastIndex(key, "/"); i >= 0 {
		return key[i+1:]
	}
	return key
}

// topLevel reports whether the key is an install in the project's own
// node_modules, the only place a direct dependency of the project can sit.
func topLevel(key string) bool {
	return strings.HasPrefix(key, nodeModules) && strings.Count(key, nodeModules) == 1
}

// directNames collects the names the project asks for: the project entry of every
// "packages" object, of which a file npm wrote has one, and the dependency maps of
// every workspace member, keyed the way the manifests spell them, which for an
// aliased dependency is the alias.
func directNames(roots []jsonRoot, locks []locked) map[string]bool {
	names := make(map[string]bool)
	add := func(r jsonRoot) {
		for _, m := range []map[string]json.RawMessage{r.Dependencies, r.DevDependencies, r.OptionalDependencies} {
			for name := range m {
				names[name] = true
			}
		}
	}
	for _, root := range roots {
		add(root)
	}
	for i := range locks {
		add(locks[i].asks)
	}
	return names
}

// countRegistryHosts weighs the hosts the file downloads from, so that the host a
// project installs through can be told from a host one entry points at alone. Only
// the URLs that have the registry layout are counted: any other URL is reported as
// a URL whatever its host serves.
func countRegistryHosts(locks []locked) *lockfile.RegistryHosts {
	hosts := lockfile.NPMRegistryHosts()
	for i := range locks {
		u, err := url.Parse(locks[i].pkg.Resolved)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !registryLayout(u) {
			continue
		}
		hosts.Count(u.Hostname())
	}
	return hosts
}

// sourceOf reads where the entry came from. An entry with no "resolved" is a
// bundled dependency, which the file does not say where to get, unless its key
// is a path outside node_modules, which is a workspace member living at that
// path in the repository.
func sourceOf(key, resolved string, hosts *lockfile.RegistryHosts) lockfile.Source {
	switch {
	case resolved == "":
		if strings.Contains(key, nodeModules) {
			return lockfile.SourceUnknown
		}
		return lockfile.SourcePath
	case gitURL(resolved):
		return lockfile.SourceGit
	case strings.HasPrefix(resolved, "file:"):
		return lockfile.SourcePath
	}
	u, err := url.Parse(resolved)
	if err != nil {
		return lockfile.SourceUnknown
	}
	switch u.Scheme {
	case "http", "https":
		if registryURL(u, hosts) {
			return lockfile.SourceRegistry
		}
		return lockfile.SourceURL
	case "":
		// A relative path, which is how npm records a workspace or a local install.
		return lockfile.SourcePath
	default:
		return lockfile.SourceUnknown
	}
}

// gitURL reports whether the location names a git repository. npm writes the
// hosted forms (git+https, git+ssh, git:) and a bare remote ending in ".git",
// each with the resolved commit in the fragment.
func gitURL(resolved string) bool {
	for _, prefix := range []string{"git+", "git:", "git@", "ssh://"} {
		if strings.HasPrefix(resolved, prefix) {
			return true
		}
	}
	path := resolved
	if i := strings.IndexAny(path, "#?"); i >= 0 {
		path = path[:i]
	}
	return strings.HasSuffix(path, ".git")
}

// registryURL reports whether the tarball comes from the registry this project
// installs from rather than from somewhere on the web. The layout alone does not
// answer it: anybody can serve <name>/-/<name>-<version>.tgz, and a pull request
// that repoints one entry at such a host would otherwise read as a registry
// install and pass every check silently. So a host counts as the registry when it
// is a known one or when the rest of the file agrees with it, which is what
// lockfile.RegistryHosts decides. A project installing through a mirror or a
// private registry keeps every entry, and a lone outlier is reported as a URL.
func registryURL(u *url.URL, hosts *lockfile.RegistryHosts) bool {
	host := u.Hostname()
	return hosts.Known(host) || (registryLayout(u) && hosts.Serves(host))
}

// registryLayout reports whether the path is the tarball layout every npm registry
// and mirror serves, "<name>/-/<name>-<version>.tgz".
func registryLayout(u *url.URL) bool {
	return strings.Contains(u.Path, "/-/") && strings.HasSuffix(u.Path, ".tgz")
}

// openObject reads the "{" that starts an object.
func openObject(dec *json.Decoder, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("%s: want an object, found %v", what, tok)
	}
	return nil
}

// closeObject reads the "}" that ends an object.
func closeObject(dec *json.Decoder, what string) error {
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// objectKey reads the next key of an object.
func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("object key: %w", err)
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("object key: want a string, found %v", tok)
	}
	return key, nil
}

// skipValue reads and discards the next value, however deeply nested, without
// building it in memory. It is how the parser walks past lockfileVersion 2's
// legacy "dependencies" tree.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
