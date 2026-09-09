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
//     Direct. A dependency declared by a workspace member is not counted, and
//     neither is a peer dependency of the project, because npm installs those
//     through the package that asks for them.
//   - An entry with "link": true is a symbolic link into the workspace rather
//     than an install, and an entry with no version has nothing to evaluate.
//     Both are dropped with a reason, so a partial parse stays visible.
//   - The name is the part of the key after the last "node_modules/", which
//     gives the right name for a nested entry and keeps a scoped name's slash and
//     its case. npm names are case sensitive (JSONStream and jsonstream are two
//     packages), so the name is recorded as written. A workspace member's key
//     holds no "node_modules/", and there the entry's own "name" field, which npm
//     writes when the directory differs from the package name, is used instead.
//   - A workspace member stays in the entries, with SourcePath, because the link
//     entry that points at it was dropped and it would otherwise disappear from a
//     monorepo's lockfile entirely.
//   - An entry marked "extraneous", installed but reached from nothing in the
//     tree, is kept like any other install: it is code the project unpacked, and
//     the flag changes none of the fields the checks read.
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

// registryHosts are the hosts whose tarball URLs mean "installed from a
// registry" even though their layout is not the usual one. Every other npm
// registry and mirror serves tarballs as <name>/-/<file>.tgz, which
// registryTarball recognizes without a list to maintain. Verified 2026-09-09.
var registryHosts = map[string]bool{
	// The public registry npm installs from by default.
	"registry.npmjs.org": true,
	// GitHub Packages, whose tarball path is /download/<name>/<version>/<sha>.
	"npm.pkg.github.com": true,
}

func init() { lockfile.Register(parser{}) }

// parser reads package-lock.json.
type parser struct{}

// Name returns the format's name.
func (parser) Name() string { return formatName }

// Detect reports whether the file is a package-lock.json.
func (parser) Detect(base string) bool { return strings.EqualFold(base, formatName) }

// jsonPackage is the part of one "packages" entry the checks need.
type jsonPackage struct {
	// Name is written when the key is a path whose last segment is not the
	// package name, which is how a workspace member carries its scoped name.
	Name        string `json:"name"`
	Version     string `json:"version"`
	Resolved    string `json:"resolved"`
	Integrity   string `json:"integrity"`
	Dev         bool   `json:"dev"`
	Optional    bool   `json:"optional"`
	DevOptional bool   `json:"devOptional"`
	Link        bool   `json:"link"`
}

// jsonRoot is the "" entry, the project itself. Only the names in its dependency
// maps matter, so the values stay raw and are never decoded.
type jsonRoot struct {
	Dependencies         map[string]json.RawMessage `json:"dependencies"`
	DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
	OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
}

// locked is one entry as read, with the line its key sits on. The entries are
// collected first and turned into lockfile entries afterwards, because the
// project entry that decides Direct may come after them in the file.
type locked struct {
	key  string
	line int
	pkg  jsonPackage
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
		version     int
		root        jsonRoot
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
			if locks, root, err = decodePackages(dec, lines, lf); err != nil {
				return nil, err
			}
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

	direct := directNames(root)
	for i := range locks {
		addEntry(lf, &locks[i], direct)
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
		var pkg jsonPackage
		if err := dec.Decode(&pkg); err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				lf.Drop("%s: entry is %s, not an object", key, typeErr.Value)
				continue
			}
			return nil, root, fmt.Errorf("%s: %w", key, err)
		}
		locks = append(locks, locked{key: key, line: line, pkg: pkg})
	}
	if err := closeObject(dec, `"packages"`); err != nil {
		return nil, root, err
	}
	return locks, root, nil
}

// addEntry turns one read entry into a lockfile entry, or drops it with a reason.
func addEntry(lf *lockfile.Lockfile, l *locked, direct map[string]bool) {
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
	name := packageName(l.key, l.pkg.Name)
	if name == "" {
		lf.Drop("%s: no package name in the path and none declared", l.key)
		return
	}
	// devOptional means the package is reached both as a development dependency
	// and as an optional one, so it is both.
	lf.Add(lockfile.Entry{
		Ref: model.PackageRef{
			Ecosystem: model.NPM,
			Name:      model.NormalizeName(model.NPM, name),
			Version:   l.pkg.Version,
		},
		Source:    sourceOf(l.key, l.pkg.Resolved),
		Resolved:  l.pkg.Resolved,
		Integrity: l.pkg.Integrity,
		Direct:    topLevel(l.key) && direct[name],
		Dev:       l.pkg.Dev || l.pkg.DevOptional,
		Optional:  l.pkg.Optional || l.pkg.DevOptional,
		Line:      l.line,
	})
}

// packageName is the part of the install path after the last "node_modules/".
// A key that holds none is a workspace member, where npm writes the name in the
// entry and the directory is the fallback.
func packageName(key, declared string) string {
	if i := strings.LastIndex(key, nodeModules); i >= 0 {
		return key[i+len(nodeModules):]
	}
	if declared != "" {
		return declared
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

// directNames collects the names the project itself asks for.
func directNames(root jsonRoot) map[string]bool {
	names := make(map[string]bool, len(root.Dependencies)+len(root.DevDependencies)+len(root.OptionalDependencies))
	for _, m := range []map[string]json.RawMessage{root.Dependencies, root.DevDependencies, root.OptionalDependencies} {
		for name := range m {
			names[name] = true
		}
	}
	return names
}

// sourceOf reads where the entry came from. An entry with no "resolved" is a
// bundled dependency, which the file does not say where to get, unless its key
// is a path outside node_modules, which is a workspace member living at that
// path in the repository.
func sourceOf(key, resolved string) lockfile.Source {
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
		if registryURL(u) {
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

// registryURL reports whether the tarball comes from a package registry rather
// than from somewhere on the web. Registries other than the public one are
// recognized by the tarball layout they all serve, so that a project installing
// through a mirror or a private registry is not reported as exotic.
func registryURL(u *url.URL) bool {
	if registryHosts[strings.ToLower(u.Hostname())] {
		return true
	}
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
