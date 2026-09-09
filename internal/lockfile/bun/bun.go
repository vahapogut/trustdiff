// Package bun reads bun.lock, the text lockfile Bun writes, and registers itself
// with the lockfile parser registry.
//
// The file is JSON with comments and trailing commas, which is what Bun's own
// writer emits and its reader accepts. Three keys are read: "lockfileVersion",
// "workspaces" and "packages".
//
// "workspaces" is one entry per project in the repository, the repository itself
// being "", each with the name it publishes under and the dependency maps its
// package.json declares. Nothing else in the file says what the repository asks
// for, so this is what decides Direct and Dev.
//
// "packages" is one entry per resolved package, keyed by where it is installed:
// "chalk" at the top level, "boxen/chalk" for a copy nested under boxen, and a
// scoped name keeps its own slash, "@lezer/cpp". The value is an array whose
// shape depends on what the package resolved to, and the resolution in its first
// element is what says which shape it is:
//
//	npm         [ "name@1.2.3", "<registry url or empty>", { info }, "<integrity>" ]
//	tarball     [ "name@https://host/pkg.tgz", { info }, "<integrity>" ]  integrity optional
//	git         [ "name@git+ssh://host/o/r.git#<sha>", { info }, "<bun tag>" ]
//	github      [ "name@github:owner/repo#<sha>", { info }, "<bun tag>" ]
//	symlink     [ "name@link:path", { info } ]
//	folder      [ "name@file:path", { info } ]
//	workspace   [ "name@workspace:path" ]
//	root        [ "name@root:", { bin } ]
//
// Two things about that table are easy to get wrong and are why it is written out
// here. The registry URL is an element of its own that only an npm resolution has,
// so the info object is the third element there and the second everywhere else.
// And the element after the info object is an integrity for an npm or a tarball
// resolution but Bun's own checkout tag for a git one, which is not a hash of the
// package and is not recorded as one.
//
// What the fields become:
//
//   - The name and the version are read out of the resolution, which is a name and
//     what follows the "@" after it. For an npm resolution that is a version; for
//     every other resolution the file records no version anywhere, so the locator
//     is kept as written, which is what the pnpm parser does with the same case: an
//     entry reads "workspace:packages/ui" or "git+ssh://...#<sha>" where a version
//     would be. A workspace member's own "version", when its "workspaces" entry
//     states one, is preferred over the locator.
//   - Source is the protocol of the locator: a bare version is the registry,
//     "link:", "file:", "workspace:" and "root:" are a directory of the repository,
//     "git+", "git:", "ssh:", "github:", "gitlab:" and "bitbucket:" are a
//     repository, and an http URL is a download unless it names a repository.
//   - An npm resolution whose registry element is empty came from the registry the
//     project configures, which the lockfile does not name. A non-empty one is the
//     tarball URL Bun will fetch, and whether that is the project's registry or a
//     host one entry points at on its own is what lockfile.RegistryHosts decides,
//     the same way the npm parser decides it.
//   - Integrity is the hash element where the shape has one, as written.
//   - Bundled is the info object's "bundled" flag, which marks a package that
//     ships inside its parent's tarball.
//   - The "root:" entry, which Bun writes for the repository itself when it
//     installs in isolated mode, is a project and not a package it installs, so it
//     is not recorded. That is the same reading the npm parser gives the "" entry
//     of package-lock.json.
//
// Direct is true for a top level entry, one whose install path is the package name
// alone, that a workspace declares. Dev and Optional come from which map of which
// workspace declares it: a package is a development dependency when every workspace
// that names it calls it one, because a package any project needs at runtime is not
// one. A dependency reached through another package carries neither flag, because
// bun.lock records nothing per entry that would say so.
//
// Line numbers come from encoding/json: the decoder reports the byte offset it has
// reached, and lockfile.LineIndex turns that into the line the package key sits on,
// which is where a SARIF finding points. The comments and the trailing commas the
// standard decoder will not read are blanked out in a copy rather than removed, so
// that every offset in the copy is the same offset in the real file and the line
// numbers are the file's own. internal/configfile reads .jsonc the same way and for
// the same reason; the twenty lines below are written again here rather than
// imported, because internal/configfile is an editor of configuration files, with
// its own document, codec and edit types, and a lockfile reader that imported it
// would take all of that on to borrow one function.
//
// Format verified against Bun's own text lockfile writer and reader,
// src/install/lockfile/bun.lock.rs, and the recorded fixtures on 2026-09-09. Both
// fixtures declare lockfileVersion 1.
package bun

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
const formatName = "bun.lock"

// rootWorkspace is the key the "workspaces" object gives the repository itself.
const rootWorkspace = ""

func init() { lockfile.Register(parser{}) }

// parser reads bun.lock.
type parser struct{}

// Name returns the format's name, which is also the file name it reads.
func (parser) Name() string { return formatName }

// Detect reports whether the file is a bun.lock. The caller has already lowered
// the base name, so a plain comparison answers it. bun.lockb, the binary lockfile
// Bun wrote before this one, is a different format and is not claimed here.
func (parser) Detect(base string) bool { return base == formatName }

// jsonWorkspace is what one project of the repository declares. Only the names
// matter, so the ranges stay raw and are never decoded.
type jsonWorkspace struct {
	// Name is what the project publishes under, which is not read: a workspace is
	// reached through the "packages" entry that resolves to its path.
	Name                 string                     `json:"name"`
	Version              string                     `json:"version"`
	Dependencies         map[string]json.RawMessage `json:"dependencies"`
	DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
	OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
}

// jsonInfo is the part of a packages entry's info object the checks need. Its
// dependency maps, its os, cpu and bin fields say nothing an entry records.
type jsonInfo struct {
	// Bundled marks a package whose bytes ship inside its parent's tarball, so it
	// has no artifact and no hash of its own.
	Bundled bool `json:"bundled"`
}

// locked is one entry as read, with the line its key sits on. The entries are
// collected first and turned into lockfile entries afterwards, because Direct is
// decided by the workspaces, which may be written after them.
type locked struct {
	// key is the install path, which names the package as the manifest that asked
	// for it spells it: the name, or the alias for an aliased dependency.
	key  string
	line int
	// name and locator are the two halves of the resolution.
	name    string
	locator string
	// registry is the tarball URL an npm resolution states, empty when it came
	// from the registry the project configures.
	registry  string
	integrity string
	bundled   bool
}

// Parse reads the lockfile. path names the file in messages and in Lockfile.Path
// only.
func (parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", formatName, err)
	}
	lines := lockfile.NewLineIndex(data)
	dec := json.NewDecoder(bytes.NewReader(blankJSONC(data)))
	lf := &lockfile.Lockfile{Path: path, Format: formatName, Ecosystem: model.NPM}

	if err := openObject(dec, "the top level"); err != nil {
		return nil, err
	}
	var (
		version    int
		hasVersion bool
		workspaces []jsonWorkspace
		locks      []locked
	)
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "lockfileVersion":
			if err := dec.Decode(&version); err != nil {
				return nil, fmt.Errorf("%s: lockfileVersion: %w", formatName, err)
			}
			hasVersion = true
		case "workspaces":
			if workspaces, err = decodeWorkspaces(dec, lines, lf); err != nil {
				return nil, err
			}
		case "packages":
			if locks, err = decodePackages(dec, lines, lf); err != nil {
				return nil, err
			}
		default:
			// "configVersion", "overrides", "patchedDependencies",
			// "trustedDependencies", "catalog" and "catalogs", none of which
			// changes a field an entry records.
			if err := skipValue(dec); err != nil {
				return nil, fmt.Errorf("%s: %q: %w", formatName, key, err)
			}
		}
	}
	if err := closeObject(dec, "the top level"); err != nil {
		return nil, err
	}
	if !hasVersion {
		return nil, fmt.Errorf("%s states no lockfileVersion: this is not a bun.lock that bun wrote, and bun.lockb, the binary lockfile bun wrote before this one, is a different format that `bun install --save-text-lockfile` replaces", formatName)
	}
	lf.Version = strconv.Itoa(version)

	direct, versions := requested(workspaces)
	hosts := countRegistryHosts(locks)
	for i := range locks {
		add(lf, &locks[i], direct, versions, hosts)
	}
	return lf, nil
}

// decodeWorkspaces reads the "workspaces" object. A workspace whose value is not
// an object is dropped rather than failing the file, which costs the Direct flag
// of what it asks for and nothing else.
func decodeWorkspaces(dec *json.Decoder, lines *lockfile.LineIndex, lf *lockfile.Lockfile) ([]jsonWorkspace, error) {
	if err := openObject(dec, `"workspaces"`); err != nil {
		return nil, err
	}
	var out []jsonWorkspace
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		line := lines.Line(dec.InputOffset())
		var ws jsonWorkspace
		if err := dec.Decode(&ws); err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				// Decode read the whole value before it found the type wrong, so
				// the stream already sits at the next key.
				lf.Drop("the workspace %s on line %d is %s, not an object, so what it asks for is not counted as direct", named(key), line, typeErr.Value)
				continue
			}
			return nil, fmt.Errorf("%s: the workspace %s: %w", formatName, named(key), err)
		}
		out = append(out, ws)
	}
	if err := closeObject(dec, `"workspaces"`); err != nil {
		return nil, err
	}
	return out, nil
}

// named words a workspace key for a message. The repository itself is keyed by the
// empty string, and a reason that said `""` would send a reader nowhere.
func named(key string) string {
	if key == rootWorkspace {
		return "at the root of the repository"
	}
	return strconv.Quote(key)
}

// decodePackages reads the "packages" object, in file order. An entry whose value
// is not the array this format writes is dropped with a reason.
func decodePackages(dec *json.Decoder, lines *lockfile.LineIndex, lf *lockfile.Lockfile) ([]locked, error) {
	if err := openObject(dec, `"packages"`); err != nil {
		return nil, err
	}
	var locks []locked
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		// The offset now sits just past the key's closing quote, on the key's own
		// line, because a JSON string cannot hold a raw newline.
		line := lines.Line(dec.InputOffset())
		var items []json.RawMessage
		if err := dec.Decode(&items); err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				// Decode read the whole value before it found the type wrong, so
				// the stream already sits at the next key.
				lf.Drop("%q on line %d is %s, not the array this format writes", key, line, typeErr.Value)
				continue
			}
			return nil, fmt.Errorf("%s: %q: %w", formatName, key, err)
		}
		l, ok := shape(lf, key, line, items)
		if ok {
			locks = append(locks, l)
		}
	}
	if err := closeObject(dec, `"packages"`); err != nil {
		return nil, err
	}
	return locks, nil
}

// shape reads one packages array by the resolution in its first element, because
// that is what says how many elements come before the hash and whether the element
// after the info object is a hash at all.
func shape(lf *lockfile.Lockfile, key string, line int, items []json.RawMessage) (locked, bool) {
	if len(items) == 0 {
		lf.Drop("%q on line %d is an empty array, which states no resolution", key, line)
		return locked{}, false
	}
	var resolution string
	if err := json.Unmarshal(items[0], &resolution); err != nil {
		lf.Drop("%q on line %d does not start with a resolution string", key, line)
		return locked{}, false
	}
	l := locked{key: key, line: line}
	l.name, l.locator = splitLocator(resolution)
	if l.name == "" || l.locator == "" {
		lf.Drop("%q on line %d resolves to %q, which names no package version", key, line, resolution)
		return locked{}, false
	}

	at := 1
	if bareVersion(l.locator) {
		// The registry URL is an element of its own that only an npm resolution
		// has. Bun writes it empty for the registry the project configures, and an
		// element that is not a string at all leaves it empty too, which reads as
		// that same registry: an entry whose shape is wrong here still names a
		// package version, and dropping it would hide the package rather than the
		// mistake.
		if at < len(items) {
			_ = json.Unmarshal(items[at], &l.registry)
			at++
		}
	}
	if at < len(items) {
		var info jsonInfo
		// An info object this parser cannot read costs the bundled flag and
		// nothing else, so it is not worth dropping the entry over.
		if err := json.Unmarshal(items[at], &info); err == nil {
			l.bundled = info.Bundled
		}
		at++
	}
	if at < len(items) && carriesIntegrity(l.locator) {
		// An element that is not a string leaves the hash empty, which is what an
		// entry that states none looks like and is what TD014 reports.
		_ = json.Unmarshal(items[at], &l.integrity)
	}
	return l, true
}

// add turns one read entry into a lockfile entry.
func add(lf *lockfile.Lockfile, l *locked, direct map[string]*asked, versions map[string]string, hosts *lockfile.RegistryHosts) {
	if l.locator == "root:" {
		// The repository itself, which is a project and not a package it installs.
		return
	}
	// The key names the dependency as the manifests spell it, which for an alias is
	// the alias; the resolution names the package that is really installed. Every
	// lookup wants the installed name, and Direct wants the spelling the dependency
	// maps use.
	asked := lastName(l.key)
	version := l.locator
	if strings.HasPrefix(l.locator, "workspace:") && versions[l.name] != "" {
		// A workspace member's own version, which the locator states nowhere and
		// which only that member's "workspaces" entry holds.
		version = versions[l.name]
	}
	entry := lockfile.Entry{
		Ref: model.PackageRef{
			Ecosystem: model.NPM,
			Name:      model.NormalizeName(model.NPM, l.name),
			Version:   version,
		},
		Source:    sourceOf(l.locator, l.registry, hosts),
		Resolved:  resolvedOf(l.locator, l.registry),
		Integrity: l.integrity,
		Bundled:   l.bundled,
		Line:      l.line,
	}
	if ref := direct[asked]; ref != nil && topLevel(l.key) {
		entry.Direct = true
		// A package every workspace calls a development dependency is one; a
		// package any project needs at runtime is not. Optional reads the same way,
		// because an install may leave out only what no project requires.
		entry.Dev = ref.sections == ref.dev
		entry.Optional = ref.sections == ref.optional
	}
	lf.Add(entry)
}

// asked is how the workspaces name one package: how many maps name it at all, and
// how many of those were devDependencies or optionalDependencies.
type asked struct {
	sections int
	dev      int
	optional int
}

// requested indexes every package the projects depend on directly, keyed the way
// the manifests spell it, which for an aliased dependency is the alias. The second
// map is the version each workspace publishes under, which is the only place a
// workspace member's version is written and is not itself a dependency on it.
func requested(workspaces []jsonWorkspace) (map[string]*asked, map[string]string) {
	direct := make(map[string]*asked)
	versions := make(map[string]string)
	for i := range workspaces {
		ws := &workspaces[i]
		for _, section := range []struct {
			names    map[string]json.RawMessage
			dev      bool
			optional bool
		}{
			{names: ws.Dependencies},
			{names: ws.DevDependencies, dev: true},
			{names: ws.OptionalDependencies, optional: true},
		} {
			for name := range section.names {
				ref := direct[name]
				if ref == nil {
					ref = &asked{}
					direct[name] = ref
				}
				ref.sections++
				if section.dev {
					ref.dev++
				}
				if section.optional {
					ref.optional++
				}
			}
		}
		if ws.Name != "" && ws.Version != "" {
			versions[ws.Name] = ws.Version
		}
	}
	return direct, versions
}

// countRegistryHosts weighs the hosts the file downloads from, so that the host a
// project installs through can be told from a host one entry points at alone. Only
// the URLs that have the registry layout are counted: any other URL is reported as
// a URL whatever its host serves.
func countRegistryHosts(locks []locked) *lockfile.RegistryHosts {
	hosts := lockfile.NPMRegistryHosts()
	for i := range locks {
		u, err := url.Parse(locks[i].registry)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !registryLayout(u) {
			continue
		}
		hosts.Count(u.Hostname())
	}
	return hosts
}

// splitLocator reads a resolution into the package name and what follows it. Bun's
// own rule is used: an optional "@scope/" prefix, then a name that holds neither
// "/" nor "@", then "@" and everything after it. Splitting at the last "@" instead
// would read the alias "widgets@npm:@acme/widgets@1.4.2" as a different package.
func splitLocator(resolution string) (name, locator string) {
	from := 0
	if strings.HasPrefix(resolution, "@") {
		slash := strings.IndexByte(resolution, '/')
		if slash < 1 {
			return "", ""
		}
		from = slash
	}
	at := strings.IndexByte(resolution[from:], '@')
	if at < 0 {
		return resolution, ""
	}
	return resolution[:from+at], resolution[from+at+1:]
}

// bareVersion reports whether the locator is a version rather than a place to
// fetch from, which is what an npm resolution states and what no other shape does.
// No character of a semantic version is a ":", so the test is exact. It is also
// what says that the array carries a registry element before its info object.
func bareVersion(locator string) bool {
	return !strings.Contains(locator, ":")
}

// carriesIntegrity reports whether the element after the info object is a hash.
// For a git resolution it is Bun's own checkout tag, which is not a hash of the
// package and must not be recorded as one.
func carriesIntegrity(locator string) bool {
	return bareVersion(locator) || sourceOf(locator, "", nil) == lockfile.SourceURL
}

// resolvedOf is the location the entry records, as written. A resolution that is a
// bare version records the tarball URL alongside it, which is empty for the
// registry the project configures; every other shape is itself the location.
func resolvedOf(locator, registry string) string {
	if bareVersion(locator) {
		return registry
	}
	return locator
}

// sourceOf reads where a locator says the version came from. registry is the
// tarball URL an npm resolution states, empty when the file states none, and hosts
// weighs it against the rest of the file; both are ignored for every other shape.
func sourceOf(locator, registry string, hosts *lockfile.RegistryHosts) lockfile.Source {
	if bareVersion(locator) {
		return registrySource(registry, hosts)
	}
	if strings.HasPrefix(locator, "git+") {
		// git+ssh, git+https and the rest, whose scheme holds a second ":".
		return lockfile.SourceGit
	}
	proto, _, _ := strings.Cut(locator, ":")
	switch proto {
	case "link", "file", "workspace", "root":
		return lockfile.SourcePath
	case "git", "ssh", "github", "gitlab", "bitbucket":
		return lockfile.SourceGit
	case "http", "https":
		if gitRemote(locator) {
			return lockfile.SourceGit
		}
		return lockfile.SourceURL
	default:
		return lockfile.SourceUnknown
	}
}

// registrySource decides an npm resolution. An entry that states no URL came from
// the registry the project configures, which bun.lock does not name and cannot
// therefore be repointed in. An entry that states one is a registry install only
// when the rest of the file agrees the host is the registry, which is what
// lockfile.RegistryHosts decides and what a repointed entry cannot fake.
func registrySource(registry string, hosts *lockfile.RegistryHosts) lockfile.Source {
	if registry == "" {
		return lockfile.SourceRegistry
	}
	u, err := url.Parse(registry)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return lockfile.SourceUnknown
	}
	if hosts != nil && (hosts.Known(u.Hostname()) || (registryLayout(u) && hosts.Serves(u.Hostname()))) {
		return lockfile.SourceRegistry
	}
	return lockfile.SourceURL
}

// registryLayout reports whether the path is the tarball layout every npm registry
// and mirror serves, "<name>/-/<name>-<version>.tgz".
func registryLayout(u *url.URL) bool {
	return strings.Contains(u.Path, "/-/") && strings.HasSuffix(u.Path, ".tgz")
}

// gitRemote reports whether an http locator names a repository rather than a file
// to download: a path ending in ".git", which is how Bun writes a git dependency
// reached over https, with the commit it resolved to in the fragment.
func gitRemote(locator string) bool {
	u, err := url.Parse(locator)
	if err != nil {
		return false
	}
	return strings.HasSuffix(u.Path, ".git")
}

// lastName is the name at the end of an install path, which is the name the
// manifest that asked for the entry wrote: the package name, or the alias for an
// aliased dependency. A scoped name holds a slash of its own, so the last name is
// the last two segments when the one before it opens a scope.
func lastName(key string) string {
	parts := strings.Split(key, "/")
	if n := len(parts); n >= 2 && strings.HasPrefix(parts[n-2], "@") {
		return parts[n-2] + "/" + parts[n-1]
	}
	return parts[len(parts)-1]
}

// topLevel reports whether the install path is the package name alone, which is
// the only place a direct dependency of a project can sit. A copy nested under
// another package, "boxen/chalk", is there because something else asked for it.
func topLevel(key string) bool {
	return key != "" && lastName(key) == key
}

// blankJSONC returns a copy of the file in which every byte of every comment and
// every trailing comma has been replaced by a space, which is what makes it
// readable by encoding/json. Nothing is removed and nothing is added, so every
// offset in the copy is the same offset in the file, which is what lets the
// decoder say which line of the real file an entry sits on.
func blankJSONC(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			out[i] = ' '
		}
	}
	for i := 0; i < len(out); {
		switch {
		case out[i] == '"':
			i += stringLen(out[i:])
		case bytes.HasPrefix(out[i:], []byte("//")):
			end := bytes.IndexByte(out[i:], '\n')
			if end < 0 {
				blank(i, len(out))
				i = len(out)
				continue
			}
			// The newline ends the comment rather than belonging to it, so it stays
			// and the line count of the copy is the line count of the file.
			blank(i, i+end)
			i += end
		case bytes.HasPrefix(out[i:], []byte("/*")):
			end := bytes.Index(out[i+2:], []byte("*/"))
			if end < 0 {
				blank(i, len(out))
				i = len(out)
				continue
			}
			blank(i, i+2+end+2)
			i += 2 + end + 2
		default:
			i++
		}
	}
	// The commas are found on the blanked copy, so a comma written inside a comment
	// is not one of them.
	for i := 0; i < len(out); {
		switch out[i] {
		case '"':
			i += stringLen(out[i:])
		case ',':
			if j := nextContent(out, i+1); j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
			i++
		default:
			i++
		}
	}
	return out
}

// nextContent is the offset of the next byte that is not whitespace.
func nextContent(data []byte, from int) int {
	i := from
	for i < len(data) && space(data[i]) {
		i++
	}
	return i
}

// space reports whether a byte is whitespace between two JSON tokens.
func space(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// stringLen is the length of the JSON string that starts at data, up to and
// including its closing quote, or the rest of the file when it is not closed.
func stringLen(data []byte) int {
	for i := 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(data)
}

// openObject reads the "{" that starts an object.
func openObject(dec *json.Decoder, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: %s: %w", formatName, what, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("%s: %s: want an object, found %v", formatName, what, tok)
	}
	return nil
}

// closeObject reads the "}" that ends an object.
func closeObject(dec *json.Decoder, what string) error {
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%s: %s: %w", formatName, what, err)
	}
	return nil
}

// objectKey reads the next key of an object.
func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("%s: object key: %w", formatName, err)
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("%s: object key: want a string, found %v", formatName, tok)
	}
	return key, nil
}

// skipValue reads and discards the next value, however deeply nested, without
// building it in memory. It is how the parser walks past the keys it does not read.
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
