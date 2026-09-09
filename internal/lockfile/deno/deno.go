// Package deno reads deno.lock, the file the Deno runtime writes to pin what a
// project imports. Format versions 4 and 5 are read, which are the two a current
// Deno writes; a file that declares an earlier version is refused with a message
// saying so, because versions 1 to 3 nest the same maps under a "packages" object
// and running Deno once rewrites the file.
//
// The format mixes ecosystems in one file, so Lockfile.Ecosystem is left empty and
// every entry carries its own, which is what lockfile.Lockfile documents for a
// format like this. Four top level maps matter:
//
//   - "specifiers" maps a requirement the project wrote, "jsr:@std/path@1", to the
//     version the resolver chose, "1.1.6". It creates no entry of its own; it is
//     what turns a workspace requirement into the key of a locked package.
//   - "jsr" holds one entry per JSR package, keyed "@scope/name@version". Its
//     "integrity" is a bare sha256 hex of the package's manifest, which the entry
//     records as "sha256:<hex>" so the hash names its algorithm the way every other
//     ecosystem's does. These entries carry model.JSR.
//   - "npm" holds one entry per npm package, keyed "name@version" and, when the
//     resolver had to pick a copy for particular peers, "name@version_<peers>",
//     for example "@octokit/plugin-paginate-rest@14.0.0_@octokit+core@7.0.7". The
//     peer suffix is not part of the version, so it is cut off: a package the
//     resolver installed twice for two sets of peers therefore yields two entries
//     with the same ref, which is the same thing npm's nested node_modules
//     duplicates do. Its "integrity" is an SRI string, "sha512-...", recorded as
//     written. These entries carry model.NPM.
//   - "workspace" is what the project itself asks for: "dependencies" for the root,
//     "members" for each workspace member with a list of its own, and "packageJson"
//     where the requirements come from a package.json next to the deno.json. Every
//     one of those lists holds requirement strings, and a requirement resolved
//     through "specifiers" gives the exact key of the entry it selected, which is
//     how Direct is decided. A workspace member is a directory the project builds
//     and the file gives it no version, so it contributes requirements and no entry
//     of its own.
//
// A "remote" entry is dropped rather than turned into an entry. It maps the URL of
// one module file to the hash of that file's bytes, so a single URL dependency
// contributes one entry per file it and its imports reach, hundreds for a middling
// module. There is no name in it that a lookup could use: the URL is a file inside
// a module, no registry indexes it, and model.PackageRef would not even hold it,
// since model.ParseRef rejects a name containing a slash outside npm and JSR. So
// each one is dropped with its URL as the reason, which keeps a file full of URL
// imports visibly unevaluated instead of silently empty.
//
// Two fields the format simply does not carry. Resolved stays empty on every entry:
// deno.lock records an integrity hash and nothing about where the bytes were
// fetched from, not even the registry host, which is a setting of the runtime
// rather than of the file. Dev stays false because Deno has no development
// dependency: a deno.json has one "imports" map and nothing marks part of it as
// test only. Optional stays false for the same kind of reason; a version 5 "npm"
// entry lists which of its own dependencies are optional, which says nothing about
// whether the entry itself is one.
//
// model.Deno is not used by any entry. It names the runtime, and everything
// deno.lock resolves comes from JSR or from npm.
//
// Line numbers come from encoding/json: the decoder reports the byte offset it has
// reached, and lockfile.LineIndex turns that into the line the entry's key sits on,
// which is where a SARIF finding points.
//
// Format verified against the recorded fixtures and Deno's lockfile documentation
// on 2026-09-09: https://docs.deno.com/runtime/fundamentals/modules/
package deno

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Format is the name the parser registers under, which is also the file name it
// reads.
const Format = "deno.lock"

// firstReadableVersion is the oldest format version whose maps sit at the top
// level. Versions below it nest them under "packages" and are refused.
const firstReadableVersion = 4

// peerSuffix separates the version of an npm key from the peers the resolver
// picked that copy for. A semantic version cannot contain it, so cutting at the
// first one always leaves a version.
const peerSuffix = "_"

func init() { lockfile.Register(Parser{}) }

// Parser reads deno.lock files. The zero value is ready to use.
type Parser struct{}

// Name returns the format name, "deno.lock".
func (Parser) Name() string { return Format }

// Detect reports whether the base name is a deno.lock. lockfile.For lowercases the
// name before asking, so the comparison is against the lowercase spelling.
func (Parser) Detect(base string) bool { return base == Format }

// Parse reads a deno.lock. It fails when the file is not JSON and when the format
// version is one whose maps this parser cannot find; an entry it cannot make sense
// of is dropped with a reason and the rest is kept.
func (Parser) Parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	lf, err := parse(path, r)
	if err != nil {
		// Every failure below is a place in the file rather than a file, so the
		// format is named once here and a reader always learns which file failed.
		return nil, fmt.Errorf("%s: %w", Format, err)
	}
	return lf, nil
}

// parse is Parse without the naming, so that every error it returns can say where
// in the file it happened and nothing has to repeat the format name.
func parse(path string, r io.Reader) (*lockfile.Lockfile, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read the file: %w", err)
	}
	lines := lockfile.NewLineIndex(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	lf := &lockfile.Lockfile{Path: path, Format: Format}

	if err := openObject(dec, "the top level object"); err != nil {
		return nil, err
	}
	var (
		rawVersion any
		specifiers map[string]string
		ws         workspace
		locks      []locked
	)
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "version":
			if err := dec.Decode(&rawVersion); err != nil {
				return nil, fmt.Errorf("%q: %w", key, err)
			}
		case "specifiers":
			if err := dec.Decode(&specifiers); err != nil {
				return nil, fmt.Errorf("%q: %w", key, err)
			}
		case "jsr", "npm":
			section, err := decodeSection(dec, lines, lf, key)
			if err != nil {
				return nil, err
			}
			locks = append(locks, section...)
		case "remote":
			if err := dropRemote(dec, lf); err != nil {
				return nil, err
			}
		case "workspace":
			if err := dec.Decode(&ws); err != nil {
				return nil, fmt.Errorf("%q: %w", key, err)
			}
		default:
			// "redirects", "patches" and anything a later Deno adds: none of it
			// pins a package version, so it is walked past without being built.
			if err := skipValue(dec); err != nil {
				return nil, fmt.Errorf("%q: %w", key, err)
			}
		}
	}
	if err := closeObject(dec, "the top level object"); err != nil {
		return nil, err
	}

	lf.Version = formatVersion(rawVersion)
	if err := checkVersion(lf.Version); err != nil {
		return nil, err
	}
	direct := directKeys(&ws, specifiers, lf)
	for i := range locks {
		addEntry(lf, &locks[i], direct)
	}
	return lf, nil
}

// sectionPackage is the part of one "jsr" or "npm" entry the checks need. The
// dependency lists, the platform filters and the bin declarations describe how the
// package is installed rather than which version is pinned, so they are not read.
type sectionPackage struct {
	Integrity string `json:"integrity"`
}

// locked is one entry as read: the section it came from, its key as written, the
// name and version the key holds and the line the key sits on. Entries are
// collected first and turned into lockfile entries afterwards, because the
// "workspace" block that decides Direct is written after them.
type locked struct {
	section string
	key     string
	name    string
	version string
	line    int
	pkg     sectionPackage
}

// workspace is the "workspace" block: every list of requirements the project makes
// of the resolver, whether it wrote them in a deno.json or in a package.json.
type workspace struct {
	memberConfig
	Members map[string]memberConfig `json:"members"`
}

// memberConfig is what one project in the workspace asks for. The root of the
// workspace has the same shape as a member.
type memberConfig struct {
	Dependencies []string `json:"dependencies"`
	// PackageJSON holds the requirements that came from a package.json rather than
	// from the deno.json, which a project mixing the two writes here.
	PackageJSON struct {
		Dependencies []string `json:"dependencies"`
	} `json:"packageJson"`
}

// requirements returns every requirement this project states, in one list.
func (m *memberConfig) requirements() []string {
	return append(append([]string{}, m.Dependencies...), m.PackageJSON.Dependencies...)
}

// decodeSection reads the "jsr" or "npm" map, in file order, recording the entries
// it has to drop as it meets them so that the reasons stay in file order. An entry
// whose value is not an object, and one whose key holds no version, are dropped
// rather than failing the file.
func decodeSection(dec *json.Decoder, lines *lockfile.LineIndex, lf *lockfile.Lockfile, section string) ([]locked, error) {
	if err := openObject(dec, strconv.Quote(section)); err != nil {
		return nil, err
	}
	var locks []locked
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		// The offset now sits just past the key's closing quote, on the key's own line.
		line := lines.Line(dec.InputOffset())
		var pkg sectionPackage
		if err := dec.Decode(&pkg); err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				lf.Drop("%s: entry is %s, not an object", key, typeErr.Value)
				continue
			}
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		name, version, ok := splitKey(key)
		if !ok {
			lf.Drop("%s: key %q is not a name and a version, so there is nothing to evaluate", section, key)
			continue
		}
		locks = append(locks, locked{section: section, key: key, name: name, version: version, line: line, pkg: pkg})
	}
	if err := closeObject(dec, strconv.Quote(section)); err != nil {
		return nil, err
	}
	return locks, nil
}

// dropRemote reads the "remote" map and records every URL in it as dropped. The
// package comment says why a URL cannot become an entry; the URL is the reason, so
// a reader can still see everything the file pins.
func dropRemote(dec *json.Decoder, lf *lockfile.Lockfile) error {
	if err := openObject(dec, `"remote"`); err != nil {
		return err
	}
	for dec.More() {
		url, err := objectKey(dec)
		if err != nil {
			return err
		}
		if err := skipValue(dec); err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		lf.Drop("%s: a remote URL names one module file, not a package version, so there is no name to look it up by", url)
	}
	return closeObject(dec, `"remote"`)
}

// addEntry turns one read entry into a lockfile entry.
func addEntry(lf *lockfile.Lockfile, l *locked, direct map[string]bool) {
	eco := model.NPM
	if l.section == "jsr" {
		eco = model.JSR
	}
	lf.Add(lockfile.Entry{
		// npm and JSR names both keep their case, so NormalizeName leaves them
		// alone; it is called so the identity rule lives in one place.
		Ref: model.PackageRef{
			Ecosystem: eco,
			Name:      model.NormalizeName(eco, l.name),
			Version:   l.version,
		},
		// A JSR or npm entry is a registry install by construction: the section it
		// sits in is the registry, and the file records no other location.
		Source:    lockfile.SourceRegistry,
		Integrity: integrity(l.section, l.pkg.Integrity),
		Direct:    direct[l.section+" "+l.key],
		Line:      l.line,
	})
}

// integrity renders the hash the entry carries. A JSR hash is a bare sha256 hex
// and is given its algorithm, an npm hash is already an SRI string and is recorded
// as written, and an entry with no hash carries none.
func integrity(section, hash string) string {
	if hash == "" {
		return ""
	}
	if section == "jsr" {
		return "sha256:" + hash
	}
	return hash
}

// splitKey reads the name and the version out of a "jsr" or "npm" key. A scoped
// name carries an "@" of its own, so the version's "@" is looked for after the
// scope's slash; an npm key may then append the peers the resolver picked this copy
// for, after an underscore that no version may contain.
func splitKey(key string) (name, version string, ok bool) {
	at := -1
	if strings.HasPrefix(key, "@") {
		slash := strings.Index(key, "/")
		if slash < 0 {
			return "", "", false
		}
		if rel := strings.Index(key[slash:], "@"); rel >= 0 {
			at = slash + rel
		}
	} else {
		at = strings.Index(key, "@")
	}
	if at <= 0 {
		return "", "", false
	}
	name, version = key[:at], key[at+1:]
	if cut := strings.Index(version, peerSuffix); cut >= 0 {
		version = version[:cut]
	}
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// directKeys collects the entry keys the project asks for itself: every
// requirement the workspace and its members state, resolved through "specifiers"
// into the exact key of the entry it selected. The keys are prefixed with their
// section, because a JSR and an npm package may be spelled the same way.
//
// A requirement the file states no specifier for is recorded as dropped: it is a
// direct dependency whose entry cannot be found, and leaving it silent would report
// a package as transitive with nothing saying why.
func directKeys(ws *workspace, specifiers map[string]string, lf *lockfile.Lockfile) map[string]bool {
	direct := make(map[string]bool)
	add := func(m *memberConfig) {
		for _, req := range m.requirements() {
			section, rest, found := strings.Cut(req, ":")
			if !found || (section != "jsr" && section != "npm") {
				// A bare URL import, whose entries are the "remote" ones this
				// parser drops, so there is nothing to mark.
				continue
			}
			resolved, known := specifiers[req]
			if !known {
				lf.Drop(`%s: the workspace asks for it but "specifiers" gives it no version, so no entry is marked direct for it`, req)
				continue
			}
			direct[section+" "+requirementName(rest)+"@"+resolved] = true
		}
	}
	add(&ws.memberConfig)
	// The members are decoded into a map, so they are walked in path order rather
	// than in map order: a dropped reason must land in the same place every run.
	paths := make([]string, 0, len(ws.Members))
	for path := range ws.Members {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		member := ws.Members[path]
		add(&member)
	}
	return direct
}

// requirementName is the package name of a requirement with its scheme already
// cut, "@std/path@1" or "preact@^10.28.2". The range is dropped, because the key of
// the entry is the name with the resolved version.
func requirementName(rest string) string {
	if name, _, ok := splitKey(rest); ok {
		return name
	}
	// A requirement with no range at all, "jsr:@std/path", is the whole name.
	return rest
}

// formatVersion renders the "version" key. Deno writes it as a string, "4" or "5",
// and the first format versions wrote a number; a file without one reports an empty
// string.
func formatVersion(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case string:
		return n
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	default:
		return fmt.Sprint(n)
	}
}

// checkVersion refuses a format whose maps are not where this parser looks for
// them. A version it cannot read as a number is let through, because a later Deno
// numbering its formats differently is more likely to be readable than not.
func checkVersion(version string) error {
	n, numbered := versionNumber(version)
	if !numbered || n >= firstReadableVersion {
		return nil
	}
	return fmt.Errorf("declares version %s: a version below %d keeps its packages under a \"packages\" object, and running deno once rewrites the file", version, firstReadableVersion)
}

// versionNumber reads the format version as the whole number Deno writes, and
// reports false for anything else, which is a version this parser has no opinion
// about rather than one it can compare.
func versionNumber(version string) (int, bool) {
	n, err := strconv.Atoi(version)
	if err != nil {
		return 0, false
	}
	return n, true
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
// building it in memory.
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
