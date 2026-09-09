package manifest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// npmAliasPrefix marks a dependency installed under a name of its own:
// "d3v3": "npm:d3@^3" installs d3 and calls it d3v3.
const npmAliasPrefix = "npm:"

// npmProtocols are the value prefixes that name something other than a range the
// registry can answer. Each is skipped with the words on the right, because there
// is no published version behind it to evaluate and no honest way to guess one.
var npmProtocols = []struct{ prefix, what string }{
	{"file:", "a path on this machine"},
	{"link:", "a link to a directory"},
	{"portal:", "a portal to a directory"},
	{"workspace:", "the workspace protocol, resolved inside the repository"},
	{"patch:", "a patch of another dependency"},
	{"git+", "a git repository"},
	{"git:", "a git repository"},
	{"ssh://", "a repository fetched over ssh"},
	{"github:", "a repository on GitHub"},
	{"gitlab:", "a repository on GitLab"},
	{"bitbucket:", "a repository on Bitbucket"},
	{"gist:", "a gist"},
	{"http://", "a tarball URL"},
	{"https://", "a tarball URL"},
}

// packageJSON is the part of a package.json this reader needs. The three dependency
// maps are the ones npm installs from the manifest; peerDependencies are installed
// through the package that asks for them and are not the project's own, so they are
// not read. The values stay raw so that one entry npm would reject costs one
// declaration rather than the whole file.
type packageJSON struct {
	Name                 string                     `json:"name"`
	Dependencies         map[string]json.RawMessage `json:"dependencies"`
	DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
	OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
}

// readPackageJSON reads an npm manifest, a workspace root's and a member's alike.
func readPackageJSON(path string, data []byte) (*Manifest, error) {
	var raw packageJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not a package.json this reader can parse: %w", err)
	}
	m := &Manifest{Path: path, Format: FormatPackageJSON, Ecosystem: model.NPM, Name: raw.Name}
	for _, table := range []struct {
		name     string
		values   map[string]json.RawMessage
		dev      bool
		optional bool
	}{
		{name: TableDependencies, values: raw.Dependencies},
		{name: TableDevDependencies, values: raw.DevDependencies, dev: true},
		{name: TableOptionalDependencies, values: raw.OptionalDependencies, optional: true},
	} {
		for _, name := range sortedKeys(table.values) {
			var spec string
			if err := json.Unmarshal(table.values[name], &spec); err != nil {
				m.skip(name, "", table.name, "its value is not a string, so there is no version range to read")
				continue
			}
			readNPMDependency(m, name, spec, table.name, table.dev, table.optional)
		}
	}
	return m, nil
}

// readNPMDependency turns one entry of a dependency map into a declaration, or
// skips it with the reason.
func readNPMDependency(m *Manifest, name, spec, table string, dev, optional bool) {
	installed, rangeText, reason := npmSpec(name, spec)
	if reason != "" {
		m.skip(name, strings.TrimSpace(spec), table, "%s", reason)
		return
	}
	// A range npm cannot read either is skipped by add with the parser's reason,
	// except for the one shape worth naming: a bare word in a dependency map is a
	// dist-tag, and a tag is a pointer the registry moves rather than a range.
	if _, err := parseConstraint(SyntaxNPM, rangeText); err != nil && isBareWord(rangeText) {
		m.skip(name, rangeText, table, "%q is a dist-tag rather than a version range, and a tag is a pointer the registry moves", rangeText)
		return
	}
	alias := ""
	if installed != name {
		alias = name
	}
	m.add(&Declaration{
		Ref:      model.PackageRef{Ecosystem: model.NPM, Name: model.NormalizeName(model.NPM, installed)},
		Alias:    alias,
		Range:    rangeText,
		Syntax:   SyntaxNPM,
		Table:    table,
		Dev:      dev,
		Optional: optional,
	})
}

// npmSpec reads one dependency value: which package is really installed and what
// range of it, or the reason there is no registry version behind the value.
func npmSpec(name, spec string) (installed, rangeText, reason string) {
	value := strings.TrimSpace(spec)
	installed = name
	if rest, ok := strings.CutPrefix(value, npmAliasPrefix); ok {
		// An alias: the key is the name the project imports and the value names
		// the package that is really installed, which is what every registry and
		// advisory lookup has to be made under.
		target, aliased, ok := cutNPMAlias(rest)
		if !ok {
			return "", "", fmt.Sprintf("the alias %q names no package", value)
		}
		installed, value = target, aliased
	}
	if what := npmNonRegistry(value); what != "" {
		return "", "", what + ", which has no published version to evaluate"
	}
	if value == "" {
		// npm reads an empty range as "any version", and so does this.
		value = "*"
	}
	return installed, value, ""
}

// cutNPMAlias splits the "d3@^3" that follows "npm:" into the package that is
// really installed and the range of it. A scoped name keeps its leading "@", so the
// split is at the last one; an alias with no range at all accepts any version.
func cutNPMAlias(rest string) (name, rangeText string, ok bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return rest, "*", true
	}
	name = rest[:at]
	if name == "" {
		return "", "", false
	}
	return name, rest[at+1:], true
}

// npmNonRegistry names what a value points at when it is not a registry range, and
// returns an empty string when it is one. The shorthand for a repository, "user/repo"
// and "user/repo#branch", is the one form with no prefix to recognize it by: a
// registry range never holds a slash, so a slash is what tells them apart.
func npmNonRegistry(value string) string {
	for _, protocol := range npmProtocols {
		if strings.HasPrefix(value, protocol.prefix) {
			return protocol.what
		}
	}
	if strings.Contains(value, "/") {
		return "a repository shorthand"
	}
	return ""
}

// isBareWord reports whether the value is a plain identifier. Asked only of a value
// the range grammar has already refused, that makes it a dist-tag: "latest",
// "next", "canary".
func isBareWord(value string) bool {
	if value == "" {
		return false
	}
	if !isLetter(value[0]) {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case isLetter(c), c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// isLetter reports whether the byte is an ASCII letter.
func isLetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// sortedKeys returns a map's keys in order, so that a manifest is always read, and
// its dependencies always reported, in the same order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
