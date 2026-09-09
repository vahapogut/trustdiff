package manifest

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/vahapogut/trustdiff/internal/model"
)

// pythonKey is Poetry's spelling of the interpreter constraint. It sits among the
// dependencies and is not a distribution, so it is skipped saying so rather than
// looked up on PyPI.
const pythonKey = "python"

// pyproject is the part of a pyproject.toml this reader needs: PEP 621's own
// dependency lists and Poetry's tables. A Poetry dependency's value is a string, a
// table or a list of tables, so it is decoded as any and read by shape.
type pyproject struct {
	Project struct {
		Name                 string              `toml:"name"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Name            string         `toml:"name"`
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// readPyproject reads a Python manifest: PEP 621's [project] tables, and Poetry's
// where the file uses them. A file can carry both, and then both are read, because
// a project migrating from one to the other declares in both and installs from
// whichever its build backend reads.
func readPyproject(path string, data []byte) (*Manifest, error) {
	var raw pyproject
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("not a pyproject.toml this reader can parse: %w", err)
	}
	m := &Manifest{Path: path, Format: FormatPyproject, Ecosystem: model.PyPI, Name: raw.Project.Name}
	if m.Name == "" {
		m.Name = raw.Tool.Poetry.Name
	}

	for _, requirement := range raw.Project.Dependencies {
		readPEP621Requirement(m, requirement, TableProjectDependencies, false, false)
	}
	for _, extra := range sortedKeys(raw.Project.OptionalDependencies) {
		table := "project.optional-dependencies." + extra
		for _, requirement := range raw.Project.OptionalDependencies[extra] {
			readPEP621Requirement(m, requirement, table, false, true)
		}
	}

	readPoetryTable(m, raw.Tool.Poetry.Dependencies, TablePoetryDependencies, false)
	readPoetryTable(m, raw.Tool.Poetry.DevDependencies, TablePoetryDev, true)
	for _, group := range sortedKeys(raw.Tool.Poetry.Group) {
		// A Poetry group is what the project needs to work on itself rather than
		// to run, which is the same thing dev-dependencies said before groups
		// existed.
		readPoetryTable(m, raw.Tool.Poetry.Group[group].Dependencies, "tool.poetry.group."+group+".dependencies", true)
	}
	return m, nil
}

// readPEP621Requirement reads one PEP 508 requirement string.
func readPEP621Requirement(m *Manifest, requirement, table string, dev, optional bool) {
	r, err := parseRequirement(requirement)
	if err != nil {
		m.skip(strings.TrimSpace(requirement), "", table, "%v", err)
		return
	}
	if r.url != "" {
		m.skip(r.name, r.url, table, "a direct reference to %s, which has no published version to evaluate", r.url)
		return
	}
	m.add(&Declaration{
		Ref:      model.PackageRef{Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, r.name)},
		Range:    r.specifier,
		Syntax:   SyntaxPEP440,
		Table:    table,
		Dev:      dev,
		Optional: optional,
		Extras:   r.extras,
		Marker:   r.marker,
	})
}

// readPoetryTable reads one of Poetry's dependency tables.
func readPoetryTable(m *Manifest, deps map[string]any, table string, dev bool) {
	for _, name := range sortedKeys(deps) {
		readPoetryDependency(m, name, deps[name], table, dev)
	}
}

// readPoetryDependency reads one entry of a Poetry table, whose value is a
// constraint string, a table naming the constraint and where to get it, or a list of
// such tables when the project asks for different versions on different platforms.
func readPoetryDependency(m *Manifest, name string, value any, table string, dev bool) {
	if name == pythonKey {
		m.skip(name, poetryConstraintText(value), table, "the interpreter Poetry resolves against, not a distribution")
		return
	}
	switch v := value.(type) {
	case string:
		m.add(poetryDeclaration(name, v, table, dev, false, "", nil))
	case map[string]any:
		readPoetryTableValue(m, name, v, table, dev)
	case []any:
		// One dependency declared several times, each for a different marker. Every
		// one of them is a version the project could install, so every one is read.
		for _, entry := range v {
			nested, ok := entry.(map[string]any)
			if !ok {
				m.skip(name, "", table, "one of its entries is not a table, so there is no version constraint to read")
				continue
			}
			readPoetryTableValue(m, name, nested, table, dev)
		}
	default:
		m.skip(name, "", table, "its value is neither a constraint nor a table, so there is no version constraint to read")
	}
}

// readPoetryTableValue reads a Poetry dependency written as a table.
func readPoetryTableValue(m *Manifest, name string, value map[string]any, table string, dev bool) {
	for _, source := range []struct{ key, what string }{
		{"git", "a git repository"},
		{"path", "a path on this machine"},
		{"url", "an archive URL"},
	} {
		if location, ok := value[source.key].(string); ok && location != "" {
			m.skip(name, location, table, "%s, which has no published version to evaluate", source.what)
			return
		}
	}
	constraintText, ok := value["version"].(string)
	if !ok {
		m.skip(name, "", table, "its table names no version, so there is nothing to resolve")
		return
	}
	optional, _ := value["optional"].(bool)
	marker, _ := value["markers"].(string)
	m.add(poetryDeclaration(name, constraintText, table, dev, optional, marker, poetryExtras(value)))
}

// poetryDeclaration builds one declaration read from a Poetry table.
func poetryDeclaration(name, constraintText, table string, dev, optional bool, marker string, extras []string) *Declaration {
	return &Declaration{
		Ref:      model.PackageRef{Ecosystem: model.PyPI, Name: model.NormalizeName(model.PyPI, name)},
		Range:    constraintText,
		Syntax:   SyntaxPoetry,
		Table:    table,
		Dev:      dev,
		Optional: optional,
		Marker:   marker,
		Extras:   extras,
	}
}

// poetryExtras reads the "extras" key, which names the parts of a distribution the
// project uses. They change no version and are recorded for the same reason PEP 508
// extras are.
func poetryExtras(value map[string]any) []string {
	listed, ok := value["extras"].([]any)
	if !ok {
		return nil
	}
	extras := make([]string, 0, len(listed))
	for _, entry := range listed {
		if extra, ok := entry.(string); ok {
			extras = append(extras, extra)
		}
	}
	return extras
}

// poetryConstraintText renders a Poetry value for a skipped declaration's reason,
// which is the constraint when the value is one and nothing when it is a table.
func poetryConstraintText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

// requirement is one PEP 508 requirement, split into the parts this package uses.
type requirement struct {
	name      string
	extras    []string
	specifier string
	marker    string
	// url is the direct reference the requirement names, empty for the ordinary
	// form. A requirement that names one pins an artifact rather than a version.
	url string
}

// parseRequirement splits a PEP 508 requirement string: a name, optional extras in
// brackets, either a version specifier or a direct reference after an "@", and an
// optional environment marker after a semicolon.
//
// The marker is kept and never evaluated: what the checks want to know is what
// could be installed, and a dependency this machine would skip today is one another
// machine installs.
func parseRequirement(text string) (requirement, error) {
	var r requirement
	rest := strings.TrimSpace(text)
	if rest == "" {
		return r, fmt.Errorf("an empty requirement")
	}
	if front, marker, ok := strings.Cut(rest, ";"); ok {
		rest, r.marker = strings.TrimSpace(front), strings.TrimSpace(marker)
	}

	end := 0
	for end < len(rest) && isNameByte(rest[end]) {
		end++
	}
	r.name, rest = rest[:end], strings.TrimSpace(rest[end:])
	if r.name == "" {
		return r, fmt.Errorf("%q names no distribution", strings.TrimSpace(text))
	}

	if strings.HasPrefix(rest, "[") {
		inside, after, ok := strings.Cut(rest[1:], "]")
		if !ok {
			return r, fmt.Errorf("%q leaves its extras unclosed", strings.TrimSpace(text))
		}
		for _, extra := range strings.Split(inside, ",") {
			if extra = strings.TrimSpace(extra); extra != "" {
				r.extras = append(r.extras, extra)
			}
		}
		rest = strings.TrimSpace(after)
	}

	if reference, ok := strings.CutPrefix(rest, "@"); ok {
		r.url = strings.TrimSpace(reference)
		return r, nil
	}
	// A specifier may be wrapped in parentheses, which PEP 508's grammar allows
	// and which setuptools writes.
	rest = strings.TrimSpace(rest)
	if inside, ok := strings.CutPrefix(rest, "("); ok {
		specifier, _, closed := strings.Cut(inside, ")")
		if !closed {
			return r, fmt.Errorf("%q leaves its version specifier unclosed", strings.TrimSpace(text))
		}
		rest = strings.TrimSpace(specifier)
	}
	r.specifier = rest
	return r, nil
}

// isNameByte reports whether the byte can appear in a PEP 508 distribution name.
func isNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	default:
		return b == '-' || b == '_' || b == '.'
	}
}
