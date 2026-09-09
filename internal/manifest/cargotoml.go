package manifest

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/vahapogut/trustdiff/internal/model"
)

// cargoToml is the part of a Cargo.toml this reader needs. A dependency's value is
// either a requirement string or a table, so it is decoded as any and read by shape.
type cargoToml struct {
	Package struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	Workspace         struct {
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"workspace"`
}

// readCargoToml reads a Rust manifest, a package's and a workspace root's alike.
//
// A workspace root's [workspace.dependencies] is read as a table of its own,
// because a virtual root, one with no [package] at all, declares the workspace's
// dependencies nowhere else. A member that writes "workspace = true" takes its
// requirement from that same table when this file has one, and is skipped when it
// does not: the requirement then lives in the root's Cargo.toml, which is another
// file and not this reader's to open.
func readCargoToml(path string, data []byte) (*Manifest, error) {
	var raw cargoToml
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("not a Cargo.toml this reader can parse: %w", err)
	}
	m := &Manifest{Path: path, Format: FormatCargoToml, Ecosystem: model.Cargo, Name: raw.Package.Name}
	for _, table := range []struct {
		name   string
		values map[string]any
		dev    bool
	}{
		{name: TableDependencies, values: raw.Dependencies},
		{name: TableCargoDev, values: raw.DevDependencies, dev: true},
		// A build dependency is compiled and run on the machine doing the build,
		// which makes it as much of the project's supply chain as anything it
		// ships, so it is evaluated like the rest.
		{name: TableCargoBuild, values: raw.BuildDependencies},
		{name: TableCargoWorkspace, values: raw.Workspace.Dependencies},
	} {
		for _, name := range sortedKeys(table.values) {
			readCargoDependency(m, name, table.values[name], table.name, table.dev, raw.Workspace.Dependencies)
		}
	}
	return m, nil
}

// readCargoDependency reads one entry of a dependency table.
func readCargoDependency(m *Manifest, name string, value any, table string, dev bool, workspace map[string]any) {
	switch v := value.(type) {
	case string:
		m.add(cargoDeclaration(name, name, v, table, dev, false))
	case map[string]any:
		readCargoTableValue(m, name, v, table, dev, workspace)
	default:
		m.skip(name, "", table, "its value is neither a version requirement nor a table, so there is nothing to resolve")
	}
}

// readCargoTableValue reads a dependency written as a table: where it comes from,
// what it is really called, and what version of it is asked for.
func readCargoTableValue(m *Manifest, name string, value map[string]any, table string, dev bool, workspace map[string]any) {
	// The source keys come first: a dependency with one of them is built from
	// there whatever its "version" says, and the version is then a constraint on
	// a checkout rather than on anything the registry published.
	for _, source := range []struct{ key, what string }{
		{"git", "a git repository"},
		{"path", "a path on this machine"},
	} {
		if location, ok := value[source.key].(string); ok && location != "" {
			m.skip(name, location, table, "%s, which has no published version to evaluate", source.what)
			return
		}
	}
	if index, ok := value["registry"].(string); ok && index != "" {
		// An alternate registry is a different index, which may well hold a
		// different crate under this name, so crates.io is not asked about it.
		m.skip(name, index, table, "pinned to the %q registry, which trustdiff does not know how to ask", index)
		return
	}
	if inherits, ok := value["workspace"].(bool); ok && inherits {
		inherited, ok := workspace[name]
		if !ok {
			m.skip(name, "", table, "inherited from the workspace, whose requirement is not in this file")
			return
		}
		// The requirement is the workspace's, and everything else about the
		// dependency stays the member's.
		readCargoDependency(m, name, inherited, table, dev, nil)
		return
	}

	// "package" renames a crate the way an npm alias does: the key is what the
	// code says and this is the crate that is really built.
	crate := name
	if renamed, ok := value["package"].(string); ok && renamed != "" {
		crate = renamed
	}
	requirement, ok := value["version"].(string)
	if !ok {
		m.skip(name, "", table, "its table names no version, so there is nothing to resolve")
		return
	}
	optional, _ := value["optional"].(bool)
	m.add(cargoDeclaration(name, crate, requirement, table, dev, optional))
}

// cargoDeclaration builds one declaration. declared is the key the manifest wrote
// and crate is what is really built, which differ when the table renames it.
func cargoDeclaration(declared, crate, requirement, table string, dev, optional bool) *Declaration {
	alias := ""
	if crate != declared {
		alias = declared
	}
	return &Declaration{
		Ref:      model.PackageRef{Ecosystem: model.Cargo, Name: model.NormalizeName(model.Cargo, crate)},
		Alias:    alias,
		Range:    requirement,
		Syntax:   SyntaxCargo,
		Table:    table,
		Dev:      dev,
		Optional: optional,
	}
}
