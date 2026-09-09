package doctor

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/model"
)

// dependabotScanner reads .github/dependabot.yml and judges the cooldown of every
// update block in it.
//
// It is a scanner rather than a key in a file because the setting is inside a list:
// a repository with a Node front end, a Python service and a Docker image has three
// update blocks, each with a cooldown of its own, and a scorecard line that said
// "cooldown: missing" for the file as a whole would name neither the block that has
// one nor the two that do not.
//
// Nothing here writes. A block is identified by its ecosystem and directory, and
// where to insert a key in a list somebody else ordered is a judgment this tool
// does not make; the scorecard says which block is short and the person edits it.
type dependabotScanner struct{}

// dependabotDefaultWait is what a version update waits with no cooldown block at
// all, which GitHub made the default on 2026-07-14. A project whose own cooldown
// is no longer than this is already covered. Security updates never wait, which is
// deliberate and is not something a project should change.
const dependabotDefaultWait = 3 * 24 * time.Hour

// Scan reads the file and returns one result per update block.
func (dependabotScanner) Scan(root string, m *Manager, p *Params) ([]Result, error) {
	path, rel := dependabotFile(root, m)
	if path == "" {
		return nil, nil
	}
	data, err := readConfig(path)
	if err != nil {
		return []Result{{
			Status: StatusUnreadable,
			Detail: fmt.Sprintf("could not be read: %v", err),
			File:   rel,
		}}, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return []Result{{
			Status: StatusUnreadable,
			Detail: fmt.Sprintf("is not valid yaml: %v", err),
			File:   rel,
		}}, nil
	}
	updates := mappingValue(documentRoot(&doc), "updates")
	if updates == nil || updates.Kind != yaml.SequenceNode || len(updates.Content) == 0 {
		return []Result{{
			Status: StatusUnreadable,
			Detail: "has no updates list, so there is nothing scheduled and nothing to wait",
			File:   rel,
			Line:   lineOf(documentRoot(&doc)),
		}}, nil
	}
	results := make([]Result, 0, len(updates.Content))
	for _, block := range updates.Content {
		results = append(results, dependabotBlock(rel, block, p))
	}
	return results, nil
}

// dependabotBlock judges one update block against the cooldown its own ecosystem
// is entitled to. A repository that waits three days for npm and seven for
// crates.io says so in its policy, and the block names which one it updates.
func dependabotBlock(file string, block *yaml.Node, p *Params) Result {
	name := blockName(block)
	want := blockCooldown(block, p)
	res := Result{File: file, Line: lineOf(block), Want: Days.Format(want)}
	cooldown := mappingValue(block, "cooldown")
	days := mappingValue(cooldown, "default-days")
	if days == nil {
		// No cooldown at all, and a cooldown that names only the semver kinds, wait
		// the same three days GitHub applies by default to a version update. The
		// two used to be judged differently, which reported the more careful file as
		// the worse one.
		res.Line = firstLine(block, cooldown)
		detail := fmt.Sprintf("%s has no cooldown of its own", name)
		if cooldown != nil {
			detail = fmt.Sprintf("%s sets no default-days", name)
		}
		if want <= dependabotDefaultWait {
			res.Status = StatusSet
			res.Detail = fmt.Sprintf("%s, and a version update waits %s by default, which is at least the %s the policy asks for",
				detail, Humanize(dependabotDefaultWait), Humanize(want))
			return res
		}
		res.Status = StatusMissing
		res.Detail = fmt.Sprintf("%s, and the default wait of %s is shorter than the %s the policy asks for",
			detail, Humanize(dependabotDefaultWait), Humanize(want))
		return res
	}
	res.Line = days.Line
	res.Current = days.Value
	have, err := Days.Parse(days.Value)
	if err != nil {
		res.Status = StatusWrong
		res.Detail = fmt.Sprintf("%s: default-days is %s, and %v", name, quote(days.Value), err)
		return res
	}
	switch {
	case have < want:
		res.Status = StatusWrong
		res.Detail = fmt.Sprintf("%s waits %s, and the policy asks for %s", name, Humanize(have), Humanize(want))
	default:
		res.Status = StatusSet
		res.Detail = fmt.Sprintf("%s waits %s", name, Humanize(have))
	}
	return res
}

// blockCooldown is the wait this block's ecosystem is entitled to.
func blockCooldown(block *yaml.Node, p *Params) time.Duration {
	if eco, ok := dependabotEcosystem(scalarValue(mappingValue(block, "package-ecosystem"))); ok {
		if cooldown, set := p.Cooldowns[eco]; set && cooldown > 0 {
			return cooldown
		}
	}
	return p.Cooldown
}

// dependabotEcosystem maps a package-ecosystem value onto the registry the policy
// knows it by. Dependabot updates more ecosystems than this tool evaluates, and one
// it does not know keeps the policy's own cooldown rather than being guessed at.
func dependabotEcosystem(value string) (model.Ecosystem, bool) {
	switch value {
	case "npm":
		return model.NPM, true
	case "pip", "uv":
		return model.PyPI, true
	case "cargo":
		return model.Cargo, true
	}
	return "", false
}

// firstLine is the line a message about a missing key should point at: the key it
// is missing from when that key is there, and the block itself when it is not.
func firstLine(block, cooldown *yaml.Node) int {
	if cooldown != nil {
		// The value node of a mapping starts at its first child, and what a reader
		// wants is the line above it, where "cooldown:" is written.
		if line := lineOf(cooldown); line > 1 {
			return line - 1
		}
	}
	return lineOf(block)
}

// blockName words which update block a line is about, which is the pair a reader
// scrolls to in the file.
func blockName(block *yaml.Node) string {
	eco := scalarValue(mappingValue(block, "package-ecosystem"))
	dir := scalarValue(mappingValue(block, "directory"))
	if dir == "" {
		if dirs := mappingValue(block, "directories"); dirs != nil && len(dirs.Content) > 0 {
			dir = scalarValue(dirs.Content[0])
			if len(dirs.Content) > 1 {
				dir += fmt.Sprintf(" and %d more", len(dirs.Content)-1)
			}
		}
	}
	switch {
	case eco == "" && dir == "":
		return "an update block"
	case dir == "":
		return "the " + eco + " updates"
	case eco == "":
		return "the updates in " + dir
	}
	return "the " + eco + " updates in " + dir
}

// dependabotFile finds the configuration file among the ones detection recorded,
// and returns the path to open and the path to report.
func dependabotFile(root string, m *Manager) (path, rel string) {
	for _, f := range m.Files {
		base := strings.ToLower(filepath.Base(f))
		if base == "dependabot.yml" || base == "dependabot.yaml" {
			return filepath.Join(root, filepath.FromSlash(f)), f
		}
	}
	return "", ""
}

// documentRoot unwraps the document node yaml.Unmarshal into a Node produces, so
// the caller reads the mapping the file starts with.
func documentRoot(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}
	return n
}

// mappingValue returns the value of a key in a mapping, or nil. It is written
// here rather than through Unmarshal into a struct because every result needs the
// line the value sits on, which only the node carries.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// scalarValue reads a scalar's text, and "" for anything else, including nil.
func scalarValue(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// lineOf is the 1-based line of a node, 0 when there is none.
func lineOf(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	return n.Line
}
