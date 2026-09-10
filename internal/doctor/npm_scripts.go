package doctor

import (
	"encoding/json"
	"path/filepath"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// NpmStrictAllowScripts judges npm's strict-allow-scripts, which is the one setting
// here whose safe value depends on a second file.
//
// npm's config page gives it as "If true, turn the install-script policy from a
// warning into a hard error: any dependency with install scripts that is not
// covered by allowScripts will fail the install instead of being blocked with a
// warning", default false, and the install-scripts page says npm otherwise
// "silently skip[s] lifecycle scripts for any dependency that does not have a
// matching entry in allowScripts" (https://docs.npmjs.com/cli/v12/using-npm/config
// and https://docs.npmjs.com/cli/v12/commands/npm-install-scripts, read
// 2026-09-11).
//
// So the value hardens a project that has reviewed its install scripts and breaks
// one that has not: every dependency with a postinstall becomes a failed install at
// once. Writing it into a repository that states no allowScripts is not hardening,
// it is a broken npm install somebody has to undo, and the line they take out is
// the whole rule. Where there is nothing to be strict about the rule says so and
// writes nothing, which is what the pnpm allowBuilds rule already does for the
// question of which packages may build at all.
type NpmStrictAllowScripts struct {
	// reviewed is whether package.json states an allowScripts with anything in it.
	// It is filled in by Bind, because a Desired is a package level value and this
	// answer belongs to one repository.
	reviewed bool
}

// Bind reads the package.json beside the .npmrc this rule would write.
func (n NpmStrictAllowScripts) Bind(root string, m *Manager) Desired {
	n.reviewed = allowScriptsReviewed(root, m)
	return n
}

// Want is the hardened value, which is only ever written where Judge reported the
// setting missing, and it reports missing only where there is a review to be strict
// about.
func (NpmStrictAllowScripts) Want(*Params) configfile.Literal { return configfile.Bool(true) }

// Describe says which value the rule asks for.
func (NpmStrictAllowScripts) Describe(*Params) string { return "true" }

// Judge reads the boolean the same way every other boolean setting is read, and
// answers the absent case with what the repository has reviewed.
func (n NpmStrictAllowScripts) Judge(v *configfile.Value, p *Params) (Status, string) {
	if v.Found() {
		// Somebody wrote this line themselves. Whatever package.json says, the value
		// is theirs and it either does what the rule asks or it does not.
		return BoolSetting{On: true, Defaulted: true, Default: false}.Judge(v, p)
	}
	if !n.reviewed {
		return StatusAdvice, "not set, and package.json states no allowScripts with anything in it, so turning it on would fail the install on every dependency that has an install script. Review them first, with npm approve-scripts, and this becomes the line that stops an unreviewed script from being skipped in silence"
	}
	return StatusMissing, ""
}

// allowScriptsReviewed reports whether the project has an allowScripts with at
// least one package in it. An empty object is not a review: it approves nothing, so
// every dependency with a script is still unreviewed and strictness still fails the
// install. A machine's own .npmrc has no project beside it, and never a review.
func allowScriptsReviewed(root string, m *Manager) bool {
	if m == nil || m.UserScope() {
		return false
	}
	dir := root
	if m.Root != "" && m.Root != "." {
		dir = filepath.Join(root, filepath.FromSlash(m.Root))
	}
	// readConfig, so the manifest is read the way every other file here is: a
	// symlink or a device in its place is refused rather than followed.
	data, err := readConfig(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}
	doc := configfile.NewDoc("package.json", configfile.FormatJSON, data)
	v, err := configfile.Get(doc, configfile.Key{"allowScripts"})
	if err != nil || !v.Found() || v.Kind != configfile.KindMap {
		return false
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v.Raw), &entries); err != nil {
		return false
	}
	return len(entries) > 0
}
