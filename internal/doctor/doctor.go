// Package doctor reads the hardening settings a repository's package managers
// support and reports which are set, which are missing and which are set to
// something that does not do what the person who wrote it expected.
//
// The settings are the ones the package managers themselves added after the 2025
// npm worm: a minimum release age, a refusal to run install scripts, a frozen
// lockfile. They are the cheapest defense a project has, and they are almost always
// off, because they are new and because their units disagree. npm counts days, pnpm
// and Yarn count minutes, Bun counts seconds, Deno takes a minute count or an ISO
// 8601 duration, uv takes a duration in words. A person who writes 10080 into
// bunfig.toml meaning a week has asked for three hours, and nothing tells them.
//
// A rule is data: which manager, which file, which key, since which version, what
// the value should be, and how to judge what is there. Adding one is a table entry
// and a test. The judgment is unit aware, so the scorecard can say that a setting
// is present and still wrong.
//
// Nothing here executes a package manager to find out what a setting is. Versions
// come from the files a repository commits first, and a manager is only run, with a
// fixed argument list and no shell, when those cannot answer. The files are read as
// text and edited by line through internal/configfile, so a fix never reformats a
// file somebody else wrote.
package doctor

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// ManagerID names one package manager or dependency bot.
type ManagerID string

// The managers doctor knows. The value is what a policy file, a message and the
// json document all spell it.
const (
	NPM        ManagerID = "npm"
	PNPM       ManagerID = "pnpm"
	Yarn       ManagerID = "yarn"
	Bun        ManagerID = "bun"
	Deno       ManagerID = "deno"
	UV         ManagerID = "uv"
	Pip        ManagerID = "pip"
	Poetry     ManagerID = "poetry"
	Cargo      ManagerID = "cargo"
	Dependabot ManagerID = "dependabot"
	Renovate   ManagerID = "renovate"
	Actions    ManagerID = "actions"
)

// Ecosystem is the registry a manager installs from, so that a run judges each
// manager against the cooldown the policy sets for its own ecosystem: a project
// that waits three days for npm and seven for crates.io is told to configure three
// in pnpm and seven wherever Cargo eventually accepts one. The three that are not a
// package manager for a registry, the two bots and the workflow files, answer false
// and are judged against the policy's own cooldown.
func (id ManagerID) Ecosystem() (model.Ecosystem, bool) {
	switch id {
	case NPM, PNPM, Yarn, Bun, Deno:
		return model.NPM, true
	case UV, Pip, Poetry:
		return model.PyPI, true
	case Cargo:
		return model.Cargo, true
	}
	return "", false
}

// Versioned reports whether the manager has a version worth naming. The two
// dependency bots run as a service and the workflow files are read by GitHub
// itself, so there is no version a repository could pin and no version a scorecard
// should say it failed to detect.
func (id ManagerID) Versioned() bool {
	switch id {
	case Dependabot, Renovate, Actions:
		return false
	}
	return true
}

// Manager is one package manager found in a repository.
type Manager struct {
	// ID is which manager it is.
	ID ManagerID
	// Root is the directory it manages, relative to the scan root, "." for the
	// repository itself. A monorepo with a Python service and a Node front end has
	// one Manager per directory.
	Root string
	// Version is the version the repository pins or the machine has, empty when
	// nothing said. Rules that depend on a version report "not applicable" rather
	// than guessing when this is empty.
	Version string
	// VersionSource says where Version came from, in the words the scorecard
	// prints: "the packageManager field", "pnpm-lock.yaml", "pnpm --version".
	VersionSource string
	// Evidence is what made this manager count as present, one line each: a
	// lockfile, a manifest field, a configuration file.
	Evidence []string
	// Files are the configuration files found for it, relative to the scan root.
	Files []string
	// Base is the directory Root and Files are resolved against when it is not the
	// directory the run was pointed at. It is set for the user level configuration
	// --user reports, which lives in the home directory rather than in the
	// repository, and it is what keeps a fix inside the repository: a run never
	// writes a file whose Base says it belongs to the machine.
	Base string
}

// UserScope reports whether the manager's files belong to the machine rather than
// to the repository. Those are reported and never written: a tool run inside one
// project has no business changing the settings of every other project on the
// computer.
func (m *Manager) UserScope() bool { return m.Base != "" }

// Status is what a rule concluded about one setting.
type Status string

// The statuses a scorecard prints. Set and NotApplicable are not problems; the
// other three are, in the order of how much they should worry a reader.
const (
	// StatusSet means the file holds a value that does what the rule asks.
	StatusSet Status = "set"
	// StatusWrong means the key is there and its value does not: the wrong unit,
	// or a threshold too permissive to mean anything.
	StatusWrong Status = "wrong"
	// StatusMissing means the file does not state the key at all.
	StatusMissing Status = "missing"
	// StatusUnreadable means the file exists and could not be read or the value
	// sits somewhere the reader will not interpret.
	StatusUnreadable Status = "unreadable"
	// StatusNotApplicable means the rule does not apply here: the manager is older
	// than the setting, or a newer key replaced this one.
	StatusNotApplicable Status = "not applicable"
	// StatusAdvice means the rule has no right answer to check: which packages may
	// run a build script, which scanner to trust, what a manager offers instead of a
	// setting it does not have. The row exists so that a reader knows the question
	// is there, and its note is the answer. It never fails a gate.
	StatusAdvice Status = "advice"
)

// Problem reports whether the status is one --ci should be able to fail on.
func (s Status) Problem() bool {
	return s == StatusWrong || s == StatusMissing || s == StatusUnreadable
}

// Unit is how a manager spells a length of time. The same three days is 3 for npm,
// 4320 for pnpm and Yarn, 259200 for Bun, and "P3D" or "3 days" elsewhere, which is
// why a scorecard that only compared numbers would be useless.
type Unit interface {
	// Name is what the unit is called in a message: "days", "minutes", "seconds",
	// "an ISO 8601 duration".
	Name() string
	// Parse reads a value as the file wrote it. An unparseable value is an error,
	// which the rule reports as a wrong value rather than a missing one.
	Parse(text string) (time.Duration, error)
	// Format writes a duration the way this manager's file spells it.
	Format(d time.Duration) string
}

// Params are what the rules judge against: the project's own cooldown and the
// version of the manager being judged.
type Params struct {
	// Cooldown is the threshold the policy sets for young versions, which is what
	// doctor recommends here too. A project that decided three days for its own
	// gate is not told to configure seven in its package manager.
	Cooldown time.Duration
	// Version is the manager's version, empty when unknown.
	Version string
	// Now is the run clock, for a rule that has to reason about time.
	Now time.Time
	// PinExceptions are the workflow references a project has decided may stay on
	// a tag, as globs over "owner/repo" or "owner/repo/path". The Actions rule
	// already knows the one case that cannot be pinned at all, and this is for the
	// ones only the project knows about.
	PinExceptions []string
}

// Desired is what a correct setting looks like and how to judge what is there.
// Each kind of setting has one implementation: a minimum age with a unit, a
// boolean, a value out of a set.
type Desired interface {
	// Want is the value to write when the setting is missing or wrong.
	Want(p Params) configfile.Literal
	// Judge looks at what the file holds. detail is the sentence the scorecard
	// prints after the status, in the tool's own voice, for example "3 minutes,
	// which is 3 days in npm's unit and three minutes here".
	Judge(v *configfile.Value, p Params) (status Status, detail string)
	// Describe says what the rule asks for, for the documentation and for a
	// scorecard line about a setting that is missing.
	Describe(p Params) string
}

// Target is a file a rule's key can live in. A rule lists them in the order it
// prefers: pnpm reads pnpm-workspace.yaml first, and npm's own settings live in
// .npmrc while its script policy lives in package.json.
type Target struct {
	// Name is the file name relative to the manager's root.
	Name string
	// Format is the codec that reads it.
	Format configfile.Format
	// Key is the path to the setting inside that file.
	Key configfile.Key
	// CreateIf is true when doctor --fix may create the file if it is absent. An
	// .npmrc is created; a package.json is not, because a repository without one
	// is not a repository this rule applies to.
	CreateIf bool
}

// Rule is one hardening setting: what to look at, since when it exists, what it
// should say, and how much it matters.
type Rule struct {
	// ID is stable and cited in messages and in docs/doctor.md, DR001 upward.
	ID string
	// Name is the policy name, which is how a policy file turns the rule off.
	Name string
	// Manager is whose setting it is.
	Manager ManagerID
	// Summary is one line saying what the setting does, for the scorecard.
	Summary string
	// Since is the lowest manager version that has the setting, empty when the
	// setting has always been there or the manager has no versions to speak of.
	Since string
	// Until, when set, is the first version that no longer has the setting,
	// because a newer key replaced it. onlyBuiltDependencies is a pnpm 10 key that
	// allowBuilds replaces in 11.
	Until string
	// Replaces names the rule this one supersedes, so a scorecard does not report
	// both as missing.
	Replaces string
	// Targets are the files the setting can live in, most preferred first.
	Targets []Target
	// Desired is the value and the judgment.
	Desired Desired
	// Scan, when set, replaces the lookup of a key in a file: the rule reads the
	// repository its own way and returns its own results. The GitHub Actions rule
	// needs it, because what it judges is every uses: line of every workflow file
	// rather than one setting with one value.
	Scan Scanner
	// Level is how much a missing or wrong setting matters, before the policy is
	// applied.
	Level model.Level
	// Docs is the page the row was verified against.
	Docs string
	// Verified is the date the documentation was last read, RFC 3339 date only.
	// Every one of these settings is younger than a year and the units have already
	// changed once, so a row without a date is a row nobody can trust.
	Verified string
	// Fixable is false for a rule doctor can only report: a recommendation to
	// upgrade, a setting that has no configuration file to write it into.
	Fixable bool
	// Note is an extra sentence the scorecard prints for a rule that needs one,
	// such as the Cargo row, which has no setting to write at all.
	Note string
}

// Applies reports whether the rule applies to a manager at this version, and the
// caveat the scorecard should carry when it does.
//
// A version nobody could determine is treated as a current release rather than as
// a reason to say nothing. Most repositories pin no version anywhere, and a
// scorecard that answered "not applicable" to every rule for them would be a
// scorecard that helps nobody. The caveat says what the answer rests on, and a rule
// a newer version replaced is left out, because assuming a current release means
// assuming the key that release reads.
func (r *Rule) Applies(version string) (bool, string) {
	if version == "" {
		switch {
		case r.Until != "":
			return false, fmt.Sprintf("%s %s replaced this setting, and the version in use could not be determined", r.Manager, r.Until)
		case r.Since == "":
			return true, ""
		}
		return true, fmt.Sprintf("the %s version could not be determined; this setting needs %s or later", r.Manager, r.Since)
	}
	if r.Since != "" && CompareVersions(version, r.Since) < 0 {
		return false, fmt.Sprintf("needs %s %s or later and this project pins %s", r.Manager, r.Since, version)
	}
	if r.Until != "" && CompareVersions(version, r.Until) >= 0 {
		return false, fmt.Sprintf("%s %s replaced this setting", r.Manager, version)
	}
	return true, ""
}

// Scanner is how a rule that is not one key in one file looks at a repository. It
// returns one result per thing it judged, with Rule, Manager and Level left zero:
// the caller fills those in, so that a scanner cannot report a rule other than its
// own and the policy is applied to its results like to every other.
type Scanner interface {
	// Scan reads what it needs under root, which is the directory the run was
	// pointed at, and reports what it found for this manager.
	Scan(root string, m *Manager, p Params) ([]Result, error)
}

// Result is one rule evaluated against one manager in one repository.
type Result struct {
	// Rule is the rule that was evaluated.
	Rule *Rule
	// Manager is which manager instance it was evaluated for.
	Manager *Manager
	// Status is the conclusion.
	Status Status
	// Detail is the sentence after the status.
	Detail string
	// File is the file that was read, relative to the scan root, empty when none
	// of the rule's targets exist.
	File string
	// Line is the 1-based line of the value, 0 when there is none to point at.
	Line int
	// Current is the value as the file writes it, empty when the key is absent.
	Current string
	// Want is what the rule asks for, as it would be written.
	Want string
	// Level is the level after the policy was applied.
	Level model.Level
	// Fixed is true when --fix wrote this setting in this run.
	Fixed bool
	// Edit is the change --fix would make, empty when there is nothing to write.
	Edit string
	// params are what this result was judged against: the manager's own version and
	// the cooldown of its ecosystem. The fixer writes the value they ask for, so it
	// cannot write a number the judgment did not mean.
	params Params
	// target is the file and key this result came from, so the fixer writes the
	// same place the judgment read. A scanner rule leaves it zero, which is one
	// more reason a scanner rule is never fixed automatically.
	target Target
}

var (
	rulesMu sync.Mutex
	rules   []*Rule
)

// Register adds a rule; each manager's file calls it from init. A duplicate id or
// name is a programming error and panics.
func Register(r *Rule) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	for _, existing := range rules {
		if existing.ID == r.ID {
			panic("doctor: duplicate rule id " + r.ID)
		}
		if existing.Name == r.Name {
			panic("doctor: duplicate rule name " + r.Name)
		}
	}
	rules = append(rules, r)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
}

// Rules returns every registered rule, ordered by id.
func Rules() []*Rule {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	out := make([]*Rule, len(rules))
	copy(out, rules)
	return out
}

// RulesFor returns the rules of one manager, ordered by id.
func RulesFor(id ManagerID) []*Rule {
	out := make([]*Rule, 0, 8)
	for _, r := range Rules() {
		if r.Manager == id {
			out = append(out, r)
		}
	}
	return out
}

// CompareVersions orders two dotted versions numerically, segment by segment, and
// ignores anything after a hyphen. It is not semver: what it compares are package
// manager versions such as "10.16.1" and "11.0.0-beta.2", where only the numbers
// decide and a prerelease of 11 already has what 11 has. A segment that is not a
// number sorts before one that is, so a version nobody can read never counts as
// newer than the version a setting arrived in.
func CompareVersions(a, b string) int {
	as := versionParts(a)
	bs := versionParts(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		// A segment the version does not have is a zero, so 11 and 11.0.0 are the
		// same version. A segment that is not a number is -1, which keeps it below
		// every number.
		x, y := 0, 0
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// versionParts splits a version into its numeric segments, with -1 for a segment
// that is not a number.
func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	fields := strings.Split(v, ".")
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n := 0
		ok := f != ""
		for _, c := range f {
			if c < '0' || c > '9' {
				ok = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if !ok {
			out = append(out, -1)
			continue
		}
		out = append(out, n)
	}
	return out
}
