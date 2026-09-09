package doctor

import (
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Yarn's settings, read against https://yarnpkg.com/configuration/yarnrc and the
// yarnrc schema the documentation site publishes, on 2026-09-09. The schema is
// what the defaults below come from: the values in the panel beside each setting
// on that page are examples, and reading them as defaults is how a tool ends up
// reporting a correct file as wrong.

func init() {
	Register(yarnMinimalAgeGate)
	Register(yarnEnableScripts)
	Register(yarnChecksumBehavior)
	Register(yarnHardenedMode)
}

// A bare number is minutes here, like pnpm. Yarn 4.11 also accepts a duration
// string ("3d"), and 4.15 raised the default to one day. The rule writes the
// number, because a project on 4.10 reads a string as nothing at all.
var yarnMinimalAgeGate = &Rule{
	ID:      "DR020",
	Name:    "yarn-minimal-age-gate",
	Manager: Yarn,
	Summary: "wait before installing a release that was just published",
	Since:   "4.10.0",
	Targets: []Target{{
		Name:     ".yarnrc.yml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"npmMinimalAgeGate"},
		CreateIf: true,
	}},
	Desired:  MinimumAge{Unit: Minutes, Default: 24 * time.Hour, DefaultSince: "4.15.0"},
	Level:    model.LevelWarn,
	Docs:     "https://yarnpkg.com/configuration/yarnrc",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "A number is minutes. Yarn 4.11 and later also read a duration such as 3d, and 4.10 silently ignores one. npmPreapprovedPackages takes the packages that skip the wait, and the gate can be set per scope under npmScopes.",
}

// Yarn stopped running dependency build scripts by default in 4.14, so this rule
// is about older versions and about a project that turned them back on.
var yarnEnableScripts = &Rule{
	ID:      "DR021",
	Name:    "yarn-enable-scripts",
	Manager: Yarn,
	Summary: "do not run the build scripts of dependencies",
	Targets: []Target{{
		Name:     ".yarnrc.yml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"enableScripts"},
		CreateIf: true,
	}},
	Desired:  BoolSetting{On: false, Defaulted: true, Default: false, DefaultSince: "4.14.0"},
	Level:    model.LevelWarn,
	Docs:     "https://yarnpkg.com/configuration/yarnrc",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Yarn 4.14 turned this off by default. A package that genuinely needs its build script is named in dependenciesMeta with build: true.",
}

// The checksum is what makes a lockfile a lock. Yarn's default is already to
// throw, so this rule catches the project that set it to update, which rewrites
// the lockfile to match whatever the registry served today.
var yarnChecksumBehavior = &Rule{
	ID:      "DR022",
	Name:    "yarn-checksum-behavior",
	Manager: Yarn,
	Summary: "fail when a download does not match the lockfile checksum",
	Targets: []Target{{
		Name:     ".yarnrc.yml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"checksumBehavior"},
		CreateIf: true,
	}},
	Desired: EnumSetting{
		Value:    "throw",
		Accepted: []string{"update", "ignore", "reset"},
		Weaker:   "accepts bytes that do not match the lockfile, which is the one thing the checksum is there to stop",
	},
	Level:    model.LevelWarn,
	Docs:     "https://yarnpkg.com/configuration/yarnrc",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "throw is the default. update rewrites the lockfile to match what was downloaded, which turns a tampered artifact into a committed one.",
}

// Hardened mode re-checks the lockfile against the registry during an install,
// which is what catches a lockfile a pull request edited by hand. Yarn turns it on
// by itself for a pull request from a public repository, so the rule is for the
// projects that get no such help: private repositories and pushes to a branch.
var yarnHardenedMode = &Rule{
	ID:      "DR023",
	Name:    "yarn-hardened-mode",
	Manager: Yarn,
	Summary: "check the lockfile against the registry during an install",
	Targets: []Target{{
		Name:   ".yarnrc.yml",
		Format: configfile.FormatYAML,
		Key:    configfile.Key{"enableHardenedMode"},
	}},
	// Reported and not written: it slows every install down, and Yarn already
	// turns it on where it matters most. A project that wants it everywhere sets
	// YARN_ENABLE_HARDENED_MODE in its CI rather than in the file every developer
	// reads.
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://yarnpkg.com/configuration/yarnrc",
	Verified: "2026-09-09",
	Note:     "Yarn turns hardened mode on by itself for a pull request against a public repository. Elsewhere it is off, and turning it on costs install time, so it belongs in the CI environment rather than in the file.",
}
