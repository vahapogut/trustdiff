package doctor

import (
	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// npm's settings, read against https://docs.npmjs.com/cli/v12/using-npm/config and
// the command pages on 2026-09-09, with the version each key arrived in taken from
// the published packages rather than from a changelog summary.
//
// One thing to know before writing any of these: npm warns about a key it does not
// recognize rather than failing, and has done since 11.2, so a pnpm key that ends
// up in an .npmrc is a warning nobody reads. That is why every rule here names the
// file it belongs in and doctor never writes one manager's key into another's file.

func init() {
	Register(npmMinReleaseAge)
	Register(npmStrictAllowScripts)
	Register(npmAllowGit)
	Register(npmAllowRemote)
	Register(npmStrictNpmrc)
}

// npm counts days, which is the coarsest unit of the lot: a cooldown of twelve
// hours cannot be expressed and rounds up to a whole day.
var npmMinReleaseAge = &Rule{
	ID:      "DR001",
	Name:    "npm-min-release-age",
	Manager: NPM,
	Summary: "wait before installing a release that was just published",
	Since:   "11.10.0",
	Targets: []Target{{
		Name:     ".npmrc",
		Format:   configfile.FormatINI,
		Key:      configfile.Key{"min-release-age"},
		CreateIf: true,
	}},
	Desired:  MinimumAge{Unit: Days},
	Level:    model.LevelWarn,
	Docs:     "https://docs.npmjs.com/cli/v12/using-npm/config",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "npm counts whole days. min-release-age-exclude, from 11.17.0, takes the names and globs that skip the wait. The two may sit beside an absolute before date, and npm then follows before.",
}

// Blocking install scripts is the single largest reduction in what a compromised
// package can do, and npm 12 blocks them by default. strict-allow-scripts is what
// turns the remaining silence into a failure: without it a dependency outside
// allowScripts is skipped and mentioned at the end of the install, which is where
// nobody looks. It is also the one setting here whose safe value depends on a
// second file, which is why NpmStrictAllowScripts reads package.json before it
// answers.
var npmStrictAllowScripts = &Rule{
	ID:      "DR002",
	Name:    "npm-strict-allow-scripts",
	Manager: NPM,
	Summary: "fail rather than quietly skip an install script nobody approved",
	Since:   "11.16.0",
	Targets: []Target{{
		Name:     ".npmrc",
		Format:   configfile.FormatINI,
		Key:      configfile.Key{"strict-allow-scripts"},
		CreateIf: true,
	}},
	Desired:  NpmStrictAllowScripts{},
	Level:    model.LevelWarn,
	Docs:     "https://docs.npmjs.com/cli/v12/commands/npm-install-scripts",
	Verified: "2026-09-11",
	Fixable:  true,
	Note:     "The packages allowed to run a script live in the allowScripts object of package.json, which npm approve-scripts writes. Until that object has something in it there is nothing to be strict about, so the rule reports and writes nothing. ignore-scripts=true is the blunter option: it stops every script, including the project's own.",
}

// allow-git and allow-remote are npm 12 defaults, which makes them a rule about
// older versions and about a project that turned them back on. A dependency
// installed from a git remote or a URL is the case TD013 reports in a lockfile;
// these two keys are how npm refuses to install one at all.
var npmAllowGit = &Rule{
	ID:      "DR003",
	Name:    "npm-allow-git",
	Manager: NPM,
	Summary: "refuse a dependency installed from a git remote",
	Since:   "11.9.0",
	Targets: []Target{{
		Name:     ".npmrc",
		Format:   configfile.FormatINI,
		Key:      configfile.Key{"allow-git"},
		CreateIf: true,
	}},
	Desired: &EnumSetting{
		Value:        "none",
		Accepted:     []string{"all", "root"},
		Weaker:       "lets a dependency come from a git remote, where the version number promises nothing about what is installed",
		Default:      "none",
		DefaultSince: "12.0.0",
	},
	Level:    model.LevelInfo,
	Docs:     "https://docs.npmjs.com/cli/v12/using-npm/config",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "npm 12 defaults to none, npm 11 to all. root allows the project's own git dependencies and refuses a dependency's.",
}

var npmAllowRemote = &Rule{
	ID:      "DR004",
	Name:    "npm-allow-remote",
	Manager: NPM,
	Summary: "refuse a dependency installed from a URL",
	Since:   "11.14.0",
	Targets: []Target{{
		Name:     ".npmrc",
		Format:   configfile.FormatINI,
		Key:      configfile.Key{"allow-remote"},
		CreateIf: true,
	}},
	Desired: &EnumSetting{
		Value:        "none",
		Accepted:     []string{"all", "root"},
		Weaker:       "lets a dependency come from a tarball URL, which can serve different bytes tomorrow without the lockfile changing",
		Default:      "none",
		DefaultSince: "12.0.0",
	},
	Level:    model.LevelInfo,
	Docs:     "https://docs.npmjs.com/cli/v12/using-npm/config",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "npm 12 defaults to none, npm 11 to all.",
}

// A key npm does not recognize is a warning, and a warning in an install log is
// not a signal. strict-npmrc turns a misspelled setting into a failure, which is
// what makes every other row here worth writing: a project that sets
// min-releaes-age is not protected and has no way to find out.
var npmStrictNpmrc = &Rule{
	ID:      "DR005",
	Name:    "npm-strict-npmrc",
	Manager: NPM,
	Summary: "fail on a setting npm does not recognize instead of warning",
	Since:   "12.0.0",
	Targets: []Target{{
		Name:     ".npmrc",
		Format:   configfile.FormatINI,
		Key:      configfile.Key{"strict-npmrc"},
		CreateIf: true,
	}},
	Desired:  BoolSetting{On: true, Defaulted: true, Default: false},
	Level:    model.LevelInfo,
	Docs:     "https://docs.npmjs.com/cli/v12/using-npm/npmrc",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Turn this on last: it fails on every unrecognized key in the file, including one an older npm on another machine needs.",
}
