package doctor

import (
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// pnpm's settings, read against https://pnpm.io/settings and
// https://pnpm.io/supply-chain-security on 2026-09-09.
//
// Two facts shape every rule here. The settings live in pnpm-workspace.yaml, not
// in .npmrc: pnpm reads only authentication and registry settings from an .npmrc,
// so a minimumReleaseAge written there does nothing at all. And from pnpm 12 an
// unrecognized key in pnpm-workspace.yaml fails the command when the project pins
// a pnpm version, which is why the rules that changed their name carry both the
// version they arrived in and the version that dropped them.

func init() {
	Register(pnpmMinimumReleaseAge)
	Register(pnpmStrictDepBuilds)
	Register(pnpmAllowBuilds)
	Register(pnpmOnlyBuiltDependencies)
	Register(pnpmBlockExoticSubdeps)
	Register(pnpmTrustPolicy)
}

// pnpm counts minutes, so three days is 4320. The number is large enough that a
// person who writes 3 has asked for three minutes and will never notice.
var pnpmMinimumReleaseAge = &Rule{
	ID:      "DR010",
	Name:    "pnpm-minimum-release-age",
	Manager: PNPM,
	Summary: "wait before installing a release that was just published",
	Since:   "10.16.0",
	Targets: []Target{{
		Name:     "pnpm-workspace.yaml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"minimumReleaseAge"},
		CreateIf: true,
	}},
	// pnpm 11 waits a day when the key is absent, which covers a project whose own
	// cooldown is a day or less and no more than that.
	Desired:  MinimumAge{Unit: Minutes, Default: 24 * time.Hour, DefaultSince: "11"},
	Level:    model.LevelWarn,
	Docs:     "https://pnpm.io/settings/dependency-resolution",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "pnpm counts minutes. minimumReleaseAgeExclude takes the names, globs and version selectors that skip the wait; minimumReleaseAgeStrict, from pnpm 11, refuses rather than warns when a release has no publish time.",
}

// A build script of a dependency runs with the developer's own permissions, which
// is how a compromised package reaches an ssh key. pnpm blocks them and lists what
// it blocked; strictDepBuilds makes that list a failure.
var pnpmStrictDepBuilds = &Rule{
	ID:      "DR011",
	Name:    "pnpm-strict-dep-builds",
	Manager: PNPM,
	Summary: "fail rather than list the build scripts that were skipped",
	Since:   "10.3.0",
	Targets: []Target{{
		Name:     "pnpm-workspace.yaml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"strictDepBuilds"},
		CreateIf: true,
	}},
	Desired:  BoolSetting{On: true, Defaulted: true, Default: true, DefaultSince: "11"},
	Level:    model.LevelWarn,
	Docs:     "https://pnpm.io/settings/build",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "pnpm 11 turned this on by default. On pnpm 10 it has to be written.",
}

// allowBuilds is the pnpm 11 spelling of the list of packages allowed to run a
// build script, and it is a map of package to boolean rather than a list of names.
// It arrived in 10.26, before the version that removed the old key, so both
// spellings work on a late pnpm 10.
var pnpmAllowBuilds = &Rule{
	ID:      "DR012",
	Name:    "pnpm-allow-builds",
	Manager: PNPM,
	Summary: "name the packages allowed to run a build script",
	Since:   "10.26.0",
	Targets: []Target{{
		Name:   "pnpm-workspace.yaml",
		Format: configfile.FormatYAML,
		Key:    configfile.Key{"allowBuilds"},
	}},
	// Which packages a project builds is the project's own answer, so this is
	// reported and never written: a tool that invented the list would either allow
	// what nobody reviewed or break an install that needs a native module.
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://pnpm.io/settings/build",
	Verified: "2026-09-09",
	Note:     "allowBuilds maps a package to true or false, and a package that is not in it is refused. pnpm 11 removed onlyBuiltDependencies, neverBuiltDependencies and ignoredBuiltDependencies in its favor; the codemod pnpm-v10-to-v11 converts them.",
}

// The pnpm 10 spelling, kept so that a project on pnpm 10 is judged by the key its
// own version reads. Until says pnpm 11, where the key is gone and reporting it
// missing would be telling somebody to write a setting their pnpm rejects.
var pnpmOnlyBuiltDependencies = &Rule{
	ID:      "DR013",
	Name:    "pnpm-only-built-dependencies",
	Manager: PNPM,
	Summary: "name the packages allowed to run a build script (pnpm 10)",
	Since:   "10.0.0",
	Until:   "11.0.0",
	Targets: []Target{{
		Name:   "pnpm-workspace.yaml",
		Format: configfile.FormatYAML,
		Key:    configfile.Key{"onlyBuiltDependencies"},
	}},
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://pnpm.io/settings/build",
	Verified: "2026-09-09",
	Note:     "pnpm 11 removed this key. A project upgrading to 11 moves the list into allowBuilds as a map of package to true.",
}

// A subdependency resolved from a git remote or a tarball URL is the supply chain
// hole a lockfile review is least likely to catch, because nobody scrolls to it.
var pnpmBlockExoticSubdeps = &Rule{
	ID:      "DR014",
	Name:    "pnpm-block-exotic-subdeps",
	Manager: PNPM,
	Summary: "refuse a dependency of a dependency that comes from git or a URL",
	Since:   "10.26.0",
	Targets: []Target{{
		Name:     "pnpm-workspace.yaml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"blockExoticSubdeps"},
		CreateIf: true,
	}},
	Desired:  BoolSetting{On: true, Defaulted: true, Default: true},
	Level:    model.LevelInfo,
	Docs:     "https://pnpm.io/settings/dependency-resolution",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "On by default since it arrived. The rule is here for a project that turned it off.",
}

// trustPolicy is pnpm's own version of the trust-downgrade check: it refuses a
// release whose provenance or publisher protection is weaker than the one before
// it, which is the shape almost every account takeover has.
var pnpmTrustPolicy = &Rule{
	ID:      "DR015",
	Name:    "pnpm-trust-policy",
	Manager: PNPM,
	Summary: "refuse a release whose publishing protections got weaker",
	Since:   "10.21.0",
	Targets: []Target{{
		Name:     "pnpm-workspace.yaml",
		Format:   configfile.FormatYAML,
		Key:      configfile.Key{"trustPolicy"},
		CreateIf: true,
	}},
	Desired: EnumSetting{
		Value:    "no-downgrade",
		Accepted: []string{"off"},
		Weaker:   "accepts a release published with weaker protections than the version before it",
	},
	Level:    model.LevelWarn,
	Docs:     "https://pnpm.io/settings/dependency-resolution",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Off by default. trustPolicyExclude takes the packages that are exempt, and trustPolicyIgnoreAfter, in minutes, stops applying it to releases older than a given age.",
}
