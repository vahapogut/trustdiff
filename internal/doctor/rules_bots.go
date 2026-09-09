package doctor

import (
	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The two dependency bots and the workflow files they open pull requests into.
// Read against the Dependabot options reference, the Renovate configuration
// options and GitHub's security hardening guide on 2026-09-09.
//
// A bot is where a project's cooldown either holds or leaks. A repository can wait
// three days at install time and still merge a release the day it appeared,
// because the bot opened the pull request and the tests passed. The two rules below
// are the same threshold, said again where the upgrade actually enters.

func init() {
	Register(dependabotCooldown)
	Register(renovateMinimumReleaseAge)
	Register(actionsShaPin)
}

// Dependabot writes its cooldown inside each update block, and a repository
// usually has several. That is one key per block rather than one setting in a
// file, so the rule reads the file itself and reports a line per block.
var dependabotCooldown = &Rule{
	ID:       "DR090",
	Name:     "dependabot-cooldown",
	Manager:  Dependabot,
	Summary:  "wait before opening a pull request for a release that was just published",
	Scan:     dependabotScanner{},
	Desired:  Advice{},
	Level:    model.LevelWarn,
	Docs:     "https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference",
	Verified: "2026-09-09",
	Note:     "cooldown goes inside an update block and takes default-days, between 1 and 90, plus semver-major-days, semver-minor-days and semver-patch-days where the ecosystem has semantic versions. Since 2026-07-14 a version update waits three days even with no cooldown block, and a security update never waits.",
}

// Renovate writes the same idea as one top-level setting, in words.
var renovateMinimumReleaseAge = &Rule{
	ID:      "DR100",
	Name:    "renovate-minimum-release-age",
	Manager: Renovate,
	Summary: "wait before opening a pull request for a release that was just published",
	// Renovate reads its configuration from any of several names, and from a
	// "renovate" object in package.json, which is where a project that started with
	// the GitHub app most often has it. Reading only renovate.json reported those
	// projects as missing a setting they had written.
	Targets: []Target{
		{Name: "renovate.json", Format: configfile.FormatJSON, Key: configfile.Key{"minimumReleaseAge"}},
		{Name: "renovate.json5", Format: configfile.FormatJSONC, Key: configfile.Key{"minimumReleaseAge"}},
		{Name: ".renovaterc.json", Format: configfile.FormatJSON, Key: configfile.Key{"minimumReleaseAge"}},
		{Name: ".renovaterc.json5", Format: configfile.FormatJSONC, Key: configfile.Key{"minimumReleaseAge"}},
		{Name: ".renovaterc", Format: configfile.FormatJSON, Key: configfile.Key{"minimumReleaseAge"}},
		{Name: "package.json", Format: configfile.FormatJSON, Key: configfile.Key{"renovate", "minimumReleaseAge"}},
	},
	Desired:  MinimumAge{Unit: Words, Quoted: true},
	Level:    model.LevelWarn,
	Docs:     "https://docs.renovatebot.com/configuration-options/#minimumreleaseage",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Renovate takes a duration in words such as \"3 days\". It can also sit inside a packageRules entry, which this does not read, and minimumReleaseAgeBehaviour decides when the wait applies. A json5 configuration is read as far as its syntax is json with comments; a file that uses unquoted keys is reported as unreadable rather than as missing the setting.",
}

// A workflow that names an action by a tag runs whatever that tag points at
// today, which is a dependency with no lockfile at all. GitHub's own guidance is
// that a full commit sha is the only immutable reference.
var actionsShaPin = &Rule{
	ID:       "DR110",
	Name:     "actions-sha-pin",
	Manager:  Actions,
	Summary:  "pin every action to a full commit sha",
	Scan:     actionsScanner{},
	Desired:  Advice{},
	Level:    model.LevelWarn,
	Docs:     "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
	Verified: "2026-09-09",
	Note:     "A local action and a reusable workflow in the same repository need no pin. The SLSA generator is the one published workflow that must stay on a tag, because its verifier checks the reference; it is reported as pinned by design when it carries a full version tag.",
}
