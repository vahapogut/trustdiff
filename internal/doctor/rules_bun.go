package doctor

import (
	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Bun's settings, read against the bunfig and install documentation on
// 2026-09-09. Bun counts seconds, which is the unit nothing else here uses.

func init() {
	Register(bunMinimumReleaseAge)
	Register(bunSecurityScanner)
}

// Bun counts in seconds, which is the unit nothing else here uses. A person who
// writes 10080 meaning a week in minutes, the way pnpm counts, has asked Bun to
// wait under three hours, and Bun accepts it without a word. That is exactly the
// mistake MinimumAge.Judge is written to name.
var bunMinimumReleaseAge = &Rule{
	ID:      "DR030",
	Name:    "bun-minimum-release-age",
	Manager: Bun,
	Summary: "wait before installing a release that was just published",
	Since:   "1.3",
	Targets: []Target{{
		Name:     "bunfig.toml",
		Format:   configfile.FormatTOML,
		Key:      configfile.Key{"install", "minimumReleaseAge"},
		CreateIf: true,
	}},
	Desired:  MinimumAge{Unit: Seconds},
	Level:    model.LevelWarn,
	Docs:     "https://bun.com/docs/runtime/bunfig",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Bun counts seconds. The companion key minimumReleaseAgeExcludes takes the packages that skip the wait.",
}

// The security scanner is an integration point rather than a value with a right
// answer, so it is reported and never written: which scanner to trust is the
// project's decision, and configuring one also turns Bun's auto-install off.
var bunSecurityScanner = &Rule{
	ID:      "DR031",
	Name:    "bun-security-scanner",
	Manager: Bun,
	Summary: "run a security scanner over what an install would fetch",
	Since:   "1.3",
	Targets: []Target{{
		Name:   "bunfig.toml",
		Format: configfile.FormatTOML,
		Key:    configfile.Key{"install.security", "scanner"},
	}},
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://bun.com/docs/install/security-scanner-api",
	Verified: "2026-09-09",
	Note:     "Bun 1.3 takes a scanner package under [install.security]; a scanner that reports fatal stops the install. Which scanner to trust is a decision for the project, so this is reported and never written.",
}
