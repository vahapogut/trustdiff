package doctor

import (
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Deno's settings, read against the deno.json reference and the supply chain page
// on 2026-09-09.

func init() {
	Register(denoMinimumDependencyAge)
	Register(denoFrozenLockfile)
}

// Deno takes more spellings than anything else here: an ISO 8601 duration, a bare
// number of minutes, an absolute date, an RFC 3339 timestamp, or an object with an
// age and an exclude list. The rule writes the ISO 8601 form, which is the one the
// documentation leads with and the only one that cannot be misread as another
// manager's unit.
var denoMinimumDependencyAge = &Rule{
	ID:      "DR040",
	Name:    "deno-minimum-dependency-age",
	Manager: Deno,
	Summary: "wait before installing a release that was just published",
	Since:   "2.6",
	Targets: []Target{
		{Name: "deno.json", Format: configfile.FormatJSON, Key: configfile.Key{"minimumDependencyAge"}},
		{Name: "deno.jsonc", Format: configfile.FormatJSONC, Key: configfile.Key{"minimumDependencyAge"}},
	},
	// Deno 2.9 waits a day even when the key is absent, which is protection a
	// project keeps until somebody pins an older version, so a policy cooldown of a
	// day or less is already met by the default and the scorecard says so.
	Desired:  MinimumAge{Unit: ISO8601, Quoted: true, Default: 24 * time.Hour, DefaultSince: "2.9"},
	Level:    model.LevelWarn,
	Docs:     "https://docs.deno.com/runtime/reference/deno_json/",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Deno also reads a bare number as minutes, and an object form {age, exclude} for packages that skip the wait. The default of one day arrived in 2.9.",
}

// A frozen lockfile is what turns the lockfile from a record into a rule: a
// dependency that is not in it fails the build instead of appearing quietly.
var denoFrozenLockfile = &Rule{
	ID:      "DR041",
	Name:    "deno-frozen-lockfile",
	Manager: Deno,
	Summary: "refuse a dependency the lockfile does not already have",
	Targets: []Target{
		{Name: "deno.json", Format: configfile.FormatJSON, Key: configfile.Key{"lock", "frozen"}},
		{Name: "deno.jsonc", Format: configfile.FormatJSONC, Key: configfile.Key{"lock", "frozen"}},
	},
	Desired:  BoolSetting{On: true, Defaulted: true, Default: false},
	Level:    model.LevelWarn,
	Docs:     "https://docs.deno.com/runtime/reference/deno_json/",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "The lock key also takes a plain boolean, and false there turns the lockfile off altogether.",
}
