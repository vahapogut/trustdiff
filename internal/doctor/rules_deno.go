package doctor

import (
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Deno's settings, read against the deno.json reference and the supply chain page
// on 2026-09-09.

func init() {
	Register(denoMinimumDependencyAge)
	Register(denoFrozenLockfile)
	Register(denoLockfileOn)
}

// Deno takes more spellings than anything else here: an ISO 8601 duration, a bare
// number of minutes, an absolute date, an RFC 3339 timestamp, or an object with an
// age and an exclude list. DenoMinimumAge reads all of them, because a value Deno
// accepts and acts on is not a mistake whichever way its author spelled it. The
// rule writes the ISO 8601 form, which is the one the documentation leads with and
// the only one that cannot be misread as another manager's unit.
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
	Desired:  DenoMinimumAge{Default: 24 * time.Hour, DefaultSince: "2.9"},
	Level:    model.LevelWarn,
	Docs:     "https://docs.deno.com/runtime/reference/deno_json/",
	Verified: "2026-09-10",
	Fixable:  true,
	Note:     "Deno also reads a bare number as minutes, an absolute date or RFC 3339 timestamp as a cutoff, 0 to turn the wait off, and an object form {age, exclude} for packages that skip it. All of those are read as written. The default of one day arrived in 2.9.",
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

// The lock key turns the lockfile itself on and off, and off is a different thing
// from not frozen: a project with no lockfile pins nothing at all, and the frozen
// rule above would report that as a missing setting, which understates it by a
// long way.
var denoLockfileOn = &Rule{
	ID:      "DR042",
	Name:    "deno-lockfile",
	Manager: Deno,
	Summary: "keep the lockfile that pins what an install fetches",
	Targets: []Target{
		{Name: "deno.json", Format: configfile.FormatJSON, Key: configfile.Key{"lock"}},
		{Name: "deno.jsonc", Format: configfile.FormatJSONC, Key: configfile.Key{"lock"}},
	},
	// Reported and never written. Turning a lockfile back on changes what the next
	// install resolves, and a project that switched it off did so on purpose or by
	// a mistake only a person can tell apart.
	Desired:  denoLockfile{},
	Level:    model.LevelWarn,
	Docs:     "https://docs.deno.com/runtime/reference/deno_json/",
	Verified: "2026-09-09",
	Note:     "Deno writes a lockfile by default. \"lock\": false turns it off, and an object form such as {\"path\": \"deno.lock\", \"frozen\": true} keeps it on and configures it.",
}

// denoLockfile judges the lock key, which Deno lets a project write as a boolean or
// as an object. Neither BoolSetting nor EnumSetting can read both, and reading only
// one of them would report the other as wrong.
type denoLockfile struct{}

// Want is the boolean form, which is what a project that turned the lockfile off
// would write to turn it back on.
func (denoLockfile) Want(*Params) configfile.Literal { return configfile.Bool(true) }

// Describe says what the rule asks for.
func (denoLockfile) Describe(*Params) string { return "a lockfile, which is the default" }

// Judge reads the two shapes the key takes.
func (denoLockfile) Judge(v *configfile.Value, _ *Params) (Status, string) {
	if !v.Found() {
		return StatusSet, "not set, and Deno writes a lockfile by default"
	}
	if v.Kind == configfile.KindMap {
		return StatusSet, "configured as an object, so the lockfile is on"
	}
	if strings.EqualFold(strings.TrimSpace(v.Text), "false") {
		return StatusWrong, "the lockfile is turned off, so nothing pins what an install fetches and the frozen setting below has nothing to freeze"
	}
	return StatusSet, ""
}
