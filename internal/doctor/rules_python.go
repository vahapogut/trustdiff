package doctor

import (
	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The Python package managers, read against https://docs.astral.sh/uv/reference/settings/,
// https://pip.pypa.io/en/stable/ and https://python-poetry.org/docs/configuration/
// on 2026-09-09.
//
// The three differ in where a repository can even hold the setting. uv reads
// pyproject.toml, which a project commits. Poetry reads poetry.toml, which a
// project commits. pip reads a configuration file that belongs to the machine or
// the virtual environment, so what a repository can do is name one through
// PIP_CONFIG_FILE or pass the flag in CI, and the rule says so rather than writing
// a file pip will not read.

func init() {
	Register(uvExcludeNewer)
	Register(uvMalwareCheck)
	Register(pipUploadedPriorTo)
	Register(pipRequireHashes)
	Register(poetryMinReleaseAge)
}

// uv writes the wait as words, "3 days", and resolves it into uv.lock when the
// lock is written, which is the one implementation here that records what it did.
// It also takes a point in time, and UvExcludeNewer reads both.
var uvExcludeNewer = &Rule{
	ID:      "DR050",
	Name:    "uv-exclude-newer",
	Manager: UV,
	Summary: "wait before installing a release that was just published",
	Since:   "0.9.17",
	Targets: []Target{
		{Name: "pyproject.toml", Format: configfile.FormatTOML, Key: configfile.Key{"tool", "uv", "exclude-newer"}},
		{Name: "uv.toml", Format: configfile.FormatTOML, Key: configfile.Key{"exclude-newer"}, CreateIf: true},
	},
	Desired:  UvExcludeNewer{},
	Level:    model.LevelWarn,
	Docs:     "https://docs.astral.sh/uv/reference/settings/#exclude-newer",
	Verified: "2026-09-10",
	Fixable:  true,
	Note:     "uv 0.9.17 added the relative form; before that the key took an absolute timestamp only, and both are read here. It is measured against the time a file was uploaded to the index, not the version's release date, and exclude-newer-package exempts named packages.",
}

// uv can ask OSV about a package before installing it, which is the check TD009
// runs from the outside, run by the installer itself. It is a preview feature, so
// the rule reports it and does not write it: a preview setting that changes its
// name costs a project an install that fails for no visible reason.
var uvMalwareCheck = &Rule{
	ID:      "DR051",
	Name:    "uv-malware-check",
	Manager: UV,
	Summary: "ask an advisory database about a package before installing it",
	Since:   "0.11.31",
	Targets: []Target{
		{Name: "pyproject.toml", Format: configfile.FormatTOML, Key: configfile.Key{"tool", "uv", "audit", "malware-check"}},
		{Name: "uv.toml", Format: configfile.FormatTOML, Key: configfile.Key{"audit", "malware-check"}},
	},
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://docs.astral.sh/uv/concepts/preview/",
	Verified: "2026-09-09",
	Note:     "Preview in uv 0.11.31: audit.malware-check turns it on and audit.malware-check-url chooses the database, which defaults to OSV. Reported rather than written while it is preview.",
}

// pip's own wait, which reaches a repository only through a file pip is told to
// read or a flag in CI. It is also the one setting here that depends on the index:
// pip can only apply it where the index reports upload times.
var pipUploadedPriorTo = &Rule{
	ID:      "DR060",
	Name:    "pip-uploaded-prior-to",
	Manager: Pip,
	Summary: "wait before installing a release that was just published",
	Since:   "26.1",
	Targets: []Target{
		{Name: "pip.conf", Format: configfile.FormatINI, Key: configfile.Key{"install", "uploaded-prior-to"}},
		{Name: "pip.ini", Format: configfile.FormatINI, Key: configfile.Key{"install", "uploaded-prior-to"}},
	},
	Desired:  MinimumAge{Unit: ISO8601Days},
	Level:    model.LevelWarn,
	Docs:     "https://pip.pypa.io/en/stable/cli/pip_install/",
	Verified: "2026-09-12",
	Fixable:  true,
	Note:     "pip reads its configuration from the machine, the user or the virtual environment, so a pip.conf committed to a repository does nothing until PIP_CONFIG_FILE names it. In CI, pass --uploaded-prior-to P3D or set PIP_UPLOADED_PRIOR_TO. pip 26.0 accepted an absolute date only; the relative form arrived in 26.1, and it applies only where the index reports upload times. pip documents that form as a duration in days, so a wait written here is rounded up to whole days; a shorter one already in the file is read as it stands.",
}

// Hashes are what make a Python install reproducible, and require-hashes is what
// makes them mandatory rather than optional.
var pipRequireHashes = &Rule{
	ID:      "DR061",
	Name:    "pip-require-hashes",
	Manager: Pip,
	Summary: "refuse to install anything the requirements file does not hash",
	Targets: []Target{
		{Name: "pip.conf", Format: configfile.FormatINI, Key: configfile.Key{"install", "require-hashes"}},
		{Name: "pip.ini", Format: configfile.FormatINI, Key: configfile.Key{"install", "require-hashes"}},
	},
	Desired:  BoolSetting{On: true, Defaulted: true, Default: false},
	Level:    model.LevelInfo,
	Docs:     "https://pip.pypa.io/en/stable/topics/configuration/",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "A requirements file that hashes any package already implies this. It belongs in CI, where the requirements are pinned, rather than in a developer's own configuration.",
}

// Poetry counts days, like npm, and the setting lives in poetry.toml rather than
// in pyproject.toml, which is the mistake worth catching: pyproject is where every
// other Poetry setting a person remembers lives.
var poetryMinReleaseAge = &Rule{
	ID:      "DR070",
	Name:    "poetry-min-release-age",
	Manager: Poetry,
	Summary: "wait before installing a release that was just published",
	Since:   "2.4.0",
	Targets: []Target{{
		Name:     "poetry.toml",
		Format:   configfile.FormatTOML,
		Key:      configfile.Key{"solver", "min-release-age"},
		CreateIf: true,
	}},
	Desired:  MinimumAge{Unit: Days},
	Level:    model.LevelWarn,
	Docs:     "https://python-poetry.org/docs/configuration/",
	Verified: "2026-09-09",
	Fixable:  true,
	Note:     "Poetry counts whole days, and reads this from poetry.toml or the user's config.toml rather than from pyproject.toml. poetry config solver.min-release-age <days> --local writes the same file. solver.min-release-age-exclude exempts packages and solver.min-release-age-exclude-source exempts whole sources.",
}
