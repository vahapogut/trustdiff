package doctor

import (
	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Cargo, read against https://doc.rust-lang.org/cargo/reference/config.html and
// the unstable reference on 2026-09-09.
//
// Cargo is the one manager here with nothing to turn on. There is no cooldown in
// stable Cargo: RFC 3923 was merged on 2026-05-18 and the implementation is
// nightly only, behind -Zmin-publish-age. The honest scorecard line says that,
// names what a Rust project can do instead, and does not invent a setting.

func init() {
	Register(cargoCooldown)
	Register(cargoUnstableMinPublishAge)
}

var cargoCooldown = &Rule{
	ID:       "DR080",
	Name:     "cargo-cooldown",
	Manager:  Cargo,
	Summary:  "wait before installing a release that was just published",
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://github.com/rust-lang/rfcs/pull/3923",
	Verified: "2026-09-09",
	Note:     "Stable Cargo has no cooldown. RFC 3923 was merged on 2026-05-18 and is implemented on nightly only. Until it lands, a Rust project's defenses are cargo-deny for policy, cargo-vet for review records, cargo-audit for advisories, and cargo install --locked so an install uses the lockfile it was tested with.",
}

// The nightly setting, reported so that a project that configured it knows what
// it is worth: on a stable toolchain the key is read and does nothing.
var cargoUnstableMinPublishAge = &Rule{
	ID:      "DR081",
	Name:    "cargo-min-publish-age",
	Manager: Cargo,
	Summary: "the nightly minimum publish age, if this project already sets it",
	Targets: []Target{
		{Name: ".cargo/config.toml", Format: configfile.FormatTOML, Key: configfile.Key{"registry", "global-min-publish-age"}},
	},
	Desired:  Advice{},
	Level:    model.LevelInfo,
	Docs:     "https://doc.rust-lang.org/cargo/reference/unstable.html",
	Verified: "2026-09-09",
	Note:     "registry.global-min-publish-age takes a value such as \"3 days\" and works only on nightly with -Zmin-publish-age. On a stable toolchain it is accepted and ignored, so a project that set it is not protected and has no way to tell.",
}
